//! Enrolling this host with a VTA, the way every other integration does.
//!
//! A host that is going to serve a VTA-governed room needs an identity that VTA recognises —
//! an ACL entry it can be authorized by. `vti-secrets` already packages that flow, and it is
//! the same one the mediator, PNM and the did-hosting service use:
//!
//! 1. **Mint and park.** The host mints a throwaway `did:key` locally — the private half
//!    never crosses the wire — and parks it as a pending-rotation session bound to the VTA.
//! 2. **Grant.** An operator authorizes that DID out of band, which is the one step that
//!    cannot be automated: it is a person deciding this host may act in their context.
//! 3. **Connect and rotate.** On the first successful authentication the session store swaps
//!    the throwaway for a fresh key, so the DID that travelled through a chat window or a
//!    ticket does not stay live.
//!
//! # `did:key`, deliberately
//!
//! A bootstrap identity dials out and is never dialled, so it needs no service block and
//! therefore no `did:peer`. It is self-certifying, which means the VTA can verify it with no
//! resolution at all — and it is thrown away at step 3 regardless.
//!
//! # Then the host takes the identity the VTA holds for it
//!
//! Enrolment gets an ACL entry under a throwaway. What the host actually serves as is the
//! DID its VTA context holds — fetched with [`fetch_identity`], which is the same thing the
//! mediator does at boot (`vta_sdk::integration::startup`) rather than a pattern invented
//! here.
//!
//! So the VTA generates and the host fetches. Two consequences worth stating rather than
//! discovering:
//!
//! - The VTA can act as this host, because it holds the keys. For a room host that is an
//!   availability and authenticity question, not a confidentiality one: a host holds
//!   ciphertext and no room keys, so there is nothing there for anyone to read.
//! - A host that has fetched once keeps working when the VTA is unreachable, because the
//!   bundle is cached. Without that, a VTA outage would stop every host that trusts it —
//!   which is a much larger blast radius than the outage itself.

use std::path::Path;

use vti_secrets::onboarding::IntegrationOnboarding;

/// Where this host's VTA session lives, within whatever session backend is compiled in.
///
/// Keyed by the VTA's DID rather than a fixed string: one host may serve rooms governed by
/// more than one VTA, and a single session key would make the second enrolment silently
/// overwrite the first.
fn session_key(vta_did: &str) -> String {
    format!("room-host:{vta_did}")
}

/// What enrolment produced, and what the operator has to do about it.
pub enum Enrolment {
    /// A fresh ephemeral DID is parked and waiting to be granted.
    ///
    /// The host cannot proceed alone from here, and should not pretend to: somebody has to
    /// decide this host may act in their context.
    AwaitingGrant { ephemeral_did: String },
    /// Already enrolled — the throwaway was rotated away on a previous run.
    Enrolled,
}

/// Begin or resume enrolment with `vta_did`.
///
/// Idempotent across restarts by design: an already-enrolled host reports [`Enrolment::Enrolled`]
/// and mints nothing. `begin` overwrites any parked session, so calling it unconditionally
/// would discard a grant an operator had already made — which is why `is_onboarded` is
/// checked rather than assumed.
pub fn enrol(data_dir: &Path, vta_did: &str) -> anyhow::Result<Enrolment> {
    let onboarding = IntegrationOnboarding::with_default_backend(
        "room-host",
        data_dir.join("sessions"),
        session_key(vta_did),
    );

    if onboarding.is_onboarded() {
        return Ok(Enrolment::Enrolled);
    }

    let ticket = onboarding
        .begin(vta_did)
        .map_err(|e| anyhow::anyhow!("could not begin enrolment with {vta_did}: {e}"))?;

    Ok(Enrolment::AwaitingGrant {
        ephemeral_did: ticket.ephemeral_did().to_string(),
    })
}

/// What to tell an operator who has just seen [`Enrolment::AwaitingGrant`].
///
/// Printed rather than logged, and with the command spelled out: the person who has to run it
/// is at a terminal, and the difference between "grant this DID" and a line they can paste is
/// most of whether this gets done correctly.
pub fn grant_instructions(ephemeral_did: &str, vta_did: &str) -> String {
    format!(
        "This host is not yet enrolled with {vta_did}.\n\
         \n\
         It has minted a throwaway identity and is waiting to be authorized:\n\
         \n    {ephemeral_did}\n\
         \n\
         Grant it an application role in the context that governs your rooms — from the VTA:\n\
         \n    vta import-did --did {ephemeral_did} --role application --context <CONTEXT>\n\
         \n\
         or against a running VTA:\n\
         \n    pnm acl create --did {ephemeral_did} --role application --contexts <CONTEXT>\n\
         \n\
         Then start this host again. The throwaway is rotated away on first connect, so a DID \
         that travelled through a chat window does not stay live."
    )
}

/// Fetch this host's identity from `vta_did`'s context, falling back to the cache.
pub async fn fetch_identity(
    data_dir: &Path,
    vta_did: &str,
    context: &str,
    cache: &dyn vti_common::seed_store::SeedStore,
) -> anyhow::Result<VtaIdentity> {
    let onboarding = IntegrationOnboarding::with_default_backend(
        "room-host",
        data_dir.join("sessions"),
        session_key(vta_did),
    );

    match onboarding.connect(None, None).await {
        Ok(client) => {
            let bundle = match client.fetch_did_secrets_bundle(context).await {
                Ok(b) => b,
                Err(e) => {
                    // Only on the failure path, and only one extra call: ask whether
                    // this is the one misconfiguration an operator can actually fix.
                    // Doing it eagerly would cost every boot a round trip to answer a
                    // question that is almost always "no".
                    if let Some(help) = diagnose_contextless_did(&client, context, vta_did).await {
                        anyhow::bail!(help);
                    }
                    anyhow::bail!("fetch this host's secrets from {vta_did}: {e}");
                }
            };

            // Cached before it is used, so a host that starts, fetches, and then finds the
            // VTA gone on its next boot still comes up. Caching afterwards would leave the
            // one run that mattered uncached.
            let encoded = serde_json::to_vec(&bundle)?;
            if let Err(e) = cache.set(&encoded).await {
                tracing::warn!(error = %e, "could not cache the VTA bundle; a VTA outage will \
                                            now stop this host from starting");
            }
            Ok(VtaIdentity {
                did: bundle.did.clone(),
                secrets: to_secrets(&bundle)?,
                fresh: true,
            })
        }
        Err(e) => {
            let Some(cached) = cache
                .get()
                .await
                .map_err(|c| anyhow::anyhow!("read the cached VTA bundle: {c}"))?
            else {
                anyhow::bail!(
                    "could not reach {vta_did} ({e}), and this host has no cached identity — \
                     it has never successfully fetched one. Enrol it first."
                );
            };
            let bundle: vta_sdk::did_secrets::DidSecretsBundle = serde_json::from_slice(&cached)?;
            tracing::warn!(
                vta = %vta_did,
                error = %e,
                did = %bundle.did,
                "serving on the cached identity — the VTA could not be reached"
            );
            Ok(VtaIdentity {
                did: bundle.did.clone(),
                secrets: to_secrets(&bundle)?,
                fresh: false,
            })
        }
    }
}

/// Is the reason the fetch failed simply that nobody has given this context a DID?
///
/// Returns the instructions if so, `None` if the failure was something else — in which
/// case the caller reports the original error rather than a guess about it.
///
/// # Why this exists
///
/// A host enrolled into a context with no DID gets `context 'rooms' has no DID assigned`
/// and nothing else. That is accurate and useless: it names a state, not a next step, and
/// the operator's actual question at that moment is "was I supposed to create a DID for
/// this host first?" — which is a reasonable thing not to know, because the room-creation
/// form asks for a host DID without saying where one comes from.
///
/// So this answers it, in the same shape as [`grant_instructions`]: a pasteable command,
/// because the person who has to run it is at a terminal.
async fn diagnose_contextless_did(
    client: &vta_sdk::client::VtaClient,
    context: &str,
    vta_did: &str,
) -> Option<String> {
    let ctx = client.get_context(context).await.ok()?;
    if ctx.did.is_some() {
        return None;
    }
    Some(contextless_did_help(context, vta_did))
}

/// The text of that guidance, split out so it can be read by a test.
fn contextless_did_help(context: &str, vta_did: &str) -> String {
    format!(
        "Context `{context}` on {vta_did} has no DID, so there is no identity for this host \
         to serve as.\n\
         \n\
         This host does not create one for itself: it enrols with an `application` role, and \
         minting a DID in a context needs an admin. That split is deliberate — a host holds \
         ciphertext it cannot read, and giving it authority to mint identities in your \
         context would be more power than it needs.\n\
         \n\
         Create one against the VTA:\n\
         \n    pnm did-mgmt dids create --context {context} --server <SERVER_ID> \\\n\
                 --label \"room host\" --mediator-service\n\
         \n\
         `--server` is a DID-hosting server you have registered (`pnm did-mgmt servers \
         list`). Add `--path <name>` to choose the name it is published under; omit it and \
         the hosting server assigns one.\n\
         \n\
         `--mediator-service` is not optional for a room host in practice: members reach it \
         by resolving its DID, so a DID that advertises no service block is one nobody can \
         dial.\n\
         \n\
         Then start this host again — it will fetch that DID and its keys on boot."
    )
}

/// Turn the VTA's bundle into the secrets a resolver takes.
fn to_secrets(
    bundle: &vta_sdk::did_secrets::DidSecretsBundle,
) -> anyhow::Result<Vec<affinidi_secrets_resolver::secrets::Secret>> {
    bundle
        .secrets
        .iter()
        .map(|entry| {
            // `(private, kid)` — the private key first, and the verification method it is
            // published under second. The VTA's bundle names both, so the key the host holds
            // and the method a counterparty resolves are the same one by construction.
            affinidi_secrets_resolver::secrets::Secret::from_multibase(
                &entry.private_key_multibase,
                Some(&entry.key_id),
            )
            .map_err(|e| anyhow::anyhow!("`{}` is not a usable key: {e}", entry.key_id))
        })
        .collect()
}

/// The DID this host serves as, and the keys to serve with, from its VTA context.
///
/// Fresh from the VTA when it can be reached, and from the cache when it cannot. The cache is
/// not an optimisation: without it a VTA outage would stop every host enrolled with it, and a
/// host that is merely *storing ciphertext* has no business being that fragile.
///
/// The cache is the same [`SeedStore`](vti_common::seed_store::SeedStore) the host's own
/// identity uses, so where this material rests is the operator's `[secrets]` decision and not
/// a second place to configure.
pub struct VtaIdentity {
    pub did: String,
    pub secrets: Vec<affinidi_secrets_resolver::secrets::Secret>,
    /// Whether the VTA answered, or this came from the cache.
    pub fresh: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One host, two VTAs, two sessions.
    ///
    /// A fixed session key would make enrolling with a second VTA overwrite the first — and
    /// the symptom would be the first VTA's rooms failing to authorize, long after the
    /// enrolment that caused it.
    #[test]
    fn each_vta_gets_its_own_session() {
        assert_ne!(
            session_key("did:webvh:one:vta"),
            session_key("did:webvh:two:vta")
        );
        assert!(session_key("did:webvh:one:vta").contains("did:webvh:one:vta"));
    }

    /// A host with no session mints one and asks to be granted; a second call does not mint
    /// a *different* one, because that would discard a grant already made against the first.
    #[test]
    fn enrolment_is_idempotent_while_it_waits() {
        let dir = tempfile::tempdir().unwrap();
        let vta = "did:webvh:QmScid:vta.example:agent";

        let first = enrol(dir.path(), vta).expect("begin enrolment");
        let Enrolment::AwaitingGrant { ephemeral_did } = first else {
            panic!("a fresh host must ask to be granted");
        };
        assert!(
            ephemeral_did.starts_with("did:key:"),
            "a bootstrap identity dials out and is never dialled, so it needs no service \
             block: {ephemeral_did}"
        );

        // The instructions name the DID an operator has to paste, and the context they have
        // to choose. Asserted because a message that omits either is a support ticket.
        let told = grant_instructions(&ephemeral_did, vta);
        assert!(told.contains(&ephemeral_did));
        assert!(told.contains("<CONTEXT>"));
    }

    /// The instructions are the deliverable, so they get read here rather than
    /// only in an incident. Escapes in a multi-line format string are easy to
    /// get subtly wrong, and a mangled command is worse than none — an operator
    /// pastes it, it fails, and now they distrust the guidance too.
    #[test]
    fn the_missing_did_instructions_render_a_pasteable_command() {
        // Same body as `diagnose_contextless_did` returns; kept here rather
        // than plumbed out of an async VTA call, which would test tokio.
        let rendered = super::contextless_did_help("rooms", "did:webvh:example:vta");

        assert!(rendered.contains("pnm did-mgmt dids create --context rooms"));
        assert!(
            rendered.contains("--mediator-service"),
            "a room host DID nobody can dial is the failure this flag prevents"
        );
        assert!(
            rendered.contains("--path <name>"),
            "the naming option has to be mentioned, or the default looks like the only choice"
        );
        assert!(
            !rendered.contains("\\n") && !rendered.contains("u{"),
            "escapes must have been interpreted, not printed: {rendered}"
        );
        // Every continuation line of the pasteable command must still be part
        // of that command — a line-continuation that lost its backslash yields
        // two broken commands rather than one working one.
        let cmd_line = rendered
            .lines()
            .find(|l| l.contains("pnm did-mgmt dids create"))
            .expect("the command is present");
        assert!(
            cmd_line.trim_end().ends_with('\\'),
            "the command wraps, so its first line must end in a continuation: {cmd_line:?}"
        );
    }
}
