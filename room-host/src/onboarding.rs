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
//! # What this does not do yet
//!
//! Being enrolled is not the same as having a published identity. This gets the host an ACL
//! entry under a `did:key`; turning that into the `did:webvh` a room names is a further act —
//! `webvh/dids/create` against the `room-host` template, then `acl/swap-key` onto it. See
//! `docs/05-design-notes/` and the note in `HostIdentity` about who holds which key.

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
}
