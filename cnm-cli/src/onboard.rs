//! Onboarding `cnm`'s identities the way `pnm` onboards its own: a key minted
//! on this machine, granted by an administrator, then confirmed.
//!
//! Two identities, two lifecycles:
//!
//! - **The personal VTA** — one per machine. The cold start is `pnm`'s
//!   (CLAUDE.md "Admin credential cold-start", "Deferred VTA-DID setup"): mint
//!   an ephemeral `did:key`, park it, show the grant commands, and on
//!   `cnm setup continue` authenticate and **rotate** to a fresh `did:key`
//!   (`acl/swap-key`, done by the SDK on the first authentication of a
//!   `PendingRotation` session), so the DID that travelled to the
//!   administrator does not stay live.
//! - **A community** — one identity *per community*, so two communities an
//!   operator manages share no key that links them. Minted, parked in
//!   [`CnmConfig::pending_communities`], granted at the community's VTC, and
//!   confirmed by `cnm community continue`, which authenticates to the VTC
//!   (DI-signed `auth/authenticate`, the VTC's DID as audience) and then
//!   **rotates** the identity at the VTC (`acl/swap-key/0.1`, VTI-CLT-025 –
//!   032), so the DID that travelled to the granting administrator does not
//!   stay live. The successor entry carries exactly the granted authority — a
//!   rotation is never a grant, so it takes no second administrator. `cnm
//!   community rotate` rolls a configured community's identity the same way.
//!
//!   Two identities are not rotated, because their key is also held somewhere
//!   the VTC's swap does not reach: one shared with another community
//!   (`--reuse-identity`), and one bound to a community VTA, whose own ACL
//!   entry would be left naming the old DID.
//!
//!   The new key is written to a side slot of the session store **before**
//!   the swap is sent, and promoted only once the VTC accepts it
//!   (VTI-CLT-033): a crash between the two leaves the new key on disk, and
//!   the next `cnm community rotate` adopts it ([`recover_rotation`]).
//!
//! The functions here change a [`CnmConfig`] and a [`SessionStore`] handed in,
//! and never save the config: the caller does, after the step succeeds. That is
//! what lets the tests drive them against an in-memory store.

use serde::Serialize;
use vta_sdk::client::{ClientIdentity, CreateAclRequest, VtaClient};
use vta_sdk::error::VtaError;
use vta_sdk::session::{SessionInfo, SessionStore, TransportChoice};

use crate::config::{
    CnmConfig, CommunityConfig, PERSONAL_KEYRING_KEY, PendingCommunity, PersonalVtaConfig,
    community_keyring_key,
};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The default name of the personal VTA when the operator gives none.
pub const DEFAULT_PERSONAL_NAME: &str = "personal";

// ── JSON stdout contract (non-interactive paths) ────────────────────

/// The one line a non-interactive step prints on stdout — `pnm setup`'s shape
/// (`{slug, admin_did, state}`, #1753), so a script that drives both reads
/// both the same way.
#[derive(Debug, Serialize)]
pub struct SetupOutput<'a> {
    pub slug: &'a str,
    pub admin_did: &'a str,
    pub state: &'static str,
}

pub fn emit_json(slug: &str, admin_did: &str, state: &'static str) -> std::io::Result<()> {
    use std::io::Write;
    let line = serde_json::to_string(&SetupOutput {
        slug,
        admin_did,
        state,
    })
    .expect("SetupOutput serializes");
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{line}")?;
    stdout.flush()
}

fn mint() -> (String, String) {
    vta_cli_common::local_keygen::generate_unbound_admin_did_key()
}

fn require_did(label: &str, did: &str) -> CliResult<String> {
    let did = did.trim();
    if !did.starts_with("did:") {
        return Err(format!(
            "{label} must start with `did:` (e.g. did:webvh:... or did:key:...), got `{did}`"
        )
        .into());
    }
    Ok(did.to_string())
}

// ── Personal VTA ────────────────────────────────────────────────────

/// Where the personal-VTA onboarding stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersonalState {
    /// Nothing set up.
    None,
    /// An identity is minted but not yet confirmed. `bound_vta` is the VTA DID
    /// once supplied.
    Pending {
        admin_did: String,
        bound_vta: Option<String>,
    },
    /// Authenticated (and rotated, on the cold-start path).
    Complete { vta_did: String },
}

pub fn personal_state(config: &CnmConfig, store: &SessionStore) -> PersonalState {
    let Some(personal) = config.personal_vta.as_ref() else {
        return PersonalState::None;
    };
    if let Some(vta_did) = &personal.vta_did {
        return PersonalState::Complete {
            vta_did: vta_did.clone(),
        };
    }
    // Pending only if the session store agrees; a config entry with no key
    // behind it is orphaned and is set up afresh.
    match store.loaded_session(PERSONAL_KEYRING_KEY) {
        Some(info) => PersonalState::Pending {
            admin_did: info.client_did,
            bound_vta: info.vta_did,
        },
        None => PersonalState::None,
    }
}

/// Phase 1: mint the personal VTA's ephemeral identity and park it.
///
/// Refuses a completed personal VTA outright, and a pending one unless
/// `overwrite` — the pending key may already be in an administrator's hands.
/// Returns the minted DID.
pub fn begin_personal(
    config: &mut CnmConfig,
    store: &SessionStore,
    name: &str,
    overwrite: bool,
) -> CliResult<String> {
    match personal_state(config, store) {
        PersonalState::None => {}
        PersonalState::Complete { vta_did } => {
            return Err(format!(
                "the personal VTA is already set up (VTA DID: {vta_did}).\n\n\
                 Add a community with `cnm community add`, or run `cnm setup` and choose to \
                 keep it."
            )
            .into());
        }
        PersonalState::Pending { admin_did, .. } if !overwrite => {
            return Err(format!(
                "a personal-VTA setup is already pending (admin DID: {admin_did}).\n\n\
                 Finish it with `cnm setup continue --vta-did <did:...>`, or pass --overwrite \
                 to mint a fresh identity."
            )
            .into());
        }
        PersonalState::Pending { .. } => {}
    }
    let (did, key) = mint();
    store.store_pending_vta_binding(PERSONAL_KEYRING_KEY, &did, &key)?;
    config.personal_vta = Some(PersonalVtaConfig {
        vta_did: None,
        name: Some(name.to_string()),
    });
    Ok(did)
}

/// Check `cnm setup continue <name>` names the setup that is pending.
pub fn check_personal_name(config: &CnmConfig, name: Option<&str>) -> CliResult {
    let (Some(given), Some(stored)) = (
        name,
        config.personal_vta.as_ref().and_then(|p| p.name.as_deref()),
    ) else {
        return Ok(());
    };
    if crate::setup::slugify(given) != crate::setup::slugify(stored) {
        return Err(format!(
            "the pending personal-VTA setup is named '{stored}', not '{given}'.\n\n\
             Run `cnm setup continue {stored}`."
        )
        .into());
    }
    Ok(())
}

/// Phase 2a: bind the pending identity to the VTA DID.
///
/// Idempotent for the same DID, so a `continue` that failed to authenticate
/// (the grant was not in place yet) is simply re-run. Binding marks the
/// session for rotation on its first authentication.
pub fn bind_personal(
    config: &CnmConfig,
    store: &SessionStore,
    vta_did: Option<&str>,
) -> CliResult<String> {
    match personal_state(config, store) {
        PersonalState::None => Err("no personal-VTA setup is pending.\n\n\
             Start one with `cnm setup` (or `cnm setup --name <name>` non-interactively)."
            .into()),
        PersonalState::Complete { vta_did } => Err(format!(
            "the personal VTA is already set up (VTA DID: {vta_did}). Nothing to continue."
        )
        .into()),
        PersonalState::Pending {
            bound_vta: Some(bound),
            ..
        } => match vta_did {
            Some(given) if require_did("VTA DID", given)? != bound => Err(format!(
                "this pending setup is already bound to {bound}, not {given}.\n\n\
                 Run `cnm setup continue` without --vta-did to finish it, or \
                 `cnm setup --name <name> --overwrite` to start over."
            )
            .into()),
            _ => Ok(bound),
        },
        PersonalState::Pending {
            bound_vta: None, ..
        } => {
            let Some(given) = vta_did else {
                return Err("the VTA DID is required: pass --vta-did <did:...>".into());
            };
            let given = require_did("VTA DID", given)?;
            store.bind_vta_did(PERSONAL_KEYRING_KEY, &given)?;
            Ok(given)
        }
    }
}

/// The grant routes for a pending personal-VTA identity, ready to print.
pub fn personal_grant_commands(admin_did: &str) -> String {
    format!(
        "Grant {admin_did} admin on the personal VTA — any one of:\n\
         \x20 a. A VTA not set up yet: in `vta setup --from setup.toml` set\n\
         \x20      admin_did = \"{admin_did}\"\n\
         \x20 b. On the VTA host:\n\
         \x20      vta import-did --did {admin_did} --role admin\n\
         \x20 c. From a machine whose pnm already administers that VTA:\n\
         \x20      pnm acl create --did {admin_did} --role admin --label cnm\n\
         \x20    (or run `cnm setup` there and choose \"Bootstrap from your existing pnm session\")"
    )
}

/// The ACL entry `cnm` needs on the personal VTA — exactly what it uses there.
///
/// `cnm`'s personal-VTA operations are: create a context per community it
/// manages (`contexts/create` — a *top-level* context, which the VTA gates on
/// super-admin), and create the admin ACL entry for that community's identity
/// in it (`acl/grant`). Both need an **unrestricted admin**: there is no
/// narrower role that creates a top-level context. Its capabilities are left
/// whole on purpose — every entry `cnm` writes there is an admin entry, and the
/// granter's bound (VTI-ACL-053/055) refuses an entry the granter does not
/// cover on every axis, so a capability-narrowed `cnm` could not issue them.
///
/// It is still less than copying `pnm`'s credential: it is a separate key with
/// its own entry, revocable on its own, labelled as `cnm`'s.
pub fn minimal_personal_grant(did: &str) -> CreateAclRequest {
    CreateAclRequest::new(did, "admin").label("cnm — personal VTA (granted from pnm)")
}

/// Grant `new_did` on the personal VTA using an existing `pnm` session's key.
///
/// The `pnm` key signs in memory, here, once: it is authenticated with directly
/// rather than through a [`SessionStore`], so nothing is cached into `pnm`'s
/// session and nothing rotates it. Over REST, deliberately: opening a DIDComm
/// or TSP session as `pnm`'s DID would take the mediator's one socket for that
/// DID from a `pnm` that may be running, and this is a single request.
pub async fn grant_from_pnm(
    pnm: &SessionInfo,
    vta_did: &str,
    url: &str,
    new_did: &str,
) -> CliResult {
    let token = vta_sdk::session::challenge_response(
        url,
        &pnm.client_did,
        &pnm.private_key_multibase,
        vta_did,
    )
    .await
    .map_err(|e| {
        format!(
            "could not sign in to {vta_did} as your pnm identity {}: {e}\n\n\
             Check `pnm health` works, or grant the cnm identity another way:\n{}",
            pnm.client_did,
            personal_grant_commands(new_did)
        )
    })?;
    let client = VtaClient::authenticated(
        url,
        ClientIdentity {
            client_did: pnm.client_did.clone(),
            private_key_multibase: pnm.private_key_multibase.clone(),
            vta_did: vta_did.to_string(),
            verification_method: None,
        },
        token.access_token,
    )
    .await;
    client
        .create_acl(minimal_personal_grant(new_did))
        .await
        .map_err(|e| -> Box<dyn std::error::Error> {
            let why = match &e {
                VtaError::Forbidden(_) => format!(
                    "your pnm identity {} may not grant an unrestricted admin on this VTA \
                     (it is scoped, or the grant needs an approval)",
                    pnm.client_did
                ),
                _ => "the grant failed".to_string(),
            };
            format!(
                "{why}: {e}\n\nAsk the VTA's super-admin to grant it instead:\n{}",
                personal_grant_commands(new_did)
            )
            .into()
        })?;
    Ok(())
}

/// Phase 2b: authenticate the bound personal identity, which rotates it.
///
/// The first authentication of a `PendingRotation` session swaps it for a
/// fresh `did:key` (`acl/swap-key`) and drops the temp DID's entry. Returns the
/// DID the session holds afterwards. On success the personal VTA is complete in
/// `config`; on failure nothing local changes, so `continue` can be re-run once
/// the grant is in place.
pub async fn authenticate_personal(
    config: &mut CnmConfig,
    store: &SessionStore,
    url_override: Option<&str>,
    transport: TransportChoice,
) -> CliResult<String> {
    let (admin_did, vta_did) = match personal_state(config, store) {
        PersonalState::Pending {
            admin_did,
            bound_vta: Some(vta),
        } => (admin_did, vta),
        PersonalState::Pending { .. } => {
            return Err("the VTA DID is required: pass --vta-did <did:...>".into());
        }
        PersonalState::None => return Err("no personal-VTA setup is pending".into()),
        PersonalState::Complete { vta_did } => {
            return Err(format!("the personal VTA ({vta_did}) is already set up").into());
        }
    };
    let client = store
        .connect_with_transport(PERSONAL_KEYRING_KEY, url_override, None, transport)
        .await
        .map_err(|e| personal_auth_guidance(e.as_ref(), &admin_did, &vta_did))?;
    client.shutdown().await;

    let rotated = store
        .loaded_session(PERSONAL_KEYRING_KEY)
        .map(|s| s.client_did)
        .ok_or("the personal session vanished during authentication")?;
    let name = config.personal_vta.as_ref().and_then(|p| p.name.clone());
    config.personal_vta = Some(PersonalVtaConfig {
        vta_did: Some(vta_did),
        name,
    });
    Ok(rotated)
}

/// What to say when the personal VTA did not accept the pending identity.
fn personal_auth_guidance(
    err: &(dyn std::error::Error + 'static),
    admin_did: &str,
    vta_did: &str,
) -> String {
    let refused = err
        .downcast_ref::<VtaError>()
        .is_some_and(VtaError::is_auth);
    let lead = if refused {
        format!("{vta_did} did not accept {admin_did} — the grant is not in place yet.")
    } else {
        format!("could not authenticate to {vta_did} as {admin_did}: {err}")
    };
    format!(
        "{lead}\n\n{}\n\nThen re-run: cnm setup continue\n\n({err})",
        personal_grant_commands(admin_did)
    )
}

// ── Communities ─────────────────────────────────────────────────────

/// The grant routes for a community identity, ready to print.
pub fn community_grant_commands(slug: &str, admin_did: &str) -> String {
    format!(
        "Grant {admin_did} the admin role at the community's VTC — any one of:\n\
         \x20 a. A community not set up yet: in the `vtc setup --from <toml>` file set\n\
         \x20      co_admin_did = \"{admin_did}\"\n\
         \x20 b. On the VTC host, with the daemon stopped:\n\
         \x20      vtc --config <config.toml> acl add --did {admin_did} --role admin --label cnm\n\
         \x20 c. Online, by an existing community administrator:\n\
         \x20      cnm --community <their-profile> access grant {admin_did} --role admin --label cnm\n\
         \x20    or in the admin console: Access control → Add entry (that DID, role admin).\n\
         \x20    A community-wide admin grant made online waits in the action list for a\n\
         \x20    second administrator's approval (`cnm actions list`).\n\n\
         Then: cnm community continue {slug} --vtc-did <vtc-did>"
    )
}

/// Refuse a slug that is already a community, or already pending without
/// `overwrite`.
fn check_new_community_slug(config: &CnmConfig, slug: &str, overwrite: bool) -> CliResult {
    if slug.is_empty() {
        return Err("the community name must produce a non-empty slug".into());
    }
    if config.communities.contains_key(slug) {
        return Err(format!(
            "community '{slug}' is already set up.\n\n\
             Use a different name, or remove it first: cnm community delete {slug}"
        )
        .into());
    }
    if let Some(p) = config.pending_communities.get(slug)
        && !overwrite
    {
        return Err(format!(
            "community '{slug}' is already pending (admin DID: {}).\n\n\
             Finish it with `cnm community continue {slug} --vtc-did <did>`, or pass \
             --overwrite to mint a fresh identity.",
            p.admin_did
        )
        .into());
    }
    Ok(())
}

/// What a new community's identity is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommunityIdentity {
    /// Mint a fresh `did:key` for this community alone. The default.
    Fresh,
    /// Use the identity of the community named — explicitly, because the
    /// shared key links the two communities to anyone who sees both ACLs.
    Reuse { from: String },
}

/// Phase 1 of a community: give it an identity and park it as pending.
///
/// Returns the admin DID the operator needs granted.
#[allow(clippy::too_many_arguments)]
pub fn begin_community(
    config: &mut CnmConfig,
    store: &SessionStore,
    name: &str,
    slug: &str,
    identity: &CommunityIdentity,
    vtc_did: Option<&str>,
    vta_did: Option<&str>,
    overwrite: bool,
) -> CliResult<String> {
    check_new_community_slug(config, slug, overwrite)?;
    let vtc_did = vtc_did.map(|d| require_did("VTC DID", d)).transpose()?;
    let vta_did = vta_did
        .map(|d| require_did("community VTA DID", d))
        .transpose()?;

    let (did, key) = match identity {
        CommunityIdentity::Fresh => mint(),
        CommunityIdentity::Reuse { from } => {
            if from == slug {
                return Err("a community cannot reuse its own identity".into());
            }
            if !config.communities.contains_key(from) {
                return Err(format!(
                    "no confirmed community '{from}' to reuse an identity from.\n\n\
                     `cnm community list` shows them."
                )
                .into());
            }
            let s = store
                .loaded_session(&community_keyring_key(from))
                .ok_or_else(|| format!("community '{from}' has no stored identity to reuse"))?;
            (s.client_did, s.private_key_multibase)
        }
    };
    // Held with no VTA DID: a community identity is confirmed at the VTC, and
    // the binding to a community VTA (if there is one) is made at `continue`.
    store.store_pending_vta_binding(&community_keyring_key(slug), &did, &key)?;
    config.pending_communities.insert(
        slug.to_string(),
        PendingCommunity {
            name: name.to_string(),
            admin_did: did.clone(),
            vtc_did,
            vta_did,
        },
    );
    Ok(did)
}

/// Phase 2 of a community: confirm the grant at the VTC and promote it.
///
/// Authenticates to the VTC as the pending identity — which only succeeds once
/// an administrator has granted it — then moves the community from pending to
/// configured. On a refusal nothing local changes; the error carries the grant
/// commands. Then the identity is rotated at the VTC (module docs); a rotation
/// that fails leaves the confirmed, minted key in place and says why.
pub async fn continue_community(
    config: &mut CnmConfig,
    store: &SessionStore,
    slug: &str,
    vtc_did: Option<&str>,
    vta_did: Option<&str>,
    url: Option<&str>,
) -> CliResult<CommunityConfirmed> {
    let pending = config
        .pending_communities
        .get(slug)
        .cloned()
        .ok_or_else(|| {
            if config.communities.contains_key(slug) {
                format!("community '{slug}' is already set up; nothing to continue.")
            } else {
                format!(
                    "no pending community '{slug}'.\n\n\
                 Start one with `cnm community add {slug}`; `cnm community list` shows \
                 what is configured."
                )
            }
        })?;
    let key = community_keyring_key(slug);
    let session = store.loaded_session(&key).ok_or_else(|| {
        format!(
            "community '{slug}' is pending but its key is missing from the session store \
             (was the keyring cleared?).\n\n\
             Mint a fresh identity: cnm community add \"{}\" --overwrite",
            pending.name
        )
    })?;

    let vtc_did = match vtc_did.or(pending.vtc_did.as_deref()) {
        Some(d) => require_did("VTC DID", d)?,
        None => {
            return Err(format!(
                "the community's VTC DID is needed to confirm the grant.\n\n\
                 Run: cnm community continue {slug} --vtc-did <vtc-did>\n\
                 (the DID `vtc setup` printed as `VTC DID`)"
            )
            .into());
        }
    };
    let vta_did = vta_did
        .map(|d| require_did("community VTA DID", d))
        .transpose()?
        .or(pending.vta_did.clone());

    let target = crate::vtc::resolve_target(Some(&vtc_did), url).await?;
    // A rotation an earlier `continue` committed but did not finish recording.
    let session = match recover_rotation(store, &key, &target).await? {
        Some(_) => store
            .loaded_session(&key)
            .ok_or("the recovered identity vanished from the session store")?,
        None => session,
    };
    crate::vtc::confirm_identity(&target, &session.client_did, &session.private_key_multibase)
        .await
        .map_err(|e| {
            format!(
                "{e}\n\n{}",
                community_grant_commands(slug, &session.client_did)
            )
        })?;

    // Remote effect confirmed; now commit locally. With a community VTA the
    // session is bound to it directly — not for rotation, which would move the
    // key the VTC just accepted out from under it.
    if let Some(vta) = &vta_did {
        store.store_direct(
            &key,
            &session.client_did,
            &session.private_key_multibase,
            vta,
        )?;
    }
    let context_id = None;
    config.pending_communities.remove(slug);
    config.communities.insert(
        slug.to_string(),
        CommunityConfig {
            name: pending.name,
            context_id,
            vta_did: vta_did.clone(),
            vtc_did: Some(vtc_did),
        },
    );
    if config.default_community.is_none() {
        config.default_community = Some(slug.to_string());
    }
    let rotation =
        match rotation_blocker(config, store, slug, &session.client_did, vta_did.as_deref()) {
            Some(reason) => Rotation::Skipped(reason),
            None => match rotate_identity(
                store,
                &key,
                &target,
                &session.client_did,
                &session.private_key_multibase,
            )
            .await
            {
                Ok(to) => Rotation::Rotated {
                    from: session.client_did.clone(),
                    to,
                },
                Err(e) => Rotation::Failed(e.to_string()),
            },
        };
    let did = match &rotation {
        Rotation::Rotated { to, .. } => to.clone(),
        _ => session.client_did,
    };
    Ok(CommunityConfirmed { did, rotation })
}

/// What `continue_community` confirmed: the DID cnm now authenticates to the
/// community as, and what became of the rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityConfirmed {
    pub did: String,
    pub rotation: Rotation,
}

/// What a community identity's rotation at its VTC came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rotation {
    /// The VTC moved the entry onto a fresh key.
    Rotated { from: String, to: String },
    /// Not attempted, and why: the key is also held where the swap does not
    /// reach.
    Skipped(String),
    /// Attempted and refused; the previous key is still the one in use.
    Failed(String),
}

/// Why a community identity must not be rotated at its VTC alone, if it must
/// not: its key is bound to a community VTA, or shared with another community.
fn rotation_blocker(
    config: &CnmConfig,
    store: &SessionStore,
    slug: &str,
    did: &str,
    vta_did: Option<&str>,
) -> Option<String> {
    if let Some(vta) = vta_did {
        return Some(format!(
            "this identity is bound to the community VTA {vta}, whose ACL entry the VTC's swap \
             does not move; rotating at the VTC alone would strand it there"
        ));
    }
    let shared = config
        .communities
        .keys()
        .chain(config.pending_communities.keys())
        .filter(|s| s.as_str() != slug)
        .find(|s| {
            store
                .loaded_session(&community_keyring_key(s))
                .is_some_and(|o| o.client_did == did)
        });
    shared.map(|other| {
        format!(
            "this identity is shared with community '{other}' (--reuse-identity); rotating it \
             here would leave '{other}' holding a key the VTC no longer accepts"
        )
    })
}

/// The session-store slot a rotation's new key waits in until the VTC has
/// accepted it.
fn rotation_slot(keyring_key: &str) -> String {
    format!("{keyring_key}.rotating")
}

/// Roll the identity stored under `keyring_key` onto a fresh `did:key` at
/// `target` (`acl/swap-key/0.1`). Returns the new DID.
///
/// Ordering (VTI-CLT-033 – 035): mint; write the new key to the side slot;
/// send the swap; only once the VTC accepts it, write the new key over the
/// identity and drop the slot. A refusal drops the slot and leaves the old
/// key — still the authoritative one — exactly as it was.
async fn rotate_identity(
    store: &SessionStore,
    keyring_key: &str,
    target: &crate::vtc::VtcTarget,
    old_did: &str,
    old_key: &str,
) -> CliResult<String> {
    let (new_did, new_key) = mint();
    let slot = rotation_slot(keyring_key);
    store.store_pending_vta_binding(&slot, &new_did, &new_key)?;
    if let Err(e) = crate::vtc::swap_key(target, old_did, old_key, &new_did, &new_key).await {
        store.logout(&slot);
        return Err(e);
    }
    store.store_pending_vta_binding(keyring_key, &new_did, &new_key)?;
    store.logout(&slot);
    Ok(new_did)
}

/// Finish a rotation a crash interrupted: a new key left in the side slot is
/// adopted when the VTC accepts it (the swap committed), and discarded when it
/// does not (it never did). Returns the adopted DID.
pub async fn recover_rotation(
    store: &SessionStore,
    keyring_key: &str,
    target: &crate::vtc::VtcTarget,
) -> CliResult<Option<String>> {
    let slot = rotation_slot(keyring_key);
    let Some(waiting) = store.loaded_session(&slot) else {
        return Ok(None);
    };
    let accepted =
        crate::vtc::confirm_identity(target, &waiting.client_did, &waiting.private_key_multibase)
            .await
            .is_ok();
    if accepted {
        store.store_pending_vta_binding(
            keyring_key,
            &waiting.client_did,
            &waiting.private_key_multibase,
        )?;
    }
    store.logout(&slot);
    Ok(accepted.then_some(waiting.client_did))
}

/// `cnm community rotate <slug>`: roll a configured community's identity at
/// its VTC onto a fresh key. Refused for an identity bound to a community VTA
/// or shared with another community (module docs). Returns `(from, to)`.
pub async fn rotate_community(
    config: &CnmConfig,
    store: &SessionStore,
    slug: &str,
    vtc_did: Option<&str>,
    url: Option<&str>,
) -> CliResult<(String, String)> {
    let community = config.communities.get(slug).ok_or_else(|| {
        format!("no configured community '{slug}'; `cnm community list` shows them")
    })?;
    let key = community_keyring_key(slug);
    let vtc_did = vtc_did
        .map(str::to_string)
        .or_else(|| community.vtc_did.clone())
        .ok_or_else(|| {
            format!(
                "community '{slug}' names no VTC. Record it with `cnm community set-vtc <did>` \
                 or pass --vtc-did"
            )
        })?;
    let target = crate::vtc::resolve_target(Some(&vtc_did), url).await?;
    recover_rotation(store, &key, &target).await?;
    let session = store
        .loaded_session(&key)
        .ok_or_else(|| format!("community '{slug}' has no stored identity"))?;
    if let Some(reason) = rotation_blocker(
        config,
        store,
        slug,
        &session.client_did,
        community.vta_did.as_deref(),
    ) {
        return Err(format!("not rotating: {reason}").into());
    }
    let new_did = rotate_identity(
        store,
        &key,
        &target,
        &session.client_did,
        &session.private_key_multibase,
    )
    .await?;
    Ok((session.client_did, new_did))
}

/// `did:key:z6MkhaXg…uQ` — enough of a DID to tell two apart in a list.
pub fn short_did(did: &str) -> String {
    let chars: Vec<char> = did.chars().collect();
    if chars.len() <= 24 {
        return did.to_string();
    }
    let head: String = chars[..16].iter().collect();
    let tail: String = chars[chars.len() - 6..].iter().collect();
    format!("{head}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::session::testing::InMemorySessionBackend;

    fn store() -> SessionStore {
        SessionStore::with_backend(Box::new(InMemorySessionBackend::new()))
    }

    const VTA: &str = "did:webvh:QmPersonal:vta.example.com";

    // ── personal ────────────────────────────────────────────────────

    #[test]
    fn the_personal_cold_start_parks_a_minted_key_and_survives_a_reload() {
        let store = store();
        let mut config = CnmConfig::default();
        let did = begin_personal(&mut config, &store, "home", false).unwrap();
        assert!(did.starts_with("did:key:z6Mk"), "{did}");

        // The config the caller saves records the pending setup by name …
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let reloaded: CnmConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(
            reloaded.personal_vta.as_ref().unwrap().name.as_deref(),
            Some("home")
        );
        assert!(reloaded.personal_vta.as_ref().unwrap().vta_did.is_none());
        // … and the key is in the session store, unbound.
        assert_eq!(
            personal_state(&reloaded, &store),
            PersonalState::Pending {
                admin_did: did,
                bound_vta: None
            }
        );
    }

    #[test]
    fn a_pending_personal_setup_is_kept_unless_overwritten() {
        let store = store();
        let mut config = CnmConfig::default();
        let first = begin_personal(&mut config, &store, "home", false).unwrap();
        let err = begin_personal(&mut config, &store, "home", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains(&first) && err.contains("--overwrite"), "{err}");
        let second = begin_personal(&mut config, &store, "home", true).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn a_complete_personal_vta_is_never_overwritten() {
        let store = store();
        let mut config = CnmConfig {
            personal_vta: Some(PersonalVtaConfig {
                vta_did: Some(VTA.into()),
                name: None,
            }),
            ..Default::default()
        };
        let err = begin_personal(&mut config, &store, "x", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already set up"), "{err}");
    }

    #[test]
    fn binding_is_idempotent_for_the_same_vta_and_refuses_another() {
        let store = store();
        let mut config = CnmConfig::default();
        begin_personal(&mut config, &store, "home", false).unwrap();
        assert!(
            bind_personal(&config, &store, None)
                .unwrap_err()
                .to_string()
                .contains("--vta-did")
        );
        assert_eq!(bind_personal(&config, &store, Some(VTA)).unwrap(), VTA);
        // Re-running continue (the grant was late) needs no DID again.
        assert_eq!(bind_personal(&config, &store, None).unwrap(), VTA);
        assert_eq!(bind_personal(&config, &store, Some(VTA)).unwrap(), VTA);
        let err = bind_personal(&config, &store, Some("did:web:other"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("already bound"), "{err}");
    }

    #[test]
    fn continue_checks_the_name_it_was_given() {
        let store = store();
        let mut config = CnmConfig::default();
        begin_personal(&mut config, &store, "Home VTA", false).unwrap();
        assert!(check_personal_name(&config, Some("home-vta")).is_ok());
        assert!(check_personal_name(&config, None).is_ok());
        let err = check_personal_name(&config, Some("work"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cnm setup continue Home VTA"), "{err}");
    }

    #[test]
    fn the_grant_cnm_asks_of_pnm_is_an_unrestricted_admin_labelled_as_cnms() {
        let req = minimal_personal_grant("did:key:z6MkCnm");
        assert_eq!(req.did, "did:key:z6MkCnm");
        assert_eq!(req.role, "admin");
        // Unrestricted: `contexts/create` of a top-level context is super-admin.
        assert!(req.allowed_contexts.is_empty());
        assert!(req.capabilities.is_empty());
        assert!(req.label.unwrap().contains("cnm"));
        assert!(req.expires_at.is_none());
    }

    /// A mock VTA that issues a challenge and refuses the authenticate step.
    async fn refusing_vta() -> wiremock::MockServer {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/trust-tasks"))
            .and(body_string_contains("auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": "c2VjcmV0LWNoYWxsZW5nZQ",
                "sessionId": "s-1",
                "expiresAt": "2099-01-01T00:00:00Z",
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/trust-tasks"))
            .and(body_string_contains("auth/authenticate"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "unauthorized", "message": "unknown DID"
            })))
            .mount(&server)
            .await;
        server
    }

    /// `continue` against a VTA that has not granted the key yet: the error
    /// prints the grant commands for the pending DID, and the setup stays
    /// pending and bound, so re-running `continue` later is all it takes.
    #[tokio::test]
    async fn continue_before_the_grant_names_the_fix_and_stays_resumable() {
        let server = refusing_vta().await;
        let store = store();
        let mut config = CnmConfig::default();
        let did = begin_personal(&mut config, &store, "home", false).unwrap();
        bind_personal(&config, &store, Some(VTA)).unwrap();

        let err = authenticate_personal(
            &mut config,
            &store,
            Some(&server.uri()),
            TransportChoice::Rest,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(&format!("vta import-did --did {did} --role admin")),
            "{err}"
        );
        assert!(
            err.contains(&format!("pnm acl create --did {did} --role admin")),
            "{err}"
        );
        assert!(err.contains("cnm setup continue"), "{err}");

        assert_eq!(
            personal_state(&config, &store),
            PersonalState::Pending {
                admin_did: did,
                bound_vta: Some(VTA.into())
            }
        );
    }

    #[tokio::test]
    async fn a_pnm_grant_that_cannot_sign_in_points_at_the_other_routes() {
        let server = refusing_vta().await;
        let (pnm_did, pnm_key) = mint();
        let pnm = SessionInfo {
            client_did: pnm_did,
            vta_did: Some(VTA.into()),
            private_key_multibase: pnm_key,
        };
        let err = grant_from_pnm(&pnm, VTA, &server.uri(), "did:key:z6MkNew")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("pnm health"), "{err}");
        assert!(
            err.contains("vta import-did --did did:key:z6MkNew --role admin"),
            "{err}"
        );
    }

    // ── communities ─────────────────────────────────────────────────

    #[test]
    fn two_communities_get_two_distinct_identities() {
        let store = store();
        let mut config = CnmConfig::default();
        let a = begin_community(
            &mut config,
            &store,
            "Alpha",
            "alpha",
            &CommunityIdentity::Fresh,
            None,
            None,
            false,
        )
        .unwrap();
        let b = begin_community(
            &mut config,
            &store,
            "Beta",
            "beta",
            &CommunityIdentity::Fresh,
            None,
            None,
            false,
        )
        .unwrap();
        assert_ne!(a, b);
        let ka = store
            .loaded_session(&community_keyring_key("alpha"))
            .unwrap();
        let kb = store
            .loaded_session(&community_keyring_key("beta"))
            .unwrap();
        assert_eq!(ka.client_did, a);
        assert_eq!(kb.client_did, b);
        assert_ne!(ka.private_key_multibase, kb.private_key_multibase);
        // Pending communities are not selectable yet.
        assert!(config.communities.is_empty());
        assert!(crate::config::resolve_community(Some("alpha"), &config).is_err());
    }

    #[test]
    fn selection_by_community_picks_that_communitys_identity() {
        let store = store();
        let mut config = CnmConfig::default();
        for slug in ["alpha", "beta"] {
            let (did, key) = mint();
            store
                .store_direct(&community_keyring_key(slug), &did, &key, "did:web:vta")
                .unwrap();
            config.communities.insert(
                slug.into(),
                CommunityConfig {
                    name: slug.into(),
                    context_id: None,
                    vta_did: None,
                    vtc_did: Some(format!("did:web:{slug}")),
                },
            );
        }
        config.default_community = Some("alpha".into());
        let did_of = |c: Option<&str>| {
            let (slug, _) = crate::config::resolve_community(c, &config).unwrap();
            store
                .loaded_session(&community_keyring_key(&slug))
                .unwrap()
                .client_did
        };
        assert_ne!(did_of(None), did_of(Some("beta")));
        assert_eq!(did_of(None), did_of(Some("alpha")));
    }

    #[test]
    fn reusing_an_identity_takes_an_explicit_source() {
        let store = store();
        let mut config = CnmConfig::default();
        // No confirmed community to reuse from: refused.
        let err = begin_community(
            &mut config,
            &store,
            "Beta",
            "beta",
            &CommunityIdentity::Reuse {
                from: "alpha".into(),
            },
            None,
            None,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no confirmed community 'alpha'"), "{err}");

        let (did, key) = mint();
        store
            .store_direct(&community_keyring_key("alpha"), &did, &key, "did:web:vta")
            .unwrap();
        config.communities.insert(
            "alpha".into(),
            CommunityConfig {
                name: "Alpha".into(),
                context_id: None,
                vta_did: None,
                vtc_did: None,
            },
        );
        // The default is a fresh key, never alpha's.
        let fresh = begin_community(
            &mut config,
            &store,
            "Gamma",
            "gamma",
            &CommunityIdentity::Fresh,
            None,
            None,
            false,
        )
        .unwrap();
        assert_ne!(fresh, did);
        // Only when asked for by name is the key shared.
        let reused = begin_community(
            &mut config,
            &store,
            "Beta",
            "beta",
            &CommunityIdentity::Reuse {
                from: "alpha".into(),
            },
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(reused, did);
    }

    #[test]
    fn a_community_slug_is_not_minted_twice() {
        let store = store();
        let mut config = CnmConfig::default();
        let add = |config: &mut CnmConfig, overwrite| {
            begin_community(
                config,
                &store,
                "Alpha",
                "alpha",
                &CommunityIdentity::Fresh,
                Some("did:web:vtc"),
                None,
                overwrite,
            )
        };
        let first = add(&mut config, false).unwrap();
        let err = add(&mut config, false).unwrap_err().to_string();
        assert!(err.contains(&first) && err.contains("--overwrite"), "{err}");
        assert_ne!(add(&mut config, true).unwrap(), first);
        assert!(
            begin_community(
                &mut config,
                &store,
                "x",
                "x",
                &CommunityIdentity::Fresh,
                Some("not-a-did"),
                None,
                false
            )
            .is_err()
        );
    }

    async fn mock_vtc(accept: bool) -> wiremock::MockServer {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/trust-tasks"))
            .and(body_string_contains("auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": "c2VjcmV0LWNoYWxsZW5nZQ",
                "sessionId": "s-1",
                "expiresAt": "2099-01-01T00:00:00Z",
            })))
            .mount(&server)
            .await;
        let authenticate = if accept {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "session": {
                    "id": "sess", "subject": "did:key:z6MkHolder",
                    "issuedAt": "2026-01-01T00:00:00Z", "expiresAt": "2099-12-31T23:59:59Z",
                    "amr": ["did"], "acr": "aal1"
                },
                "tokens": { "accessToken": "acc", "tokenType": "Bearer", "expiresIn": 900_u64 }
            }))
        } else {
            ResponseTemplate::new(403).set_body_string("forbidden")
        };
        Mock::given(method("POST"))
            .and(path("/v1/trust-tasks"))
            .and(body_string_contains("auth/authenticate"))
            .respond_with(authenticate)
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn continue_before_the_vtc_grant_keeps_the_community_pending() {
        let server = mock_vtc(false).await;
        let store = store();
        let mut config = CnmConfig::default();
        let did = begin_community(
            &mut config,
            &store,
            "Alpha",
            "alpha",
            &CommunityIdentity::Fresh,
            Some("did:webvh:QmVtc:vtc.example.com"),
            None,
            false,
        )
        .unwrap();
        let base = format!("{}/v1", server.uri());
        let err = continue_community(&mut config, &store, "alpha", None, None, Some(&base))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!("acl add --did {did} --role admin")),
            "{err}"
        );
        assert!(err.contains(&format!("co_admin_did = \"{did}\"")), "{err}");
        assert!(err.contains("cnm community continue alpha"), "{err}");
        assert!(config.pending_communities.contains_key("alpha"));
        assert!(config.communities.is_empty());
    }

    #[tokio::test]
    async fn continue_after_the_grant_promotes_the_community_with_its_own_key() {
        let server = mock_vtc(true).await;
        let store = store();
        let mut config = CnmConfig::default();
        let did = begin_community(
            &mut config,
            &store,
            "Alpha",
            "alpha",
            &CommunityIdentity::Fresh,
            None,
            None,
            false,
        )
        .unwrap();
        let base = format!("{}/v1", server.uri());
        // No VTC DID anywhere yet: the error says how to give one.
        let err = continue_community(&mut config, &store, "alpha", None, None, Some(&base))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("--vtc-did"), "{err}");

        let confirmed = continue_community(
            &mut config,
            &store,
            "alpha",
            Some("did:webvh:QmVtc:vtc.example.com"),
            Some("did:webvh:QmCommunityVta:vta.example.com"),
            Some(&base),
        )
        .await
        .unwrap();
        // Bound to a community VTA, whose own entry the VTC's swap would not
        // move: the minted key is kept, and the reason said.
        assert_eq!(confirmed.did, did);
        assert!(
            matches!(&confirmed.rotation, Rotation::Skipped(why) if why.contains("community VTA")),
            "{:?}",
            confirmed.rotation
        );
        assert!(config.pending_communities.is_empty());
        let c = &config.communities["alpha"];
        assert_eq!(
            c.vtc_did.as_deref(),
            Some("did:webvh:QmVtc:vtc.example.com")
        );
        assert_eq!(
            c.vta_did.as_deref(),
            Some("did:webvh:QmCommunityVta:vta.example.com")
        );
        assert_eq!(config.default_community.as_deref(), Some("alpha"));
        let s = store
            .loaded_session(&community_keyring_key("alpha"))
            .unwrap();
        assert_eq!(s.client_did, did);
        assert_eq!(
            s.vta_did.as_deref(),
            Some("did:webvh:QmCommunityVta:vta.example.com")
        );
        // And now it is selectable.
        assert!(crate::config::resolve_community(Some("alpha"), &config).is_ok());
        // Nothing left to continue.
        assert!(
            continue_community(&mut config, &store, "alpha", None, None, Some(&base))
                .await
                .unwrap_err()
                .to_string()
                .contains("already set up")
        );
    }

    /// Answer `acl/swap-key/0.1` on `server`: success (`accept`), or the
    /// refusal a VTC sends when the link proof does not verify.
    async fn mock_swap(server: &wiremock::MockServer, accept: bool) {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, ResponseTemplate};
        let reply = if accept {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "urn:uuid:22222222-2222-2222-2222-222222222222",
                "type": "https://trusttasks.org/spec/acl/swap-key/0.1#response",
                "payload": {
                    "entry": { "subject": "did:key:z6MkNew", "role": "admin" },
                    "previousSubject": "did:key:z6MkOld",
                },
            }))
        } else {
            ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "id": "urn:uuid:33333333-3333-3333-3333-333333333333",
                "type": "https://trusttasks.org/spec/trust-task-error/0.5",
                "payload": {
                    "code": "acl/swap-key:linkProofInvalid",
                    "message": "the link proof is not signed by newSubject",
                    "retryable": false,
                },
            }))
        };
        Mock::given(method("POST"))
            .and(path("/v1/trust-tasks"))
            .and(body_string_contains("acl/swap-key"))
            .respond_with(reply)
            .mount(server)
            .await;
    }

    /// The `acl/swap-key` document the mock VTC received, if any.
    async fn swap_document(server: &wiremock::MockServer) -> Option<serde_json::Value> {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(|r| serde_json::from_slice::<serde_json::Value>(&r.body).ok())
            .find(|d| {
                d["type"]
                    .as_str()
                    .is_some_and(|t| t.contains("acl/swap-key"))
            })
    }

    fn pending_alpha(store: &SessionStore, config: &mut CnmConfig) -> String {
        begin_community(
            config,
            store,
            "Alpha",
            "alpha",
            &CommunityIdentity::Fresh,
            Some("did:webvh:QmVtc:vtc.example.com"),
            None,
            false,
        )
        .unwrap()
    }

    /// VTI-CLT-025 – 033: with no community VTA bound, `continue` rolls the
    /// granted key onto a fresh one at the VTC — signed by the granted key,
    /// carrying the new key's link proof — and only then stores the new key.
    #[tokio::test]
    async fn continue_rotates_the_granted_key_at_the_vtc() {
        let server = mock_vtc(true).await;
        mock_swap(&server, true).await;
        let store = store();
        let mut config = CnmConfig::default();
        let granted = pending_alpha(&store, &mut config);
        let base = format!("{}/v1", server.uri());
        let confirmed = continue_community(&mut config, &store, "alpha", None, None, Some(&base))
            .await
            .unwrap();
        let Rotation::Rotated { from, to } = &confirmed.rotation else {
            panic!("expected a rotation, got {:?}", confirmed.rotation);
        };
        assert_eq!(from, &granted);
        assert_ne!(to, &granted);
        assert_eq!(&confirmed.did, to);

        let doc = swap_document(&server).await.expect("a swap was sent");
        assert_eq!(doc["payload"]["currentSubject"], granted.as_str());
        assert_eq!(doc["payload"]["newSubject"], to.as_str());
        assert_eq!(doc["issuer"], granted.as_str());
        let proof = doc["payload"]["linkProof"].as_str().expect("a VP-JWT");
        assert_eq!(
            vta_sdk::protocols::acl_management::swap::peek_presentation_holder(proof).unwrap(),
            *to
        );

        let key = community_keyring_key("alpha");
        assert_eq!(&store.loaded_session(&key).unwrap().client_did, to);
        assert!(
            store.loaded_session(&rotation_slot(&key)).is_none(),
            "the side slot is cleared once the VTC accepts"
        );
        assert!(config.communities.contains_key("alpha"));
    }

    /// A refused swap keeps the granted key — still the authoritative one —
    /// and the community is set up regardless; the error says why.
    #[tokio::test]
    async fn a_refused_swap_keeps_the_granted_key() {
        let server = mock_vtc(true).await;
        mock_swap(&server, false).await;
        let store = store();
        let mut config = CnmConfig::default();
        let granted = pending_alpha(&store, &mut config);
        let base = format!("{}/v1", server.uri());
        let confirmed = continue_community(&mut config, &store, "alpha", None, None, Some(&base))
            .await
            .unwrap();
        assert_eq!(confirmed.did, granted);
        assert!(
            matches!(&confirmed.rotation, Rotation::Failed(why) if why.contains("linkProofInvalid")),
            "{:?}",
            confirmed.rotation
        );
        let key = community_keyring_key("alpha");
        assert_eq!(store.loaded_session(&key).unwrap().client_did, granted);
        assert!(store.loaded_session(&rotation_slot(&key)).is_none());
        assert!(config.communities.contains_key("alpha"));
    }

    fn configured(store: &SessionStore, vta_did: Option<&str>) -> (CnmConfig, String) {
        let mut config = CnmConfig::default();
        let (did, key) = mint();
        store
            .store_pending_vta_binding(&community_keyring_key("alpha"), &did, &key)
            .unwrap();
        config.communities.insert(
            "alpha".into(),
            CommunityConfig {
                name: "Alpha".into(),
                context_id: None,
                vta_did: vta_did.map(str::to_string),
                vtc_did: Some("did:webvh:QmVtc:vtc.example.com".into()),
            },
        );
        (config, did)
    }

    /// `cnm community rotate` rolls a configured community's identity the
    /// same way.
    #[tokio::test]
    async fn rotate_rolls_a_configured_community_onto_a_fresh_key() {
        let server = mock_vtc(true).await;
        mock_swap(&server, true).await;
        let store = store();
        let (config, old) = configured(&store, None);
        let base = format!("{}/v1", server.uri());
        let (from, to) = rotate_community(&config, &store, "alpha", None, Some(&base))
            .await
            .unwrap();
        assert_eq!(from, old);
        assert_ne!(to, old);
        let key = community_keyring_key("alpha");
        assert_eq!(store.loaded_session(&key).unwrap().client_did, to);
        let doc = swap_document(&server).await.expect("a swap was sent");
        assert_eq!(doc["payload"]["currentSubject"], old.as_str());
    }

    /// Refused, with nothing sent, for an identity bound to a community VTA or
    /// shared with another community.
    #[tokio::test]
    async fn rotate_refuses_an_identity_held_elsewhere() {
        let server = mock_vtc(true).await;
        mock_swap(&server, true).await;
        let base = format!("{}/v1", server.uri());

        let store_a = store();
        let (config, old) = configured(&store_a, Some("did:webvh:QmVta:vta.example.com"));
        let err = rotate_community(&config, &store_a, "alpha", None, Some(&base))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("community VTA"), "{err}");
        let key = community_keyring_key("alpha");
        assert_eq!(store_a.loaded_session(&key).unwrap().client_did, old);

        let store_b = store();
        let (mut config, shared) = configured(&store_b, None);
        let private = store_b.loaded_session(&key).unwrap().private_key_multibase;
        store_b
            .store_pending_vta_binding(&community_keyring_key("beta"), &shared, &private)
            .unwrap();
        config.communities.insert(
            "beta".into(),
            CommunityConfig {
                name: "Beta".into(),
                context_id: None,
                vta_did: None,
                vtc_did: Some("did:webvh:QmOther:vtc.example.com".into()),
            },
        );
        let err = rotate_community(&config, &store_b, "alpha", None, Some(&base))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("shared with community 'beta'"), "{err}");
        assert!(swap_document(&server).await.is_none(), "nothing was sent");
    }

    /// A rotation the VTC committed but this machine did not finish recording
    /// is adopted from the side slot on the next run (VTI-CLT-033).
    #[tokio::test]
    async fn an_interrupted_rotation_is_adopted() {
        let server = mock_vtc(true).await;
        let store = store();
        let _ = configured(&store, None);
        let (new_did, new_key) = mint();
        let key = community_keyring_key("alpha");
        store
            .store_pending_vta_binding(&rotation_slot(&key), &new_did, &new_key)
            .unwrap();
        let target = crate::vtc::VtcTarget {
            did: "did:webvh:QmVtc:vtc.example.com".into(),
            base: format!("{}/v1", server.uri()),
        };
        let adopted = recover_rotation(&store, &key, &target).await.unwrap();
        assert_eq!(adopted.as_deref(), Some(new_did.as_str()));
        assert_eq!(store.loaded_session(&key).unwrap().client_did, new_did);
        assert!(store.loaded_session(&rotation_slot(&key)).is_none());
    }

    #[test]
    fn json_output_has_pnms_shape() {
        let line = serde_json::to_string(&SetupOutput {
            slug: "alpha",
            admin_did: "did:key:z6MkTest",
            state: "pending",
        })
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["slug"], "alpha");
        assert_eq!(v["admin_did"], "did:key:z6MkTest");
        assert_eq!(v["state"], "pending");
        assert_eq!(v.as_object().unwrap().len(), 3);
    }

    #[test]
    fn short_did_keeps_both_ends() {
        let d = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let s = short_did(d);
        assert!(
            s.starts_with("did:key:z6MkhaXg") && s.ends_with("a2doK"),
            "{s}"
        );
        assert_eq!(short_did("did:key:z6Mk"), "did:key:z6Mk");
    }
}
