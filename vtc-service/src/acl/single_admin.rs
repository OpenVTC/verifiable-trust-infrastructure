//! **Single-administrator mode** — **VTI-APV-022**.
//!
//! > A node MAY operate in single-administrator mode, in which an operation
//! > those recommendations cover is authorized by the requester's
//! > re-authentication bound to that operation under VTI-APV-015 in place of
//! > another party's consent, wherever no eligible party other than the
//! > requester exists.
//!
//! Second-party consent (VTI-APV-014, VTI-APV-018 – 020) presupposes a second
//! party. A community run by one person has none, and without this mode its
//! administrator could add a colleague or change an authority rule only through
//! the offline break-glass. The mode, `[acl] single_admin_mode` in
//! `config.toml`:
//!
//! 1. is **host configuration** — written by `vtc setup --single-admin`, or by
//!    editing `config.toml` and restarting; `config/patch` and
//!    `vtc/config/import` refuse the key by name
//!    ([`crate::config_store::host_only_refusal`]), and it is read once at
//!    start;
//! 2. **waives a consent only where nobody but the requester is eligible to
//!    give it** ([`crate::acl::admin_consent::gesture_then_consent_for`]). The
//!    moment a second eligible administrator exists, the operation is parked
//!    for their approval exactly as without the mode;
//! 3. is **reported to every administrator in every session** — the action
//!    list carries it (`ext.org.openvtc.singleAdminMode` on
//!    `vtc/admin/actions/list`, the signed read the console makes on every
//!    page), and the console shows a permanent banner;
//! 4. is **audited at `Critical`**: when it takes effect or is removed
//!    ([`audit_on_boot`]: `enabled` / `disabled`), at every start with it in
//!    effect (`inEffect`), and for every operation whose consent it waived
//!    (`consentWaived`, [`crate::admin_actions::spend_waiver`]).
//!
//! It does **not** change a reduction (VTI-APV-019): that proceeds without
//! another party's consent wherever none exists, with or without the mode, and
//! keeps its cooling-off — the subject of a reduction is another administrator,
//! and removing them at once would be the first step of a two-step way around
//! item 2. Design: `docs/05-design-notes/vtc-action-list.md` §8.5.

use tracing::warn;
use vti_common::audit::{AuditEvent, SingleAdminModeData};
use vti_common::error::AppError;

use crate::server::AppState;

/// Where the mode's value at the last start is kept, to tell a change of host
/// configuration from a restart (`install` keyspace — host state, never backed
/// up or restored).
const LAST_SEEN_KEY: &[u8] = b"install:single_admin_mode";

/// The boot half of VTI-APV-022 item 4: a `Critical` row when the mode's value
/// differs from the last start (`enabled` / `disabled`), and another at every
/// start with it in effect (`inEffect`).
///
/// A first start with the mode off records nothing but the value. Remote-first
/// (CLAUDE.md R2.1): the row is written before the value it is compared against
/// is updated, so a crash between them audits the change again rather than
/// never.
pub async fn audit_on_boot(state: &AppState) -> Result<(), AppError> {
    let on = state.config.read().await.acl.single_admin_mode;
    let last: Option<bool> = state.install_ks.get(LAST_SEEN_KEY.to_vec()).await?;
    let changed = match last {
        Some(was) => was != on,
        // Never recorded: a node that starts with it on has just put it into
        // effect; one that starts with it off has changed nothing.
        None => on,
    };
    if changed {
        warn!(
            enabled = on,
            "single-administrator mode {} by host configuration (VTI-APV-022)",
            if on { "enabled" } else { "disabled" }
        );
        write(state, if on { "enabled" } else { "disabled" }).await?;
    }
    if on {
        warn!(
            "single-administrator mode is in effect (VTI-APV-022): where no administrator but \
             the requester is eligible to consent, the requester's operation-bound step-up \
             authorizes the operation instead"
        );
        write(state, "inEffect").await?;
    }
    if last != Some(on) {
        state.install_ks.insert(LAST_SEEN_KEY.to_vec(), &on).await?;
    }
    Ok(())
}

async fn write(state: &AppState, event: &str) -> Result<(), AppError> {
    let Some(writer) = state.audit_writer.as_ref() else {
        return Ok(());
    };
    writer
        .write(
            "daemon",
            None,
            AuditEvent::SingleAdminMode(SingleAdminModeData {
                event: event.into(),
                requirement: None,
                task: None,
                digest: None,
                kind: None,
            }),
        )
        .await?;
    Ok(())
}
