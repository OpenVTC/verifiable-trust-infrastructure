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
//! 2. **waives a consent whether or not other administrators' entries exist**
//!    ([`crate::acl::admin_consent::gesture_then_consent_for`]): it is the
//!    host's statement that every administrator is the same person, under as
//!    many identifiers (one per device, say) as they hold, and the node cannot
//!    tell one person's identifiers from two people's, so it does not count
//!    them. It should be on only where that is true (the specification's item
//!    2); an administrator who is in fact someone else sees it in every
//!    session (item 3) and can have it turned off on the host;
//! 3. is **reported to every administrator in every session** — the action
//!    list carries it (`ext.org.openvtc.singleAdminMode` on
//!    `vtc/admin/actions/list`, the signed read the console makes on every
//!    page), and the console shows a permanent banner;
//! 4. is **audited at `Critical`**: when it takes effect or is removed
//!    ([`audit_on_boot`]: `enabled` / `disabled`), at every start with it in
//!    effect (`inEffect`), and for every operation whose consent it waived
//!    (`consentWaived`, [`crate::admin_actions::spend_waiver`]).
//!
//! A reduction of another administrator (VTI-APV-019) is not consented to in
//! the mode either: it takes the unopposed path — the requester's gesture, a
//! notice to the subject, a `Critical` row — and keeps its cooling-off, which
//! is a delay, not a consent: the subject is told, and sees it coming.
//!
//! An administrator whose entry is unrestricted may edit its own entry in the
//! mode (**VTI-ACL-052** item 3, [`authorize_self_edit`]). Design:
//! `docs/05-design-notes/vtc-action-list.md` §8.5.

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

/// The `SingleAdminMode` audit event a sole administrator's edit of its own
/// entry is recorded under (VTI-ACL-052 item 3).
pub const SELF_EDIT_EVENT: &str = "selfEditWaived";

/// What [`authorize_self_edit`] settled to.
#[derive(Debug)]
pub enum SelfEditGate {
    /// The requester's gesture bound to this operation was spent and the
    /// `Critical` row written. Commit the write.
    Authorized,
    /// No gesture yet. A ceremony is parked; refuse with it.
    StepUpRequired(Box<crate::acl::bound_step_up::ApproveRequest>),
}

/// Authorize an unrestricted administrator's edit of its own entry in
/// single-administrator mode — **VTI-ACL-052** item 3.
///
/// The modification MUST be authorized by the subject's re-authentication bound
/// to the operation under VTI-APV-015 — asked for and spent here, the same
/// operation-bound step-up this mode waives a consent on
/// ([`crate::acl::admin_consent::gesture_then_consent_for`]) — and MUST be
/// audited at the node's highest severity: a `Critical` `SingleAdminMode` row
/// ([`SELF_EDIT_EVENT`]) naming the task and its digest, written **before** the
/// write it authorizes, so an unrecorded self-edit cannot land. A failure to
/// audit refuses it.
///
/// Whether the exception applies at all — the mode on, the requester the only
/// unrestricted entry, the result still unrestricted — is decided by
/// [`crate::routes::acl::plan_write`] before this is reached.
pub async fn authorize_self_edit(
    state: &AppState,
    requester: &str,
    op: crate::acl::admin_consent::Operation<'_>,
) -> Result<SelfEditGate, AppError> {
    use crate::acl::bound_step_up::{self, EvidencedGate};
    match bound_step_up::redeem_or_request_with_evidence(
        state,
        requester,
        op.type_uri,
        op.payload,
        "Edit your own ACL entry as an unrestricted administrator (single-administrator \
         mode, VTI-ACL-052)",
    )
    .await?
    {
        EvidencedGate::Required(request) => return Ok(SelfEditGate::StepUpRequired(request)),
        EvidencedGate::Satisfied(_) => {}
    }
    warn!(
        requester,
        task = op.type_uri,
        "an unrestricted administrator edited its own ACL entry — single-administrator \
         mode (VTI-ACL-052 item 3, VTI-APV-022), authorized by its operation-bound step-up"
    );
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                requester,
                Some(requester),
                AuditEvent::SingleAdminMode(SingleAdminModeData {
                    event: SELF_EDIT_EVENT.into(),
                    requirement: Some("VTI-ACL-052".into()),
                    task: Some(op.type_uri.to_string()),
                    digest: Some(vti_common::task_consent::payload_digest(
                        op.type_uri,
                        op.payload,
                    )?),
                    kind: Some("acl.self-edit".into()),
                    ..Default::default()
                }),
            )
            .await?;
    }
    Ok(SelfEditGate::Authorized)
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
                ..Default::default()
            }),
        )
        .await?;
    Ok(())
}
