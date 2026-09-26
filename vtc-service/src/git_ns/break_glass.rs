//! **Break-glass** — separation of duties' escape hatch
//! (`git-ns/right/break-glass/0.1`, `git-ns/right/ratify/0.1`,
//! `git-ns/right/break-glass-notice/0.1`).
//!
//! Fixed rule 7 of `git-ns/right/grant/0.3` forbids anyone granting themselves
//! an elevated right (`git.ns.admin`, `git.repo.create`, `git.repo.own`). This
//! module is the one way to do it anyway, and it is built so that nothing
//! about it is quiet:
//!
//! - **explicit**: its own task, with a mandatory justification;
//! - **step-up**: an operation-bound passkey gesture (aal2, user verification)
//!   is *always* required, bound to this one request by digest
//!   ([`crate::acl::bound_step_up`]). The specification cannot require one
//!   (SPEC §7.3 item 13); this VTC does. Because the real step-up applies, the
//!   `elevated_requires_admin` stand-in ([`super::ops::consent_gate`]) does not;
//! - **immediate, no expiry**: it must work when nobody else is there, so the
//!   right lasts until another administrator ratifies or revokes it;
//! - **visible**: a [`AuditSeverity::Critical`](vti_common::audit::AuditSeverity)
//!   audit row with the justification and the step-up evidence, an activity
//!   entry, a signed notice to every other administrator of the namespace, and
//!   the `breakGlass` flag on every surface that shows the record;
//! - **policy may tighten, never quieten**: the community's `gitNamespace`
//!   policy can disable it, delay its effect or demand a longer justification
//!   ([`super::policy::BreakGlassSettings`]); nothing it says reaches
//!   [`announce`].

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use tracing::{error, info, warn};
use trust_tasks_rs::specs::git_ns::right::{
    break_glass::v0_1 as break_glass, break_glass_notice::v0_1 as notice, ratify::v0_1 as ratify,
};
use vti_common::audit::{AuditEvent, GitNsBreakGlassData};
use vti_common::capability_client::{TRUST_TASK_ENVELOPE_TYPE, build_document};
use vti_common::error::AppError;

use crate::acl::VtcRole;
use crate::acl::bound_step_up::{self, EvidencedGate, StepUpEvidence};
use crate::server::AppState;

use super::model::{BreakGlassMark, Namespace, RepoState, Resource, Right, RightRow, Scope};
use super::ops::{
    self, Audit, BREAK_GLASS_DISABLED, BREAK_GLASS_NOT_HEADLESS, NOT_BREAK_GLASS, OpError,
    OpResult, POLICY_DENIED, PolicyInput, RECORD_CHANGED, REPO_NOT_ACTIVE, SELF_RATIFICATION,
    Standing, audit, declared, now, standing,
};
use super::rules::{self, BreakGlassRefusal};
use super::store::{self, Snapshot};
use super::wire;

/// The type URI a break-glass is served and step-up-bound under.
pub fn break_glass_type() -> &'static str {
    <break_glass::Payload as trust_tasks_rs::Payload>::TYPE_URI
}

/// A `git-ns/right/break-glass-notice` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    BreakGlass,
    Ratified,
    Revoked,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Event::BreakGlass => "breakGlass",
            Event::Ratified => "ratified",
            Event::Revoked => "revoked",
        }
    }
}

/// Whether the namespace is headless: no live `git.ns.admin` record whose
/// subject is a current member (`git-ns/namespace/reseat`, *Definitions*).
pub async fn is_headless(state: &AppState, snap: &Snapshot, ns: &Namespace) -> OpResult<bool> {
    let t = now();
    for row in snap
        .rows(&Scope::Namespace(ns.id.clone()))
        .iter()
        .filter(|r| r.right == Right::NsAdmin && r.is_live(t))
    {
        if standing(state, &row.subject).await?.member {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The administrators of a namespace (`git-ns/right/break-glass/0.1`,
/// *Definitions*): every community administrator, and every live
/// `git.ns.admin` of it — current members only — except `except`, who acted.
///
/// Community policy never reaches this: the audience of a break-glass notice
/// cannot be narrowed (`break-glass-notice/0.1`, producer requirement 2).
pub async fn audience(
    state: &AppState,
    snap: &Snapshot,
    ns: &Namespace,
    except: &str,
) -> OpResult<Vec<String>> {
    let now_epoch = crate::auth::session::now_epoch();
    let mut out = BTreeSet::new();
    for entry in crate::acl::list_acl_entries(&state.acl_ks).await? {
        if entry.role == VtcRole::Admin
            && matches!(entry.act_scope(), vti_common::acl::ActScope::All)
            && !entry.is_expired(now_epoch)
            && standing(state, &entry.did).await?.community_admin
        {
            out.insert(entry.did.clone());
        }
    }
    for did in rules::admins(snap, &ns.id, now()) {
        if standing(state, &did).await?.member {
            out.insert(did);
        }
    }
    out.remove(except);
    Ok(out.into_iter().collect())
}

/// Tell every administrator of the namespace, and write the critical audit
/// row. Returns an error only when the audit row could not be written — which
/// a break-glass treats as fatal (step 9: no response before it is durable)
/// and a ratification or revocation, already done, logs.
#[allow(clippy::too_many_arguments)]
pub(super) async fn announce(
    state: &AppState,
    snap: &Snapshot,
    ns: &Namespace,
    resource: &Resource,
    row: &RightRow,
    event: Event,
    by: &str,
    statement: Option<String>,
    entitlement: Option<rules::BreakGlassEntitlement>,
    step_up: Option<StepUpEvidence>,
    policy_version: Option<u32>,
) -> Result<(), AppError> {
    let Some(mark) = row.break_glass.as_ref() else {
        return Ok(());
    };
    let at = match event {
        Event::BreakGlass => mark.at,
        Event::Ratified => mark.ratified_at.unwrap_or_else(now),
        Event::Revoked => now(),
    };
    let recipients = audience(state, snap, ns, by).await.map_err(|e| match e {
        OpError::Internal(e) => e,
        other => AppError::Internal(other.to_string()),
    })?;
    let payload = notice_payload(ns, resource, row, event, by, at, statement.as_deref())?;
    let mut notified = 0u32;
    let mut undeliverable = Vec::new();
    for did in &recipients {
        match send_notice(state, did, &payload).await {
            Ok(()) => notified += 1,
            Err(e) => {
                warn!(
                    recipient = %did,
                    event = event.as_str(),
                    error = %e,
                    "a break-glass notice could not be queued"
                );
                undeliverable.push(did.clone());
            }
        }
    }
    if recipients.is_empty() {
        warn!(
            namespace = %ns.id,
            event = event.as_str(),
            "a break-glass event had nobody to tell: no other community or namespace administrator"
        );
    }
    let data = GitNsBreakGlassData {
        event: event.as_str().to_string(),
        namespace: ns.id.clone(),
        resource: resource.to_string(),
        right: row.right.as_str().to_string(),
        break_glass_at: mark.at,
        justification: mark.justification.clone(),
        statement,
        effective_at: mark.effective_at,
        entitlement: entitlement.map(|e| e.as_str().to_string()),
        step_up: step_up.map(Into::into),
        policy_version,
        notified,
        undeliverable,
    };
    error!(
        event = event.as_str(),
        actor = %by,
        subject = %row.subject,
        right = %row.right,
        resource = %resource,
        notified,
        "BREAK-GLASS on a git right"
    );
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(by, Some(&row.subject), AuditEvent::GitNsBreakGlass(data))
            .await?;
    }
    Ok(())
}

/// The notice's payload, read back through the generated type so a notice
/// this VTC sends is one the specification admits.
fn notice_payload(
    ns: &Namespace,
    resource: &Resource,
    row: &RightRow,
    event: Event,
    by: &str,
    at: DateTime<Utc>,
    statement: Option<&str>,
) -> Result<Value, AppError> {
    let mut v = json!({
        "event": event.as_str(),
        "namespace": ns.id,
        "record": wire::right_record_full(row, resource, true),
        "by": by,
        "at": wire::timestamp(at),
    });
    if let Some(s) = statement.filter(|s| !s.trim().is_empty()) {
        v["statement"] = json!(s);
    }
    let _checked: notice::Payload = wire::into(v.clone())?;
    Ok(v)
}

/// One signed notice, in the trust-task envelope, queued over the VTC's own
/// mediator connection — as [`crate::ceremony::removal_notice`] sends.
async fn send_notice(state: &AppState, recipient: &str, payload: &Value) -> Result<(), AppError> {
    let vtc_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;
    let signer = state
        .credential_signer
        .as_ref()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;
    let type_uri = <notice::Payload as trust_tasks_rs::Payload>::TYPE_URI;
    let doc = build_document(&vtc_did, recipient, type_uri, payload.clone());
    let mut doc_value = serde_json::to_value(&doc)
        .map_err(|e| AppError::Internal(format!("serialise break-glass notice: {e}")))?;
    signer.sign_doc(&mut doc_value).await?;
    let envelope = affinidi_messaging_didcomm::Message::build(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        TRUST_TASK_ENVELOPE_TYPE.to_string(),
        doc_value,
    )
    .from(vtc_did)
    .to(recipient.to_string())
    .finalize();
    // An administrator who is away still needs to hear of it: the long window.
    state
        .send_to_member_by(
            recipient,
            envelope,
            crate::server::REMOVAL_NOTICE_DELIVER_BY,
        )
        .await?;
    info!(recipient, "break-glass notice queued");
    Ok(())
}

fn non_whitespace_chars(s: &str) -> usize {
    s.chars().filter(|c| !c.is_whitespace()).count()
}

// ── git-ns/right/break-glass/0.1 ────────────────────────────────────────────

/// `git-ns/right/break-glass/0.1`, *Request*, in order.
pub async fn right_break_glass(
    state: &AppState,
    actor_did: &str,
    p: break_glass::Payload,
) -> OpResult<break_glass::Response> {
    let actor = standing(state, actor_did).await?;
    let payload_json = serde_json::to_value(&p).map_err(AppError::from)?;
    let right = Right::parse(payload_json["right"].as_str().unwrap_or_default())
        .ok_or_else(|| OpError::Malformed("`right` is not a git right".into()))?;
    let resource = ops::parse_resource(payload_json["resource"].as_str().unwrap_or_default())?;
    let justification = payload_json["justification"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if justification.trim().is_empty() {
        return Err(OpError::Malformed(
            "a break-glass needs a justification: say why nobody else could grant this".into(),
        ));
    }

    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();
    // Step 2.
    let ns = ops::bound_namespace_for(&snap, &resource)?.clone();
    let scope = if resource.is_namespace() {
        Scope::Namespace(ns.id.clone())
    } else {
        let repo = ops::repo_at(&snap, &resource)?;
        if !matches!(
            repo.state,
            RepoState::Active | RepoState::Orphaned | RepoState::PendingCreate
        ) {
            return Err(declared(
                REPO_NOT_ACTIVE,
                format!("{resource} is {}; it takes no grants", repo.state.as_str()),
            ));
        }
        Scope::Repo(repo.id.clone())
    };
    // Steps 3–5.
    let headless = if resource.is_namespace() {
        is_headless(state, &snap, &ns).await?
    } else {
        false
    };
    let st = super::policy::active_settings(state).await;
    let (passed, entitlement) = rules::break_glass_admitted(
        &snap,
        &actor.did,
        right,
        &resource,
        actor.member,
        actor.community_admin,
        headless,
        st.rules,
        t,
    )
    .map_err(|r| match r {
        BreakGlassRefusal::Rule(r) => OpError::from(r),
        BreakGlassRefusal::NotHeadless(m) => declared(BREAK_GLASS_NOT_HEADLESS, m),
    })?;
    // Step 6 — a record the actor already holds is returned unchanged, and
    // nothing is recorded, audited or announced.
    if let Some(existing) = snap
        .rows(&scope)
        .iter()
        .find(|r| r.subject == actor.did && r.right == right && r.is_recorded(t))
    {
        return Ok(wire::into(json!({
            "right": wire::right_record_full(existing, &resource, true),
        }))?);
    }
    // Step 7 — policy: disable, tighten, defer. Never quieten.
    if !st.break_glass.enabled {
        return Err(declared(
            BREAK_GLASS_DISABLED,
            format!(
                "this community's gitNamespace policy does not allow break-glass; ask another \
                 administrator to grant {right} on {resource}"
            ),
        ));
    }
    if non_whitespace_chars(&justification) < st.break_glass.min_justification_chars {
        return Err(declared(
            POLICY_DENIED,
            format!(
                "this community's policy asks for a justification of at least {} characters",
                st.break_glass.min_justification_chars
            ),
        ));
    }
    let version = ops::check_policy(
        state,
        PolicyInput {
            action: "right.breakGlass",
            actor: &actor,
            actor_rights: rules::effective_on(&snap, &actor.did, &resource, t)
                .into_iter()
                .collect(),
            resource: &resource,
            right: Some(right),
            subject: Some((
                &actor,
                rules::effective_on(&snap, &actor.did, &resource, t)
                    .into_iter()
                    .collect(),
            )),
            visibility: None,
            expires_at: None,
            namespace: Some(&ns),
            passed,
        },
    )
    .await?;

    // The step-up, after every check that decides whether the act is allowed
    // and before anything is written (`bound_step_up`): a passkey gesture
    // bound to this one document, from the acting member's own passkey.
    let reason = format!(
        "BREAK GLASS: give yourself {right} on {resource}. Every other administrator will be \
         told, with your justification."
    );
    let evidence = match bound_step_up::redeem_or_request_with_evidence(
        state,
        &actor.did,
        break_glass_type(),
        &payload_json,
        &reason,
    )
    .await?
    {
        EvidencedGate::Satisfied(e) => e,
        EvidencedGate::Required(request) => {
            return Err(OpError::StepUpRequired {
                message: "a passkey gesture bound to this break-glass is required".into(),
                request,
            });
        }
    };

    // Step 8.
    let effective_at = (st.break_glass.delay_seconds > 0)
        .then(|| t + Duration::seconds(st.break_glass.delay_seconds as i64));
    let mut set = store::get_rights(&state.git_ns.ks, &scope).await?;
    set.rows
        .retain(|r| !(r.subject == actor.did && r.right == right));
    let mut row = ops::new_row(&actor.did, right, &actor.did, actor.member);
    row.granter_was_member = actor.member;
    row.break_glass = Some(BreakGlassMark {
        by: actor.did.clone(),
        at: t,
        justification: justification.clone(),
        effective_at,
        ratified_by: None,
        ratified_at: None,
    });
    let before = store::get_rights(&state.git_ns.ks, &scope).await?;
    set.rows.push(row.clone());
    store::put_rights(&state.git_ns.ks, &scope, &set).await?;
    if let Scope::Repo(id) = &scope
        && right == Right::RepoOwn
        && effective_at.is_none()
        && let Some(mut repo) = snap.repo(id).cloned()
        && repo.state == RepoState::Orphaned
    {
        repo.state = RepoState::Active;
        store::put_repo(&state.git_ns.ks, &repo).await?;
    }

    // Steps 9 and 10. The critical row must be durable before the response;
    // if it cannot be written, the break-glass is undone rather than left
    // unaudited.
    let after = Snapshot::load(&state.git_ns.ks).await?;
    if let Err(e) = announce(
        state,
        &after,
        &ns,
        &resource,
        &row,
        Event::BreakGlass,
        &actor.did,
        None,
        Some(entitlement),
        Some(evidence),
        version,
    )
    .await
    {
        error!(error = %e, "the break-glass audit row could not be written; undoing the break-glass");
        store::put_rights(&state.git_ns.ks, &scope, &before).await?;
        return Err(OpError::Internal(e));
    }
    audit(
        state,
        &actor.did,
        Some(&actor.did),
        Audit {
            action: "gitNs.right.breakGlass",
            namespace: Some(&ns.id),
            resource: Some(resource.to_string()),
            right: Some(right),
            policy_version: version,
            detail: Some(
                if effective_at.is_some() {
                    "delayed"
                } else {
                    "immediate"
                }
                .into(),
            ),
        },
    )
    .await;
    Ok(wire::into(json!({
        "right": wire::right_record_full(&row, &resource, true),
    }))?)
}

// ── git-ns/right/ratify/0.1 ─────────────────────────────────────────────────

/// `git-ns/right/ratify/0.1`, *Request*, in order.
pub async fn right_ratify(
    state: &AppState,
    actor_did: &str,
    p: ratify::Payload,
) -> OpResult<ratify::Response> {
    let actor: Standing = standing(state, actor_did).await?;
    let pj = serde_json::to_value(&p).map_err(AppError::from)?;
    let right = Right::parse(pj["right"].as_str().unwrap_or_default())
        .ok_or_else(|| OpError::Malformed("`right` is not a git right".into()))?;
    let resource = ops::parse_resource(pj["resource"].as_str().unwrap_or_default())?;
    let subject = pj["subject"].as_str().unwrap_or_default().to_string();
    ops::did_core("subject", &subject)?;
    let read_at = p.break_glass_at;
    let statement = p.statement.as_ref().map(|s| s.to_string());

    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let t = now();
    let not_bg = || {
        declared(
            NOT_BREAK_GLASS,
            format!(
                "no unratified break-glass record gives {subject} {right} on {resource}: there is \
                 none, it was never a break-glass, or it is already ratified"
            ),
        )
    };
    // Step 1.
    let scope = ops::scope_for(&snap, &resource)?.ok_or_else(not_bg)?;
    let row = snap
        .rows(&scope)
        .iter()
        .find(|r| {
            r.subject == subject
                && r.right == right
                && r.is_recorded(t)
                && r.is_unratified_break_glass()
        })
        .cloned()
        .ok_or_else(not_bg)?;
    let mark = row.break_glass.clone().ok_or_else(not_bg)?;
    // Step 2 — bound to the break-glass the ratifier read.
    if wire::timestamp(mark.at) != wire::timestamp(read_at) {
        return Err(declared(
            RECORD_CHANGED,
            format!(
                "the break-glass on record was made at {}, not {}; read it and its \
                 justification again before ratifying",
                wire::timestamp(mark.at),
                wire::timestamp(read_at)
            ),
        ));
    }
    // Step 3.
    if subject == actor.did {
        return Err(declared(
            SELF_RATIFICATION,
            "a break-glass is ratified by another administrator, or not at all",
        ));
    }
    let st = super::policy::active_settings(state).await;
    let passed = rules::ratify_admitted(
        &snap,
        &actor.did,
        &row,
        &resource,
        actor.community_admin,
        st.rules,
        t,
    )?;
    ops::consent_gate(state, &actor, "right.grant", Some(right)).await?;
    let ns = snap.scope_namespace(&scope).cloned().ok_or_else(not_bg)?;
    // Step 4.
    let subject_standing = standing(state, &subject).await?;
    let version = ops::check_policy(
        state,
        PolicyInput {
            action: "right.ratify",
            actor: &actor,
            actor_rights: rules::effective_on(&snap, &actor.did, &resource, t)
                .into_iter()
                .collect(),
            resource: &resource,
            right: Some(right),
            subject: Some((&subject_standing, vec![right])),
            visibility: None,
            expires_at: None,
            namespace: Some(&ns),
            passed,
        },
    )
    .await?;
    // Step 5.
    let mut set = store::get_rights(&state.git_ns.ks, &scope).await?;
    let Some(stored) = set
        .rows
        .iter_mut()
        .find(|r| r.subject == subject && r.right == right && r.is_unratified_break_glass())
    else {
        return Err(not_bg());
    };
    if let Some(m) = stored.break_glass.as_mut() {
        m.ratified_by = Some(actor.did.clone());
        m.ratified_at = Some(t);
    }
    let ratified = stored.clone();
    store::put_rights(&state.git_ns.ks, &scope, &set).await?;
    // Step 6.
    let after = Snapshot::load(&state.git_ns.ks).await?;
    if let Err(e) = announce(
        state,
        &after,
        &ns,
        &resource,
        &ratified,
        Event::Ratified,
        &actor.did,
        statement,
        None,
        None,
        version,
    )
    .await
    {
        error!(error = %e, "the ratification's audit row could not be written");
    }
    audit(
        state,
        &actor.did,
        Some(&subject),
        Audit {
            action: "gitNs.right.breakGlassRatified",
            namespace: Some(&ns.id),
            resource: Some(resource.to_string()),
            right: Some(right),
            policy_version: version,
            detail: None,
        },
    )
    .await;
    Ok(wire::into(json!({
        "right": wire::right_record_full(&ratified, &resource, true),
    }))?)
}
