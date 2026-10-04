//! Capability modules on the signed-document spine —
//! `governance/capability/{list,enable,disable}/0.1`
//! (`design-docs/vtc-capability-modules.md`; [`crate::capability_modules`]).
//!
//! "Capability" here is a pluggable governance module such as `git-trust`, not
//! an ACL capability on an administrator's entry. The ACL capability that
//! gates enabling one is `vtc.config.admin`.
//!
//! | task | signed by | authority (read now) |
//! |---|---|---|
//! | `list` | a member, or an administrator | a live ACL entry of community role other than `application` (or a console key's administrator) |
//! | `enable`, `disable` | an administrator | `vtc.config.admin` (**VTI-ACL-030**), plus the requester's step-up bound to the document |
//!
//! # Who may list
//!
//! The specification leaves it to the host's read policy: "hosts MAY restrict
//! `available`/`all` listings to community members or operators while leaving
//! `enabled` open". This community restricts every listing to its members and
//! administrators — the request names the caller, a member's client is the
//! surface asking (OpenVTC's Capabilities panel), and nobody else has a reason
//! to read the community's governance posture. An `application` entry (a
//! bridge, an external signer) is not a membership and is refused.
//!
//! # Why enable and disable take a bound step-up, and do not park
//!
//! `vtc-capability-modules.md` §4.1 classes `enable` as `destructive` — it
//! changes what the community's registry answers for — and the enable spec
//! asks hosts to treat disable the same. In this VTC that class is the
//! requester's gesture **bound to the digest of this one document**
//! ([`crate::acl::bound_step_up`], VTI-APV-015): a stolen or delegated signing
//! key alone cannot turn a module on or off. It is not parked in the action
//! list for other administrators' consent: second-party consent is what the
//! specification requires of authority-conferring and authority-reducing acts
//! (VTI-APV-018 – 020, VTI-VTC-022), and enabling a module confers no ACL
//! authority on anyone. Single-administrator mode therefore changes nothing
//! here — it waives consents, and there is none to waive.
//!
//! # Replies
//!
//! Every answer — refusals included — is the spine's: signed by this
//! community (`sign_response`), addressed to the requester and threaded to the
//! request (SPEC §4.9, `respond_with` / `reject_with`). The list reply is the
//! generated `#response`, the shape `trust-tasks-capability-client`'s
//! `parse_capability_reply` reads.

use serde_json::{Value, json};
use trust_tasks_rs::specs::governance::capability::{
    disable::v0_1 as disable, enable::v0_1 as enable, list::v0_1 as list,
};
use trust_tasks_rs::validate::ValidatedPayload;
use trust_tasks_rs::{Payload, RejectReason, TrustTask};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response, task_error_to_reject,
};
use super::member_tasks::acting_party;
use super::{JoinAuthCtx, capable_signer, parse_spec_payload};
use crate::acl::{Capability, VtcRole};
use crate::capability_modules::{self as modules, ModuleError, ModuleState};
use crate::error::TaskError;
use crate::server::AppState;

pub(crate) const LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;
pub(crate) const ENABLE_TYPE: &str = <enable::Payload as Payload>::TYPE_URI;
pub(crate) const DISABLE_TYPE: &str = <disable::Payload as Payload>::TYPE_URI;

/// Every URI [`dispatch`] routes. `super::DISPATCHED_URIS` names each of these
/// and `dispatcher_routes_every_dispatched_uri` holds the two in step.
pub(crate) const URIS: &[&str] = &[LIST_TYPE, ENABLE_TYPE, DISABLE_TYPE];

/// Route one of [`URIS`]; `None` for any other URI.
pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        LIST_TYPE => handle_list(state, ctx, doc).await,
        ENABLE_TYPE => handle_enable(state, ctx, doc).await,
        DISABLE_TYPE => handle_disable(state, ctx, doc).await,
        _ => return None,
    })
}

/// Answer with `body` held to the generated `#response` type and its schema.
/// A mismatch is this service's fault, so it is an `internalError`, never a
/// reply that claims a schema it does not satisfy.
fn respond<R>(doc: &TrustTask<Value>, body: Value) -> TrustTaskOutcome
where
    R: serde::de::DeserializeOwned + serde::Serialize + ValidatedPayload,
{
    let checked = R::validate_value(&body)
        .map_err(|e| e.to_string())
        .and_then(|()| serde_json::from_value::<R>(body).map_err(|e| e.to_string()));
    match checked {
        Ok(response) => success_response(doc, response),
        Err(e) => {
            tracing::error!(task = %doc.type_uri, error = %e, "response does not match its published schema");
            reject_with(
                doc,
                RejectReason::InternalError {
                    reason: format!("response does not match its published schema: {e}"),
                },
            )
        }
    }
}

fn refuse(doc: &TrustTask<Value>, e: ModuleError) -> TrustTaskOutcome {
    let declared =
        |code: &str, message: String| reject_with_code(doc, extended_code(code), message, None);
    match e {
        ModuleError::UnknownCapability(m) => {
            declared(enable::error_codes::UNKNOWN_CAPABILITY.code, m)
        }
        ModuleError::AlreadyEnabled => declared(
            enable::error_codes::ALREADY_ENABLED.code,
            "the capability module is already enabled for this community".into(),
        ),
        ModuleError::NotEnabled => declared(
            disable::error_codes::NOT_ENABLED.code,
            "the capability module is not enabled for this community".into(),
        ),
        ModuleError::ConfigInvalid(m) => declared(enable::error_codes::CONFIG_INVALID.code, m),
        ModuleError::Storage(e) => app_error_to_reject(doc, &e),
    }
}

/// The projection's standing, as an `ext` member — for the administrator who
/// made the decision, and for an administrator's list.
fn projection_ext(entry: &ModuleState) -> Value {
    let mut p = json!({ "status": entry.projection.status.as_str() });
    if let Some(e) = &entry.projection.last_error {
        p["lastError"] = json!(e);
    }
    if let Some(at) = entry.projection.applied_at {
        p["appliedAt"] = json!(at);
    }
    if entry.projection.attempts > 0 {
        p["attempts"] = json!(entry.projection.attempts);
    }
    p
}

// ─── list ────────────────────────────────────────────────────────────────

/// `governance/capability/list/0.1` — the modules this community has enabled
/// (`status` absent or `enabled`), those it could enable (`available`), or
/// both (`all`): the same filter the registry's own listing applies.
async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match acting_party(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if actor.entry.role == VtcRole::Application && !actor.entry.admin.is_administrator() {
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: "an application entry is not a membership; this community lists its \
                         capability modules to its members and administrators"
                    .into(),
            },
        );
    }
    let checked: list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    // Absence means `enabled` — the most restrictive listing (R5.1, and the
    // spec's own default).
    let status = checked.status.unwrap_or(list::PayloadStatus::Enabled);

    let decisions = match modules::load(&state.community_ks).await {
        Ok(d) => d,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let sees_projection = actor.entry.can(Capability::ConfigAdmin, None);
    let mut projections = serde_json::Map::new();
    let mut entries = Vec::new();
    for def in modules::available() {
        let decision = decisions.get(def.slug());
        let enabled = decision.is_some_and(|d| d.enabled);
        let wanted = match status {
            list::PayloadStatus::Enabled => enabled,
            list::PayloadStatus::Available => !enabled,
            list::PayloadStatus::All => true,
            // A status a later schema adds reads as the most restrictive one
            // this build knows (R5.1).
            _ => enabled,
        };
        if !wanted {
            continue;
        }
        let mut entry = json!({ "manifest": def.manifest, "enabled": enabled });
        if let Some(d) = decision {
            if enabled && let Some(at) = d.enabled_at {
                entry["enabledAt"] = json!(at);
            }
            if sees_projection {
                projections.insert(def.slug().to_string(), projection_ext(d));
            }
        }
        entries.push(entry);
    }
    let mut body = json!({ "capabilities": entries });
    if !projections.is_empty() {
        body["ext"] = json!({ "org.openvtc": { "projection": projections } });
    }
    respond::<list::Response>(&doc, body)
}

// ─── enable / disable ────────────────────────────────────────────────────

/// The requester's gesture bound to this document: `Ok(())` once spent, the
/// refusal asking for it otherwise.
async fn bound_step_up(
    state: &AppState,
    actor: &str,
    doc: &TrustTask<Value>,
    reason: &str,
) -> Result<(), TrustTaskOutcome> {
    use crate::acl::bound_step_up::{self, Gate};
    match bound_step_up::redeem_or_request(
        state,
        actor,
        &doc.type_uri.to_string(),
        &doc.payload,
        reason,
    )
    .await
    {
        Ok(Gate::Satisfied) => Ok(()),
        Ok(Gate::Required(request)) => Err(task_error_to_reject(doc, &TaskError::step_up(request))),
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

fn unavailable(doc: &TrustTask<Value>, message: &str) -> TrustTaskOutcome {
    use trust_tasks_rs::{StandardCode, TrustTaskCode};
    reject_with_code(
        doc,
        TrustTaskCode::Standard(StandardCode::Unavailable),
        message,
        None,
    )
}

/// A module decision is an administrative write, so it is refused rather
/// than made unaudited.
fn require_audit(state: &AppState, doc: &TrustTask<Value>) -> Result<(), TrustTaskOutcome> {
    if state.audit_writer.is_some() {
        return Ok(());
    }
    Err(unavailable(
        doc,
        "the audit log is not configured; a capability-module change is refused rather than \
         made unaudited",
    ))
}

/// `governance/capability/enable/0.1`.
async fn handle_enable(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(state, ctx, &doc, Capability::ConfigAdmin, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: enable::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    if let Err(reject) = require_audit(state, &doc) {
        return reject;
    }
    let Some(vtc_did) = state.config.read().await.vtc_did.clone() else {
        return unavailable(
            &doc,
            "this community has no DID yet, so no module can be enabled under it",
        );
    };
    let capability = checked.capability.to_string();
    let version = checked.version.to_string();

    // Every check that decides whether the enable is allowed, before the
    // gesture is asked for.
    let plan = match modules::plan_enable(
        &state.community_ks,
        &vtc_did,
        &capability,
        &version,
        &checked.config,
        checked.delegate.is_some(),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return refuse(&doc, e),
    };
    if let Err(reject) = bound_step_up(
        state,
        &actor.did,
        &doc,
        &format!("Enable the {capability} capability module for this community"),
    )
    .await
    {
        return reject;
    }

    let entry = match modules::commit_enable(state, &actor.did, plan).await {
        Ok(e) => e,
        Err(e) => return refuse(&doc, e),
    };
    modules::audit(state, &actor.did, &capability, &entry, "enabled", None).await;
    tracing::info!(
        capability = %capability,
        version = %entry.version,
        enabled_by = %actor.did,
        projection = entry.projection.status.as_str(),
        "capability module enabled; trust-registry projection queued"
    );
    let mut body = json!({
        "capability": capability,
        "version": entry.version,
        "enabled": true,
        "ext": { "org.openvtc": { "projection": projection_ext(&entry) } },
    });
    if let Some(at) = entry.enabled_at {
        body["enabledAt"] = json!(at);
    }
    respond::<enable::Response>(&doc, body)
}

/// `governance/capability/disable/0.1`.
async fn handle_disable(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(state, ctx, &doc, Capability::ConfigAdmin, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: disable::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    if let Err(reject) = require_audit(state, &doc) {
        return reject;
    }
    let capability = checked.capability.to_string();
    if let Err(e) = modules::plan_disable(&state.community_ks, &capability).await {
        return refuse(&doc, e);
    }
    if let Err(reject) = bound_step_up(
        state,
        &actor.did,
        &doc,
        &format!("Disable the {capability} capability module for this community"),
    )
    .await
    {
        return reject;
    }
    let reason = checked.reason.as_ref().map(|r| r.to_string());
    let entry = match modules::commit_disable(state, &actor.did, &capability, reason).await {
        Ok(e) => e,
        Err(e) => return refuse(&doc, e),
    };
    modules::audit(state, &actor.did, &capability, &entry, "disabled", None).await;
    tracing::info!(
        capability = %capability,
        disabled_by = %actor.did,
        projection = entry.projection.status.as_str(),
        "capability module disabled; trust-registry projection queued"
    );
    respond::<disable::Response>(
        &doc,
        json!({
            "capability": capability,
            "enabled": false,
            "ext": { "org.openvtc": { "projection": projection_ext(&entry) } },
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::super::members_admin_tests::{
        assert_conforms, error_code, payload_of, seed_acl, signed,
    };
    use super::super::{JoinAuthCtx, TrustTaskOutcome, dispatch_trust_task_core};
    use super::*;
    use crate::capability_modules::ProjectionStatus;
    use crate::join::JoinTransport;
    use crate::registry::{MockRegistryClient, RegistryError};
    use crate::test_support::{TEST_VTC_DID, TestVtc};
    use std::sync::Arc;
    use vti_common::capability_client::{CapabilityReply, parse_capability_reply};
    use vti_rooms_dtg::test_support::Party;

    const TRANSPORTS: [JoinTransport; 3] = [
        JoinTransport::Rest,
        JoinTransport::DIDComm,
        JoinTransport::Tsp,
    ];

    struct Fixture {
        vtc: TestVtc,
        registry: MockRegistryClient,
        admin: Party,
        moderator: Party,
        member: Party,
        /// A DID with no ACL row at all.
        stranger: Party,
    }

    async fn fixture() -> Fixture {
        let registry = MockRegistryClient::new();
        let vtc = TestVtc::builder()
            .with_audit(true)
            .with_signers(true)
            .with_registry_client(Arc::new(registry.clone()))
            .build()
            .await;
        let f = Fixture {
            vtc,
            registry,
            admin: Party::new(),
            moderator: Party::new(),
            member: Party::new(),
            stranger: Party::new(),
        };
        seed_acl(&f.vtc, &f.admin.did, VtcRole::Admin, vec![]).await;
        seed_acl(&f.vtc, &f.moderator.did, VtcRole::Moderator, vec![]).await;
        seed_acl(&f.vtc, &f.member.did, VtcRole::Member, vec![]).await;
        f
    }

    fn ctx(transport: JoinTransport, from: &Party) -> JoinAuthCtx {
        match transport {
            JoinTransport::Rest => JoinAuthCtx::rest(),
            _ => JoinAuthCtx {
                transport,
                sender_did: Some(from.did.clone()),
                verified_signer: None,
            },
        }
    }

    /// Send a signed document; the request alongside its answer.
    async fn send(
        f: &Fixture,
        transport: JoinTransport,
        from: &Party,
        uri: &str,
        payload: Value,
    ) -> (TrustTask<Value>, TrustTaskOutcome) {
        let doc = signed(from, uri, payload).await;
        let body = serde_json::to_vec(&doc).expect("a document serialises");
        let out = dispatch_trust_task_core(&f.vtc.state, &ctx(transport, from), &body).await;
        (doc, out)
    }

    fn reply(out: &TrustTaskOutcome) -> TrustTask<Value> {
        serde_json::from_slice(&out.body).expect("the answer is a Trust Task document")
    }

    fn ok(out: &TrustTaskOutcome, what: &str) {
        assert!(
            out.status.is_success(),
            "{what}: {}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// Enable git-trust as `f.admin`, with the gesture already recorded.
    async fn enable_git_trust(f: &Fixture, payload: Value) -> TrustTaskOutcome {
        crate::acl::bound_step_up::record_mark_for_test(
            &f.vtc.state,
            &f.admin.did,
            ENABLE_TYPE,
            &payload,
        )
        .await
        .unwrap();
        send(f, JoinTransport::DIDComm, &f.admin, ENABLE_TYPE, payload)
            .await
            .1
    }

    fn listed(out: &TrustTaskOutcome) -> Vec<String> {
        payload_of(out)["capabilities"]
            .as_array()
            .expect("a capabilities array")
            .iter()
            .map(|e| e["manifest"]["capability"].as_str().unwrap().to_string())
            .collect()
    }

    async fn capability_rows(f: &Fixture) -> Vec<CapabilityModuleChangedData> {
        f.vtc
            .state
            .audit_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap()
            .into_iter()
            .filter_map(|(_, v)| {
                serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok()
            })
            .filter_map(|env| match env.event {
                vti_common::audit::AuditEvent::CapabilityModuleChanged(d) => Some(d),
                _ => None,
            })
            .collect()
    }

    use vti_common::audit::CapabilityModuleChangedData;

    // ── list ─────────────────────────────────────────────────────────────

    /// The reply OpenVTC's Capabilities panel reads: on every transport, a
    /// member's listing is signed by this community, addressed back to the
    /// member, threaded to the request, and parses with the client the panel
    /// uses.
    #[tokio::test]
    async fn a_member_lists_capability_modules_in_the_shape_the_client_parses() {
        let f = fixture().await;
        ok(
            &enable_git_trust(&f, json!({ "capability": "git-trust", "version": "0.1" })).await,
            "enable",
        );
        for t in TRANSPORTS {
            let (doc, out) = send(&f, t, &f.member, LIST_TYPE, json!({ "status": "all" })).await;
            ok(&out, "list");
            assert_conforms::<list::Response>(&out);
            let answer = reply(&out);
            assert!(answer.proof.is_some(), "{t:?}: the reply is signed");
            assert_eq!(answer.issuer.as_deref(), Some(TEST_VTC_DID));
            assert_eq!(answer.recipient.as_deref(), Some(f.member.did.as_str()));
            assert_eq!(answer.thread_id.as_deref(), Some(doc.id.as_str()));
            let Some(CapabilityReply::Listing(items)) = parse_capability_reply(&answer, &doc.id)
            else {
                panic!("{t:?}: expected a listing: {answer:?}");
            };
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].slug, "git-trust");
            assert_eq!(items[0].version, "0.1");
            assert_eq!(items[0].title.as_deref(), Some("Git Commit Trust"));
            assert!(items[0].enabled);
            assert!(items[0].enabled_at.is_some());
            // The projection's standing is the administrators' business.
            assert!(payload_of(&out).get("ext").is_none(), "{t:?}");
        }
    }

    /// The request exactly as OpenVTC builds it — the capability client's own
    /// `build_list_document`, signed by the member — is answered, and the
    /// answer resolves that request's thread.
    #[tokio::test]
    async fn the_capability_clients_own_list_request_is_answered() {
        let f = fixture().await;
        let doc = super::super::members_admin_tests::sign(
            &f.member,
            vti_common::capability_client::build_list_document(&f.member.did, TEST_VTC_DID),
        )
        .await;
        let thread = vti_common::capability_client::correlation_thread(&doc).to_string();
        let body = serde_json::to_vec(&doc).unwrap();
        let out =
            dispatch_trust_task_core(&f.vtc.state, &ctx(JoinTransport::DIDComm, &f.member), &body)
                .await;
        ok(&out, "list");
        let Some(CapabilityReply::Listing(items)) = parse_capability_reply(&reply(&out), &thread)
        else {
            panic!("expected a listing: {}", String::from_utf8_lossy(&out.body));
        };
        assert_eq!(items.len(), 1, "`all` lists git-trust, not yet enabled");
        assert!(!items[0].enabled);
    }

    /// A DID the community holds no entry for is refused — and the refusal is
    /// itself signed and threaded, so the client can attribute it.
    #[tokio::test]
    async fn a_non_member_is_refused_the_listing() {
        let f = fixture().await;
        for t in TRANSPORTS {
            let (doc, out) = send(&f, t, &f.stranger, LIST_TYPE, json!({})).await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("permissionDenied"),
                "{t:?}"
            );
            let answer = reply(&out);
            assert!(answer.proof.is_some(), "{t:?}: the refusal is signed");
            assert_eq!(answer.recipient.as_deref(), Some(f.stranger.did.as_str()));
            assert!(matches!(
                parse_capability_reply(&answer, &doc.id),
                Some(CapabilityReply::Rejected { code, .. }) if code == "permissionDenied"
            ));
        }
    }

    /// An `application` entry (a bridge, an external signer) is not a
    /// membership.
    #[tokio::test]
    async fn an_application_entry_is_refused_the_listing() {
        let f = fixture().await;
        let bridge = Party::new();
        seed_acl(&f.vtc, &bridge.did, VtcRole::Application, vec![]).await;
        let (_, out) = send(&f, JoinTransport::Tsp, &bridge, LIST_TYPE, json!({})).await;
        assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
    }

    /// `status` filters as the registry's own listing does: absent means
    /// `enabled`, `available` is what could be enabled, `all` is both.
    #[tokio::test]
    async fn the_status_filter_matches_the_registrys() {
        let f = fixture().await;
        let list = |status: Option<&str>| {
            let payload = status.map_or(json!({}), |s| json!({ "status": s }));
            let f = &f;
            async move {
                send(f, JoinTransport::DIDComm, &f.member, LIST_TYPE, payload)
                    .await
                    .1
            }
        };
        assert!(listed(&list(None).await).is_empty(), "nothing enabled yet");
        assert!(listed(&list(Some("enabled")).await).is_empty());
        assert_eq!(listed(&list(Some("available")).await), ["git-trust"]);
        assert_eq!(listed(&list(Some("all")).await), ["git-trust"]);

        ok(
            &enable_git_trust(&f, json!({ "capability": "git-trust", "version": "0.1" })).await,
            "enable",
        );
        assert_eq!(listed(&list(None).await), ["git-trust"]);
        assert_eq!(listed(&list(Some("enabled")).await), ["git-trust"]);
        assert!(listed(&list(Some("available")).await).is_empty());
        assert_eq!(listed(&list(Some("all")).await), ["git-trust"]);

        let out = list(Some("everything")).await;
        assert_eq!(error_code(&out).as_deref(), Some("malformedRequest"));
    }

    /// An administrator's listing carries where each decision stands at the
    /// trust registry.
    #[tokio::test]
    async fn an_administrators_listing_carries_the_projection() {
        let f = fixture().await;
        ok(
            &enable_git_trust(&f, json!({ "capability": "git-trust", "version": "0.1" })).await,
            "enable",
        );
        let (_, out) = send(&f, JoinTransport::DIDComm, &f.admin, LIST_TYPE, json!({})).await;
        ok(&out, "list");
        assert_eq!(
            payload_of(&out)["ext"]["org.openvtc"]["projection"]["git-trust"]["status"],
            "pending"
        );
    }

    // ── enable / disable ─────────────────────────────────────────────────

    /// VTI-ACL-030: an enable needs `vtc.config.admin`. A moderator and a
    /// member are refused, and nothing is written.
    #[tokio::test]
    async fn vti_acl_030_enable_and_disable_refuse_a_non_administrator() {
        let f = fixture().await;
        for who in [&f.moderator, &f.member, &f.stranger] {
            for (uri, payload) in [
                (
                    ENABLE_TYPE,
                    json!({ "capability": "git-trust", "version": "0.1" }),
                ),
                (DISABLE_TYPE, json!({ "capability": "git-trust" })),
            ] {
                let (_, out) = send(&f, JoinTransport::DIDComm, who, uri, payload).await;
                assert_eq!(
                    error_code(&out).as_deref(),
                    Some("permissionDenied"),
                    "{uri}"
                );
                assert!(reply(&out).proof.is_some(), "the refusal is signed");
            }
        }
        assert!(
            modules::load(&f.vtc.state.community_ks)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(f.registry.capability_module_changes().await.is_empty());
    }

    /// VTI-APV-015: the administrator's signature alone does not enable a
    /// module; the gesture bound to this document does, and is spent by it.
    #[tokio::test]
    async fn vti_apv_015_an_enable_asks_for_a_step_up_bound_to_the_document() {
        let f = fixture().await;
        let payload = json!({ "capability": "git-trust", "version": "0.1" });
        let (_, out) = send(&f, JoinTransport::DIDComm, &f.admin, ENABLE_TYPE, payload).await;
        assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
        // This administrator holds no step-up factor, so the refusal says how
        // to get one rather than parking a ceremony nobody can answer.
        let message = payload_of(&out)["message"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(message.contains("step-up"), "{message}");
        assert!(
            modules::load(&f.vtc.state.community_ks)
                .await
                .unwrap()
                .is_empty(),
            "nothing written before the gesture"
        );
    }

    /// An accepted enable is persisted here first — the VTC is the source of
    /// truth — with `config.authority` defaulted to this community, audited,
    /// and queued for the registry; the projector then tells the registry and
    /// records that it took it.
    #[tokio::test]
    async fn an_enable_persists_then_projects_to_the_registry() {
        let f = fixture().await;
        let out =
            enable_git_trust(&f, json!({ "capability": "git-trust", "version": "0.1" })).await;
        ok(&out, "enable");
        assert_conforms::<enable::Response>(&out);
        let answer = payload_of(&out);
        assert_eq!(answer["enabled"], true);
        assert_eq!(
            answer["ext"]["org.openvtc"]["projection"]["status"],
            "pending"
        );

        let stored = modules::load(&f.vtc.state.community_ks).await.unwrap();
        let entry = &stored["git-trust"];
        assert!(entry.enabled);
        assert_eq!(entry.enabled_by.as_deref(), Some(f.admin.did.as_str()));
        assert_eq!(modules::authority_of(entry).as_deref(), Some(TEST_VTC_DID));
        assert_eq!(entry.projection.status, ProjectionStatus::Pending);
        assert!(
            f.registry.capability_module_changes().await.is_empty(),
            "the handler never calls the registry itself"
        );

        assert_eq!(modules::project_due(&f.vtc.state).await.unwrap(), 1);
        let sent = f.registry.capability_module_changes().await;
        assert_eq!(sent.len(), 1);
        assert!(sent[0].enabled);
        assert_eq!(sent[0].capability, "git-trust");
        assert_eq!(sent[0].config, Some(json!({ "authority": TEST_VTC_DID })));
        let stored = modules::load(&f.vtc.state.community_ks).await.unwrap();
        assert_eq!(
            stored["git-trust"].projection.status,
            ProjectionStatus::Applied
        );
        assert_eq!(
            modules::project_due(&f.vtc.state).await.unwrap(),
            0,
            "an applied decision is not re-sent"
        );

        let events: Vec<String> = capability_rows(&f)
            .await
            .into_iter()
            .map(|d| d.event)
            .collect();
        assert_eq!(events, ["enabled", "projected"]);
    }

    /// A refusal at the registry is visible — status, audit row — and is
    /// retried rather than dropped; a transient failure backs off. Either way
    /// the decision here stands.
    #[tokio::test]
    async fn a_projection_failure_is_visible_and_retried() {
        let f = fixture().await;
        ok(
            &enable_git_trust(&f, json!({ "capability": "git-trust", "version": "0.1" })).await,
            "enable",
        );

        f.registry
            .fail_next_capability_module(RegistryError::Unreachable("down".into()))
            .await;
        modules::project_due(&f.vtc.state).await.unwrap();
        let entry = &modules::load(&f.vtc.state.community_ks).await.unwrap()["git-trust"];
        assert_eq!(entry.projection.status, ProjectionStatus::Pending);
        assert_eq!(entry.projection.attempts, 1);
        assert!(entry.projection.next_attempt_at > chrono::Utc::now());
        assert!(entry.enabled);

        // Due again, then refused outright.
        force_due(&f).await;
        f.registry
            .fail_next_capability_module(RegistryError::Permanent("permissionDenied".into()))
            .await;
        modules::project_due(&f.vtc.state).await.unwrap();
        let entry = &modules::load(&f.vtc.state.community_ks).await.unwrap()["git-trust"];
        assert_eq!(entry.projection.status, ProjectionStatus::Failed);
        assert!(
            entry
                .projection
                .last_error
                .as_deref()
                .unwrap()
                .contains("permissionDenied")
        );
        let failed: Vec<_> = capability_rows(&f)
            .await
            .into_iter()
            .filter(|d| d.event == "projectionFailed")
            .collect();
        assert_eq!(failed.len(), 1);

        // Once the registry side is fixed, the next pass converges.
        force_due(&f).await;
        modules::project_due(&f.vtc.state).await.unwrap();
        let entry = &modules::load(&f.vtc.state.community_ks).await.unwrap()["git-trust"];
        assert_eq!(entry.projection.status, ProjectionStatus::Applied);
    }

    async fn force_due(f: &Fixture) {
        let mut all = modules::load(&f.vtc.state.community_ks).await.unwrap();
        for m in all.values_mut() {
            m.projection.next_attempt_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        }
        let key = String::from_utf8(modules::STATE_STORAGE_KEY.to_vec()).unwrap();
        f.vtc.state.community_ks.insert(key, &all).await.unwrap();
    }

    /// The declared refusals: an unknown module or version, a config naming
    /// another authority or a setting nothing reads, a second enable, and a
    /// disable of what is not enabled.
    #[tokio::test]
    async fn the_declared_refusals() {
        let f = fixture().await;
        let refused = |payload: Value| {
            let f = &f;
            async move {
                send(f, JoinTransport::DIDComm, &f.admin, ENABLE_TYPE, payload)
                    .await
                    .1
            }
        };
        assert_eq!(
            error_code(&refused(json!({ "capability": "moderation", "version": "0.1" })).await)
                .as_deref(),
            Some(enable::error_codes::UNKNOWN_CAPABILITY.code)
        );
        assert_eq!(
            error_code(&refused(json!({ "capability": "git-trust", "version": "9.9" })).await)
                .as_deref(),
            Some(enable::error_codes::UNKNOWN_CAPABILITY.code)
        );
        assert_eq!(
            error_code(
                &refused(json!({
                    "capability": "git-trust", "version": "0.1",
                    "config": { "authority": "did:example:someone-else" }
                }))
                .await
            )
            .as_deref(),
            Some(enable::error_codes::CONFIG_INVALID.code)
        );
        assert_eq!(
            error_code(
                &refused(json!({
                    "capability": "git-trust", "version": "0.1",
                    "config": { "grantOnRole": { "maintainer": { "resource": "acme" } } }
                }))
                .await
            )
            .as_deref(),
            Some(enable::error_codes::CONFIG_INVALID.code)
        );
        let (_, out) = send(
            &f,
            JoinTransport::DIDComm,
            &f.admin,
            DISABLE_TYPE,
            json!({ "capability": "git-trust" }),
        )
        .await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(disable::error_codes::NOT_ENABLED.code)
        );

        // An explicit authority equal to this community is accepted.
        ok(
            &enable_git_trust(
                &f,
                json!({ "capability": "git-trust", "version": "0.1",
                        "config": { "authority": TEST_VTC_DID } }),
            )
            .await,
            "enable",
        );
        assert_eq!(
            error_code(&refused(json!({ "capability": "git-trust", "version": "0.2" })).await)
                .as_deref(),
            Some(enable::error_codes::UNKNOWN_CAPABILITY.code)
        );
        assert_eq!(
            error_code(&refused(json!({ "capability": "git-trust", "version": "0.1" })).await)
                .as_deref(),
            Some(enable::error_codes::ALREADY_ENABLED.code)
        );
    }

    /// A disable keeps the decision row (who enabled it, and when), is
    /// audited with its reason, and projects as a disable; a later projection
    /// result for the superseded enable is not recorded against it.
    #[tokio::test]
    async fn a_disable_is_kept_audited_and_projected() {
        let f = fixture().await;
        ok(
            &enable_git_trust(&f, json!({ "capability": "git-trust", "version": "0.1" })).await,
            "enable",
        );
        let payload =
            json!({ "capability": "git-trust", "reason": "pausing during the migration" });
        crate::acl::bound_step_up::record_mark_for_test(
            &f.vtc.state,
            &f.admin.did,
            DISABLE_TYPE,
            &payload,
        )
        .await
        .unwrap();
        let (_, out) = send(&f, JoinTransport::Tsp, &f.admin, DISABLE_TYPE, payload).await;
        ok(&out, "disable");
        assert_conforms::<disable::Response>(&out);
        assert_eq!(payload_of(&out)["enabled"], false);

        let entry = &modules::load(&f.vtc.state.community_ks).await.unwrap()["git-trust"];
        assert!(!entry.enabled);
        assert_eq!(entry.generation, 2);
        assert!(entry.enabled_at.is_some(), "disable is not delete");
        assert_eq!(entry.enabled_by.as_deref(), Some(f.admin.did.as_str()));
        assert_eq!(entry.disabled_by.as_deref(), Some(f.admin.did.as_str()));

        modules::project_due(&f.vtc.state).await.unwrap();
        let sent = f.registry.capability_module_changes().await;
        assert_eq!(sent.len(), 1, "only the current decision is projected");
        assert!(!sent[0].enabled);
        assert_eq!(
            sent[0].reason.as_deref(),
            Some("pausing during the migration")
        );

        let rows = capability_rows(&f).await;
        let disabled = rows
            .iter()
            .find(|d| d.event == "disabled")
            .expect("a disabled row");
        assert_eq!(
            disabled.reason.as_deref(),
            Some("pausing during the migration")
        );

        // The listing reports it disabled, with no `enabledAt`.
        let (_, out) = send(
            &f,
            JoinTransport::DIDComm,
            &f.member,
            LIST_TYPE,
            json!({ "status": "all" }),
        )
        .await;
        let entry = &payload_of(&out)["capabilities"][0];
        assert_eq!(entry["enabled"], false);
        assert!(entry.get("enabledAt").is_none());
    }
}
