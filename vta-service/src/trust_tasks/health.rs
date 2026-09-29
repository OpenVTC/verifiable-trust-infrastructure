//! The agent's reports on itself, split by who may read them.
//!
//! - `spec/vta/health/details/0.1` — **public** ([`vta_sdk::trust_tasks::PUBLIC_URIS`]):
//!   the non-identifying flags, the same answer for every asker.
//! - `spec/vta/restore/status/0.1` — administrators only: the software version
//!   and the VTI-VTA-051 restore record.
//!
//! Both replace `GET /health/details`, which answered all of it — version and
//! restore record included — to any authenticated caller, whatever its role.
//! The specifications split it on purpose rather than adding members for a
//! caller who authenticated: an answer whose content depends on who asked
//! leaks the richer form through a cache, a log line or one path that forgets
//! the check, and leaves the schema unable to say what the task discloses. Two
//! tasks give each a fixed schema and a fixed disclosure policy.

use serde_json::Value;
use trust_tasks_rs::specs::vta::health::details::v0_1 as health_spec;
use trust_tasks_rs::specs::vta::restore::status::v0_1 as restore_spec;
use trust_tasks_rs::{RejectReason, TrustTask};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, parse_payload, reject_with, success_response,
};
use crate::acl::Role;
use crate::auth::AuthClaims;
use crate::server::AppState;

/// Build the response through the generated type, so what leaves is checked
/// against the published schema on the way — `additionalProperties: false` is
/// what guarantees the public answer cannot grow a version or a restore record.
fn typed_response<R: serde::de::DeserializeOwned + serde::Serialize>(
    doc: &TrustTask<Value>,
    body: Value,
) -> TrustTaskOutcome {
    match serde_json::from_value::<R>(body) {
        Ok(r) => success_response(doc, r),
        Err(e) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("response does not match its schema: {e}"),
            },
        ),
    }
}

/// The platform name as the registry spells it. The internal enum displays
/// `sev_snp`; the specifications say `sev-snp`.
#[cfg(feature = "tee")]
fn tee_type_wire(tee_type: &str) -> &'static str {
    match tee_type {
        "nitro" => "nitro",
        "sev_snp" | "sev-snp" => "sev-snp",
        _ => "simulated",
    }
}

/// `spec/vta/health/details/0.1` — this agent's public health flags.
///
/// Public: answered to anyone, including a caller with no identity here, and
/// the same for everyone (consumer rule 3). Computed per request, so `sealed`
/// and the messaging members reflect the running state rather than boot. Never
/// the software version, never the restore record — those are
/// [`handle_restore_status`]'s, and the response schema cannot carry them.
pub(super) async fn handle_health_details(
    state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(resp) = parse_payload::<health_spec::Payload>(&doc) {
        return resp;
    }

    let (mediator_url, mediator_did, tsp_enabled) = {
        let config = state.config.read().await;
        let (url, did) = config
            .messaging
            .as_ref()
            .map(|m| (Some(m.mediator_url.clone()), Some(m.mediator_did.clone())))
            .unwrap_or((None, None));
        (url, did, config.services.tsp)
    };

    // A seal that cannot be read is reported as not sealed: this is the
    // agent's claim about its own posture, and claiming a protection it cannot
    // confirm is the wrong direction to err in.
    let sealed = crate::seal::get_seal(&state.acl_ks)
        .await
        .ok()
        .flatten()
        .is_some();

    let mut body = serde_json::json!({
        "status": "ok",
        "sealed": sealed,
        "storageEncrypted": state.keys_ks.is_encrypted(),
        "tspEnabled": tsp_enabled,
    });
    if let Some(url) = mediator_url {
        body["mediatorUrl"] = Value::String(url);
    }
    if let Some(did) = mediator_did {
        body["mediatorDid"] = Value::String(did);
    }

    // Exactly what `vta/attestation/status/0.1` answers, and absent where that
    // task would answer `notAttested` (consumer rule 4).
    #[cfg(feature = "tee")]
    if let Some(tee) = state.tee.as_ref() {
        let status = crate::operations::attestation::get_tee_status(&tee.state);
        let mut tee_status = serde_json::json!({
            "teeType": tee_type_wire(&status.tee_type.to_string()),
            "detected": status.detected,
        });
        if let Some(v) = status.platform_version {
            tee_status["platformVersion"] = Value::String(v);
        }
        body["teeStatus"] = tee_status;
    }

    typed_response::<health_spec::Response>(&doc, body)
}

/// `spec/vta/restore/status/0.1` — this agent's version and restore record.
///
/// Administrators only, and the check comes **before** anything restore-shaped
/// is read (consumer rule 2): the refusal is `permissionDenied` whether or not
/// the agent was restored, so it cannot be used to learn that. Any
/// administrator qualifies, context-scoped or not — the answer concerns the
/// whole agent.
///
/// The request proof is REQUIRED by the specification and enforced on the
/// spine (`SpecPolicy::enforce`) before this runs; `auth` is the proven signer.
pub(super) async fn handle_restore_status(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(resp) = parse_payload::<restore_spec::Payload>(&doc) {
        return resp;
    }

    // The ACL, read now, is the authority — not the role a token was minted
    // with, which may be stale. A caller with no entry is refused the same way
    // as one holding a lesser role.
    let is_admin = match crate::acl::get_acl_entry(&state.acl_ks, &auth.did).await {
        Ok(Some(entry)) => entry.role == Role::Admin,
        Ok(None) => false,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    if !is_admin {
        tracing::warn!(
            caller = %auth.did,
            "restore/status refused: the caller is not an administrator of this agent"
        );
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: "reading this agent's restore status needs an administrator role".into(),
            },
        );
    }

    let provenance =
        match vta_backup::restore::read_provenance(&state.backup_access().target()).await {
            Ok(p) => p,
            Err(e) => return app_error_to_reject(&doc, e),
        };

    let mut body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "restored": provenance.is_some(),
    });
    // `restore` is present exactly when `restored` is true (consumer rule 3):
    // both are derived from the one read above.
    if let Some(p) = provenance {
        let rfc3339 =
            |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut record = serde_json::json!({
            "appliedAt": rfc3339(p.applied_at),
            "stagedAt": rfc3339(p.staged_at),
            "stagedBy": p.staged_by,
            "targetEnvironment": p.target_environment.to_string(),
        });
        if let Some(did) = p.source_did {
            record["sourceDid"] = Value::String(did);
        }
        if let Some(env) = p.source_environment {
            record["sourceEnvironment"] = Value::String(env.to_string());
        }
        if !p.internal_keys_lost.is_empty() {
            record["internalKeysLost"] = serde_json::json!(p.internal_keys_lost);
        }
        if !p.hosted_dids_detached.is_empty() {
            record["hostedDidsDetached"] = serde_json::json!(p.hosted_dids_detached);
        }
        body["restore"] = record;
    }

    typed_response::<restore_spec::Response>(&doc, body)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::super::transport::TransportConfidentiality;
    use crate::acl::Role;
    use crate::auth::AuthClaims;
    use crate::test_support::build_signing_test_app_state;

    fn error_code(doc: &Value) -> Option<&str> {
        doc.pointer("/payload/code").and_then(Value::as_str)
    }

    /// An unsigned request as an unidentified observer sends it.
    async fn anonymous_body(state: &crate::server::AppState, type_uri: &str) -> Vec<u8> {
        let mut doc = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {},
        });
        if let Some(vta_did) = state.config.read().await.vta_did.clone() {
            doc["recipient"] = json!(vta_did);
        }
        serde_json::to_vec(&doc).unwrap()
    }

    async fn dispatch(state: &crate::server::AppState, auth: &AuthClaims, body: &[u8]) -> Value {
        let out = super::super::dispatch_trust_task_core(
            state,
            auth,
            body,
            TransportConfidentiality::HopByHop,
        )
        .await;
        serde_json::from_slice(&out.body).expect("a JSON document")
    }

    /// A document signed as `seed`'s DID, addressed to this agent.
    async fn signed_body(state: &crate::server::AppState, seed: u8, type_uri: &str) -> Vec<u8> {
        let vta_did = state.config.read().await.vta_did.clone().expect("vta_did");
        let (did, _) = crate::test_support::did_for_seed(seed);
        let mut doc: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "issuer": did,
            "recipient": vta_did,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {},
        }))
        .unwrap();
        crate::test_support::sign_as(seed, &mut doc);
        serde_json::to_vec(&doc).unwrap()
    }

    fn claims(did: &str, role: Role, contexts: Vec<String>) -> AuthClaims {
        AuthClaims {
            did: did.to_string(),
            role,
            allowed_contexts: contexts,
            ..Default::default()
        }
    }

    /// Anyone gets the fixed flags, signed, and nothing that identifies the
    /// build or a restore — the response schema has no room for either.
    #[tokio::test]
    async fn health_details_answers_an_anonymous_caller_with_only_the_public_flags() {
        let (state, _dir) = build_signing_test_app_state().await;
        let body = anonymous_body(&state, vta_sdk::trust_tasks::TASK_VTA_HEALTH_DETAILS_0_1).await;
        let resp = dispatch(&state, &super::super::anonymous_claims(), &body).await;
        assert_eq!(
            resp["type"],
            format!(
                "{}#response",
                vta_sdk::trust_tasks::TASK_VTA_HEALTH_DETAILS_0_1
            ),
            "{resp}"
        );
        let payload = resp["payload"].as_object().expect("a payload");
        assert_eq!(payload["status"], "ok");
        assert!(payload["sealed"].is_boolean());
        assert!(payload["storageEncrypted"].is_boolean());
        assert!(payload["tspEnabled"].is_boolean());
        for member in payload.keys() {
            assert!(
                [
                    "status",
                    "mediatorUrl",
                    "mediatorDid",
                    "teeStatus",
                    "sealed",
                    "storageEncrypted",
                    "tspEnabled"
                ]
                .contains(&member.as_str()),
                "the public answer grew `{member}`: {resp}"
            );
        }
        assert!(resp["proof"].is_object(), "the answer is signed: {resp}");
    }

    /// Consumer rule 3: an authenticated administrator gets exactly what the
    /// anonymous caller got.
    #[tokio::test]
    async fn health_details_is_the_same_for_an_administrator() {
        let (state, _dir) = build_signing_test_app_state().await;
        let body = anonymous_body(&state, vta_sdk::trust_tasks::TASK_VTA_HEALTH_DETAILS_0_1).await;
        let anon = dispatch(&state, &super::super::anonymous_claims(), &body).await;
        let body = signed_body(
            &state,
            0x61,
            vta_sdk::trust_tasks::TASK_VTA_HEALTH_DETAILS_0_1,
        )
        .await;
        let (did, _) = crate::test_support::did_for_seed(0x61);
        let admin = dispatch(&state, &claims(&did, Role::Admin, vec![]), &body).await;
        assert_eq!(anon["payload"], admin["payload"], "{anon} vs {admin}");
    }

    async fn seed_acl(
        state: &crate::server::AppState,
        seed: u8,
        role: Role,
        ctx: Vec<String>,
    ) -> String {
        let (did, _) = crate::test_support::did_for_seed(seed);
        crate::test_support::seed_acl_entry(&state.acl_ks, &did, role, ctx).await;
        did
    }

    /// An administrator — scoped or not — reads the version, and `restored` is
    /// stated rather than inferred.
    #[tokio::test]
    async fn restore_status_answers_an_administrator_with_version_and_restored() {
        let (state, _dir) = build_signing_test_app_state().await;
        for (seed, contexts) in [(0x62u8, vec![]), (0x63u8, vec!["ctx-a".to_string()])] {
            let did = seed_acl(&state, seed, Role::Admin, contexts.clone()).await;
            let body = signed_body(
                &state,
                seed,
                vta_sdk::trust_tasks::TASK_VTA_RESTORE_STATUS_0_1,
            )
            .await;
            let resp = dispatch(&state, &claims(&did, Role::Admin, contexts), &body).await;
            assert_eq!(
                resp["payload"]["version"],
                env!("CARGO_PKG_VERSION"),
                "{resp}"
            );
            assert_eq!(resp["payload"]["restored"], false, "{resp}");
            assert!(resp["payload"].get("restore").is_none(), "{resp}");
            assert!(resp["proof"].is_object(), "{resp}");
        }
    }

    /// Consumer rule 2: anyone else — a lesser role, or no ACL entry — is
    /// `permissionDenied`, and the token's claimed role does not count.
    #[tokio::test]
    async fn restore_status_refuses_a_non_administrator() {
        let (state, _dir) = build_signing_test_app_state().await;
        let reader = seed_acl(&state, 0x64, Role::Reader, vec!["ctx-a".into()]).await;
        let (stranger, _) = crate::test_support::did_for_seed(0x65);
        for (seed, did) in [(0x64u8, reader), (0x65u8, stranger)] {
            let body = signed_body(
                &state,
                seed,
                vta_sdk::trust_tasks::TASK_VTA_RESTORE_STATUS_0_1,
            )
            .await;
            // A token that claims admin: the ACL, read now, is the authority.
            let resp = dispatch(&state, &claims(&did, Role::Admin, vec![]), &body).await;
            assert_eq!(error_code(&resp), Some("permissionDenied"), "{resp}");
        }
    }

    /// The request proof is REQUIRED: an unsigned request is refused before
    /// the handler, even from an administrator's session.
    #[tokio::test]
    async fn restore_status_refuses_an_unsigned_request() {
        let (state, _dir) = build_signing_test_app_state().await;
        let did = seed_acl(&state, 0x66, Role::Admin, vec![]).await;
        let vta_did = state.config.read().await.vta_did.clone().expect("vta_did");
        let body = serde_json::to_vec(&json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": vta_sdk::trust_tasks::TASK_VTA_RESTORE_STATUS_0_1,
            "issuer": did,
            "recipient": vta_did,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {},
        }))
        .unwrap();
        let resp = dispatch(&state, &claims(&did, Role::Admin, vec![]), &body).await;
        assert!(
            resp["type"]
                .as_str()
                .is_some_and(|t| t.contains("trust-task-error")),
            "{resp}"
        );
    }

    /// A restored agent reports the VTI-VTA-051 record, in the specification's
    /// member names, and `restored` agrees with it.
    #[tokio::test]
    async fn restore_status_reports_the_restore_record_when_restored() {
        let (state, _dir) = build_signing_test_app_state().await;
        let provenance = vta_backup::restore::RestoreProvenance {
            restore_id: "restore-1".into(),
            applied_at: chrono::Utc::now(),
            staged_at: chrono::Utc::now(),
            staged_by: "did:key:z6MkStager".into(),
            source_did: Some("did:webvh:QmOld:vta-old.example.com".into()),
            source_environment: Some(
                vta_sdk::protocols::backup_management::types::BackupEnvironment::Hardened,
            ),
            target_environment:
                vta_sdk::protocols::backup_management::types::BackupEnvironment::Plain,
            internal_keys_lost: vec!["audit-signer".into()],
            hosted_dids_detached: vec![],
            audited: true,
        };
        state
            .keys_ks
            .insert(vta_backup::restore::PROVENANCE_KEY, &provenance)
            .await
            .expect("write the provenance row");

        let did = seed_acl(&state, 0x67, Role::Admin, vec![]).await;
        let body = signed_body(
            &state,
            0x67,
            vta_sdk::trust_tasks::TASK_VTA_RESTORE_STATUS_0_1,
        )
        .await;
        let resp = dispatch(&state, &claims(&did, Role::Admin, vec![]), &body).await;
        let p = &resp["payload"];
        assert_eq!(p["restored"], true, "{resp}");
        assert_eq!(p["restore"]["stagedBy"], "did:key:z6MkStager", "{resp}");
        assert_eq!(p["restore"]["sourceEnvironment"], "hardened", "{resp}");
        assert_eq!(p["restore"]["targetEnvironment"], "plain", "{resp}");
        assert_eq!(
            p["restore"]["internalKeysLost"],
            json!(["audit-signer"]),
            "{resp}"
        );
        assert!(p["restore"].get("hostedDidsDetached").is_none(), "{resp}");

        // And the public task still says nothing about it.
        let body = anonymous_body(&state, vta_sdk::trust_tasks::TASK_VTA_HEALTH_DETAILS_0_1).await;
        let public = dispatch(&state, &super::super::anonymous_claims(), &body).await;
        assert!(
            !public.to_string().contains("z6MkStager"),
            "the public answer leaked the restore record: {public}"
        );
    }
}
