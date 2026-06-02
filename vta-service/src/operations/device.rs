//! `device/*` family operations — Companion/Service lifecycle.
//!
//! A [`DeviceBinding`] is the device-facing half of an [`AclEntry`], co-stored
//! under the `acl` keyspace. `device/register/0.1` attaches the binding to the
//! caller's existing ACL entry (placed there by provision-integration +
//! acl/swap-key). See dtgwg `device/*`.

use serde_json::{Value, json};
use tracing::info;
use uuid::Uuid;

use crate::acl::{
    AclEntry, Capability, CompanionFormFactor, ConsumerKind, DeviceBinding, ServiceKind,
    derived_capabilities_for_role, get_acl_entry, store_acl_entry,
};
use crate::audit;
use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

use trust_tasks_rs::specs::device::register::v0_1 as register_spec;

/// Register the caller's device: attach a [`DeviceBinding`] to its existing ACL
/// entry. The caller (`auth.did`) MUST already be in the ACL (its long-term key,
/// swapped in at enrolment). Re-registration is refused — the device rotates
/// keys and retries — per the spec. Returns the `{ binding }` response payload.
///
/// `attestation` is **accepted but not yet verified** (the spec treats it as a
/// policy input, not a gate; platform-attestation verification — Apple App
/// Attest / Play Integrity — is a follow-up). A stricter deployment will gate
/// on it later.
#[allow(clippy::too_many_arguments)]
pub async fn register_device(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    consumer_kind: ConsumerKind,
    display_name: String,
    platform: Option<String>,
    hpke_public_key: Option<String>,
    channel: &str,
) -> Result<Value, AppError> {
    let did = auth.did.clone();

    // The device must already hold an ACL entry (its long-term key, swapped in
    // at enrolment). No entry → no pending enrolment.
    let mut entry = get_acl_entry(acl_ks, &did).await?.ok_or_else(|| {
        AppError::NotFound(format!(
            "device/register:no_pending_enrolment — DID {did} is not in the ACL; \
             complete provision-integration + acl/swap-key first"
        ))
    })?;

    // Re-registration is intentionally not idempotent (spec): rotate keys + retry.
    if entry.device.is_some() {
        return Err(AppError::Conflict(format!(
            "device/register:already_registered — a DeviceBinding already exists for {did}"
        )));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let binding = DeviceBinding {
        device_id: format!("dev-{}", Uuid::new_v4()),
        display_name,
        platform,
        registered_at: now.clone(),
        last_seen_at: Some(now),
        disabled_at: None,
        wiped_at: None,
        hpke_public_key,
        wake: None,
    };

    entry.kind = consumer_kind;
    entry.device = Some(binding);
    entry.version = entry.version.saturating_add(1);
    store_acl_entry(acl_ks, &entry).await?;

    info!(channel, did = %did, "device registered");
    let _ = audit::record(
        audit_ks,
        "device.register",
        &did,
        Some(&did),
        "success",
        Some(channel),
        None,
    )
    .await;

    Ok(json!({ "binding": to_wire_binding(&entry) }))
}

/// Device heartbeat: refresh the binding's `lastSeenAt` (and `platform` if the
/// device reports a change), and return the maintainer's server time + any
/// queued operations. The caller MUST be a registered device (else
/// `not_registered`).
///
/// Does **not** bump the ACL entry `version` — a heartbeat is a metadata
/// refresh, not a policy change, so it must not collide with concurrent admin
/// edits guarded by `If-Match`. High-volume, so it is not individually audited
/// (the spec permits sampling).
///
/// `queuedOperations` is empty until `device/wipe` lands (C3); `syncHint` is
/// `up-to-date` until vault/sync is wired (the `vaultSeq` hint is accepted but
/// not yet acted on).
pub async fn heartbeat_device(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    platform: Option<String>,
) -> Result<Value, AppError> {
    let did = auth.did.clone();
    let mut entry = get_acl_entry(acl_ks, &did).await?.ok_or_else(|| {
        AppError::NotFound(format!(
            "device/heartbeat:not_registered — no DeviceBinding for {did}"
        ))
    })?;
    let binding = entry.device.as_mut().ok_or_else(|| {
        AppError::NotFound(format!(
            "device/heartbeat:not_registered — no DeviceBinding for {did}"
        ))
    })?;

    let now = chrono::Utc::now().to_rfc3339();
    binding.last_seen_at = Some(now.clone());
    if platform.is_some() {
        binding.platform = platform;
    }
    store_acl_entry(acl_ks, &entry).await?;

    Ok(json!({
        "serverTime": now,
        "queuedOperations": [],
        "syncHint": "up-to-date",
    }))
}

/// Assemble the wire `DeviceBinding` (device/_shared schema) from an ACL entry
/// that carries a [`DeviceBinding`]. Reused by `device/list`.
///
/// Built as JSON directly: the internal [`ConsumerKind`] serialises its
/// Companion `formFactor` field as kebab-case (`form-factor`), which does not
/// match the wire schema's camelCase `formFactor`, so the discriminator is
/// mapped explicitly here ([`kind_to_wire`]) rather than via serde.
///
/// # Panics
/// If `entry.device` is `None` — callers must check first.
pub fn to_wire_binding(entry: &AclEntry) -> Value {
    let b = entry
        .device
        .as_ref()
        .expect("to_wire_binding requires entry.device to be Some");

    let mut out = json!({
        "deviceId": b.device_id,
        "consumerDid": entry.did,
        "consumerKind": kind_to_wire(&entry.kind),
        "displayName": b.display_name,
        "registeredAt": b.registered_at,
        "pushCapable": b.push_capable(),
        "capabilities": wire_capabilities(entry),
    });
    let map = out.as_object_mut().expect("json object");
    if let Some(p) = &b.platform {
        map.insert("platform".into(), json!(p));
    }
    if let Some(t) = &b.last_seen_at {
        map.insert("lastSeenAt".into(), json!(t));
    }
    if let Some(t) = &b.disabled_at {
        map.insert("disabledAt".into(), json!(t));
    }
    if let Some(t) = &b.wiped_at {
        map.insert("wipedAt".into(), json!(t));
    }
    out
}

/// Wire `ConsumerKind` (register payload) → internal [`ConsumerKind`].
/// Explicit because the two types' serde forms differ (see [`to_wire_binding`]).
pub fn wire_kind_to_internal(w: &register_spec::ConsumerKind) -> ConsumerKind {
    use register_spec::{ConsumerKindFormFactor as Wff, ConsumerKindServiceKind as Wsk};
    match w {
        register_spec::ConsumerKind::Companion { form_factor } => ConsumerKind::Companion {
            form_factor: match form_factor {
                Wff::Browser => CompanionFormFactor::Browser,
                Wff::Mobile => CompanionFormFactor::Mobile,
                Wff::Desktop => CompanionFormFactor::Desktop,
            },
        },
        register_spec::ConsumerKind::Service { service_kind } => ConsumerKind::Service {
            service_kind: match service_kind {
                Wsk::Mediator => ServiceKind::Mediator,
                Wsk::AiAgent => ServiceKind::AiAgent,
                Wsk::Daemon => ServiceKind::Daemon,
            },
        },
    }
}

/// Internal [`ConsumerKind`] → wire JSON (camelCase `formFactor`/`serviceKind`).
fn kind_to_wire(kind: &ConsumerKind) -> Value {
    match kind {
        ConsumerKind::Companion { form_factor } => json!({
            "kind": "companion",
            "formFactor": match form_factor {
                CompanionFormFactor::Browser => "browser",
                CompanionFormFactor::Mobile => "mobile",
                CompanionFormFactor::Desktop => "desktop",
            },
        }),
        ConsumerKind::Service { service_kind } => json!({
            "kind": "service",
            "serviceKind": match service_kind {
                ServiceKind::Mediator => "mediator",
                ServiceKind::AiAgent => "ai-agent",
                ServiceKind::Daemon => "daemon",
            },
        }),
    }
}

/// Wire capability list (kebab-case), mirrored from the ACL entry — derived from
/// the role for legacy entries with no explicit set. Drops the VTA-internal
/// `sign-trust-task` capability, which is absent from the wire schema's closed
/// `Capability` enum.
fn wire_capabilities(entry: &AclEntry) -> Vec<Value> {
    let caps = if entry.capabilities.is_empty() {
        derived_capabilities_for_role(&entry.role)
    } else {
        entry.capabilities.clone()
    };
    caps.iter()
        .filter(|c| !matches!(c, Capability::SignTrustTask))
        .map(|c| serde_json::to_value(c).expect("Capability serialises"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Role;

    fn entry_with_binding() -> AclEntry {
        let mut e = AclEntry::new("did:key:zDevice", Role::Application, "did:key:zSetup");
        e.kind = ConsumerKind::Companion {
            form_factor: CompanionFormFactor::Mobile,
        };
        e.device = Some(DeviceBinding {
            device_id: "dev-abc".into(),
            display_name: "Glenn's iPhone".into(),
            platform: Some("iOS 19".into()),
            registered_at: "2026-06-02T00:00:00+00:00".into(),
            last_seen_at: Some("2026-06-02T00:00:00+00:00".into()),
            disabled_at: None,
            wiped_at: None,
            hpke_public_key: Some("did:key:zHpke".into()),
            wake: None,
        });
        e
    }

    #[test]
    fn wire_binding_uses_camel_case_consumer_kind() {
        let v = to_wire_binding(&entry_with_binding());
        // Companion formFactor must be camelCase to match the wire schema.
        assert_eq!(v["consumerKind"]["kind"], "companion");
        assert_eq!(v["consumerKind"]["formFactor"], "mobile");
        assert_eq!(v["consumerDid"], "did:key:zDevice");
        assert_eq!(v["deviceId"], "dev-abc");
        assert_eq!(v["pushCapable"], false); // no wake channel yet
        // hpkePublicKey is a register-payload field, not part of the binding.
        assert!(v.get("hpkePublicKey").is_none());
    }

    #[test]
    fn wire_capabilities_drops_internal_sign_trust_task() {
        let mut e = entry_with_binding();
        e.capabilities = vec![
            Capability::VaultRead,
            Capability::SignTrustTask,
            Capability::Sign,
        ];
        let caps = wire_capabilities(&e);
        let strs: Vec<&str> = caps.iter().map(|c| c.as_str().unwrap()).collect();
        assert!(strs.contains(&"vault-read"));
        assert!(strs.contains(&"sign"));
        assert!(
            !strs.contains(&"sign-trust-task"),
            "internal-only capability must not leak to the wire: {strs:?}"
        );
    }

    #[test]
    fn consumer_kind_round_trips_through_explicit_maps() {
        // service / ai-agent survives wire→internal→wire.
        let internal = ConsumerKind::Service {
            service_kind: ServiceKind::AiAgent,
        };
        let wire = kind_to_wire(&internal);
        assert_eq!(wire["serviceKind"], "ai-agent");
    }

    // ── register_device (enrolment) ─────────────────────────────────

    use crate::auth::AuthClaims;
    use crate::store::{KeyspaceHandle, Store};
    use vti_common::config::StoreConfig;

    async fn fresh() -> (KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let acl_ks = store.keyspace("acl").unwrap();
        let audit_ks = store.keyspace("audit").unwrap();
        (acl_ks, audit_ks, dir)
    }

    fn device_auth(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.into(),
            role: Role::Application,
            allowed_contexts: vec![],
            session_id: "s".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    fn mobile_kind() -> ConsumerKind {
        ConsumerKind::Companion {
            form_factor: CompanionFormFactor::Mobile,
        }
    }

    #[tokio::test]
    async fn register_rejects_did_not_in_acl() {
        let (acl_ks, audit_ks, _dir) = fresh().await;
        let err = register_device(
            &acl_ks,
            &audit_ks,
            &device_auth("did:key:zUnknown"),
            mobile_kind(),
            "Phone".into(),
            None,
            Some("did:key:zHpke".into()),
            "test",
        )
        .await
        .expect_err("a DID with no ACL entry must be refused");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn register_attaches_binding_then_refuses_reregistration() {
        let (acl_ks, audit_ks, _dir) = fresh().await;
        let did = "did:key:zDevice";
        // Seed the device's ACL entry (as provision-integration + swap-key would).
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Application, "did:key:zSetup"),
        )
        .await
        .unwrap();

        let body = register_device(
            &acl_ks,
            &audit_ks,
            &device_auth(did),
            mobile_kind(),
            "Glenn's iPhone".into(),
            Some("iOS 19".into()),
            Some("did:key:zHpke".into()),
            "test",
        )
        .await
        .expect("first registration succeeds");
        assert_eq!(body["binding"]["consumerKind"]["formFactor"], "mobile");
        assert_eq!(body["binding"]["consumerDid"], did);

        // The binding is now attached to the ACL entry…
        let entry = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
        let bound = entry.device.expect("binding attached");
        assert_eq!(bound.hpke_public_key.as_deref(), Some("did:key:zHpke"));
        assert!(bound.device_id.starts_with("dev-"));

        // …and a second registration is refused (rotate keys + retry).
        let err = register_device(
            &acl_ks,
            &audit_ks,
            &device_auth(did),
            mobile_kind(),
            "Glenn's iPhone".into(),
            None,
            Some("did:key:zHpke".into()),
            "test",
        )
        .await
        .expect_err("re-registration must conflict");
        assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn heartbeat_refreshes_last_seen_and_platform() {
        let (acl_ks, audit_ks, _dir) = fresh().await;
        let did = "did:key:zDevice";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Application, "did:key:zSetup"),
        )
        .await
        .unwrap();
        register_device(
            &acl_ks,
            &audit_ks,
            &device_auth(did),
            mobile_kind(),
            "Phone".into(),
            Some("iOS 19.0".into()),
            Some("did:key:zHpke".into()),
            "test",
        )
        .await
        .unwrap();

        let body = heartbeat_device(&acl_ks, &device_auth(did), Some("iOS 19.1".into()))
            .await
            .expect("heartbeat on a registered device succeeds");
        assert_eq!(body["syncHint"], "up-to-date");
        assert!(body["queuedOperations"].as_array().unwrap().is_empty());
        assert!(body["serverTime"].is_string());

        // Platform update + lastSeenAt are persisted; version is NOT bumped.
        let entry = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
        let b = entry.device.unwrap();
        assert_eq!(b.platform.as_deref(), Some("iOS 19.1"));
        assert!(b.last_seen_at.is_some());
        assert_eq!(
            entry.version, 1,
            "heartbeat must not bump the entry version"
        );
    }

    #[tokio::test]
    async fn heartbeat_rejects_unregistered_device() {
        let (acl_ks, _audit_ks, _dir) = fresh().await;
        // ACL entry exists but no DeviceBinding attached.
        store_acl_entry(
            &acl_ks,
            &AclEntry::new("did:key:zBare", Role::Application, "did:key:zSetup"),
        )
        .await
        .unwrap();
        let err = heartbeat_device(&acl_ks, &device_auth("did:key:zBare"), None)
            .await
            .expect_err("heartbeat without a binding must be refused");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }
}
