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
    WakeChannel, derived_capabilities_for_role, get_acl_entry, list_acl_entries, store_acl_entry,
};
use crate::audit;
use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

use trust_tasks_rs::specs::device::list::v0_1 as list_spec;
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

/// List the maintainer's registered devices, filtered per the request. Requires
/// management rights. Disabled/wiped devices are omitted unless explicitly
/// included. Returns `{ devices, cursor, truncated }`.
///
/// Cursor pagination is not yet implemented — `pageSize` truncates and sets
/// `truncated`, with no continuation `cursor` (operators narrow filters). This
/// is the only deviation from the spec's pagination and is called out here.
pub async fn list_devices(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    payload: &list_spec::Payload,
) -> Result<Value, AppError> {
    auth.require_manage()?;

    let entries = list_acl_entries(acl_ks).await?;
    let mut devices: Vec<Value> = Vec::new();
    for entry in &entries {
        let Some(b) = entry.device.as_ref() else {
            continue;
        };
        if !payload.include_disabled && b.disabled_at.is_some() {
            continue;
        }
        if !payload.include_wiped && b.wiped_at.is_some() {
            continue;
        }
        if let Some(ckf) = &payload.consumer_kind_filter {
            let is_companion = matches!(entry.kind, ConsumerKind::Companion { .. });
            let want_companion = matches!(ckf, list_spec::PayloadConsumerKindFilter::Companion);
            if is_companion != want_companion {
                continue;
            }
        }
        if let Some(fff) = &payload.form_factor_filter {
            match &entry.kind {
                ConsumerKind::Companion { form_factor }
                    if form_factor_matches(fff, form_factor) => {}
                // A form-factor filter excludes Services and non-matching companions.
                _ => continue,
            }
        }
        if let Some(cap) = &payload.capability_filter {
            let want = serde_json::to_value(cap).ok();
            let have = wire_capabilities(entry);
            if !want.is_some_and(|w| have.contains(&w)) {
                continue;
            }
        }
        if let Some(since) = payload.last_seen_since {
            let seen = b
                .last_seen_at
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.with_timezone(&chrono::Utc) >= since)
                .unwrap_or(false);
            if !seen {
                continue;
            }
        }
        devices.push(to_wire_binding(entry));
    }

    let limit = payload.page_size.map(|n| n.get() as usize).unwrap_or(200);
    let truncated = devices.len() > limit;
    devices.truncate(limit);
    Ok(json!({ "devices": devices, "truncated": truncated }))
}

fn form_factor_matches(
    filter: &list_spec::PayloadFormFactorFilter,
    ff: &CompanionFormFactor,
) -> bool {
    use list_spec::PayloadFormFactorFilter as F;
    matches!(
        (filter, ff),
        (F::Browser, CompanionFormFactor::Browser)
            | (F::Mobile, CompanionFormFactor::Mobile)
            | (F::Desktop, CompanionFormFactor::Desktop)
    )
}

/// Disable a device by its `deviceId`: set `disabledAt` (idempotent — a
/// re-disable keeps the original timestamp) so it can no longer authenticate.
/// Requires management rights. Returns `{ deviceId, disabledAt }`.
///
/// NOTE: the auth-path enforcement (a disabled device is rejected at
/// authentication) is a separate follow-up — this records the state and
/// surfaces it via `device/list`.
pub async fn disable_device(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    device_id: &str,
) -> Result<Value, AppError> {
    auth.require_manage()?;

    let mut entry = list_acl_entries(acl_ks)
        .await?
        .into_iter()
        .find(|e| e.device.as_ref().map(|b| b.device_id.as_str()) == Some(device_id))
        .ok_or_else(|| {
            AppError::NotFound(format!("device/disable — no device with id {device_id}"))
        })?;

    let binding = entry.device.as_mut().expect("matched entry has a binding");
    if binding.disabled_at.is_none() {
        binding.disabled_at = Some(chrono::Utc::now().to_rfc3339());
    }
    let disabled_at = binding.disabled_at.clone().expect("disabled_at set above");
    // Disabling changes authorization-relevant state — bump the version so a
    // concurrent ACL edit guarded by If-Match conflicts rather than racing.
    entry.version = entry.version.saturating_add(1);
    let did = entry.did.clone();
    store_acl_entry(acl_ks, &entry).await?;

    info!(did = %did, device_id, "device disabled");
    let _ = audit::record(
        audit_ks,
        "device.disable",
        &auth.did,
        Some(&did),
        "success",
        None,
        None,
    )
    .await;

    Ok(json!({ "deviceId": device_id, "disabledAt": disabled_at }))
}

/// `device/wipe/0.1` — issue a remote wipe for a lost/compromised device.
///
/// Marks the binding `wiped_at` **and** `disabled_at` (a wiped device must not
/// be able to authenticate) and bumps the entry version. `reason` and `scope`
/// (`cache` | `cache-and-keys` | `full`) are logged and echoed back; the device
/// observes the wiped state on its next `device/list` / heartbeat. Idempotent:
/// re-wiping a wiped device keeps the original `wiped_at`.
pub async fn wipe_device(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    device_id: &str,
    reason: &str,
    scope: &str,
) -> Result<Value, AppError> {
    auth.require_manage()?;

    let mut entry = list_acl_entries(acl_ks)
        .await?
        .into_iter()
        .find(|e| e.device.as_ref().map(|b| b.device_id.as_str()) == Some(device_id))
        .ok_or_else(|| {
            AppError::NotFound(format!("device/wipe — no device with id {device_id}"))
        })?;

    let now = chrono::Utc::now().to_rfc3339();
    let binding = entry.device.as_mut().expect("matched entry has a binding");
    if binding.wiped_at.is_none() {
        binding.wiped_at = Some(now.clone());
    }
    // A wiped device must not authenticate — disable it too.
    if binding.disabled_at.is_none() {
        binding.disabled_at = Some(now.clone());
    }
    let wiped_at = binding.wiped_at.clone().expect("wiped_at set above");
    let disabled_at = binding.disabled_at.clone().expect("disabled_at set above");
    // Wiping changes authorization-relevant state — bump the version so a
    // concurrent ACL edit guarded by If-Match conflicts rather than racing.
    entry.version = entry.version.saturating_add(1);
    let did = entry.did.clone();
    store_acl_entry(acl_ks, &entry).await?;

    info!(did = %did, device_id, reason, scope, "device wiped");
    let _ = audit::record(
        audit_ks,
        "device.wipe",
        &auth.did,
        Some(&did),
        "success",
        None,
        None,
    )
    .await;

    Ok(json!({
        "deviceId": device_id,
        "wipedAt": wiped_at,
        "disabledAt": disabled_at,
        "scope": scope,
        "reason": reason,
    }))
}

/// Set (or clear) the caller device's push **wake channel** from a
/// `device/set-wake/0.1`. The caller MUST be a registered device. The VTA
/// **owns the trigger allowlist**: it computes `{ vta_did } ∪ suggested` (the
/// device's `suggestedTriggers` hint — typically its mediator — which the VTA
/// MAY honor) and records it on the binding. `wake = None` clears the channel.
/// Returns the effective `{ triggerPolicy, pushCapable }`.
///
/// NOTE: provisioning the allowlist to the gateway (a `push/provision` Trust
/// Task to the gateway DID) is a follow-up — it is blocked on the gateway being
/// able to authenticate the `did:webvh` VTA, which arrives with the gateway's
/// DIDComm surface. This records the VTA-side state the VTA-trigger reads.
pub async fn set_wake_device(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    wake: Option<(String, String)>,
    suggested_triggers: Vec<String>,
    vta_did: Option<String>,
) -> Result<Value, AppError> {
    let did = auth.did.clone();
    let mut entry = get_acl_entry(acl_ks, &did).await?.ok_or_else(|| {
        AppError::NotFound(format!(
            "device/set-wake:not_registered — no DeviceBinding for {did}"
        ))
    })?;
    if entry.device.is_none() {
        return Err(AppError::NotFound(format!(
            "device/set-wake:not_registered — no DeviceBinding for {did}"
        )));
    }

    let Some((gateway, handle)) = wake else {
        // Clear: the device is no longer wakeable.
        entry.device.as_mut().unwrap().wake = None;
        store_acl_entry(acl_ks, &entry).await?;
        let _ = audit::record(
            audit_ks,
            "device.set_wake.clear",
            &did,
            Some(&did),
            "success",
            None,
            None,
        )
        .await;
        return Ok(json!({ "pushCapable": false }));
    };

    // VTA owns the allowlist: its own DID (policy-driven wake) plus any
    // device-suggested triggers (its mediator), deduped, order-preserved.
    let mut allowed: Vec<String> = Vec::new();
    for t in vta_did.into_iter().chain(suggested_triggers) {
        if !t.is_empty() && !allowed.contains(&t) {
            allowed.push(t);
        }
    }

    let binding = entry
        .device
        .as_mut()
        .expect("binding present (checked above)");
    binding.wake = Some(WakeChannel {
        gateway,
        handle,
        allowed_triggers: allowed.clone(),
    });
    let push_capable = binding.push_capable();
    store_acl_entry(acl_ks, &entry).await?;

    info!(did = %did, triggers = allowed.len(), "device wake channel set");
    let _ = audit::record(
        audit_ks,
        "device.set_wake",
        &did,
        Some(&did),
        "success",
        None,
        None,
    )
    .await;
    // TODO(gateway): push/provision the allowlist to the gateway DID over
    // DIDComm once the gateway's DIDComm surface can authenticate the VTA.

    Ok(json!({
        "pushCapable": push_capable,
        "triggerPolicy": { "allowedTriggers": allowed },
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
        let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();
        let audit_ks = store.keyspace(crate::keyspaces::AUDIT).unwrap();
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

    fn admin_auth() -> AuthClaims {
        AuthClaims {
            did: "did:key:zAdmin".into(),
            role: Role::Admin,
            allowed_contexts: vec![],
            session_id: "s".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    fn list_payload(v: Value) -> list_spec::Payload {
        serde_json::from_value(v).expect("valid list payload")
    }

    async fn seed_and_register(
        acl_ks: &KeyspaceHandle,
        audit_ks: &KeyspaceHandle,
        did: &str,
        ff: CompanionFormFactor,
        name: &str,
    ) {
        store_acl_entry(
            acl_ks,
            &AclEntry::new(did, Role::Application, "did:key:zSetup"),
        )
        .await
        .unwrap();
        register_device(
            acl_ks,
            audit_ks,
            &device_auth(did),
            ConsumerKind::Companion { form_factor: ff },
            name.into(),
            None,
            Some("did:key:zHpke".into()),
            "test",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn list_filters_then_disable_hides_device() {
        let (acl_ks, audit_ks, _dir) = fresh().await;
        seed_and_register(
            &acl_ks,
            &audit_ks,
            "did:key:zPhone",
            CompanionFormFactor::Mobile,
            "Phone",
        )
        .await;
        seed_and_register(
            &acl_ks,
            &audit_ks,
            "did:key:zLaptop",
            CompanionFormFactor::Desktop,
            "Laptop",
        )
        .await;

        // Default list returns both active devices.
        let all = list_devices(&acl_ks, &admin_auth(), &list_payload(json!({})))
            .await
            .unwrap();
        assert_eq!(all["devices"].as_array().unwrap().len(), 2);

        // formFactorFilter=mobile narrows to the phone.
        let mob = list_devices(
            &acl_ks,
            &admin_auth(),
            &list_payload(json!({ "formFactorFilter": "mobile" })),
        )
        .await
        .unwrap();
        let devs = mob["devices"].as_array().unwrap();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0]["consumerKind"]["formFactor"], "mobile");

        // Disable the phone by its deviceId.
        let phone_id = devs[0]["deviceId"].as_str().unwrap().to_string();
        let d = disable_device(&acl_ks, &audit_ks, &admin_auth(), &phone_id)
            .await
            .unwrap();
        assert_eq!(d["deviceId"], phone_id.as_str());
        assert!(d["disabledAt"].is_string());

        // Default list now hides the disabled phone…
        let after = list_devices(&acl_ks, &admin_auth(), &list_payload(json!({})))
            .await
            .unwrap();
        assert_eq!(after["devices"].as_array().unwrap().len(), 1);
        // …and includeDisabled brings it back.
        let incl = list_devices(
            &acl_ks,
            &admin_auth(),
            &list_payload(json!({ "includeDisabled": true })),
        )
        .await
        .unwrap();
        assert_eq!(incl["devices"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn disable_unknown_device_is_not_found() {
        let (acl_ks, audit_ks, _dir) = fresh().await;
        let err = disable_device(&acl_ks, &audit_ks, &admin_auth(), "dev-nope")
            .await
            .expect_err("unknown deviceId must be NotFound");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn wipe_marks_wiped_and_disabled_then_hidden() {
        let (acl_ks, audit_ks, _dir) = fresh().await;
        seed_and_register(
            &acl_ks,
            &audit_ks,
            "did:key:zLost",
            CompanionFormFactor::Desktop,
            "Laptop",
        )
        .await;
        let all = list_devices(&acl_ks, &admin_auth(), &list_payload(json!({})))
            .await
            .unwrap();
        let id = all["devices"][0]["deviceId"].as_str().unwrap().to_string();

        let w = wipe_device(&acl_ks, &audit_ks, &admin_auth(), &id, "stolen", "full")
            .await
            .unwrap();
        assert_eq!(w["deviceId"], id.as_str());
        assert!(w["wipedAt"].is_string());
        assert!(w["disabledAt"].is_string(), "wipe must also disable");
        assert_eq!(w["scope"], "full");
        assert_eq!(w["reason"], "stolen");

        // Default list hides the wiped device; it returns only with both
        // includeWiped + includeDisabled (a wiped device is also disabled).
        let after = list_devices(&acl_ks, &admin_auth(), &list_payload(json!({})))
            .await
            .unwrap();
        assert_eq!(after["devices"].as_array().unwrap().len(), 0);
        let incl = list_devices(
            &acl_ks,
            &admin_auth(),
            &list_payload(json!({ "includeWiped": true, "includeDisabled": true })),
        )
        .await
        .unwrap();
        assert_eq!(incl["devices"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn wipe_unknown_device_is_not_found() {
        let (acl_ks, audit_ks, _dir) = fresh().await;
        let err = wipe_device(&acl_ks, &audit_ks, &admin_auth(), "dev-nope", "r", "full")
            .await
            .expect_err("unknown deviceId must be NotFound");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn set_wake_records_channel_and_vta_owned_allowlist() {
        let (acl_ks, audit_ks, _dir) = fresh().await;
        let did = "did:key:zDevice";
        seed_and_register(
            &acl_ks,
            &audit_ks,
            did,
            CompanionFormFactor::Mobile,
            "Phone",
        )
        .await;

        let body = set_wake_device(
            &acl_ks,
            &audit_ks,
            &device_auth(did),
            Some(("did:webvh:gw".into(), "z6MkHandle".into())),
            vec!["did:webvh:mediator".into()],
            Some("did:webvh:vta".into()),
        )
        .await
        .unwrap();

        assert_eq!(body["pushCapable"], true);
        // VTA owns the allowlist: its own DID first, then the device-suggested mediator.
        let triggers: Vec<&str> = body["triggerPolicy"]["allowedTriggers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(triggers, vec!["did:webvh:vta", "did:webvh:mediator"]);

        // Persisted on the binding's wake channel.
        let entry = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
        let w = entry.device.unwrap().wake.unwrap();
        assert_eq!(w.gateway, "did:webvh:gw");
        assert_eq!(w.handle, "z6MkHandle");
        assert_eq!(
            w.allowed_triggers,
            vec!["did:webvh:vta", "did:webvh:mediator"]
        );
    }

    #[tokio::test]
    async fn set_wake_clear_removes_channel() {
        let (acl_ks, audit_ks, _dir) = fresh().await;
        let did = "did:key:zDevice";
        seed_and_register(
            &acl_ks,
            &audit_ks,
            did,
            CompanionFormFactor::Mobile,
            "Phone",
        )
        .await;
        set_wake_device(
            &acl_ks,
            &audit_ks,
            &device_auth(did),
            Some(("did:webvh:gw".into(), "h".into())),
            vec![],
            Some("did:webvh:vta".into()),
        )
        .await
        .unwrap();

        // Clearing (wake = None) removes the channel.
        let body = set_wake_device(
            &acl_ks,
            &audit_ks,
            &device_auth(did),
            None,
            vec![],
            Some("did:webvh:vta".into()),
        )
        .await
        .unwrap();
        assert_eq!(body["pushCapable"], false);
        let entry = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
        assert!(entry.device.unwrap().wake.is_none());
    }

    #[tokio::test]
    async fn set_wake_rejects_unregistered_device() {
        let (acl_ks, audit_ks, _dir) = fresh().await;
        store_acl_entry(
            &acl_ks,
            &AclEntry::new("did:key:zBare", Role::Application, "did:key:zSetup"),
        )
        .await
        .unwrap();
        let err = set_wake_device(
            &acl_ks,
            &audit_ks,
            &device_auth("did:key:zBare"),
            Some(("g".into(), "h".into())),
            vec![],
            Some("did:webvh:vta".into()),
        )
        .await
        .expect_err("set-wake without a binding must be refused");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }
}
