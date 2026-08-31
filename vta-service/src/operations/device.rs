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
    WakeChannel, derived_capabilities_for_role, get_acl_entry, is_acl_entry_visible,
    list_acl_entries, store_acl_entry,
};
use crate::audit;
use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

use trust_tasks_rs::specs::device::heartbeat::v0_1 as heartbeat_spec;
use trust_tasks_rs::specs::device::list::v0_1 as list_spec;
use trust_tasks_rs::specs::device::register::v0_1 as register_spec;

// The extension key a device uses to correct its own `displayName`
// (`org.openvtc.device-name`) is defined by the SDK that produces it, and
// imported rather than re-spelled: the two sides agree by string, and a typo on
// either would be a rename that silently never happens. `EXT_DEVICE_NAME` on
// that constant carries the rationale — in short, `displayName` is set once at
// registration and re-registration is intentionally refused, so heartbeat's
// `ext` is the only spec-provided place a correction can travel. Honouring it
// weakens nothing: the binding, its `deviceId` and its `registeredAt` are
// untouched, and no new binding can be claimed this way.
use vta_sdk::protocols::device_management::EXT_DEVICE_NAME;

/// Ceiling on a display name, mirroring the `device/register` schema's
/// `maxLength: 128`. The `ext` slot is untyped, so a bound the schema would have
/// enforced has to be enforced here — a heartbeat must not become a way to store
/// an unbounded string on the maintainer.
const MAX_DISPLAY_NAME_CHARS: usize = 128;

/// The corrected display name a heartbeat carries, if it carries a usable one.
///
/// **Invalid input is ignored, not rejected.** A heartbeat's real job is to
/// refresh `lastSeenAt`; failing the whole call over a malformed extension would
/// make a device with a client-side bug look *offline*, which is the more
/// expensive error — it is the one that sends an operator looking for a machine
/// that is running fine. A name that does not survive this returns `None` and
/// the rest of the heartbeat proceeds.
fn extension_display_name(ext: Option<&heartbeat_spec::Ext>) -> Option<String> {
    let value = ext?
        .iter()
        .find(|(key, _)| key.as_str() == EXT_DEVICE_NAME)
        .map(|(_, value)| value)?;
    let name = value.get("displayName")?.as_str()?.trim();
    if name.is_empty() || name.chars().count() > MAX_DISPLAY_NAME_CHARS {
        tracing::debug!(
            len = name.chars().count(),
            "ignoring a heartbeat display name outside 1..={MAX_DISPLAY_NAME_CHARS} characters"
        );
        return None;
    }
    Some(name.to_string())
}

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
    audit: &vta_audit::SharedAuditSink,
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
            "device/register:noPendingEnrolment — DID {did} is not in the ACL; \
             complete provision-integration + acl/swap-key first"
        ))
    })?;

    // Re-registration is intentionally not idempotent (spec): rotate keys + retry.
    if entry.device.is_some() {
        return Err(AppError::Conflict(format!(
            "device/register:alreadyRegistered — a DeviceBinding already exists for {did}"
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
        audit,
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

/// Device heartbeat: refresh the binding's `lastSeenAt` (and `platform` or
/// `displayName` if the device reports a change), and return the maintainer's
/// server time + any queued operations. The caller MUST be a registered device
/// (else `not_registered`).
///
/// A device may only correct **its own** binding: the entry is fetched by
/// `auth.did`, so the rename reaches the row the caller authenticated as and no
/// other. See [`EXT_DEVICE_NAME`] for why the correction rides here.
///
/// Does **not** bump the ACL entry `version` — a heartbeat is a metadata
/// refresh, not a policy change, so it must not collide with concurrent admin
/// edits guarded by `If-Match`. A rename is metadata by the same measure:
/// `displayName` **MUST NOT** be used as a security input by anything that
/// renders it (dtgwg `device/register/0.2`), so no policy decision can turn on
/// it. High-volume, so it is not individually audited (the spec permits
/// sampling).
///
/// `queuedOperations` is empty until `device/wipe` lands (C3); `syncHint` is
/// `up-to-date` until vault/sync is wired (the `vaultSeq` hint is accepted but
/// not yet acted on).
pub async fn heartbeat_device(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    platform: Option<String>,
    ext: Option<&heartbeat_spec::Ext>,
) -> Result<Value, AppError> {
    let did = auth.did.clone();
    let mut entry = get_acl_entry(acl_ks, &did).await?.ok_or_else(|| {
        AppError::NotFound(format!(
            "device/heartbeat:notRegistered — no DeviceBinding for {did}"
        ))
    })?;
    let binding = entry.device.as_mut().ok_or_else(|| {
        AppError::NotFound(format!(
            "device/heartbeat:notRegistered — no DeviceBinding for {did}"
        ))
    })?;

    let now = chrono::Utc::now().to_rfc3339();
    binding.last_seen_at = Some(now.clone());
    if platform.is_some() {
        binding.platform = platform;
    }
    if let Some(renamed) = extension_display_name(ext)
        && renamed != binding.display_name
    {
        info!(
            did = %did,
            from = %binding.display_name,
            to = %renamed,
            "device corrected its display name"
        );
        binding.display_name = renamed;
    }
    store_acl_entry(acl_ks, &entry).await?;

    Ok(json!({
        "serverTime": now,
        "queuedOperations": [],
        "syncHint": "up-to-date",
    }))
}

/// List the registered devices the caller may manage, filtered per the request.
/// Requires management rights **in the binding's context**: a super-admin sees
/// every device, a context admin only those whose ACL entry acts in a context
/// they hold, and an entry authorized nowhere sees none. Disabled/wiped devices
/// are omitted unless explicitly included. Returns `{ devices, cursor,
/// truncated }`.
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
        // The caller's *context* scope, not just their role. `require_manage`
        // above is role-only, and on its own it handed a context-scoped admin
        // every binding on the VTA — including the hostname, platform and
        // activity window of machines in contexts they hold no rights in.
        if !is_acl_entry_visible(auth, entry) {
            continue;
        }
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
            let have = split_capabilities(entry).0;
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

/// Find the entry holding `device_id`, refusing one the caller may not manage.
///
/// Shared by `device/disable` and `device/wipe` so the two cannot drift on who
/// may reach a binding — they had no scope check at all before, so
/// `require_manage` alone let any context admin disable or wipe **every** device
/// on the VTA, a super-admin's included.
///
/// A binding outside the caller's scope conflates to the same `NotFound` an
/// absent id returns. That is deliberate: a distinct "forbidden" would confirm
/// the id exists, turning the error into an oracle for enumerating device ids
/// the caller cannot otherwise see. Same reading as the vault's use paths.
///
/// [`is_acl_entry_visible`] is the *management* predicate, not the wider
/// [`crate::acl::is_acl_entry_auditable`] used by `acl list`. Both mutations here plainly
/// need management authority, and `device/list` reads the same way on purpose:
/// a binding carries operational metadata about a **machine** — hostname,
/// platform, last-seen — which is a different and more revealing disclosure
/// than the entry's authority that the auditable predicate exists to surface.
/// So the read and the mutations agree: you see the devices you may manage.
async fn find_manageable_device(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    device_id: &str,
    op: &str,
) -> Result<AclEntry, AppError> {
    list_acl_entries(acl_ks)
        .await?
        .into_iter()
        .find(|e| e.device.as_ref().map(|b| b.device_id.as_str()) == Some(device_id))
        .filter(|e| is_acl_entry_visible(auth, e))
        .ok_or_else(|| AppError::NotFound(format!("{op} — no device with id {device_id}")))
}

/// Disable a device by its `deviceId`: set `disabledAt` (idempotent — a
/// re-disable keeps the original timestamp) so it can no longer authenticate.
/// Requires management rights over the binding's own entry — see
/// `find_manageable_device`. Returns `{ deviceId, disabledAt }`.
///
/// NOTE: the auth-path enforcement (a disabled device is rejected at
/// authentication) is a separate follow-up — this records the state and
/// surfaces it via `device/list`.
pub async fn disable_device(
    acl_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    device_id: &str,
) -> Result<Value, AppError> {
    auth.require_manage()?;

    let mut entry = find_manageable_device(acl_ks, auth, device_id, "device/disable").await?;

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
        audit,
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
/// re-wiping a wiped device keeps the original `wiped_at`. Requires management
/// rights over the binding's own entry — see `find_manageable_device`.
pub async fn wipe_device(
    acl_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    device_id: &str,
    reason: &str,
    scope: &str,
) -> Result<Value, AppError> {
    auth.require_manage()?;

    let mut entry = find_manageable_device(acl_ks, auth, device_id, "device/wipe").await?;

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
    // Wiping changes authorization-relevant state — bump the version so a
    // concurrent ACL edit guarded by If-Match conflicts rather than racing.
    entry.version = entry.version.saturating_add(1);
    let did = entry.did.clone();
    store_acl_entry(acl_ks, &entry).await?;

    info!(did = %did, device_id, reason, scope, "device wiped");
    let _ = audit::record(
        audit,
        "device.wipe",
        &auth.did,
        Some(&did),
        "success",
        None,
        None,
    )
    .await;

    // Canonical `device/wipe/0.1` response: `{deviceId, scope, completedAt}`
    // (additionalProperties: false — the previous `wipedAt`/`disabledAt`/
    // `reason` members are not in the schema; #857). The wipe both marks and
    // disables in the same instant, so `completedAt` is that timestamp; the
    // caller already knows `reason`, it sent it.
    Ok(json!({
        "deviceId": device_id,
        "scope": scope,
        "completedAt": wiped_at,
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
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    wake: Option<(String, String)>,
    suggested_triggers: Vec<String>,
    vta_did: Option<String>,
) -> Result<Value, AppError> {
    let did = auth.did.clone();
    let mut entry = get_acl_entry(acl_ks, &did).await?.ok_or_else(|| {
        AppError::NotFound(format!(
            "device/set-wake:notRegistered — no DeviceBinding for {did}"
        ))
    })?;
    if entry.device.is_none() {
        return Err(AppError::NotFound(format!(
            "device/set-wake:notRegistered — no DeviceBinding for {did}"
        )));
    }

    let Some((gateway, handle)) = wake else {
        // Clear: the device is no longer wakeable.
        entry.device.as_mut().unwrap().wake = None;
        store_acl_entry(acl_ks, &entry).await?;
        let _ = audit::record(
            audit,
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
        audit,
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

    let (published_caps, local_caps) = split_capabilities(entry);
    let mut out = json!({
        "deviceId": b.device_id,
        "consumerDid": entry.did,
        "consumerKind": kind_to_wire(&entry.kind),
        "displayName": b.display_name,
        "registeredAt": b.registered_at,
        "pushCapable": b.push_capable(),
        "capabilities": published_caps,
    });
    let map = out.as_object_mut().expect("json object");
    if !local_caps.is_empty() {
        // Reverse-DNS namespaced per SPEC §4.5.1: these are this ecosystem's
        // capabilities, not the framework's, so they travel in the slot the
        // framework provides rather than widening its closed enum.
        map.insert(
            "ext".into(),
            json!({ "org.openvtc": { "capabilities": local_caps } }),
        );
    }
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
///
/// Fallible because the generated wire enums are `#[non_exhaustive]`: a caller
/// on a newer registry can name a device kind, form factor or service kind
/// added after this binary was built. `device/register` writes an ACL entry
/// from this value, and the kind is what the VTA's policy keys off — mapping an
/// unknown one onto `Daemon`, or onto any other arm, would register a device
/// under a privilege profile nobody asked for. Refusing is the only answer that
/// cannot silently be wrong.
pub fn wire_kind_to_internal(w: &register_spec::ConsumerKind) -> Result<ConsumerKind, AppError> {
    use register_spec::{ConsumerKindFormFactor as Wff, ConsumerKindServiceKind as Wsk};
    let unknown = |what: &str| {
        AppError::Validation(format!(
            "device/register: unrecognised {what} — this VTA cannot apply a policy to a              value added to the registry after it was built"
        ))
    };
    Ok(match w {
        register_spec::ConsumerKind::Companion { form_factor } => ConsumerKind::Companion {
            form_factor: match form_factor {
                Wff::Browser => CompanionFormFactor::Browser,
                Wff::Mobile => CompanionFormFactor::Mobile,
                Wff::Desktop => CompanionFormFactor::Desktop,
                _ => return Err(unknown("companion form factor")),
            },
        },
        register_spec::ConsumerKind::Service { service_kind } => ConsumerKind::Service {
            service_kind: match service_kind {
                Wsk::Mediator => ServiceKind::Mediator,
                Wsk::AiAgent => ServiceKind::AiAgent,
                Wsk::Daemon => ServiceKind::Daemon,
                _ => return Err(unknown("service kind")),
            },
        },
        _ => return Err(unknown("consumer kind")),
    })
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

/// Capabilities the published `device/_shared/0.2` `Capability` enum defines.
///
/// Listed **positively** so a capability added to this workspace later is
/// treated as ecosystem-local by default and lands in `ext` rather than
/// leaking into a closed enum. The previous code filtered out the one local
/// capability by name; `CredentialWrite` was added afterwards, the filter was
/// not extended, and it went onto the wire and failed the schema.
const PUBLISHED_CAPABILITIES: &[Capability] = &[
    Capability::VaultRead,
    Capability::VaultWrite,
    Capability::ProxyLogin,
    Capability::FillRelease,
    Capability::PolicyAdmin,
    Capability::DeviceAdmin,
    Capability::Sign,
    Capability::KeyMint,
];

/// The capabilities an ACL entry confers, split into what the published
/// `capabilities` member may carry and what belongs under `ext`.
///
/// Ecosystem-local capabilities are **carried, not dropped**. SPEC §4.5.1 has
/// an extension slot for exactly this, and `DeviceBinding` declares one; the
/// earlier approach silently omitted `sign-trust-task`, which told a reader the
/// device lacked an authority it actually held. Dropping a capability from a
/// listing is a safety claim, and it was not a true one.
fn split_capabilities(entry: &AclEntry) -> (Vec<Value>, Vec<Value>) {
    let caps = if entry.capabilities.is_empty() {
        derived_capabilities_for_role(&entry.role)
    } else {
        entry.capabilities.clone()
    };
    let (published, local): (Vec<_>, Vec<_>) = caps
        .iter()
        .partition(|c| PUBLISHED_CAPABILITIES.contains(c));
    let to_value = |c: &Capability| serde_json::to_value(c).expect("Capability serialises");
    // The published list is re-cased kebab -> camel on the way out by the 0.2
    // dual-accept layer (`wire_v0_2`), which only knows the members the
    // specification defines. An `ext` member is invisible to it, so these are
    // camel-cased here — a document that spelled `deviceAdmin` beside
    // `sign-trust-task` would be answering in two dialects at once, and
    // SPEC §4.10 asks for lowerCamelCase either way.
    let to_camel = |c: &Capability| {
        let kebab = to_value(c);
        let s = kebab.as_str().unwrap_or_default();
        let mut out = String::with_capacity(s.len());
        let mut upper = false;
        for ch in s.chars() {
            match ch {
                '-' => upper = true,
                c if upper => {
                    out.extend(c.to_uppercase());
                    upper = false;
                }
                c => out.push(c),
            }
        }
        Value::String(out)
    };
    (
        published.iter().map(to_value).collect(),
        local.iter().map(to_camel).collect(),
    )
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
    fn local_capabilities_are_split_out_not_dropped() {
        let mut e = entry_with_binding();
        e.capabilities = vec![
            Capability::VaultRead,
            Capability::SignTrustTask,
            Capability::Sign,
        ];
        let (published, local) = split_capabilities(&e);
        let p: Vec<&str> = published.iter().map(|c| c.as_str().unwrap()).collect();
        let l: Vec<&str> = local.iter().map(|c| c.as_str().unwrap()).collect();
        assert!(p.contains(&"vault-read"), "{p:?}");
        assert!(p.contains(&"sign"), "{p:?}");
        assert!(
            !p.contains(&"sign-trust-task"),
            "an ecosystem-local capability must not enter the closed enum: {p:?}"
        );
        assert!(
            l.contains(&"signTrustTask"),
            "…but it must still be reported, under `ext` — and in lowerCamelCase, \
             so the document does not answer in two dialects at once: {l:?}"
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

    async fn fresh() -> (
        KeyspaceHandle,
        vta_audit::SharedAuditSink,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();
        let audit: vta_audit::SharedAuditSink = std::sync::Arc::new(
            vta_audit::KeyspaceAuditSink::new(store.keyspace(crate::keyspaces::AUDIT).unwrap()),
        );
        (acl_ks, audit, dir)
    }

    fn device_auth(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.into(),
            role: Role::Application,
            allowed_contexts: vec![],
            session_id: "s".into(),
            access_expires_at: 0,
            issued_at: 0,
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
        let (acl_ks, audit, _dir) = fresh().await;
        let err = register_device(
            &acl_ks,
            &audit,
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
        let (acl_ks, audit, _dir) = fresh().await;
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
            &audit,
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
            &audit,
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
        let (acl_ks, audit, _dir) = fresh().await;
        let did = "did:key:zDevice";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Application, "did:key:zSetup"),
        )
        .await
        .unwrap();
        register_device(
            &acl_ks,
            &audit,
            &device_auth(did),
            mobile_kind(),
            "Phone".into(),
            Some("iOS 19.0".into()),
            Some("did:key:zHpke".into()),
            "test",
        )
        .await
        .unwrap();

        let body = heartbeat_device(&acl_ks, &device_auth(did), Some("iOS 19.1".into()), None)
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

    /// Build the heartbeat `ext` a device sends to correct its own name.
    fn name_ext(display_name: &str) -> heartbeat_spec::Ext {
        serde_json::from_value(
            serde_json::json!({ EXT_DEVICE_NAME: { "displayName": display_name } }),
        )
        .expect("the ext key matches the schema's reverse-DNS pattern")
    }

    /// Enrol a device and give it a binding, returning its DID.
    async fn registered(
        acl_ks: &KeyspaceHandle,
        audit: &vta_audit::SharedAuditSink,
        did: &str,
        display_name: &str,
    ) {
        store_acl_entry(
            acl_ks,
            &AclEntry::new(did, Role::Application, "did:key:zSetup"),
        )
        .await
        .unwrap();
        register_device(
            acl_ks,
            audit,
            &device_auth(did),
            mobile_kind(),
            display_name.into(),
            None,
            Some("did:key:zHpke".into()),
            "test",
        )
        .await
        .unwrap();
    }

    /// `displayName` is set once at registration and re-registration is refused,
    /// so without this a renamed machine announces its old name forever — in the
    /// list the name exists to disambiguate.
    #[tokio::test]
    async fn heartbeat_applies_a_corrected_display_name() {
        let (acl_ks, audit, _dir) = fresh().await;
        let did = "did:key:zDevice";
        registered(&acl_ks, &audit, did, "OpenVTC on old-host (default)").await;
        let before = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
        let claimed = before.device.unwrap();

        heartbeat_device(
            &acl_ks,
            &device_auth(did),
            None,
            Some(&name_ext("OpenVTC on new-host (default)")),
        )
        .await
        .expect("heartbeat succeeds");

        let entry = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
        let b = entry.device.unwrap();
        assert_eq!(b.display_name, "OpenVTC on new-host (default)");
        // The binding is corrected, not re-claimed: identity and enrolment time
        // are exactly what registration minted, and no policy version moved.
        assert_eq!(b.device_id, claimed.device_id);
        assert_eq!(b.registered_at, claimed.registered_at);
        assert_eq!(
            entry.version, 1,
            "a rename is metadata, so it must not bump the entry version"
        );
    }

    /// A device can only correct the binding it authenticated as — the entry is
    /// fetched by `auth.did`, so there is no way to rename someone else's row.
    #[tokio::test]
    async fn a_rename_reaches_only_the_callers_own_binding() {
        let (acl_ks, audit, _dir) = fresh().await;
        registered(&acl_ks, &audit, "did:key:zMine", "Mine").await;
        registered(&acl_ks, &audit, "did:key:zTheirs", "Theirs").await;

        heartbeat_device(
            &acl_ks,
            &device_auth("did:key:zMine"),
            None,
            Some(&name_ext("Renamed")),
        )
        .await
        .unwrap();

        let theirs = get_acl_entry(&acl_ks, "did:key:zTheirs")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(theirs.device.unwrap().display_name, "Theirs");
    }

    /// A malformed extension must not fail the heartbeat: `lastSeenAt` is the
    /// call's real job, and a device that looks offline sends an operator
    /// chasing a machine that is running fine.
    #[tokio::test]
    async fn an_unusable_name_is_ignored_and_the_heartbeat_still_lands() {
        let (acl_ks, audit, _dir) = fresh().await;
        let did = "did:key:zDevice";
        registered(&acl_ks, &audit, did, "Original").await;

        for bad in [
            serde_json::json!({ EXT_DEVICE_NAME: { "displayName": "   " } }),
            serde_json::json!({ EXT_DEVICE_NAME: { "displayName": "x".repeat(129) } }),
            serde_json::json!({ EXT_DEVICE_NAME: { "displayName": 42 } }),
            serde_json::json!({ EXT_DEVICE_NAME: { "somethingElse": "y" } }),
            serde_json::json!({ "org.example.unrelated": { "displayName": "Hijack" } }),
        ] {
            let ext: heartbeat_spec::Ext = serde_json::from_value(bad.clone()).unwrap();
            heartbeat_device(&acl_ks, &device_auth(did), None, Some(&ext))
                .await
                .unwrap_or_else(|e| panic!("heartbeat must survive {bad}: {e:?}"));

            let entry = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
            let b = entry.device.unwrap();
            assert_eq!(b.display_name, "Original", "{bad} must not rename");
            assert!(
                b.last_seen_at.is_some(),
                "{bad} must still refresh liveness"
            );
        }
    }

    /// A name is trimmed, and one that is already current is a no-op.
    #[tokio::test]
    async fn a_name_is_trimmed_and_an_unchanged_one_is_a_no_op() {
        let (acl_ks, audit, _dir) = fresh().await;
        let did = "did:key:zDevice";
        registered(&acl_ks, &audit, did, "Original").await;

        heartbeat_device(
            &acl_ks,
            &device_auth(did),
            None,
            Some(&name_ext("  Trimmed  ")),
        )
        .await
        .unwrap();
        let entry = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
        assert_eq!(entry.device.unwrap().display_name, "Trimmed");

        heartbeat_device(&acl_ks, &device_auth(did), None, Some(&name_ext("Trimmed")))
            .await
            .unwrap();
        let entry = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
        assert_eq!(entry.device.unwrap().display_name, "Trimmed");
        assert_eq!(entry.version, 1);
    }

    /// The boundary the untyped `ext` slot has to enforce itself, since the
    /// register schema's `maxLength: 128` cannot reach it.
    #[test]
    fn the_name_length_bound_matches_the_register_schema() {
        let at_limit = "x".repeat(MAX_DISPLAY_NAME_CHARS);
        assert_eq!(
            extension_display_name(Some(&name_ext(&at_limit))).as_deref(),
            Some(at_limit.as_str())
        );
        let over = "x".repeat(MAX_DISPLAY_NAME_CHARS + 1);
        assert!(extension_display_name(Some(&name_ext(&over))).is_none());
        assert!(extension_display_name(None).is_none());
    }

    #[tokio::test]
    async fn heartbeat_rejects_unregistered_device() {
        let (acl_ks, _audit, _dir) = fresh().await;
        // ACL entry exists but no DeviceBinding attached.
        store_acl_entry(
            &acl_ks,
            &AclEntry::new("did:key:zBare", Role::Application, "did:key:zSetup"),
        )
        .await
        .unwrap();
        let err = heartbeat_device(&acl_ks, &device_auth("did:key:zBare"), None, None)
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
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    /// A context admin: `Role::Admin` with a **non-empty** context list, so its
    /// [`ActScope`](vta_sdk::acl::ActScope) is `Contexts`, not `All`.
    fn context_admin(did: &str, contexts: &[&str]) -> AuthClaims {
        AuthClaims {
            did: did.into(),
            role: Role::Admin,
            allowed_contexts: contexts.iter().map(|c| (*c).to_string()).collect(),
            ..admin_auth()
        }
    }

    /// Register a device against an ACL entry scoped to `contexts`.
    async fn registered_in(
        acl_ks: &KeyspaceHandle,
        audit: &vta_audit::SharedAuditSink,
        did: &str,
        contexts: &[&str],
        name: &str,
    ) {
        store_acl_entry(
            acl_ks,
            &AclEntry::new(did, Role::Application, "did:key:zSetup")
                .with_contexts(contexts.iter().map(|c| (*c).to_string()).collect()),
        )
        .await
        .unwrap();
        register_device(
            acl_ks,
            audit,
            &device_auth(did),
            mobile_kind(),
            name.into(),
            None,
            Some("did:key:zHpke".into()),
            "test",
        )
        .await
        .unwrap();
    }

    async fn listed_names(acl_ks: &KeyspaceHandle, auth: &AuthClaims) -> Vec<String> {
        let body = list_devices(acl_ks, auth, &list_payload(json!({})))
            .await
            .unwrap();
        body["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["displayName"].as_str().unwrap().to_string())
            .collect()
    }

    async fn device_id_of(acl_ks: &KeyspaceHandle, did: &str) -> String {
        get_acl_entry(acl_ks, did)
            .await
            .unwrap()
            .unwrap()
            .device
            .unwrap()
            .device_id
    }

    /// The #1216 defect: `require_manage` is role-only, so a context admin read
    /// every binding on the VTA — hostnames and activity windows from contexts
    /// they hold no rights in.
    #[tokio::test]
    async fn a_context_admin_lists_only_its_own_contexts_devices() {
        let (acl_ks, audit, _dir) = fresh().await;
        registered_in(&acl_ks, &audit, "did:key:zEng", &["acme/eng"], "eng-laptop").await;
        registered_in(&acl_ks, &audit, "did:key:zOps", &["acme/ops"], "ops-laptop").await;

        let names = listed_names(&acl_ks, &context_admin("did:key:zEngAdmin", &["acme/eng"])).await;
        assert_eq!(
            names,
            ["eng-laptop"],
            "a context admin must not see acme/ops"
        );
    }

    /// Folder authority: an admin of a parent context covers the whole subtree,
    /// the same ancestry `has_context_access` applies elsewhere.
    #[tokio::test]
    async fn a_parent_context_admin_lists_the_subtree() {
        let (acl_ks, audit, _dir) = fresh().await;
        registered_in(
            &acl_ks,
            &audit,
            "did:key:zTeam",
            &["acme/eng/team-a"],
            "team-a",
        )
        .await;
        registered_in(&acl_ks, &audit, "did:key:zOther", &["other"], "other").await;

        let names = listed_names(&acl_ks, &context_admin("did:key:zAcmeAdmin", &["acme"])).await;
        assert_eq!(names, ["team-a"]);
    }

    /// A super-admin is unchanged — the fix must not narrow the one caller that
    /// legitimately sees everything.
    #[tokio::test]
    async fn a_super_admin_still_lists_every_device() {
        let (acl_ks, audit, _dir) = fresh().await;
        registered_in(&acl_ks, &audit, "did:key:zEng", &["acme/eng"], "eng-laptop").await;
        registered_in(&acl_ks, &audit, "did:key:zOps", &["acme/ops"], "ops-laptop").await;
        registered_in(&acl_ks, &audit, "did:key:zRoot", &[], "root-box").await;

        let mut names = listed_names(&acl_ks, &admin_auth()).await;
        names.sort();
        assert_eq!(names, ["eng-laptop", "ops-laptop", "root-box"]);
    }

    /// The regression guard for the `allowed_contexts.is_empty()` reading: an
    /// **Initiator** with no contexts is authorized *nowhere*, not everywhere.
    /// It passes `require_manage` on role alone, which is exactly why the role
    /// test was never sufficient.
    #[tokio::test]
    async fn an_authorized_nowhere_manager_lists_nothing() {
        let (acl_ks, audit, _dir) = fresh().await;
        registered_in(&acl_ks, &audit, "did:key:zEng", &["acme/eng"], "eng-laptop").await;

        let nowhere = AuthClaims {
            did: "did:key:zNowhere".into(),
            role: Role::Initiator,
            allowed_contexts: vec![],
            ..admin_auth()
        };
        assert!(
            nowhere.require_manage().is_ok(),
            "role gate alone still passes"
        );
        assert!(
            listed_names(&acl_ks, &nowhere).await.is_empty(),
            "an acts-nowhere entry must see no devices"
        );
    }

    /// A super-admin's own device names no context, so it is not inside any
    /// context admin's subtree — the `ActScope::All` edge.
    #[tokio::test]
    async fn a_context_admin_does_not_see_an_unrestricted_entrys_device() {
        let (acl_ks, audit, _dir) = fresh().await;
        store_acl_entry(
            &acl_ks,
            &AclEntry::new("did:key:zRoot", Role::Admin, "did:key:zSetup"),
        )
        .await
        .unwrap();
        register_device(
            &acl_ks,
            &audit,
            &device_auth("did:key:zRoot"),
            mobile_kind(),
            "root-box".into(),
            None,
            Some("did:key:zHpke".into()),
            "test",
        )
        .await
        .unwrap();

        assert!(
            listed_names(&acl_ks, &context_admin("did:key:zEngAdmin", &["acme/eng"]))
                .await
                .is_empty()
        );
    }

    /// Worse than the listing: disable had no scope check at all, so a context
    /// admin could disable any device on the VTA by id.
    #[tokio::test]
    async fn disable_refuses_a_device_outside_the_callers_contexts() {
        let (acl_ks, audit, _dir) = fresh().await;
        registered_in(&acl_ks, &audit, "did:key:zOps", &["acme/ops"], "ops-laptop").await;
        let id = device_id_of(&acl_ks, "did:key:zOps").await;

        let err = disable_device(
            &acl_ks,
            &audit,
            &context_admin("did:key:zEngAdmin", &["acme/eng"]),
            &id,
        )
        .await
        .expect_err("a device outside the caller's contexts must be refused");
        // Conflated to NotFound so the error cannot confirm the id exists.
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");

        let binding = get_acl_entry(&acl_ks, "did:key:zOps")
            .await
            .unwrap()
            .unwrap()
            .device
            .unwrap();
        assert!(binding.disabled_at.is_none(), "the refusal must not mutate");
    }

    #[tokio::test]
    async fn wipe_refuses_a_device_outside_the_callers_contexts() {
        let (acl_ks, audit, _dir) = fresh().await;
        registered_in(&acl_ks, &audit, "did:key:zOps", &["acme/ops"], "ops-laptop").await;
        let id = device_id_of(&acl_ks, "did:key:zOps").await;

        let err = wipe_device(
            &acl_ks,
            &audit,
            &context_admin("did:key:zEngAdmin", &["acme/eng"]),
            &id,
            "lost",
            "full",
        )
        .await
        .expect_err("a device outside the caller's contexts must be refused");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");

        let binding = get_acl_entry(&acl_ks, "did:key:zOps")
            .await
            .unwrap()
            .unwrap()
            .device
            .unwrap();
        assert!(binding.wiped_at.is_none(), "the refusal must not mutate");
    }

    /// The in-scope path still works, so the gate is a scope check and not a
    /// blanket refusal.
    #[tokio::test]
    async fn disable_allows_a_device_inside_the_callers_contexts() {
        let (acl_ks, audit, _dir) = fresh().await;
        registered_in(&acl_ks, &audit, "did:key:zEng", &["acme/eng"], "eng-laptop").await;
        let id = device_id_of(&acl_ks, "did:key:zEng").await;

        disable_device(
            &acl_ks,
            &audit,
            &context_admin("did:key:zEngAdmin", &["acme/eng"]),
            &id,
        )
        .await
        .expect("an in-scope device must be disableable");
    }

    fn list_payload(v: Value) -> list_spec::Payload {
        serde_json::from_value(v).expect("valid list payload")
    }

    async fn seed_and_register(
        acl_ks: &KeyspaceHandle,
        audit: &vta_audit::SharedAuditSink,
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
            audit,
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
        let (acl_ks, audit, _dir) = fresh().await;
        seed_and_register(
            &acl_ks,
            &audit,
            "did:key:zPhone",
            CompanionFormFactor::Mobile,
            "Phone",
        )
        .await;
        seed_and_register(
            &acl_ks,
            &audit,
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
        let d = disable_device(&acl_ks, &audit, &admin_auth(), &phone_id)
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
        let (acl_ks, audit, _dir) = fresh().await;
        let err = disable_device(&acl_ks, &audit, &admin_auth(), "dev-nope")
            .await
            .expect_err("unknown deviceId must be NotFound");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn wipe_marks_wiped_and_disabled_then_hidden() {
        let (acl_ks, audit, _dir) = fresh().await;
        seed_and_register(
            &acl_ks,
            &audit,
            "did:key:zLost",
            CompanionFormFactor::Desktop,
            "Laptop",
        )
        .await;
        let all = list_devices(&acl_ks, &admin_auth(), &list_payload(json!({})))
            .await
            .unwrap();
        let id = all["devices"][0]["deviceId"].as_str().unwrap().to_string();

        let w = wipe_device(&acl_ks, &audit, &admin_auth(), &id, "stolen", "full")
            .await
            .unwrap();
        // Canonical `device/wipe/0.1` response shape (#857): exactly
        // `{deviceId, scope, completedAt}` — the schema is closed, so the
        // pre-fix `wipedAt`/`disabledAt`/`reason` members must be gone.
        assert_eq!(w["deviceId"], id.as_str());
        assert!(w["completedAt"].is_string());
        assert_eq!(w["scope"], "full");
        for legacy in ["wipedAt", "disabledAt", "reason"] {
            assert!(w.get(legacy).is_none(), "{legacy} is not in the schema");
        }
        // The disable side-effect is still asserted below: the wiped device
        // only reappears with includeDisabled + includeWiped.

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
        let (acl_ks, audit, _dir) = fresh().await;
        let err = wipe_device(&acl_ks, &audit, &admin_auth(), "dev-nope", "r", "full")
            .await
            .expect_err("unknown deviceId must be NotFound");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn set_wake_records_channel_and_vta_owned_allowlist() {
        let (acl_ks, audit, _dir) = fresh().await;
        let did = "did:key:zDevice";
        seed_and_register(&acl_ks, &audit, did, CompanionFormFactor::Mobile, "Phone").await;

        let body = set_wake_device(
            &acl_ks,
            &audit,
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
        let (acl_ks, audit, _dir) = fresh().await;
        let did = "did:key:zDevice";
        seed_and_register(&acl_ks, &audit, did, CompanionFormFactor::Mobile, "Phone").await;
        set_wake_device(
            &acl_ks,
            &audit,
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
            &audit,
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
        let (acl_ks, audit, _dir) = fresh().await;
        store_acl_entry(
            &acl_ks,
            &AclEntry::new("did:key:zBare", Role::Application, "did:key:zSetup"),
        )
        .await
        .unwrap();
        let err = set_wake_device(
            &acl_ks,
            &audit,
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
