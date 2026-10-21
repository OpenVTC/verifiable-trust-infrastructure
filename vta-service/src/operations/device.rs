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
    WakeChannel, effective_capabilities, get_acl_entry, is_acl_entry_visible, list_acl_entries,
    store_acl_entry, validate_role_assignment,
};

/// Whether `auth` may manage the device bound to `entry`: it can see the entry
/// (context scope) *and* is at least as privileged as the entry's role, the
/// rule `acl/delete` applies to the same entry. Visibility alone let an
/// initiator disable or wipe the device of an admin in its context.
fn device_manageable_by(auth: &AuthClaims, entry: &AclEntry) -> bool {
    is_acl_entry_visible(auth, entry) && validate_role_assignment(auth, &entry.role).is_ok()
}
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
use vta_sdk::protocols::device_management::{
    EXT_UV_KEY, EXT_UV_KEY_CHANGE, UvKeyEnrolment, UvKeyMaterial,
};
use vti_common::acl::UvKey;

use super::uv_pin::{self, PinRefusal, PinStatus};

/// The UV key a `device/register` or `device/heartbeat` payload's `ext`
/// carries under [`EXT_UV_KEY`], if any.
///
/// Unlike [`extension_display_name`], a malformed one is **refused**, not
/// ignored: enrolling a UV key is a security decision the device is waiting
/// on, and a device told "ok" for a key that was dropped would believe it can
/// approve sign-ins when the VTA will refuse every one.
pub fn extension_uv_key<'a>(
    ext: impl IntoIterator<Item = (&'a str, &'a Value)>,
) -> Result<Option<UvKeyEnrolment>, AppError> {
    let Some((_, value)) = ext.into_iter().find(|(k, _)| *k == EXT_UV_KEY) else {
        return Ok(None);
    };
    UvKeyEnrolment::from_ext_value(value)
        .map(Some)
        .map_err(|e| AppError::Validation(format!("device:uvKeyInvalid — {e}")))
}

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
/// **One device, one row.** Each of a member's devices — every browser
/// install, every phone — enrols under a DID of its own and so has an ACL
/// entry of its own; this writes the binding and `consumerKind` of that row
/// and no other. A member with N devices has N entries, and registering,
/// renaming (heartbeat), re-keying (heartbeat), disabling or wiping one leaves
/// the others — and the member's own administrative entries, which are not
/// devices — exactly as they were.
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
    uv_key: Option<UvKeyEnrolment>,
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
        last_seen_at: Some(now.clone()),
        disabled_at: None,
        wiped_at: None,
        hpke_public_key,
        wake: None,
        uv_key: uv_key.map(|enrolment| UvKey {
            enrolment,
            enrolled_at: now.clone(),
        }),
    };
    let uv_detail = binding.uv_key.as_ref().map(uv_key_audit_detail);

    entry.kind = consumer_kind;
    entry.device = Some(binding);
    entry.version = entry.version.saturating_add(1);
    store_acl_entry(acl_ks, &entry).await?;

    info!(channel, did = %did, uv_key = uv_detail.is_some(), "device registered");
    audit::record_best_effort(
        audit,
        "device.register",
        &did,
        Some(&did),
        "success",
        Some(channel),
        None,
    )
    .await;
    if let Some(detail) = uv_detail {
        crate::audit::record_with_detail_best_effort(
            audit,
            "device.uv-key.enrol",
            &did,
            Some(&did),
            "success",
            Some(channel),
            None,
            Some(&detail),
        )
        .await;
    }

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
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    platform: Option<String>,
    ext: Option<&heartbeat_spec::Ext>,
) -> Result<Value, AppError> {
    heartbeat_device_checked(
        acl_ks,
        audit,
        auth,
        platform,
        ext,
        chrono::Utc::now().timestamp(),
    )
    .await
    .map_err(AppError::from)
}

/// Why a heartbeat was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum HeartbeatError {
    App(AppError),
    /// Replacing a `vtaPin` UV key was refused for want of the current PIN.
    /// `code` is the `device:*` code, `details` the refusal's machine-readable
    /// member (`code`, and `attemptsRemaining` or `lockedUntil`).
    UvKeyChange {
        code: &'static str,
        message: String,
        details: Value,
    },
}

impl From<AppError> for HeartbeatError {
    fn from(e: AppError) -> Self {
        HeartbeatError::App(e)
    }
}

impl From<HeartbeatError> for AppError {
    fn from(e: HeartbeatError) -> Self {
        match e {
            HeartbeatError::App(e) => e,
            HeartbeatError::UvKeyChange { code, message, .. } => {
                AppError::Forbidden(format!("{code} — {message}"))
            }
        }
    }
}

/// [`heartbeat_device`], with the clock `now` (unix seconds) the PIN guess
/// limit reads, and a typed refusal for a `vtaPin` change.
///
/// Replacing a `vtaPin` UV key — with any new key — needs
/// `ext["org.openvtc.uv-key-change"].pinProof`, an HMAC by the **current**
/// PIN over the new enrolment ([`uv_pin::change_message`]), counted against the
/// same guess limit as a sign-in. Without it, a copied browser profile (which
/// holds the transport key that authenticates this call) could swap the PIN
/// for one it chose and so walk around the limit. Enrolling where there is no
/// key, or replacing a key of another kind, needs nothing extra.
pub async fn heartbeat_device_checked(
    acl_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    platform: Option<String>,
    ext: Option<&heartbeat_spec::Ext>,
    now: i64,
) -> Result<Value, HeartbeatError> {
    // Read (and refuse) a UV key replacement before touching the row, so a bad
    // one leaves the binding exactly as it was.
    let ext_member = |key: &str| -> Option<Value> {
        ext.and_then(|e| {
            e.iter()
                .find(|(k, _)| k.as_str() == key)
                .map(|(_, v)| v.clone())
        })
    };
    let uv_replacement = extension_uv_key(
        ext.into_iter()
            .flat_map(|e| e.iter().map(|(k, v)| (k.as_str(), v))),
    )?;
    let sent_uv_key = ext_member(EXT_UV_KEY).unwrap_or(Value::Null);
    let change_proof: Option<String> = ext_member(EXT_UV_KEY_CHANGE).and_then(|v| {
        v.get("pinProof")
            .and_then(Value::as_str)
            .map(str::to_string)
    });
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

    let now_rfc3339 = chrono::Utc::now().to_rfc3339();
    binding.last_seen_at = Some(now_rfc3339.clone());
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
    // A replacement UV key (base design §11 item 5) is accepted only here: the
    // entry was fetched by `auth.did`, the device's own transport key, so no
    // other caller — an administrator included — can put a key on this row. A
    // disabled or wiped device approves nothing, so it may not re-key either.
    let uv_detail = match uv_replacement {
        Some(enrolment) => {
            if binding.disabled_at.is_some() || binding.wiped_at.is_some() {
                return Err(AppError::Forbidden(format!(
                    "device/heartbeat:deviceDisabled — {did} is disabled and cannot enrol a UV key"
                ))
                .into());
            }
            if let Some(current) = binding.uv_key.as_ref()
                && matches!(current.enrolment.key, UvKeyMaterial::VtaPin { .. })
            {
                authorize_pin_change(
                    acl_ks,
                    audit,
                    &did,
                    current,
                    &sent_uv_key,
                    change_proof.as_deref(),
                    now,
                )
                .await?;
            }
            let replaced = binding.uv_key.is_some();
            let key = UvKey {
                enrolment,
                enrolled_at: now_rfc3339.clone(),
            };
            let detail = uv_key_audit_detail(&key);
            binding.uv_key = Some(key);
            Some((replaced, detail))
        }
        None => None,
    };
    let uv_summary = match binding.uv_key.as_ref() {
        Some(key) => Some(uv_key_summary(
            key,
            pin_status(acl_ks, &did, key, now).await,
        )),
        None => None,
    };
    store_acl_entry(acl_ks, &entry).await?;
    if let Some((replaced, detail)) = uv_detail {
        info!(did = %did, replaced, "device enrolled a UV key");
        crate::audit::record_with_detail_best_effort(
            audit,
            if replaced {
                "device.uv-key.replace"
            } else {
                "device.uv-key.enrol"
            },
            &did,
            Some(&did),
            "success",
            None,
            None,
            Some(&detail),
        )
        .await;
    }

    let mut out = json!({
        "serverTime": now_rfc3339,
        "queuedOperations": [],
        "syncHint": "up-to-date",
    });
    // The device's own UV key summary — never the key — so a browser whose
    // local state was cleared can recover a PIN's salt and iterations, and see
    // a lock, without a management read.
    if let Some(summary) = uv_summary {
        out["ext"] = json!({ EXT_UV_KEY: summary });
    }
    Ok(out)
}

/// Check the `pinProof` that authorises replacing the `vtaPin` key `current`
/// with the enrolment `sent` (the `org.openvtc.uv-key` value as received).
async fn authorize_pin_change(
    acl_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    did: &str,
    current: &UvKey,
    sent: &Value,
    proof: Option<&str>,
    now: i64,
) -> Result<(), HeartbeatError> {
    let refuse = |code: &'static str, message: &str, details: Value| HeartbeatError::UvKeyChange {
        code,
        message: message.to_string(),
        details,
    };
    let Some(proof) = proof else {
        return Err(refuse(
            "device:uvKeyChangeProofRequired",
            "this device's UV key is a PIN; replacing it needs \
             ext.org.openvtc.uv-key-change.pinProof made with the current PIN",
            json!({ "code": "device:uvKeyChangeProofRequired" }),
        ));
    };
    let message = uv_pin::change_message(sent)?;
    match uv_pin::check(acl_ks, did, current, &message, proof, now).await {
        Ok(()) => Ok(()),
        Err(refusal) => {
            uv_pin::audit_refusal(audit, did, "uv-key-change", &refusal).await;
            Err(match refusal {
                PinRefusal::Locked { locked_until } => refuse(
                    "device:uvKeyLocked",
                    "too many wrong PINs; the PIN is locked",
                    json!({ "code": "device:uvKeyLocked", "lockedUntil": locked_until }),
                ),
                PinRefusal::Wrong {
                    attempts_remaining,
                    locked_until,
                    ..
                } => {
                    let mut details = json!({
                        "code": "device:uvPinWrong",
                        "attemptsRemaining": attempts_remaining,
                    });
                    if let Some(t) = locked_until {
                        details["lockedUntil"] = json!(t);
                    }
                    refuse("device:uvPinWrong", "the current PIN is wrong", details)
                }
                PinRefusal::Malformed => refuse(
                    "device:uvKeyChangeProofInvalid",
                    "pinProof must be a 32-byte HMAC in base64url",
                    json!({ "code": "device:uvKeyChangeProofInvalid" }),
                ),
                PinRefusal::NotAPin => HeartbeatError::App(AppError::Internal(
                    "the stored PIN verifier is unreadable".into(),
                )),
                PinRefusal::App(e) => HeartbeatError::App(e),
            })
        }
    }
}

/// The guard state a `vtaPin` summary shows; `None` for any other kind.
async fn pin_status(
    acl_ks: &KeyspaceHandle,
    did: &str,
    key: &UvKey,
    now: i64,
) -> Option<PinStatus> {
    match key.enrolment.key {
        UvKeyMaterial::VtaPin { .. } => Some(uv_pin::status(acl_ks, did, key, now).await),
        _ => None,
    }
}

/// Whether `candidate` may be named as `device`'s `remoteApprover` — the
/// member's phone that approves this browser's sign-ins.
///
/// A browser must not be able to name a DID it controls: the approval would
/// then be its own. A browser device is commonly a context admin, and a context
/// admin can create ACL entries in its contexts and register them as devices,
/// so neither "has an ACL entry" nor "is a registered mobile companion" is
/// something it cannot forge. What it cannot write is the operator's own
/// designation of an approver, so that is the rule:
///
/// 1. the candidate is not the device itself, and holds a live (unexpired) ACL
///    entry;
/// 2. it is **designated by the operator** as an approver, either as this
///    device's own `stepUpApprover` (set on the device's entry by another
///    administrator — an entry may not modify itself, `acl/update`), or as a
///    member of an approver set (`pnm approvals approvers add`, written only
///    by a super-admin through `policy/upsert`). Both are how the phone app is
///    named today (`pnm acl create --did <phone>` then one of those two);
/// 3. the device did not create the candidate's entry;
/// 4. if the candidate carries a device binding of its own, it is an active
///    mobile or desktop companion — never another browser or a service. The
///    phone app itself registers no binding, so an entry without one passes.
pub fn uv_approver_eligible(
    device: &AclEntry,
    candidate: &AclEntry,
    approver_set_members: &std::collections::HashSet<String>,
    now_unix: u64,
) -> bool {
    if candidate.did == device.did || candidate.is_expired(now_unix) {
        return false;
    }
    let designated = device.step_up_approver.as_deref() == Some(candidate.did.as_str())
        || approver_set_members.contains(&candidate.did);
    if !designated || candidate.created_by == device.did {
        return false;
    }
    match &candidate.device {
        None => true,
        Some(b) => {
            b.disabled_at.is_none()
                && b.wiped_at.is_none()
                && matches!(
                    candidate.kind,
                    ConsumerKind::Companion {
                        form_factor: CompanionFormFactor::Mobile | CompanionFormFactor::Desktop
                    }
                )
        }
    }
}

/// The approvers `device_did` may name ([`uv_approver_eligible`]), as
/// `[{ did, displayName?, formFactor? }]` for a picker.
pub async fn uv_approvers(
    acl_ks: &KeyspaceHandle,
    device_did: &str,
    approver_set_members: &std::collections::HashSet<String>,
    now_unix: u64,
) -> Result<Vec<Value>, AppError> {
    let Some(device) = get_acl_entry(acl_ks, device_did).await? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for candidate in list_acl_entries(acl_ks).await? {
        if !uv_approver_eligible(&device, &candidate, approver_set_members, now_unix) {
            continue;
        }
        let mut row = json!({ "did": candidate.did });
        let name = candidate
            .device
            .as_ref()
            .map(|b| b.display_name.clone())
            .or_else(|| candidate.label.clone());
        if let Some(name) = name {
            row["displayName"] = json!(name);
        }
        if candidate.device.is_some()
            && let ConsumerKind::Companion { form_factor } = &candidate.kind
        {
            row["formFactor"] = json!(match form_factor {
                CompanionFormFactor::Browser => "browser",
                CompanionFormFactor::Mobile => "mobile",
                CompanionFormFactor::Desktop => "desktop",
            });
        }
        out.push(row);
    }
    Ok(out)
}

/// Refuse a `remoteApprover` enrolment naming an approver the device may not
/// name. Any other enrolment passes.
pub async fn require_uv_approver_permitted(
    acl_ks: &KeyspaceHandle,
    device_did: &str,
    enrolment: Option<&UvKeyEnrolment>,
    approver_set_members: &std::collections::HashSet<String>,
    now_unix: u64,
) -> Result<(), AppError> {
    let Some(UvKeyMaterial::RemoteApprover { approver }) = enrolment.map(|e| &e.key) else {
        return Ok(());
    };
    if uv_approver_permitted(acl_ks, device_did, approver, approver_set_members, now_unix).await? {
        Ok(())
    } else {
        Err(AppError::Validation(
            "device:uvApproverNotPermitted — the remote approver must be another of your \
             devices that the operator has designated as an approver (this device's \
             stepUpApprover, or a member of an approver set); list the candidates with \
             device/heartbeat ext org.openvtc.uv-approvers"
                .into(),
        ))
    }
}

/// Whether `device_did` may name `approver` ([`uv_approver_eligible`]),
/// against the ACL as it stands.
pub async fn uv_approver_permitted(
    acl_ks: &KeyspaceHandle,
    device_did: &str,
    approver: &str,
    approver_set_members: &std::collections::HashSet<String>,
    now_unix: u64,
) -> Result<bool, AppError> {
    let (Some(device), Some(candidate)) = (
        get_acl_entry(acl_ks, device_did).await?,
        get_acl_entry(acl_ks, approver).await?,
    ) else {
        return Ok(false);
    };
    Ok(uv_approver_eligible(
        &device,
        &candidate,
        approver_set_members,
        now_unix,
    ))
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
        if !device_manageable_by(auth, entry) {
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
        let pin = match b.uv_key.as_ref() {
            Some(key) => pin_status(acl_ks, &entry.did, key, chrono::Utc::now().timestamp()).await,
            None => None,
        };
        devices.push(to_wire_binding_with(entry, pin));
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
/// [`device_manageable_by`] (visibility plus [`validate_role_assignment`]) is
/// the *management* predicate, not the wider
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
        .filter(|e| device_manageable_by(auth, e))
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
    audit::record_best_effort(
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
    audit::record_best_effort(
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
        audit::record_best_effort(
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
    audit::record_best_effort(
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
    to_wire_binding_with(entry, None)
}

/// [`to_wire_binding`], with a `vtaPin` key's guard state for its summary.
pub fn to_wire_binding_with(entry: &AclEntry, pin: Option<PinStatus>) -> Value {
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
    let mut openvtc = serde_json::Map::new();
    if !local_caps.is_empty() {
        // Reverse-DNS namespaced per SPEC §4.5.1: these are this ecosystem's
        // capabilities, not the framework's, so they travel in the slot the
        // framework provides rather than widening its closed enum.
        openvtc.insert("capabilities".into(), json!(local_caps));
    }
    if let Some(uv) = &b.uv_key {
        // The binding schema has no UV-key member yet, so its summary rides
        // in the same slot.
        openvtc.insert("uvKey".into(), uv_key_summary(uv, pin));
    }
    if !openvtc.is_empty() {
        map.insert("ext".into(), json!({ "org.openvtc": openvtc }));
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

/// What the audit trail records about a UV key: its kind, its public
/// identifier and the device's claims about it — never anything secret. A
/// `vtaPin` key's verifier is the one secret a UV key carries, and it is in
/// neither the summary nor `publicKey`.
fn uv_key_audit_detail(key: &UvKey) -> String {
    json!({
        "uvKey": uv_key_summary(key, None),
        "publicKey": match &key.enrolment.key {
            UvKeyMaterial::HardwareKey { did } | UvKeyMaterial::PrfSealedKey { did } => did.clone(),
            UvKeyMaterial::Webauthn { credential_id, .. } => credential_id.clone(),
            UvKeyMaterial::RemoteApprover { approver } => approver.clone(),
            _ => String::new(),
        },
    })
    .to_string()
}

/// The binding's view of its UV key, for `device/list`, the register and the
/// heartbeat responses: enough for a device to know whether, and how, it can
/// approve grants. For a `vtaPin` key: the salt and iterations (so a browser
/// that lost its local state can derive `K` again) and the guess-limit state —
/// **never** the verifier. For a `remoteApprover`: the approver's DID.
fn uv_key_summary(key: &UvKey, pin: Option<PinStatus>) -> Value {
    let kind = match &key.enrolment.key {
        UvKeyMaterial::HardwareKey { .. } => "hardwareKey",
        UvKeyMaterial::PrfSealedKey { .. } => "prfSealedKey",
        UvKeyMaterial::Webauthn { .. } => "webauthn",
        UvKeyMaterial::VtaPin { .. } => "vtaPin",
        UvKeyMaterial::RemoteApprover { .. } => "remoteApprover",
        _ => "unknown",
    };
    let mut out = json!({
        "kind": kind,
        "hardwareBacked": key.enrolment.hardware_backed,
        "biometricGated": key.enrolment.biometric_gated,
        "attestationPresented": key.enrolment.attestation.is_some(),
        "enrolledAt": key.enrolled_at,
    });
    match &key.enrolment.key {
        UvKeyMaterial::VtaPin {
            salt, iterations, ..
        } => {
            let pin = pin.unwrap_or_default();
            out["salt"] = json!(salt);
            out["iterations"] = json!(iterations);
            out["failedAttempts"] = json!(pin.failed_attempts);
            out["lockedUntil"] = json!(pin.locked_until);
        }
        UvKeyMaterial::RemoteApprover { approver } => {
            out["approver"] = json!(approver);
        }
        _ => {}
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
                // `ServiceKind` is `#[non_exhaustive]`: its kebab-case serde
                // name is the wire value.
                other => return json!({ "kind": "service", "serviceKind": other }),
            },
        }),
        // `ConsumerKind` is `#[non_exhaustive]`: its serde form is the wire form.
        _ => serde_json::to_value(kind).unwrap_or(Value::Null),
    }
}

/// Whether `cap` is a member of the published `device/_shared` `Capability`
/// enum, and so belongs in a binding's `capabilities` rather than under `ext`.
///
/// Answered by the **generated** type, not a hand-kept list. The hand-kept list
/// this replaces drifted twice: first a local capability (`CredentialWrite`)
/// leaked into the closed enum because a by-name filter was not extended, then —
/// once it was listed positively — the specification registered `signTrustTask`,
/// `credentialWrite`, `memoryRead`/`memoryWrite` and `roomPresent`/`roomOpen`
/// and the list did not follow, so every one of them was reported as
/// ecosystem-local and a `capabilityFilter` naming one could never match. Asking
/// the generated enum whether it can read the name makes the partition move with
/// the specification through a `trust-tasks-rs` bump, and keeps a capability the
/// specification has not registered (`keyExport`, `personaHolder`) in `ext`.
fn is_published_capability(cap: &Capability) -> bool {
    serde_json::to_value(cap)
        .ok()
        .and_then(|v| serde_json::from_value::<list_spec::Capability>(v).ok())
        .is_some()
}

/// The capabilities an ACL entry confers, split into what the published
/// `capabilities` member may carry and what belongs under `ext`.
///
/// What is listed is the entry's **effective** set
/// ([`effective_capabilities`]), never its stored list. The stored list is a
/// narrowing of the role plus any additive grant by name, not a statement of
/// what the entry holds: an entry whose list is just `[PersonaHolder]` holds its
/// whole role *and* holder authority, and reading the stored list verbatim
/// reported it as holding holder authority alone. A listing that under-reports
/// an authority is a safety claim, and it is not a true one.
///
/// Ecosystem-local capabilities are **carried, not dropped**. SPEC §4.5.1 has
/// an extension slot for exactly this, and `DeviceBinding` declares one; the
/// earlier approach silently omitted `sign-trust-task`, which told a reader the
/// device lacked an authority it actually held.
fn split_capabilities(entry: &AclEntry) -> (Vec<Value>, Vec<Value>) {
    let caps = effective_capabilities(&entry.role, &entry.capabilities);
    let (published, local): (Vec<_>, Vec<_>) =
        caps.iter().partition(|c| is_published_capability(c));
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
            uv_key: None,
        });
        e
    }

    /// The remote-approver rule (`uv_approver_eligible`): only an entry the
    /// operator designated, that the browser did not create, that is not
    /// itself, expired, a browser, a service, or a disabled device.
    #[test]
    fn a_remote_approver_must_be_designated_by_the_operator() {
        use std::collections::HashSet;
        let browser = AclEntry::new("did:key:zBrowser", Role::Admin, "did:key:zAdmin")
            .with_step_up_approver(Some("did:key:zPhone".into()));
        let phone = AclEntry::new("did:key:zPhone", Role::Reader, "did:key:zAdmin");
        let none = HashSet::new();
        assert!(uv_approver_eligible(&browser, &phone, &none, 0));

        // Undesignated: neither the step-up approver nor in any set.
        let tablet = AclEntry::new("did:key:zTablet", Role::Reader, "did:key:zAdmin");
        assert!(!uv_approver_eligible(&browser, &tablet, &none, 0));
        let sets: HashSet<String> = ["did:key:zTablet".to_string()].into();
        assert!(uv_approver_eligible(&browser, &tablet, &sets, 0));

        // Itself, or one it created.
        let me = browser
            .clone()
            .with_step_up_approver(Some("did:key:zBrowser".into()));
        assert!(!uv_approver_eligible(&me, &me, &none, 0));
        let minted = AclEntry::new("did:key:zPhone", Role::Reader, "did:key:zBrowser");
        assert!(!uv_approver_eligible(&browser, &minted, &none, 0));

        // Expired.
        let lapsed = phone.clone().with_expires_at(Some(10));
        assert!(!uv_approver_eligible(&browser, &lapsed, &none, 10));

        // A registered device must be an active phone or desktop.
        let mut registered = entry_with_binding();
        registered.did = "did:key:zPhone".into();
        registered.created_by = "did:key:zAdmin".into();
        assert!(uv_approver_eligible(&browser, &registered, &none, 0));
        let mut other_browser = registered.clone();
        other_browser.kind = ConsumerKind::Companion {
            form_factor: CompanionFormFactor::Browser,
        };
        assert!(!uv_approver_eligible(&browser, &other_browser, &none, 0));
        let mut service = registered.clone();
        service.kind = ConsumerKind::default();
        assert!(!uv_approver_eligible(&browser, &service, &none, 0));
        let mut disabled = registered.clone();
        disabled.device.as_mut().unwrap().disabled_at = Some("2026-01-01T00:00:00Z".into());
        assert!(!uv_approver_eligible(&browser, &disabled, &none, 0));
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

    fn split_strs(e: &AclEntry) -> (Vec<String>, Vec<String>) {
        let (published, local) = split_capabilities(e);
        let strs = |v: Vec<Value>| -> Vec<String> {
            v.into_iter()
                .map(|c| c.as_str().unwrap().to_string())
                .collect()
        };
        (strs(published), strs(local))
    }

    #[test]
    fn local_capabilities_are_split_out_not_dropped() {
        let mut e = entry_with_binding();
        e.role = Role::Admin;
        e.capabilities = vec![
            Capability::VaultRead,
            Capability::KeyExport,
            Capability::Sign,
        ];
        let (p, l) = split_strs(&e);
        assert!(p.contains(&"vault-read".to_string()), "{p:?}");
        assert!(p.contains(&"sign".to_string()), "{p:?}");
        // `keyExport` was ecosystem-local until the specification registered it
        // (trust-tasks 0.23), so it is published now, not carried under `ext`.
        assert!(p.contains(&"key-export".to_string()), "{p:?}");
        assert!(l.is_empty(), "every capability is registered: {l:?}");
    }

    /// The published `device/_shared` enum registers `signTrustTask`,
    /// `credentialWrite`, the memory, the room and (since 0.23) the `keyExport`
    /// capabilities. They go in `capabilities`, where a `capabilityFilter` can
    /// find them — not in `ext`.
    #[test]
    fn capabilities_the_specification_registers_are_published() {
        let mut e = entry_with_binding();
        e.role = Role::Admin;
        let (p, l) = split_strs(&e);
        for cap in [
            "sign-trust-task",
            "credential-write",
            "memory-read",
            "memory-write",
            "room-present",
            "room-open",
            "key-export",
            "external-accounts-manage",
            "external-auth-use",
            "pcs-vetter",
            "pcs-applicant",
            "witness-request",
            "pcs-voter",
            "pcs-trustee",
        ] {
            assert!(
                p.contains(&cap.to_string()),
                "{cap} must be published: {p:?}"
            );
        }
        assert!(l.is_empty(), "only unregistered ones go in ext: {l:?}");
    }

    /// An entry whose stored list is only an additive grant holds its whole role
    /// *plus* that grant (`effective_capabilities`, #1279). Listing the stored
    /// list verbatim reported it as holding holder authority alone.
    #[test]
    fn an_additive_grant_alone_does_not_hide_the_role() {
        let mut e = entry_with_binding(); // Role::Application
        e.capabilities = vec![Capability::PersonaHolder];
        let (p, l) = split_strs(&e);
        for cap in ["vault-read", "sign", "sign-trust-task", "memory-read"] {
            assert!(
                p.contains(&cap.to_string()),
                "role-derived {cap} missing: {p:?}"
            );
        }
        assert_eq!(l, vec!["personaHolder".to_string()], "{l:?}");
    }

    /// A stored list naming a capability the role does not carry lists only what
    /// the entry can actually exercise — the listing is bounded by the role.
    #[test]
    fn a_narrowing_is_bounded_by_the_role() {
        let mut e = entry_with_binding(); // Role::Application
        e.capabilities = vec![Capability::VaultRead, Capability::KeyMint];
        let (p, l) = split_strs(&e);
        assert_eq!(p, vec!["vault-read".to_string()], "{p:?}");
        assert!(l.is_empty(), "{l:?}");
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
        let audit: vta_audit::SharedAuditSink =
            vta_audit::shared_keyspace_sink(store.keyspace(crate::keyspaces::AUDIT).unwrap());
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
            None,
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
            None,
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
            None,
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
            None,
            "test",
        )
        .await
        .unwrap();

        let body = heartbeat_device(
            &acl_ks,
            &audit,
            &device_auth(did),
            Some("iOS 19.1".into()),
            None,
        )
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

    const UV_DID: &str = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";

    fn uv_ext(gated: bool) -> heartbeat_spec::Ext {
        serde_json::from_value(serde_json::json!({ EXT_UV_KEY: {
            "kind": "hardwareKey", "did": UV_DID,
            "hardwareBacked": true, "biometricGated": gated } }))
        .expect("ext")
    }

    /// Base design §11 item 1: the UV key is recorded with the device's claims
    /// about it, and the binding reports it (without the key) so a wallet can
    /// tell whether it can approve sign-ins.
    #[tokio::test]
    async fn a_uv_key_is_enrolled_on_heartbeat_and_reported_on_the_binding() {
        let (acl_ks, audit, _dir) = fresh().await;
        let did = "did:key:zUvDevice";
        registered(&acl_ks, &audit, did, "Phone").await;

        heartbeat_device(
            &acl_ks,
            &audit,
            &device_auth(did),
            None,
            Some(&uv_ext(true)),
        )
        .await
        .expect("enrol");
        let entry = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
        let uv = entry
            .device
            .as_ref()
            .unwrap()
            .uv_key
            .clone()
            .expect("enrolled");
        assert!(uv.enrolment.biometric_gated && uv.enrolment.hardware_backed);
        let wire = to_wire_binding(&entry);
        let summary = &wire["ext"]["org.openvtc"]["uvKey"];
        assert_eq!(summary["kind"], "hardwareKey");
        assert_eq!(summary["biometricGated"], true);
        assert!(
            !wire.to_string().contains(UV_DID),
            "the key itself is not listed"
        );
    }

    /// A UV key that is not biometric-gated is refused, and the refusal leaves
    /// the binding untouched rather than half-updated.
    #[tokio::test]
    async fn a_bad_uv_key_on_heartbeat_is_refused_and_changes_nothing() {
        let (acl_ks, audit, _dir) = fresh().await;
        let did = "did:key:zUvDevice2";
        registered(&acl_ks, &audit, did, "Phone").await;
        let err = heartbeat_device(
            &acl_ks,
            &audit,
            &device_auth(did),
            None,
            Some(&uv_ext(false)),
        )
        .await
        .expect_err("refused");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        let entry = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
        assert!(entry.device.unwrap().uv_key.is_none());
    }

    /// Base design §11 item 5: a disabled device approves nothing, so it may
    /// not enrol a UV key either.
    #[tokio::test]
    async fn a_disabled_device_cannot_enrol_a_uv_key() {
        let (acl_ks, audit, _dir) = fresh().await;
        let did = "did:key:zUvDevice3";
        registered(&acl_ks, &audit, did, "Phone").await;
        let mut entry = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
        entry.device.as_mut().unwrap().disabled_at = Some("2026-01-01T00:00:00Z".into());
        store_acl_entry(&acl_ks, &entry).await.unwrap();
        let err = heartbeat_device(
            &acl_ks,
            &audit,
            &device_auth(did),
            None,
            Some(&uv_ext(true)),
        )
        .await
        .expect_err("refused");
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
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
            None,
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
            &audit,
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
            &audit,
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
            heartbeat_device(&acl_ks, &audit, &device_auth(did), None, Some(&ext))
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
            &audit,
            &device_auth(did),
            None,
            Some(&name_ext("  Trimmed  ")),
        )
        .await
        .unwrap();
        let entry = get_acl_entry(&acl_ks, did).await.unwrap().unwrap();
        assert_eq!(entry.device.unwrap().display_name, "Trimmed");

        heartbeat_device(
            &acl_ks,
            &audit,
            &device_auth(did),
            None,
            Some(&name_ext("Trimmed")),
        )
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
        let (acl_ks, audit, _dir) = fresh().await;
        // ACL entry exists but no DeviceBinding attached.
        store_acl_entry(
            &acl_ks,
            &AclEntry::new("did:key:zBare", Role::Application, "did:key:zSetup"),
        )
        .await
        .unwrap();
        let err = heartbeat_device(&acl_ks, &audit, &device_auth("did:key:zBare"), None, None)
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
            None,
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

    /// Managing a device follows `acl/delete`: context scope *and* privilege.
    /// An initiator in the same context can neither see nor disable nor wipe an
    /// admin's device; the context's admin can.
    #[tokio::test]
    async fn an_initiator_cannot_manage_an_admins_device() {
        let (acl_ks, audit, _dir) = fresh().await;
        registered_in(&acl_ks, &audit, "did:key:zBoss", &["acme"], "boss-laptop").await;
        let mut entry = get_acl_entry(&acl_ks, "did:key:zBoss")
            .await
            .unwrap()
            .unwrap();
        entry.role = Role::Admin;
        store_acl_entry(&acl_ks, &entry).await.unwrap();
        let id = device_id_of(&acl_ks, "did:key:zBoss").await;

        let initiator = AuthClaims {
            role: Role::Initiator,
            ..context_admin("did:key:zInit", &["acme"])
        };
        assert!(listed_names(&acl_ks, &initiator).await.is_empty());
        let err = disable_device(&acl_ks, &audit, &initiator, &id)
            .await
            .expect_err("an initiator must not disable an admin's device");
        assert!(matches!(err, AppError::NotFound(_)), "{err:?}");
        let err = wipe_device(&acl_ks, &audit, &initiator, &id, "lost", "full")
            .await
            .expect_err("an initiator must not wipe an admin's device");
        assert!(matches!(err, AppError::NotFound(_)), "{err:?}");

        let admin = context_admin("did:key:zAcmeAdmin", &["acme"]);
        assert!(disable_device(&acl_ks, &audit, &admin, &id).await.is_ok());
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
            None,
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
            None,
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
