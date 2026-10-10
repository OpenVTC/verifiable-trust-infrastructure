//! Wallet sign-in (`auth/oob/*`): what the vault checks before it signs an
//! `identify` or a `grant` as one of the member's personas.
//!
//! The default VTA policy of the key-grant sign-in design (base design §11;
//! sign-in trigger-link contract C5 and C6). It is not a Rego rule because
//! most of it is cryptography the policy engine cannot do, and it is not
//! optional: it runs for every `vault/sign-trust-task` whose envelope is one of
//! these two documents, whatever the operator's policy set says, so every VTA
//! supports wallet sign-in out of the box and none signs a grant without the
//! member's user verification.
//!
//! # `auth/oob/identify/0.1` — no user verification
//!
//! "I am this DID, I hold this lock, and I can see the screen." It grants no
//! authority on its own, so the VTA signs it unattended (for `authentication`)
//! once the document is exactly the schema's shape: the exact Type URI, the
//! framework members only, and a payload of `requestId`, `approverKey` and
//! `enteredNumber` with nothing else (`additionalProperties: false`, no `ext`).
//!
//! # `auth/oob/grant/0.1` — only on the device's UV approval
//!
//! "Let this browser key act as me at this origin until `notAfter`." Signed
//! for `assertionMethod`, and only when the request carries, under
//! [`EXT_UV_CONSENT`], a `task-consent/decision/0.2` approving **this** grant:
//! its `payloadDigest` (and `challenge`) is [`grant_digest`] of the unsigned
//! grant, and the device's enrolled UV key made it —
//!
//! - **hardware key** (phone): the decision's proof is by the UV key's
//!   `did:key`, which the OS uses only after a biometric;
//! - **passkey** (browser plugin): the decision's proof is by the device's
//!   transport key, and its `evidence` is a WebAuthn assertion by the enrolled
//!   credential over the UTF-8 bytes of `challenge`, with the UV flag set,
//!   verified with `vti-webauthn`.
//!
//! The same grant `id` is never signed twice.
//!
//! # Both documents
//!
//! The caller is an enrolled, active device; `issuer` is the vault entry's
//! principal (the persona's DID) and `recipient` is a DID the vault entry
//! targets; the document is fresh. Every signature is audited with the device,
//! the persona, the `requestId` and, for a grant, the UV decision
//! ([`record_signature`]).
//!
//! # Many devices, one member
//!
//! A member signs in from any of their devices — several browser installs, a
//! phone, a desktop — and each is a device in its own right: its own DID (its
//! transport key), its own ACL entry, its own [`DeviceBinding`] on that entry
//! and so its own UV key, `consumerKind` and form factor. Nothing about one
//! device is stored on another's row.
//!
//! So "the member's device" needs no table of its own. The caller reached this
//! gate through the ordinary `vault/sign-trust-task` checks — the
//! `sign-trust-task` capability and context scope over the vault entry — which
//! is what makes the persona the caller's to sign as. This gate adds only that
//! the caller's **own** ACL entry carries an active binding, and checks a
//! grant's UV decision against that binding's UV key and the caller's own
//! transport key, never another device's. Disabling or wiping one device
//! changes one row, and every other device of the member signs in as before.
//!
//! A caller with no binding is [`OobError::NotEnrolledDevice`] (the device can
//! fix it itself with `device/register`); a disabled or wiped one is
//! [`OobError::DeviceDisabled`] (it cannot, and must not try).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::TypeUri;
use trust_tasks_rs::specs::task_consent::decision::v0_2 as decision_spec;
use vta_sdk::protocols::backup_management::chunked::{
    sha256_digest_multibase, sha256_from_digest_multibase,
};
use vta_sdk::protocols::device_management::{EXT_UV_CONSENT, UvKeyMaterial};
use vti_common::acl::{AclEntry, DeviceBinding, UvKey, get_acl_entry};
use vti_common::error::AppError;
use vti_common::vault::{SiteTarget, VaultEntry, VaultSecret};

use crate::store::KeyspaceHandle;

/// Registry slug of the document that proves who is signing in.
pub const IDENTIFY_SLUG: &str = "auth/oob/identify";
/// Registry slug of the document that lets a browser key act as the member.
pub const GRANT_SLUG: &str = "auth/oob/grant";
/// The `auth/oob` family. A persona signs only `identify` and `grant`; every
/// other document of the family is the wallet's throwaway key's or the
/// service's, and the vault refuses to sign one as a persona.
const FAMILY_PREFIX: &str = "auth/oob/";
/// The one decision version that can carry WebAuthn evidence.
const DECISION_SLUG: &str = "task-consent/decision";

/// How far `issuedAt` may be from now, either way. The service's decision
/// window is 120 s (base design §7.2); this only bounds how stale a document
/// the vault will sign is.
pub const MAX_SKEW_SECS: i64 = 300;

/// The framework members an `identify` or `grant` envelope may carry. No
/// `ext`, no `ceremony`, nothing a relying party would have to ignore.
const ENVELOPE_MEMBERS: &[&str] = &[
    "id",
    "type",
    "issuer",
    "recipient",
    "issuedAt",
    "expiresAt",
    "threadId",
    "parentThreadId",
    "payload",
];

/// Key prefix, in the task-consent keyspace, of the record that a grant `id`
/// has been signed. Distinct from that keyspace's `pending:`, `grant:` and
/// `wire:` rows.
const GRANT_REPLAY_PREFIX: &str = "oob-grant:";

// ─── Wire types ─────────────────────────────────────────────────────────────

/// `auth/oob/grant/0.1` payload, generated from the specification.
pub use trust_tasks_rs::specs::auth::oob::grant::v0_1::Payload as GrantPayload;
/// The member's answer, as the grant states it.
pub use trust_tasks_rs::specs::auth::oob::grant::v0_1::PayloadDecision as GrantDecision;
/// `auth/oob/identify/0.1` payload, generated from the specification. Its
/// newtypes enforce the schema's patterns (`requestId`, `approverKey`,
/// `enteredNumber`) when the payload is parsed.
pub use trust_tasks_rs::specs::auth::oob::identify::v0_1::Payload as IdentifyPayload;

/// `notAfter` as an instant: integer epoch seconds (contract C9).
fn not_after_instant(p: &GrantPayload) -> Option<chrono::DateTime<chrono::Utc>> {
    i64::try_from(p.not_after)
        .ok()
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
}

// ─── Outcome types ──────────────────────────────────────────────────────────

/// Which of the two documents is being signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OobDocument {
    Identify,
    Grant,
}

impl OobDocument {
    fn audit_action(self) -> &'static str {
        match self {
            OobDocument::Identify => "vault.sign-trust-task.oob-identify",
            OobDocument::Grant => "vault.sign-trust-task.oob-grant",
        }
    }
}

/// The UV approval a grant was signed on.
#[derive(Debug, Clone)]
pub struct UvApproval {
    /// `hardwareKey` or `webauthn`.
    pub kind: &'static str,
    /// The DID that made the decision's proof.
    pub signer: String,
    /// The decision document's `id`.
    pub decision_id: String,
    /// The grant digest it approved.
    pub digest: String,
}

/// Everything [`authorize`] established, for the audit row.
#[derive(Debug, Clone)]
pub struct OobAuthorization {
    pub document: OobDocument,
    pub envelope_id: String,
    pub request_id: String,
    pub persona: String,
    pub recipient: String,
    pub device_did: String,
    pub device_id: String,
    pub uv: Option<UvApproval>,
}

/// Why the vault refuses to sign an `identify` or a `grant`. Each maps onto a
/// `vault/sign-trust-task:<code>` reject; the text names the rule, never key
/// material. Non-exhaustive: the sign-in policy will gain refusals, and a
/// caller must already carry a `_ =>` arm for the ones it does not know.
#[derive(Debug)]
#[non_exhaustive]
pub enum OobError {
    /// An `auth/oob/*` document other than `identify/0.1` and `grant/0.1`.
    UnsupportedType,
    /// The envelope or payload is not exactly the schema's shape.
    DocumentInvalid(String),
    /// `issuer` is not the entry's principal.
    IssuerNotPrincipal,
    /// `recipient` is not a DID the entry targets.
    RecipientNotTarget,
    /// `issuedAt` is missing, malformed or outside [`MAX_SKEW_SECS`].
    Stale,
    /// The caller's ACL entry carries no device binding: it has not run
    /// `device/register`.
    NotEnrolledDevice,
    /// The caller is a registered device that has been disabled or wiped.
    /// Registering again cannot fix it (`device/register` refuses a second
    /// binding); an administrator re-provisions the device.
    DeviceDisabled,
    /// A grant arrived without a UV decision.
    UvRequired,
    /// The device has no UV key, so it cannot approve grants.
    NoUvKey,
    /// The UV decision did not verify, or did not approve this grant.
    UvInvalid(String),
    /// This grant `id` has been signed before.
    Replayed,
    /// The persona's DID document does not authorise the signing key for
    /// `assertionMethod`, so the service could not accept the grant.
    AssertionMethodMissing,
    /// Storage or configuration failure.
    App(AppError),
}

impl From<AppError> for OobError {
    fn from(e: AppError) -> Self {
        OobError::App(e)
    }
}

impl OobError {
    /// The `vault/sign-trust-task:<code>` local code and the message.
    pub fn code_and_message(&self) -> (&'static str, String) {
        match self {
            OobError::UnsupportedType => (
                "oobUnsupportedType",
                "a persona signs only auth/oob/identify/0.1 and auth/oob/grant/0.1".into(),
            ),
            OobError::DocumentInvalid(why) => ("oobDocumentInvalid", why.clone()),
            OobError::IssuerNotPrincipal => (
                "envelopeIssuerMismatch",
                "envelope.issuer must equal the entry's principalDid".into(),
            ),
            OobError::RecipientNotTarget => (
                "oobRecipientNotTarget",
                "envelope.recipient must be a DID the vault entry targets".into(),
            ),
            OobError::Stale => (
                "oobStale",
                format!("issuedAt must be within {MAX_SKEW_SECS} s of the VTA's clock"),
            ),
            OobError::NotEnrolledDevice => (
                "oobNotEnrolledDevice",
                "sign-in documents are signed only for an enrolled, active device; register \
                 this device with device/register first"
                    .into(),
            ),
            OobError::DeviceDisabled => (
                "oobDeviceDisabled",
                "this device has been disabled or wiped, so it cannot sign in; enrol it again \
                 under a new key"
                    .into(),
            ),
            OobError::UvRequired => (
                "oobUvRequired",
                format!(
                    "a grant is signed only with the device's UV approval under ext.{EXT_UV_CONSENT}"
                ),
            ),
            OobError::NoUvKey => (
                "oobNoUvKey",
                "this device has no UV key; enrol one with device/heartbeat ext \
                 org.openvtc.uv-key"
                    .into(),
            ),
            OobError::UvInvalid(why) => ("oobUvInvalid", why.clone()),
            OobError::Replayed => (
                "oobGrantReplayed",
                "this grant id has already been signed; build a new grant".into(),
            ),
            OobError::AssertionMethodMissing => (
                "oobAssertionMethodMissing",
                "the persona's DID document does not list its signing key under \
                 assertionMethod, so no service can accept a grant it signs; add the key to \
                 assertionMethod"
                    .into(),
            ),
            OobError::App(e) => ("internal", e.to_string()),
        }
    }
}

/// What [`authorize`] reads.
pub struct OobDeps<'a> {
    /// ACL rows, which carry each device's binding and UV key.
    pub acl_ks: &'a KeyspaceHandle,
    /// Where signed grant ids are recorded.
    pub task_consent_ks: &'a KeyspaceHandle,
    /// Locally hosted DID logs, to check a persona's `assertionMethod`.
    #[cfg(feature = "webvh")]
    pub webvh_ks: &'a KeyspaceHandle,
    /// This VTA's DID: a UV decision addressed elsewhere is refused.
    pub vta_did: Option<String>,
}

// ─── Classification ─────────────────────────────────────────────────────────

/// Which sign-in document `envelope` is, if any.
///
/// `Ok(None)` for every other document — including a `type` that is not a Type
/// URI and a private registry's reuse of the slug, both of which the ordinary
/// signing path handles. An `auth/oob/*` document of the registry that is not
/// exactly `identify/0.1` or `grant/0.1` (another version, a `#response`, a
/// `#request` spelling, `claim`, `respond`, …) is refused rather than signed
/// unattended.
pub fn classify(envelope: &Value) -> Result<Option<OobDocument>, OobError> {
    let Some(type_uri) = envelope
        .get("type")
        .and_then(Value::as_str)
        .and_then(|t| t.parse::<TypeUri>().ok())
    else {
        return Ok(None);
    };
    let canonical = |slug: &str| TypeUri::canonical(slug, 0, 1).ok();
    let on_registry = TypeUri::canonical(type_uri.slug(), type_uri.major(), type_uri.minor())
        .is_ok_and(|c| c == type_uri.bare());
    if !on_registry || !type_uri.slug().starts_with(FAMILY_PREFIX) {
        return Ok(None);
    }
    if canonical(IDENTIFY_SLUG).as_ref() == Some(&type_uri) {
        Ok(Some(OobDocument::Identify))
    } else if canonical(GRANT_SLUG).as_ref() == Some(&type_uri) {
        Ok(Some(OobDocument::Grant))
    } else {
        Err(OobError::UnsupportedType)
    }
}

/// The digest a UV decision must approve: SHA-256 over the RFC 8785 (JCS)
/// canonical **unsigned** grant — the whole envelope as sent in
/// `unsignedEnvelope`, without a `proof` — as a sha2-256 multihash in
/// base58btc (`DigestMultibase`, `z…`).
pub fn grant_digest(unsigned_grant: &Value) -> Result<String, AppError> {
    Ok(sha256_digest_multibase(&grant_digest_bytes(
        unsigned_grant,
    )?))
}

fn grant_digest_bytes(unsigned_grant: &Value) -> Result<[u8; 32], AppError> {
    let canonical = serde_json_canonicalizer::to_string(unsigned_grant)
        .map_err(|e| AppError::Internal(format!("grant JCS canonicalization failed: {e}")))?;
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

// ─── The gate ───────────────────────────────────────────────────────────────

/// Decide whether the vault may sign `envelope` as `entry`'s principal for the
/// device `device_did`. `Ok(None)` when `envelope` is not a sign-in document —
/// the ordinary path then applies unchanged.
///
/// On success for a grant, the grant `id` is already recorded as signed: a
/// grant that passes here is never signed a second time, even if this
/// signature then fails (the wallet builds a new grant).
#[allow(clippy::too_many_arguments)]
pub async fn authorize(
    deps: &OobDeps<'_>,
    device_did: &str,
    entry: &VaultEntry,
    secret: &VaultSecret,
    envelope: &Value,
    payload_ext: Option<&Value>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<OobAuthorization>, OobError> {
    let Some(document) = classify(envelope)? else {
        return Ok(None);
    };
    // Shapes the ordinary path refuses with its own codes: let it.
    let principal = match secret {
        VaultSecret::DidSelfIssued { did, .. } | VaultSecret::DidcommPeer { peer_did: did, .. } => {
            did.clone()
        }
        _ => return Ok(None),
    };
    let Some(obj) = envelope.as_object() else {
        return Ok(None);
    };
    if obj.contains_key("proof") {
        return Ok(None);
    }

    // The framework members, and nothing else.
    if let Some(extra) = obj.keys().find(|k| !ENVELOPE_MEMBERS.contains(&k.as_str())) {
        return Err(OobError::DocumentInvalid(format!(
            "envelope member '{extra}' is not allowed on a sign-in document"
        )));
    }
    let str_member = |k: &str| obj.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
    let envelope_id = str_member("id")
        .ok_or_else(|| OobError::DocumentInvalid("id must be a non-empty string".into()))?
        .to_string();

    // VTI-KEY-106: the persona signs as itself, for the service it names.
    if str_member("issuer") != Some(principal.as_str()) {
        return Err(OobError::IssuerNotPrincipal);
    }
    let recipient = str_member("recipient").ok_or(OobError::RecipientNotTarget)?;
    let targeted = entry
        .targets
        .iter()
        .any(|t| matches!(t, SiteTarget::Did { did } if did == recipient));
    if !targeted {
        return Err(OobError::RecipientNotTarget);
    }

    let issued_at = str_member("issuedAt")
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .ok_or(OobError::Stale)?;
    if (now - issued_at.with_timezone(&chrono::Utc))
        .num_seconds()
        .abs()
        > MAX_SKEW_SECS
    {
        return Err(OobError::Stale);
    }

    // An enrolled, active device: the caller's own row, so each of the
    // member's devices stands or falls on its own binding.
    let device_entry = get_acl_entry(deps.acl_ks, device_did)
        .await?
        .ok_or(OobError::NotEnrolledDevice)?;
    let binding = active_binding(&device_entry)?;

    let payload = obj.get("payload").cloned().unwrap_or(Value::Null);
    let (request_id, uv) = match document {
        OobDocument::Identify => {
            let p: IdentifyPayload = serde_json::from_value(payload)
                .map_err(|e| OobError::DocumentInvalid(format!("identify payload: {e}")))?;
            check_identify(&p)?;
            (p.request_id.to_string(), None)
        }
        OobDocument::Grant => {
            let p: GrantPayload = serde_json::from_value(payload)
                .map_err(|e| OobError::DocumentInvalid(format!("grant payload: {e}")))?;
            check_grant(&p, now)?;
            let uv =
                verify_uv_decision(deps, device_did, binding, envelope, payload_ext, now).await?;
            check_assertion_method(deps, &principal, secret).await?;
            // Last, so a refusal above never burns the id. One signature per
            // grant id, ever (base design §11 item 3).
            let marker = json!({
                "grantId": envelope_id,
                "requestId": p.request_id,
                "digest": uv.digest,
                "device": device_did,
                "signedAt": now.to_rfc3339(),
                "notAfter": p.not_after,
            });
            let key = format!(
                "{GRANT_REPLAY_PREFIX}{}",
                hex::encode(Sha256::digest(envelope_id.as_bytes()))
            );
            if !deps.task_consent_ks.insert_if_absent(key, &marker).await? {
                return Err(OobError::Replayed);
            }
            (p.request_id.to_string(), Some(uv))
        }
    };

    Ok(Some(OobAuthorization {
        document,
        envelope_id,
        request_id,
        persona: principal,
        recipient: recipient.to_string(),
        device_did: device_did.to_string(),
        device_id: binding.device_id.clone(),
        uv,
    }))
}

/// The entry's device binding, if it is enrolled and active.
fn active_binding(entry: &AclEntry) -> Result<&DeviceBinding, OobError> {
    let binding = entry.device.as_ref().ok_or(OobError::NotEnrolledDevice)?;
    if binding.disabled_at.is_some() || binding.wiped_at.is_some() {
        return Err(OobError::DeviceDisabled);
    }
    Ok(binding)
}

fn is_request_id(s: &str) -> bool {
    (16..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// An Ed25519 `did:key` — what the starter and approver keys must be (base
/// design §10, "Rules for the whole family").
fn is_ed25519_did_key(s: &str) -> bool {
    s.strip_prefix("did:key:")
        .and_then(|id| multibase::decode(id).ok())
        .is_some_and(|(base, bytes)| {
            base == multibase::Base::Base58Btc && bytes.len() == 34 && bytes[..2] == [0xed, 0x01]
        })
}

/// `https://host[:port]`, with no path, query, fragment or userinfo. The
/// generated `Origin` already requires `https://` and no `/?#` (auth/oob/grant
/// 0.1); this adds the userinfo and space refusals the pattern leaves open.
fn is_web_origin(s: &str) -> bool {
    s.strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty() && !rest.contains(['/', '?', '#', '@', ' ']))
}

fn check_identify(p: &IdentifyPayload) -> Result<(), OobError> {
    if !is_request_id(&p.request_id) {
        return Err(OobError::DocumentInvalid(
            "requestId must be 16-128 base64url characters".into(),
        ));
    }
    if !is_ed25519_did_key(&p.approver_key) {
        return Err(OobError::DocumentInvalid(
            "approverKey must be an Ed25519 did:key".into(),
        ));
    }
    if !(p.entered_number.len() == 2 && p.entered_number.bytes().all(|b| b.is_ascii_digit())) {
        return Err(OobError::DocumentInvalid(
            "enteredNumber must be a string of two digits".into(),
        ));
    }
    Ok(())
}

fn check_grant(p: &GrantPayload, now: chrono::DateTime<chrono::Utc>) -> Result<(), OobError> {
    let invalid = |why: &str| Err(OobError::DocumentInvalid(why.to_string()));
    if !is_request_id(&p.request_id) {
        return invalid("requestId must be 16-128 base64url characters");
    }
    if !is_ed25519_did_key(&p.session_key) {
        return invalid("sessionKey must be an Ed25519 did:key");
    }
    if !is_ed25519_did_key(&p.approver_key) {
        return invalid("approverKey must be an Ed25519 did:key");
    }
    if !is_web_origin(&p.origin) {
        return invalid("origin must be an https origin with no path or userinfo");
    }
    if sha256_from_digest_multibase(&p.context_digest).is_none() {
        return invalid("contextDigest must be a sha2-256 multihash in multibase");
    }
    match not_after_instant(p) {
        Some(t) if t > now => Ok(()),
        Some(_) => invalid("notAfter is in the past"),
        None => invalid("notAfter must be integer epoch seconds"),
    }
}

// ─── The UV decision ────────────────────────────────────────────────────────

/// Verify the `task-consent/decision/0.2` under [`EXT_UV_CONSENT`] against the
/// device's UV key and the grant it must approve.
async fn verify_uv_decision(
    deps: &OobDeps<'_>,
    device_did: &str,
    binding: &DeviceBinding,
    unsigned_grant: &Value,
    payload_ext: Option<&Value>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<UvApproval, OobError> {
    let uv_key: &UvKey = binding.uv_key.as_ref().ok_or(OobError::NoUvKey)?;
    let decision = payload_ext
        .and_then(|e| e.get(EXT_UV_CONSENT))
        .and_then(|c| c.get("decision"))
        .ok_or(OobError::UvRequired)?;
    let bad = |why: &str| OobError::UvInvalid(why.to_string());
    let obj = decision
        .as_object()
        .ok_or_else(|| bad("the UV decision is not a document"))?;

    let expected_type = TypeUri::canonical(DECISION_SLUG, 0, 2)
        .map_err(|e| OobError::App(AppError::Internal(format!("decision type: {e}"))))?;
    let is_decision = obj
        .get("type")
        .and_then(Value::as_str)
        .and_then(|t| t.parse::<TypeUri>().ok())
        .is_some_and(|t| t == expected_type);
    if !is_decision {
        return Err(bad(
            "the UV decision must be a task-consent/decision/0.2 document",
        ));
    }
    let decision_id = obj
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("the UV decision has no id"))?
        .to_string();
    if let Some(vta) = &deps.vta_did
        && obj.get("recipient").and_then(Value::as_str) != Some(vta.as_str())
    {
        return Err(bad("the UV decision must be addressed to this VTA"));
    }
    let issued_at = obj
        .get("issuedAt")
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .ok_or_else(|| bad("the UV decision needs an RFC 3339 issuedAt"))?;
    if (now - issued_at.with_timezone(&chrono::Utc))
        .num_seconds()
        .abs()
        > MAX_SKEW_SECS
    {
        return Err(bad("the UV decision is stale"));
    }
    if let Some(exp) = obj.get("expiresAt") {
        let ok = exp
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .is_some_and(|t| t > now);
        if !ok {
            return Err(bad("the UV decision has expired"));
        }
    }

    let payload: decision_spec::Payload = serde_json::from_value(
        obj.get("payload").cloned().unwrap_or(Value::Null),
    )
    .map_err(|_| bad("the UV decision's payload is not a task-consent/decision/0.2 payload"))?;
    if payload.decision != decision_spec::Decision::Approve {
        return Err(bad("the UV decision does not approve the grant"));
    }

    // The decision approves exactly this grant: its digest, compared as
    // decoded multihash bytes (the encoding is the producer's choice), and
    // its challenge is that same digest string — the value the passkey signed.
    let expected = grant_digest_bytes(unsigned_grant)?;
    let digest_str = payload.payload_digest.as_str();
    if sha256_from_digest_multibase(digest_str) != Some(expected) {
        return Err(bad(
            "payloadDigest is not the digest of this unsigned grant",
        ));
    }
    let challenge = payload.challenge.as_str();
    if challenge != digest_str {
        return Err(bad("challenge must equal payloadDigest"));
    }

    // The proof: an approver's attestation, verified over the document as
    // received, against `did:key` only (both the UV key and a transport key
    // are `did:key`s; nothing here touches the network).
    let signer = vti_common::auth::verify_approval_proof_value(
        decision,
        &vti_common::auth::TrustTaskVmResolver::did_key_only(),
    )
    .await
    .map_err(|e| {
        tracing::info!(cause = ?e.cause(), "oob grant: UV decision proof refused");
        bad("the UV decision's proof does not verify")
    })?;
    if obj.get("issuer").and_then(Value::as_str) != Some(signer.as_str()) {
        return Err(bad("the UV decision's issuer did not sign it"));
    }

    let kind = match &uv_key.enrolment.key {
        UvKeyMaterial::HardwareKey { did } => {
            // The OS signs with this key only after a biometric.
            if &signer != did {
                return Err(bad("the UV decision is not signed by the device's UV key"));
            }
            if payload.evidence.is_some() {
                return Err(bad("a hardware-key UV decision carries no evidence"));
            }
            "hardwareKey"
        }
        UvKeyMaterial::Webauthn {
            credential_id,
            public_key_multibase,
            rp_id,
            origin,
        } => {
            // The document is the device's; the passkey assertion inside it
            // is the user verification.
            if signer != device_did {
                return Err(bad(
                    "a passkey UV decision must be signed by the device's transport key",
                ));
            }
            let Some(decision_spec::Evidence::Webauthn { assertion }) = &payload.evidence else {
                return Err(bad("a passkey UV decision must carry webauthn evidence"));
            };
            verify_passkey(
                assertion,
                challenge,
                credential_id,
                public_key_multibase,
                rp_id,
                origin,
                device_did,
            )
            .await
            .map_err(|why| bad(&why))?;
            "webauthn"
        }
        _ => return Err(OobError::NoUvKey),
    };

    Ok(UvApproval {
        kind,
        signer,
        decision_id,
        digest: sha256_digest_multibase(&expected),
    })
}

/// The enrolled passkey, as a [`vti_webauthn::VmResolver`] that knows exactly
/// one method.
struct EnrolledPasskey {
    vm: String,
    controller: String,
    public_key: Vec<u8>,
}

#[async_trait::async_trait]
impl vti_webauthn::VmResolver for EnrolledPasskey {
    async fn resolve_vm(
        &self,
        vm_url: &str,
    ) -> Result<vti_webauthn::ResolvedVm, vti_webauthn::ResolverError> {
        if vm_url != self.vm {
            return Err(vti_webauthn::ResolverError::NotFound);
        }
        Ok(vti_webauthn::ResolvedVm {
            algorithm: vti_webauthn::VerificationAlgorithm::P256,
            public_key_bytes: self.public_key.clone(),
            controller: self.controller.clone(),
        })
    }
}

/// WebAuthn L2 §7.2 against the enrolled credential: challenge = the UTF-8
/// bytes of `challenge`, the enrolled RP id and origin, UV required.
async fn verify_passkey(
    assertion: &decision_spec::AssertionResponse,
    challenge: &str,
    credential_id: &str,
    public_key_multibase: &str,
    rp_id: &str,
    origin: &str,
    device_did: &str,
) -> Result<(), String> {
    let dec = |s: &str| {
        URL_SAFE_NO_PAD
            .decode(s.trim_end_matches('='))
            .map_err(|_| "the WebAuthn assertion is not base64url".to_string())
    };
    let enrolled = dec(credential_id)?;
    if dec(&assertion.raw_id)? != enrolled || dec(&assertion.id)? != enrolled {
        return Err("the WebAuthn assertion is not from the enrolled passkey".into());
    }
    let (_, public_key) = vti_webauthn::multikey::decode_multikey(public_key_multibase)
        .map_err(|_| "the enrolled passkey key is unreadable".to_string())?;
    let vm = format!("{device_did}#uv-passkey");
    let resolver = EnrolledPasskey {
        vm: vm.clone(),
        controller: device_did.to_string(),
        public_key,
    };
    let config = vti_webauthn::VerifierConfig {
        rp_id: rp_id.to_string(),
        expected_origin: origin.to_string(),
        require_user_verification: true,
    };
    let payload = vti_webauthn::AssertionPayload {
        credential_id: enrolled,
        authenticator_data: dec(&assertion.response.authenticator_data)?,
        client_data_json: dec(&assertion.response.client_data_json)?,
        signature: dec(&assertion.response.signature)?,
        verification_method: vm,
    };
    let verified =
        vti_webauthn::verify_assertion(&payload, challenge.as_bytes(), &resolver, &config)
            .await
            .map_err(|e| {
                tracing::info!(error = %e, "oob grant: passkey assertion refused");
                "the WebAuthn assertion does not verify with user verification".to_string()
            })?;
    if !verified.user_verified {
        return Err("the WebAuthn assertion was made without user verification".into());
    }
    Ok(())
}

// ─── The persona's assertionMethod ──────────────────────────────────────────

/// A grant is signed for `assertionMethod`, so the persona's DID document must
/// authorise the signing key for it or every service refuses the grant
/// (VTI-KEY-022). Checked against the locally hosted `did:webvh` log; a
/// `did:key` authorises its key for every purpose; any other DID is not ours
/// to read, and the service checks it.
async fn check_assertion_method(
    #[cfg_attr(not(feature = "webvh"), allow(unused_variables))] deps: &OobDeps<'_>,
    principal: &str,
    secret: &VaultSecret,
) -> Result<(), OobError> {
    let signing_key_id = match secret {
        VaultSecret::DidSelfIssued { signing_key_id, .. }
        | VaultSecret::DidcommPeer { signing_key_id, .. } => signing_key_id,
        _ => return Ok(()),
    };
    if principal.starts_with("did:key:") {
        return Ok(());
    }
    // Without `webvh` this VTA hosts no DID logs, so there is nothing local
    // to read; the service checks the document it resolves.
    #[cfg(feature = "webvh")]
    {
        let Some(log) = crate::webvh_store::get_did_log(deps.webvh_ks, principal).await? else {
            return Ok(());
        };
        let doc = crate::operations::protocol::document::current_document_from_log(&log)
            .map_err(|e| AppError::Internal(format!("persona DID document: {e}")))?;
        check_document_assertion_method(doc, principal, signing_key_id)?;
    }
    #[cfg(not(feature = "webvh"))]
    let _ = signing_key_id;
    Ok(())
}

/// The persona's current document authorises `signing_key_id` (an absolute
/// DID URL or a fragment) for `assertionMethod`.
pub fn check_document_assertion_method(
    doc: Value,
    principal: &str,
    signing_key_id: &str,
) -> Result<(), OobError> {
    let vm = if signing_key_id.starts_with("did:") {
        signing_key_id.to_string()
    } else {
        format!("{principal}#{}", signing_key_id.trim_start_matches('#'))
    };
    let doc: affinidi_tdk::did_common::Document = serde_json::from_value(doc)
        .map_err(|e| AppError::Internal(format!("persona DID document: {e}")))?;
    vta_sdk::trust_task_proof::purpose::authorised_method(
        &doc,
        principal,
        &vm,
        vta_sdk::trust_task_proof::ProofPurpose::AssertionMethod,
    )
    .map(|_| ())
    .map_err(|_| OobError::AssertionMethodMissing)
}

// ─── Audit ──────────────────────────────────────────────────────────────────

/// Record the signature: the device, the persona, the `requestId` and, for a
/// grant, the UV decision (base design §11 item 7). A write that fails is
/// returned, and the caller withholds the signature: a sign-in the audit trail
/// cannot show did not happen.
pub async fn record_signature(
    audit: &vta_audit::SharedAuditSink,
    entry_id: &str,
    context_id: &str,
    channel: &str,
    auth: &OobAuthorization,
) -> Result<(), AppError> {
    let detail = json!({
        "envelopeId": auth.envelope_id,
        "requestId": auth.request_id,
        "persona": auth.persona,
        "recipient": auth.recipient,
        "device": auth.device_did,
        "deviceId": auth.device_id,
        "entryId": entry_id,
        "uvDecision": auth.uv.as_ref().map(|uv| json!({
            "kind": uv.kind,
            "signer": uv.signer,
            "decisionId": uv.decision_id,
            "digest": uv.digest,
        })),
    })
    .to_string();
    crate::audit::record_with_detail(
        audit,
        auth.document.audit_action(),
        &auth.device_did,
        Some(entry_id),
        "success",
        Some(channel),
        Some(context_id),
        Some(&detail),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_type(t: &str) -> Value {
        json!({ "type": t })
    }

    #[test]
    fn only_the_exact_identify_and_grant_uris_are_sign_in_documents() {
        let spec = |s: &str| format!("{}{s}", "https://trusttasks.org/spec/");
        assert_eq!(
            classify(&with_type(&spec("auth/oob/identify/0.1"))).unwrap(),
            Some(OobDocument::Identify)
        );
        assert_eq!(
            classify(&with_type(&spec("auth/oob/grant/0.1"))).unwrap(),
            Some(OobDocument::Grant)
        );
        // Another version, a variant, or another document of the family is
        // refused, never signed unattended.
        for t in [
            "auth/oob/grant/0.2",
            "auth/oob/grant/0.1#response",
            "auth/oob/identify/1.0",
            "auth/oob/claim/0.1",
            "auth/oob/respond/0.1",
        ] {
            assert!(
                matches!(
                    classify(&with_type(&spec(t))),
                    Err(OobError::UnsupportedType)
                ),
                "{t}"
            );
        }
        // Not sign-in documents: the ordinary path applies.
        for t in [
            spec("acl/grant/0.1"),
            "https://registry.example/spec/auth/oob/grant/0.1".to_string(),
            "not a uri".to_string(),
        ] {
            assert_eq!(classify(&with_type(&t)).unwrap(), None, "{t}");
        }
    }

    #[test]
    fn the_grant_digest_is_sha256_over_jcs() {
        let a = json!({ "b": 1, "a": "x" });
        let b = json!({ "a": "x", "b": 1 });
        let d = grant_digest(&a).unwrap();
        assert_eq!(d, grant_digest(&b).unwrap(), "member order is irrelevant");
        assert!(d.starts_with('z'));
        let expected: [u8; 32] = Sha256::digest(br#"{"a":"x","b":1}"#).into();
        assert_eq!(sha256_from_digest_multibase(&d), Some(expected));
    }

    #[test]
    fn identify_payloads_are_exact() {
        let ok = json!({ "requestId": "AAAAAAAAAAAAAAAAAAAAAA",
            "approverKey": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "enteredNumber": "07" });
        let p: IdentifyPayload = serde_json::from_value(ok.clone()).unwrap();
        check_identify(&p).unwrap();

        let mut extra = ok.clone();
        extra["ext"] = json!({ "org.example": {} });
        assert!(serde_json::from_value::<IdentifyPayload>(extra).is_err());

        for (field, bad) in [
            ("enteredNumber", json!(7)),
            ("enteredNumber", json!("7")),
            ("enteredNumber", json!("123")),
            (
                "approverKey",
                json!("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"),
            ),
            ("requestId", json!("short")),
        ] {
            let mut v = ok.clone();
            v[field] = bad.clone();
            let refused = serde_json::from_value::<IdentifyPayload>(v)
                .map_err(|_| ())
                .and_then(|p| check_identify(&p).map_err(|_| ()))
                .is_err();
            assert!(refused, "{field} = {bad}");
        }
    }

    /// Base design §11 item 6: a grant is refused, with the fix named, when
    /// the persona's document does not list its signing key under
    /// `assertionMethod` — the service would refuse the grant anyway
    /// (VTI-KEY-022).
    #[test]
    fn a_persona_must_list_its_signing_key_under_assertion_method() {
        const DID: &str = "did:webvh:scid:example.com:alice";
        let doc = |am: Value| {
            json!({
                "id": DID,
                "verificationMethod": [{
                    "id": format!("{DID}#key-0"), "type": "Multikey", "controller": DID,
                    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                }],
                "authentication": [format!("{DID}#key-0")],
                "assertionMethod": am,
            })
        };
        check_document_assertion_method(doc(json!([format!("{DID}#key-0")])), DID, "key-0")
            .expect("listed");
        check_document_assertion_method(doc(json!(["#key-0"])), DID, &format!("{DID}#key-0"))
            .expect("listed by fragment");
        assert!(matches!(
            check_document_assertion_method(doc(json!([])), DID, "key-0"),
            Err(OobError::AssertionMethodMissing)
        ));
    }

    #[test]
    fn web_origins_are_bare() {
        assert!(is_web_origin("https://portal.example"));
        assert!(is_web_origin("https://portal.example:8443"));
        assert!(!is_web_origin("http://localhost:5173"));
        assert!(!is_web_origin("https://user@portal.example"));
        assert!(!is_web_origin("http://portal.example"));
        assert!(!is_web_origin("https://portal.example/members"));
        assert!(!is_web_origin("chrome-extension://abc"));
    }
}
