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
//! - **PRF-sealed key** (browser plugin): the decision's proof is by the UV
//!   key's `did:key`, which the wallet unseals only with the PRF output of
//!   its passkey, made with user verification for this approval;
//! - **passkey** (a WebAuthn client): the decision's proof is by the device's
//!   transport key, and its `evidence` is a WebAuthn assertion by the enrolled
//!   credential over the UTF-8 bytes of `challenge`, with the UV flag set,
//!   verified with `vti-webauthn`;
//! - **VTA-checked PIN** (browser plugin without a PRF passkey): the
//!   decision's proof is by the device's transport key, with no evidence, and
//!   the consent carries `pinProof`, an HMAC by the PIN-derived key over
//!   `org.openvtc.uv-pin/v1|<digest>`, counted against a persisted, escalating
//!   guess limit ([`crate::operations::uv_pin`]);
//! - **remote approver** (approve on the member's phone): the consent is
//!   `{ "remote": true }` and carries no decision. The VTA raises a
//!   `task-consent` request bound to the enrolled approver and this grant's
//!   digest, pushes it to the phone, and answers `oobUvPending` (with the match
//!   code the phone shows) until the phone's `task-consent/decision/0.1`
//!   approves it; the resulting single-use grant is then consumed here.
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
use vta_sdk::protocols::device_management::{EXT_UV_CONSENT, UvKeyMaterial, uv_pin_grant_message};
use vti_common::acl::{AclEntry, DeviceBinding, UvKey, get_acl_entry};
use vti_common::error::AppError;
use vti_common::task_consent as consent;
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

/// `auth/oob/grant/0.2` payload: 0.1's, plus the task families the browser
/// key may sign for as the member (`signingScope`).
pub use trust_tasks_rs::specs::auth::oob::grant::v0_2::Payload as GrantPayloadV0_2;

/// Families a grant may never delegate signing for (auth/oob/grant/0.2, wallet
/// item 5): signing in, access control and consent. A grant naming one, or a
/// family under one, is refused whatever the service offered.
const UNDELEGABLE_FAMILIES: &[&str] = &["auth", "acl", "consent", "task-consent", "confirm"];

/// What the vault checks of a grant, from its 0.1 or 0.2 payload.
struct GrantFields {
    request_id: String,
    session_key: String,
    approver_key: String,
    origin: String,
    context_digest: String,
    not_after: u64,
    signing_scope: Vec<String>,
}

impl GrantFields {
    fn read(payload: Value, v0_2: bool) -> Result<Self, OobError> {
        let bad = |e: serde_json::Error| OobError::DocumentInvalid(format!("grant payload: {e}"));
        Ok(if v0_2 {
            let p: GrantPayloadV0_2 = serde_json::from_value(payload).map_err(bad)?;
            Self {
                request_id: p.request_id.to_string(),
                session_key: p.session_key.to_string(),
                approver_key: p.approver_key.to_string(),
                origin: p.origin.to_string(),
                context_digest: p.context_digest.to_string(),
                not_after: p.not_after,
                signing_scope: p
                    .signing_scope
                    .map(|s| s.iter().map(|f| f.to_string()).collect())
                    .unwrap_or_default(),
            }
        } else {
            let p: GrantPayload = serde_json::from_value(payload).map_err(bad)?;
            Self {
                request_id: p.request_id.to_string(),
                session_key: p.session_key.to_string(),
                approver_key: p.approver_key.to_string(),
                origin: p.origin.to_string(),
                context_digest: p.context_digest.to_string(),
                not_after: p.not_after,
                signing_scope: Vec::new(),
            }
        })
    }
}

/// `notAfter` as an instant: integer epoch seconds (contract C9).
fn not_after_instant(not_after: u64) -> Option<chrono::DateTime<chrono::Utc>> {
    i64::try_from(not_after)
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
    /// `hardwareKey`, `prfSealedKey`, `webauthn`, `vtaPin` or
    /// `remoteApprover`.
    pub kind: &'static str,
    /// The DID that made the decision's proof — for `remoteApprover`, the
    /// approving phone.
    pub signer: String,
    /// The decision document's `id`; for `remoteApprover`, the task-consent
    /// grant it consumed (`task-consent:<digest>`).
    pub decision_id: String,
    /// The grant digest it approved.
    pub digest: String,
    /// For `remoteApprover`: the task-consent grant `(type, digest)` to spend
    /// once every other check has passed.
    remote_grant: Option<(String, String)>,
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
    /// An `auth/oob/*` document other than `identify/0.1` and `grant/0.1` or
    /// `0.2`.
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
    /// The PIN proof is wrong. `locked_until` is set when this proof locked
    /// the PIN.
    UvPinWrong {
        attempts_remaining: u32,
        locked_until: Option<i64>,
    },
    /// Too many wrong PINs: refused unchecked until `locked_until` (unix s).
    UvLocked { locked_until: i64 },
    /// The phone has been asked and has not answered yet.
    UvPending { match_code: String, expires_at: u64 },
    /// The phone declined this grant.
    UvDeclined,
    /// The phone was asked and did not answer in time.
    UvExpired,
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
                "a persona signs only auth/oob/identify/0.1 and auth/oob/grant/0.1 or 0.2".into(),
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
            OobError::UvPinWrong {
                attempts_remaining, ..
            } => (
                "oobUvPinWrong",
                format!("the PIN is wrong; {attempts_remaining} attempt(s) left before a lock"),
            ),
            OobError::UvLocked { .. } => (
                "oobUvLocked",
                "too many wrong PINs; the PIN is locked for now".into(),
            ),
            OobError::UvPending { .. } => (
                "oobUvPending",
                "approve this sign-in on your phone; send the same request again to collect \
                 the approval"
                    .into(),
            ),
            OobError::UvDeclined => (
                "oobUvDeclined",
                "the sign-in was declined on the phone".into(),
            ),
            OobError::UvExpired => (
                "oobUvExpired",
                "the phone did not approve this sign-in in time; start a new sign-in".into(),
            ),
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

    /// The refusal's `details`: `{ code }`, plus `attemptsRemaining`,
    /// `lockedUntil` (unix seconds), or `matchCode` and `expiresAt` (unix
    /// seconds) where the refusal carries them.
    pub fn details(&self) -> Value {
        let (code, _) = self.code_and_message();
        let mut out = json!({ "code": code });
        match self {
            OobError::UvPinWrong {
                attempts_remaining,
                locked_until,
            } => {
                out["attemptsRemaining"] = json!(attempts_remaining);
                if let Some(t) = locked_until {
                    out["lockedUntil"] = json!(t);
                }
            }
            OobError::UvLocked { locked_until } => out["lockedUntil"] = json!(locked_until),
            OobError::UvPending {
                match_code,
                expires_at,
            } => {
                out["matchCode"] = json!(match_code);
                out["expiresAt"] = json!(expires_at);
            }
            _ => {}
        }
        out
    }
}

/// What a `remoteApprover` approval needs from the service around the gate:
/// who may approve, and a way to ask them.
#[async_trait::async_trait]
pub trait RemoteApproval: Send + Sync {
    /// Whether `device_did` may (still) name `approver` as its remote
    /// approver.
    async fn approver_permitted(&self, device_did: &str, approver: &str) -> Result<bool, AppError>;
    /// Sign the `task-consent/request` for `pending` and push it to its bound
    /// approver. Called once per raised request, never per poll.
    async fn ask(
        &self,
        pending: &consent::PendingTaskConsent,
        ask: &RemoteAsk,
    ) -> Result<(), AppError>;
}

/// What the phone is told about the sign-in it is asked to approve.
#[derive(Debug, Clone)]
pub struct RemoteAsk {
    /// The grant's `origin`: the community's site.
    pub origin: String,
    /// The browser device's display name.
    pub device_name: String,
    /// The persona signing in.
    pub persona: String,
    /// The grant's `notAfter` (unix seconds).
    pub not_after: u64,
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
    /// Where refused PIN proofs are audited.
    pub audit: &'a vta_audit::SharedAuditSink,
    /// The service's side of a `remoteApprover` approval. `None` refuses every
    /// remote approval.
    pub remote: Option<&'a (dyn RemoteApproval + 'a)>,
}

// ─── Classification ─────────────────────────────────────────────────────────

/// Which sign-in document `envelope` is, if any.
///
/// `Ok(None)` for every other document — including a `type` that is not a Type
/// URI and a private registry's reuse of the slug, both of which the ordinary
/// signing path handles. An `auth/oob/*` document of the registry that is not
/// exactly `identify/0.1` or `grant/0.1` or `0.2` (another version, a `#response`, a
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
    let canonical_v0_2 = |slug: &str| TypeUri::canonical(slug, 0, 2).ok();
    let on_registry = TypeUri::canonical(type_uri.slug(), type_uri.major(), type_uri.minor())
        .is_ok_and(|c| c == type_uri.bare());
    if !on_registry || !type_uri.slug().starts_with(FAMILY_PREFIX) {
        return Ok(None);
    }
    if canonical(IDENTIFY_SLUG).as_ref() == Some(&type_uri) {
        Ok(Some(OobDocument::Identify))
    } else if canonical(GRANT_SLUG).as_ref() == Some(&type_uri)
        || canonical_v0_2(GRANT_SLUG).as_ref() == Some(&type_uri)
    {
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
            let v0_2 = obj
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|t| t.ends_with("/auth/oob/grant/0.2"));
            let p = GrantFields::read(payload, v0_2)?;
            check_grant(&p, now)?;
            let grant_ctx = GrantContext {
                envelope_id: &envelope_id,
                persona: &principal,
                origin: &p.origin,
                not_after: p.not_after,
            };
            let uv = verify_uv_decision(
                deps,
                device_did,
                binding,
                envelope,
                payload_ext,
                &grant_ctx,
                now,
            )
            .await?;
            check_assertion_method(deps, &principal, secret).await?;
            // Spend the phone's approval only now that nothing else refuses:
            // single use, and never burnt by a refusal above.
            if let Some((type_uri, digest)) = &uv.remote_grant {
                let now_s = u64::try_from(now.timestamp()).unwrap_or(0);
                if consent::consume_grant(deps.task_consent_ks, device_did, type_uri, digest, now_s)
                    .await?
                    .is_none()
                {
                    return Err(OobError::UvInvalid(
                        "this phone approval has already been used".into(),
                    ));
                }
            }
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
            let key = grant_replay_key(&envelope_id);
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

/// The replay marker's key for grant `id`.
fn grant_replay_key(envelope_id: &str) -> String {
    format!(
        "{GRANT_REPLAY_PREFIX}{}",
        hex::encode(Sha256::digest(envelope_id.as_bytes()))
    )
}

/// What the UV check needs to know about the grant beyond its digest.
struct GrantContext<'a> {
    envelope_id: &'a str,
    persona: &'a str,
    origin: &'a str,
    not_after: u64,
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

fn check_grant(p: &GrantFields, now: chrono::DateTime<chrono::Utc>) -> Result<(), OobError> {
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
    // Wallet item 5: never delegate signing in, access control or consent.
    if let Some(family) = p.signing_scope.iter().find(|f| {
        UNDELEGABLE_FAMILIES
            .iter()
            .any(|x| *f == x || f.starts_with(&format!("{x}/")))
    }) {
        return Err(OobError::DocumentInvalid(format!(
            "signingScope may not delegate '{family}': signing in, access control and consent \
             are signed only by the member's own key"
        )));
    }
    match not_after_instant(p.not_after) {
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
    grant: &GrantContext<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<UvApproval, OobError> {
    let uv_key: &UvKey = binding.uv_key.as_ref().ok_or(OobError::NoUvKey)?;
    let consent_ext = payload_ext.and_then(|e| e.get(EXT_UV_CONSENT));
    if let UvKeyMaterial::RemoteApprover { approver } = &uv_key.enrolment.key {
        return remote_approval(
            deps,
            device_did,
            binding,
            approver,
            unsigned_grant,
            consent_ext,
            grant,
            now,
        )
        .await;
    }
    let decision = consent_ext
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
        UvKeyMaterial::PrfSealedKey { did } => {
            // The wallet unseals this key only with a PRF output its
            // authenticator yields after user verification, for this one
            // signature. Verified exactly as a hardware key; recorded apart.
            if &signer != did {
                return Err(bad("the UV decision is not signed by the device's UV key"));
            }
            if payload.evidence.is_some() {
                return Err(bad("a PRF-sealed UV decision carries no evidence"));
            }
            "prfSealedKey"
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
        UvKeyMaterial::VtaPin { .. } => {
            // The document is the device's; the PIN proof beside it is the
            // user verification, checked against the guess limit.
            if signer != device_did {
                return Err(bad(
                    "a PIN UV decision must be signed by the device's transport key",
                ));
            }
            if payload.evidence.is_some() {
                return Err(bad("a PIN UV decision carries no evidence"));
            }
            let proof = consent_ext
                .and_then(|c| c.get("pinProof"))
                .and_then(Value::as_str)
                .ok_or_else(|| bad("a PIN approval needs pinProof"))?;
            check_pin(
                deps,
                device_did,
                uv_key,
                &uv_pin_grant_message(digest_str),
                proof,
                now,
            )
            .await?;
            "vtaPin"
        }
        _ => return Err(OobError::NoUvKey),
    };

    Ok(UvApproval {
        kind,
        signer,
        decision_id,
        digest: sha256_digest_multibase(&expected),
        remote_grant: None,
    })
}

/// Check a `vtaPin` proof over `message`, auditing a refusal.
async fn check_pin(
    deps: &OobDeps<'_>,
    device_did: &str,
    uv_key: &UvKey,
    message: &str,
    proof: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), OobError> {
    use crate::operations::uv_pin::{self, PinRefusal};
    match uv_pin::check(
        deps.acl_ks,
        device_did,
        uv_key,
        message,
        proof,
        now.timestamp(),
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(refusal) => {
            uv_pin::audit_refusal(deps.audit, device_did, "oob-grant", &refusal).await;
            Err(match refusal {
                PinRefusal::Locked { locked_until } => OobError::UvLocked { locked_until },
                PinRefusal::Wrong {
                    attempts_remaining,
                    locked_until,
                    ..
                } => OobError::UvPinWrong {
                    attempts_remaining,
                    locked_until,
                },
                PinRefusal::Malformed => {
                    OobError::UvInvalid("pinProof must be a 32-byte HMAC in base64url".into())
                }
                PinRefusal::NotAPin => OobError::App(AppError::Internal(
                    "the stored PIN verifier is unreadable".into(),
                )),
                PinRefusal::App(e) => OobError::App(e),
            })
        }
    }
}

// ─── Remote approval ────────────────────────────────────────────────────────

/// The approver-set label a remote approval's request carries. Not a policy
/// set: the request is bound to one approver
/// ([`consent::PendingTaskConsent::bound_approver`]), and the decision handler
/// accepts that approver's decision and no other.
pub const REMOTE_APPROVER_SET: &str = "org.openvtc.uv-approver";

/// How long the phone has to answer: the service's own decision window for a
/// grant (base design §7.2), and never past the grant's `notAfter`.
pub const REMOTE_WINDOW_SECS: u64 = 120;

/// How long a raised request's mark outlives it, so a late poll still reads
/// "declined" or "expired" rather than raising the question again.
const REMOTE_MARK_KEEP_SECS: u64 = 600;

/// A `remoteApprover` device's approval of this grant: spend the phone's
/// approval if it has given one, else report where the request stands —
/// declined, expired, or pending (raising it, once, if it has not been).
#[allow(clippy::too_many_arguments)]
async fn remote_approval(
    deps: &OobDeps<'_>,
    device_did: &str,
    binding: &DeviceBinding,
    approver: &str,
    unsigned_grant: &Value,
    consent_ext: Option<&Value>,
    grant: &GrantContext<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<UvApproval, OobError> {
    if consent_ext
        .and_then(|c| c.get("remote"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(
            if consent_ext.is_some_and(|c| c.get("decision").is_some()) {
                OobError::UvInvalid(
                    "this device approves sign-ins on a phone; send { \"remote\": true }".into(),
                )
            } else {
                OobError::UvRequired
            },
        );
    }
    let port = deps.remote.ok_or_else(|| {
        OobError::App(AppError::Internal(
            "remote approval is not available on this VTA".into(),
        ))
    })?;
    if !port.approver_permitted(device_did, approver).await? {
        return Err(OobError::UvInvalid(
            "the enrolled remote approver is no longer one this device may name; enrol \
             another approval method"
                .into(),
        ));
    }

    let ks = deps.task_consent_ks;
    let now_s = u64::try_from(now.timestamp()).unwrap_or(0);
    let digest = grant_digest(unsigned_grant)?;
    let type_uri = unsigned_grant
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    // What the request is keyed by: this grant, this device, this approver. A
    // changed enrolment never reuses another approver's request.
    let task_payload = json!({ "grantDigest": digest, "device": device_did, "approver": approver });
    let internal = consent::payload_digest(&type_uri, &task_payload)?;

    // The phone approved: the decision handler minted a single-use grant for
    // (this device, this digest), naming the approver it accepted.
    if let Some(g) = consent::get_grant(ks, device_did, &internal, now_s).await? {
        if g.type_uri == type_uri && g.approvers.iter().any(|a| a == approver) {
            return Ok(UvApproval {
                kind: "remoteApprover",
                signer: approver.to_string(),
                decision_id: format!("task-consent:{internal}"),
                digest,
                remote_grant: Some((type_uri, internal)),
            });
        }
        consent::discard_grant(ks, device_did, &internal).await?;
    }

    let replayed = ks
        .get_raw(grant_replay_key(grant.envelope_id))
        .await?
        .is_some();
    if let Some(mark) = consent::get_bound_mark(ks, device_did, &internal).await? {
        if mark.denied {
            return Err(OobError::UvDeclined);
        }
        if let Some(p) = consent::get_pending(ks, &internal, now_s).await? {
            return Err(pending_refusal(&p));
        }
        return Err(if replayed {
            OobError::Replayed
        } else {
            OobError::UvExpired
        });
    }
    // Never ask the phone about a grant id that has been signed already.
    if replayed {
        return Err(OobError::Replayed);
    }

    let expires_at = (now_s + REMOTE_WINDOW_SECS).min(grant.not_after);
    // 256 bits: the replay nonce and the digest salt, as the consent gate's.
    let challenge = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let pending = consent::PendingTaskConsent {
        digest: internal.clone(),
        wire_digest: consent::wire_digest(&type_uri, &task_payload, &challenge)?,
        correlator: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_uri,
        requester_did: device_did.to_string(),
        approver_set: REMOTE_APPROVER_SET.to_string(),
        min_approvals: 1,
        exclude_requester: true,
        challenge,
        approvals: Vec::new(),
        state_pin: None,
        guards: Default::default(),
        subject_context: None,
        requester_authorized: true,
        bound_approver: Some(approver.to_string()),
        created_at: now_s,
        expires_at,
    };
    if !consent::store_bound_pending(ks, &pending, expires_at + REMOTE_MARK_KEEP_SECS).await? {
        // A concurrent poll raised it first: answer with its request.
        return Err(match consent::get_pending(ks, &internal, now_s).await? {
            Some(p) => pending_refusal(&p),
            None => OobError::UvExpired,
        });
    }
    let ask = RemoteAsk {
        origin: grant.origin.to_string(),
        device_name: binding.display_name.clone(),
        persona: grant.persona.to_string(),
        not_after: grant.not_after,
    };
    if let Err(e) = port.ask(&pending, &ask).await {
        // Nobody was asked: withdraw the question so the next poll raises it
        // again, rather than waiting out a request no phone will ever see.
        tracing::warn!(error = %e, device = %device_did, "remote UV approval: could not ask the approver");
        consent::discard_bound_pending(ks, &pending).await?;
        return Err(OobError::App(e));
    }
    Err(pending_refusal(&pending))
}

/// `oobUvPending` for `p`, with the match code the phone shows for it.
fn pending_refusal(p: &consent::PendingTaskConsent) -> OobError {
    OobError::UvPending {
        match_code: vta_sdk::task_consent::match_code(&p.wire_digest).unwrap_or_default(),
        expires_at: p.expires_at,
    }
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
/// The string an authenticator's `rpIdHash` covers for a passkey scoped to
/// `rp_id` and used from `origin`.
///
/// For a web origin it is the RP ID. A Chrome extension is different: it must
/// pass its bare runtime id as `rp.id` (`chrome-extension://<id>` is refused),
/// but Chrome scopes the credential to, and hashes, the whole origin
/// `chrome-extension://<id>`, so it cannot collide with a web RP ID. The
/// enrolment records the bare id the extension passed, so the extension's
/// origin is what the hash is checked against.
fn rp_id_hashed(rp_id: &str, origin: &str) -> String {
    match origin.strip_prefix("chrome-extension://") {
        Some(id) if id == rp_id => origin.to_string(),
        _ => rp_id.to_string(),
    }
}

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
        rp_id: rp_id_hashed(rp_id, origin),
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
        // 0.2 adds the signing scope; it is the same document, gated the same.
        assert_eq!(
            classify(&with_type(&spec("auth/oob/grant/0.2"))).unwrap(),
            Some(OobDocument::Grant)
        );
        // Another version, a variant, or another document of the family is
        // refused, never signed unattended.
        for t in [
            "auth/oob/grant/0.3",
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

    #[test]
    fn an_extension_passkey_is_checked_against_its_origin() {
        let ext = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
        assert_eq!(rp_id_hashed("abcdefghijklmnopabcdefghijklmnop", ext), ext);
        // A web passkey, and an RP ID that is not this extension's, are
        // checked as they are.
        assert_eq!(
            rp_id_hashed("example.com", "https://login.example.com"),
            "example.com"
        );
        assert_eq!(rp_id_hashed("other", ext), "other");
    }

    /// Wallet item 5 (auth/oob/grant/0.2): a grant never delegates signing in,
    /// access control or consent, whatever the service offered.
    #[test]
    fn a_grant_never_delegates_sign_in_access_control_or_consent() {
        let now = chrono::Utc::now();
        let grant = |scope: &[&str]| GrantFields {
            request_id: "AAAAAAAAAAAAAAAA".into(),
            session_key: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into(),
            approver_key: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into(),
            origin: "https://vtc.example.com".into(),
            context_digest: sha256_digest_multibase(&[0u8; 32]),
            not_after: (now.timestamp() + 600) as u64,
            signing_scope: scope.iter().map(|s| s.to_string()).collect(),
        };
        assert!(check_grant(&grant(&["vtc/directory"]), now).is_ok());
        assert!(check_grant(&grant(&[]), now).is_ok());
        for refused in ["auth", "acl/grant", "task-consent", "consent", "confirm"] {
            assert!(
                matches!(
                    check_grant(&grant(&["vtc/directory", refused]), now),
                    Err(OobError::DocumentInvalid(_))
                ),
                "{refused}"
            );
        }
    }
}
