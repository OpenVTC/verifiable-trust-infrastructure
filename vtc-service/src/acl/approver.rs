//! **Step-up approvers** — a `did:key` bound at this VTC to exactly one
//! subject as that subject's own step-up factor, and the verification of the
//! statements it signs (`auth/step-up/approver/attest/0.1`).
//!
//! Design: `docs/05-design-notes/vtc-approver-step-up.md` (§4 the factor, §5 the
//! ceremony, §6 enrolment). Requirements:
//!
//! - **VTI-APV-015** (as amended): a re-authentication must be the caller's own
//!   additional factor. A signature satisfies it only where the signing key is
//!   bound to the caller as a factor under VTI-APV-016, is distinct from every
//!   key that can sign the caller's operations, and is held where using it takes
//!   user verification. The last is trusted from enrolment (§8.1, §11.2) — this
//!   module enforces the first two, at enrolment **and again at every use**.
//! - **VTI-APV-016**: a factor is bound only on evidence independent of the
//!   subject's signing keys, proves possession, and is audited naming that
//!   evidence ([`EnrolledVia`] plus the anchor, on every binding).
//! - **VTI-SES-001–004**: every challenge a statement answers is minted here
//!   from the CSPRNG, bound to one subject, expiring and single use; a
//!   statement's own `id` is recorded so it is spent once ([`verify_statement`]).
//!
//! ## What an approver confers
//!
//! Nothing. No role, no scope, no session, no login. It is read only by the
//! bound step-up gate ([`super::bound_step_up`]) and by the enrolment tasks
//! that change it, from [`crate::store::keyspaces::STEP_UP_APPROVERS`], which
//! login and session step-up never read — the same construction as
//! `STEP_UP_PASSKEYS`.
//!
//! ## Storage (`step_up_approvers`)
//!
//! - `approver:<did>` — an [`ApproverRecord`], live or a revoked tombstone. A
//!   tombstone is never removed: an approver DID is bound to one subject, once
//!   (`auth/step-up/approver/revoke/0.1` item 4).
//! - `subject:<did>` — the subject's live approver DIDs, at most
//!   [`MAX_PER_SUBJECT`].
//! - `spent:<sha256(statement id)>` — a statement already accepted, until its
//!   acceptance window ends.
//!
//! The enrolment ceremonies that write bindings live beside these and are
//! [`crate::step_up_approver`]'s.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, MutexGuard};
use tracing::warn;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::auth::step_up::approver::attest::v0_1 as attest;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::server::AppState;

/// The most live approvers one subject holds (design note §4: the same cap as
/// console keys).
pub const MAX_PER_SUBJECT: usize = 5;

/// `auth/step-up/approver/attest/0.1`.
pub const ATTEST_TYPE: &str = <attest::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Every write of the approver records — a binding, a revocation, an invite's
/// claim-code count, the spending of a statement id — is serialised here, so
/// two concurrent enrolments can neither both pass the cap nor bind one
/// approver twice (`redeem/finish/0.1` item 7, `enroll/0.1` item 7,
/// `revoke/0.1` item 6).
static LOCK: Mutex<()> = Mutex::const_new(());

/// Serialises the check-then-record of a statement's spent `id`.
static SPENT_LOCK: Mutex<()> = Mutex::const_new(());

/// Take the approver write lock. Callers that consume an enrolment ceremony
/// together with the binding it authorizes hold it across both.
pub(crate) async fn lock() -> MutexGuard<'static, ()> {
    LOCK.lock().await
}

/// The anchor a binding rested on (`_shared/0.1` `EnrolledVia`, VTI-APV-016).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EnrolledVia {
    /// Claimed with the community's install token (`vtc/install/claim/finish/0.3`).
    Install,
    /// Redeemed from an administrator's invite.
    Invite,
    /// Added by the subject behind a factor they already held.
    SelfService,
    /// Redeemed from an invite the operator minted on the host, daemon stopped.
    Offline,
}

impl EnrolledVia {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Invite => "invite",
            Self::SelfService => "selfService",
            Self::Offline => "offline",
        }
    }
}

/// One approver binding, as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproverRecord {
    pub approver_did: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub enrolled_at: DateTime<Utc>,
    pub enrolled_via: EnrolledVia,
    /// What the anchor was — the inviting administrator, the install token's
    /// `jti`, `host`, or the step-up evidence a self-service enrolment rested
    /// on. Kept with the binding for incident review; never on the wire.
    pub anchor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Set on revocation; the row stays as a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
}

impl ApproverRecord {
    pub fn is_live(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// The `_shared/0.1` `Approver` shape every response carries.
    pub fn to_wire(&self) -> Value {
        let mut v = json!({
            "approverDid": self.approver_did,
            "subject": self.subject,
            "enrolledAt": self.enrolled_at,
            "enrolledVia": self.enrolled_via.as_str(),
        });
        if let Some(label) = &self.label {
            v["label"] = json!(label);
        }
        if let Some(at) = self.last_used_at {
            v["lastUsedAt"] = json!(at);
        }
        v
    }
}

fn approver_key(did: &str) -> String {
    format!("approver:{did}")
}
fn subject_key(did: &str) -> String {
    format!("subject:{did}")
}
fn spent_key(id: &str) -> String {
    format!("spent:{}", hex::encode(Sha256::digest(id.as_bytes())))
}

/// The record for `approver_did`, live or tombstoned.
pub async fn get(
    ks: &KeyspaceHandle,
    approver_did: &str,
) -> Result<Option<ApproverRecord>, AppError> {
    ks.get(approver_key(approver_did)).await
}

/// `subject`'s live bindings, as stored — whatever the subject's standing.
pub async fn stored_live(
    ks: &KeyspaceHandle,
    subject: &str,
) -> Result<Vec<ApproverRecord>, AppError> {
    let dids: Vec<String> = ks.get(subject_key(subject)).await?.unwrap_or_default();
    let mut out = Vec::with_capacity(dids.len());
    for did in dids {
        if let Some(r) = get(ks, &did).await?
            && r.is_live()
            && r.subject == subject
        {
            out.push(r);
        }
    }
    out.sort_by_key(|r| std::cmp::Reverse(r.enrolled_at));
    Ok(out)
}

/// The approvers that **count** for `subject` right now: live bindings of a
/// current member, each still distinct from the subject's DID and signing keys
/// (attest/0.1 consumer item 6 — checked at every use, because a DID document
/// or a console-key enrolment can change after the binding was made).
///
/// Empty for a DID that is no longer a current member: removing a subject from
/// the ACL removes their approvers (design note §6f) in the sense that matters
/// — none of them answers anything.
pub async fn live_approvers(
    state: &AppState,
    subject: &str,
) -> Result<Vec<ApproverRecord>, AppError> {
    if !crate::git_ns::ops::standing(state, subject).await?.member {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for r in stored_live(&state.step_up_approvers_ks, subject).await? {
        match check_distinct(state, subject, &r.approver_did).await? {
            Ok(()) => out.push(r),
            Err(why) => warn!(
                %subject,
                approver = %r.approver_did,
                why,
                security_alert = true,
                "a step-up approver is no longer distinct from its subject's keys; it does not count"
            ),
        }
    }
    Ok(out)
}

/// The Ed25519 public key a `did:key:z6Mk…` names, or `None` when `did` is
/// not one (`_shared/0.1` `ApproverDid`).
pub fn ed25519_did_key(did: &str) -> Option<[u8; 32]> {
    let mb = did.strip_prefix("did:key:")?;
    if !mb.starts_with("z6Mk") || mb.contains('#') {
        return None;
    }
    let (base, bytes) = multibase::decode(mb).ok()?;
    if base != multibase::Base::Base58Btc || bytes.len() != 34 || bytes[..2] != [0xed, 0x01] {
        return None;
    }
    bytes[2..].try_into().ok()
}

/// Every public key `subject`'s DID document lists. A `did:key` resolves
/// locally; anything else through the configured resolver. Failing to resolve
/// is an error, which every caller treats as "not distinct" — fail closed.
async fn subject_keys(state: &AppState, subject: &str) -> Result<Vec<Vec<u8>>, AppError> {
    if subject.starts_with("did:key:") {
        let mb = subject.trim_start_matches("did:key:");
        let (_, bytes) = multibase::decode(mb)
            .map_err(|e| AppError::Validation(format!("subject did:key: {e}")))?;
        // Multicodec prefix dropped: what is compared is the raw key.
        return Ok(vec![bytes.get(2..).unwrap_or_default().to_vec()]);
    }
    let resolver = state.did_resolver.as_ref().ok_or_else(|| {
        AppError::Internal(format!(
            "no DID resolver is configured, so {subject}'s document cannot be read"
        ))
    })?;
    let resolved = resolver
        .resolve(subject)
        .await
        .map_err(|e| AppError::Internal(format!("{subject} did not resolve: {e}")))?;
    Ok(resolved
        .doc
        .verification_method
        .iter()
        .filter_map(|vm| vm.get_public_key_bytes().ok())
        .collect())
}

/// Whether `approver_did` is distinct from everything `subject` can already
/// sign with (attest/0.1 consumer item 6; `redeem/finish/0.1` item 4):
///
/// - it is not the subject's DID;
/// - its key appears as no verification method of the subject's DID document;
/// - it is no console signing key — of the subject or anyone else (a console
///   key is a key some administrator signs operations with here);
/// - it holds no standing of its own (no ACL row).
///
/// `Ok(Err(why))` names the rule that failed, for the operator's log.
pub async fn check_distinct(
    state: &AppState,
    subject: &str,
    approver_did: &str,
) -> Result<Result<(), &'static str>, AppError> {
    let Some(key) = ed25519_did_key(approver_did) else {
        return Ok(Err("not an Ed25519 did:key"));
    };
    if approver_did == subject {
        return Ok(Err("the subject's own DID"));
    }
    if crate::acl::console_key::get_delegation(&state.console_keys_ks, approver_did)
        .await?
        .is_some()
    {
        return Ok(Err("a console signing key"));
    }
    if crate::acl::get_acl_entry(&state.acl_ks, approver_did)
        .await?
        .is_some()
    {
        return Ok(Err("holds standing of its own"));
    }
    match subject_keys(state, subject).await {
        Ok(keys) if keys.iter().any(|k| k.as_slice() == key.as_slice()) => {
            Ok(Err("a verification method of the subject's DID document"))
        }
        Ok(_) => Ok(Ok(())),
        Err(e) => {
            warn!(%subject, error = %e, "subject DID document unreadable; approver treated as not distinct");
            Ok(Err("the subject's DID document could not be read"))
        }
    }
}

/// Why a binding could not be written.
#[derive(Debug)]
pub enum BindError {
    /// Bound already — to anyone — or bound and revoked: burned.
    AlreadyBound,
    /// The subject already holds [`MAX_PER_SUBJECT`] live approvers.
    TooMany,
    /// `replaces` names no live approver of the subject.
    ReplaceNotFound,
    Internal(AppError),
}

impl From<AppError> for BindError {
    fn from(e: AppError) -> Self {
        Self::Internal(e)
    }
}

/// Whether `record` could be written now, without writing it — the same rules
/// [`write_binding`] applies. For a binding that must be checked before
/// something else is committed (the install bootstrap).
pub async fn check_bindable(
    ks: &KeyspaceHandle,
    approver_did: &str,
    subject: &str,
    replaces: Option<&str>,
) -> Result<(), BindError> {
    if get(ks, approver_did).await?.is_some() {
        return Err(BindError::AlreadyBound);
    }
    let live = stored_live(ks, subject).await?;
    if let Some(r) = replaces
        && !live.iter().any(|a| a.approver_did == r)
    {
        return Err(BindError::ReplaceNotFound);
    }
    let after = live.len() - usize::from(replaces.is_some());
    if after >= MAX_PER_SUBJECT {
        return Err(BindError::TooMany);
    }
    Ok(())
}

/// Write `record` as a live binding, revoking `replaces` in the same step.
///
/// **The caller holds [`lock`]**, across whatever ceremony this consumes, so
/// the cap, the uniqueness rule and the consumption are one critical section.
pub(crate) async fn write_binding(
    ks: &KeyspaceHandle,
    record: &ApproverRecord,
    replaces: Option<&str>,
    replaced_by: &str,
) -> Result<(), BindError> {
    check_bindable(ks, &record.approver_did, &record.subject, replaces).await?;
    if let Some(old) = replaces {
        tombstone(ks, &record.subject, old, replaced_by).await?;
    }
    ks.insert(approver_key(&record.approver_did), record)
        .await?;
    let mut dids: Vec<String> = ks
        .get(subject_key(&record.subject))
        .await?
        .unwrap_or_default();
    dids.retain(|d| d != &record.approver_did);
    dids.push(record.approver_did.clone());
    ks.insert(subject_key(&record.subject), &dids).await?;
    Ok(())
}

/// Turn `subject`'s live binding of `approver_did` into a tombstone. The
/// caller holds [`lock`]. Returns the record as it stood, or `None` when there
/// was no live binding of it to `subject`.
pub(crate) async fn tombstone(
    ks: &KeyspaceHandle,
    subject: &str,
    approver_did: &str,
    by: &str,
) -> Result<Option<ApproverRecord>, AppError> {
    let Some(mut r) = get(ks, approver_did).await? else {
        return Ok(None);
    };
    if r.subject != subject || !r.is_live() {
        return Ok(None);
    }
    let before = r.clone();
    r.revoked_at = Some(Utc::now());
    r.revoked_by = Some(by.to_string());
    ks.insert(approver_key(approver_did), &r).await?;
    let mut dids: Vec<String> = ks.get(subject_key(subject)).await?.unwrap_or_default();
    dids.retain(|d| d != approver_did);
    ks.insert(subject_key(subject), &dids).await?;
    Ok(Some(before))
}

/// Record that `approver_did` answered a step-up (`lastUsedAt`).
pub async fn record_use(ks: &KeyspaceHandle, approver_did: &str) -> Result<(), AppError> {
    let _guard = lock().await;
    if let Some(mut r) = get(ks, approver_did).await?
        && r.is_live()
    {
        r.last_used_at = Some(Utc::now());
        ks.insert(approver_key(approver_did), &r).await?;
    }
    Ok(())
}

// ── statements ──────────────────────────────────────────────────────────────

/// Which approver a statement must come from.
#[derive(Debug, Clone, Copy)]
pub enum ExpectedApprover<'a> {
    /// A live approver bound to the subject, and one of those the relying
    /// party offered when it minted the challenge (approve-response 0.6 step
    /// 4.2). For `stepUp` and `decision`.
    BoundAmong(&'a [String]),
    /// The approver the carrying task is enrolling, not yet bound to anyone.
    /// Distinctness is the carrying task's own check (it has its own code).
    Enrolling(&'a str),
}

/// What the relying party's **own pending record** says the statement must
/// match — never values taken from the carrying document (attest/0.1
/// consumer item 4).
#[derive(Debug, Clone, Copy)]
pub struct ExpectedStatement<'a> {
    pub purpose: attest::PayloadPurpose,
    pub subject: &'a str,
    pub challenge: &'a str,
    pub bound_to: &'a str,
    /// The pending record's lifetime; `issuedAt` must fall inside it.
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub approver: ExpectedApprover<'a>,
}

/// Why a statement was refused. The carrying task reports each under its own
/// code (attest/0.1 consumer item 8).
#[derive(Debug)]
pub enum StatementError {
    /// Not a valid attest/0.1 document for this record — the carrying task's
    /// `statementInvalid`. The reason is for the log only.
    Invalid(&'static str),
    /// Signed by a DID that is not a live, distinct approver of the subject
    /// that was offered — approve-response 0.6's `approverNotBound`.
    NotBound,
    Internal(AppError),
}

impl From<AppError> for StatementError {
    fn from(e: AppError) -> Self {
        Self::Internal(e)
    }
}

/// An `auth/step-up/approver/attest/0.1` statement that **has been verified**
/// against a pending record of this service's own. Only [`verify_statement`]
/// constructs one, so a function that takes it cannot be handed a statement
/// nobody checked (the typestate rule in the workspace `CLAUDE.md`).
#[derive(Debug, Clone)]
pub struct VerifiedApproverStatement {
    approver_did: String,
    subject: String,
    purpose: attest::PayloadPurpose,
    statement_id: String,
    issued_at: DateTime<Utc>,
}

impl VerifiedApproverStatement {
    /// The approver `did:key` that signed it.
    pub fn approver_did(&self) -> &str {
        &self.approver_did
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn purpose(&self) -> attest::PayloadPurpose {
        self.purpose
    }
    /// The statement document's `id`, now spent.
    pub fn statement_id(&self) -> &str {
        &self.statement_id
    }
    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }
}

/// Constant-time equality, for the challenge (approve-response 0.6 step 3).
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Verify an embedded `auth/step-up/approver/attest/0.1` statement, **as
/// received**, against `expected` — attest/0.1's consumer requirements in full:
///
/// 1. a Trust Task document of type attest/0.1, its proof made for
///    `authentication` by its own `issuer`, a `did:key` (verified over the
///    object exactly as received — no re-serialisation, VTI-45);
/// 2. its acceptance window, and `recipient` and `payload.audience` both this
///    VTC's DID;
/// 3. `purpose`, `subject`, `challenge` and `boundTo` equal, bit for bit, the
///    pending record's, and `issuedAt` inside that record's lifetime;
/// 4. the issuer a live, distinct approver of the subject that was offered —
///    or, enrolling, the approver being enrolled — and never the subject;
/// 5. its `id` not spent before, and spent now (VTI-SES-004).
///
/// Then, and only then, the [`VerifiedApproverStatement`].
pub async fn verify_statement(
    state: &AppState,
    statement: &Value,
    expected: &ExpectedStatement<'_>,
) -> Result<VerifiedApproverStatement, StatementError> {
    use trust_tasks_rs::validate::ValidatedPayload as _;
    let invalid = |why: &'static str| {
        warn!(subject = %expected.subject, why, "step-up approver statement refused");
        StatementError::Invalid(why)
    };

    if !statement.is_object() {
        return Err(invalid("not an object"));
    }
    let doc: TrustTask<Value> =
        serde_json::from_value(statement.clone()).map_err(|_| invalid("not a Trust Task"))?;
    if doc.type_uri.to_string() != ATTEST_TYPE {
        return Err(invalid("not an attest/0.1 document"));
    }
    let Some(issuer) = doc.issuer.clone() else {
        return Err(invalid("no issuer"));
    };
    if ed25519_did_key(&issuer).is_none() {
        return Err(invalid("issuer is not an Ed25519 did:key"));
    }
    if statement
        .pointer("/proof/proofPurpose")
        .and_then(Value::as_str)
        != Some("authentication")
    {
        return Err(invalid("proof not made for authentication"));
    }
    // `did:key` only, so the factor's key is a function of its identifier and
    // verifying it never fetches.
    let signer = vti_common::auth::verify_trust_task_proof_value(
        statement,
        &vti_common::auth::TrustTaskVmResolver::did_key_only(),
    )
    .await
    .map_err(|e| {
        warn!(error = %e, cause = e.cause().unwrap_or_default(), "statement proof did not verify");
        invalid("proof does not verify")
    })?;
    if signer != issuer {
        return Err(invalid("proof not by the issuer"));
    }

    let vtc_did =
        state.config.read().await.vtc_did.clone().ok_or_else(|| {
            AppError::Config("this VTC has no DID; it cannot be an audience".into())
        })?;
    let now = Utc::now();
    let window = vti_common::trust_task::acceptance::VTI_ACCEPTANCE_WINDOW;
    if doc
        .validate_freshness(now, &window.freshness_policy().requiring_issued_at())
        .is_err()
    {
        return Err(invalid("outside its acceptance window"));
    }
    if doc.validate_basic(now, &vtc_did).is_err() || doc.recipient.as_deref() != Some(&vtc_did) {
        return Err(invalid("recipient is not this VTC"));
    }
    attest::Payload::validate_value(&doc.payload).map_err(|_| invalid("payload schema"))?;
    let payload: attest::Payload =
        serde_json::from_value(doc.payload.clone()).map_err(|_| invalid("payload shape"))?;
    if payload.audience.as_str() != vtc_did {
        return Err(invalid("audience is not this VTC"));
    }
    if payload.purpose != expected.purpose {
        return Err(invalid("wrong purpose"));
    }
    if payload.subject.as_str() != expected.subject {
        return Err(invalid("subject differs from the pending record"));
    }
    if !ct_eq(payload.challenge.as_str(), expected.challenge) {
        return Err(invalid("challenge differs from the pending record"));
    }
    if payload.bound_to.as_str() != expected.bound_to {
        return Err(invalid("boundTo differs from the pending record"));
    }
    let issued_at = doc.issued_at.ok_or_else(|| invalid("no issuedAt"))?;
    let skew = Duration::seconds(60);
    if issued_at < expected.not_before - skew || issued_at > expected.not_after + skew {
        return Err(invalid("issued outside the pending record's lifetime"));
    }
    if issuer == expected.subject {
        return Err(invalid("issuer is the subject"));
    }

    match expected.approver {
        ExpectedApprover::Enrolling(approver) => {
            if issuer != approver {
                return Err(invalid("issuer is not the approver being enrolled"));
            }
        }
        ExpectedApprover::BoundAmong(offered) => {
            if !offered.iter().any(|d| d == &issuer) {
                return Err(StatementError::NotBound);
            }
            let bound = live_approvers(state, expected.subject).await?;
            if !bound.iter().any(|r| r.approver_did == issuer) {
                warn!(
                    subject = %expected.subject,
                    approver = %issuer,
                    security_alert = true,
                    "a statement by a DID that is not a live approver of its subject"
                );
                return Err(StatementError::NotBound);
            }
        }
    }

    // Spent last, after everything else held: a refused statement keeps its
    // id, a verified one cannot be presented again (attest/0.1 item 7).
    let ks = &state.step_up_approvers_ks;
    let key = spent_key(&doc.id);
    {
        // Its own lock, not [`lock`]: an enrolment verifies its statement
        // while it already holds the binding lock.
        let _guard = SPENT_LOCK.lock().await;
        if let Some(until) = ks.get::<i64>(key.clone()).await?
            && until > now.timestamp()
        {
            return Err(invalid("statement id already spent"));
        }
        let until = issued_at + window.max_age + window.clock_skew + skew;
        ks.insert(key, &until.timestamp()).await?;
    }

    Ok(VerifiedApproverStatement {
        approver_did: issuer,
        subject: expected.subject.to_string(),
        purpose: payload.purpose,
        statement_id: doc.id.clone(),
        issued_at,
    })
}

/// Bind `approver_did` to `subject` directly, as if an enrolment had — for
/// tests of the gate it feeds, which would otherwise have to run an enrolment
/// ceremony first. Never compiled into a release build.
#[cfg(any(test, feature = "test-support"))]
pub async fn bind_for_test(
    state: &AppState,
    subject: &str,
    approver_did: &str,
) -> Result<(), AppError> {
    let _guard = lock().await;
    write_binding(
        &state.step_up_approvers_ks,
        &ApproverRecord {
            approver_did: approver_did.to_string(),
            subject: subject.to_string(),
            label: Some("test".into()),
            enrolled_at: Utc::now(),
            enrolled_via: EnrolledVia::Invite,
            anchor: "test".into(),
            last_used_at: None,
            revoked_at: None,
            revoked_by: None,
        },
        None,
        subject,
    )
    .await
    .map_err(|e| AppError::Internal(format!("bind_for_test: {e:?}")))
}

/// Remove spent statement ids whose window has ended. A storage bound: a
/// statement older than its window is refused by its acceptance window anyway.
pub(crate) async fn sweep_spent(
    ks: &KeyspaceHandle,
    now: DateTime<Utc>,
) -> Result<usize, AppError> {
    let mut removed = 0;
    for (key, value) in ks.prefix_iter_raw(b"spent:".to_vec()).await? {
        let lapsed = serde_json::from_slice::<i64>(&value).map_or(true, |t| t <= now.timestamp());
        if lapsed {
            ks.remove(key).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_ed25519_did_key_is_an_approver() {
        let party = vti_rooms_dtg::test_support::Party::new();
        assert!(ed25519_did_key(&party.did).is_some());
        assert!(ed25519_did_key("did:web:example.com").is_none());
        assert!(ed25519_did_key(&format!("{}#key-1", party.did)).is_none());
        assert!(
            ed25519_did_key("did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc").is_none()
        );
    }

    #[test]
    fn the_constant_time_compare_is_equality() {
        assert!(ct_eq("abcdef", "abcdef"));
        assert!(!ct_eq("abcdef", "abcdeg"));
        assert!(!ct_eq("abc", "abcd"));
    }

    #[test]
    fn the_wire_record_is_the_shared_approver_shape() {
        let r = ApproverRecord {
            approver_did: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".into(),
            subject: "did:key:z6MkSubject".into(),
            label: Some("laptop".into()),
            enrolled_at: Utc::now(),
            enrolled_via: EnrolledVia::SelfService,
            anchor: "webauthn:c0ffee".into(),
            last_used_at: None,
            revoked_at: None,
            revoked_by: None,
        };
        let v = r.to_wire();
        assert_eq!(v["enrolledVia"], "selfService");
        assert!(v.get("anchor").is_none(), "the anchor is never on the wire");
    }
}
