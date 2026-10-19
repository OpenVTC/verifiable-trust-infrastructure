//! The VTA as the principal's **witnessed party** — the engine behind `vta/witness/open`,
//! `vta/witness/present` and `vta/witness/accept` at 0.2 (trust-tasks-tf #779, #799; the family's
//! rules are `specs/vta/_shared/0.6/CONVENTIONS.md`, cited below as "conventions").
//!
//! Sessions are conducted under `witness/session/0.2` and `witness/session/submit/0.2`, whose
//! payload carries the member presentation in its own `memberPresentation`. A session record is
//! continued only by the version that opened it: one whose stored document is not a
//! `witness/session/0.2` answers `sessionUnknown` (conventions, introduction).
//!
//! A witness checks that the
//! transport-proven sender of each document is its `issuer`, and replies to that sender. The
//! relationship DID's one mediator connection belongs to whoever holds the relationship —
//! normally the client — so the VTA never speaks to the witness (conventions §2 item 3). It
//! builds and signs, as the relationship DID, every document the party sends, and verifies and
//! stores what the witness returns; the client carries the documents.
//!
//! # The session record (conventions §3)
//!
//! One row per session in [`crate::keyspaces::WITNESS_SESSIONS`], keyed by the session id (the
//! `id` of the `witness/session` document built at open), in the context of the relationship
//! DID's key. It moves `opened` → `presented` → `accepted`; an accepted session keeps only its
//! stub until the record's expiry. It holds no presentation and no challenge. An unknown,
//! expired, out-of-scope or wrong-state record is one answer — [`WitnessError::SessionUnknown`]
//! — so the answer says nothing about sessions the caller cannot see.
//!
//! # Every handed-back document is checked before it is read
//!
//! [`verify_answer`] is the only way to a [`VerifiedWitnessAnswer`]: the expected `#response`
//! type, `issuer` the record's witness, `recipient` the record's relationship DID, `threadId` the
//! session id, and a proof that verifies for the witness's DID. `present` reads the challenge and
//! domain only from one; [`verify_outcome`] turns one into the [`VerifiedWitnessOutcome`] that is
//! the only thing [`accept`] stores. A call site that forgets either check does not compile.
//!
//! # Custody (conventions §2)
//!
//! The relationship DID's key — and, under the member link, the member DID's — is found through
//! [`crate::operations::persona::persona_key_for`] (a DID this VTA holds a key of in a context the
//! caller acts in; a pairwise `did:peer` included) and then held to the oracle's gates by
//! [`crate::operations::keys::require_key_nameable`]. Every signature goes through
//! [`crate::operations::keys::sign_payload`] as `ProtocolDefined` input the VTA built itself, never
//! bytes the caller supplied, so `sign` is neither required nor sufficient.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::specs::witness::session;
use vta_sdk::trust_task_proof::{
    ProofPurpose, TrustTaskVmResolver, verify_proof_set, verify_trust_task_proof_value,
};
use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle};

use crate::auth::AuthClaims;
use crate::operations::persona::{PersonaStores, Relationship, persona_key_for};
use crate::operations::room_issuance::{SigningContext, VtaKeySigner};
use crate::server::AppState;
use crate::vault::model::{
    CredentialFormat, CredentialPurpose, CredentialStatus, StoredCredential,
};

/// The `witness/session/submit/0.2` payload member carrying the member presentation.
pub const MEMBER_PRESENTATION: &str = "memberPresentation";

/// The reserved credential-vault tag holding the `witness/session` document a stored VWC cites,
/// as the VTA built it (`vta/witness/accept/0.2` item 5).
pub const EVIDENCE_SESSION_TAG: &str = "witness:session";
/// The reserved credential-vault tag holding the witness's `witness/session/submit` `#response`,
/// as handed back.
pub const EVIDENCE_OUTCOME_TAG: &str = "witness:outcome";

/// The DTG predicate a VWC states (`witness/session/submit/0.2`, *The credential delivered*).
const WITNESSED_V1: &str = dtg_credentials::WITNESSED_V1;

fn session_type() -> &'static str {
    <session::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI
}
fn session_response_type() -> &'static str {
    <session::v0_2::Response as trust_tasks_rs::Payload>::TYPE_URI
}
fn submit_type() -> &'static str {
    <session::submit::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI
}
fn submit_response_type() -> &'static str {
    <session::submit::v0_2::Response as trust_tasks_rs::Payload>::TYPE_URI
}

// ─── Errors ──────────────────────────────────────────────────────────────────

/// Why a witnessed-party step was refused. Each maps to the code the task declares, or to the
/// framework's standard code where conventions §7 says so.
#[derive(Debug)]
#[non_exhaustive]
pub enum WitnessError {
    /// No key of a DID the session needs in the caller's contexts, or no standing:
    /// `permissionDenied`.
    PermissionDenied(String),
    /// A payload a stated rule rejects: `malformedRequest`.
    Malformed(String),
    /// A named credential is not in the vault in the caller's contexts, or is not active.
    NotFound(String),
    /// A credential does not fit its role, or has changed since open.
    CredentialMismatch(String),
    /// The witness's DID could not be resolved.
    WitnessUnresolvable(String),
    /// No record in a state that admits the task, in the caller's contexts. Deliberately
    /// carries no reason: the answer must be the same whatever the cause.
    SessionUnknown,
    /// The document handed back is not the witness's answer for this session.
    ResponseInvalid(String),
    /// The witness's answer is genuine, but the VWC does not verify against the session.
    VwcInvalid(String),
    /// Anything else.
    App(AppError),
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PermissionDenied(m)
            | Self::Malformed(m)
            | Self::NotFound(m)
            | Self::CredentialMismatch(m)
            | Self::WitnessUnresolvable(m)
            | Self::ResponseInvalid(m)
            | Self::VwcInvalid(m) => f.write_str(m),
            Self::SessionUnknown => f.write_str(
                "no witnessed session with this id is in a state that admits this step, in a \
                 context you may act in — it may never have existed here, have expired, or have \
                 moved on; open a new session with vta/witness/open",
            ),
            Self::App(e) => write!(f, "{e}"),
        }
    }
}

impl From<AppError> for WitnessError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

// ─── The session record ──────────────────────────────────────────────────────

/// A credential bound to the session at open: its vault handle and the SHA-256 of its stored
/// bytes, so a later step presents exactly what open checked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundCredential {
    pub id: String,
    pub digest: String,
}

/// The membership evidence bound at open.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundMembership {
    pub credential: BoundCredential,
    /// The member DID under the member link; absent when the VMC names the relationship DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_did: Option<String>,
}

/// A session between `open` and `accept` (conventions §3 item 1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionRecord {
    pub session_id: String,
    /// The context of the relationship DID's key; `None` for an unscoped key (super-admin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    pub witness: String,
    pub relationship_did: String,
    pub counterparty_did: String,
    pub relationship_thread_id: String,
    /// The `witness/session/0.2` document exactly as built and signed.
    pub session_document: Value,
    pub relationship_credential: BoundCredential,
    /// The relationship credential's DTG digest (proof excluded) — what the VWC's
    /// `credentialSubject.object.digestMultibase` must name.
    pub relationship_credential_object_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<BoundMembership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_as: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// What an accepted session keeps until its expiry (conventions §3 item 5): enough to find it in
/// the caller's contexts, check a handed-back outcome again, and answer as before.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptedStub {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    pub witness: String,
    pub relationship_did: String,
    pub credential_id: String,
    pub vwc_digest_multibase: String,
    pub expires_at: DateTime<Utc>,
}

/// A row of [`crate::keyspaces::WITNESS_SESSIONS`]: the session's state machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum SessionEntry {
    /// Opened: the session document exists, nothing has been presented.
    Opened(SessionRecord),
    /// A submit document has been built; it may be built again (conventions §5).
    Presented(SessionRecord),
    /// The VWC is stored; only the stub remains.
    Accepted(AcceptedStub),
}

impl SessionEntry {
    fn expires_at(&self) -> DateTime<Utc> {
        match self {
            Self::Opened(r) | Self::Presented(r) => r.expires_at,
            Self::Accepted(s) => s.expires_at,
        }
    }

    fn context_id(&self) -> Option<&str> {
        match self {
            Self::Opened(r) | Self::Presented(r) => r.context_id.as_deref(),
            Self::Accepted(s) => s.context_id.as_deref(),
        }
    }
}

fn session_key(session_id: &str) -> String {
    format!("session:{session_id}")
}

/// Whether `auth` may act in the record's context. An unscoped record (an unscoped key) is the
/// super-admin's alone.
fn in_scope(auth: &AuthClaims, context: Option<&str>) -> bool {
    match context {
        Some(ctx) => auth.has_context_access(ctx),
        None => auth.is_super_admin(),
    }
}

/// The session `session_id`, as stored, if it is unexpired and in the caller's contexts —
/// with the raw row, for a compare-and-set. Everything else is [`WitnessError::SessionUnknown`].
async fn find_session(
    ks: &KeyspaceHandle,
    auth: &AuthClaims,
    session_id: &str,
    now: DateTime<Utc>,
) -> Result<(SessionEntry, Vec<u8>), WitnessError> {
    let Some(raw) = ks.get_raw(session_key(session_id)).await? else {
        return Err(WitnessError::SessionUnknown);
    };
    let entry: SessionEntry = serde_json::from_slice(&raw).map_err(|e| {
        tracing::error!(error = %e, "a witnessed-session record does not parse; treated as unknown");
        WitnessError::SessionUnknown
    })?;
    if entry.expires_at() <= now || !in_scope(auth, entry.context_id()) {
        return Err(WitnessError::SessionUnknown);
    }
    Ok((entry, raw))
}

/// Whether `record` was opened by `vta/witness/open/0.2`: its stored session document is a
/// `witness/session/0.2`. A session is continued only by the version that opened it
/// (conventions, introduction), so any other record answers `sessionUnknown`.
fn opened_at_this_version(record: &SessionRecord) -> bool {
    record.session_document.get("type").and_then(Value::as_str) == Some(session_type())
}

/// Replace the row at `session_id` with `next`, only while it still holds `expected`. A lost
/// race is [`WitnessError::SessionUnknown`]: the session moved on under another request.
async fn replace_session(
    ks: &KeyspaceHandle,
    session_id: &str,
    expected: Vec<u8>,
    next: &SessionEntry,
) -> Result<(), WitnessError> {
    let key = session_key(session_id);
    let mut batch = Batch::new();
    batch.require_unchanged(key.clone(), expected);
    batch.insert(key, next)?;
    if ks.apply_batch(batch).await?.is_applied() {
        Ok(())
    } else {
        Err(WitnessError::SessionUnknown)
    }
}

/// Delete every record past its expiry. The storage thread runs this on its interval; reads
/// already treat an expired record as unknown, so a missed pass costs space and nothing else.
pub async fn sweep_expired(ks: &KeyspaceHandle, now: DateTime<Utc>) -> Result<usize, AppError> {
    let mut removed = 0;
    for (key, value) in ks.prefix_iter_raw("session:").await? {
        let expired = match serde_json::from_slice::<SessionEntry>(&value) {
            Ok(entry) => entry.expires_at() <= now,
            // A row this build cannot read is no session anyone can use.
            Err(_) => true,
        };
        if expired {
            ks.remove(key).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

// ─── Custody ─────────────────────────────────────────────────────────────────

/// A key this VTA signs with as one of the session's DIDs.
struct PartyKey {
    key_id: String,
    verification_method: String,
    context_id: Option<String>,
}

/// The key of `did` this VTA may sign with for `auth`, listed under `authentication` — or
/// `permissionDenied`, the same whether the DID is unknown here or held for another context.
async fn party_key(
    state: &AppState,
    auth: &AuthClaims,
    did: &str,
) -> Result<PartyKey, WitnessError> {
    let not_held = || {
        WitnessError::PermissionDenied(format!(
            "this agent holds no key of `{did}` that you may use, so it cannot act as it in a \
             witnessed session. Name a DID whose keys this agent holds in a context you act in \
             (a relationship DID created with its keys at this VTA)"
        ))
    };
    let key = persona_key_for(
        PersonaStores::from_state(state),
        auth,
        did,
        Relationship::Authentication,
    )
    .await?
    .ok_or_else(not_held)?;
    // The oracle's gates, applied now rather than at the first signature: a refusal here
    // happens before the witness learns anything (`vta/witness/open/0.2` item 1).
    let record = crate::operations::keys::require_key_nameable(
        &state.keys_ks,
        &state.acl_ks,
        auth,
        &key.key_id,
    )
    .await
    .map_err(|_| not_held())?;
    Ok(PartyKey {
        key_id: key.key_id,
        verification_method: key.verification_method,
        context_id: record.context_id,
    })
}

fn signing_context<'a>(state: &'a AppState, auth: &'a AuthClaims) -> SigningContext<'a> {
    SigningContext {
        keys_ks: &state.keys_ks,
        imported_ks: &state.imported_ks,
        internal_ks: &state.internal_ks,
        contexts_ks: &state.contexts_ks,
        acl_ks: &state.acl_ks,
        seed_store: &state.seed_store,
        audit: &state.audit_sink,
        auth,
    }
}

/// Attach a Data Integrity proof for `purpose` by `key` to `object`, through the gated oracle.
async fn sign_as(
    state: &AppState,
    auth: &AuthClaims,
    key: &PartyKey,
    object: &mut Value,
    purpose: ProofPurpose,
) -> Result<(), WitnessError> {
    if let Some(map) = object.as_object_mut() {
        map.remove("proof");
    }
    let signer = VtaKeySigner::new(
        signing_context(state, auth),
        &key.key_id,
        &key.verification_method,
    );
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &*object,
        &signer,
        affinidi_data_integrity::SignOptions::new()
            .with_proof_purpose(purpose.as_str())
            .with_created(Utc::now()),
    )
    .await
    .map_err(|e| {
        let mut cause = String::new();
        let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
        while let Some(inner) = src {
            cause = format!("{cause}: {inner}");
            src = inner.source();
        }
        WitnessError::App(AppError::Internal(format!(
            "sign as `{}`: {e}{cause}",
            key.verification_method
        )))
    })?;
    object["proof"] = serde_json::to_value(proof)
        .map_err(|e| AppError::Internal(format!("encode the proof: {e}")))?;
    Ok(())
}

// ─── Credentials ─────────────────────────────────────────────────────────────

/// A credential read from the vault for this session.
struct HeldCredential {
    body: Value,
    digest: String,
}

/// SHA-256 of the stored bytes, hex: any change to the stored credential — a re-proofing
/// included — reads as a change.
fn stored_digest(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// `id` from the vault: active, in the caller's contexts, a JSON Data Integrity credential.
async fn read_credential(
    state: &AppState,
    auth: &AuthClaims,
    id: &str,
) -> Result<HeldCredential, WitnessError> {
    let not_found = || {
        WitnessError::NotFound(format!(
            "no active credential `{id}` in the credential vault in a context you may act in; \
             `pnm cred-vault query` lists the handles you can use"
        ))
    };
    let stored = crate::vault::storage::get(&state.vault_ks, id)
        .await?
        .filter(|c| {
            c.is_active()
                && crate::vault::query::caller_may_access_custody(
                    &auth.act_scope(),
                    c.context_id.as_deref(),
                )
        })
        .ok_or_else(not_found)?;
    if stored.format != CredentialFormat::EddsaJcs2022 {
        return Err(WitnessError::CredentialMismatch(format!(
            "credential `{id}` is not a JSON Data Integrity credential, which is the only form a \
             witness reads"
        )));
    }
    let body: Value = serde_json::from_slice(&stored.body)
        .map_err(|_| WitnessError::CredentialMismatch(format!("credential `{id}` is not JSON")))?;
    Ok(HeldCredential {
        digest: stored_digest(&stored.body),
        body,
    })
}

/// Which role a credential must fit.
enum Role<'a> {
    /// A `RelationshipCredential` issued by `issuer` naming `subject`.
    Relationship { issuer: &'a str, subject: &'a str },
    /// A community-issued `MembershipCredential` grant naming `member`.
    Membership { member: &'a str },
}

/// `credentialMismatch` unless `body` fits `role` and is in its validity window at `now`.
fn check_role(
    id: &str,
    body: &Value,
    role: &Role<'_>,
    now: DateTime<Utc>,
) -> Result<(), WitnessError> {
    use dtg_credentials::{DTGCredential, DTGCredentialType};
    let mismatch =
        |why: String| WitnessError::CredentialMismatch(format!("credential `{id}` {why}"));
    let dtg = DTGCredential::try_from(body.clone())
        .map_err(|e| mismatch(format!("is not a DTG credential: {e}")))?;
    match role {
        Role::Relationship { issuer, subject } => {
            if !matches!(dtg.type_(), DTGCredentialType::Relationship) {
                return Err(mismatch("is not a RelationshipCredential".into()));
            }
            if dtg.issuer() != *issuer {
                return Err(mismatch(format!(
                    "is not issued by the relationship DID `{issuer}`"
                )));
            }
            if dtg.subject() != *subject {
                return Err(mismatch(format!(
                    "does not name the counterparty `{subject}`"
                )));
            }
        }
        Role::Membership { member } => {
            if !matches!(dtg.type_(), DTGCredentialType::Membership)
                || dtg.subject_digest().is_some()
            {
                return Err(mismatch(
                    "is not a community's MembershipCredential grant".into(),
                ));
            }
            if dtg.subject() != *member {
                return Err(mismatch(format!("does not name `{member}` as its member")));
            }
        }
    }
    let valid = dtg.valid_from() <= now && dtg.valid_until().is_none_or(|until| now < until);
    if !valid {
        return Err(mismatch("is outside its validity period".into()));
    }
    Ok(())
}

// ─── Resolution ──────────────────────────────────────────────────────────────

/// The resolver every witness proof is verified with: the VTA's own, or `did:key`/`did:peer`
/// only where it has none.
fn vm_resolver(state: &AppState) -> TrustTaskVmResolver {
    TrustTaskVmResolver::from_optional(state.did_resolver.clone())
}

/// `witnessUnresolvable` unless `witness` resolves (`vta/witness/open/0.2` item 5): nothing it
/// answers could be verified otherwise.
async fn require_resolvable(state: &AppState, witness: &str) -> Result<(), WitnessError> {
    let unresolvable = |why: String| {
        WitnessError::WitnessUnresolvable(format!(
            "the witness `{witness}` could not be resolved, so no answer from it could be \
             verified: {why}. Check the DID, or retry once its DID document is reachable"
        ))
    };
    if witness.starts_with("did:key:") {
        let id = witness.trim_start_matches("did:key:");
        return vta_sdk::did_key::decode_ed25519_public_key_multibase(id)
            .map(|_| ())
            .map_err(|e| unresolvable(e.to_string()));
    }
    if witness.starts_with("did:peer:") {
        use affinidi_did_resolver_traits::{PeerResolver, Resolver};
        let did =
            affinidi_did_common::DID::try_from(witness).map_err(|e| unresolvable(e.to_string()))?;
        return match PeerResolver.resolve(&did) {
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) => Err(unresolvable(e.to_string())),
            None => Err(unresolvable("not a did:peer this build resolves".into())),
        };
    }
    let resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| unresolvable("this agent has no DID resolver".into()))?;
    resolver
        .resolve(witness)
        .await
        .map(|_| ())
        .map_err(|e| unresolvable(e.to_string()))
}

// ─── open ────────────────────────────────────────────────────────────────────

/// What `vta/witness/open` was asked, from the generated payload.
pub struct OpenRequest<'a> {
    pub witness: &'a str,
    pub relationship_did: &'a str,
    pub counterparty_did: &'a str,
    pub relationship_thread_id: &'a str,
    pub relationship_credential_id: &'a str,
    pub membership_credential_id: Option<&'a str>,
    pub member_did: Option<&'a str>,
    pub store_as: Option<&'a str>,
}

/// What `vta/witness/open` answers.
#[derive(Debug)]
pub struct Opened {
    pub session_id: String,
    pub document: Value,
    pub expires_at: DateTime<Utc>,
    /// The relationship key's context, for the audit row.
    pub context_id: Option<String>,
}

/// `vta/witness/open/0.2`, items 1–7, in order.
pub async fn open(
    state: &AppState,
    auth: &AuthClaims,
    req: OpenRequest<'_>,
) -> Result<Opened, WitnessError> {
    let now = Utc::now();
    let witness_config = state.config.read().await.witness.clone();

    // 1. Custody: a key of the relationship DID, and of the member DID when named.
    let relationship_key = party_key(state, auth, req.relationship_did).await?;
    if let Some(member) = req.member_did {
        party_key(state, auth, member).await?;
    }

    // 2. Three different DIDs, and a member DID that is none of them.
    let parties = [req.relationship_did, req.counterparty_did, req.witness];
    if parties[0] == parties[1] || parties[0] == parties[2] || parties[1] == parties[2] {
        return Err(WitnessError::Malformed(
            "relationshipDid, counterpartyDid and witness must be three different DIDs: a party \
             cannot witness its own exchange, nor relate to itself"
                .into(),
        ));
    }
    if req.member_did.is_some_and(|m| parties.contains(&m)) {
        return Err(WitnessError::Malformed(
            "membership.memberDid must be none of relationshipDid, counterpartyDid and witness"
                .into(),
        ));
    }
    if req.member_did.is_some() && req.membership_credential_id.is_none() {
        return Err(WitnessError::Malformed(
            "membership.memberDid names the DID a membership credential names, so it needs \
             membership.credentialId"
                .into(),
        ));
    }

    // 3. The credentials, by handle, fitting their roles.
    let vrc = read_credential(state, auth, req.relationship_credential_id).await?;
    check_role(
        req.relationship_credential_id,
        &vrc.body,
        &Role::Relationship {
            issuer: req.relationship_did,
            subject: req.counterparty_did,
        },
        now,
    )?;
    let object_digest = dtg_credentials::digest_multibase_json(&vrc.body).map_err(|e| {
        WitnessError::CredentialMismatch(format!("the relationship credential: {e}"))
    })?;
    let membership = match req.membership_credential_id {
        Some(id) => {
            let vmc = read_credential(state, auth, id).await?;
            check_role(
                id,
                &vmc.body,
                &Role::Membership {
                    member: req.member_did.unwrap_or(req.relationship_did),
                },
                now,
            )?;
            Some(BoundMembership {
                credential: BoundCredential {
                    id: id.to_string(),
                    digest: vmc.digest,
                },
                member_did: req.member_did.map(str::to_string),
            })
        }
        None => None,
    };

    // A handle already in use would be overwritten, or refused at accept after the witness
    // has seen everything; refuse it before anything is disclosed.
    if let Some(handle) = req.store_as
        && crate::vault::storage::get(&state.vault_ks, handle)
            .await?
            .is_some()
    {
        return Err(WitnessError::Malformed(format!(
            "storeAs `{handle}` names a credential the vault already holds; choose another handle, \
             or omit storeAs and this agent derives one"
        )));
    }

    // 4. The witness resolves.
    require_resolvable(state, req.witness).await?;

    // 5. The session document, signed as the relationship DID.
    let session_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let mut document = json!({
        "id": session_id,
        "type": session_type(),
        "issuer": req.relationship_did,
        "recipient": req.witness,
        "issuedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "threadId": session_id,
        "parentThreadId": req.relationship_thread_id,
        "payload": { "parties": [req.relationship_did, req.counterparty_did] },
    });
    sign_as(
        state,
        auth,
        &relationship_key,
        &mut document,
        ProofPurpose::Authentication,
    )
    .await?;

    // 6. The record, `opened`.
    let expires_at = now + TimeDelta::seconds(witness_config.session_ttl_secs as i64);
    let record = SessionRecord {
        session_id: session_id.clone(),
        context_id: relationship_key.context_id.clone(),
        witness: req.witness.to_string(),
        relationship_did: req.relationship_did.to_string(),
        counterparty_did: req.counterparty_did.to_string(),
        relationship_thread_id: req.relationship_thread_id.to_string(),
        session_document: document.clone(),
        relationship_credential: BoundCredential {
            id: req.relationship_credential_id.to_string(),
            digest: vrc.digest,
        },
        relationship_credential_object_digest: object_digest,
        membership,
        store_as: req.store_as.map(str::to_string),
        expires_at,
    };
    let inserted = state
        .witness_sessions_ks
        .insert_if_absent(session_key(&session_id), &SessionEntry::Opened(record))
        .await?;
    if !inserted {
        return Err(WitnessError::App(AppError::Internal(
            "a fresh session id collided with a stored one".into(),
        )));
    }

    // 7.
    Ok(Opened {
        session_id,
        document,
        expires_at,
        context_id: relationship_key.context_id,
    })
}

// ─── The witness's answers ───────────────────────────────────────────────────

/// A document handed back that is the witness's own answer for this session: checked against
/// the record (conventions §3 item 3). Only [`verify_answer`] makes one.
#[derive(Debug)]
pub struct VerifiedWitnessAnswer {
    document: Value,
}

impl VerifiedWitnessAnswer {
    /// The answer's payload, now attributable to the witness.
    pub fn payload(&self) -> &Value {
        &self.document["payload"]
    }

    /// The document exactly as handed back.
    pub fn document(&self) -> &Value {
        &self.document
    }
}

/// Check `response` against the session before reading anything from it: `expected_type`, the
/// witness as `issuer`, the relationship DID as `recipient`, the session's thread, and a proof
/// that verifies for the witness's DID. Anything else is [`WitnessError::ResponseInvalid`].
pub async fn verify_answer(
    resolver: &TrustTaskVmResolver,
    witness: &str,
    relationship_did: &str,
    session_id: &str,
    expected_type: &str,
    response: &Value,
) -> Result<VerifiedWitnessAnswer, WitnessError> {
    let invalid = |why: &str| {
        WitnessError::ResponseInvalid(format!(
            "the document handed back is not the witness's answer for this session: {why}. Hand \
             back exactly what `{witness}` returned, unaltered; a refusal from the witness ends \
             the session and is not handed back"
        ))
    };
    let str_of = |k: &str| response.get(k).and_then(Value::as_str);
    if str_of("type") != Some(expected_type) {
        return Err(invalid(&format!("its type is not {expected_type}")));
    }
    if str_of("issuer") != Some(witness) {
        return Err(invalid("it is not issued by the session's witness"));
    }
    if str_of("recipient") != Some(relationship_did) {
        return Err(invalid(
            "it is not addressed to the session's relationship DID",
        ));
    }
    if str_of("threadId") != Some(session_id) {
        return Err(invalid("it is not on the session's thread"));
    }
    let signer = verify_trust_task_proof_value(response, resolver)
        .await
        .map_err(|e| invalid(&format!("its proof does not verify ({e})")))?;
    if signer != witness {
        return Err(invalid("it is signed by someone other than the witness"));
    }
    Ok(VerifiedWitnessAnswer {
        document: response.clone(),
    })
}

// ─── present ─────────────────────────────────────────────────────────────────

/// What `vta/witness/present` answers.
#[derive(Debug)]
pub struct Presented {
    pub document: Value,
    pub context_id: Option<String>,
    pub witness: String,
}

/// A presentation by `holder` of `credentials`, bound to `challenge` and `domain`, signed by
/// `key` for `authentication` — the members `vti-witness` reads (`nonce`, `domain`), both
/// covered by the proof.
async fn presentation(
    state: &AppState,
    auth: &AuthClaims,
    key: &PartyKey,
    holder: &str,
    credentials: Vec<Value>,
    challenge: &str,
    domain: &str,
) -> Result<Value, WitnessError> {
    let mut vp = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": holder,
        "verifiableCredential": credentials,
        "nonce": challenge,
        "domain": domain,
    });
    sign_as(state, auth, key, &mut vp, ProofPurpose::Authentication).await?;
    Ok(vp)
}

/// The credential `bound` names, as open checked it: still active and in scope (`notFound`),
/// byte-identical and in its window (`credentialMismatch`).
async fn reread(
    state: &AppState,
    auth: &AuthClaims,
    bound: &BoundCredential,
    now: DateTime<Utc>,
) -> Result<Value, WitnessError> {
    let held = read_credential(state, auth, &bound.id).await?;
    if held.digest != bound.digest {
        return Err(WitnessError::CredentialMismatch(format!(
            "credential `{}` has changed since the session was opened; open a new session to \
             present it as it is now",
            bound.id
        )));
    }
    let dtg = dtg_credentials::DTGCredential::try_from(held.body.clone())
        .map_err(|e| WitnessError::CredentialMismatch(format!("credential `{}`: {e}", bound.id)))?;
    if !(dtg.valid_from() <= now && dtg.valid_until().is_none_or(|until| now < until)) {
        return Err(WitnessError::CredentialMismatch(format!(
            "credential `{}` has left its validity period",
            bound.id
        )));
    }
    Ok(held.body)
}

/// `vta/witness/present/0.2`, items 2–7.
pub async fn present(
    state: &AppState,
    auth: &AuthClaims,
    session_id: &str,
    response: &Value,
) -> Result<Presented, WitnessError> {
    let now = Utc::now();
    // 2. The record, `opened` or `presented`.
    let (entry, raw) = find_session(&state.witness_sessions_ks, auth, session_id, now).await?;
    let record = match entry {
        SessionEntry::Opened(r) | SessionEntry::Presented(r) if opened_at_this_version(&r) => r,
        _ => return Err(WitnessError::SessionUnknown),
    };

    // 3. The witness's own answer for this session — before any of it is read.
    let answer = verify_answer(
        &vm_resolver(state),
        &record.witness,
        &record.relationship_did,
        &record.session_id,
        session_response_type(),
        response,
    )
    .await?;
    let binding: session::v0_2::Response = serde_json::from_value(answer.payload().clone())
        .map_err(|e| {
            WitnessError::ResponseInvalid(format!(
                "the witness's session answer does not carry a challenge and domain: {e}"
            ))
        })?;
    let challenge = binding.challenge.to_string();
    let domain = binding.domain.to_string();

    // Custody, again: the caller's standing is read now, not remembered from open.
    let relationship_key = party_key(state, auth, &record.relationship_did).await?;
    let member_key = match record
        .membership
        .as_ref()
        .and_then(|m| m.member_did.as_deref())
    {
        Some(member) => Some((member.to_string(), party_key(state, auth, member).await?)),
        None => None,
    };

    // 4. The credentials bound at open.
    let vrc = reread(state, auth, &record.relationship_credential, now).await?;
    let vmc = match &record.membership {
        Some(m) => Some(reread(state, auth, &m.credential, now).await?),
        None => None,
    };

    // 5. The presentations.
    let mut relationship_credentials = vec![vrc];
    let mut member_presentation = None;
    match (vmc, member_key) {
        (Some(vmc), Some((member, key))) => {
            member_presentation = Some(
                presentation(state, auth, &key, &member, vec![vmc], &challenge, &domain).await?,
            );
        }
        (Some(vmc), None) => relationship_credentials.push(vmc),
        (None, _) => {}
    }
    let vp = presentation(
        state,
        auth,
        &relationship_key,
        &record.relationship_did,
        relationship_credentials,
        &challenge,
        &domain,
    )
    .await?;

    // 6. The submit document, signed as the relationship DID.
    let mut payload = json!({ "vp": vp });
    if let Some(mp) = member_presentation {
        payload[MEMBER_PRESENTATION] = mp;
    }
    let mut document = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": submit_type(),
        "issuer": record.relationship_did,
        "recipient": record.witness,
        "issuedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "threadId": record.session_id,
        "parentThreadId": record.relationship_thread_id,
        "payload": payload,
    });
    sign_as(
        state,
        auth,
        &relationship_key,
        &mut document,
        ProofPurpose::Authentication,
    )
    .await?;

    // 7. `presented`. Neither presentation nor the document is kept.
    let context_id = record.context_id.clone();
    let witness = record.witness.clone();
    let next = SessionEntry::Presented(record);
    if let Err(lost) = replace_session(&state.witness_sessions_ks, session_id, raw, &next).await {
        // A concurrent present that moved the same record to `presented` is the repeat
        // conventions §5 allows, not a lost session. Anything else is.
        let now_stored = find_session(&state.witness_sessions_ks, auth, session_id, now)
            .await
            .map(|(entry, _)| entry);
        if !matches!(now_stored, Ok(ref entry) if *entry == next) {
            return Err(lost);
        }
    }
    Ok(Presented {
        document,
        context_id,
        witness,
    })
}

// ─── accept ──────────────────────────────────────────────────────────────────

/// A VWC verified against the session that produced it (`vta/witness/accept/0.2` item 4).
/// Only [`verify_outcome`] makes one, and [`accept`] stores nothing else.
#[derive(Debug)]
pub struct VerifiedWitnessOutcome {
    outcome: Value,
    vwc: Value,
    vwc_digest_multibase: String,
}

/// `vwcDigestMultibase` as `witness/session/submit/0.2` defines it: sha2-256 multihash, base58btc,
/// of the RFC 8785 canonicalization of the VWC **whole, proof included**.
fn vwc_digest(vwc: &Value) -> Result<String, AppError> {
    let canonical = serde_json_canonicalizer::to_vec(vwc)
        .map_err(|e| AppError::Internal(format!("canonicalize the VWC: {e}")))?;
    let mut multihash = vec![0x12, 0x20];
    multihash.extend_from_slice(&Sha256::digest(&canonical));
    Ok(multibase::encode(multibase::Base::Base58Btc, multihash))
}

fn digests_match(left: &str, right: &str) -> bool {
    dtg_credentials::digests_match(left, right).unwrap_or(false)
}

/// Item 4: the VWC as a verifier of the evidence would check it. Anything that fails is
/// [`WitnessError::VwcInvalid`].
pub async fn verify_outcome(
    resolver: &TrustTaskVmResolver,
    record: &SessionRecord,
    answer: VerifiedWitnessAnswer,
) -> Result<VerifiedWitnessOutcome, WitnessError> {
    let invalid = |why: String| {
        WitnessError::VwcInvalid(format!(
            "the witness answered, but its credential does not verify against this session: \
             {why}. Nothing was stored"
        ))
    };
    let payload = answer.payload();
    let vwc = payload
        .get("vwc")
        .filter(|v| v.is_object())
        .cloned()
        .ok_or_else(|| invalid("the answer carries no VWC".into()))?;
    let carried = payload
        .get("vwcDigestMultibase")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("the answer carries no vwcDigestMultibase".into()))?
        .to_string();

    // 1. Issued by the session's witness, under its assertionMethod proof.
    let issuer = match vwc.get("issuer") {
        Some(Value::String(s)) => Some(s.as_str()),
        Some(Value::Object(o)) => o.get("id").and_then(Value::as_str),
        _ => None,
    };
    if issuer != Some(record.witness.as_str()) {
        return Err(invalid("it is not issued by the session's witness".into()));
    }
    let signed = verify_proof_set(&vwc, ProofPurpose::AssertionMethod, resolver)
        .await
        .map_err(|e| invalid(format!("its proof does not verify ({e})")))?;
    if signed.signer() != record.witness {
        return Err(invalid("it is not signed by the session's witness".into()));
    }

    // 2. It cites this session document.
    let dtg = dtg_credentials::DTGCredential::try_from(vwc.clone())
        .map_err(|e| invalid(format!("it is not a DTG credential ({e})")))?;
    if dtg.task_context() != Some(record.session_id.as_str()) {
        return Err(invalid("its taskContext names another session".into()));
    }
    if !dtg.cites_task(&record.session_document).unwrap_or(false) {
        return Err(invalid(
            "its taskDigestMultibase is not the digest of the session document".into(),
        ));
    }

    // 3. About the relationship DID, naming the relationship credential presented.
    let subject = vwc.get("credentialSubject");
    let field = |k: &str| subject.and_then(|s| s.get(k)).and_then(Value::as_str);
    if field("id") != Some(record.relationship_did.as_str()) {
        return Err(invalid("its subject is not the relationship DID".into()));
    }
    if field("predicate") != Some(WITNESSED_V1) {
        return Err(invalid(format!("its predicate is not {WITNESSED_V1}")));
    }
    let object = subject
        .and_then(|s| s.get("object"))
        .and_then(|o| o.get("digestMultibase"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !digests_match(object, &record.relationship_credential_object_digest) {
        return Err(invalid(
            "it does not name the relationship credential this session presented".into(),
        ));
    }

    // 4. vwcDigestMultibase over the VWC as received, proof included.
    let recomputed = vwc_digest(&vwc)?;
    if !digests_match(&carried, &recomputed) {
        return Err(invalid(
            "vwcDigestMultibase is not the digest of the VWC".into(),
        ));
    }

    Ok(VerifiedWitnessOutcome {
        outcome: answer.document,
        vwc,
        vwc_digest_multibase: carried,
    })
}

/// What `vta/witness/accept` answers.
#[derive(Debug)]
pub struct Accepted {
    pub credential_id: String,
    pub witness: String,
    pub vwc_digest_multibase: String,
    pub session_document: Value,
    pub outcome: Value,
    pub context_id: Option<String>,
    /// `true` when this answers a repeat of an accepted outcome, storing nothing.
    pub repeated: bool,
}

/// The VWC as a vault entry, in the relationship key's context, with its evidence in the
/// reserved tags.
fn vault_entry(
    id: &str,
    record: &SessionRecord,
    verified: &VerifiedWitnessOutcome,
    now: DateTime<Utc>,
) -> Result<StoredCredential, AppError> {
    let types = match verified.vwc.get("type") {
        Some(Value::Array(ts)) => ts
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(t)) => vec![t.clone()],
        _ => Vec::new(),
    };
    let str_of = |k: &str| {
        verified
            .vwc
            .get(k)
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let mut tags = std::collections::BTreeMap::new();
    tags.insert(
        EVIDENCE_SESSION_TAG.to_string(),
        serde_json::to_string(&record.session_document)
            .map_err(|e| AppError::Internal(format!("encode the session document: {e}")))?,
    );
    tags.insert(
        EVIDENCE_OUTCOME_TAG.to_string(),
        serde_json::to_string(&verified.outcome)
            .map_err(|e| AppError::Internal(format!("encode the outcome: {e}")))?,
    );
    Ok(StoredCredential {
        id: id.to_string(),
        format: CredentialFormat::EddsaJcs2022,
        types,
        schema_id: None,
        community_did: None,
        context_id: record.context_id.clone(),
        subject_did: Some(record.relationship_did.clone()),
        issuer_did: Some(record.witness.clone()),
        purpose: Some(CredentialPurpose::Other("witness".into())),
        status: CredentialStatus::Valid,
        valid_from: str_of("validFrom"),
        valid_until: str_of("validUntil"),
        received_at: now.to_rfc3339(),
        source: Some(format!("witness/session {}", record.session_id)),
        tags,
        body: serde_json::to_vec(&verified.vwc)
            .map_err(|e| AppError::Internal(format!("encode the VWC: {e}")))?,
        lifecycle: vti_common::vault::VaultStatus::Active,
        archived_at: None,
        deleted_at: None,
        grace_until: None,
    })
}

/// `vta/witness/accept/0.2`, items 2–6.
pub async fn accept(
    state: &AppState,
    auth: &AuthClaims,
    session_id: &str,
    response: &Value,
) -> Result<Accepted, WitnessError> {
    let now = Utc::now();
    let resolver = vm_resolver(state);
    // 2. The record: `presented`, or an accepted one answering the same outcome again.
    let (entry, raw) = find_session(&state.witness_sessions_ks, auth, session_id, now).await?;
    let record = match entry {
        SessionEntry::Presented(r) if opened_at_this_version(&r) => r,
        SessionEntry::Opened(_) | SessionEntry::Presented(_) => {
            return Err(WitnessError::SessionUnknown);
        }
        SessionEntry::Accepted(stub) => {
            return accepted_again(state, &resolver, stub, response).await;
        }
    };

    // 3. The witness's own answer for this session.
    let answer = verify_answer(
        &resolver,
        &record.witness,
        &record.relationship_did,
        &record.session_id,
        submit_response_type(),
        response,
    )
    .await?;
    // 4. The VWC against the session.
    let verified = verify_outcome(&resolver, &record, answer).await?;

    // 5. Stored with its evidence, under `storeAs` or a handle derived from the VWC.
    let credential_id = record
        .store_as
        .clone()
        .or_else(|| {
            verified
                .vwc
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4()));
    let entry = vault_entry(&credential_id, &record, &verified, now)?;
    match crate::vault::storage::get(&state.vault_ks, &credential_id).await? {
        // A retry after a crash between this write and the record's: the same VWC again.
        Some(existing) if existing.body == entry.body => {}
        Some(_) => {
            return Err(WitnessError::App(AppError::Conflict(format!(
                "the vault already holds a different credential under `{credential_id}`, so the \
                 VWC was not stored; nothing was overwritten"
            ))));
        }
        None => {}
    }
    crate::vault::storage::put(&state.vault_ks, &entry).await?;

    // 6. `accepted`, keeping only the stub.
    let stub = AcceptedStub {
        session_id: record.session_id.clone(),
        context_id: record.context_id.clone(),
        witness: record.witness.clone(),
        relationship_did: record.relationship_did.clone(),
        credential_id: credential_id.clone(),
        vwc_digest_multibase: verified.vwc_digest_multibase.clone(),
        expires_at: record.expires_at,
    };
    replace_session(
        &state.witness_sessions_ks,
        session_id,
        raw,
        &SessionEntry::Accepted(stub),
    )
    .await?;
    Ok(Accepted {
        credential_id,
        witness: record.witness,
        vwc_digest_multibase: verified.vwc_digest_multibase,
        session_document: record.session_document,
        outcome: verified.outcome,
        context_id: record.context_id,
        repeated: false,
    })
}

/// Conventions §5: the same outcome handed back for an accepted session is answered again,
/// storing nothing. A different one is `sessionUnknown`.
async fn accepted_again(
    state: &AppState,
    resolver: &TrustTaskVmResolver,
    stub: AcceptedStub,
    response: &Value,
) -> Result<Accepted, WitnessError> {
    let answer = verify_answer(
        resolver,
        &stub.witness,
        &stub.relationship_did,
        &stub.session_id,
        submit_response_type(),
        response,
    )
    .await
    .map_err(|_| WitnessError::SessionUnknown)?;
    let carried = answer
        .payload()
        .get("vwcDigestMultibase")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !digests_match(carried, &stub.vwc_digest_multibase) {
        return Err(WitnessError::SessionUnknown);
    }
    let stored = crate::vault::storage::get(&state.vault_ks, &stub.credential_id)
        .await?
        .ok_or(WitnessError::SessionUnknown)?;
    let session_document = stored
        .tags
        .get(EVIDENCE_SESSION_TAG)
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .ok_or(WitnessError::SessionUnknown)?;
    Ok(Accepted {
        credential_id: stub.credential_id,
        witness: stub.witness,
        vwc_digest_multibase: stub.vwc_digest_multibase,
        session_document,
        outcome: answer.document,
        context_id: stub.context_id,
        repeated: true,
    })
}

// ─── list ────────────────────────────────────────────────────────────────────

/// The most entries one page of `vta/witness/list` holds (its schema's `maximum`), and the
/// default when the caller names none.
pub const LIST_MAX_PAGE: usize = 100;

/// The cursor's version prefix. The cursor is opaque to the caller (`vta/witness/list/0.1`,
/// producer conformance): the position after which the next page starts, `acceptedAt` then
/// `credentialId`, base64url-encoded behind this prefix so a changed encoding is refused as
/// `cursorInvalid` rather than misread.
const LIST_CURSOR_PREFIX: &str = "w1.";

/// What `vta/witness/list` asks for.
#[derive(Debug, Default)]
pub struct ListRequest<'a> {
    pub relationship_did: Option<&'a str>,
    pub witness: Option<&'a str>,
    pub page_size: Option<usize>,
    pub cursor: Option<&'a str>,
}

/// One stored VWC with its evidence, as `vta/witness/accept` stored it.
#[derive(Debug, Clone)]
pub struct StoredWitnessing {
    pub credential_id: String,
    pub witness: String,
    pub relationship_did: String,
    pub vwc_digest_multibase: String,
    pub accepted_at: String,
    /// The `witness/session` document, exactly as stored.
    pub session: Value,
    /// The witness's `witness/session/submit` `#response`, exactly as stored.
    pub outcome: Value,
}

/// A page of [`list`].
#[derive(Debug)]
pub struct Listed {
    pub witnessings: Vec<StoredWitnessing>,
    pub truncated: bool,
    pub cursor: Option<String>,
}

/// Why `vta/witness/list` refused: only a cursor it cannot honour. Every other condition —
/// a DID it does not hold, one held where the caller cannot act — is an empty page.
#[derive(Debug)]
#[non_exhaustive]
pub enum ListError {
    CursorInvalid,
    App(AppError),
}

impl From<AppError> for ListError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

fn encode_cursor(accepted_at: &str, credential_id: &str) -> String {
    use base64::Engine as _;
    let raw = format!("{accepted_at}\n{credential_id}");
    format!(
        "{LIST_CURSOR_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    )
}

fn decode_cursor(cursor: &str) -> Option<(String, String)> {
    use base64::Engine as _;
    let body = cursor.strip_prefix(LIST_CURSOR_PREFIX)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .ok()?;
    let raw = String::from_utf8(raw).ok()?;
    let (at, id) = raw.split_once('\n')?;
    DateTime::parse_from_rfc3339(at).ok()?;
    (!id.is_empty()).then(|| (at.to_string(), id.to_string()))
}

/// The witnessing a vault entry records, if it is one `vta/witness/accept` stored — under any
/// version — with both evidence documents. Anything else in the vault is not listed.
fn stored_witnessing(c: &StoredCredential) -> Option<StoredWitnessing> {
    if c.purpose != Some(CredentialPurpose::Other("witness".into())) {
        return None;
    }
    let session: Value = serde_json::from_str(c.tags.get(EVIDENCE_SESSION_TAG)?).ok()?;
    let outcome: Value = serde_json::from_str(c.tags.get(EVIDENCE_OUTCOME_TAG)?).ok()?;
    let vwc_digest_multibase = outcome
        .get("payload")
        .and_then(|p| p.get("vwcDigestMultibase"))
        .and_then(Value::as_str)?
        .to_string();
    Some(StoredWitnessing {
        credential_id: c.id.clone(),
        witness: c.issuer_did.clone()?,
        relationship_did: c.subject_did.clone()?,
        vwc_digest_multibase,
        accepted_at: c.received_at.clone(),
        session,
        outcome,
    })
}

/// `vta/witness/list/0.1`: the VWCs `vta/witness/accept` stored, active, in a context the caller
/// may act in, matching every filter, oldest first.
///
/// A filter naming a DID this agent does not hold, or holds where the caller cannot act, simply
/// matches nothing: the answer is an empty page either way, so it reveals nothing about DIDs the
/// caller cannot see. The evidence is returned as stored and never rebuilt or re-signed.
pub async fn list(
    state: &AppState,
    auth: &AuthClaims,
    req: ListRequest<'_>,
) -> Result<Listed, ListError> {
    let after = match req.cursor {
        Some(c) => Some(decode_cursor(c).ok_or(ListError::CursorInvalid)?),
        None => None,
    };
    let limit = req
        .page_size
        .unwrap_or(LIST_MAX_PAGE)
        .clamp(1, LIST_MAX_PAGE);

    // The vault has no enumeration primitive; the witness purpose is the index term every
    // stored VWC carries (or its issuer, which narrows further when filtered on).
    let candidates = match req.witness {
        Some(w) => {
            crate::vault::storage::find_by_index(
                &state.vault_ks,
                crate::vault::model::IndexField::IssuerDid,
                w,
            )
            .await?
        }
        None => {
            crate::vault::storage::find_by_index(
                &state.vault_ks,
                crate::vault::model::IndexField::Purpose,
                "witness",
            )
            .await?
        }
    };

    let mut rows: Vec<(DateTime<Utc>, StoredWitnessing)> = candidates
        .iter()
        .filter(|c| c.lifecycle == vti_common::vault::VaultStatus::Active)
        .filter(|c| in_scope(auth, c.context_id.as_deref()))
        .filter_map(stored_witnessing)
        .filter(|w| req.relationship_did.is_none_or(|r| w.relationship_did == r))
        .filter(|w| req.witness.is_none_or(|x| w.witness == x))
        .filter_map(|w| {
            DateTime::parse_from_rfc3339(&w.accepted_at)
                .ok()
                .map(|t| (t.with_timezone(&Utc), w))
        })
        .collect();
    rows.sort_by(|(a, x), (b, y)| a.cmp(b).then_with(|| x.credential_id.cmp(&y.credential_id)));
    if let Some((at, id)) = &after {
        let at = DateTime::parse_from_rfc3339(at)
            .map_err(|_| ListError::CursorInvalid)?
            .with_timezone(&Utc);
        rows.retain(|(t, w)| (*t, w.credential_id.as_str()) > (at, id.as_str()));
    }

    let truncated = rows.len() > limit;
    rows.truncate(limit);
    let cursor = truncated
        .then(|| rows.last())
        .flatten()
        .map(|(_, w)| encode_cursor(&w.accepted_at, &w.credential_id));
    Ok(Listed {
        witnessings: rows.into_iter().map(|(_, w)| w).collect(),
        truncated,
        cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vwc_digest_covers_the_proof_and_ignores_member_order() {
        let a = json!({ "a": 1, "proof": { "proofValue": "z1" } });
        let b = json!({ "a": 1, "proof": { "proofValue": "z2" } });
        let reordered = json!({ "proof": { "proofValue": "z1" }, "a": 1 });
        assert_ne!(vwc_digest(&a).unwrap(), vwc_digest(&b).unwrap());
        assert_eq!(vwc_digest(&a).unwrap(), vwc_digest(&reordered).unwrap());
    }

    /// The digest is the one `vti-witness` puts on the wire, so an honest witness's answer is
    /// never refused for a disagreement over the computation.
    #[test]
    fn the_vwc_digest_is_the_witness_s() {
        let vwc = json!({ "issuer": "did:example:w", "proof": { "proofValue": "z9" } });
        assert_eq!(
            vwc_digest(&vwc).unwrap(),
            vti_witness::witness::vwc_digest_multibase(&vwc).unwrap()
        );
    }

    #[tokio::test]
    async fn the_sweeper_removes_expired_sessions_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::WITNESS_SESSIONS).unwrap();
        let now = Utc::now();
        let stub = |id: &str, expires_at| {
            SessionEntry::Accepted(AcceptedStub {
                session_id: id.into(),
                context_id: Some("c".into()),
                witness: "did:example:w".into(),
                relationship_did: "did:example:r".into(),
                credential_id: "vwc".into(),
                vwc_digest_multibase: "z".into(),
                expires_at,
            })
        };
        ks.insert(
            session_key("old"),
            &stub("old", now - TimeDelta::seconds(1)),
        )
        .await
        .unwrap();
        ks.insert(
            session_key("new"),
            &stub("new", now + TimeDelta::minutes(5)),
        )
        .await
        .unwrap();
        assert_eq!(sweep_expired(&ks, now).await.unwrap(), 1);
        assert!(ks.get_raw(session_key("old")).await.unwrap().is_none());
        assert!(ks.get_raw(session_key("new")).await.unwrap().is_some());
    }
}
