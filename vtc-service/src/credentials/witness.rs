//! Verifying the digest binding on a Verifiable Witness Credential.
//!
//! A VWC is a DTG Verifiable Statement Credential (`StatementCredential`)
//! under the predicate `https://registry.trustoverip.org/dtg/vsc/witnessed/1`
//! (`dtg_credentials::WITNESSED_V1`; witness/session/submit/0.1, "The
//! credential delivered"). It is recognised by that predicate, never by a type
//! string: DTG Credentials no longer defines a witness credential type.
//!
//! A VWC asserts that its issuer witnessed *one specific* relationship being
//! issued. The only thing that says *which* is
//! `credentialSubject.object.digestMultibase`: a digest over the witnessed edge
//! credential, in the form DTG Credentials
//! §Digest Encoding specifies — SHA-256 over the RFC 8785 canonicalization of
//! the credential **with its top-level `proof` removed**, wrapped as a
//! `sha2-256` multihash and multibase-encoded.
//!
//! Until this module existed, nothing recomputed it. The ceremony engine took
//! a witness credential as a policy fact carrying trusted-issuer, validity and
//! holder-binding predicates, and reasoned to a decision on the *assertion*
//! that a witness credential was present — with no code path that could have
//! established which edge, if any, it witnessed. DTG Credentials Security
//! Considerations 6 (*Digest integrity*) is explicit that without recomputing
//! the digest against the referenced edge credential, a VWC is not evidence of
//! which edge was witnessed.
//!
//! ## One definition of the digest, and it is the library's
//!
//! The recompute and the decode both go through `dtg-credentials`
//! (`digest_multibase_json`, `decode_digest_multibase`), the implementation
//! `DTGCredential::new_witnessed_vsc` uses to produce the value. A first
//! version of this module digested with
//! [`crate::credentials::ingress::digest_multibase`]
//! — the Trust Task framework digest, same encoding, but over the document
//! *proof included* — and read a member name the library never wrote. Both
//! compile, both produce plausible strings, and a VWC built by the library to
//! the specification came back `Absent`. The round-trip test at the bottom of
//! this file pins the two implementations together.
//!
//! ## The subject–object rule
//!
//! The `witnessed/1` profile binds each VWC to one direction of the edge:
//! `credentialSubject.id` MUST be the `issuer` of the credential the digest
//! names. A digest that matches a stored edge whose issuer is someone else is
//! [`WitnessBinding::SubjectMismatch`], not `Bound` — otherwise a VWC attesting
//! that Bob issued a VRC could be presented as evidence about Alice's.
//!
//! ## Recomputed, not compared to a stored digest
//!
//! [`resolve_binding`] recomputes the digest from each stored VRC body rather
//! than comparing against the `vrc_digest_multibase` column. The column is the
//! right thing to *index* on and the wrong thing to *verify* against: it holds
//! the framework digest used to bind a publish authorization, which covers the
//! proof and so is a different value from the one a witness asserts. Trusting
//! it would make this check assert that two stored strings agree, which is not
//! the claim being made.
//!
//! ## Decoded bytes, not encoded strings
//!
//! §Digest Encoding forbids string comparison: a verifier "decodes the
//! Multibase value, decodes the Multihash to recover the algorithm identifier
//! and the raw digest, and compares those". This is not pedantry: multibase is
//! a *family* of encodings, and the same 34-byte multihash is `z...` in
//! base58btc and `f...` in base16. Two conforming implementations can assert
//! the identical digest in strings that are not equal, and a string comparison
//! rejects a valid witness. It fails in the safe direction, which is exactly
//! why it would survive a long time undetected.

use serde_json::Value as JsonValue;
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use serde::Deserialize;
use vti_common::auth::TrustTaskVmResolver;

use crate::credentials::ingress::dtg_credential_digest_multibase;
use crate::credentials::trusted_witnesses::TrustedWitnesses;
use crate::relationships::Relationship;

/// The host's verdict on a VWC, resolved before policy runs: whether its
/// witness is one this community trusts, whether the witnessing it cites is
/// shown to have completed, and which edge its digest names.
///
/// Follows the same division of labour as `issuer_trusted` and the resolved
/// `CredentialStatus`: the host does the work that needs keys, storage or a
/// network, and the policy branches on a settled state. A policy that had to
/// recompute a digest itself would be a policy doing cryptography.
///
/// The variants distinguish four genuinely different situations, because
/// collapsing them loses the distinction a verifier most needs — between a
/// credential that witnessed *something this service cannot see* and one that
/// witnessed *nothing*.
///
/// The checks run in a fixed order, and each later state implies every earlier
/// check passed ([`assess`]):
///
/// 1. the issuer is a trusted witness, else [`Self::UntrustedWitness`];
/// 2. the witnessing it cites completed, shown by outcome evidence that pairs
///    with it, else [`Self::NoOutcomeEvidence`] or [`Self::OutcomeInvalid`];
/// 3. its digest names an edge — [`Self::Bound`], [`Self::SubjectMismatch`],
///    [`Self::Unresolved`], [`Self::Absent`] or [`Self::Malformed`].
///
/// So a policy that accepts `unresolved` (an edge held elsewhere) still accepts
/// only a trusted witness whose session completed: no policy can admit a VWC the
/// host refused at steps 1–2 (VTI-VTC-022).
///
/// Reaches policy under the snake_case key `witness_binding`, as
/// `{ "state": "bound", "relationship_id": "<uuid>" }` or
/// `{ "state": "subjectMismatch", "relationship_id": "<uuid>" }` or
/// `{ "state": "untrustedWitness" | "noOutcomeEvidence" | "outcomeInvalid" |
/// "unresolved" | "absent" | "malformed" }` — on the ceremony `Credential`
/// fact and on each `witnessed/1` statement of the personhood projection alike
/// ([`annotate_vp_claims`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum WitnessBinding {
    /// The asserted digest decodes, and a stored relationship's VRC recomputes
    /// to the same bytes. This is the only variant that establishes *which*
    /// edge was witnessed, so it is the only one carrying an id.
    Bound { relationship_id: Uuid },
    /// The digest names a stored edge, but `credentialSubject.id` is not that
    /// edge's issuer, so the `witnessed/1` subject–object rule fails: the
    /// credential attests somebody else issuing it. Carries the edge so an
    /// operator can see which one was misattributed; never evidence.
    SubjectMismatch { relationship_id: Uuid },
    /// The digest decodes and is well-formed, but no relationship this service
    /// holds recomputes to it.
    ///
    /// Not an accusation. A witness may legitimately attest an edge published
    /// on another VTC, and a verifier that treats this as forgery refuses
    /// honest evidence. It is surfaced so the policy can decide, which is the
    /// same reason `CredentialStatus::Unknown` exists rather than a guess.
    Unresolved,
    /// The credential asserts no `credentialSubject.object.digestMultibase` at
    /// all. A VWC without one witnesses nothing in particular.
    Absent,
    /// A digest is present but is not a decodable multibase multihash, or does
    /// not name `sha2-256`. Distinguished from [`Self::Unresolved`] because
    /// this one cannot be explained by an honest edge held elsewhere — and
    /// §Digest Encoding requires a digest naming an algorithm the verifier does
    /// not accept to be *rejected*, "rather than treating it as a mismatch".
    Malformed,
    /// The issuer is not on this community's list of trusted witnesses
    /// ([`crate::credentials::trusted_witnesses`]). Nothing else is checked:
    /// whoever issued it, it counts for nothing here. The default list is
    /// empty, so this is every VWC until a community names a witness.
    UntrustedWitness,
    /// No outcome evidence for the witnessing session this VWC cites travelled
    /// with it. VTI-CMP-022/023: a credential citing an exchange is not evidence
    /// that the exchange completed unless the relying party holds the outcome
    /// evidence — the `witness/session` document and the witness's
    /// `witness/session/submit#response` — and a VWC verifies in full for a
    /// session that was cancelled or never completed.
    NoOutcomeEvidence,
    /// Outcome evidence for the cited session travelled with the VWC but does
    /// not pair with it under the four checks of the Trust Task framework's
    /// *Evidence That a Cited Exchange Completed*, or the response does not
    /// carry this VWC. The reason is logged, not exposed to policy.
    OutcomeInvalid,
}

impl WitnessBinding {
    /// Whether this binding establishes which edge was witnessed. The one
    /// predicate a policy needs in the common case.
    pub fn is_bound(&self) -> bool {
        matches!(self, Self::Bound { .. })
    }
}

/// Length of a `sha2-256` digest. `decode_digest_multibase` checks that the
/// multihash's declared length matches the bytes it carries; this checks that
/// the length is the one `sha2-256` produces, so a truncated digest is
/// malformed rather than a well-formed value that merely matches nothing.
const SHA2_256_LEN: usize = 32;

/// Decode a multibase-encoded `sha2-256` multihash to its raw digest bytes.
///
/// Rejects anything that is not the digest DTG Credentials names. A digest of
/// a different length, or one announcing a different hash function, is not a
/// weaker version of this claim — it is a different claim, and accepting it
/// would let the algorithm be chosen by the party being checked.
fn decode_sha256_multihash(encoded: &str) -> Option<Vec<u8>> {
    let (_algorithm, raw) = dtg_credentials::decode_digest_multibase(encoded).ok()?;
    (raw.len() == SHA2_256_LEN).then_some(raw)
}

/// Whether two multibase digests denote the same bytes, regardless of the base
/// each was encoded in.
///
/// The whole point of the function: decode both sides, then compare. `a == b`
/// on the strings answers a different question.
pub fn digests_match(asserted: &str, recomputed: &str) -> bool {
    match (
        decode_sha256_multihash(asserted),
        decode_sha256_multihash(recomputed),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The members of a statement's subject: under `credentialSubject` (a DI VC,
/// where `claims` is the whole credential) or at the top level (an SD-JWT-VC,
/// where `claims` is already the subject). Both shapes reach the ceremony
/// `Credential` fact through the same field, so both are read here rather
/// than at one call site. `credentialSubject` wins when both are present,
/// because that is the issuer-signed location.
fn statement_subject(claims: &JsonValue) -> &JsonValue {
    match claims.get("credentialSubject") {
        Some(subject) if subject.is_object() => subject,
        _ => claims,
    }
}

/// Read the asserted digest out of a credential's claims:
/// `object.digestMultibase` of the statement subject, the only object kind
/// `witnessed/1` permits.
fn asserted_digest(claims: &JsonValue) -> Option<&str> {
    statement_subject(claims)
        .get("object")
        .and_then(|object| object.get("digestMultibase"))
        .and_then(JsonValue::as_str)
}

/// `credentialSubject.id` of the statement: the party the witness says issued
/// the witnessed credential.
fn asserted_issuer(claims: &JsonValue) -> Option<&str> {
    statement_subject(claims)
        .get("id")
        .and_then(JsonValue::as_str)
}

/// Resolve a presented VWC's digest binding against the relationships this
/// service holds.
///
/// Walks the primary keyspace the way `find_by_hash` does, and for the same
/// reason: there is no digest-keyed secondary index yet. The scan cost is the
/// same one idempotent publish already pays, and it buys the property that
/// matters — every candidate is compared by *recomputing* from its stored VRC,
/// so the answer does not depend on a column written for a different purpose.
pub async fn resolve_binding(
    relationships_ks: &KeyspaceHandle,
    claims: &JsonValue,
) -> Result<WitnessBinding, AppError> {
    let Some(asserted) = asserted_digest(claims) else {
        return Ok(WitnessBinding::Absent);
    };
    if decode_sha256_multihash(asserted).is_none() {
        return Ok(WitnessBinding::Malformed);
    }
    for rel in crate::relationships::storage::list_all(relationships_ks).await? {
        if recomputes_to(&rel, asserted) {
            // `witnessed/1`: the subject is the issuer of the witnessed edge.
            return Ok(
                if asserted_issuer(claims) == Some(rel.issuer_did.as_str()) {
                    WitnessBinding::Bound {
                        relationship_id: rel.id,
                    }
                } else {
                    WitnessBinding::SubjectMismatch {
                        relationship_id: rel.id,
                    }
                },
            );
        }
    }
    Ok(WitnessBinding::Unresolved)
}

/// Whether a credential is a `witnessed/1` statement: `type` includes
/// `StatementCredential` and the subject's `predicate` is
/// [`dtg_credentials::WITNESSED_V1`], compared byte for byte.
///
/// Classified by predicate, never by a type string — DTG Credentials has no
/// witness type. Keyed off the predicate rather than the presence of a digest
/// member: a statement that should carry one and does not is exactly the case
/// worth surfacing as [`WitnessBinding::Absent`], and keying off the member
/// would silently classify it as "not a witness" instead. `type` may be a
/// string or an array, as W3C VCDM allows; an SD-JWT-VC projection carries no
/// `type` beside its claims, so the predicate alone decides there.
pub fn is_witness_statement(credential: &JsonValue) -> bool {
    let typed_as_statement = match credential.get("type") {
        Some(JsonValue::String(t)) => t == STATEMENT_TYPE,
        Some(JsonValue::Array(types)) => types.iter().any(|t| t.as_str() == Some(STATEMENT_TYPE)),
        None => credential.get("credentialSubject").is_none(),
        _ => false,
    };
    typed_as_statement
        && statement_subject(credential)
            .get("predicate")
            .and_then(JsonValue::as_str)
            == Some(dtg_credentials::WITNESSED_V1)
}

const STATEMENT_TYPE: &str = vta_sdk::protocols::members::STATEMENT_CREDENTIAL_TYPE;

/// The key a binding verdict is written under on a projected credential. Shared
/// with the ceremony `Credential` fact, which serializes its field under the
/// same name, so one policy idiom reads both.
pub const WITNESS_BINDING_KEY: &str = "witness_binding";

/// Attach the host's [`WitnessBinding`] verdict to every `witnessed/1`
/// statement in a `vp_claims` projection
/// (`crate::policy::extract::extract_vp_claims`) of `presentation`.
///
/// The personhood `assert` path hands policy this projection rather than the
/// ceremony facts, and before this existed it carried no binding verdict at
/// all — so the default `personhood.rego` could only check that a
/// witness credential had a non-empty issuer, which says nothing about which
/// edge, if any, was witnessed. This puts the same verdict the ceremony path
/// computes onto the projection, and the policy branches on it the same way.
///
/// The verdict is assessed over the credential **as presented** — the
/// projection drops `taskContext` and `taskDigestMultibase`, which the outcome
/// evidence pairs on — taking the presentation's object credentials in order,
/// which is the order the projection keeps. A projection that does not line up
/// with `presentation` is assessed from its own entries, which carry no
/// citation and so pair with no evidence: the restrictive reading.
///
/// The key is **host-owned**: it is written on every witness entry and
/// removed from every other one, so nothing a presenter put in the VP can
/// stand in for the verdict. (`extract_vp_claims` does not copy the member
/// either; this does not rely on that.)
///
/// A storage failure resolves to [`WitnessBinding::Unresolved`], the same
/// choice the join path makes: one unreadable keyspace must not decide the
/// assertion, and "could not find the edge" is the honest answer. The policy
/// still sees an unbound witness.
pub async fn annotate_vp_claims(
    ctx: &WitnessContext<'_>,
    presentation: &JsonValue,
    vp_claims: &mut JsonValue,
) {
    let originals: Vec<JsonValue> = presentation
        .get("verifiableCredential")
        .and_then(JsonValue::as_array)
        .map(|vcs| vcs.iter().filter(|v| v.is_object()).cloned().collect())
        .unwrap_or_default();
    let Some(credentials) = vp_claims
        .get_mut("credentials")
        .and_then(JsonValue::as_array_mut)
    else {
        return;
    };
    let aligned = originals.len() == credentials.len();
    for (n, credential) in credentials.iter_mut().enumerate() {
        let is_witness = is_witness_statement(credential);
        let Some(entry) = credential.as_object_mut() else {
            continue;
        };
        if !is_witness {
            entry.remove(WITNESS_BINDING_KEY);
            continue;
        }
        entry.remove(WITNESS_BINDING_KEY);
        let snapshot = match originals.get(n).filter(|_| aligned) {
            Some(original) => original.clone(),
            None => JsonValue::Object(entry.clone()),
        };
        let issuer = credential_issuer(&snapshot).unwrap_or_default().to_string();
        let binding = assess_or_unresolved(ctx, &issuer, &snapshot).await;
        entry.insert(
            WITNESS_BINDING_KEY.into(),
            serde_json::to_value(&binding).expect("WitnessBinding serializes"),
        );
    }
}

/// A credential's `issuer`, as a string or as an object's `id`.
pub fn credential_issuer(credential: &JsonValue) -> Option<&str> {
    match credential.get("issuer")? {
        JsonValue::String(s) => Some(s),
        JsonValue::Object(o) => o.get("id").and_then(JsonValue::as_str),
        _ => None,
    }
}

// ─── trust, completion and binding, in one verdict ───────────────────────────

/// Everything the host needs to assess a VWC: the edges it holds, the
/// witnesses it trusts, the outcome evidence that travelled with the
/// presentation, and a resolver for the witness's DID.
pub struct WitnessContext<'a> {
    pub relationships_ks: &'a KeyspaceHandle,
    pub trusted: &'a TrustedWitnesses,
    pub evidence: &'a [OutcomeEvidence],
    pub resolver: &'a TrustTaskVmResolver,
}

/// Assess one `witnessed/1` statement issued by `issuer`. `credential` is the
/// credential as presented — the whole VWC where the path has it, which the
/// outcome evidence pairs on. The order of the checks is [`WitnessBinding`]'s.
pub async fn assess(
    ctx: &WitnessContext<'_>,
    issuer: &str,
    credential: &JsonValue,
) -> Result<WitnessBinding, AppError> {
    if !ctx.trusted.contains(issuer) {
        return Ok(WitnessBinding::UntrustedWitness);
    }
    match pair_outcome(ctx.evidence, issuer, credential, ctx.resolver).await {
        Pairing::Paired => {}
        Pairing::Missing => return Ok(WitnessBinding::NoOutcomeEvidence),
        Pairing::Invalid(reason) => {
            tracing::warn!(
                witness = %issuer,
                %reason,
                "a VWC's outcome evidence does not pair with it; it counts for nothing"
            );
            return Ok(WitnessBinding::OutcomeInvalid);
        }
    }
    resolve_binding(ctx.relationships_ks, credential).await
}

/// [`assess`], with a storage failure read as [`WitnessBinding::Unresolved`]:
/// one unreadable keyspace must not decide a ceremony, and "could not find the
/// edge" is the honest answer. Only the digest scan reads storage, so the
/// trust and completion checks have already passed when this happens.
pub async fn assess_or_unresolved(
    ctx: &WitnessContext<'_>,
    issuer: &str,
    credential: &JsonValue,
) -> WitnessBinding {
    assess(ctx, issuer, credential).await.unwrap_or_else(|e| {
        tracing::warn!(error = %e, %issuer, "could not resolve witness digest binding");
        WitnessBinding::Unresolved
    })
}

// ─── outcome evidence ────────────────────────────────────────────────────────

/// The vendor-extension namespace a presentation's outcome evidence travels
/// in — the same one the witness's member link uses
/// (`docs/05-design-notes/witness-host-service.md` §3.3a).
pub const OUTCOME_EVIDENCE_EXT: &str = "org.openvtc.witness";

/// The member of [`OUTCOME_EVIDENCE_EXT`] that carries it: an array of
/// [`OutcomeEvidence`], one per VWC presented.
pub const OUTCOME_EVIDENCE: &str = "outcomeEvidence";

/// The most outcome-evidence entries one presentation may carry.
pub const MAX_OUTCOME_EVIDENCE: usize = 16;

/// Outcome evidence for one witnessing session (Trust Task framework,
/// *Evidence That a Cited Exchange Completed*): the initiating
/// `witness/session/0.1` document and the terminal
/// `witness/session/submit/0.1#response`, both exactly as received. The shape
/// `vta/witness/accept/0.1` answers in its `evidence` member, so a client hands
/// on what its VTA gave it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeEvidence {
    pub session: JsonValue,
    pub outcome: JsonValue,
}

/// Read the outcome evidence out of a payload's `ext`, refusing a malformed
/// carriage rather than ignoring it.
///
/// `witness/session/submit`'s evidence has no member of its own in any VTC
/// task, so it rides the payload's vendor extension, exactly as the member link
/// rides the submit payload's: `ext["org.openvtc.witness"].outcomeEvidence`.
/// The namespace is closed — a member this service does not read is refused —
/// so it can be replaced cleanly when the carriage is standardised.
pub fn outcome_evidence_from_ext(
    ext: Option<&JsonValue>,
) -> Result<Vec<OutcomeEvidence>, AppError> {
    let Some(ns) = ext.and_then(|e| e.get(OUTCOME_EVIDENCE_EXT)) else {
        return Ok(Vec::new());
    };
    let ns = ns.as_object().ok_or_else(|| {
        AppError::Validation(format!("ext[\"{OUTCOME_EVIDENCE_EXT}\"] must be an object"))
    })?;
    if let Some(other) = ns.keys().find(|k| k.as_str() != OUTCOME_EVIDENCE) {
        return Err(AppError::Validation(format!(
            "ext[\"{OUTCOME_EVIDENCE_EXT}\"].{other} is not a member this community reads"
        )));
    }
    let Some(list) = ns.get(OUTCOME_EVIDENCE) else {
        return Ok(Vec::new());
    };
    let evidence: Vec<OutcomeEvidence> = serde_json::from_value(list.clone()).map_err(|e| {
        AppError::Validation(format!(
            "ext[\"{OUTCOME_EVIDENCE_EXT}\"].{OUTCOME_EVIDENCE} must be an array of \
             {{ \"session\", \"outcome\" }} objects: {e}"
        ))
    })?;
    if evidence.len() > MAX_OUTCOME_EVIDENCE {
        return Err(AppError::Validation(format!(
            "{} outcome-evidence entries; at most {MAX_OUTCOME_EVIDENCE} may travel with one \
             presentation",
            evidence.len()
        )));
    }
    Ok(evidence)
}

/// Whether outcome evidence pairs with a VWC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pairing {
    /// One entry pairs under every check.
    Paired,
    /// No entry names the session the VWC cites.
    Missing,
    /// An entry names it and fails a check; the reason is for the log.
    Invalid(String),
}

fn session_type() -> &'static str {
    <trust_tasks_rs::specs::witness::session::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI
}

fn submit_response_type() -> &'static str {
    <trust_tasks_rs::specs::witness::session::submit::v0_1::Response as trust_tasks_rs::Payload>::TYPE_URI
}

/// Pair a VWC issued by `issuer` with the outcome evidence of the session it
/// cites (its `taskContext`). An entry for another session is not this VWC's
/// evidence and is passed over.
pub async fn pair_outcome(
    evidence: &[OutcomeEvidence],
    issuer: &str,
    vwc: &JsonValue,
    resolver: &TrustTaskVmResolver,
) -> Pairing {
    let Some(cited) = vwc.get("taskContext").and_then(JsonValue::as_str) else {
        return Pairing::Missing;
    };
    let mut first_failure = None;
    for entry in evidence
        .iter()
        .filter(|e| e.session.get("id").and_then(JsonValue::as_str) == Some(cited))
    {
        match check_pair(entry, issuer, vwc, resolver).await {
            Ok(()) => return Pairing::Paired,
            Err(reason) => {
                first_failure.get_or_insert(reason);
            }
        }
    }
    match first_failure {
        Some(reason) => Pairing::Invalid(reason),
        None => Pairing::Missing,
    }
}

/// A string member of a document.
fn str_at<'a>(doc: &'a JsonValue, key: &str) -> Option<&'a str> {
    doc.get(key).and_then(JsonValue::as_str)
}

/// The checks, cheapest first and the witness's signature last.
///
/// The framework's four (*Evidence That a Cited Exchange Completed*):
///
/// 1. the citation binds the initiating document — its `id` is the VWC's
///    `taskContext` (the caller selected on it) and the VWC's
///    `taskDigestMultibase` reproduces over it;
/// 2. the terminal document is on that exchange's thread, and carries the
///    binding `witness/session/submit` declares — the VWC it delivers cites the
///    same document, which holds because it is this VWC (below);
/// 3. its type is the declared outcome evidence,
///    `witness/session/submit/0.1#response`;
/// 4. its proof verifies under the initiating document's `recipient`.
///
/// Then what makes it *this* VWC's evidence: the `recipient` is the VWC's
/// issuer; the session was opened by, and answered to, the VWC's subject; the
/// response's `vwcDigestMultibase` is the digest of the VWC it delivers, proof
/// included; and that VWC is the one presented, compared over its content
/// (DTG §Digest Encoding, proof excluded), since a presentation path may have
/// kept only what its proof covers.
async fn check_pair(
    entry: &OutcomeEvidence,
    issuer: &str,
    vwc: &JsonValue,
    resolver: &TrustTaskVmResolver,
) -> Result<(), String> {
    let session = &entry.session;
    let outcome = &entry.outcome;

    if str_at(session, "type") != Some(session_type()) {
        return Err(format!("the initiating document is not {}", session_type()));
    }
    // Check 1, the digest half.
    let cited_digest =
        str_at(vwc, "taskDigestMultibase").ok_or("the VWC carries no taskDigestMultibase")?;
    let session_digest = dtg_credentials::task_digest_multibase_json(session)
        .map_err(|e| format!("the session document will not canonicalize ({e})"))?;
    if !digests_match(cited_digest, &session_digest) {
        return Err("the VWC's taskDigestMultibase is not the session document's".into());
    }
    // Check 2: the thread runs through the initiating document.
    let thread = str_at(session, "threadId")
        .or_else(|| str_at(session, "id"))
        .ok_or("the session document has no id")?;
    if str_at(outcome, "threadId") != Some(thread) {
        return Err("the response is not on the session's thread".into());
    }
    // Check 3.
    if str_at(outcome, "type") != Some(submit_response_type()) {
        return Err(format!("the response is not {}", submit_response_type()));
    }
    // The responder named by the initiating document is the witness.
    let recipient = str_at(session, "recipient")
        .ok_or("the session document names no recipient, so no responder can be checked")?;
    if recipient != issuer {
        return Err("the session was addressed to someone other than the VWC's issuer".into());
    }
    if str_at(outcome, "issuer") != Some(recipient) {
        return Err("the response is not issued by the session's witness".into());
    }
    // The party: the VWC's subject opened the session and was answered.
    let subject = statement_subject(vwc)
        .get("id")
        .and_then(JsonValue::as_str)
        .ok_or("the VWC names no subject")?;
    if str_at(session, "issuer") != Some(subject) {
        return Err("the session was not opened by the VWC's subject".into());
    }
    if str_at(outcome, "recipient") != Some(subject) {
        return Err("the response was not addressed to the VWC's subject".into());
    }
    // The VWC delivered, and that it is the one presented.
    let payload = outcome
        .get("payload")
        .ok_or("the response has no payload")?;
    let delivered = payload
        .get("vwc")
        .filter(|v| v.is_object())
        .ok_or("the response delivers no VWC")?;
    let carried = str_at(payload, "vwcDigestMultibase")
        .ok_or("the response carries no vwcDigestMultibase")?;
    let delivered_digest = crate::credentials::ingress::digest_multibase(delivered)
        .map_err(|e| format!("the delivered VWC will not canonicalize ({e})"))?;
    if !digests_match(carried, &delivered_digest) {
        return Err("vwcDigestMultibase is not the digest of the VWC delivered".into());
    }
    let same = match (
        dtg_credential_digest_multibase(delivered),
        dtg_credential_digest_multibase(vwc),
    ) {
        (Ok(a), Ok(b)) => digests_match(&a, &b),
        _ => false,
    };
    if !same {
        return Err("the response delivered a different VWC from the one presented".into());
    }
    // Check 4, last: the only one that resolves a DID.
    let signer = vti_common::auth::verify_trust_task_proof_value(outcome, resolver)
        .await
        .map_err(|e| format!("the response's proof does not verify ({e})"))?;
    if signer != recipient {
        return Err("the response is signed by someone other than the session's witness".into());
    }
    Ok(())
}

/// Whether this relationship's stored VRC recomputes to the asserted digest.
///
/// A VRC that will not canonicalize cannot match anything, and is skipped
/// rather than propagated: one unserializable row must not make every witness
/// in the community unverifiable.
fn recomputes_to(rel: &Relationship, asserted: &str) -> bool {
    match dtg_credential_digest_multibase(&rel.vrc_jsonld) {
        Ok(recomputed) => digests_match(asserted, &recomputed),
        Err(e) => {
            tracing::warn!(
                error = %e, relationship_id = %rel.id,
                "stored VRC will not canonicalize; skipped for witness-digest matching"
            );
            false
        }
    }
}

/// Real witnessing evidence for tests: a `did:key` witness, the session
/// document, a signed VWC, and the witness-signed `submit#response`.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
    use chrono::Utc;
    use dtg_credentials::{DTGCredential, IssuerScope};
    use serde_json::json;
    pub use vti_rooms_dtg::test_support::Party;

    pub struct Witnessed {
        pub witness: Party,
        pub session: JsonValue,
        /// The VWC as presented: signed by the witness.
        pub vwc: JsonValue,
        pub evidence: OutcomeEvidence,
    }

    /// The `witness/session` document `party` opened with `witness`.
    pub fn session_document(party: &str, counterparty: &str, witness: &str) -> JsonValue {
        let id = format!("urn:uuid:{}", Uuid::new_v4());
        json!({
            "id": id,
            "type": session_type(),
            "threadId": id,
            "issuer": party,
            "recipient": witness,
            "issuedAt": "2026-10-15T09:59:00Z",
            "payload": { "parties": [party, counterparty] }
        })
    }

    /// The witness's signed `witness/session/submit/0.1#response` delivering `vwc`.
    pub async fn outcome(witness: &Party, session: &JsonValue, vwc: &JsonValue) -> JsonValue {
        let submitter = session["issuer"].as_str().unwrap();
        let mut doc = vta_sdk::trust_task_sign::build_unsigned(
            submit_response_type(),
            json!({
                "vwc": vwc,
                "vwcDigestMultibase": crate::credentials::ingress::digest_multibase(vwc).unwrap(),
            }),
            &witness.did,
            submitter,
        )
        .expect("build the response");
        doc.thread_id = session["threadId"].as_str().map(str::to_string);
        let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(
            &witness.did,
            &witness.secret_multibase,
        )
        .expect("a did:key names its own verification method");
        vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
            .await
            .expect("sign the response");
        serde_json::to_value(&doc).unwrap()
    }

    /// A witness attests `edge` (issued by `edge["issuer"]`, the party) being
    /// presented in a session with `counterparty`.
    pub async fn witnessed(edge: &JsonValue, counterparty: &str) -> Witnessed {
        witnessed_with(edge, counterparty, |_| {}).await
    }

    /// [`witnessed`], with the VWC edited by `edit` before the witness signs it
    /// and delivers it — how a witness would issue a VWC naming some other
    /// digest, or none.
    pub async fn witnessed_with(
        edge: &JsonValue,
        counterparty: &str,
        edit: impl FnOnce(&mut JsonValue),
    ) -> Witnessed {
        let witness = Party::new();
        let party = edge["issuer"].as_str().unwrap().to_string();
        let session = session_document(&party, counterparty, &witness.did);
        let built = DTGCredential::new_witnessed_vsc(
            witness.did.clone(),
            IssuerScope::Public,
            edge,
            &session,
            Utc::now(),
            None,
            None,
        )
        .expect("the opening witness/session document builds a VWC");
        let mut vwc = crate::test_support::dtg_json(&built);
        edit(&mut vwc);
        let proof = DataIntegrityProof::sign(
            &vwc,
            &witness.secret,
            SignOptions::new().with_proof_purpose("assertionMethod"),
        )
        .await
        .expect("sign the VWC");
        vwc["proof"] = serde_json::to_value(proof).unwrap();
        let outcome = outcome(&witness, &session, &vwc).await;
        Witnessed {
            witness,
            evidence: OutcomeEvidence {
                session: session.clone(),
                outcome,
            },
            session,
            vwc,
        }
    }

    /// Trust `dids` as witnesses, through the runtime key as `config/patch`
    /// writes it.
    pub async fn trust(state: &crate::server::AppState, dids: &[&str]) {
        let list: Vec<JsonValue> = dids.iter().map(|d| json!({ "did": d })).collect();
        crate::config_store::ConfigStore::new(state.config_ks.clone())
            .put(
                crate::credentials::trusted_witnesses::WITNESSES_TRUSTED,
                &JsonValue::Array(list),
            )
            .await
            .expect("store the list");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vrc() -> JsonValue {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
            "issuer": "did:webvh:issuer.example",
            "credentialSubject": { "id": "did:webvh:subject.example" }
        })
    }

    /// The property the whole module exists for: the same multihash encoded in
    /// two different bases is the same digest. A string comparison says no
    /// here, and says it to an honest witness.
    #[test]
    fn the_same_digest_in_two_bases_matches() {
        let b58 = dtg_credential_digest_multibase(&vrc()).unwrap();
        let (_, bytes) = multibase::decode(&b58).unwrap();
        let b16 = multibase::encode(multibase::Base::Base16Lower, &bytes);

        assert_ne!(b58, b16, "the fixture must actually differ as strings");
        assert!(digests_match(&b58, &b16));
        assert!(digests_match(&b16, &b58), "and it is symmetric");
    }

    #[test]
    fn different_documents_do_not_match() {
        let a = dtg_credential_digest_multibase(&vrc()).unwrap();
        let mut other = vrc();
        other["issuer"] = json!("did:webvh:someone-else.example");
        let b = dtg_credential_digest_multibase(&other).unwrap();
        assert!(!digests_match(&a, &b));
    }

    /// Member order is not a difference — that is what naming RFC 8785 buys,
    /// and a witness must not be rejected for reserialising the VRC.
    #[test]
    fn member_order_does_not_break_the_binding() {
        let ordered = json!({ "a": 1, "b": { "x": 1, "y": 2 } });
        let shuffled = json!({ "b": { "y": 2, "x": 1 }, "a": 1 });
        assert!(digests_match(
            &dtg_credential_digest_multibase(&ordered).unwrap(),
            &dtg_credential_digest_multibase(&shuffled).unwrap()
        ));
    }

    /// The digest length and algorithm are fixed by the specification. A
    /// 64-byte digest is not a stronger claim to be accepted generously — it
    /// is a different claim, and admitting it lets the party being checked
    /// choose the hash function.
    #[test]
    fn rejects_a_digest_that_is_not_sha2_256() {
        // sha2-512: multihash code 0x13, length 0x40.
        let mut mh = vec![0x13, 0x40];
        mh.extend_from_slice(&[7u8; 64]);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &mh);
        assert!(decode_sha256_multihash(&encoded).is_none());
        assert!(
            !digests_match(&encoded, &encoded),
            "not even against itself"
        );
    }

    #[test]
    fn rejects_a_bare_hash_with_no_multihash_header() {
        let bare = multibase::encode(multibase::Base::Base58Btc, [9u8; 32]);
        assert!(decode_sha256_multihash(&bare).is_none());
    }

    #[test]
    fn rejects_text_that_is_not_multibase_at_all() {
        assert!(decode_sha256_multihash("not-a-digest").is_none());
        assert!(decode_sha256_multihash("").is_none());
    }

    /// The two claim shapes that reach the ceremony fact: a DI VC keeps the
    /// statement under `credentialSubject`, an SD-JWT-VC has already unwrapped
    /// it.
    #[test]
    fn reads_the_digest_from_either_claim_shape() {
        assert_eq!(
            asserted_digest(
                &json!({ "credentialSubject": { "object": { "digestMultibase": "zAbc" } } })
            ),
            Some("zAbc")
        );
        assert_eq!(
            asserted_digest(&json!({ "object": { "digestMultibase": "zAbc" } })),
            Some("zAbc")
        );
        assert_eq!(asserted_digest(&json!({ "credentialSubject": {} })), None);
        assert_eq!(asserted_digest(&json!({})), None);
    }

    /// The retired placement — a digest directly under `credentialSubject`, as
    /// the pre-v1 witness type carried it — is not read: it is not a
    /// `witnessed/1` statement.
    #[test]
    fn the_retired_digest_placement_is_not_read() {
        assert_eq!(
            asserted_digest(&json!({ "credentialSubject": { "digestMultibase": "zOld" } })),
            None
        );
    }

    /// `credentialSubject` wins when both are present, because that is the
    /// issuer-signed location — a top-level object beside it is not a second
    /// opinion to be preferred.
    #[test]
    fn the_signed_location_wins() {
        assert_eq!(
            asserted_digest(&json!({
                "credentialSubject": { "object": { "digestMultibase": "zSigned" } },
                "object": { "digestMultibase": "zElsewhere" }
            })),
            Some("zSigned")
        );
    }

    /// A `sha2-256` multihash whose declared length matches its bytes but is
    /// not 32 is a truncated digest. Malformed, not a well-formed value that
    /// merely matches nothing.
    #[test]
    fn rejects_a_truncated_sha2_256_digest() {
        let mut mh = vec![0x12, 0x10];
        mh.extend_from_slice(&[7u8; 16]);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &mh);
        assert!(decode_sha256_multihash(&encoded).is_none());
    }

    /// The WD01 `sha256:<hex>` value form is not a multibase multihash, so it
    /// does not decode — the member name is tolerated, the retired encoding is
    /// not.
    #[test]
    fn a_wd01_hex_digest_value_does_not_decode() {
        assert!(decode_sha256_multihash(&format!("sha256:{}", "ab".repeat(32))).is_none());
    }

    /// DTG Credentials §Digest Encoding step 1: the digest is taken over the
    /// referenced credential **excluding its top-level `proof`**. A signed VRC
    /// and the same claims unsigned are one edge.
    #[test]
    fn the_digest_excludes_the_top_level_proof() {
        let mut signed = vrc();
        signed["proof"] = json!({ "type": "DataIntegrityProof", "proofValue": "zSig" });
        assert!(digests_match(
            &dtg_credential_digest_multibase(&signed).unwrap(),
            &dtg_credential_digest_multibase(&vrc()).unwrap()
        ));
    }

    // ── against real storage ──────────────────────────────────────────────

    use crate::relationships::Relationship;
    use crate::relationships::storage::store_relationship;

    /// Hand-built claims of a `witnessed/1` statement by `subject` over
    /// `witnessed`.
    fn vwc_claims(subject: &str, witnessed: &JsonValue) -> JsonValue {
        json!({
            "type": ["VerifiableCredential", "DTGCredential", "StatementCredential"],
            "credentialSubject": {
                "id": subject,
                "predicate": dtg_credentials::WITNESSED_V1,
                "object": {
                    "digestMultibase": dtg_credential_digest_multibase(witnessed).unwrap()
                }
            }
        })
    }
    use chrono::Utc;
    use uuid::Uuid;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_kss() -> (KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let primary = store.keyspace("relationships").unwrap();
        let index = store.keyspace("relationships_by_did").unwrap();
        (primary, index, dir)
    }

    /// A stored edge whose `vrc_digest_multibase` column is **deliberately
    /// wrong**, mirroring the fixture in `relationships::storage::tests`.
    ///
    /// This is the point of the fixture, not an oversight: the resolver must
    /// find this edge anyway, because it recomputes from `vrc_jsonld` rather
    /// than trusting the column. An implementation that matched on the column
    /// fails every test that uses this fixture.
    fn edge_with_a_stale_digest_column(issuer: &str, subject: &str) -> Relationship {
        let id = Uuid::new_v4();
        Relationship {
            id,
            issuer_did: issuer.into(),
            subject_did: subject.into(),
            vrc_jsonld: json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
                "issuer": issuer,
                "credentialSubject": { "id": subject }
            }),
            vrc_digest_multibase: format!("{:x}", id.as_u128()),
            created_at: Utc::now(),
            persona: None,
            lifecycle: Default::default(),
        }
    }

    #[tokio::test]
    async fn binds_a_witness_to_the_edge_its_digest_names() {
        let (primary, index, _dir) = temp_kss().await;
        let edge = edge_with_a_stale_digest_column("did:key:zIssuer", "did:key:zSubject");
        let other = edge_with_a_stale_digest_column("did:key:zSomeone", "did:key:zElse");
        store_relationship(&primary, &index, &edge).await.unwrap();
        store_relationship(&primary, &index, &other).await.unwrap();

        let vwc = vwc_claims("did:key:zIssuer", &edge.vrc_jsonld);
        assert_eq!(
            resolve_binding(&primary, &vwc).await.unwrap(),
            WitnessBinding::Bound {
                relationship_id: edge.id
            },
            "must name the edge it witnessed, not merely 'some edge'"
        );
    }

    /// `witnessed/1`'s subject–object rule: a witness attesting that the
    /// *subject* issued an edge the *issuer* issued names the wrong party.
    #[tokio::test]
    async fn a_witness_naming_the_wrong_issuer_is_a_subject_mismatch() {
        let (primary, index, _dir) = temp_kss().await;
        let edge = edge_with_a_stale_digest_column("did:key:zIssuer", "did:key:zSubject");
        store_relationship(&primary, &index, &edge).await.unwrap();

        let vwc = vwc_claims("did:key:zSubject", &edge.vrc_jsonld);
        assert_eq!(
            resolve_binding(&primary, &vwc).await.unwrap(),
            WitnessBinding::SubjectMismatch {
                relationship_id: edge.id
            }
        );
    }

    /// The cross-base case again, but through storage: a witness that encoded
    /// its digest in base16 witnesses the same edge as one that used base58btc.
    #[tokio::test]
    async fn a_foreign_base_encoding_still_binds() {
        let (primary, index, _dir) = temp_kss().await;
        let edge = edge_with_a_stale_digest_column("did:key:zIssuer", "did:key:zSubject");
        store_relationship(&primary, &index, &edge).await.unwrap();

        let (_, bytes) =
            multibase::decode(dtg_credential_digest_multibase(&edge.vrc_jsonld).unwrap()).unwrap();
        let mut vwc = vwc_claims("did:key:zIssuer", &edge.vrc_jsonld);
        vwc["credentialSubject"]["object"]["digestMultibase"] =
            json!(multibase::encode(multibase::Base::Base16Lower, &bytes));
        assert_eq!(
            resolve_binding(&primary, &vwc).await.unwrap(),
            WitnessBinding::Bound {
                relationship_id: edge.id
            }
        );
    }

    /// A digest naming an edge held elsewhere is `Unresolved`, not a rejection
    /// — surfaced for the policy to weigh, the way an unresolvable status list
    /// is.
    #[tokio::test]
    async fn an_edge_this_service_does_not_hold_is_unresolved() {
        let (primary, index, _dir) = temp_kss().await;
        store_relationship(
            &primary,
            &index,
            &edge_with_a_stale_digest_column("did:key:zA", "did:key:zB"),
        )
        .await
        .unwrap();

        let elsewhere = json!({ "type": ["VerifiableCredential"], "issuer": "did:key:zNowhere" });
        let vwc = vwc_claims("did:key:zNowhere", &elsewhere);
        assert_eq!(
            resolve_binding(&primary, &vwc).await.unwrap(),
            WitnessBinding::Unresolved
        );
    }

    #[tokio::test]
    async fn a_witness_asserting_no_digest_is_absent() {
        let (primary, _index, _dir) = temp_kss().await;
        assert_eq!(
            resolve_binding(&primary, &json!({ "credentialSubject": {} }))
                .await
                .unwrap(),
            WitnessBinding::Absent
        );
    }

    /// Malformed is kept distinct from `Unresolved`: an honest witness can
    /// legitimately name an edge we do not hold, but cannot legitimately emit
    /// a digest that is not a `sha2-256` multihash.
    #[tokio::test]
    async fn an_undecodable_digest_is_malformed() {
        let (primary, _index, _dir) = temp_kss().await;
        for bad in ["not-a-digest", "", "zzzz!!!"] {
            assert_eq!(
                resolve_binding(
                    &primary,
                    &json!({ "credentialSubject": { "object": { "digestMultibase": bad } } })
                )
                .await
                .unwrap(),
                WitnessBinding::Malformed,
                "{bad:?}"
            );
        }
    }

    /// An empty community has no edges, so every witness is unresolved — and
    /// notably not `Bound` by a vacuous scan.
    #[tokio::test]
    async fn an_empty_keyspace_binds_nothing() {
        let (primary, _index, _dir) = temp_kss().await;
        let vwc = vwc_claims("did:webvh:issuer.example", &vrc());
        assert_eq!(
            resolve_binding(&primary, &vwc).await.unwrap(),
            WitnessBinding::Unresolved
        );
    }

    // ── a VWC built by the catalog, verified by this module ───────────────

    use crate::test_support::dtg_json;
    use dtg_credentials::{DTGCredential, IssuerScope};

    const WITNESS: &str = "did:webvh:witness.example";
    const ALICE: &str = "did:key:zAlice";
    const BOB: &str = "did:key:zBob";
    /// The `id` of the `witness/session` document that opened the witnessing
    /// session — what a VWC's `taskContext` names (trust task
    /// `witness/session/0.1` §The nesting).
    const SESSION: &str = "urn:uuid:6f1c1c1e-5a8b-4f7e-9d0c-2b7a4e1d9c30";

    /// The `witness/session` document that opened the session, as the witness
    /// received it. `new_witnessed_vsc` reads both halves of the citation off
    /// it — `taskContext` from its `id`, `taskDigestMultibase` from its task
    /// digest — so the two cannot disagree, and refuses anything that is not
    /// the opening document (a `submit`, a `#response`, or one whose
    /// `threadId` is not its own `id`).
    fn witness_session() -> JsonValue {
        json!({
            "id": SESSION,
            "type": "https://trusttasks.org/spec/witness/session/0.1",
            "threadId": SESSION,
            "issuer": ALICE,
            "recipient": WITNESS,
            "issuedAt": "2026-09-22T09:59:00Z",
            "payload": { "parties": [ALICE, BOB] }
        })
    }

    /// A VRC as it is stored after publication: the catalog's own credential,
    /// **signed** — the `proof` is what a stored edge carries and what the VWC
    /// digest must not cover.
    fn stored_signed_vrc(issuer: &str, subject: &str) -> (DTGCredential, Relationship) {
        let vrc = DTGCredential::new_vrc(
            issuer.into(),
            IssuerScope::Pairwise,
            subject.into(),
            Utc::now(),
            None,
        );
        let mut vrc_jsonld = dtg_json(&vrc);
        vrc_jsonld["proof"] = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("{issuer}#key-0"),
            "proofPurpose": "assertionMethod",
            "proofValue": "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk"
        });
        let rel = Relationship {
            id: Uuid::new_v4(),
            issuer_did: issuer.into(),
            subject_did: subject.into(),
            // What publication actually writes to the column: the framework
            // digest, proof included — a different value from the one a
            // witness asserts, so matching on the column fails here too.
            vrc_digest_multibase: crate::credentials::ingress::digest_multibase(&vrc_jsonld)
                .unwrap(),
            vrc_jsonld,
            created_at: Utc::now(),
            persona: None,
            lifecycle: Default::default(),
        };
        (vrc, rel)
    }

    /// A VWC for one direction of a witnessed edge, built the only way the
    /// catalog builds one: a `witnessed/1` statement whose
    /// `credentialSubject.id` is read off the witnessed VRC's issuer (the
    /// profile's subject–object rule) and whose `taskContext` is REQUIRED. The
    /// witness declares `directed`, the profile's minimum.
    fn vwc_for(witnessed: &DTGCredential) -> DTGCredential {
        DTGCredential::new_witnessed_vsc(
            WITNESS.into(),
            IssuerScope::Directed,
            &dtg_json(witnessed),
            &witness_session(),
            Utc::now(),
            None,
            None,
        )
        .expect("the opening witness/session document builds a VWC")
    }

    /// **The round trip #1068 asked for.** A VWC built through
    /// `DTGCredential::new_witnessed_vsc`, its digest produced by the
    /// catalog's own `digest_multibase` over the witnessed VRC, binds to that
    /// VRC as this service stores it — signed, with a `proof` the digest
    /// excludes.
    ///
    /// Before this test existed the two sides disagreed twice over, and both
    /// were silent: the verifier read `credentialSubject.digest` where the
    /// catalog writes `digestMultibase` (so this came back `Absent`), and it
    /// digested the stored VRC proof-included (so even the right member would
    /// have come back `Unresolved`).
    #[tokio::test]
    async fn a_catalog_built_vwc_binds_to_the_signed_vrc_it_witnessed() {
        let (primary, index, _dir) = temp_kss().await;
        let (alice_to_bob, edge) = stored_signed_vrc(ALICE, BOB);
        let (_, unrelated) = stored_signed_vrc("did:key:zCarol", "did:key:zDave");
        store_relationship(&primary, &index, &unrelated)
            .await
            .unwrap();
        store_relationship(&primary, &index, &edge).await.unwrap();

        let vwc = dtg_json(&vwc_for(&alice_to_bob));
        assert!(is_witness_statement(&vwc));
        assert_eq!(vwc["credentialSubject"]["id"], ALICE);
        assert_eq!(
            vwc["credentialSubject"]["object"]["digestMultibase"]
                .as_str()
                .and_then(|d| d.chars().next()),
            Some('z'),
            "§Digest Encoding: issuers MUST use base58btc"
        );

        assert_eq!(
            resolve_binding(&primary, &vwc).await.unwrap(),
            WitnessBinding::Bound {
                relationship_id: edge.id
            }
        );
    }

    /// The same catalog-built VWC clears the receipt half of Trust Task Context
    /// Binding (#1065): `new_witnessed_vsc` cannot omit `taskContext`, and
    /// ingress, which refuses a VWC without one, accepts it.
    ///
    /// Since dtg-credentials 0.11 it also carries `taskDigestMultibase`, the
    /// task digest of the same document — the half that *binds* the citation,
    /// where `taskContext` only names it (`witness/session/submit` Conformance
    /// item 1). Both are read off one document, so they cannot disagree.
    #[test]
    fn a_catalog_built_vwc_carries_the_required_task_context() {
        let (alice_to_bob, _) = stored_signed_vrc(ALICE, BOB);
        let built = vwc_for(&alice_to_bob);
        let vwc = dtg_json(&built);
        assert_eq!(vwc["taskContext"], SESSION);
        assert_eq!(
            vwc["taskDigestMultibase"],
            dtg_credentials::task_digest_multibase_json(&witness_session()).unwrap(),
            "the digest is the session document's, not something the issuer chose"
        );
        assert!(
            built.cites_task(&witness_session()).unwrap(),
            "both halves of the citation resolve back to the document they came from"
        );
        assert_eq!(
            crate::credentials::ingress::classify_dtg(&vwc).unwrap(),
            dtg_credentials::DTGCredentialType::Statement
        );
        assert_eq!(vwc["issuerScope"], "directed");
    }

    /// One VWC per direction (DTG Credentials §VWC: the witness "SHOULD issue
    /// one VWC per direction"). Each binds to its own edge and not the other's
    /// — the digest, not the subject id, is what names the edge.
    #[tokio::test]
    async fn each_direction_of_a_witnessed_exchange_binds_its_own_edge() {
        let (primary, index, _dir) = temp_kss().await;
        let (a_to_b, edge_ab) = stored_signed_vrc(ALICE, BOB);
        let (b_to_a, edge_ba) = stored_signed_vrc(BOB, ALICE);
        store_relationship(&primary, &index, &edge_ab)
            .await
            .unwrap();
        store_relationship(&primary, &index, &edge_ba)
            .await
            .unwrap();

        for (vrc, edge) in [(&a_to_b, &edge_ab), (&b_to_a, &edge_ba)] {
            assert_eq!(
                resolve_binding(&primary, &dtg_json(&vwc_for(vrc)))
                    .await
                    .unwrap(),
                WitnessBinding::Bound {
                    relationship_id: edge.id
                }
            );
        }
    }

    // ── the personhood projection ─────────────────────────────────────────

    /// The personhood `assert` path's projection gains the verdict, on witness
    /// entries only, under the same key and shape the ceremony fact uses.
    #[tokio::test]
    async fn annotation_puts_the_verdict_on_witness_entries_only() {
        let (primary, index, _dir) = temp_kss().await;
        let (_, edge) = stored_signed_vrc(ALICE, BOB);
        store_relationship(&primary, &index, &edge).await.unwrap();
        let w = fixtures::witnessed(&edge.vrc_jsonld, BOB).await;
        let trusted = TrustedWitnesses::from_list(&[TrustedWitness {
            did: w.witness.did.clone(),
            label: None,
        }]);
        let resolver = TrustTaskVmResolver::did_key_only();
        let evidence = [w.evidence.clone()];
        let ctx = WitnessContext {
            relationships_ks: &primary,
            trusted: &trusted,
            evidence: &evidence,
            resolver: &resolver,
        };

        let vp = json!({
            "holder": ALICE,
            "verifiableCredential": [
                w.vwc,
                { "type": ["VerifiableCredential"], "issuer": "did:key:zOther",
                  "credentialSubject": { "id": ALICE } }
            ]
        });
        let mut claims = crate::policy::extract::extract_vp_claims(&vp);
        annotate_vp_claims(&ctx, &vp, &mut claims).await;

        assert_eq!(
            claims["credentials"][0][WITNESS_BINDING_KEY],
            json!({ "state": "bound", "relationship_id": edge.id })
        );
        assert!(
            claims["credentials"][1].get(WITNESS_BINDING_KEY).is_none(),
            "a non-witness credential has no binding question to answer"
        );
    }

    /// The verdict is the host's, never the presenter's. A VP that tries to
    /// carry its own `witness_binding` — on the witness it forged, or on a
    /// non-witness credential — does not get it into the policy input.
    #[tokio::test]
    async fn a_presenter_cannot_supply_the_verdict() {
        let (primary, _index, _dir) = temp_kss().await;
        let forged_verdict = json!({ "state": "bound", "relationship_id": Uuid::new_v4() });
        let trusted = TrustedWitnesses::from_list(&[TrustedWitness {
            did: WITNESS.into(),
            label: None,
        }]);
        let resolver = TrustTaskVmResolver::did_key_only();
        let ctx = WitnessContext {
            relationships_ks: &primary,
            trusted: &trusted,
            evidence: &[],
            resolver: &resolver,
        };

        let mut claims = json!({
            "holder": BOB,
            "credentials": [
                { "type": ["VerifiableCredential", "DTGCredential", "StatementCredential"],
                  "issuer": WITNESS,
                  "credentialSubject": {
                      "id": ALICE,
                      "predicate": dtg_credentials::WITNESSED_V1,
                      "object": { "id": "did:key:zNotADigest" }
                  },
                  "witness_binding": forged_verdict },
                { "type": ["VerifiableCredential"],
                  "issuer": WITNESS,
                  "witness_binding": forged_verdict }
            ]
        });
        annotate_vp_claims(&ctx, &JsonValue::Null, &mut claims).await;

        assert_eq!(
            claims["credentials"][0][WITNESS_BINDING_KEY],
            json!({ "state": "noOutcomeEvidence" }),
            "overwritten with what the credential actually establishes"
        );
        assert!(claims["credentials"][1].get(WITNESS_BINDING_KEY).is_none());
    }

    // ── the trusted-witness list and the outcome evidence ─────────────────

    use crate::credentials::trusted_witnesses::TrustedWitness;
    use fixtures::Witnessed;

    async fn assess_with(
        w: &Witnessed,
        trusted: &[&str],
        evidence: &[OutcomeEvidence],
    ) -> WitnessBinding {
        let (primary, index, _dir) = temp_kss().await;
        let edge = Relationship {
            id: Uuid::new_v4(),
            issuer_did: ALICE.into(),
            subject_did: BOB.into(),
            vrc_jsonld: witnessed_edge(),
            vrc_digest_multibase: String::new(),
            created_at: Utc::now(),
            persona: None,
            lifecycle: Default::default(),
        };
        store_relationship(&primary, &index, &edge).await.unwrap();
        let list: Vec<TrustedWitness> = trusted
            .iter()
            .map(|d| TrustedWitness {
                did: (*d).into(),
                label: None,
            })
            .collect();
        let trusted = TrustedWitnesses::from_list(&list);
        let resolver = TrustTaskVmResolver::did_key_only();
        let ctx = WitnessContext {
            relationships_ks: &primary,
            trusted: &trusted,
            evidence,
            resolver: &resolver,
        };
        assess(&ctx, &w.witness.did, &w.vwc).await.unwrap()
    }

    fn witnessed_edge() -> JsonValue {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
            "issuer": ALICE,
            "credentialSubject": { "id": BOB }
        })
    }

    #[tokio::test]
    async fn a_listed_witness_with_paired_evidence_binds() {
        let w = fixtures::witnessed(&witnessed_edge(), BOB).await;
        let did = w.witness.did.clone();
        let evidence = [w.evidence.clone()];
        assert!(assess_with(&w, &[&did], &evidence).await.is_bound());
    }

    /// Empty is the default, and it trusts nobody — before any evidence or
    /// digest is looked at.
    #[tokio::test]
    async fn an_unlisted_witness_is_untrusted_whatever_else_holds() {
        let w = fixtures::witnessed(&witnessed_edge(), BOB).await;
        let evidence = [w.evidence.clone()];
        assert_eq!(
            assess_with(&w, &[], &evidence).await,
            WitnessBinding::UntrustedWitness,
            "the empty default"
        );
        assert_eq!(
            assess_with(&w, &["did:key:z6MkSomeoneElse"], &evidence).await,
            WitnessBinding::UntrustedWitness
        );
    }

    #[tokio::test]
    async fn a_listed_witness_without_evidence_has_none() {
        let w = fixtures::witnessed(&witnessed_edge(), BOB).await;
        let did = w.witness.did.clone();
        assert_eq!(
            assess_with(&w, &[&did], &[]).await,
            WitnessBinding::NoOutcomeEvidence
        );
        // Evidence for some other session is not this VWC's.
        let other = fixtures::witnessed(&witnessed_edge(), BOB).await;
        assert_eq!(
            assess_with(&w, &[&did], &[other.evidence]).await,
            WitnessBinding::NoOutcomeEvidence
        );
    }

    /// Each way the evidence can fail to pair, one at a time. Every one is
    /// `OutcomeInvalid` with its own reason.
    #[tokio::test]
    async fn evidence_that_does_not_pair_is_invalid() {
        let w = fixtures::witnessed(&witnessed_edge(), BOB).await;
        let resolver = TrustTaskVmResolver::did_key_only();
        let pair = |e: OutcomeEvidence| {
            let vwc = w.vwc.clone();
            let did = w.witness.did.clone();
            let resolver = resolver.clone();
            async move { pair_outcome(&[e], &did, &vwc, &resolver).await }
        };
        assert_eq!(pair(w.evidence.clone()).await, Pairing::Paired);

        let resign = |outcome: &JsonValue| {
            let mut unsigned = outcome.clone();
            unsigned.as_object_mut().unwrap().remove("proof");
            unsigned
        };
        let mut cases: Vec<(&str, OutcomeEvidence, &str)> = Vec::new();

        // Check 1: the session document is not the one the VWC's digest names.
        let mut e = w.evidence.clone();
        e.session["payload"]["parties"] = json!([ALICE, "did:key:zMallory"]);
        cases.push(("tampered session", e, "taskDigestMultibase"));

        // Check 2: a response on another thread.
        let mut e = w.evidence.clone();
        e.outcome["threadId"] = json!("urn:uuid:another-thread");
        cases.push(("another thread", e, "thread"));

        // Check 3: not the declared outcome evidence (a session #response).
        let mut e = w.evidence.clone();
        e.outcome["type"] = json!(format!("{}#response", session_type()));
        cases.push(("wrong type", e, "is not"));

        // Check 4: signed by someone other than the session's recipient.
        let forger = fixtures::Party::new();
        let mut forged = fixtures::outcome(&forger, &w.session, &w.vwc).await;
        forged["issuer"] = json!(w.witness.did);
        cases.push((
            "forged signature",
            OutcomeEvidence {
                session: w.session.clone(),
                outcome: forged,
            },
            "proof",
        ));

        // A response whose proof no longer covers what it says.
        let mut e = w.evidence.clone();
        e.outcome["payload"]["vwcDigestMultibase"] =
            json!(crate::credentials::ingress::digest_multibase(&json!({ "x": 1 })).unwrap());
        cases.push(("wrong vwcDigestMultibase", e, "vwcDigestMultibase"));

        // A response delivering a different VWC from the one presented.
        let other = fixtures::witnessed(&witnessed_edge(), BOB).await;
        let delivered_elsewhere = fixtures::outcome(&w.witness, &w.session, &other.vwc).await;
        cases.push((
            "another VWC",
            OutcomeEvidence {
                session: w.session.clone(),
                outcome: delivered_elsewhere,
            },
            "different VWC",
        ));

        // An unsigned response.
        cases.push((
            "unsigned",
            OutcomeEvidence {
                session: w.session.clone(),
                outcome: resign(&w.evidence.outcome),
            },
            "proof",
        ));

        for (why, evidence, expect) in cases {
            match pair(evidence).await {
                Pairing::Invalid(reason) => {
                    assert!(reason.contains(expect), "{why}: {reason}")
                }
                other => panic!("{why}: expected Invalid, got {other:?}"),
            }
        }
    }

    /// The session must have been addressed to the VWC's issuer: evidence of
    /// a session with another witness does not pair.
    #[tokio::test]
    async fn a_session_with_another_witness_does_not_pair() {
        let w = fixtures::witnessed(&witnessed_edge(), BOB).await;
        let resolver = TrustTaskVmResolver::did_key_only();
        assert!(matches!(
            pair_outcome(
                std::slice::from_ref(&w.evidence),
                "did:key:z6MkAnotherWitness",
                &w.vwc,
                &resolver
            )
            .await,
            Pairing::Invalid(_)
        ));
    }

    #[test]
    fn the_carriage_is_read_and_its_namespace_is_closed() {
        let session = json!({ "id": "urn:uuid:s" });
        let outcome = json!({ "type": "x" });
        let ext = json!({ OUTCOME_EVIDENCE_EXT: {
            OUTCOME_EVIDENCE: [{ "session": session, "outcome": outcome }]
        }});
        let got = outcome_evidence_from_ext(Some(&ext)).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].session, session);

        assert!(outcome_evidence_from_ext(None).unwrap().is_empty());
        assert!(
            outcome_evidence_from_ext(Some(&json!({ "org.example": {} })))
                .unwrap()
                .is_empty(),
            "another namespace is not ours to read"
        );
        for bad in [
            json!({ OUTCOME_EVIDENCE_EXT: [] }),
            json!({ OUTCOME_EVIDENCE_EXT: { "memberPresentation": {} } }),
            json!({ OUTCOME_EVIDENCE_EXT: { OUTCOME_EVIDENCE: [{ "session": {} }] } }),
            json!({ OUTCOME_EVIDENCE_EXT: { OUTCOME_EVIDENCE: [
                { "session": {}, "outcome": {}, "extra": 1 }
            ] } }),
        ] {
            assert!(outcome_evidence_from_ext(Some(&bad)).is_err(), "{bad}");
        }
        let too_many: Vec<_> = (0..=MAX_OUTCOME_EVIDENCE)
            .map(|_| json!({ "session": {}, "outcome": {} }))
            .collect();
        assert!(
            outcome_evidence_from_ext(Some(
                &json!({ OUTCOME_EVIDENCE_EXT: { OUTCOME_EVIDENCE: too_many } })
            ))
            .is_err()
        );
    }

    /// A witness is classified by its predicate. A single-string `type` is
    /// legal VCDM; a statement under any other predicate is not a witness; and
    /// the retired witness type string classifies nothing.
    #[test]
    fn a_witness_is_a_witnessed_statement() {
        let subject = json!({ "id": ALICE, "predicate": dtg_credentials::WITNESSED_V1 });
        assert!(is_witness_statement(
            &json!({ "type": "StatementCredential", "credentialSubject": subject })
        ));
        assert!(!is_witness_statement(&json!({
            "type": ["VerifiableCredential", "StatementCredential"],
            "credentialSubject": { "id": ALICE, "predicate": dtg_credentials::ENDORSES_V1 }
        })));
        assert!(!is_witness_statement(&json!({
            "type": ["VerifiableCredential", "RelationshipCredential"],
            "credentialSubject": subject
        })));
        // A predicate is compared byte for byte: no CURIE, no trailing slash.
        assert!(!is_witness_statement(&json!({
            "type": "StatementCredential",
            "credentialSubject": { "predicate": "dtg:witnessed" }
        })));
        assert!(!is_witness_statement(&json!({})));
    }
}
