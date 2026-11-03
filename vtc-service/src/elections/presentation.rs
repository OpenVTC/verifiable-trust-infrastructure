//! A membership presentation carried by a ticket claim (`vtc/elections/tickets/issue/0.3`) or a
//! read (`vtc/elections/show/0.6`), checked **before** the election it names is looked up and
//! without reference to it (VTI-VOT-018, VTI-VOT-025; tickets/issue Conformance item 2).
//!
//! What this establishes needs nothing of any election: that the presentation is bound to the
//! request (`binding`), that its holder and the credential's subject are the request's signer
//! and that it carries one credential (`holder`), that the credential's issuer signed it
//! (`proof`), that it is within its validity period (`validity`), and that its status shows it
//! neither revoked nor suspended (`revoked`). Each check is **passed**, **failed** or, where it
//! needs something this community does not control — the holder's or issuer's DID document, a
//! status list — that cannot be obtained, **unknown**. The outcome is the first failed check in
//! that order; or, where none failed and one is unknown, [`Outcome::Indeterminate`]; or
//! [`Outcome::Passed`]. The caller answers an indeterminate outcome with the framework's
//! `indeterminate` whatever the election, and decides what a failed or passed one means only
//! after the lookup.
//!
//! The cryptography is the workspace's own: the Data Integrity proof set
//! ([`crate::credentials::proof_set`]), the issuer binding, the SD-JWT verifier
//! ([`crate::credentials::verify_presentation_with_anchors`]) and the status-list fetcher of
//! the join path. A credential this community issued has its status read from its own status
//! list, never fetched (tickets/issue item 6.2).
//!
//! Nothing of the presentation is kept: the caller holds the [`Outcome`] while it decides, and
//! the issuance record (or nothing at all) is what survives (VTI-CRD-042).

use std::sync::atomic::{AtomicBool, Ordering};

use affinidi_data_integrity::{DataIntegrityError, ResolvedKey};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use vti_common::auth::{ProofPurpose, PurposeVmResolver};

use crate::ceremony::CredentialStatus;
use crate::credentials::proof_set;
use crate::credentials::vm_resolver::{DidVmResolver, check_issuer_binding};
use crate::server::AppState;

/// A check a presentation can fail, in the order they are made (tickets/issue item 2), named as
/// `membershipNotProven`'s `details.reason` names them — `revoked` is answered
/// `membershipRevoked` instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Binding,
    Holder,
    Proof,
    Validity,
    Revoked,
}

impl Check {
    /// `details.reason`.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Check::Binding => "binding",
            Check::Holder => "holder",
            Check::Proof => "proof",
            Check::Validity => "validity",
            Check::Revoked => "revoked",
        }
    }
}

/// What a presentation came to, before any election is looked up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Every check passed.
    Passed(Presented),
    /// `check` failed, the first in order. `issuer` is the credential's stated issuer where the
    /// presentation got far enough to name one, for the item a claim checks it at.
    Failed {
        check: Check,
        issuer: Option<String>,
    },
    /// None failed, and one needs a reference that could not be obtained: `reference` is its
    /// kind — `didDocument` or `statusList` — and all the answer may say (SPEC §8.3).
    Indeterminate { reference: &'static str },
}

impl Outcome {
    /// The credential's issuer, where the presentation named one.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        match self {
            Outcome::Passed(p) => Some(&p.issuer),
            Outcome::Failed { issuer, .. } => issuer.as_deref(),
            Outcome::Indeterminate { .. } => None,
        }
    }
}

/// The one credential a presentation that passed carried: who issued it, and whom it is about.
/// Neither the presentation nor any other claim of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presented {
    pub issuer: String,
    pub subject: String,
}

/// One check's result while the checks are made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Pass,
    Fail,
    Unknown(&'static str),
}

/// A [`PurposeVmResolver`] that notes whether a refusal was the DID document being out of reach
/// rather than the key being wrong: a key the document does not list, or lists for another
/// purpose, is a failed check; a document that cannot be obtained is an unknown one.
struct Noting<'a> {
    inner: DidVmResolver,
    state: &'a AppState,
    unobtainable: AtomicBool,
}

impl<'a> Noting<'a> {
    fn new(state: &'a AppState) -> Self {
        Self {
            inner: DidVmResolver::new(state.did_resolver.clone()),
            state,
            unobtainable: AtomicBool::new(false),
        }
    }

    fn unobtainable(&self) -> bool {
        self.unobtainable.load(Ordering::SeqCst)
    }
}

/// Whether `did`'s document can be obtained now. A `did:key` is its own document.
async fn obtainable(state: &AppState, did: &str) -> bool {
    if did.starts_with("did:key:") {
        return true;
    }
    match &state.did_resolver {
        Some(r) => r.resolve(did).await.is_ok(),
        None => false,
    }
}

#[async_trait::async_trait]
impl PurposeVmResolver for Noting<'_> {
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        purpose: ProofPurpose,
    ) -> Result<ResolvedKey, DataIntegrityError> {
        let out = self.inner.resolve_vm_for_purpose(vm, purpose).await;
        if out.is_err() {
            let did = vm.split('#').next().unwrap_or(vm);
            if !obtainable(self.state, did).await {
                self.unobtainable.store(true, Ordering::SeqCst);
            }
        }
        out
    }
}

/// `did` without its fragment.
fn base_did(did: &str) -> &str {
    did.split('#').next().unwrap_or(did)
}

/// Check `presentation` for a request whose `id` is `document_id`, signed by `signer`, to the
/// community `community` (tickets/issue/0.3 Conformance item 2; show/0.6 item 8.2).
pub async fn check(
    state: &AppState,
    presentation: &Value,
    document_id: &str,
    community: &str,
    signer: &str,
    now: DateTime<Utc>,
) -> Outcome {
    match presentation {
        Value::Object(_) => {
            check_di(state, presentation, document_id, community, signer, now).await
        }
        Value::String(compact) => {
            check_sd_jwt(state, compact, document_id, community, signer, now).await
        }
        _ => Outcome::Failed {
            check: Check::Binding,
            issuer: None,
        },
    }
}

/// The first failed step, else the first unknown, else passed.
fn conclude(steps: &[(Check, Step)], issuer: Option<String>, subject: String) -> Outcome {
    if let Some((check, _)) = steps.iter().find(|(_, s)| *s == Step::Fail) {
        return Outcome::Failed {
            check: *check,
            issuer,
        };
    }
    if let Some(reference) = steps.iter().find_map(|(_, s)| match s {
        Step::Unknown(r) => Some(*r),
        _ => None,
    }) {
        return Outcome::Indeterminate { reference };
    }
    match issuer {
        Some(issuer) => Outcome::Passed(Presented { issuer, subject }),
        // Unreachable: a presentation that named no issuer failed `holder` or `proof`.
        None => Outcome::Failed {
            check: Check::Proof,
            issuer: None,
        },
    }
}

/// A W3C Data Integrity presentation (`present_di_vc`'s shape).
async fn check_di(
    state: &AppState,
    vp: &Value,
    document_id: &str,
    community: &str,
    signer: &str,
    now: DateTime<Utc>,
) -> Outcome {
    let mut steps: Vec<(Check, Step)> = Vec::with_capacity(5);
    let resolver = Noting::new(state);

    // binding: the holder proof verifies, as `authentication`, over the presentation with its
    // `nonce` this document's `id` and its `domain` this community; a proof that also states
    // `challenge` or `domain` states the same.
    let mut holder: Option<String> = None;
    let binding = 'b: {
        if vp.get("nonce").and_then(Value::as_str) != Some(document_id)
            || vp.get("domain").and_then(Value::as_str) != Some(community)
            || !crate::directory::present::proof_options_agree(vp, document_id, community)
        {
            break 'b Step::Fail;
        }
        let Some(proof_value) = vp.get("proof") else {
            break 'b Step::Fail;
        };
        let Ok(proofs) = proof_set::proof_set(proof_value) else {
            break 'b Step::Fail;
        };
        if proofs.iter().any(|p| p.proof_purpose != "authentication") {
            break 'b Step::Fail;
        }
        let mut unsigned = vp.clone();
        if let Some(o) = unsigned.as_object_mut() {
            o.remove("proof");
        }
        let mut outcomes = Vec::with_capacity(proofs.len());
        for p in &proofs {
            let did = proof_set::proof_signer_did(p).to_string();
            let r =
                proof_set::verify_one(p, &unsigned, &resolver, ProofPurpose::Authentication).await;
            outcomes.push((did, r));
        }
        match proof_set::accept_all(&outcomes) {
            Ok(did) => {
                holder = Some(did);
                Step::Pass
            }
            Err(_) if resolver.unobtainable() => Step::Unknown("didDocument"),
            Err(_) => Step::Fail,
        }
    };
    steps.push((Check::Binding, binding));

    // holder: the proven holder is the signer, the presentation names no other, and it carries
    // one credential, about the signer.
    let vcs = vp
        .get("verifiableCredential")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let vc = vcs.first().cloned().unwrap_or(Value::Null);
    let subject = vc["credentialSubject"]["id"]
        .as_str()
        .map(|s| base_did(s).to_string())
        .unwrap_or_default();
    let named_holder = vp
        .get("holder")
        .map(|h| h.as_str().or_else(|| h.get("id").and_then(Value::as_str)));
    let holder_step = if vcs.len() != 1
        || subject != signer
        || named_holder.is_some_and(|h| h != Some(signer))
        || holder.as_deref().is_some_and(|h| h != signer)
    {
        Step::Fail
    } else if holder.is_none() {
        // The holder proof did not verify, so who holds it is not known; `binding` says why.
        binding
    } else {
        Step::Pass
    };
    steps.push((Check::Holder, holder_step));

    // proof: the issuer's proof, by a key its DID document gives `assertionMethod`, bound to the
    // credential's `issuer`.
    let issuer = vc
        .get("issuer")
        .and_then(|i| match i {
            Value::String(s) => Some(s.clone()),
            Value::Object(o) => o.get("id").and_then(Value::as_str).map(str::to_string),
            _ => None,
        })
        .filter(|i| i.starts_with("did:"));
    let proof = match &issuer {
        None => Step::Fail,
        Some(iss) => issuer_proof(&vc, iss, &resolver).await,
    };
    steps.push((Check::Proof, proof));

    // validity: the credential's window includes now.
    let validity =
        match crate::credentials::ingress::check_validity_window(&vc, now, "membership credential")
        {
            Ok(()) if vc.is_object() => Step::Pass,
            _ => Step::Fail,
        };
    steps.push((Check::Validity, validity));

    // revoked: its status, where it carries one.
    let revoked = status(state, vc.get("credentialStatus"), issuer.as_deref()).await;
    steps.push((Check::Revoked, revoked));

    conclude(&steps, issuer, subject)
}

/// The issuer's proof set on `vc`: every proof bound to `issuer`, each valid under
/// `assertionMethod` over the proof-stripped credential.
async fn issuer_proof(vc: &Value, issuer: &str, resolver: &Noting<'_>) -> Step {
    let Some(proof_value) = vc.get("proof") else {
        return Step::Fail;
    };
    let Ok(proofs) = proof_set::proof_set(proof_value) else {
        return Step::Fail;
    };
    if proofs
        .iter()
        .any(|p| check_issuer_binding(&p.verification_method, issuer).is_err())
    {
        return Step::Fail;
    }
    let mut unsigned = vc.clone();
    if let Some(o) = unsigned.as_object_mut() {
        o.remove("proof");
    }
    let mut outcomes = Vec::with_capacity(proofs.len());
    for p in &proofs {
        let did = proof_set::proof_signer_did(p).to_string();
        let r = proof_set::verify_one(p, &unsigned, resolver, ProofPurpose::AssertionMethod).await;
        outcomes.push((did, r));
    }
    match proof_set::accept_all(&outcomes) {
        Ok(_) => Step::Pass,
        Err(_) if resolver.unobtainable() => Step::Unknown("didDocument"),
        Err(_) => Step::Fail,
    }
}

/// The `revoked` check: no status mechanism is checked by the validity period alone
/// (VTI-DIR-085); a status list of this community's own is read from its own record; any other
/// is fetched, and one that cannot be read is unknown.
async fn status(state: &AppState, entry: Option<&Value>, issuer: Option<&str>) -> Step {
    let Some(entry) = entry else {
        return Step::Pass;
    };
    if let Some(own) = own_status(state, entry).await {
        return if own { Step::Fail } else { Step::Pass };
    }
    let fetcher = crate::routes::join_requests::present::credential_status_fetcher(state);
    match crate::routes::join_requests::present::resolve_presented_status(
        Some(entry),
        issuer,
        &fetcher,
    )
    .await
    {
        CredentialStatus::Valid => Step::Pass,
        CredentialStatus::Revoked | CredentialStatus::Suspended => Step::Fail,
        CredentialStatus::Unknown => Step::Unknown("statusList"),
    }
}

/// Whether a `BitstringStatusListEntry` names a slot set in one of this community's own lists:
/// `None` when the entry names a list that is not this community's.
async fn own_status(state: &AppState, entry: &Value) -> Option<bool> {
    let url = entry.get("statusListCredential")?.as_str()?;
    let index: usize = match entry.get("statusListIndex")? {
        Value::String(s) => s.parse().ok()?,
        Value::Number(n) => usize::try_from(n.as_u64()?).ok()?,
        _ => return None,
    };
    let rows = crate::status_list::list_states(&state.status_lists_ks)
        .await
        .ok()?;
    let row = rows.iter().find(|r| r.list_credential_id == url)?;
    Some(row.is_set(index))
}

/// The payload of a compact JWT segment, read without verifying it — only to compare its
/// binding claims before the verifier checks the signature over them.
fn jwt_payload(jwt: &str) -> Option<Value> {
    use base64::Engine as _;
    let payload = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// A compact SD-JWT presentation with its key-binding JWT.
///
/// The SD-JWT verifier checks the issuer's signature, the key binding and the credential's
/// window together, so of `proof` and `validity` it can say only that one failed: a refusal it
/// makes is reported as `proof`. The key-binding JWT's `nonce` and `aud` are compared first, so
/// a presentation bound to another request is reported as `binding`.
async fn check_sd_jwt(
    state: &AppState,
    compact: &str,
    document_id: &str,
    community: &str,
    signer: &str,
    now: DateTime<Utc>,
) -> Outcome {
    let mut steps: Vec<(Check, Step)> = Vec::with_capacity(5);
    let kb = compact.rsplit('~').next().filter(|s| !s.is_empty());
    let kb_claims = kb.and_then(jwt_payload);
    let bound = kb_claims.as_ref().is_some_and(|c| {
        c.get("nonce").and_then(Value::as_str) == Some(document_id)
            && c.get("aud").and_then(Value::as_str) == Some(community)
    });
    let issuer_claims = compact.split('~').next().and_then(jwt_payload);
    let issuer = issuer_claims
        .as_ref()
        .and_then(|c| c.get("iss"))
        .and_then(Value::as_str)
        .filter(|i| i.starts_with("did:"))
        .map(str::to_string);

    let verified = if bound {
        crate::credentials::exchange::verify_presentation_with_anchors(
            &json!(compact),
            community,
            document_id,
            state.did_resolver.as_ref(),
            &state.x509_trust_anchors,
            now,
        )
        .await
        .ok()
    } else {
        None
    };
    let issuer_reachable = match &issuer {
        Some(i) => obtainable(state, base_did(i)).await,
        None => true,
    };
    let proof_or_unknown = |pass: bool| {
        if pass {
            Step::Pass
        } else if !issuer_reachable {
            Step::Unknown("didDocument")
        } else {
            Step::Fail
        }
    };

    steps.push((Check::Binding, if bound { Step::Pass } else { Step::Fail }));
    let (holder_step, subject) = match &verified {
        Some(v) => {
            let kid = crate::directory::present::kb_jwt_kid(compact);
            let is_signer = crate::directory::present::holder_is_member(
                state,
                &v.holder_did,
                kid.as_deref(),
                signer,
            )
            .await;
            let subject = v
                .claims
                .get("sub")
                .or_else(|| v.claims.get("id"))
                .and_then(Value::as_str)
                .map(|s| base_did(s).to_string());
            let about_signer = subject.as_deref().is_none_or(|s| s == signer);
            (
                if is_signer && about_signer && v.holder_bound {
                    Step::Pass
                } else {
                    Step::Fail
                },
                signer.to_string(),
            )
        }
        // The verifier refused it, so who holds it is not proven; `proof` says why.
        None => (proof_or_unknown(false), signer.to_string()),
    };
    steps.push((Check::Holder, holder_step));
    steps.push((Check::Proof, proof_or_unknown(verified.is_some())));
    // Checked with the proof above (see the function's documentation).
    steps.push((
        Check::Validity,
        if verified.is_some() {
            Step::Pass
        } else {
            proof_or_unknown(false)
        },
    ));
    let revoked = match &verified {
        Some(v) => status(state, v.credential_status.as_ref(), issuer.as_deref()).await,
        None => Step::Pass,
    };
    steps.push((Check::Revoked, revoked));
    conclude(&steps, issuer, subject)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_failure_wins_and_an_unknown_only_without_one() {
        let iss = Some("did:example:i".to_string());
        let out = conclude(
            &[
                (Check::Binding, Step::Pass),
                (Check::Holder, Step::Pass),
                (Check::Proof, Step::Unknown("didDocument")),
                (Check::Validity, Step::Fail),
                (Check::Revoked, Step::Unknown("statusList")),
            ],
            iss.clone(),
            "did:example:s".into(),
        );
        assert_eq!(
            out,
            Outcome::Failed {
                check: Check::Validity,
                issuer: iss.clone()
            }
        );
        let out = conclude(
            &[
                (Check::Binding, Step::Pass),
                (Check::Revoked, Step::Unknown("statusList")),
            ],
            iss.clone(),
            "did:example:s".into(),
        );
        assert_eq!(
            out,
            Outcome::Indeterminate {
                reference: "statusList"
            }
        );
        let out = conclude(&[(Check::Binding, Step::Pass)], iss, "did:example:s".into());
        assert!(matches!(out, Outcome::Passed(p) if p.subject == "did:example:s"));
    }
}
