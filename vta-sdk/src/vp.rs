//! DCQL credential selection + holder-bound OID4VP `vp_token` assembly.
//!
//! Two steps that mirror what a wallet does when answering a verifier's DCQL
//! query — the query a VTC carries in `join-requests/manifest`,
//! `join-requests/status-response`, or `credential-exchange/query`:
//!
//! 1. [`select_credentials`] — evaluate a DCQL `presentation_definition`
//!    against the credentials a holder holds, returning the satisfying
//!    selection (which held credential answers which credential-query, plus the
//!    claim paths the query asked to disclose).
//! 2. [`build_vp_token`] — assemble a holder-bound OID4VP `vp_token` from that
//!    selection, signing each presentation with the holder's `eddsa-jcs-2022`
//!    Data-Integrity key and binding the verifier `nonce` + `audience`.
//!
//! The matcher is [`affinidi_openid4vp::DcqlQuery`] — the workspace's DCQL
//! engine. This module is the missing client-side wrapper: nothing in the
//! published tree previously turned a `presentation_definition` + a set of held
//! credentials into a signed `vp_token`, so every consumer (OpenVTC,
//! `vta-mobile-core`, …) would have re-implemented selection + assembly.
//!
//! The `vp_token` shape produced here is the canonical DCQL object — a JSON map
//! keyed by credential-query id whose values are W3C Data-Integrity Verifiable
//! Presentations — exactly what `vtc-service`'s join verifier (`verify_vp_token`
//! → `verify_di_vp`) consumes: a holder `eddsa-jcs-2022` proof with
//! `proofPurpose: authentication` over a VP carrying `nonce` + `domain`, each
//! embedded credential keeping its own issuer proof.
//!
//! ## Disclosure
//!
//! `eddsa-jcs-2022` Data-Integrity VCs cannot be redacted, so [`build_vp_token`]
//! presents each selected credential **whole**. `disclosed_paths` from the DCQL
//! match is carried on [`SelectedCredential`] for callers (and for future
//! selective-disclosure formats — SD-JWT-VC / BBS+), but does not narrow a DI
//! presentation. This mirrors the server-side `present_di_vc` behaviour.

use std::collections::HashMap;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
use affinidi_openid4vp::{CandidateCredential, ClaimPathSegment, DcqlQuery, Oid4vpError};
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::{Value, json};

/// W3C credentials v2 context — the VP envelope's `@context`.
const VC_V2_CONTEXT_URL: &str = "https://www.w3.org/ns/credentials/v2";

/// Errors from DCQL selection / `vp_token` assembly.
#[derive(Debug, thiserror::Error)]
pub enum VpError {
    /// The `presentation_definition` was not a valid DCQL query, or no held
    /// credential satisfied a required credential-set.
    #[error("DCQL: {0}")]
    Dcql(#[from] Oid4vpError),

    /// The matcher returned a candidate id that is not in the supplied `held`
    /// set. Indicates a programming error (mismatched ids), not bad input.
    #[error("DCQL match referenced unknown candidate id `{0}`")]
    UnknownCandidate(String),

    /// The selection was empty — there is nothing to present.
    #[error("DCQL match produced no credentials to present")]
    EmptySelection,

    /// Signing a presentation with the holder key failed.
    #[error("sign vp_token presentation: {0}")]
    Sign(String),

    /// (De)serializing a VP / proof failed.
    #[error("serialize vp_token: {0}")]
    Serialize(String),
}

/// A credential the holder holds, in the shape the DCQL matcher needs.
///
/// `claims` is the JSON object a DCQL claim `path` walks (for a W3C VC this is
/// typically the `credentialSubject`); `vc` is the **full signed credential**
/// embedded verbatim into the presentation (it must already carry its issuer
/// proof — the verifier re-checks it). Keeping the two separate lets the matcher
/// read claims without the presentation layer having to parse a wire credential.
#[derive(Debug, Clone)]
pub struct HeldCredential {
    /// Caller-chosen identifier, echoed back through the match. Unique within a
    /// `select_credentials` call.
    pub id: String,
    /// Credential format, compared against the DCQL `format` (e.g. `ldp_vc`,
    /// `dc+sd-jwt`, `jwt_vc_json`).
    pub format: String,
    /// The credential's claims as a JSON object — the tree a claim `path` walks.
    pub claims: Value,
    /// SD-JWT-VC type, matched against a query's `meta.vct_values` when present.
    pub vct: Option<String>,
    /// mdoc doctype, matched against a query's `meta.doctype_value` when present.
    pub doctype: Option<String>,
    /// Whether this credential can prove cryptographic holder binding. A DCQL
    /// query that requires holder binding (the default) will not match a
    /// candidate that cannot.
    pub supports_holder_binding: bool,
    /// The full signed credential, embedded verbatim into the VP.
    pub vc: Value,
}

impl HeldCredential {
    fn to_candidate(&self) -> CandidateCredential {
        CandidateCredential {
            id: self.id.clone(),
            format: self.format.clone(),
            claims: self.claims.clone(),
            vct: self.vct.clone(),
            doctype: self.doctype.clone(),
            supports_holder_binding: self.supports_holder_binding,
        }
    }
}

/// One credential-query the DCQL request selected, paired with the held
/// credential that satisfied it and the claim paths the query asked to disclose.
#[derive(Debug, Clone)]
pub struct SelectedCredential {
    /// The DCQL `credentials[].id` this entry answers.
    pub credential_query_id: String,
    /// The held credential chosen to satisfy that query.
    pub credential: HeldCredential,
    /// Claim paths the query asked to disclose. **Empty** means "no per-claim
    /// constraint" — the query named no `claims`. For `eddsa-jcs-2022` DI VCs
    /// this is informational only (the whole credential is presented).
    pub disclosed_paths: Vec<Vec<ClaimPathSegment>>,
}

/// The satisfying selection produced by [`select_credentials`]: the credentials
/// that, together, answer the DCQL `presentation_definition`.
///
/// One entry per `(credential-query → held credential)` pairing, in
/// credential-query order. A query marked `multiple` in the DCQL may contribute
/// several entries with the same `credential_query_id`.
#[derive(Debug, Clone)]
pub struct CandidateSet {
    /// The matched credentials, in credential-query order.
    pub entries: Vec<SelectedCredential>,
}

impl CandidateSet {
    /// True iff nothing was selected.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Select which held credentials satisfy a DCQL `presentation_definition`.
///
/// `presentation_definition` is the DCQL query JSON a verifier carries (the
/// `join-requests/manifest` `presentation_definition`, a deferred
/// `status-response`, or a `credential-exchange/query`). It is parsed and
/// validated via [`DcqlQuery::from_json`], then matched against `held`.
///
/// Returns the satisfying selection. Errors with [`VpError::Dcql`] if the query
/// is malformed or no held credential satisfies a required credential-set.
pub fn select_credentials(
    presentation_definition: &Value,
    held: &[HeldCredential],
) -> Result<CandidateSet, VpError> {
    let query = DcqlQuery::from_json(presentation_definition)?;
    let candidates: Vec<CandidateCredential> =
        held.iter().map(HeldCredential::to_candidate).collect();
    let dcql_match = query.match_credentials(&candidates)?;

    let by_id: HashMap<&str, &HeldCredential> = held.iter().map(|h| (h.id.as_str(), h)).collect();

    let mut entries = Vec::with_capacity(dcql_match.matches.len());
    for m in dcql_match.matches {
        let cred = by_id
            .get(m.candidate_id.as_str())
            .ok_or_else(|| VpError::UnknownCandidate(m.candidate_id.clone()))?;
        entries.push(SelectedCredential {
            credential_query_id: m.credential_query_id,
            credential: (*cred).clone(),
            disclosed_paths: m.disclosed_paths,
        });
    }

    Ok(CandidateSet { entries })
}

/// Assemble a holder-bound OID4VP `vp_token` from a [`CandidateSet`].
///
/// Produces the canonical DCQL `vp_token` object: a JSON map keyed by
/// credential-query id. Each value is a W3C Data-Integrity Verifiable
/// Presentation embedding that query's selected credential(s), signed with the
/// holder's `eddsa-jcs-2022` key (`holder_signer`) under
/// `proofPurpose: authentication`. The verifier `nonce` and `audience` are
/// bound into the signed VP (`nonce` + `domain`), so freshness + audience are
/// covered by the holder signature — the same binding `vtc-service`'s
/// `verify_di_vp` checks.
///
/// `holder_signer.id` is the holder DID (its `#fragment`, if any, is the
/// verification method); the DID portion becomes the VP `holder`.
///
/// Errors with [`VpError::EmptySelection`] if `candidates` is empty.
pub async fn build_vp_token(
    candidates: &CandidateSet,
    holder_signer: &Secret,
    nonce: &str,
    audience: &str,
) -> Result<Value, VpError> {
    if candidates.is_empty() {
        return Err(VpError::EmptySelection);
    }

    let holder_did = holder_signer
        .id
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(holder_signer.id.as_str());

    // Group selected credentials by credential-query id, preserving first-seen
    // (credential-query) order. Each query id becomes one presentation, whose
    // `verifiableCredential` array carries every credential matched for it (a
    // `multiple` query may match several).
    let mut order: Vec<String> = Vec::new();
    let mut grouped: HashMap<String, Vec<Value>> = HashMap::new();
    for entry in &candidates.entries {
        if !grouped.contains_key(&entry.credential_query_id) {
            order.push(entry.credential_query_id.clone());
        }
        grouped
            .entry(entry.credential_query_id.clone())
            .or_default()
            .push(entry.credential.vc.clone());
    }

    let mut vp_token = serde_json::Map::new();
    for query_id in order {
        let vcs = grouped.remove(&query_id).unwrap_or_default();
        let vp = build_di_vp(holder_did, vcs, nonce, audience, holder_signer).await?;
        vp_token.insert(query_id, vp);
    }

    Ok(Value::Object(vp_token))
}

/// Build one holder-bound DI VP wrapping `vcs`, signed by `holder_signer`.
async fn build_di_vp(
    holder_did: &str,
    vcs: Vec<Value>,
    nonce: &str,
    audience: &str,
    holder_signer: &Secret,
) -> Result<Value, VpError> {
    // Unsigned VP — sign over this exact shape minus `proof` (JCS is sensitive
    // to field presence), then insert the proof.
    let vp = json!({
        "@context": [VC_V2_CONTEXT_URL],
        "type": ["VerifiablePresentation"],
        "holder": holder_did,
        "verifiableCredential": vcs,
        "nonce": nonce,
        "domain": audience,
    });

    let proof = DataIntegrityProof::sign(
        &vp,
        holder_signer,
        SignOptions::new()
            .with_proof_purpose("authentication")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .map_err(|e| VpError::Sign(e.to_string()))?;

    let mut signed = vp;
    signed.as_object_mut().expect("vp is an object").insert(
        "proof".into(),
        serde_json::to_value(proof).map_err(|e| VpError::Serialize(e.to_string()))?,
    );
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_data_integrity::{DidKeyResolver, VerifyOptions};

    /// A `did:key` Ed25519 `Secret` from a fixed seed, with `id` set to
    /// `<did>#<multibase>` (the verification-method shape the signer expects).
    fn test_secret(seed_byte: u8) -> Secret {
        let seed = [seed_byte; 32];
        let mut secret = Secret::generate_ed25519(None, Some(&seed));
        let pub_mb = secret.get_public_keymultibase().unwrap();
        secret.id = format!("did:key:{pub_mb}#{pub_mb}");
        secret
    }

    fn did_of(secret: &Secret) -> String {
        secret.id.split_once('#').unwrap().0.to_string()
    }

    /// A signed `eddsa-jcs-2022` DI VC issued by `issuer` to `subject_did`.
    async fn signed_vc(issuer: &Secret, subject_did: &str, mut subject: Value) -> Value {
        subject
            .as_object_mut()
            .unwrap()
            .insert("id".into(), json!(subject_did));
        let vc = json!({
            "@context": [VC_V2_CONTEXT_URL],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": did_of(issuer),
            "credentialSubject": subject,
        });
        let proof = DataIntegrityProof::sign(
            &vc,
            issuer,
            SignOptions::new().with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .unwrap();
        let mut signed = vc;
        signed
            .as_object_mut()
            .unwrap()
            .insert("proof".into(), serde_json::to_value(proof).unwrap());
        signed
    }

    /// A manifest-style DCQL: one membership credential disclosing `givenName`.
    fn membership_pd() -> Value {
        json!({
            "credentials": [{
                "id": "membership",
                "format": "ldp_vc",
                "claims": [ { "path": ["givenName"] } ]
            }]
        })
    }

    fn held(id: &str, subject: Value, vc: Value) -> HeldCredential {
        HeldCredential {
            id: id.to_string(),
            format: "ldp_vc".to_string(),
            claims: subject,
            vct: None,
            doctype: None,
            supports_holder_binding: true,
            vc,
        }
    }

    #[test]
    fn select_credentials_matches_the_membership_query() {
        let subject = json!({ "givenName": "Ada", "memberSince": "2024-01-01" });
        let set = select_credentials(
            &membership_pd(),
            &[held(
                "vmc",
                subject.clone(),
                json!({"credentialSubject": subject}),
            )],
        )
        .expect("a matching credential");

        assert_eq!(set.entries.len(), 1);
        let entry = &set.entries[0];
        assert_eq!(entry.credential_query_id, "membership");
        assert_eq!(entry.credential.id, "vmc");
        assert_eq!(
            entry.disclosed_paths,
            vec![vec![ClaimPathSegment::Name("givenName".into())]]
        );
    }

    #[test]
    fn select_credentials_errors_when_no_credential_satisfies_the_query() {
        // No `givenName` claim → the credential-query matches nothing.
        let subject = json!({ "familyName": "Lovelace" });
        let err = select_credentials(
            &membership_pd(),
            &[held(
                "vmc",
                subject.clone(),
                json!({"credentialSubject": subject}),
            )],
        )
        .expect_err("no match");
        assert!(matches!(err, VpError::Dcql(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn build_vp_token_produces_a_holder_bound_di_vp_that_verifies() {
        let holder = test_secret(7);
        let issuer = test_secret(9);
        let holder_did = did_of(&holder);

        let subject = json!({ "givenName": "Ada", "memberSince": "2024-01-01" });
        let vc = signed_vc(&issuer, &holder_did, subject.clone()).await;
        let set = select_credentials(
            &membership_pd(),
            &[held("vmc", vc["credentialSubject"].clone(), vc.clone())],
        )
        .unwrap();

        let token = build_vp_token(&set, &holder, "nonce-123", "did:web:community.example")
            .await
            .expect("build vp_token");

        // Canonical DCQL vp_token: an object keyed by credential-query id.
        let vp = token
            .as_object()
            .and_then(|m| m.get("membership"))
            .expect("vp_token keyed by `membership`");
        assert_eq!(vp["holder"], json!(holder_did));
        assert_eq!(vp["nonce"], json!("nonce-123"));
        assert_eq!(vp["domain"], json!("did:web:community.example"));
        assert_eq!(
            vp["verifiableCredential"][0]["credentialSubject"]["givenName"],
            json!("Ada")
        );

        // The holder binding the VTC's `verify_di_vp` checks: an
        // `eddsa-jcs-2022` proof, `proofPurpose: authentication`, verification
        // method under the holder DID, verifying over the VP minus its proof.
        let di: DataIntegrityProof = serde_json::from_value(vp["proof"].clone()).unwrap();
        assert_eq!(di.proof_purpose, "authentication");
        assert_eq!(
            di.verification_method.split('#').next().unwrap(),
            holder_did
        );
        let mut unsigned = vp.clone();
        unsigned.as_object_mut().unwrap().remove("proof");
        di.verify(&unsigned, &DidKeyResolver, VerifyOptions::new())
            .await
            .expect("holder proof verifies");
    }

    #[tokio::test]
    async fn build_vp_token_rejects_an_empty_selection() {
        let holder = test_secret(7);
        let err = build_vp_token(&CandidateSet { entries: vec![] }, &holder, "n", "aud")
            .await
            .expect_err("empty selection");
        assert!(matches!(err, VpError::EmptySelection));
    }
}
