//! `vtc/directory/card/present/0.1`: a member fills `credential`-sourced
//! fields from a credential they present. The community verifies the
//! presentation, keeps only the claim each named field reads with its issuer,
//! and forgets the rest (items 3 – 6).
//!
//! What "the presentation" proves is checked here, not in the handler, so the
//! rule has one place: the issuer's proof and the holder's, the binding to this
//! document and this community, the credential's window and status, and that
//! its holder is the member. A presentation another member obtained is a
//! correctly signed, correctly addressed document; the holder rule is the only
//! thing that stops it landing on this member's card.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::model::{FieldDef, FieldSource, FieldState, FieldType};
use crate::credentials::VerifiedPresentation;
use crate::credentials::vm_resolver::DidVmResolver;
use crate::server::AppState;

/// The longest text a verified value holds (`VerifiedValue.value`).
const MAX_VALUE_CHARS: usize = 2000;
/// The longest `credentialType` a verified value names.
const MAX_TYPE_CHARS: usize = 128;

/// Why a presentation wrote nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentError {
    FieldUnknown(String),
    FieldNotWritable(String),
    /// The presentation does not verify, is not bound to this document and
    /// community, or is not the member's. The reason is logged, never
    /// answered: it would say which check a forged presentation got past.
    PresentationInvalid(String),
    IssuerNotAccepted(String),
    ClaimMissing(String),
}

/// What a field accepts, read from its `constraints.claim`.
#[derive(Debug, Clone)]
pub struct Selector {
    pub credential_type: String,
    pub claim_path: String,
    pub issuers: Option<Vec<String>>,
}

impl Selector {
    fn of(field: &FieldDef) -> Option<Self> {
        let c = field.constraints.as_ref()?.get("claim")?;
        Some(Self {
            credential_type: c.get("credentialType")?.as_str()?.to_string(),
            claim_path: c.get("claimPath")?.as_str()?.to_string(),
            issuers: c.get("issuers").and_then(Value::as_array).map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            }),
        })
    }
}

/// Items 2 and 4's field checks, before anything is verified: every named
/// field is an active, `credential`-sourced claim field.
pub fn selectors(
    schema: &[FieldDef],
    named: &[String],
) -> Result<Vec<(String, Selector)>, PresentError> {
    let mut out = Vec::with_capacity(named.len());
    for key in named {
        let f = schema
            .iter()
            .find(|f| &f.key == key && f.state == FieldState::Active)
            .ok_or_else(|| PresentError::FieldUnknown(key.clone()))?;
        if f.source != FieldSource::Credential || f.kind != FieldType::Claim {
            return Err(PresentError::FieldNotWritable(key.clone()));
        }
        // A claim field always names its selector (`fields::check_constraints`).
        let s = Selector::of(f).ok_or_else(|| PresentError::FieldNotWritable(key.clone()))?;
        out.push((key.clone(), s));
    }
    Ok(out)
}

/// One credential of a verified presentation, as the fields read it.
#[derive(Debug, Clone)]
pub struct Presented {
    pub issuer: String,
    pub types: Vec<String>,
    /// The most specific type, for the badge.
    pub concrete_type: Option<String>,
    /// `credentialSubject` (DI) or the disclosed claims (SD-JWT): what a
    /// `claimPath` points into.
    pub subject: Value,
    pub valid_until: Option<DateTime<Utc>>,
}

/// The `kid` of an SD-JWT presentation's key-binding JWT: the last `~`
/// segment's protected header. Read only to find which of the member's keys
/// the holder key claims to be; the signature under it has already verified.
fn kb_jwt_kid(compact: &str) -> Option<String> {
    let kb = compact.rsplit('~').next().filter(|s| !s.is_empty())?;
    let header = kb.split('.').next()?;
    let bytes = URL_SAFE_NO_PAD.decode(header).ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get("kid").and_then(Value::as_str).map(str::to_string)
}

/// Whether `holder` — the DID a presentation proved control of — is the
/// member (item 3): the membership DID itself, or, for an SD-JWT whose holder
/// key is a `did:key`, a key the member's own DID document lists for
/// authentication and the key-binding JWT names (`kid` under the member's DID).
async fn holder_is_member(
    state: &AppState,
    holder: &str,
    kb_kid: Option<&str>,
    member: &str,
) -> bool {
    use vta_sdk::trust_task_proof::purpose::PurposeVmResolver as _;
    if holder == member {
        return true;
    }
    let Some(kid) = kb_kid else {
        return false;
    };
    let Some((did, fragment)) = kid.split_once('#') else {
        return false;
    };
    if did != member || fragment.is_empty() {
        return false;
    }
    let resolver = DidVmResolver::new(state.did_resolver.clone());
    match resolver
        .resolve_vm_for_purpose(kid, vti_common::auth::ProofPurpose::Authentication)
        .await
    {
        Ok(key) => vta_sdk::jws::JwsKey::from_resolved(&key)
            .map(|k| k.did_key() == holder)
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// `did` without its fragment.
fn base_did(did: &str) -> &str {
    did.split('#').next().unwrap_or(did)
}

/// The presentation's members a Data Integrity holder proof may also carry:
/// `challenge` and `domain`. The proof library does not sign them, so the
/// binding rests on the presentation's own `nonce` and `domain`, which the
/// holder proof covers; a proof that names others is refused rather than read
/// past.
fn proof_options_agree(vp: &Value, document_id: &str, community: &str) -> bool {
    let proofs: Vec<&Value> = match vp.get("proof") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(p) => vec![p],
        None => return false,
    };
    proofs.iter().all(|p| {
        p.get("challenge")
            .is_none_or(|c| c.as_str() == Some(document_id))
            && p.get("domain")
                .is_none_or(|d| d.as_str() == Some(community))
    })
}

/// Verify `presentation` for `member`, bound to `document_id` and `community`
/// (item 3). Returns each credential it carried.
pub async fn verify(
    state: &AppState,
    presentation: &Value,
    document_id: &str,
    community: &str,
    member: &str,
    now: DateTime<Utc>,
) -> Result<Vec<Presented>, PresentError> {
    let invalid = |why: String| PresentError::PresentationInvalid(why);
    // `verify_vp_token` reads an object as a map of presentations, so a DI
    // presentation goes in under a name of its own.
    let (token, kb_kid) = match presentation {
        Value::Object(_) => {
            if !proof_options_agree(presentation, document_id, community) {
                return Err(invalid(
                    "a proof's challenge or domain is not this one".into(),
                ));
            }
            (json!({ "card": presentation }), None)
        }
        Value::String(s) => (presentation.clone(), kb_jwt_kid(s)),
        _ => return Err(invalid("not a presentation".into())),
    };
    let set = crate::credentials::verify_vp_token_with_anchors(
        &token,
        community,
        document_id,
        state.did_resolver.as_ref(),
        &state.x509_trust_anchors,
        now,
    )
    .await
    .map_err(|e| invalid(e.to_string()))?;

    if let Some(h) = presentation.get("holder") {
        let named = h.as_str().or_else(|| h.get("id").and_then(Value::as_str));
        if named != Some(set.holder.as_str()) {
            return Err(invalid("the presentation names another holder".into()));
        }
    }
    if !holder_is_member(state, &set.holder, kb_kid.as_deref(), member).await {
        return Err(invalid("the holder is not the signer's membership".into()));
    }

    let fetcher = crate::routes::join_requests::present::credential_status_fetcher(state);
    let mut out = Vec::with_capacity(set.presentations.len());
    for p in set.presentations {
        out.push(presented(p, &set.holder, &fetcher).await?);
    }
    Ok(out)
}

async fn presented(
    p: VerifiedPresentation,
    holder: &str,
    fetcher: &dyn crate::recognition::verify::StatusListFetcher,
) -> Result<Presented, PresentError> {
    let invalid = |why: &str| PresentError::PresentationInvalid(why.to_string());
    if !p.holder_bound {
        return Err(invalid("the presentation does not prove its holder"));
    }
    // A credential about someone else is not the member's, whoever holds it.
    if let Some(subject) = p.claims.get("id").and_then(Value::as_str)
        && subject.starts_with("did:")
        && base_did(subject) != holder
    {
        return Err(invalid("the credential is about someone else"));
    }
    let status = crate::routes::join_requests::present::resolve_presented_status(
        p.credential_status.as_ref(),
        Some(&p.issuer_did),
        fetcher,
    )
    .await;
    if status != crate::ceremony::CredentialStatus::Valid {
        return Err(invalid("the credential is not in force"));
    }
    Ok(Presented {
        issuer: p.issuer_did,
        types: p.types,
        concrete_type: p.vct,
        subject: p.claims,
        valid_until: p.valid_until,
    })
}

/// A claim a verified value may hold: a string up to 2000 characters, a
/// boolean or a number.
fn claim_value(subject: &Value, pointer: &str) -> Option<Value> {
    let v = subject.pointer(pointer)?;
    match v {
        Value::String(s) if s.chars().count() <= MAX_VALUE_CHARS => Some(v.clone()),
        Value::Bool(_) | Value::Number(_) => Some(v.clone()),
        _ => None,
    }
}

/// Whether `issuer` is one a field accepts: one it lists, else one the
/// community trusts — its own DID, one its trust registry recognises, or one
/// its swiyu trust vouches for (the join criteria's `recognised`).
async fn issuer_accepted(state: &AppState, selector: &Selector, issuer: &str) -> bool {
    if !issuer.starts_with("did:") {
        return false;
    }
    match &selector.issuers {
        Some(list) => list.iter().any(|i| i == issuer),
        None => {
            let own = state.config.read().await.vtc_did.clone();
            crate::join::criteria::issuer_admitted(
                state,
                own.as_deref(),
                crate::schemas::accepts::CredentialIssuers::Recognised,
                issuer,
            )
            .await
        }
    }
}

/// Item 4 and 5: the value each named field takes from `presented`, or `None`
/// to clear it (only when `clear`).
pub async fn answer(
    state: &AppState,
    selectors: &[(String, Selector)],
    presented: &[Presented],
    clear: bool,
    now: DateTime<Utc>,
) -> Result<BTreeMap<String, Option<Value>>, PresentError> {
    let mut out = BTreeMap::new();
    for (key, s) in selectors {
        let of_type: Vec<&Presented> = presented
            .iter()
            .filter(|p| p.types.iter().any(|t| t == &s.credential_type))
            .collect();
        let mut accepted = Vec::new();
        for p in &of_type {
            if issuer_accepted(state, s, &p.issuer).await {
                accepted.push(*p);
            }
        }
        if !of_type.is_empty() && accepted.is_empty() {
            return Err(PresentError::IssuerNotAccepted(key.clone()));
        }
        let found = accepted
            .iter()
            .find_map(|p| claim_value(&p.subject, &s.claim_path).map(|v| (*p, v)));
        match found {
            Some((p, value)) => {
                let credential_type = p
                    .concrete_type
                    .clone()
                    .filter(|t| t.chars().count() <= MAX_TYPE_CHARS)
                    .unwrap_or_else(|| s.credential_type.clone());
                let mut v = json!({
                    "value": value,
                    "issuer": p.issuer,
                    "credentialType": credential_type,
                    "verifiedAt": now,
                });
                if let Some(until) = p.valid_until {
                    v["validUntil"] = json!(until);
                }
                out.insert(key.clone(), Some(v));
            }
            None if clear => {
                out.insert(key.clone(), None);
            }
            None => return Err(PresentError::ClaimMissing(key.clone())),
        }
    }
    Ok(out)
}

/// Whether a stored verified value's `validUntil` has passed (item 7).
pub fn lapsed(value: &Value, now: DateTime<Utc>) -> bool {
    value
        .get("validUntil")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .is_some_and(|t| t.with_timezone(&Utc) <= now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claim_is_a_short_string_a_boolean_or_a_number() {
        let subject = json!({
            "registration": "REG-1",
            "adult": true,
            "year": 2020,
            "address": { "city": "x" },
            "long": "x".repeat(2001),
        });
        assert_eq!(claim_value(&subject, "/registration"), Some(json!("REG-1")));
        assert_eq!(claim_value(&subject, "/adult"), Some(json!(true)));
        assert_eq!(claim_value(&subject, "/year"), Some(json!(2020)));
        assert_eq!(claim_value(&subject, "/address/city"), Some(json!("x")));
        assert_eq!(claim_value(&subject, "/address"), None);
        assert_eq!(claim_value(&subject, "/long"), None);
        assert_eq!(claim_value(&subject, "/missing"), None);
    }

    #[test]
    fn the_key_binding_jwt_names_its_key() {
        let header =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"kb+jwt","kid":"did:example:m#k"}"#);
        let compact = format!("issuer.jwt.sig~disc~{header}.payload.sig");
        assert_eq!(kb_jwt_kid(&compact).as_deref(), Some("did:example:m#k"));
        assert_eq!(kb_jwt_kid("issuer.jwt.sig~disc~"), None);
    }

    #[test]
    fn a_proof_naming_another_challenge_is_refused() {
        let vp = json!({ "proof": { "challenge": "urn:uuid:1", "domain": "did:example:c" } });
        assert!(proof_options_agree(&vp, "urn:uuid:1", "did:example:c"));
        assert!(!proof_options_agree(&vp, "urn:uuid:2", "did:example:c"));
        assert!(!proof_options_agree(&vp, "urn:uuid:1", "did:example:d"));
        assert!(proof_options_agree(
            &json!({ "proof": {} }),
            "urn:uuid:1",
            "did:example:c"
        ));
    }

    #[test]
    fn a_value_lapses_at_its_valid_until() {
        let now = Utc::now();
        let past = json!({ "validUntil": (now - chrono::Duration::seconds(1)).to_rfc3339() });
        let future = json!({ "validUntil": (now + chrono::Duration::days(1)).to_rfc3339() });
        assert!(lapsed(&past, now));
        assert!(!lapsed(&future, now));
        assert!(!lapsed(&json!({}), now));
    }
}
