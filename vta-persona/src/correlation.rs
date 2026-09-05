//! The blinded correlation index.
//!
//! Multiple personas exist to be unlinkable, and a composition tool is a machine
//! for accidentally linking them: the same value in two profiles correlates the
//! personas presenting them, permanently, for anyone who sees both. The holder
//! will not notice while composing, which is why this is a first-class output
//! rather than a lint.
//!
//! # Why a keyed hash and not an index
//!
//! Answering "does this value appear elsewhere" needs exact-match lookup and
//! nothing more. A plaintext index would provide it and would also put every
//! value the holder holds into a structure a database dump reveals — enlarging
//! the risk the index exists to measure.
//!
//! So the index is keyed by `HMAC-SHA256(agent_key, canonical(value))`. Exact
//! match works; a dump reveals nothing; and prefix or substring search over
//! values is **out of scope by construction**, which is a deliberate trade
//! rather than a missing feature.
//!
//! # Scope
//!
//! The index is **agent-scoped**, which is what lets it see the risk it most
//! needs to report: the same value presented by two personas in two different
//! *contexts*. A per-context index cannot see that by construction, and the
//! whole reason the pool sits above the context boundary is to make this
//! possible.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// A blinded index key for one value.
///
/// Canonicalisation is JSON with sorted object members, so that two values a
/// holder would consider identical hash identically regardless of how a producer
/// happened to serialise them. Without it, `{"a":1,"b":2}` and `{"b":2,"a":1}`
/// would be two different facts and the guard would miss the reuse it exists to
/// catch.
#[must_use]
pub fn blind(agent_key: &[u8; 32], value: &serde_json::Value) -> String {
    let mut mac = HmacSha256::new_from_slice(agent_key).expect("HMAC accepts any key length");
    mac.update(canonical(value).as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// Whether two blinded keys match, in constant time.
///
/// A timing side channel here would let an attacker who can submit candidate
/// values learn which of them the holder already holds — turning the guard into
/// an oracle over the pool it protects.
#[must_use]
pub fn matches(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Deterministic JSON with object members in sorted order.
fn canonical(value: &serde_json::Value) -> String {
    use std::fmt::Write as _;
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            let mut s = String::from("{");
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                let _ = write!(
                    s,
                    "{}:{}",
                    serde_json::Value::String((*k).clone()),
                    canonical(&map[*k])
                );
            }
            s.push('}');
            s
        }
        serde_json::Value::Array(items) => {
            let mut s = String::from("[");
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&canonical(v));
            }
            s.push(']');
            s
        }
        other => other.to_string(),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// How strongly a disclosure of this claim would link the holder.
///
/// The inversion here is easy to get backwards and is the reason this is a
/// function rather than a field. **A credential presented whole correlates more
/// than a self-asserted value**, because the issuer's signature is identical at
/// every verifier — while a derived proof correlates *less*, because it differs
/// on every presentation.
///
/// So severity is a function of the value *and* the proof rung together. Scoring
/// on provenance alone would rank an attested claim as safer than a typed one
/// and push holders toward the riskier option.
#[must_use]
pub fn severity(
    reused_elsewhere: bool,
    provenance_is_credential: bool,
    rung: crate::ProofRung,
) -> Severity {
    use crate::ProofRung as R;
    match (provenance_is_credential, rung) {
        // Unlinkable proofs disclose nothing reusable, so the value being
        // reused elsewhere does not link anything through THIS disclosure.
        (true, R::Predicate | R::Derived) => Severity::None,
        // A constant issuer signature links every presentation of it, whether
        // or not the value is reused.
        (true, R::SelectiveDisclosure | R::Whole) => Severity::High,
        // A self-asserted value is itself the join key, so it links exactly
        // when it is reused.
        (false, _) if reused_elsewhere => Severity::High,
        (false, _) => Severity::None,
    }
}

/// Advisory correlation severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    None,
    Low,
    High,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProofRung;

    const K: [u8; 32] = [7u8; 32];

    #[test]
    fn member_order_does_not_change_the_blinded_key() {
        // Two serialisations of the same fact must hash identically, or the
        // guard misses the reuse it exists to catch.
        let a: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        assert_eq!(blind(&K, &a), blind(&K, &b));
    }

    #[test]
    fn different_values_and_different_keys_diverge() {
        let v = serde_json::json!("+61 4");
        assert_ne!(blind(&K, &v), blind(&K, &serde_json::json!("+61 5")));
        // A different agent key yields a different index, so two agents'
        // indexes cannot be compared against each other.
        assert_ne!(blind(&K, &v), blind(&[9u8; 32], &v));
    }

    #[test]
    fn the_blinded_key_does_not_contain_the_value() {
        let v = serde_json::json!("secret-number");
        assert!(!blind(&K, &v).contains("secret"));
    }

    #[test]
    fn credential_backed_correlates_more_when_presented_whole() {
        // The inversion. A whole credential links every verifier that sees it,
        // even though it is "better evidence" than a typed value.
        assert_eq!(
            severity(false, true, ProofRung::Whole),
            Severity::High,
            "a whole credential links regardless of reuse"
        );
        // And correlates LESS than a reused self-asserted value when derived.
        assert_eq!(severity(true, true, ProofRung::Derived), Severity::None);
        assert_eq!(severity(true, false, ProofRung::Whole), Severity::High);
    }

    #[test]
    fn an_unreused_self_asserted_value_links_nothing() {
        assert_eq!(severity(false, false, ProofRung::Whole), Severity::None);
    }
}

// ─── Findings ────────────────────────────────────────────────────────────

use serde::Serialize;

/// One place the holder's identities link, and what can be done about it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub attribute_id: Option<String>,
    pub severity: &'static str,
    /// Plain-language cause. A severity with no explanation is a warning a
    /// holder learns to dismiss.
    pub why: String,
    pub shared_with_profile_count: usize,
    /// What the holder can actually do.
    ///
    /// `reissueCredentialToThisDid` matters more than it looks: without it, a
    /// holder told "this links your personas" has no action available but to
    /// abandon the attribute, and the honest fix — a credential re-issued
    /// against the persona actually using it — stays invisible unless the
    /// analysis names it.
    pub remedies: Vec<&'static str>,
}

impl crate::PersonaStore {
    /// Report where the holder's identities link.
    ///
    /// Accepts a **candidate** the holder is considering but has not written,
    /// which is the difference between a guard and a report: it can warn before
    /// the mistake rather than after. A candidate is analysed and never stored.
    pub async fn analyze_correlation(
        &self,
        attribute_id: Option<&str>,
        candidate: Option<&serde_json::Value>,
    ) -> Result<Vec<Finding>, vti_common::error::AppError> {
        let mut findings = Vec::new();

        if let Some(value) = candidate {
            let count = self.correlation_count(value, "").await?;
            if count > 0 {
                findings.push(Finding {
                    attribute_id: None,
                    severity: "high",
                    why: format!(
                        "this value is already held by {count} other attribute(s); presenting \
                         both links the personas that carry them, permanently, to anyone who \
                         sees both"
                    ),
                    shared_with_profile_count: count,
                    remedies: vec![
                        "useDifferentValue",
                        "reissueCredentialToThisDid",
                        "correlateDeliberately",
                        "proceedAndRecord",
                    ],
                });
            }
        }

        let subjects: Vec<crate::Attribute> = match attribute_id {
            Some(id) => self.get(id).await?.into_iter().collect(),
            None => self.list_attributes(None, true).await?,
        };

        for a in subjects {
            let Some(value) = &a.value else { continue };
            let count = self.correlation_count(value, &a.attribute_id).await?;
            if count == 0 {
                continue;
            }
            let credential_backed =
                matches!(a.provenance, crate::Provenance::CredentialBacked { .. });
            let rung = match &a.provenance {
                crate::Provenance::CredentialBacked { proof, .. } => {
                    proof.unwrap_or(crate::ProofRung::Whole)
                }
                _ => crate::ProofRung::Whole,
            };
            let sev = severity(true, credential_backed, rung);
            findings.push(Finding {
                attribute_id: Some(a.attribute_id.clone()),
                severity: match sev {
                    Severity::High => "high",
                    Severity::Low => "low",
                    Severity::None => "none",
                },
                why: if credential_backed {
                    format!(
                        "credential-backed and presented at the {rung:?} rung. A credential \
                         presented whole carries the same issuer signature to every verifier, \
                         so it links them however few claims each received"
                    )
                } else {
                    format!("the same value is held by {count} other attribute(s)")
                },
                shared_with_profile_count: count,
                remedies: if credential_backed {
                    vec![
                        "reissueCredentialToThisDid",
                        "correlateDeliberately",
                        "proceedAndRecord",
                    ]
                } else {
                    vec![
                        "useDifferentValue",
                        "correlateDeliberately",
                        "proceedAndRecord",
                    ]
                },
            });
        }

        Ok(findings)
    }
}
