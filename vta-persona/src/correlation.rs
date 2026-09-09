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
/// would be two different attributes and the guard would miss the reuse it exists to
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
        // Two serialisations of the same attribute must hash identically, or the
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

use std::collections::{BTreeSet, HashMap};

use serde::Serialize;

/// The published cap on `findings[].sharedWith` (`maxItems: 128`).
///
/// Enforced here rather than left to the response layer to catch. A finding
/// truncated to the cap still names 128 places the value has reached, which is
/// far past the point a holder is reading the list one row at a time; a
/// finding that overflows the cap is *dropped whole* by schema validation, and
/// the holder is told nothing at all about the value that has spread furthest.
const MAX_SHARED_WITH: usize = 128;

/// The published cap on `sharedWith[].disclosedTo` (`maxItems: 64`), for the
/// same reason.
const MAX_DISCLOSED_TO: usize = 64;

/// One place a shared value has actually reached.
///
/// Every member is optional and every one is **absent rather than null** when
/// it is unknown: the response schema types them `string` / `array`, neither
/// of which accepts `null`, so a `None` serialised as `null` fails validation
/// and takes the whole response with it.
///
/// The shape answers three widths of question with one type. A value sitting
/// in a profile that is bound nowhere carries only `profileId` — it is one
/// `binding/set` away from a disclosure and worth reporting, but there is no
/// context to name. A bound one adds `contextId` and `personaDid`, which is
/// what makes the finding actionable: a DID with no context beside it tells a
/// holder nothing they can act on. `disclosedTo` is the strongest reading —
/// not "this could link you" but "this already went to these verifiers".
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedWith {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// The facet this profile belongs to, where it belongs to one.
    ///
    /// Absent for a profile in no facet, and that is a real and common state
    /// rather than a gap: most profiles are unarranged until somebody arranges
    /// them. A consumer MUST NOT read absence as a facet of its own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facet_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persona_did: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub disclosed_to: Vec<String>,
}

/// Verifier DIDs a claim type has actually been presented to, keyed by the
/// binding that presented it: `(context_id, persona_did, claim_type)`.
///
/// Built once per analysis from a single pass over the disclosure log, rather
/// than queried per finding. The per-finding shape is the obvious one and is
/// quadratic: `analyze_correlation` with no `attributeId` walks the whole
/// pool, and each finding would re-scan every disclosure record in every
/// context to answer a question about one claim type.
type DisclosureIndex = HashMap<(String, String, String), BTreeSet<String>>;

/// Which facet each profile belongs to.
///
/// Built once per analysis, for the reason [`DisclosureIndex`] is: the
/// per-finding shape re-lists every facet for every finding, and
/// `analyze_correlation` with no `attributeId` walks the whole pool.
///
/// Empty is meaningful and is not the same as "not built" — see
/// [`FacetIndex::any`], which is what decides whether `crossesFacets` is
/// answered at all.
#[derive(Default)]
pub(crate) struct FacetIndex {
    by_profile: HashMap<String, String>,
    any: bool,
}

impl FacetIndex {
    /// Whether the holder keeps any facets. False means the question has no
    /// answer rather than the answer being "no crossing".
    pub(crate) fn any(&self) -> bool {
        self.any
    }

    pub(crate) fn of(&self, profile_id: &str) -> Option<&str> {
        self.by_profile.get(profile_id).map(String::as_str)
    }
}

/// One place the holder's identities link, and what can be done about it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub attribute_id: Option<String>,
    pub severity: &'static str,
    /// Plain-language cause. A severity with no explanation is a warning a
    /// holder learns to dismiss.
    ///
    /// Carries the count of other attributes holding the value, which is the
    /// one thing [`Finding::shared_with`] does not restate: that list is keyed
    /// on the *profiles and bindings* the value reaches, and two attributes
    /// referenced by one profile collapse to a single entry there.
    pub why: String,
    /// Where the value has actually gone.
    ///
    /// Identifiers, not a count — and that asymmetry with the write tasks is
    /// deliberate on both sides. `correlation_count` returns a bare number
    /// because it answers a *write*, where naming the holder's other
    /// compositions would disclose them to whatever tool made the write. This
    /// task is holder-authorized and exists so the holder can act, and nobody
    /// can act on a number: "this value appears in 3 other places" leaves them
    /// with no way to find those places short of reading every profile.
    ///
    /// Empty is a legitimate answer (a value shared with an attribute that no
    /// profile references), and it serialises as an absent member rather than
    /// an empty array, matching the schema's `default`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub shared_with: Vec<SharedWith>,
    /// Whether this linkage spans two or more of the holder's facets.
    ///
    /// **A second axis, not a restatement of `severity`.** `severity` says how
    /// strongly a disclosure would link the holder — a fact about provenance
    /// and proof rung, true whatever they intended. This says whether they
    /// would mind: a value shared between two profiles in the *same* facet is
    /// linkage they arranged on purpose, and alarming on it teaches people to
    /// dismiss alarms, which costs them the one that matters.
    ///
    /// `None` — omitted on the wire — where the holder keeps no facets at all,
    /// because `false` asserts that these identities sit in one part of their
    /// life and there is no such finding to make. The specification requires a
    /// consumer to read absence as *unknown*.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crosses_facets: Option<bool>,
    /// The distinct facets this linkage touches, so a consumer can name them.
    ///
    /// Identifiers, never names: the caller holds the facet records and can
    /// resolve one, and the name is the member of a facet worth protecting.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub facet_ids: Vec<String>,
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
    /// Every verifier each (context, persona, claim type) has presented to.
    ///
    /// One pass over the whole disclosure log, across every context — which is
    /// exactly why this is reachable only from a holder-authorized task. The
    /// same scan `disclosure/history` performs, and it sits behind the same
    /// gate.
    async fn disclosure_index(&self) -> Result<DisclosureIndex, vti_common::error::AppError> {
        let mut index = DisclosureIndex::new();
        for record in self
            .disclosure_history(&crate::HistoryQuery::default())
            .await?
        {
            for claim in &record.claims {
                index
                    .entry((
                        record.context_id.clone(),
                        record.persona_did.clone(),
                        claim.r#type.clone(),
                    ))
                    .or_default()
                    .insert(record.verifier_did.clone());
            }
        }
        Ok(index)
    }

    /// Where a value has reached: the profiles carrying it, the bindings
    /// pushing those profiles into a context, and — when the claim type is
    /// known — the verifiers each binding has actually presented it to.
    ///
    /// `claim_type` is `None` for a **candidate**, and that omission is
    /// correct rather than a gap. A candidate is a value the holder has not
    /// written, so there is no attribute and no claim type; the disclosures
    /// this scan could reach belong to the *other* attributes already holding
    /// the value, whose own findings report them under their own types.
    /// Attributing those disclosures to the candidate would tell the holder
    /// their unwritten value had already been presented somewhere, which is
    /// false. So `disclosedTo` is left **absent** — never null, never an empty
    /// array standing in for "unknown".
    async fn shared_with(
        &self,
        value: &serde_json::Value,
        excluding_attribute_id: &str,
        claim_type: Option<&str>,
        disclosures: &DisclosureIndex,
        facets: &FacetIndex,
    ) -> Result<Vec<SharedWith>, vti_common::error::AppError> {
        let blind = blind(&self.correlation_key, value);
        let others: Vec<String> = self
            .indexed_ids(&blind)
            .await?
            .into_iter()
            .filter(|id| id != excluding_attribute_id)
            .collect();

        // Deduplicated, and sorted by construction. One profile commonly
        // references several of the attributes sharing a value, and naming it
        // once per attribute would spend the schema's 128-entry budget saying
        // the same thing repeatedly — pushing the entries that name a
        // *different* place off the end.
        let mut profiles: BTreeSet<String> = BTreeSet::new();
        for id in &others {
            profiles.extend(self.referring_profiles(id).await?);
        }

        let mut out: Vec<SharedWith> = Vec::new();
        for profile_id in profiles {
            let bindings = self.bindings_to_anywhere(&profile_id).await?;
            if bindings.is_empty() {
                // A composition that carries the value but is bound nowhere.
                // Still worth naming — it is one `binding/set` away from being
                // a disclosure — but there is no context and no persona, and
                // those members stay absent rather than null.
                out.push(SharedWith {
                    facet_id: facets.of(&profile_id).map(str::to_owned),
                    profile_id: Some(profile_id),
                    ..Default::default()
                });
                continue;
            }
            for (context_id, persona_did) in bindings {
                let disclosed_to = claim_type
                    .and_then(|t| {
                        disclosures.get(&(context_id.clone(), persona_did.clone(), t.to_string()))
                    })
                    .map(|verifiers| {
                        verifiers
                            .iter()
                            .take(MAX_DISCLOSED_TO)
                            .cloned()
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                out.push(SharedWith {
                    facet_id: facets.of(&profile_id).map(str::to_owned),
                    profile_id: Some(profile_id.clone()),
                    context_id: Some(context_id),
                    persona_did: Some(persona_did),
                    disclosed_to,
                });
            }
        }

        out.truncate(MAX_SHARED_WITH);
        Ok(out)
    }

    /// Build the profile → facet index for one analysis.
    async fn facet_index(&self) -> Result<FacetIndex, vti_common::error::AppError> {
        let facets = self.list_facets().await?;
        let mut by_profile = HashMap::new();
        for facet in &facets {
            for face in &facet.face_ids {
                // A profile belongs to at most one facet — `put_facet` refuses
                // otherwise — so the first writer wins here and the second is
                // a state the store does not permit. Not an assertion: an index
                // is the wrong place to discover a store invariant, and picking
                // one answer keeps the analysis running either way.
                by_profile
                    .entry(face.clone())
                    .or_insert(facet.facet_id.clone());
            }
        }
        Ok(FacetIndex {
            by_profile,
            any: !facets.is_empty(),
        })
    }

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
        let disclosures = self.disclosure_index().await?;
        let facets = self.facet_index().await?;

        if let Some(value) = candidate {
            let count = self.correlation_count(value, "").await?;
            if count > 0 {
                let shared = self
                    .shared_with(value, "", None, &disclosures, &facets)
                    .await?;
                let (crosses_facets, facet_ids) = crossing(&shared, &facets);
                findings.push(Finding {
                    attribute_id: None,
                    severity: "high",
                    why: format!(
                        "this value is already held by {count} other attribute(s); presenting \
                         both links the personas that carry them, permanently, to anyone who \
                         sees both"
                    ),
                    shared_with: shared,
                    crosses_facets,
                    facet_ids,
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
            // Every value, sensitive ones included. The sensitivity control is
            // about what a listing *carries out*; here the values are hashed
            // against the correlation index and never leave — a `payment.card`
            // skipped for sensitivity would be a card whose reuse the holder is
            // never warned about.
            None => {
                self.list_attributes(None, crate::ValueVisibility::All)
                    .await?
                    .attributes
            }
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
            let shared = self
                .shared_with(
                    value,
                    &a.attribute_id,
                    Some(&a.r#type),
                    &disclosures,
                    &facets,
                )
                .await?;
            let (crosses_facets, facet_ids) = crossing(&shared, &facets);
            findings.push(Finding {
                attribute_id: Some(a.attribute_id.clone()),
                // The published enum is `{low, high}` — a finding has no
                // "none" rung, and emitting one was the second way this
                // response failed its own schema. The mapping is not a
                // workaround for that: `severity()` answers a narrower
                // question than a finding asks. `None` from it means *this
                // disclosure* links nothing, which is true of a credential
                // presented at the Derived or Predicate rung. A finding says
                // something wider — the value is reused, and the first time it
                // is presented at a linking rung it links — so the weakest
                // true thing a finding can say is `low`, never nothing at all.
                severity: match sev {
                    Severity::High => "high",
                    Severity::Low | Severity::None => "low",
                },
                // Both branches state the count, because `shared_with` below
                // does not: it is keyed on the profiles and bindings the value
                // reaches, so two attributes referenced by one profile appear
                // as one entry there. The count and the list answer different
                // questions and neither substitutes for the other.
                why: if credential_backed {
                    format!(
                        "credential-backed and presented at the {rung:?} rung. A credential \
                         presented whole carries the same issuer signature to every verifier, \
                         so it links them however few claims each received; the same value is \
                         held by {count} other attribute(s)"
                    )
                } else {
                    format!("the same value is held by {count} other attribute(s)")
                },
                shared_with: shared,
                crosses_facets,
                facet_ids,
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

/// Whether a set of locations spans two or more facets, and which.
///
/// **Only distinct, named facets count.** A profile belonging to no facet is
/// unarranged, not a second facet — count it as one and every holder who has
/// arranged one part of their life and not the rest sees a crossing on
/// everything they own, which is the dismissal problem arriving from the other
/// direction.
///
/// Returns `None` for the whole question when the holder keeps no facets: the
/// specification requires absence rather than `false`, because `false` asserts
/// these identities sit in one part of a life and an agent with no facets has
/// made no such finding.
fn crossing(shared: &[SharedWith], facets: &FacetIndex) -> (Option<bool>, Vec<String>) {
    if !facets.any() {
        return (None, Vec::new());
    }
    let distinct: BTreeSet<&str> = shared
        .iter()
        .filter_map(|s| s.facet_id.as_deref())
        .collect();
    (
        Some(distinct.len() >= 2),
        distinct.into_iter().map(str::to_owned).collect(),
    )
}

#[cfg(test)]
mod facet_crossing_tests {
    use super::*;

    fn at(profile: &str, facet: Option<&str>) -> SharedWith {
        SharedWith {
            profile_id: Some(profile.to_owned()),
            facet_id: facet.map(str::to_owned),
            ..Default::default()
        }
    }

    fn index(pairs: &[(&str, &str)]) -> FacetIndex {
        FacetIndex {
            by_profile: pairs
                .iter()
                .map(|(p, f)| ((*p).to_owned(), (*f).to_owned()))
                .collect(),
            any: !pairs.is_empty(),
        }
    }

    #[test]
    fn no_facets_means_the_question_has_no_answer() {
        // Absent, never `false`. `false` asserts these identities sit in one
        // part of the holder's life, and an agent with no facets has made no
        // such finding — the specification requires a consumer to read absence
        // as unknown, which it cannot do if we answer.
        let (crosses, ids) = crossing(&[at("p1", None), at("p2", None)], &FacetIndex::default());
        assert_eq!(crosses, None);
        assert!(ids.is_empty());
    }

    #[test]
    fn sharing_inside_one_facet_is_not_a_crossing() {
        // The linkage the holder arranged on purpose — a work email in every
        // work profile. Alarming on it teaches people to dismiss alarms.
        let facets = index(&[("p1", "w1"), ("p2", "w1")]);
        let (crosses, ids) = crossing(&[at("p1", Some("w1")), at("p2", Some("w1"))], &facets);
        assert_eq!(crosses, Some(false));
        assert_eq!(ids, vec!["w1".to_owned()]);
    }

    #[test]
    fn sharing_across_two_facets_is_the_finding_worth_raising() {
        let facets = index(&[("p1", "w1"), ("p2", "w2")]);
        let (crosses, ids) = crossing(&[at("p1", Some("w1")), at("p2", Some("w2"))], &facets);
        assert_eq!(crosses, Some(true));
        assert_eq!(ids, vec!["w1".to_owned(), "w2".to_owned()]);
    }

    #[test]
    fn an_unarranged_profile_is_not_a_second_facet() {
        // The defect this closes: counting "no facet" as a facet makes every
        // holder who has arranged one part of their life and not the rest see a
        // crossing on everything they own.
        let facets = index(&[("p1", "w1")]);
        let (crosses, ids) = crossing(&[at("p1", Some("w1")), at("p2", None)], &facets);
        assert_eq!(
            crosses,
            Some(false),
            "an unarranged profile read as a crossing"
        );
        assert_eq!(ids, vec!["w1".to_owned()]);
    }

    #[test]
    fn every_location_unarranged_is_no_crossing_but_still_answered() {
        // The holder keeps facets, so the question HAS an answer — it is just
        // "no". Distinct from the no-facets case above, which has none.
        let facets = index(&[("pX", "w1")]);
        let (crosses, ids) = crossing(&[at("p1", None), at("p2", None)], &facets);
        assert_eq!(crosses, Some(false));
        assert!(ids.is_empty());
    }

    #[test]
    fn the_facets_touched_are_distinct_and_ordered() {
        // Ordered so two findings over the same worlds list them the same way;
        // deduplicated so a world holding three of the sharing profiles is
        // named once.
        let facets = index(&[("p1", "w2"), ("p2", "w1"), ("p3", "w2")]);
        let (_, ids) = crossing(
            &[
                at("p1", Some("w2")),
                at("p2", Some("w1")),
                at("p3", Some("w2")),
            ],
            &facets,
        );
        assert_eq!(ids, vec!["w1".to_owned(), "w2".to_owned()]);
    }
}
