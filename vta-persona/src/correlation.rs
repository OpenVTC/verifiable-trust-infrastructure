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

use crate::face_values::FaceCarrier;
use crate::model::ProfileEntry;

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
    /// The world this profile belongs to, where it belongs to one.
    ///
    /// Absent for a profile in no world, and that is a real and common state
    /// rather than a gap: most profiles are unarranged until somebody arranges
    /// them. A consumer MUST NOT read absence as a world of its own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub world_id: Option<String>,
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

/// Which world each profile belongs to.
///
/// Built once per analysis, for the reason [`DisclosureIndex`] is: the
/// per-finding shape re-lists every world for every finding, and
/// `analyze_correlation` with no `attributeId` walks the whole pool.
///
/// Empty is meaningful and is not the same as "not built" — see
/// [`WorldIndex::any`], which is what decides whether `crossesWorlds` is
/// answered at all.
#[derive(Default)]
pub(crate) struct WorldIndex {
    by_profile: HashMap<String, String>,
    any: bool,
}

impl WorldIndex {
    /// Whether the holder keeps any worlds. False means the question has no
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
    /// The attribute analysed. Absent for a candidate and for a value only
    /// faces hold — there is no attribute to name.
    ///
    /// Absent, never `null`: the schema types it a string, and a `null` here
    /// failed the whole response. That made every candidate analysis that
    /// found a match an error, which is to say the guard failed exactly when
    /// it had something to say.
    #[serde(skip_serializing_if = "Option::is_none")]
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
    /// Whether this linkage spans two or more of the holder's worlds.
    ///
    /// **A second axis, not a restatement of `severity`.** `severity` says how
    /// strongly a disclosure would link the holder — a fact about provenance
    /// and proof rung, true whatever they intended. This says whether they
    /// would mind: a value shared between two profiles in the *same* world is
    /// linkage they arranged on purpose, and alarming on it teaches people to
    /// dismiss alarms, which costs them the one that matters.
    ///
    /// `None` — omitted on the wire — where the holder keeps no worlds at all,
    /// because `false` asserts that these identities sit in one part of their
    /// life and there is no such finding to make. The specification requires a
    /// consumer to read absence as *unknown*.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crosses_worlds: Option<bool>,
    /// The distinct worlds this linkage touches, so a consumer can name them.
    ///
    /// Identifiers, never names: the caller holds the world records and can
    /// resolve one, and the name is the member of a world worth protecting.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub world_ids: Vec<String>,
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

    /// Where a value has reached: the profiles and faces carrying it, the
    /// bindings pushing those into a context, and — when the claim type is
    /// known — the verifiers each binding has actually presented it to.
    ///
    /// Two sources, because a value reaches a face two ways. Through the pool:
    /// another attribute holds it and a profile references that attribute.
    /// Or directly: a face carries it as an `override` or an `inline` entry,
    /// which no attribute holds — see [`crate::face_values`]. Reading only the
    /// first is how the same value in two context-local faces used to produce
    /// no finding at all.
    ///
    /// `claim_type` is `None` for a **candidate**, and that omission is
    /// correct rather than a gap. A candidate is a value the holder has not
    /// written, so there is no attribute and no claim type; the disclosures
    /// this scan could reach belong to the *other* places already holding the
    /// value, whose own findings report them under their own types.
    /// Attributing those disclosures to the candidate would tell the holder
    /// their unwritten value had already been presented somewhere, which is
    /// false. So `disclosedTo` is left **absent** — never null, never an empty
    /// array standing in for "unknown". A face-carried value reports its
    /// disclosures under the claim type *that face* shows it as.
    async fn shared_with(
        &self,
        reach: &Reach,
        claim_type: Option<&str>,
        disclosures: &DisclosureIndex,
        worlds: &WorldIndex,
    ) -> Result<Vec<SharedWith>, vti_common::error::AppError> {
        // Deduplicated, and sorted by construction. One profile commonly
        // references several of the attributes sharing a value, and naming it
        // once per attribute would spend the schema's 128-entry budget saying
        // the same thing repeatedly — pushing the entries that name a
        // *different* place off the end.
        let mut profiles: BTreeSet<String> = BTreeSet::new();
        for id in &reach.attributes {
            profiles.extend(self.referring_profiles(id).await?);
        }

        let mut out: Vec<SharedWith> = Vec::new();
        for profile_id in &profiles {
            self.push_locations(&mut out, profile_id, None, claim_type, disclosures, worlds)
                .await?;
        }

        for carrier in &reach.faces {
            // A pool face that also references one of the attributes above is
            // already named; naming it twice spends the budget on nothing.
            if carrier.context_id.is_none() && profiles.contains(&carrier.profile_id) {
                continue;
            }
            let own_type = match (claim_type, self.carrier_face(carrier).await?) {
                (None, _) | (_, None) => None,
                (Some(_), Some(face)) => self
                    .claims_carrying(&face, &reach.blind)
                    .await?
                    .into_iter()
                    .map(|c| c.claim_type)
                    .find(|t| !t.is_empty()),
            };
            self.push_locations(
                &mut out,
                &carrier.profile_id,
                carrier.context_id.as_deref(),
                own_type.as_deref(),
                disclosures,
                worlds,
            )
            .await?;
        }

        out.truncate(MAX_SHARED_WITH);
        Ok(out)
    }

    /// Append every place one face is worn — or the face alone, when it is
    /// worn nowhere.
    ///
    /// `local_context` is the context a context-local face lives in. Such a
    /// face is confined to it, so only bindings there count, and an unbound one
    /// still names its context: it is not "nowhere", it is one `binding/set`
    /// away from a disclosure inside a context the holder chose.
    async fn push_locations(
        &self,
        out: &mut Vec<SharedWith>,
        profile_id: &str,
        local_context: Option<&str>,
        claim_type: Option<&str>,
        disclosures: &DisclosureIndex,
        worlds: &WorldIndex,
    ) -> Result<(), vti_common::error::AppError> {
        // Worlds arrange pool faces only; a local face is in none.
        let world_id = match local_context {
            None => worlds.of(profile_id).map(str::to_owned),
            Some(_) => None,
        };
        let bindings: Vec<(String, String)> = self
            .bindings_to_anywhere(profile_id)
            .await?
            .into_iter()
            .filter(|(ctx, _)| local_context.is_none_or(|lc| lc == ctx))
            .collect();

        if bindings.is_empty() {
            // A composition that carries the value but is bound nowhere.
            // Still worth naming — it is one `binding/set` away from being
            // a disclosure — but there is no persona, and that member stays
            // absent rather than null.
            out.push(SharedWith {
                world_id,
                profile_id: Some(profile_id.to_string()),
                context_id: local_context.map(str::to_owned),
                ..Default::default()
            });
            return Ok(());
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
                world_id: world_id.clone(),
                profile_id: Some(profile_id.to_string()),
                context_id: Some(context_id),
                persona_did: Some(persona_did),
                disclosed_to,
            });
        }
        Ok(())
    }

    /// Every place holding the value behind `blind`, less the one asking.
    async fn reach_of(
        &self,
        blind: &str,
        excluding_attribute: Option<&str>,
        excluding_face: Option<&FaceCarrier>,
    ) -> Result<Reach, vti_common::error::AppError> {
        Ok(Reach {
            blind: blind.to_string(),
            attributes: self
                .indexed_ids(blind)
                .await?
                .into_iter()
                .filter(|id| Some(id.as_str()) != excluding_attribute)
                .collect(),
            faces: self
                .faces_carrying(blind)
                .await?
                .into_iter()
                .filter(|f| Some(f) != excluding_face)
                .collect(),
        })
    }

    /// Build the profile → world index for one analysis.
    async fn world_index(&self) -> Result<WorldIndex, vti_common::error::AppError> {
        let worlds = self.list_worlds().await?;
        let mut by_profile = HashMap::new();
        for world in &worlds {
            for face in &world.face_ids {
                // A profile belongs to at most one world — `put_world` refuses
                // otherwise — so the first writer wins here and the second is
                // a state the store does not permit. Not an assertion: an index
                // is the wrong place to discover a store invariant, and picking
                // one answer keeps the analysis running either way.
                by_profile
                    .entry(face.clone())
                    .or_insert(world.world_id.clone());
            }
        }
        Ok(WorldIndex {
            by_profile,
            any: !worlds.is_empty(),
        })
    }

    /// Report where the holder's identities link.
    ///
    /// Accepts a **candidate** the holder is considering but has not written,
    /// which is the difference between a guard and a report: it can warn before
    /// the mistake rather than after. A candidate is analysed and never stored.
    ///
    /// With neither an attribute nor a candidate, the whole store is analysed:
    /// every pool attribute, and every value a face carries that no attribute
    /// holds. The second half is what reports two faces typing the same value
    /// — a finding with no `attributeId`, because there is no attribute.
    pub async fn analyze_correlation(
        &self,
        attribute_id: Option<&str>,
        candidate: Option<&serde_json::Value>,
    ) -> Result<Vec<Finding>, vti_common::error::AppError> {
        self.ensure_face_value_index().await?;
        let ctx = self.analysis_context().await?;
        let mut findings = Vec::new();

        if let Some(value) = candidate {
            let blind = blind(&self.correlation_key, value);
            let reach = self.reach_of(&blind, None, None).await?;
            if !reach.is_empty() {
                let shared = self.shared_with(&reach, None, &ctx.0, &ctx.1).await?;
                let (crosses_worlds, world_ids) = crossing(&shared, &ctx.1);
                findings.push(Finding {
                    attribute_id: None,
                    severity: "high",
                    why: format!(
                        "this value is already held by {}; presenting both links the personas \
                         that carry them, permanently, to anyone who sees both",
                        reach.describe()
                    ),
                    shared_with: shared,
                    crosses_worlds,
                    world_ids,
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
            None if candidate.is_none() => {
                self.list_attributes(None, crate::ValueVisibility::All)
                    .await?
                    .attributes
            }
            None => Vec::new(),
        };
        for a in &subjects {
            if let Some(f) = self.attribute_finding(a, &ctx).await? {
                findings.push(f);
            }
        }

        // Values only faces hold. A value some attribute also holds is already
        // reported by that attribute's finding, whose `sharedWith` names these
        // faces — reporting it again here would be one linkage told twice.
        if attribute_id.is_none() && candidate.is_none() {
            for (blind, carriers) in self.all_face_values().await? {
                if carriers.len() < 2 || !self.indexed_ids(&blind).await?.is_empty() {
                    continue;
                }
                if let Some(f) = self.face_value_finding(&carriers[0], &blind, &ctx).await? {
                    findings.push(f);
                }
            }
        }

        findings.truncate(MAX_FINDINGS);
        Ok(findings)
    }

    /// What one face would link if it were worn — `correlation/analyze` with a
    /// `profileId`.
    ///
    /// Covers both halves of what a face shows: the pool attributes it draws on
    /// (a `ref` or a `pin`), and the values it carries itself. An `override`
    /// contributes its displayed value and **not** the attribute beneath it,
    /// because that attribute's value is not what the face presents.
    ///
    /// The face may be pool or context-local; the id is looked for in the pool
    /// first. `NotFound` when it is in neither.
    pub async fn analyze_face_correlation(
        &self,
        profile_id: &str,
    ) -> Result<Vec<Finding>, vti_common::error::AppError> {
        self.ensure_face_value_index().await?;
        let (face, context_id) = match self.get_profile(profile_id).await? {
            Some(p) => (p, None),
            None => self.find_local_profile(profile_id).await?.ok_or_else(|| {
                vti_common::error::AppError::NotFound(format!("profile {profile_id}"))
            })?,
        };
        let ctx = self.analysis_context().await?;
        let mut findings = Vec::new();

        // A pin to a kept earlier version presents that version, not the
        // current one, so it is analysed with what the face carries below
        // rather than as the live attribute.
        let mut drawn: BTreeSet<&str> = BTreeSet::new();
        for entry in &face.entries {
            match entry {
                ProfileEntry::Ref { r#ref, .. } => {
                    drawn.insert(r#ref);
                }
                ProfileEntry::Pinned {
                    r#ref, pin_version, ..
                } if self
                    .pinned_retained_value(r#ref, *pin_version)
                    .await?
                    .is_none() =>
                {
                    drawn.insert(r#ref);
                }
                _ => {}
            }
        }
        for id in drawn {
            if let Some(a) = self.get(id).await?
                && let Some(f) = self.attribute_finding(&a, &ctx).await?
            {
                findings.push(f);
            }
        }

        let carrier = FaceCarrier {
            profile_id: face.profile_id.clone(),
            context_id,
        };
        for b in self.face_blinds(Some(&face)).await? {
            if let Some(f) = self.face_value_finding(&carrier, &b, &ctx).await? {
                findings.push(f);
            }
        }

        findings.truncate(MAX_FINDINGS);
        Ok(findings)
    }

    async fn analysis_context(
        &self,
    ) -> Result<(DisclosureIndex, WorldIndex), vti_common::error::AppError> {
        Ok((self.disclosure_index().await?, self.world_index().await?))
    }

    /// Find a context-local face by id alone, across every context. Only a
    /// holder-reach task may call this: it is a scan of every context's faces.
    pub(crate) async fn find_local_profile(
        &self,
        profile_id: &str,
    ) -> Result<Option<(crate::Profile, Option<String>)>, vti_common::error::AppError> {
        let suffix = format!(":{profile_id}");
        for key in self.ks.prefix_keys(b"plp:".to_vec()).await? {
            let Ok(key) = String::from_utf8(key) else {
                continue;
            };
            let Some(context_id) = key
                .strip_prefix("plp:")
                .and_then(|rest| rest.strip_suffix(&suffix))
            else {
                continue;
            };
            if let Some(p) = self.get_local_profile(context_id, profile_id).await? {
                return Ok(Some((p, Some(context_id.to_string()))));
            }
        }
        Ok(None)
    }

    /// The finding for one pool attribute, or `None` when nothing else holds
    /// its value.
    async fn attribute_finding(
        &self,
        a: &crate::Attribute,
        ctx: &(DisclosureIndex, WorldIndex),
    ) -> Result<Option<Finding>, vti_common::error::AppError> {
        let Some(value) = &a.value else {
            return Ok(None);
        };
        let b = blind(&self.correlation_key, value);
        let reach = self.reach_of(&b, Some(&a.attribute_id), None).await?;
        if reach.is_empty() {
            return Ok(None);
        }
        let shared = self
            .shared_with(&reach, Some(&a.r#type), &ctx.0, &ctx.1)
            .await?;
        Ok(Some(finding(
            Some(a.attribute_id.clone()),
            &a.provenance,
            &reach,
            shared,
            &ctx.1,
        )))
    }

    /// The finding for a value `carrier` shows itself, or `None` when nothing
    /// else holds it.
    async fn face_value_finding(
        &self,
        carrier: &FaceCarrier,
        blind: &str,
        ctx: &(DisclosureIndex, WorldIndex),
    ) -> Result<Option<Finding>, vti_common::error::AppError> {
        let reach = self.reach_of(blind, None, Some(carrier)).await?;
        if reach.is_empty() {
            return Ok(None);
        }
        let Some(face) = self.carrier_face(carrier).await? else {
            return Ok(None);
        };
        let Some(claim) = self.claims_carrying(&face, blind).await?.into_iter().next() else {
            return Ok(None);
        };

        // The face asking is itself one of the places the value has reached,
        // so it leads the list: a finding that named only the *other* face
        // would leave the holder unable to tell which pair is linked.
        let mut shared = Vec::new();
        self.push_locations(
            &mut shared,
            &carrier.profile_id,
            carrier.context_id.as_deref(),
            Some(&claim.claim_type)
                .filter(|t| !t.is_empty())
                .map(String::as_str),
            &ctx.0,
            &ctx.1,
        )
        .await?;
        let claim_type = Some(claim.claim_type.as_str()).filter(|t| !t.is_empty());
        shared.extend(self.shared_with(&reach, claim_type, &ctx.0, &ctx.1).await?);
        shared.truncate(MAX_SHARED_WITH);

        Ok(Some(finding(
            None,
            &claim.provenance,
            &reach,
            shared,
            &ctx.1,
        )))
    }
}

/// The published cap on `findings` (`maxItems: 256`). Truncated here for the
/// reason [`MAX_SHARED_WITH`] is: a response over the cap fails validation
/// whole, and the holder is told nothing.
const MAX_FINDINGS: usize = 256;

/// Every place holding one value, apart from the one being analysed.
pub(crate) struct Reach {
    blind: String,
    attributes: Vec<String>,
    faces: Vec<FaceCarrier>,
}

impl Reach {
    fn is_empty(&self) -> bool {
        self.attributes.is_empty() && self.faces.is_empty()
    }

    /// The count, in words. Stated in the finding because `sharedWith` does not
    /// restate it: that list is keyed on the profiles and bindings the value
    /// reaches, so two attributes referenced by one profile appear there once.
    fn describe(&self) -> String {
        match (self.attributes.len(), self.faces.len()) {
            (a, 0) => format!("{a} other attribute(s)"),
            (0, f) => format!("{f} other face(s) that show it without drawing on your attributes"),
            (a, f) => format!(
                "{a} other attribute(s) and {f} face(s) that show it without drawing on your \
                 attributes"
            ),
        }
    }
}

/// Assemble a finding from what linked it.
fn finding(
    attribute_id: Option<String>,
    provenance: &crate::Provenance,
    reach: &Reach,
    shared_with: Vec<SharedWith>,
    worlds: &WorldIndex,
) -> Finding {
    let credential_backed = matches!(provenance, crate::Provenance::CredentialBacked { .. });
    let rung = match provenance {
        crate::Provenance::CredentialBacked { proof, .. } => {
            proof.unwrap_or(crate::ProofRung::Whole)
        }
        _ => crate::ProofRung::Whole,
    };
    let sev = severity(true, credential_backed, rung);
    let (crosses_worlds, world_ids) = crossing(&shared_with, worlds);
    Finding {
        attribute_id,
        // The published enum is `{low, high}` — a finding has no "none" rung,
        // and emitting one was the second way this response failed its own
        // schema. The mapping is not a workaround for that: `severity()`
        // answers a narrower question than a finding asks. `None` from it
        // means *this disclosure* links nothing, which is true of a credential
        // presented at the Derived or Predicate rung. A finding says something
        // wider — the value is reused, and the first time it is presented at
        // a linking rung it links — so the weakest true thing a finding can
        // say is `low`, never nothing at all.
        severity: match sev {
            Severity::High => "high",
            Severity::Low | Severity::None => "low",
        },
        why: if credential_backed {
            format!(
                "credential-backed and presented at the {rung:?} rung. A credential presented \
                 whole carries the same issuer signature to every verifier, so it links them \
                 however few claims each received; the same value is held by {}",
                reach.describe()
            )
        } else {
            format!("the same value is held by {}", reach.describe())
        },
        shared_with,
        crosses_worlds,
        world_ids,
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
    }
}

/// Whether a set of locations spans two or more worlds, and which.
///
/// **Only distinct, named worlds count.** A profile belonging to no world is
/// unarranged, not a second world — count it as one and every holder who has
/// arranged one part of their life and not the rest sees a crossing on
/// everything they own, which is the dismissal problem arriving from the other
/// direction.
///
/// Returns `None` for the whole question when the holder keeps no worlds: the
/// specification requires absence rather than `false`, because `false` asserts
/// these identities sit in one part of a life and an agent with no worlds has
/// made no such finding.
fn crossing(shared: &[SharedWith], worlds: &WorldIndex) -> (Option<bool>, Vec<String>) {
    if !worlds.any() {
        return (None, Vec::new());
    }
    let distinct: BTreeSet<&str> = shared
        .iter()
        .filter_map(|s| s.world_id.as_deref())
        .collect();
    (
        Some(distinct.len() >= 2),
        distinct.into_iter().map(str::to_owned).collect(),
    )
}

#[cfg(test)]
mod world_crossing_tests {
    use super::*;

    fn at(profile: &str, world: Option<&str>) -> SharedWith {
        SharedWith {
            profile_id: Some(profile.to_owned()),
            world_id: world.map(str::to_owned),
            ..Default::default()
        }
    }

    fn index(pairs: &[(&str, &str)]) -> WorldIndex {
        WorldIndex {
            by_profile: pairs
                .iter()
                .map(|(p, f)| ((*p).to_owned(), (*f).to_owned()))
                .collect(),
            any: !pairs.is_empty(),
        }
    }

    #[test]
    fn no_worlds_means_the_question_has_no_answer() {
        // Absent, never `false`. `false` asserts these identities sit in one
        // part of the holder's life, and an agent with no worlds has made no
        // such finding — the specification requires a consumer to read absence
        // as unknown, which it cannot do if we answer.
        let (crosses, ids) = crossing(&[at("p1", None), at("p2", None)], &WorldIndex::default());
        assert_eq!(crosses, None);
        assert!(ids.is_empty());
    }

    #[test]
    fn sharing_inside_one_world_is_not_a_crossing() {
        // The linkage the holder arranged on purpose — a work email in every
        // work profile. Alarming on it teaches people to dismiss alarms.
        let worlds = index(&[("p1", "w1"), ("p2", "w1")]);
        let (crosses, ids) = crossing(&[at("p1", Some("w1")), at("p2", Some("w1"))], &worlds);
        assert_eq!(crosses, Some(false));
        assert_eq!(ids, vec!["w1".to_owned()]);
    }

    #[test]
    fn sharing_across_two_worlds_is_the_finding_worth_raising() {
        let worlds = index(&[("p1", "w1"), ("p2", "w2")]);
        let (crosses, ids) = crossing(&[at("p1", Some("w1")), at("p2", Some("w2"))], &worlds);
        assert_eq!(crosses, Some(true));
        assert_eq!(ids, vec!["w1".to_owned(), "w2".to_owned()]);
    }

    #[test]
    fn an_unarranged_profile_is_not_a_second_world() {
        // The defect this closes: counting "no world" as a world makes every
        // holder who has arranged one part of their life and not the rest see a
        // crossing on everything they own.
        let worlds = index(&[("p1", "w1")]);
        let (crosses, ids) = crossing(&[at("p1", Some("w1")), at("p2", None)], &worlds);
        assert_eq!(
            crosses,
            Some(false),
            "an unarranged profile read as a crossing"
        );
        assert_eq!(ids, vec!["w1".to_owned()]);
    }

    #[test]
    fn every_location_unarranged_is_no_crossing_but_still_answered() {
        // The holder keeps worlds, so the question HAS an answer — it is just
        // "no". Distinct from the no-worlds case above, which has none.
        let worlds = index(&[("pX", "w1")]);
        let (crosses, ids) = crossing(&[at("p1", None), at("p2", None)], &worlds);
        assert_eq!(crosses, Some(false));
        assert!(ids.is_empty());
    }

    #[test]
    fn the_worlds_touched_are_distinct_and_ordered() {
        // Ordered so two findings over the same worlds list them the same way;
        // deduplicated so a world holding three of the sharing profiles is
        // named once.
        let worlds = index(&[("p1", "w2"), ("p2", "w1"), ("p3", "w2")]);
        let (_, ids) = crossing(
            &[
                at("p1", Some("w2")),
                at("p2", Some("w1")),
                at("p3", Some("w2")),
            ],
            &worlds,
        );
        assert_eq!(ids, vec!["w1".to_owned(), "w2".to_owned()]);
    }
}
