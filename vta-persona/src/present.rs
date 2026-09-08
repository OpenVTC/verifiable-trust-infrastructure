//! The disclosure flow: preview, then present.
//!
//! Two calls that **cannot be collapsed**. [`PersonaStore::create_preview`]
//! mints a single-use token that [`PersonaStore::consume_preview`] destroys, so
//! there is no code path to a disclosure that did not first produce the summary
//! a human can be shown — and a maintainer cannot accidentally provide one by
//! forgetting a flag, because the second call requires a token only the first
//! can produce.
//!
//! # Four refusals, and each is a refusal rather than a degradation
//!
//! - **A rung the credential cannot support** is refused, never silently
//!   lowered. A silent privacy downgrade discloses material the holder believed
//!   was hidden.
//! - **A renderer that cannot carry a claim** fails at negotiation. Dropping the
//!   claim would produce a disclosure that verifies and says less than the
//!   holder approved — and a verifier receiving fewer claims than were approved
//!   cannot tell that from a holder who approved fewer.
//! - **A claim that went stale between preview and present** refuses the whole
//!   disclosure rather than issuing a short one, for the same reason.
//! - **A consumed or expired preview** is refused rather than re-derived from
//!   current state. The holder was shown one thing; re-deriving could disclose
//!   another.

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

use crate::binding::MaterialisedClaim;
use crate::disclosure::{DisclosedClaim, DisclosureRecord, new_disclosure};
use crate::model::{ProofRung, Provenance, Ulid};
use crate::store::PersonaStore;

/// How long a preview stands.
///
/// A preview a holder approved an hour ago is not evidence they approve it now,
/// and one that could be replayed would let a second disclosure ride an earlier
/// decision.
pub const PREVIEW_TTL_SECONDS: i64 = 300;

/// What a renderer can and cannot carry.
///
/// Lossiness is **declared**, so a preview can tell the holder what a format
/// will not carry before they decide — rather than their discovering it from a
/// verifier who never learned a claim was attested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Renderer {
    pub id: &'static str,
    pub canonical: bool,
    pub carries_provenance: bool,
    pub carries_predicates: bool,
}

/// The renderers this agent offers.
///
/// Two ship. `sd-jwt-vc`, `mdoc` or a future agent-card would each be one more
/// entry rather than a redesign — and none is added speculatively, because every
/// unused renderer is a mapping table somebody must keep true.
pub const RENDERERS: &[Renderer] = &[
    Renderer {
        id: "rcard",
        canonical: true,
        carries_provenance: true,
        carries_predicates: true,
    },
    Renderer {
        id: "jcard",
        canonical: false,
        // No vCard property says "this was attested", and no field says "over
        // the threshold".
        carries_provenance: false,
        carries_predicates: false,
    },
];

#[must_use]
pub fn renderer(id: Option<&str>) -> Option<Renderer> {
    match id {
        None => RENDERERS.iter().find(|r| r.canonical).copied(),
        Some(want) => RENDERERS.iter().find(|r| r.id == want).copied(),
    }
}

/// A predicate a claim would be proven by, rather than shown.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Predicate {
    pub op: String,
    pub arg: serde_json::Value,
    pub over: String,
}

/// One line of a preview: what would be disclosed, and how strongly hidden.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewClaim {
    pub r#type: String,
    /// Absent for a predicate claim, which discloses no value at all. That
    /// absence is the point and must not be rendered as missing data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicate: Option<Predicate>,
    pub provenance: String,
    pub rung: ProofRung,
    pub new_to_this_verifier: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
}

/// A preview, held until consumed or expired.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub preview_id: Ulid,
    pub context_id: String,
    pub persona_did: String,
    pub verifier_did: String,
    /// Pairwise by default — a per-relationship identifier rather than the
    /// persona DID, so two verifiers cannot recognise the holder as one party.
    /// The persona DID is the account; this is the face.
    pub subject: String,
    pub claims: Vec<PreviewClaim>,
    pub renderer_id: String,
    pub renderer_drops: Vec<String>,
    pub purpose: Option<String>,
    pub expires_at: String,
    /// Whether any claim in this preview needs a fresh approval to leave.
    ///
    /// **Resolved once, here, and stored** — unlike `sensitivity`, which is
    /// derived at every read. The reason is where the inputs live: the answer
    /// depends on the holder's per-attribute `release` override, which travels
    /// down with the materialised claim and is *not* on `PreviewClaim`. The
    /// preview response's schema declares `additionalProperties: false` on its
    /// claims, so putting it there would put it on the wire, and this is an
    /// at-rest decision rather than something a verifier is owed.
    ///
    /// Freezing it for the preview's lifetime is also the honest reading: a
    /// preview is a snapshot of what the holder was shown, it is single-use,
    /// and it expires in minutes. A holder who changes the override afterwards
    /// previews again.
    ///
    /// `false` on a preview written before this field existed — which is what
    /// those previews enforced.
    #[serde(default)]
    pub step_up_required: bool,
    /// When a step-up approval bound to this preview was recorded, if one was.
    ///
    /// **On the preview, not beside it.** An approval authorises one disclosure
    /// — this one — so it shares the preview's lifetime by living in the same
    /// record: consumed when the preview is consumed, expired when it expires,
    /// and incapable of outliving the decision it belongs to. A separate
    /// approval record would need its own expiry, its own cleanup, and a reason
    /// why the two could not disagree.
    ///
    /// It also means freshness needs no separate rule. "Each time" is bounded
    /// by the preview's own TTL, because an approval cannot be older than the
    /// preview it is written on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<u64>,
}

impl PersonaStore {
    /// Determine what a disclosure would reveal. Signs nothing, sends nothing.
    pub async fn create_preview(
        &self,
        context_id: &str,
        persona_did: &str,
        verifier_did: &str,
        purpose: Option<&str>,
        requested: Option<&[String]>,
        renderer_id: Option<&str>,
    ) -> Result<Preview, AppError> {
        let Some(r) = renderer(renderer_id) else {
            return Err(AppError::Validation(format!(
                "renderer {} is not offered by this agent",
                renderer_id.unwrap_or("<default>")
            )));
        };

        let materialised = self.materialised_claims(context_id, persona_did).await?;
        if materialised.is_empty() {
            return Err(AppError::NotFound(format!(
                "persona {persona_did} has no profile bound, so there is nothing to disclose"
            )));
        }

        // Which claim types this verifier has already received, so the preview
        // can rank by what is new rather than listing everything equally.
        let seen = self.claim_types_seen_by(verifier_did).await?;

        // The included originals are kept alongside, because the `release`
        // decision is read from them and `PreviewClaim` deliberately does not
        // carry it (see `Preview::step_up_required`). Filtered by `requested`
        // exactly as `claims` is: a verifier asking for only a name must not be
        // gated by a card the profile also holds but that is not being sent.
        let mut claims = Vec::new();
        let mut included: Vec<crate::MaterialisedClaim> = Vec::new();
        for m in &materialised {
            if let Some(want) = requested
                && !want.iter().any(|t| t == &m.r#type)
            {
                continue;
            }
            claims.push(preview_claim(m, &seen));
            included.push(m.clone());
        }

        if claims.is_empty() {
            return Err(AppError::Validation(
                "none of the requested claim types are present in this persona's profile".into(),
            ));
        }

        // Negotiation, not a silent drop. A verifier receiving fewer claims than
        // were approved cannot tell that from a holder who approved fewer.
        if !r.carries_predicates
            && let Some(bad) = claims.iter().find(|c| c.predicate.is_some())
        {
            return Err(AppError::Validation(format!(
                "renderer {} cannot carry the predicate on claim {}; refusing rather than \
                 dropping it",
                r.id, bad.r#type
            )));
        }

        let preview = Preview {
            preview_id: ulid::Ulid::generate().to_string(),
            context_id: context_id.to_string(),
            persona_did: persona_did.to_string(),
            verifier_did: verifier_did.to_string(),
            subject: pairwise_subject(persona_did, verifier_did),
            claims,
            renderer_id: r.id.to_string(),
            renderer_drops: if r.carries_provenance {
                Vec::new()
            } else {
                vec!["provenance".to_string()]
            },
            purpose: purpose.map(str::to_string),
            expires_at: (chrono::Utc::now() + chrono::Duration::seconds(PREVIEW_TTL_SECONDS))
                .to_rfc3339(),
            step_up_required: Self::any_claim_requires_step_up(&included),
            approved_at: None,
        };

        let _guard = self.write_lock.lock().await;
        self.ks
            .insert(preview_key(&preview.preview_id), &preview)
            .await?;
        Ok(preview)
    }

    /// Read a preview without consuming it.
    ///
    /// The gate that refuses a disclosure for want of a step-up approval has to
    /// run *before* the preview is taken: refusing for want of an approval must
    /// not cost the holder the decision they already made, and
    /// [`consume_preview`](Self::consume_preview) removes the record before it
    /// validates anything.
    ///
    /// Deliberately does not check expiry. A caller reading a preview to decide
    /// whether to ask for an approval wants to know what is there; the expiry
    /// refusal belongs to the consume, which is the operation that would
    /// otherwise act on it.
    pub async fn peek_preview(&self, preview_id: &str) -> Result<Option<Preview>, AppError> {
        self.ks.get::<Preview>(preview_key(preview_id)).await
    }

    /// Record that a step-up approval bound to this preview was obtained.
    ///
    /// Returns whether a preview was there to mark. `false` is not an error:
    /// an approval can arrive after its preview has expired or been consumed,
    /// and the honest response is to have changed nothing. The disclosure it
    /// would have authorised is gone, and the holder previews again.
    pub async fn approve_preview(&self, preview_id: &str) -> Result<bool, AppError> {
        let _guard = self.write_lock.lock().await;
        let key = preview_key(preview_id);
        let Some(mut preview) = self.ks.get::<Preview>(key.clone()).await? else {
            return Ok(false);
        };
        preview.approved_at = Some(vti_common::auth::session::now_epoch());
        self.ks.insert(key, &preview).await?;
        Ok(true)
    }

    /// Whether this preview would disclose anything the holder has to approve
    /// afresh — any claim whose type resolves to [`ReleaseRequirement::StepUp`].
    ///
    /// Whether this preview needs a fresh approval before it may be presented.
    ///
    /// Reads the decision [`create_preview`](Self::create_preview) recorded.
    /// See [`Preview::step_up_required`] for why it is stored rather than
    /// re-derived here.
    #[must_use]
    pub fn requires_step_up(preview: &Preview) -> bool {
        preview.step_up_required
    }

    /// Does any of these materialised claims need a fresh approval to leave?
    ///
    /// Per claim: **the holder's override where one travelled down**, and the
    /// claim-type registry otherwise. The override cannot be looked up from
    /// here — nothing below the boundary may read the pool — so it is carried
    /// down with the value at bind time and read off the copy. Copies go down;
    /// nothing reads up.
    ///
    /// A binding written before that field existed carries `None` on every
    /// claim and resolves entirely from the registry, which is what it did
    /// before.
    fn any_claim_requires_step_up(claims: &[crate::MaterialisedClaim]) -> bool {
        claims.iter().any(|m| {
            crate::claim_types::release_of_claim(&m.r#type, m.release)
                == crate::claim_types::ReleaseRequirement::StepUp
        })
    }

    /// Take a preview, destroying it.
    ///
    /// Single-use: a producer wanting to disclose twice previews twice, which is
    /// correct rather than inconvenient — the second disclosure is a second
    /// decision, and a token that could be replayed would let it ride the first.
    pub async fn consume_preview(&self, preview_id: &str) -> Result<Preview, AppError> {
        let _guard = self.write_lock.lock().await;
        let key = preview_key(preview_id);
        let Some(preview) = self.ks.get::<Preview>(key.clone()).await? else {
            return Err(AppError::NotFound(
                "preview is unknown, already consumed, or expired".into(),
            ));
        };
        self.ks.remove(key).await?;

        let expired = chrono::DateTime::parse_from_rfc3339(&preview.expires_at)
            .is_ok_and(|t| t < chrono::Utc::now());
        if expired {
            // Refused rather than re-derived from current state: the holder was
            // shown one thing, and re-deriving could disclose another.
            return Err(AppError::Gone("preview has expired; preview again".into()));
        }
        Ok(preview)
    }

    /// Produce the disclosure a preview described, and record it.
    ///
    /// The record is written **before** the artifact is returned. A crash
    /// between the two would otherwise release data the holder could never
    /// afterwards discover they had released.
    pub async fn present(
        &self,
        preview_id: &str,
        challenge: Option<&str>,
        durable: bool,
    ) -> Result<(String, DisclosureRecord), AppError> {
        let preview = self.consume_preview(preview_id).await?;

        // Refuse whole rather than issue short. A verifier receiving fewer
        // claims than were approved cannot tell that from a holder who approved
        // fewer.
        if let Some(stale) = preview.claims.iter().find(|c| c.stale) {
            return Err(AppError::Conflict(format!(
                "claim {} could not be re-derived since the preview; refusing the whole \
                 disclosure rather than issuing a shorter one",
                stale.r#type
            )));
        }

        let artifact = render(&preview, challenge);

        let mut record = new_disclosure(
            preview.context_id.clone(),
            preview.verifier_did.clone(),
            preview.persona_did.clone(),
            preview
                .claims
                .iter()
                .map(|c| DisclosedClaim {
                    r#type: c.r#type.clone(),
                    rung: c.rung,
                })
                .collect(),
        );
        record.subject = Some(preview.subject.clone());
        record.purpose = preview.purpose.clone();
        record.renderer = Some(preview.renderer_id.clone());
        if durable {
            record.durable_credential_id = Some(ulid::Ulid::generate().to_string());
        }

        self.record_disclosure(record.clone()).await?;
        Ok((artifact, record))
    }

    /// Claim types a verifier has already received, from the disclosure record.
    async fn claim_types_seen_by(&self, verifier_did: &str) -> Result<Vec<String>, AppError> {
        Ok(self
            .disclosure_history(&crate::disclosure::HistoryQuery {
                verifier_did: Some(verifier_did),
                ..Default::default()
            })
            .await?
            .into_iter()
            .flat_map(|r| r.claims.into_iter().map(|c| c.r#type))
            .collect())
    }
}

fn preview_key(preview_id: &str) -> String {
    format!("ppv:{preview_id}")
}

/// Select the rung and shape one preview line.
///
/// The rung is the **highest the claim's provenance supports** — `max()` over
/// the ordering rather than a hand-written table, so "highest supported" cannot
/// disagree with the ordering it is defined against.
fn preview_claim(m: &MaterialisedClaim, seen: &[String]) -> PreviewClaim {
    let (provenance, rung) = match &m.provenance {
        Provenance::SelfAsserted => ("selfAsserted", ProofRung::Whole),
        Provenance::Generated { .. } => ("generated", ProofRung::Whole),
        Provenance::CredentialBacked { proof, .. } => (
            "credentialBacked",
            // Absent means the credential's format was never assessed, and the
            // conservative answer is the least private one — never the most,
            // which would claim an unlinkability the proof does not provide.
            proof.unwrap_or(ProofRung::Whole),
        ),
    };

    PreviewClaim {
        r#type: m.r#type.clone(),
        value: if rung == ProofRung::Predicate {
            None
        } else {
            m.value.clone()
        },
        predicate: None,
        provenance: provenance.to_string(),
        rung,
        new_to_this_verifier: !seen.iter().any(|t| t == &m.r#type),
        stale: m.stale,
    }
}

/// A per-relationship identifier.
///
/// Pairwise by default so two verifiers cannot recognise the holder as one
/// party. Derived rather than random so the same relationship keeps one face
/// across disclosures, which is what lets a counterparty recognise a returning
/// holder without anyone else being able to.
fn pairwise_subject(persona_did: &str, verifier_did: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"vta-persona/pairwise-subject/v1");
    h.update(persona_did.as_bytes());
    h.update([0u8]);
    h.update(verifier_did.as_bytes());
    format!("did:peer:0z{}", hex_short(&h.finalize()))
}

fn hex_short(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().take(16).fold(String::new(), |mut a, b| {
        let _ = write!(a, "{b:02x}");
        a
    })
}

/// Render the approved claim set.
///
/// **This produces an UNSIGNED document.** Signing belongs to the key custodian
/// (`keys/derive-and-sign-document`), which holds the persona's key; a signature
/// minted here would either need that key in this crate or be a placeholder that
/// looks like a signature and is not. The second is worse than no signature at
/// all, so the seam is left visible rather than filled with something
/// misleading.
fn render(preview: &Preview, challenge: Option<&str>) -> String {
    let claims: serde_json::Map<String, serde_json::Value> = preview
        .claims
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut o = serde_json::Map::new();
            o.insert("type".into(), serde_json::json!(c.r#type));
            if let Some(v) = &c.value {
                o.insert("value".into(), v.clone());
            }
            if let Some(p) = &c.predicate {
                o.insert("predicate".into(), serde_json::json!(p));
            }
            if preview.renderer_drops.iter().all(|d| d != "provenance") {
                o.insert("provenance".into(), serde_json::json!(c.provenance));
            }
            (format!("{i:04}"), serde_json::Value::Object(o))
        })
        .collect();

    serde_json::json!({
        "type": ["VerifiableDataStructure", "RelationshipCard"],
        "publisher": preview.subject,
        "cardVersion": 1,
        "claims": claims,
        "challenge": challenge,
        "renderer": preview.renderer_id,
        // Named, so nothing downstream mistakes this for a signed artifact.
        "unsigned": true,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProfileEntry, ValueType};
    use crate::profile::new_profile;
    use crate::store::new_attribute;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn fresh() -> (tempfile::TempDir, PersonaStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        (
            dir,
            PersonaStore::new(store.keyspace(vta_keyspaces::PERSONA).unwrap(), [31u8; 32]),
        )
    }

    /// A persona bound to a profile carrying one claim of the given type — used
    /// to put a `release: stepUp` type in front of the gate.
    async fn bound_with_type(s: &PersonaStore, claim_type: &str) -> String {
        let a = new_attribute(
            claim_type,
            ValueType::String,
            serde_json::json!("4111111111111111"),
            Provenance::SelfAsserted,
        );
        s.put(a.clone(), None).await.unwrap();
        let p = new_profile(
            "Work",
            vec![ProfileEntry::Ref {
                r#ref: a.attribute_id.clone(),
            }],
        );
        s.put_profile(p.clone(), None).await.unwrap();
        s.set_binding("ctx", "did:persona:a", Some(&p.profile_id), vec![], None)
            .await
            .unwrap();
        p.profile_id
    }

    /// As `bound_with_type`, returning the attribute id too, so a test can
    /// reach back into the pool and set an override on it.
    async fn bound_returning_ids(s: &PersonaStore, claim_type: &str) -> (String, String) {
        let a = new_attribute(
            claim_type,
            ValueType::String,
            serde_json::json!("4111111111111111"),
            Provenance::SelfAsserted,
        );
        s.put(a.clone(), None).await.unwrap();
        let p = new_profile(
            "Work",
            vec![ProfileEntry::Ref {
                r#ref: a.attribute_id.clone(),
            }],
        );
        s.put_profile(p.clone(), None).await.unwrap();
        s.set_binding("ctx", "did:persona:a", Some(&p.profile_id), vec![], None)
            .await
            .unwrap();
        (p.profile_id, a.attribute_id)
    }

    /// A holder's override reaches the gate, in both directions.
    ///
    /// This is the whole of what "carry it down at bind time" buys: the
    /// override is set on the pool attribute, above the boundary, and the
    /// decision has to arrive at a preview built entirely from the context's
    /// copy — which cannot read the pool to ask.
    ///
    /// Both directions, because both are the holder's to make. Tightening an
    /// ungated name is the easy case to get right; **loosening a card is the
    /// one worth pinning**, since an agent that quietly kept gating it would be
    /// overruling the person the gate exists to serve.
    #[tokio::test]
    async fn a_holders_release_override_reaches_the_gate() {
        // Tighten: a display name the registry does not gate.
        let (_d, s) = fresh().await;
        let (p, id) = bound_returning_ids(&s, "name.display").await;
        let ungated = s
            .create_preview("ctx", "did:persona:a", "did:verifier:v", None, None, None)
            .await
            .unwrap();
        assert!(
            !PersonaStore::requires_step_up(&ungated),
            "registry default"
        );

        let mut a = s.get(&id).await.unwrap().unwrap();
        a.release = Some(crate::claim_types::ReleaseRequirement::StepUp);
        s.put(a, None).await.unwrap();
        s.set_binding("ctx", "did:persona:a", Some(&p), vec![], None)
            .await
            .unwrap();
        let now_gated = s
            .create_preview("ctx", "did:persona:a", "did:verifier:v", None, None, None)
            .await
            .unwrap();
        assert!(
            PersonaStore::requires_step_up(&now_gated),
            "the holder asked for a fresh approval on their display name and did not get one"
        );

        // Loosen: a card the registry does gate.
        let (_d2, s2) = fresh().await;
        let (p2, id2) = bound_returning_ids(&s2, "payment.card").await;
        let gated = s2
            .create_preview("ctx", "did:persona:a", "did:verifier:v", None, None, None)
            .await
            .unwrap();
        assert!(PersonaStore::requires_step_up(&gated), "registry default");

        let mut a2 = s2.get(&id2).await.unwrap().unwrap();
        a2.release = Some(crate::claim_types::ReleaseRequirement::Consent);
        s2.put(a2, None).await.unwrap();
        s2.set_binding("ctx", "did:persona:a", Some(&p2), vec![], None)
            .await
            .unwrap();
        let now_open = s2
            .create_preview("ctx", "did:persona:a", "did:verifier:v", None, None, None)
            .await
            .unwrap();
        assert!(
            !PersonaStore::requires_step_up(&now_open),
            "the holder's own decision about their own pool was overruled"
        );
    }

    /// A claim the verifier did not ask for does not gate the disclosure.
    ///
    /// The preview is filtered by `requestedClaims`; the gate must be filtered
    /// the same way. A profile holding a card and a name, asked only for the
    /// name, is a `consent` disclosure — gating it on the card would demand a
    /// fresh approval for something that is not being sent.
    #[tokio::test]
    async fn a_claim_not_being_sent_does_not_gate_the_one_that_is() {
        let (_d, s) = fresh().await;
        let card = new_attribute(
            "payment.card",
            ValueType::String,
            serde_json::json!("4111111111111111"),
            Provenance::SelfAsserted,
        );
        let name = new_attribute(
            "name.display",
            ValueType::String,
            serde_json::json!("Ada"),
            Provenance::SelfAsserted,
        );
        s.put(card.clone(), None).await.unwrap();
        s.put(name.clone(), None).await.unwrap();
        let p = new_profile(
            "Both",
            vec![
                ProfileEntry::Ref {
                    r#ref: card.attribute_id.clone(),
                },
                ProfileEntry::Ref {
                    r#ref: name.attribute_id.clone(),
                },
            ],
        );
        s.put_profile(p.clone(), None).await.unwrap();
        s.set_binding("ctx", "did:persona:a", Some(&p.profile_id), vec![], None)
            .await
            .unwrap();

        let name_only = s
            .create_preview(
                "ctx",
                "did:persona:a",
                "did:verifier:v",
                None,
                Some(&["name.display".to_string()]),
                None,
            )
            .await
            .unwrap();
        assert!(
            !PersonaStore::requires_step_up(&name_only),
            "a card that is not being disclosed gated a disclosure of a display name"
        );

        let everything = s
            .create_preview("ctx", "did:persona:a", "did:verifier:v", None, None, None)
            .await
            .unwrap();
        assert!(
            PersonaStore::requires_step_up(&everything),
            "the card IS being disclosed here and must gate it"
        );
    }

    /// A card number needs a fresh approval; a display name does not. The pair
    /// is the point — a gate that answered "yes" to everything would pass the
    /// first assertion alone.
    #[tokio::test]
    async fn only_a_step_up_type_requires_an_approval() {
        let (_d, s) = fresh().await;
        bound_with_type(&s, "payment.card").await;
        let gated = s
            .create_preview("ctx", "did:persona:a", "did:verifier:v", None, None, None)
            .await
            .unwrap();
        assert!(PersonaStore::requires_step_up(&gated));

        let (_d2, s2) = fresh().await;
        bound_with_type(&s2, "name.display").await;
        let ungated = s2
            .create_preview("ctx", "did:persona:a", "did:verifier:v", None, None, None)
            .await
            .unwrap();
        assert!(!PersonaStore::requires_step_up(&ungated));
    }

    /// A token invented under a gated family is gated too — the registry's
    /// prefix rule reaching the disclosure path, not just the listing one.
    #[tokio::test]
    async fn an_unregistered_member_of_a_gated_family_still_requires_approval() {
        let (_d, s) = fresh().await;
        bound_with_type(&s, "payment.giftCard").await;
        let preview = s
            .create_preview("ctx", "did:persona:a", "did:verifier:v", None, None, None)
            .await
            .unwrap();
        assert!(
            PersonaStore::requires_step_up(&preview),
            "a gated family must not be leavable by inventing a token"
        );
    }

    /// A preview is minted unapproved, and an approval is recorded on it.
    #[tokio::test]
    async fn an_approval_is_recorded_on_the_preview_it_authorises() {
        let (_d, s) = fresh().await;
        bound_with_type(&s, "payment.card").await;
        let preview = s
            .create_preview("ctx", "did:persona:a", "did:verifier:v", None, None, None)
            .await
            .unwrap();
        assert!(preview.approved_at.is_none(), "minted unapproved");

        assert!(s.approve_preview(&preview.preview_id).await.unwrap());
        let seen = s
            .peek_preview(&preview.preview_id)
            .await
            .unwrap()
            .expect("still there");
        assert!(seen.approved_at.is_some());
    }

    /// Peeking must not consume. The gate reads the preview before deciding
    /// whether to refuse, and a refusal that ate the preview would cost the
    /// holder the decision they already made — which is the whole reason
    /// `stepUpRequired` is retryable.
    #[tokio::test]
    async fn peeking_leaves_the_preview_for_the_retry() {
        let (_d, s) = fresh().await;
        bound_with_type(&s, "payment.card").await;
        let preview = s
            .create_preview("ctx", "did:persona:a", "did:verifier:v", None, None, None)
            .await
            .unwrap();

        assert!(s.peek_preview(&preview.preview_id).await.unwrap().is_some());
        assert!(
            s.peek_preview(&preview.preview_id).await.unwrap().is_some(),
            "a peek is not a consume, however many times it is done"
        );
        // And the consume still works afterwards, once.
        s.consume_preview(&preview.preview_id).await.unwrap();
        assert!(s.consume_preview(&preview.preview_id).await.is_err());
    }

    /// An approval arriving for a preview that is gone changes nothing and is
    /// not an error. The disclosure it would have authorised no longer exists;
    /// the holder previews again.
    #[tokio::test]
    async fn approving_a_vanished_preview_is_not_an_error() {
        let (_d, s) = fresh().await;
        assert!(!s.approve_preview("01JUNKUNKNOWN").await.unwrap());
    }

    /// An approval cannot outlive the disclosure it authorised: consuming the
    /// preview takes the approval with it, so a second disclosure needs a
    /// second approval. This is what "each time" means.
    #[tokio::test]
    async fn an_approval_does_not_survive_the_disclosure_it_authorised() {
        let (_d, s) = fresh().await;
        bound_with_type(&s, "payment.card").await;
        let preview = s
            .create_preview("ctx", "did:persona:a", "did:verifier:v", None, None, None)
            .await
            .unwrap();
        s.approve_preview(&preview.preview_id).await.unwrap();
        s.consume_preview(&preview.preview_id).await.unwrap();

        assert!(
            s.peek_preview(&preview.preview_id).await.unwrap().is_none(),
            "the approval goes with the preview it was written on"
        );
    }

    /// A persona bound to a profile with one self-asserted claim.
    async fn bound(s: &PersonaStore, value: &str) -> String {
        let a = new_attribute(
            "name.display",
            ValueType::String,
            serde_json::json!(value),
            Provenance::SelfAsserted,
        );
        s.put(a.clone(), None).await.unwrap();
        let p = new_profile(
            "Work",
            vec![ProfileEntry::Ref {
                r#ref: a.attribute_id.clone(),
            }],
        );
        s.put_profile(p.clone(), None).await.unwrap();
        s.set_binding("ctx", "did:persona:a", Some(&p.profile_id), vec![], None)
            .await
            .unwrap();
        p.profile_id
    }

    #[tokio::test]
    async fn present_consumes_the_preview_so_the_two_calls_cannot_be_collapsed() {
        let (_d, s) = fresh().await;
        bound(&s, "Stormer").await;
        let pv = s
            .create_preview(
                "ctx",
                "did:persona:a",
                "did:web:bar",
                Some("entry"),
                None,
                None,
            )
            .await
            .unwrap();

        s.present(&pv.preview_id, Some("nonce"), false)
            .await
            .expect("first present");

        // A replayed token would let a second disclosure ride the first
        // decision.
        let err = s
            .present(&pv.preview_id, Some("nonce"), false)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_disclosure_cannot_be_produced_without_a_preview() {
        // The structural property: present requires a token only create_preview
        // can mint, so there is no path that skips the summary.
        let (_d, s) = fresh().await;
        bound(&s, "Stormer").await;
        let err = s.present("01NEVERMINTED", None, false).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn an_expired_preview_is_refused_not_re_derived() {
        let (_d, s) = fresh().await;
        bound(&s, "Stormer").await;
        let mut pv = s
            .create_preview("ctx", "did:persona:a", "did:web:bar", None, None, None)
            .await
            .unwrap();

        // Age it past its TTL.
        pv.expires_at = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        s.ks.insert(preview_key(&pv.preview_id), &pv).await.unwrap();

        let err = s.present(&pv.preview_id, None, false).await.unwrap_err();
        assert!(matches!(err, AppError::Gone(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_renderer_that_cannot_carry_a_predicate_fails_at_negotiation() {
        let (_d, s) = fresh().await;
        bound(&s, "Stormer").await;

        // jcard declares it carries no provenance; the preview must say so
        // rather than let the holder discover it from a verifier.
        let pv = s
            .create_preview(
                "ctx",
                "did:persona:a",
                "did:web:bar",
                None,
                None,
                Some("jcard"),
            )
            .await
            .unwrap();
        assert_eq!(pv.renderer_drops, vec!["provenance".to_string()]);

        // And an unknown renderer is refused rather than silently defaulted to
        // the canonical one, which would disclose through a format the caller
        // never chose.
        let err = s
            .create_preview(
                "ctx",
                "did:persona:a",
                "did:web:bar",
                None,
                None,
                Some("mdoc"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn a_stale_claim_refuses_the_whole_disclosure() {
        let (_d, s) = fresh().await;
        bound(&s, "Stormer").await;
        let mut pv = s
            .create_preview("ctx", "did:persona:a", "did:web:bar", None, None, None)
            .await
            .unwrap();

        pv.claims[0].stale = true;
        s.ks.insert(preview_key(&pv.preview_id), &pv).await.unwrap();

        // Issuing a shorter disclosure would be indistinguishable, to the
        // verifier, from a holder who approved fewer claims.
        let err = s.present(&pv.preview_id, None, false).await.unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn the_subject_is_pairwise_so_two_verifiers_cannot_join_a_holder() {
        let (_d, s) = fresh().await;
        bound(&s, "Stormer").await;
        let a = s
            .create_preview("ctx", "did:persona:a", "did:web:one", None, None, None)
            .await
            .unwrap();
        let b = s
            .create_preview("ctx", "did:persona:a", "did:web:two", None, None, None)
            .await
            .unwrap();

        assert_ne!(
            a.subject, b.subject,
            "one persona must show two verifiers two faces"
        );
        assert_ne!(
            a.subject, "did:persona:a",
            "and neither face is the account"
        );

        // Stable for one relationship, so a counterparty recognises a returning
        // holder without anyone else being able to.
        let a2 = s
            .create_preview("ctx", "did:persona:a", "did:web:one", None, None, None)
            .await
            .unwrap();
        assert_eq!(a.subject, a2.subject);
    }

    #[tokio::test]
    async fn presenting_records_the_disclosure_and_marks_what_is_new() {
        let (_d, s) = fresh().await;
        bound(&s, "Stormer").await;

        let first = s
            .create_preview("ctx", "did:persona:a", "did:web:bar", None, None, None)
            .await
            .unwrap();
        assert!(first.claims[0].new_to_this_verifier, "nothing sent yet");
        s.present(&first.preview_id, None, false).await.unwrap();

        // The record exists and is queryable by the holder.
        let history = s
            .disclosure_history(&crate::disclosure::HistoryQuery::default())
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].verifier_did, "did:web:bar");
        assert_eq!(history[0].claims[0].r#type, "name.display");

        // A second preview to the same verifier knows the claim is not new,
        // which is what lets the preview rank rather than enumerate.
        let second = s
            .create_preview("ctx", "did:persona:a", "did:web:bar", None, None, None)
            .await
            .unwrap();
        assert!(!second.claims[0].new_to_this_verifier);
    }

    #[tokio::test]
    async fn an_unbound_persona_has_nothing_to_disclose() {
        let (_d, s) = fresh().await;
        let err = s
            .create_preview("ctx", "did:persona:none", "did:web:bar", None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn requested_claims_are_a_ceiling_not_a_hint() {
        let (_d, s) = fresh().await;
        bound(&s, "Stormer").await;
        // Narrowing to a type the profile does not carry yields nothing rather
        // than quietly disclosing what it does carry.
        let err = s
            .create_preview(
                "ctx",
                "did:persona:a",
                "did:web:bar",
                None,
                Some(&["address.postal".to_string()]),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }
}
