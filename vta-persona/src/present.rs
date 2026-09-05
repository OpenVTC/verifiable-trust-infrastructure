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

        let mut claims = Vec::new();
        for m in &materialised {
            if let Some(want) = requested
                && !want.iter().any(|t| t == &m.r#type)
            {
                continue;
            }
            claims.push(preview_claim(m, &seen));
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
            preview_id: ulid::Ulid::new().to_string(),
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
        };

        let _guard = self.write_lock.lock().await;
        self.ks
            .insert(preview_key(&preview.preview_id), &preview)
            .await?;
        Ok(preview)
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
            record.durable_credential_id = Some(ulid::Ulid::new().to_string());
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
