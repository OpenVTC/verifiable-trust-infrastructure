//! External cards (`vtc/directory/card/{publish,public}/0.1`, VTI-DIR-046):
//! a member's public values as a JSContact card **they** signed, served by the
//! community exactly as signed, and pointed to from their recognition record.
//!
//! The community never composes, signs or edits a card (VTI-REG-004 item 4).
//! It checks that what the member signed is exactly their public values
//! ([`expected_members`], [`compare`]) and verifies their proof; then it serves
//! the bytes it was given.
//!
//! **Never stale.** A card is served only while it still says exactly what the
//! member's card now shows the public. Whatever changes that — their update, an
//! administrator's assertion, a ceiling narrowed, a field retired, a policy
//! change, a suspension — the card is withdrawn to `awaitingSignature`
//! ([`reconcile`]). Every serving path reconciles first, so no hook missed can
//! serve a stale card; the hooks and the directory sweep only make the state,
//! and the registry pointer, follow promptly.
//!
//! Rows in the `directory` keyspace: `published:<entryId>` ([`Published`]).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tracing::warn;
use vti_common::audit::{AuditEvent, DirectoryCardPublicationData};
use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle};

use super::cards;
use super::model::{Card, ExternalCard, ExternalState, FieldDef, FieldState};
use super::project::{ProjectionContext, Subject};
use crate::server::AppState;

/// A card's `uid` is this and its entry identifier.
pub const UID_PREFIX: &str = "urn:vtc-directory:";

/// JSContact members that carry no directory value (`card/publish` item 4).
pub const NON_VALUE_MEMBERS: [&str; 7] = [
    "@type", "version", "uid", "issuer", "kind", "updated", "proof",
];

/// The cryptosuites a card's proof may use (`PublishedCard`).
pub const CRYPTOSUITES: [&str; 2] = ["eddsa-jcs-2022", "ecdsa-jcs-2019"];

/// `published:<entryId>`: the card the member signed, as received.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Published {
    pub card: Value,
    pub card_digest: String,
    pub published_at: DateTime<Utc>,
    /// The JSContact members the card was checked against when published:
    /// what the member's public values mapped to then. The card is current
    /// exactly while their public values still map to this.
    pub expected: Map<String, Value>,
    /// The `id` of the signed `card/publish` document.
    pub document_id: String,
}

pub(crate) fn published_key(entry_id: &str) -> Vec<u8> {
    format!("published:{entry_id}").into_bytes()
}

pub async fn get_published(
    ks: &KeyspaceHandle,
    entry_id: &str,
) -> Result<Option<Published>, AppError> {
    ks.get(published_key(entry_id)).await
}

// ─── the mapping ──────────────────────────────────────────────────────────

/// The JSContact members a card holding `public` must carry, keyed by member
/// name (`card/publish`, *Mapping the public values*). Map identifiers are
/// fixed, so two producers sign the same bytes for the same values.
pub fn expected_members(
    entry_id: &str,
    schema: &[FieldDef],
    public: &Map<String, Value>,
) -> Map<String, Value> {
    let mut out = Map::new();
    for field in schema.iter().filter(|f| f.state == FieldState::Active) {
        let Some(value) = public.get(&field.key) else {
            continue;
        };
        let (member, mapped) = map_field(entry_id, field, value);
        out.insert(member, mapped);
    }
    out
}

/// One field's JSContact member: its name and value.
fn map_field(entry_id: &str, field: &FieldDef, value: &Value) -> (String, Value) {
    let path = field
        .base
        .then_some(field.js_contact_path.as_deref())
        .flatten();
    match (path, value) {
        (Some("name.full"), v) => ("name".into(), json!({ "full": v })),
        (Some("nicknames"), v) => ("nicknames".into(), json!({ "k1": { "name": v } })),
        (Some("media"), v) => (
            "media".into(),
            json!({ "m1": {
                "kind": "photo",
                "uri": format!(
                    "{UID_PREFIX}{entry_id}:{}:{}",
                    field.key,
                    super::images::sha_of(v).unwrap_or_default()
                ),
                "mediaType": v.get("mediaType").cloned().unwrap_or(Value::Null),
            }}),
        ),
        (Some("speakToAs.pronouns"), v) => (
            "speakToAs".into(),
            json!({ "pronouns": { "p1": { "pronouns": v } } }),
        ),
        (Some("notes"), v) => ("notes".into(), json!({ "n1": { "note": v } })),
        (Some("links"), Value::Array(items)) => {
            let links: Map<String, Value> = items
                .iter()
                .enumerate()
                .map(|(i, uri)| (format!("l{}", i + 1), json!({ "uri": uri })))
                .collect();
            ("links".into(), Value::Object(links))
        }
        // Every other field: a member named by its key, holding the value as
        // the card holds it. A stored picture never carries a URL.
        _ => (field.key.clone(), value.clone()),
    }
}

/// The directory field a JSContact member carries, for `cardMismatch`'s
/// `fields`.
fn field_of(member: &str, schema: &[FieldDef]) -> String {
    let by_path = |path: &str| {
        schema
            .iter()
            .find(|f| f.base && f.js_contact_path.as_deref() == Some(path))
            .map(|f| f.key.clone())
    };
    match member {
        "name" => by_path("name.full"),
        "speakToAs" => by_path("speakToAs.pronouns"),
        "nicknames" | "media" | "notes" | "links" => by_path(member),
        _ => None,
    }
    .unwrap_or_else(|| member.to_string())
}

/// Why a card is not the one the member may publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `cardMismatch`, naming the fields that differ (none when the card's
    /// frame — `@type`, `version`, `uid` — is what is wrong).
    Mismatch { fields: Vec<String>, why: String },
    /// `signatureInvalid`.
    Signature(String),
}

/// Check `card` carries exactly `expected` and nothing else that holds a
/// directory value, under the frame `PublishedCard` leaves to the consumer:
/// its own entry as `uid`, and `did` — the membership DID — as `issuer`, the
/// signer a custodian holding the member's key signs as (`card/publish`
/// items 4 and 5).
pub fn compare(
    card: &Value,
    entry_id: &str,
    did: &str,
    schema: &[FieldDef],
    expected: &Map<String, Value>,
) -> Result<(), Refusal> {
    let frame = |why: &str| Refusal::Mismatch {
        fields: vec![],
        why: why.to_string(),
    };
    let Some(obj) = card.as_object() else {
        return Err(frame("the card is not a JSON object"));
    };
    if obj.get("@type").and_then(Value::as_str) != Some("Card") {
        return Err(frame("the card's `@type` is not `Card`"));
    }
    if obj.get("version").and_then(Value::as_str) != Some("1.0") {
        return Err(frame("the card's `version` is not `1.0`"));
    }
    if obj.get("uid").and_then(Value::as_str) != Some(format!("{UID_PREFIX}{entry_id}").as_str()) {
        return Err(frame(
            "the card's `uid` does not name the member's own entry",
        ));
    }
    if obj.get("issuer").and_then(Value::as_str) != Some(did) {
        return Err(frame(
            "the card's `issuer` is not the member's membership DID",
        ));
    }
    let mut differ: Vec<String> = Vec::new();
    for (member, value) in obj {
        if NON_VALUE_MEMBERS.contains(&member.as_str()) {
            continue;
        }
        if expected.get(member) != Some(value) {
            differ.push(field_of(member, schema));
        }
    }
    for member in expected.keys() {
        if !obj.contains_key(member) {
            differ.push(field_of(member, schema));
        }
    }
    if differ.is_empty() {
        return Ok(());
    }
    differ.sort();
    differ.dedup();
    Err(Refusal::Mismatch {
        why: format!(
            "the card is not exactly the member's public values: {}",
            differ.join(", ")
        ),
        fields: differ,
    })
}

/// The proof's shape, which `PublishedCard` leaves to the consumer: one
/// `DataIntegrityProof`, an accepted cryptosuite, made for `assertionMethod`
/// (`card/publish` item 5). Whether it verifies is [`verify`]'s question.
pub fn check_proof(card: &Value) -> Result<(), Refusal> {
    let bad = |why: &str| Refusal::Signature(why.to_string());
    let Some(proof) = card.get("proof") else {
        return Err(bad("the card carries no proof"));
    };
    let Some(proof) = proof.as_object() else {
        return Err(bad("the card's proof is not one Data Integrity proof"));
    };
    if proof.get("type").and_then(Value::as_str) != Some("DataIntegrityProof") {
        return Err(bad("the card's proof is not a DataIntegrityProof"));
    }
    if !proof
        .get("cryptosuite")
        .and_then(Value::as_str)
        .is_some_and(|c| CRYPTOSUITES.contains(&c))
    {
        return Err(bad(
            "the card's proof uses neither eddsa-jcs-2022 nor ecdsa-jcs-2019",
        ));
    }
    if proof.get("proofPurpose").and_then(Value::as_str) != Some("assertionMethod") {
        return Err(bad("the card's proof is not made for assertionMethod"));
    }
    Ok(())
}

/// Verify the card's proof over the card without it, by one of `did`'s
/// `assertionMethod` verification methods (`card/publish` item 5).
pub async fn verify(state: &AppState, card: &Value, did: &str) -> Result<(), Refusal> {
    let resolver = crate::credentials::vm_resolver::DidVmResolver::new(state.did_resolver.clone());
    crate::credentials::proof_set::verify_issued(card, did, &resolver)
        .await
        .map_err(Refusal::Signature)
}

/// `cardDigest`: RFC 8785 JCS of the card exactly as signed, `proof` included,
/// as a SHA-256 multihash in base58btc. Not `dtg_credentials`'
/// `digest_multibase_json`, which digests a document without its proof: the
/// digest names the exact signed card, signature and all.
pub fn card_digest(card: &Value) -> Result<String, AppError> {
    use sha2::{Digest, Sha256};
    let canonical = serde_json_canonicalizer::to_vec(card)
        .map_err(|e| AppError::Internal(format!("card digest: {e}")))?;
    let mut multihash = vec![0x12, 0x20];
    multihash.extend_from_slice(&Sha256::digest(&canonical));
    Ok(multibase::encode(multibase::Base::Base58Btc, multihash))
}

// ─── state ────────────────────────────────────────────────────────────────

/// What `card`'s member's public values map to now.
pub async fn current_expected(
    state: &AppState,
    card: &Card,
) -> Result<Map<String, Value>, AppError> {
    let ctx = super::read::read_context(state).await?;
    let subject = match super::read::subject_by_did(state, &card.did).await? {
        Some(s) => s,
        // A card whose member record is gone shows the public nothing.
        None => return Ok(Map::new()),
    };
    expected_for(&ctx.projection_at(Utc::now()), &subject)
}

/// [`current_expected`] for a subject already read.
pub fn expected_for(
    ctx: &ProjectionContext<'_>,
    subject: &Subject,
) -> Result<Map<String, Value>, AppError> {
    let public = super::project::public_fields(ctx, subject)?;
    Ok(expected_members(
        &subject.card.entry_id,
        ctx.schema,
        &public,
    ))
}

/// Store a publication: the signed card as received, the card's state
/// `published`, `external` on, the revision incremented (`card/publish`
/// item 6). `false` when the card changed since `before` was read.
pub async fn commit_publication(
    ks: &KeyspaceHandle,
    before: &Card,
    published: &Published,
) -> Result<Option<Card>, AppError> {
    let _guard = super::WRITE_LOCK.lock().await;
    let Some(current) = cards::get(ks, &before.entry_id).await? else {
        return Ok(None);
    };
    if current.revision != before.revision || current.did != before.did {
        return Ok(None);
    }
    let mut next = current;
    next.discoverability.external = true;
    next.external_card = Some(ExternalCard {
        state: ExternalState::Published,
        card_digest: Some(published.card_digest.clone()),
        published_at: Some(published.published_at),
    });
    next.revision += 1;
    next.updated_at = published.published_at;
    let mut batch = Batch::new();
    batch
        .insert(cards::card_key(&next.entry_id), &next)?
        .insert(published_key(&next.entry_id), published)?;
    ks.apply_batch(batch).await?;
    Ok(Some(next))
}

/// Why a card is withdrawn — the audit row's `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withdrawal {
    /// The member's public values changed: `awaitingSignature`, publication
    /// still chosen (`card/publish` item 8).
    Stale,
    /// The member turned `external` off (`card/update` item 7).
    Member,
    /// The member withdrew registry-publication consent (VTI-DIR-047).
    Consent,
    /// The member left (VTI-DIR-120).
    Departure,
}

impl Withdrawal {
    fn as_str(self) -> &'static str {
        match self {
            Withdrawal::Stale => "stale",
            Withdrawal::Member => "member",
            Withdrawal::Consent => "consent",
            Withdrawal::Departure => "departure",
        }
    }
}

/// Withdraw `entry_id`'s external card: stop serving and erase it at once,
/// and leave the card `awaitingSignature` ([`Withdrawal::Stale`]) or with
/// `external` off (every other reason). The registry pointer follows through
/// the audit tail. Returns the digest withdrawn, if one was published.
pub async fn withdraw(
    state: &AppState,
    entry_id: &str,
    why: Withdrawal,
) -> Result<Option<String>, AppError> {
    let ks = state.directory.ks();
    let (did, digest) = {
        let _guard = super::WRITE_LOCK.lock().await;
        let Some(mut card) = cards::get(ks, entry_id).await? else {
            ks.remove(published_key(entry_id)).await?;
            return Ok(None);
        };
        let digest = card.published_digest().map(str::to_string);
        let unchanged = match why {
            Withdrawal::Stale => digest.is_none(),
            _ => !card.discoverability.external && card.external_card.is_none(),
        };
        if unchanged {
            ks.remove(published_key(entry_id)).await?;
            return Ok(None);
        }
        match why {
            Withdrawal::Stale => card.external_card = Some(ExternalCard::awaiting_signature()),
            _ => {
                card.discoverability.external = false;
                card.external_card = None;
            }
        }
        let mut batch = Batch::new();
        batch
            .remove(published_key(entry_id))
            .insert(cards::card_key(entry_id), &card)?;
        ks.apply_batch(batch).await?;
        (card.did, digest)
    };
    record(
        state,
        &did,
        entry_id,
        "withdrawn",
        Some(why),
        digest.clone(),
        None,
    )
    .await;
    Ok(digest)
}

/// Audit a publication or withdrawal. The member's DID is the target, which is
/// what lets the registry syncer re-publish their record with or without the
/// pointer. Withdrawal has already happened by the time this runs, so a failed
/// audit write is logged, not refused: the sweep repairs the pointer.
pub(crate) async fn record(
    state: &AppState,
    did: &str,
    entry_id: &str,
    change: &str,
    why: Option<Withdrawal>,
    card_digest: Option<String>,
    document_id: Option<String>,
) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let actor = match why {
        Some(Withdrawal::Member | Withdrawal::Consent) | None => did,
        Some(Withdrawal::Stale | Withdrawal::Departure) => super::sweep::ACTOR,
    };
    if let Err(e) = writer
        .write(
            actor,
            Some(did),
            AuditEvent::DirectoryCardPublication(DirectoryCardPublicationData {
                entry_id: entry_id.to_string(),
                change: change.to_string(),
                reason: why.map(|w| w.as_str().to_string()),
                card_digest,
                document_id,
            }),
        )
        .await
    {
        warn!(error = %e, entry_id, change, "could not audit an external card change");
    }
}

/// Withdraw `entry_id`'s card to `awaitingSignature` if it no longer says
/// exactly what the member's card shows the public. Returns whether it did.
pub async fn reconcile(state: &AppState, entry_id: &str) -> Result<bool, AppError> {
    let ks = state.directory.ks();
    let Some(card) = cards::get(ks, entry_id).await? else {
        return Ok(false);
    };
    if card.published_digest().is_none() {
        return Ok(false);
    }
    let current = match get_published(ks, entry_id).await? {
        Some(p) if Some(p.card_digest.as_str()) == card.published_digest() => {
            p.expected == current_expected(state, &card).await?
        }
        _ => false,
    };
    if current {
        return Ok(false);
    }
    withdraw(state, entry_id, Withdrawal::Stale).await?;
    Ok(true)
}

/// [`reconcile`] every published card. Returns how many were withdrawn.
pub async fn reconcile_all(state: &AppState) -> Result<usize, AppError> {
    let mut withdrawn = 0;
    for card in cards::all(state.directory.ks()).await? {
        if card.published_digest().is_some() && reconcile(state, &card.entry_id).await? {
            withdrawn += 1;
        }
    }
    Ok(withdrawn)
}

/// The card to serve for `entry_id`, if one is published and still current —
/// reconciled first, so nothing stale is ever served (`card/publish` item 8).
pub async fn served(state: &AppState, entry_id: &str) -> Result<Option<Published>, AppError> {
    if reconcile(state, entry_id).await? {
        return Ok(None);
    }
    let ks = state.directory.ks();
    let Some(card) = cards::get(ks, entry_id).await? else {
        return Ok(None);
    };
    let Some(digest) = card.published_digest() else {
        return Ok(None);
    };
    Ok(get_published(ks, entry_id)
        .await?
        .filter(|p| p.card_digest == digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::fields::base_fields;

    const ENTRY: &str = "dir_Q2xhcmFRMmxoY21GUk1t";

    fn carol_public() -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("displayName".into(), json!("Carol Example"));
        m.insert(
            "bio".into(),
            json!("Rust, decentralised identity, and long walks."),
        );
        m
    }

    const CAROL: &str = "did:example:carol";

    /// The specification's own example card, signed.
    fn spec_card() -> Value {
        json!({
            "@type": "Card",
            "version": "1.0",
            "uid": "urn:vtc-directory:dir_Q2xhcmFRMmxoY21GUk1t",
            "issuer": "did:example:carol",
            "name": { "full": "Carol Example" },
            "notes": { "n1": { "note": "Rust, decentralised identity, and long walks." } },
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:example:carol#key-1",
                "created": "2026-10-19T09:10:00Z",
                "proofPurpose": "assertionMethod",
                "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz"
            }
        })
    }

    #[test]
    fn the_specs_example_card_is_exactly_carols_public_values() {
        let schema = base_fields();
        let expected = expected_members(ENTRY, &schema, &carol_public());
        compare(&spec_card(), ENTRY, CAROL, &schema, &expected).unwrap();
        check_proof(&spec_card()).unwrap();
    }

    #[test]
    fn the_digest_covers_the_signature() {
        let mut other = spec_card();
        other["proof"]["proofValue"] = json!("z3FXQ");
        assert_ne!(
            card_digest(&other).unwrap(),
            card_digest(&spec_card()).unwrap()
        );
    }

    #[test]
    fn the_specs_example_digest_is_reproduced() {
        assert_eq!(
            card_digest(&spec_card()).unwrap(),
            "zQmcjRKZd1TExLaEuMVv5xe2tTx4a1YkRQ58zwVrnByxYS4"
        );
    }

    #[test]
    fn every_base_field_maps_to_its_fixed_place() {
        let schema = base_fields();
        let mut public = carol_public();
        public.insert("nickname".into(), json!("cee"));
        public.insert("pronouns".into(), json!("she/her"));
        public.insert(
            "links".into(),
            json!(["https://a.example", "https://b.example"]),
        );
        public.insert(
            "avatar".into(),
            json!({ "sha256": "ab".repeat(32), "mediaType": "image/jpeg", "size": 9 }),
        );
        let got = expected_members(ENTRY, &schema, &public);
        assert_eq!(got["nicknames"], json!({ "k1": { "name": "cee" } }));
        assert_eq!(
            got["speakToAs"],
            json!({ "pronouns": { "p1": { "pronouns": "she/her" } } })
        );
        assert_eq!(
            got["links"],
            json!({ "l1": { "uri": "https://a.example" }, "l2": { "uri": "https://b.example" } })
        );
        assert_eq!(
            got["media"],
            json!({ "m1": {
                "kind": "photo",
                "uri": format!("urn:vtc-directory:{ENTRY}:avatar:{}", "ab".repeat(32)),
                "mediaType": "image/jpeg",
            }})
        );
    }

    #[test]
    fn a_community_field_is_a_member_named_by_its_key() {
        let mut schema = base_fields();
        let mut f = schema[0].clone();
        f.key = "org.example.team".into();
        f.base = false;
        f.js_contact_path = Some("name.full".into());
        schema.push(f);
        let mut public = Map::new();
        public.insert("org.example.team".into(), json!("Platform"));
        let got = expected_members(ENTRY, &schema, &public);
        // A community field's own path is never followed.
        assert_eq!(got.get("org.example.team"), Some(&json!("Platform")));
        assert!(got.get("name").is_none());
    }

    #[test]
    fn a_card_that_says_more_less_or_otherwise_names_the_fields() {
        let schema = base_fields();
        let expected = expected_members(ENTRY, &schema, &carol_public());
        let mut more = spec_card();
        more["speakToAs"] = json!({ "pronouns": { "p1": { "pronouns": "she/her" } } });
        let mut less = spec_card();
        less.as_object_mut().unwrap().remove("notes");
        let mut other = spec_card();
        other["name"] = json!({ "full": "Someone Else" });
        for (card, field) in [(more, "pronouns"), (less, "bio"), (other, "displayName")] {
            match compare(&card, ENTRY, CAROL, &schema, &expected) {
                Err(Refusal::Mismatch { fields, .. }) => assert_eq!(fields, vec![field]),
                other => panic!("{field}: {other:?}"),
            }
        }
        let mut stray = spec_card();
        stray["org.example.extra"] = json!("x");
        assert!(matches!(
            compare(&stray, ENTRY, CAROL, &schema, &expected),
            Err(Refusal::Mismatch { .. })
        ));
    }

    #[test]
    fn the_frame_is_checked_before_the_values() {
        let schema = base_fields();
        let expected = expected_members(ENTRY, &schema, &carol_public());
        let mut other_entry = spec_card();
        other_entry["uid"] = json!("urn:vtc-directory:dir_SomebodyElse000000");
        let mut not_card = spec_card();
        not_card["@type"] = json!("Group");
        let mut other_issuer = spec_card();
        other_issuer["issuer"] = json!("did:example:dave");
        let mut no_issuer = spec_card();
        no_issuer.as_object_mut().unwrap().remove("issuer");
        for card in [other_entry, not_card, other_issuer, no_issuer] {
            assert!(matches!(
                compare(&card, ENTRY, CAROL, &schema, &expected),
                Err(Refusal::Mismatch { fields, .. }) if fields.is_empty()
            ));
        }
    }

    #[test]
    fn a_proof_of_the_wrong_shape_is_a_signature_refusal() {
        for (member, value) in [
            ("proofPurpose", json!("authentication")),
            ("cryptosuite", json!("bbs-2023")),
            ("type", json!("Ed25519Signature2020")),
        ] {
            let mut card = spec_card();
            card["proof"][member] = value;
            assert!(
                matches!(check_proof(&card), Err(Refusal::Signature(_))),
                "{member}"
            );
        }
        let mut set = spec_card();
        set["proof"] = json!([spec_card()["proof"].clone()]);
        assert!(matches!(check_proof(&set), Err(Refusal::Signature(_))));
        let mut none = spec_card();
        none.as_object_mut().unwrap().remove("proof");
        assert!(matches!(check_proof(&none), Err(Refusal::Signature(_))));
    }
}
