//! Cards: one per member, keyed by a random entry identifier
//! (`card:<entryId>`), with an index from the member's current DID
//! (`entry:<did>`).
//!
//! The entry identifier is what every other store keys on, so a rotation
//! rewrites only the index and the card's `did` (VTI-DIR-050, VTI-DIR-122).

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle};

use super::fields::{DERIVED_KEYS, MEMBER_CHOOSABLE_DERIVED};
use super::model::{
    AppliedUpdate, Audience, Card, Discoverability, FieldDef, FieldSource, FieldState,
    Introductions, Listing, SearchMode, Settings,
};

/// A card's values, serialized, may not exceed this (VTI-DIR-016).
pub const MAX_CARD_VALUE_BYTES: usize = 16 * 1024;

/// Whether a member can publish their card beyond the community (VTI-DIR-046).
/// This build cannot, so `card/update` refuses `external` and the disclosure
/// statement says no card leaves the community.
pub const EXTERNAL_PUBLICATION: bool = false;

/// What a member's search may match on a new card.
pub const NEW_CARD_SEARCH: SearchMode = SearchMode::ByName;

/// From whom a new card accepts introductions.
pub const NEW_CARD_INTRODUCTIONS: Introductions = Introductions::Anyone;

fn card_key(entry_id: &str) -> Vec<u8> {
    format!("card:{entry_id}").into_bytes()
}

fn index_key(did: &str) -> Vec<u8> {
    format!("entry:{did}").into_bytes()
}

/// A fresh entry identifier: `dir_` and 22 base64url characters of
/// randomness, derived from nothing about the member (VTI-DIR-050).
pub fn new_entry_id() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    format!(
        "dir_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

pub async fn get(ks: &KeyspaceHandle, entry_id: &str) -> Result<Option<Card>, AppError> {
    ks.get(card_key(entry_id)).await
}

/// The entry identifier of `did`'s card, if it has one.
pub async fn entry_of(ks: &KeyspaceHandle, did: &str) -> Result<Option<String>, AppError> {
    Ok(ks
        .get_raw(index_key(did))
        .await?
        .and_then(|b| String::from_utf8(b).ok()))
}

pub async fn by_did(ks: &KeyspaceHandle, did: &str) -> Result<Option<Card>, AppError> {
    match entry_of(ks, did).await? {
        Some(id) => get(ks, &id).await,
        None => Ok(None),
    }
}

/// Every stored card.
pub async fn all(ks: &KeyspaceHandle) -> Result<Vec<Card>, AppError> {
    ks.prefix_iter_raw(b"card:".to_vec())
        .await?
        .into_iter()
        .map(|(_, raw)| {
            serde_json::from_slice(&raw).map_err(|e| {
                AppError::Internal(format!("stored directory card is unreadable: {e}"))
            })
        })
        .collect()
}

/// A new card as a member starts with it (`card/show` item 3): no values but
/// the name they gave themselves, every visibility at its default, the
/// community's listing, `byName`, never external, introductions from anyone.
pub fn fresh(did: &str, settings: &Settings, own_label: Option<&str>, now: DateTime<Utc>) -> Card {
    let mut values = BTreeMap::new();
    // A label the member set on their own entry is the name they chose for
    // this community; one an administrator set is not theirs to publish.
    if let Some(label) = own_label
        && !label.trim().is_empty()
        && label.chars().count() <= 64
        && !label.contains('\n')
    {
        values.insert("displayName".to_string(), Value::String(label.to_string()));
    }
    Card {
        entry_id: new_entry_id(),
        did: did.to_string(),
        values,
        visibility: BTreeMap::new(),
        discoverability: Discoverability {
            listing: settings.default_listing,
            search: NEW_CARD_SEARCH,
            // VTI-DIR-042: only ever the member's own choice.
            external: false,
        },
        introductions: NEW_CARD_INTRODUCTIONS,
        group_audience: None,
        revision: 0,
        updated_at: now,
        last_update: None,
    }
}

/// `did`'s card, created if it has none. Every member has a card; one that has
/// never been read or written is made the first time anyone needs it.
pub async fn ensure(
    ks: &KeyspaceHandle,
    did: &str,
    settings: &Settings,
    own_label: Option<&str>,
) -> Result<Card, AppError> {
    if let Some(card) = by_did(ks, did).await? {
        return Ok(card);
    }
    let _guard = super::WRITE_LOCK.lock().await;
    if let Some(card) = by_did(ks, did).await? {
        return Ok(card);
    }
    let card = fresh(did, settings, own_label, Utc::now());
    let mut batch = Batch::new();
    batch
        .require_absent(index_key(did))
        .require_absent(card_key(&card.entry_id))
        .insert(card_key(&card.entry_id), &card)?
        .insert_raw(index_key(did), card.entry_id.clone().into_bytes());
    if !ks.apply_batch(batch).await?.is_applied() {
        return Err(AppError::Conflict(
            "a directory card was created for this member concurrently; read it again".into(),
        ));
    }
    Ok(card)
}

/// Store `card`, provided its stored revision is still `expected_revision`.
async fn store_if_revision(
    ks: &KeyspaceHandle,
    card: &Card,
    expected_revision: u64,
) -> Result<bool, AppError> {
    let Some(current) = get(ks, &card.entry_id).await? else {
        return Ok(false);
    };
    if current.revision != expected_revision || current.did != card.did {
        return Ok(false);
    }
    ks.insert(card_key(&card.entry_id), card).await?;
    Ok(true)
}

/// Why a card write was refused — one variant per declared error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardError {
    Superseded {
        revision: u64,
    },
    FieldUnknown(String),
    FieldRetired(String),
    FieldNotWritable(String),
    ValueInvalid {
        field: String,
        reason: String,
    },
    AboveCeiling {
        field: String,
        ceiling: Audience,
    },
    NotAvailable,
    /// A widening only the membership DID itself may sign (`card/update`
    /// producer conformance).
    NeedsMembershipDid,
}

/// Who is writing, and how far their write may reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writer {
    /// The member, signing as their membership DID.
    Member,
    /// The member, through a key they delegated for this community.
    Delegated,
    /// An administrator asserting `admin`-sourced values.
    Admin,
}

/// A member's `card/update`, as read from its payload. `None` members are not
/// in the document. `group_audience` distinguishes absent (`None`) from
/// `null` (`Some(None)`), which the generated type cannot.
#[derive(Debug, Clone, Default)]
pub struct MemberUpdate {
    pub values: BTreeMap<String, Option<Value>>,
    pub visibility: BTreeMap<String, Option<Audience>>,
    pub discoverability: Option<Discoverability>,
    pub introductions: Option<Introductions>,
    pub group_audience: Option<Option<Vec<String>>>,
    pub expected_revision: Option<u64>,
}

impl MemberUpdate {
    /// Read the members of a schema-checked `card/update/0.1` payload.
    pub fn from_payload(p: &Value) -> Result<Self, AppError> {
        let bad = |what: &str| AppError::Validation(format!("card/update: unreadable {what}"));
        let mut out = MemberUpdate::default();
        if let Some(v) = p.get("values").and_then(Value::as_object) {
            for (k, val) in v {
                out.values
                    .insert(k.clone(), (!val.is_null()).then(|| val.clone()));
            }
        }
        if let Some(v) = p.get("visibility").and_then(Value::as_object) {
            for (k, a) in v {
                let a = match a {
                    Value::Null => None,
                    Value::String(s) => Some(Audience::parse(s).ok_or_else(|| bad("audience"))?),
                    _ => return Err(bad("audience")),
                };
                out.visibility.insert(k.clone(), a);
            }
        }
        if let Some(d) = p.get("discoverability") {
            out.discoverability =
                Some(serde_json::from_value(d.clone()).map_err(|_| bad("discoverability"))?);
        }
        if let Some(i) = p.get("introductions") {
            out.introductions =
                Some(serde_json::from_value(i.clone()).map_err(|_| bad("introductions"))?);
        }
        if let Some(g) = p.get("groupAudience") {
            out.group_audience = Some(if g.is_null() {
                None
            } else {
                Some(serde_json::from_value(g.clone()).map_err(|_| bad("groupAudience"))?)
            });
        }
        out.expected_revision = p.get("expectedRevision").and_then(Value::as_u64);
        Ok(out)
    }
}

/// The result of applying a write to a card in memory.
#[derive(Debug, Clone)]
pub struct Applied {
    pub card: Card,
    /// Fields whose value or visibility the write named — what the audit row
    /// lists (never the values).
    pub changed: Vec<String>,
    /// Whether anything the write did lets a viewer see or find more than
    /// before. A write that only narrows is never refused by policy
    /// (`card/update` item 5).
    pub widens: bool,
}

fn schema_map(schema: &[FieldDef]) -> BTreeMap<&str, &FieldDef> {
    schema.iter().map(|f| (f.key.as_str(), f)).collect()
}

fn check_field<'a>(
    schema: &BTreeMap<&str, &'a FieldDef>,
    key: &str,
) -> Result<&'a FieldDef, CardError> {
    let f = schema
        .get(key)
        .copied()
        .ok_or_else(|| CardError::FieldUnknown(key.into()))?;
    if f.state != FieldState::Active {
        return Err(CardError::FieldRetired(key.into()));
    }
    Ok(f)
}

/// Apply a member's update to `card` (`card/update` items 2 – 7), in memory.
/// The caller evaluates `directoryWrite` over the result before storing it.
pub fn apply_member_update(
    card: &Card,
    schema: &[FieldDef],
    update: &MemberUpdate,
    writer: Writer,
    document_id: &str,
    issued_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<Applied, CardError> {
    // VTI-DIR-012: never apply an update issued before the one in force.
    if card
        .last_update
        .as_ref()
        .is_some_and(|last| last.issued_at > issued_at)
        || update.expected_revision.is_some_and(|r| r != card.revision)
    {
        return Err(CardError::Superseded {
            revision: card.revision,
        });
    }
    let schema = schema_map(schema);
    let mut next = card.clone();
    let mut changed = BTreeSet::new();
    let mut widens = false;

    for (key, value) in &update.values {
        let f = check_field(&schema, key)?;
        // VTI-DIR-011 / VTI-DIR-013: a member writes only what is theirs.
        if f.source != FieldSource::Member {
            return Err(CardError::FieldNotWritable(key.clone()));
        }
        match value {
            None => {
                next.values.remove(key);
            }
            Some(v) => {
                super::values::check(f, v).map_err(|reason| CardError::ValueInvalid {
                    field: key.clone(),
                    reason,
                })?;
                if card.values.get(key) != Some(v) {
                    // A new or changed value is something someone may now see.
                    widens = true;
                }
                next.values.insert(key.clone(), v.clone());
            }
        }
        changed.insert(key.clone());
    }

    for (key, audience) in &update.visibility {
        let f = check_field(&schema, key)?;
        if f.source == FieldSource::Derived && key != MEMBER_CHOOSABLE_DERIVED {
            return Err(CardError::FieldNotWritable(key.clone()));
        }
        let before = card.chosen(f);
        match audience {
            None => {
                next.visibility.remove(key);
            }
            Some(a) => {
                // Never clamped silently: the member must know what they chose.
                if !a.within(f.ceiling) {
                    return Err(CardError::AboveCeiling {
                        field: key.clone(),
                        ceiling: f.ceiling,
                    });
                }
                if *a == Audience::Public && writer == Writer::Delegated {
                    return Err(CardError::NeedsMembershipDid);
                }
                next.visibility.insert(key.clone(), *a);
            }
        }
        if next.chosen(f).reaches_beyond(before) {
            widens = true;
        }
        changed.insert(key.clone());
    }

    if let Some(d) = update.discoverability {
        if d.external && !EXTERNAL_PUBLICATION {
            // VTI-DIR-046 / VTI-REG-004: this build publishes no external
            // card. Refused whole, so nothing else in the document lands.
            return Err(CardError::NotAvailable);
        }
        let was = card.discoverability;
        if d.listing.rank() > was.listing.rank() || d.search.rank() > was.search.rank() {
            widens = true;
        }
        next.discoverability = d;
    }

    if let Some(i) = update.introductions {
        let rank = |i: Introductions| match i {
            Introductions::Off => 0,
            Introductions::Groups | Introductions::Connections => 1,
            Introductions::Anyone => 2,
        };
        if rank(i) > rank(card.introductions)
            || (rank(i) == 1 && i != card.introductions && rank(card.introductions) == 1)
        {
            widens = true;
        }
        next.introductions = i;
    }

    if let Some(groups) = &update.group_audience {
        // `None` is every group the member is in: wider than any list.
        if groups.is_none() && card.group_audience.is_some() {
            widens = true;
        }
        if let (Some(new), Some(old)) = (groups, &card.group_audience)
            && new.iter().any(|g| !old.contains(g))
        {
            widens = true;
        }
        next.group_audience = groups.clone();
    }

    check_size(&next)?;
    next.revision = card.revision + 1;
    next.updated_at = now;
    next.last_update = Some(AppliedUpdate {
        document_id: document_id.to_string(),
        issued_at,
    });
    Ok(Applied {
        card: next,
        changed: changed.into_iter().collect(),
        widens,
    })
}

/// Apply an administrator's assertion (`card/assert` items 3 and 5): only
/// `admin`-sourced values, never a visibility.
pub fn apply_assertion(
    card: &Card,
    schema: &[FieldDef],
    values: &BTreeMap<String, Option<Value>>,
    now: DateTime<Utc>,
) -> Result<Applied, CardError> {
    let schema = schema_map(schema);
    let mut next = card.clone();
    let mut changed = Vec::new();
    for (key, value) in values {
        let f = check_field(&schema, key)?;
        if f.source != FieldSource::Admin {
            return Err(CardError::FieldNotWritable(key.clone()));
        }
        match value {
            None => {
                next.values.remove(key);
            }
            Some(v) => {
                super::values::check(f, v).map_err(|reason| CardError::ValueInvalid {
                    field: key.clone(),
                    reason,
                })?;
                next.values.insert(key.clone(), v.clone());
            }
        }
        changed.push(key.clone());
    }
    check_size(&next)?;
    next.revision = card.revision + 1;
    next.updated_at = now;
    Ok(Applied {
        card: next,
        changed,
        widens: true,
    })
}

fn check_size(card: &Card) -> Result<(), CardError> {
    let bytes = serde_json::to_vec(&card.values)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if bytes > MAX_CARD_VALUE_BYTES {
        return Err(CardError::ValueInvalid {
            field: "values".into(),
            reason: format!("a card holds at most {MAX_CARD_VALUE_BYTES} bytes of values"),
        });
    }
    Ok(())
}

/// Store an applied write, provided nobody else changed the card since it was
/// read. `false`: read and apply again.
pub async fn commit(
    ks: &KeyspaceHandle,
    before: &Card,
    applied: &Applied,
) -> Result<bool, AppError> {
    let _guard = super::WRITE_LOCK.lock().await;
    store_if_revision(ks, &applied.card, before.revision).await
}

/// VTI-DIR-122: a rotation carries the card to the new DID without changing
/// its entry identifier. A member with no card has nothing to carry.
pub async fn rotate(ks: &KeyspaceHandle, old_did: &str, new_did: &str) -> Result<(), AppError> {
    let _guard = super::WRITE_LOCK.lock().await;
    let Some(entry_id) = entry_of(ks, old_did).await? else {
        return Ok(());
    };
    let Some(mut card) = get(ks, &entry_id).await? else {
        ks.remove(index_key(old_did)).await?;
        return Ok(());
    };
    card.did = new_did.to_string();
    let mut batch = Batch::new();
    batch
        .require_absent(index_key(new_did))
        .remove(index_key(old_did))
        .insert_raw(index_key(new_did), entry_id.clone().into_bytes())
        .insert(card_key(&entry_id), &card)?;
    if !ks.apply_batch(batch).await?.is_applied() {
        return Err(AppError::Conflict(format!(
            "{new_did} already has a directory entry; the rotation cannot carry the card"
        )));
    }
    Ok(())
}

/// How a departure leaves the card (VTI-DIR-121).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Departure {
    /// `purge` and `tombstone`: the card and its index are erased. A
    /// tombstone keeps a record that someone was a member, never what they
    /// said about themselves.
    Erase,
    /// `historical`: kept verbatim. Never projected again — the member is no
    /// longer active (VTI-DIR-111).
    Keep,
}

pub async fn on_departure(ks: &KeyspaceHandle, did: &str, how: Departure) -> Result<(), AppError> {
    if how == Departure::Keep {
        return Ok(());
    }
    let _guard = super::WRITE_LOCK.lock().await;
    if let Some(entry_id) = entry_of(ks, did).await? {
        let mut batch = Batch::new();
        batch.remove(card_key(&entry_id)).remove(index_key(did));
        ks.apply_batch(batch).await?;
    }
    Ok(())
}

/// Erase every value of `field` from every card (`fields/retire` item 4).
/// Returns how many cards held one.
pub async fn purge_field(ks: &KeyspaceHandle, field: &str) -> Result<usize, AppError> {
    let _guard = super::WRITE_LOCK.lock().await;
    let mut purged = 0;
    for mut card in all(ks).await? {
        let had_value = card.values.remove(field).is_some();
        let had_choice = card.visibility.remove(field).is_some();
        if had_value || had_choice {
            ks.insert(card_key(&card.entry_id), &card).await?;
            purged += usize::from(had_value);
        }
    }
    Ok(purged)
}

/// Whether `key` is a derived base field.
pub fn is_derived(key: &str) -> bool {
    DERIVED_KEYS.contains(&key)
}

/// Whether the card's required fields are filled in, so that browsing may
/// list it (`entries/list` item 2).
pub fn required_complete(card: &Card, schema: &[FieldDef]) -> bool {
    missing_required(card, schema).is_empty()
}

/// The required fields this card holds no value for — `missingRequired`.
pub fn missing_required(card: &Card, schema: &[FieldDef]) -> Vec<String> {
    schema
        .iter()
        .filter(|f| {
            f.required
                && f.state == FieldState::Active
                && f.source != FieldSource::Derived
                && !card.values.contains_key(&f.key)
        })
        .map(|f| f.key.clone())
        .collect()
}

/// The listing a card has, as a rank — exported for the query layer.
pub fn listing_of(card: &Card) -> Listing {
    card.discoverability.listing
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::fields::base_fields;
    use serde_json::json;

    fn card() -> Card {
        fresh("did:example:carol", &Settings::default(), None, Utc::now())
    }

    fn update(p: Value) -> MemberUpdate {
        MemberUpdate::from_payload(&p).unwrap()
    }

    fn apply(c: &Card, p: Value, at: DateTime<Utc>) -> Result<Applied, CardError> {
        apply_member_update(
            c,
            &base_fields(),
            &update(p),
            Writer::Member,
            "urn:uuid:1",
            at,
            at,
        )
    }

    #[test]
    fn vti_dir_050_entry_ids_are_random_and_well_formed() {
        let a = new_entry_id();
        let b = new_entry_id();
        assert_ne!(a, b);
        let re = regress::Regex::new("^dir_[A-Za-z0-9_-]{16,64}$").unwrap();
        assert!(re.find(&a).is_some(), "{a}");
    }

    #[test]
    fn a_fresh_card_starts_narrow() {
        let c = fresh(
            "did:example:x",
            &Settings::default(),
            Some("Carol"),
            Utc::now(),
        );
        assert_eq!(c.values.get("displayName"), Some(&json!("Carol")));
        assert!(c.visibility.is_empty());
        assert_eq!(c.discoverability.listing, Listing::Listed);
        assert!(!c.discoverability.external);
        assert_eq!(c.revision, 0);
    }

    #[test]
    fn vti_dir_012_an_older_update_is_superseded() {
        let c = card();
        let t1 = Utc::now();
        let a = apply(&c, json!({ "values": { "displayName": "Carol" } }), t1).unwrap();
        let earlier = t1 - chrono::Duration::seconds(5);
        assert_eq!(
            apply(
                &a.card,
                json!({ "values": { "displayName": "Old" } }),
                earlier
            )
            .unwrap_err(),
            CardError::Superseded { revision: 1 }
        );
        assert_eq!(
            apply(&a.card, json!({ "expectedRevision": 0 }), t1).unwrap_err(),
            CardError::Superseded { revision: 1 }
        );
    }

    #[test]
    fn vti_dir_013_a_member_writes_only_member_fields() {
        let c = card();
        let now = Utc::now();
        assert_eq!(
            apply(&c, json!({ "values": { "role": "admin" } }), now).unwrap_err(),
            CardError::FieldNotWritable("role".into())
        );
        assert_eq!(
            apply(&c, json!({ "values": { "org.example.x": "y" } }), now).unwrap_err(),
            CardError::FieldUnknown("org.example.x".into())
        );
        assert_eq!(
            apply(&c, json!({ "visibility": { "role": "public" } }), now).unwrap_err(),
            CardError::FieldNotWritable("role".into())
        );
        // The DID is the one derived field a member chooses for.
        apply(&c, json!({ "visibility": { "did": "members" } }), now).unwrap();
    }

    #[test]
    fn a_visibility_above_the_ceiling_is_refused_not_clamped() {
        let c = card();
        assert_eq!(
            apply(&c, json!({ "visibility": { "did": "public" } }), Utc::now()).unwrap_err(),
            CardError::AboveCeiling {
                field: "did".into(),
                ceiling: Audience::Members
            }
        );
    }

    #[test]
    fn external_publication_is_not_available() {
        let c = card();
        let r = apply(
            &c,
            json!({
                "values": { "displayName": "Carol" },
                "discoverability": { "listing": "listed", "search": "byName", "external": true }
            }),
            Utc::now(),
        );
        assert_eq!(r.unwrap_err(), CardError::NotAvailable);
    }

    #[test]
    fn a_delegated_key_cannot_make_anything_public() {
        let c = card();
        let r = apply_member_update(
            &c,
            &base_fields(),
            &update(json!({ "visibility": { "displayName": "public" } })),
            Writer::Delegated,
            "urn:uuid:2",
            Utc::now(),
            Utc::now(),
        );
        assert_eq!(r.unwrap_err(), CardError::NeedsMembershipDid);
    }

    #[test]
    fn narrowing_is_told_apart_from_widening() {
        let c = card();
        let now = Utc::now();
        let narrow = apply(
            &c,
            json!({
                "visibility": { "displayName": "admins" },
                "discoverability": { "listing": "hidden", "search": "off", "external": false },
                "introductions": "off",
            }),
            now,
        )
        .unwrap();
        assert!(!narrow.widens);
        let wide = apply(
            &narrow.card,
            json!({ "visibility": { "displayName": "members" } }),
            now,
        )
        .unwrap();
        assert!(wide.widens);
        let value = apply(&c, json!({ "values": { "pronouns": "she/her" } }), now).unwrap();
        assert!(value.widens);
        let cleared = apply(&value.card, json!({ "values": { "pronouns": null } }), now).unwrap();
        assert!(!cleared.widens);
        assert!(!cleared.card.values.contains_key("pronouns"));
    }

    #[test]
    fn group_audience_null_and_absent_differ() {
        let u = update(json!({ "groupAudience": null }));
        assert_eq!(u.group_audience, Some(None));
        let u = update(json!({}));
        assert_eq!(u.group_audience, None);
    }

    #[test]
    fn an_assertion_writes_only_admin_fields() {
        let c = card();
        let mut values = BTreeMap::new();
        values.insert("displayName".to_string(), Some(json!("X")));
        assert_eq!(
            apply_assertion(&c, &base_fields(), &values, Utc::now()).unwrap_err(),
            CardError::FieldNotWritable("displayName".into())
        );
    }

    #[test]
    fn vti_dir_016_a_card_is_bounded() {
        let mut c = card();
        for i in 0..10 {
            c.values.insert(format!("k{i}"), json!("x".repeat(2000)));
        }
        assert!(check_size(&c).is_err());
    }

    #[tokio::test]
    async fn vti_dir_122_rotation_keeps_the_entry_id() {
        let ks = super::super::tests::scratch().await;
        let s = Settings::default();
        let c = ensure(&ks, "did:example:old", &s, None).await.unwrap();
        rotate(&ks, "did:example:old", "did:example:new")
            .await
            .unwrap();
        assert!(by_did(&ks, "did:example:old").await.unwrap().is_none());
        let moved = by_did(&ks, "did:example:new").await.unwrap().unwrap();
        assert_eq!(moved.entry_id, c.entry_id);
        assert_eq!(moved.did, "did:example:new");
    }

    #[tokio::test]
    async fn vti_dir_121_a_departure_erases_or_keeps_the_card() {
        let ks = super::super::tests::scratch().await;
        let s = Settings::default();
        ensure(&ks, "did:example:a", &s, None).await.unwrap();
        ensure(&ks, "did:example:b", &s, None).await.unwrap();
        on_departure(&ks, "did:example:a", Departure::Erase)
            .await
            .unwrap();
        on_departure(&ks, "did:example:b", Departure::Keep)
            .await
            .unwrap();
        assert!(by_did(&ks, "did:example:a").await.unwrap().is_none());
        assert!(by_did(&ks, "did:example:b").await.unwrap().is_some());
        assert_eq!(all(&ks).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_retired_field_is_purged_from_every_card() {
        let ks = super::super::tests::scratch().await;
        let s = Settings::default();
        let mut c = ensure(&ks, "did:example:a", &s, None).await.unwrap();
        c.values.insert("org.example.gone".into(), json!("v"));
        c.visibility
            .insert("org.example.gone".into(), Audience::Members);
        ks.insert(card_key(&c.entry_id), &c).await.unwrap();
        assert_eq!(purge_field(&ks, "org.example.gone").await.unwrap(), 1);
        let c = by_did(&ks, "did:example:a").await.unwrap().unwrap();
        assert!(c.values.is_empty() && c.visibility.is_empty());
    }
}
