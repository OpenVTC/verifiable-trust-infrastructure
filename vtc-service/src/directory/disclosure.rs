//! The directory's disclosure statement (VTI-DIR-130): what the directory
//! would disclose about a member, and to whom.
//!
//! Served on its own as `vtc/directory/disclosure/0.1`, and carried as
//! `directoryDisclosure` in `vtc/join-requests/manifest/0.4`, so an applicant
//! reads it before applying.
//!
//! **Generated, never written.** Every member is read from what this community
//! runs at the moment of the request: the field schema in the `directory`
//! keyspace, the `[directory]` settings, the defaults a new card is created
//! with ([`cards::fresh`]), and which directory features this build serves. No
//! administrator text goes into it but a field's own label and description, so
//! it cannot describe a directory someone intended rather than the one that
//! runs, and there is nothing to regenerate on a change: the next read is the
//! new statement.
//!
//! Every audience in it is an upper bound. A value reaches a viewer only where
//! its member's choice, the field's ceiling and the `directory` policy all
//! admit them, and the policy only narrows (VTI-DIR-021), so a ceiling is the
//! widest a value can go whatever the policy says.

use serde_json::{Map, Value, json};
use trust_tasks_rs::specs::vtc::directory::disclosure::v0_1 as disclosure;
use vti_common::error::AppError;

use super::Directory;
use super::cards;
use super::fields;
use super::model::{Audience, FieldDef};

/// The member the statement names itself by.
pub const STATEMENT_DIGEST_MEMBER: &str = "statementDigest";

/// The base field holding a member's membership DID.
const MEMBERSHIP_DID_FIELD: &str = "did";

/// Which parts of the directory this build serves. Each is a fact about the
/// running service, not a setting, and the statement must follow it: a
/// community that starts keeping notes, grouping members or publishing cards
/// says so in the next statement without anyone editing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Served {
    /// `vtc/directory/notes/append` is served: administrators can keep notes.
    pub admin_notes: bool,
    /// `vtc/directory/introduce` is served: introductions are delivered.
    pub introductions: bool,
    /// Community groups exist, with this validity for their membership
    /// credentials (an ISO 8601 duration).
    pub group_credential_validity: Option<&'static str>,
    /// A member can turn on external publication of their card.
    pub external_cards: bool,
}

impl Served {
    /// What this build serves, read from the dispatch table and the card
    /// rules themselves, so the two cannot disagree.
    pub fn this_build() -> Self {
        let serves = |slug: &str| {
            crate::trust_tasks::directory_tasks::URIS
                .iter()
                .any(|uri| uri.contains(&format!("/spec/{slug}/")))
        };
        Self {
            admin_notes: serves("vtc/directory/notes/append"),
            introductions: serves("vtc/directory/introduce"),
            // No `vtc/groups/*` task is served yet.
            group_credential_validity: None,
            external_cards: cards::EXTERNAL_PUBLICATION,
        }
    }
}

/// The statement for `directory` as it is now, `statementDigest` set.
///
/// # Errors
///
/// [`AppError::Internal`] when the stored schema cannot be read, or the
/// statement it gives does not meet the generated `DirectoryDisclosure` — a
/// stored field this build cannot describe is this service's fault, and a
/// statement that left it out would understate what the directory discloses.
pub async fn statement(directory: &Directory) -> Result<Value, AppError> {
    let schema = fields::schema(directory.ks()).await?;
    build(
        &schema,
        directory.settings().default_listing,
        Served::this_build(),
    )
}

/// The statement over `schema`, in display order, `statementDigest` set.
pub fn build(
    schema: &[FieldDef],
    default_listing: super::model::Listing,
    served: Served,
) -> Result<Value, AppError> {
    let active: Vec<&FieldDef> = schema.iter().filter(|f| f.is_shown()).collect();

    let fields = active
        .iter()
        .map(|f| disclosed_field(f))
        .collect::<Result<Vec<_>, _>>()?;

    let mut new_card = json!({
        "listing": encode(&default_listing)?,
        "search": encode(&cards::NEW_CARD_SEARCH)?,
    });
    if served.introductions {
        new_card["introductions"] = encode(&cards::NEW_CARD_INTRODUCTIONS)?;
    }

    // VTI-DIR-042 holds a new card's DID at `admins`; what a member may choose
    // is the field's ceiling, and with the field off nobody but administrators
    // ever sees it.
    let membership_identifiers = active
        .iter()
        .find(|f| f.key == MEMBERSHIP_DID_FIELD)
        .map(|f| f.ceiling)
        .unwrap_or(Audience::Admins);

    let mut out = json!({
        "fields": fields,
        "newCard": new_card,
        "membershipIdentifiers": membership_identifiers.as_str(),
        "adminNotes": served.admin_notes,
        "externalCards": served.external_cards,
    });
    if let Some(validity) = served.group_credential_validity {
        out["groups"] = json!({ "credentialValidity": validity });
    }

    let digest = statement_digest(&out)?;
    out[STATEMENT_DIGEST_MEMBER] = Value::String(digest.clone());

    // Through the generated type, so a statement the schema refuses is never
    // served. What is served is what was digested: a round trip that changed
    // anything would hand readers a digest they cannot recompute.
    let typed: disclosure::DirectoryDisclosure = serde_json::from_value(out.clone())
        .map_err(|e| AppError::Internal(format!("directory disclosure statement: {e}")))?;
    if statement_digest(&encode(&typed)?)? != digest {
        return Err(AppError::Internal(
            "directory disclosure statement: the generated type does not round-trip it".into(),
        ));
    }
    Ok(out)
}

/// `statementDigest` over `statement` as served: RFC 8785 JCS of the statement
/// without its `statementDigest`, as a SHA-256 multihash in base58btc.
pub fn statement_digest(statement: &Value) -> Result<String, AppError> {
    let mut without = statement.clone();
    if let Some(map) = without.as_object_mut() {
        map.remove(STATEMENT_DIGEST_MEMBER);
    }
    dtg_credentials::digest_multibase_json(&without)
        .map_err(|e| AppError::Internal(format!("statement digest: {e}")))
}

fn disclosed_field(f: &FieldDef) -> Result<Value, AppError> {
    let mut m = Map::new();
    m.insert("key".into(), f.key.clone().into());
    m.insert("label".into(), f.label.clone().into());
    if let Some(description) = &f.description {
        m.insert("description".into(), description.clone().into());
    }
    m.insert("type".into(), encode(&f.kind)?);
    m.insert("source".into(), encode(&f.source)?);
    m.insert("ceiling".into(), f.ceiling.as_str().into());
    m.insert(
        "defaultVisibility".into(),
        f.default_visibility.as_str().into(),
    );
    m.insert("searchable".into(), f.searchable.into());
    if f.facet {
        m.insert("facet".into(), true.into());
    }
    Ok(Value::Object(m))
}

fn encode(value: &impl serde::Serialize) -> Result<Value, AppError> {
    serde_json::to_value(value)
        .map_err(|e| AppError::Internal(format!("directory disclosure encode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::model::{FieldSource, FieldState, FieldType, Listing};

    fn served() -> Served {
        Served {
            admin_notes: false,
            introductions: false,
            group_credential_validity: None,
            external_cards: false,
        }
    }

    fn base_statement() -> Value {
        build(&fields::base_fields(), Listing::Listed, served()).unwrap()
    }

    #[test]
    fn the_digest_recomputes_from_what_a_reader_receives() {
        let s = base_statement();
        assert_eq!(
            s[STATEMENT_DIGEST_MEMBER].as_str().unwrap(),
            statement_digest(&s).unwrap()
        );
    }

    /// The spec's own example digest, recomputed here, so the two
    /// implementations of the rule cannot drift apart.
    #[test]
    fn the_digest_matches_the_specification_example() {
        let mut example = json!({
            "fields": [
                {"key": "displayName", "label": "Name", "type": "text", "source": "member", "ceiling": "members", "defaultVisibility": "members", "searchable": true},
                {"key": "bio", "label": "About", "type": "longText", "source": "member", "ceiling": "members", "defaultVisibility": "admins", "searchable": false},
                {"key": "role", "label": "Role", "type": "text", "source": "derived", "ceiling": "members", "defaultVisibility": "members", "searchable": false}
            ],
            "newCard": {"listing": "listed", "search": "byName"},
            "membershipIdentifiers": "admins",
            "adminNotes": false,
            "externalCards": false
        });
        assert_eq!(
            statement_digest(&example).unwrap(),
            "zQmcPXnjL36U7nmj7oDPBuCSzdUd15C5aquDWkT4YGMDHge"
        );
        example[STATEMENT_DIGEST_MEMBER] = json!("zQmcPXnjL36U7nmj7oDPBuCSzdUd15C5aquDWkT4YGMDHge");
        assert_eq!(
            statement_digest(&example).unwrap(),
            "zQmcPXnjL36U7nmj7oDPBuCSzdUd15C5aquDWkT4YGMDHge",
            "the digest ignores itself"
        );
    }

    #[test]
    fn every_active_field_is_listed_in_order_and_nothing_else() {
        let mut schema = fields::base_fields();
        schema
            .iter_mut()
            .find(|f| f.key == "pronouns")
            .unwrap()
            .state = FieldState::Disabled;
        let s = build(&schema, Listing::Listed, served()).unwrap();
        let keys: Vec<&str> = s["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["key"].as_str().unwrap())
            .collect();
        let expected: Vec<&str> = schema
            .iter()
            .filter(|f| f.is_shown())
            .map(|f| f.key.as_str())
            .collect();
        assert_eq!(keys, expected);
        assert!(!keys.contains(&"pronouns"));
    }

    /// A field's constraints, display order and JSContact path are not what an
    /// applicant decides by, and are not in the statement.
    #[test]
    fn a_field_is_described_by_what_it_discloses() {
        let s = base_statement();
        let name = &s["fields"][0];
        assert_eq!(name["key"], "displayName");
        let mut members: Vec<&String> = name.as_object().unwrap().keys().collect();
        members.sort();
        assert_eq!(
            members,
            [
                "ceiling",
                "defaultVisibility",
                "key",
                "label",
                "searchable",
                "source",
                "type"
            ]
        );
    }

    #[test]
    fn membership_identifiers_follow_the_did_field() {
        let reach = |state: FieldState, ceiling: Audience| {
            let mut schema = fields::base_fields();
            let did = schema.iter_mut().find(|f| f.key == "did").unwrap();
            did.state = state;
            did.ceiling = ceiling;
            build(&schema, Listing::Listed, served()).unwrap()["membershipIdentifiers"].clone()
        };
        assert_eq!(reach(FieldState::Active, Audience::Members), "members");
        assert_eq!(reach(FieldState::Active, Audience::Public), "public");
        assert_eq!(reach(FieldState::Disabled, Audience::Public), "admins");
    }

    #[test]
    fn a_changed_ceiling_changes_the_statement_and_its_digest() {
        let before = base_statement();
        let mut schema = fields::base_fields();
        schema.iter_mut().find(|f| f.key == "bio").unwrap().ceiling = Audience::Members;
        let after = build(&schema, Listing::Listed, served()).unwrap();
        assert_ne!(
            before[STATEMENT_DIGEST_MEMBER],
            after[STATEMENT_DIGEST_MEMBER]
        );
        // The same configuration, read twice, is the same statement.
        assert_eq!(before, base_statement());
    }

    #[test]
    fn the_new_card_defaults_are_the_ones_a_card_is_created_with() {
        let s = build(&fields::base_fields(), Listing::Findable, served()).unwrap();
        assert_eq!(s["newCard"]["listing"], "findable");
        assert_eq!(s["newCard"]["search"], "byName");
        assert!(s["newCard"].get("introductions").is_none());

        let mut with = served();
        with.introductions = true;
        let s = build(&fields::base_fields(), Listing::Listed, with).unwrap();
        assert_eq!(s["newCard"]["introductions"], "anyone");
    }

    #[test]
    fn the_features_a_build_serves_are_stated() {
        let s = base_statement();
        assert_eq!(s["adminNotes"], false);
        assert_eq!(s["externalCards"], false);
        assert!(s.get("groups").is_none());

        let s = build(
            &fields::base_fields(),
            Listing::Listed,
            Served {
                admin_notes: true,
                introductions: true,
                group_credential_validity: Some("P30D"),
                external_cards: true,
            },
        )
        .unwrap();
        assert_eq!(s["adminNotes"], true);
        assert_eq!(s["externalCards"], true);
        assert_eq!(s["groups"]["credentialValidity"], "P30D");
    }

    /// What this build serves is read off the dispatch table and the card
    /// rules, so turning a feature on cannot leave the statement behind.
    #[test]
    fn this_build_states_what_it_serves() {
        let served = Served::this_build();
        let uris = crate::trust_tasks::directory_tasks::URIS;
        assert_eq!(
            served.admin_notes,
            uris.iter()
                .any(|u| u.contains("/vtc/directory/notes/append/"))
        );
        assert_eq!(
            served.introductions,
            uris.iter().any(|u| u.contains("/vtc/directory/introduce/"))
        );
        assert_eq!(served.external_cards, cards::EXTERNAL_PUBLICATION);
    }

    #[test]
    fn an_admin_asserted_facet_is_described_as_one() {
        let mut schema = fields::base_fields();
        schema.push(FieldDef {
            key: "org.example.chapter".into(),
            label: "Chapter".into(),
            description: Some("Where you meet.".into()),
            kind: FieldType::Enum,
            constraints: Some(json!({ "options": [{ "value": "syd", "label": "Sydney" }] })),
            source: FieldSource::Admin,
            base: false,
            js_contact_path: None,
            required: false,
            ceiling: Audience::Members,
            default_visibility: Audience::Members,
            searchable: false,
            facet: true,
            order: 500,
            state: FieldState::Active,
            retired_at: None,
            purge_after: None,
            updated_at: None,
        });
        let s = build(&schema, Listing::Listed, served()).unwrap();
        let chapter = s["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["key"] == "org.example.chapter")
            .unwrap();
        assert_eq!(chapter["source"], "admin");
        assert_eq!(chapter["facet"], true);
        assert_eq!(chapter["description"], "Where you meet.");
        assert!(chapter.get("constraints").is_none());
    }
}
