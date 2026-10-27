//! What the directory stores: field definitions and cards.
//!
//! These are the community's records, not wire types. Every task reads its
//! payload through the generated `trust_tasks_rs::specs::vtc::directory`
//! types (schema-checked first), and answers in the shapes
//! `_shared/0.1/directory-card` and `_shared/0.1/field-definition` define —
//! which these records serialize to member for member, so a stored row and
//! the wire never need a translation table between them.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Who may see a field, narrowest first (`directory-card` `Audience`).
///
/// Not a total order: `groups` and `connections` are both above `admins` and
/// below `members`, and neither covers the other. [`Audience::within`] is the
/// partial order; never compare two audiences any other way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Audience {
    Admins,
    Groups,
    Connections,
    Members,
    Public,
}

impl Audience {
    pub const ALL: [Audience; 5] = [
        Audience::Admins,
        Audience::Groups,
        Audience::Connections,
        Audience::Members,
        Audience::Public,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Audience::Admins => "admins",
            Audience::Groups => "groups",
            Audience::Connections => "connections",
            Audience::Members => "members",
            Audience::Public => "public",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.as_str() == s)
    }

    /// Whether every viewer of `self` is also a viewer of `outer`: `self` is
    /// no wider than `outer`. `groups` is not within `connections`, nor the
    /// reverse (VTI-DIR-020's table).
    pub fn within(self, outer: Audience) -> bool {
        use Audience::*;
        match (self, outer) {
            (a, b) if a == b => true,
            (Admins, _) => true,
            (Groups | Connections, Members | Public) => true,
            (Members, Public) => true,
            _ => false,
        }
    }

    /// Whether `self` is strictly wider than `other` somewhere: some viewer of
    /// `self` is not a viewer of `other`. The test a widening is.
    pub fn reaches_beyond(self, other: Audience) -> bool {
        !self.within(other)
    }
}

/// The kind of value a field holds (`field-definition` `FieldType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FieldType {
    Text,
    LongText,
    Url,
    Email,
    Phone,
    Enum,
    MultiEnum,
    Date,
    Country,
    Image,
    Did,
    Claim,
}

impl FieldType {
    /// Whether a field of this type may be filtered on and counted.
    pub fn may_be_facet(self) -> bool {
        matches!(
            self,
            FieldType::Enum | FieldType::MultiEnum | FieldType::Country
        )
    }

    /// Whether a value of this type is a string a search may match.
    pub fn is_textual(self) -> bool {
        matches!(
            self,
            FieldType::Text
                | FieldType::LongText
                | FieldType::Url
                | FieldType::Email
                | FieldType::Phone
                | FieldType::Enum
                | FieldType::Date
                | FieldType::Country
        )
    }
}

/// Who writes a field's value (`field-definition` `FieldSource`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FieldSource {
    Member,
    Admin,
    Credential,
    Derived,
}

/// `active`, `disabled` (a base field switched off) or `retired` (a community
/// field withdrawn for good).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FieldState {
    Active,
    Disabled,
    Retired,
}

/// One field of the community's schema, exactly as `FieldDefinition` states
/// it on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldDef {
    pub key: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub kind: FieldType,
    /// Kept as the `FieldConstraints` object it was written as; checked when
    /// written ([`super::fields::check_constraints`]) and read by
    /// [`super::values`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Value>,
    pub source: FieldSource,
    pub base: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub js_contact_path: Option<String>,
    pub required: bool,
    pub ceiling: Audience,
    pub default_visibility: Audience,
    pub searchable: bool,
    pub facet: bool,
    pub order: i64,
    pub state: FieldState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purge_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl FieldDef {
    pub fn is_shown(&self) -> bool {
        self.state == FieldState::Active
    }

    /// A `string`-valued constraint member.
    pub fn constraint_u64(&self, name: &str) -> Option<u64> {
        self.constraints.as_ref()?.get(name)?.as_u64()
    }

    /// The permitted values of an `enum` / `multiEnum` field.
    pub fn options(&self) -> Vec<String> {
        self.constraints
            .as_ref()
            .and_then(|c| c.get("options"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|o| o.get("value").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// `listed`, `findable` or `hidden`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Listing {
    Listed,
    Findable,
    Hidden,
}

impl Listing {
    pub fn as_str(self) -> &'static str {
        match self {
            Listing::Listed => "listed",
            Listing::Findable => "findable",
            Listing::Hidden => "hidden",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "listed" => Some(Listing::Listed),
            "findable" => Some(Listing::Findable),
            "hidden" => Some(Listing::Hidden),
            _ => None,
        }
    }

    /// How discoverable, as a rank: `hidden` < `findable` < `listed`.
    pub fn rank(self) -> u8 {
        match self {
            Listing::Hidden => 0,
            Listing::Findable => 1,
            Listing::Listed => 2,
        }
    }
}

/// What a member's search may match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SearchMode {
    ByName,
    ExactNickname,
    Off,
}

impl SearchMode {
    pub fn rank(self) -> u8 {
        match self {
            SearchMode::Off => 0,
            SearchMode::ExactNickname => 1,
            SearchMode::ByName => 2,
        }
    }
}

/// The member's three discoverability decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Discoverability {
    pub listing: Listing,
    pub search: SearchMode,
    pub external: bool,
}

/// Who may ask to be introduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Introductions {
    Anyone,
    Groups,
    Connections,
    Off,
}

/// The member's last accepted `card/update`: what VTI-DIR-012 orders later
/// updates against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppliedUpdate {
    pub document_id: String,
    pub issued_at: DateTime<Utc>,
}

/// Where a member's external card stands (`directory-card` `ExternalCard`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExternalState {
    /// The community serves the card the member signed, and its registry
    /// points to it.
    Published,
    /// The member's public values changed after they signed: nothing is served
    /// until they sign the current ones (`card/publish` item 8).
    AwaitingSignature,
}

/// The card's `externalCard`: present exactly while `discoverability.external`
/// is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalCard {
    pub state: ExternalState,
    /// While `published`: the digest of the card served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_digest: Option<String>,
    /// While `published`: when the card served was published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<DateTime<Utc>>,
}

impl ExternalCard {
    pub fn awaiting_signature() -> Self {
        Self {
            state: ExternalState::AwaitingSignature,
            card_digest: None,
            published_at: None,
        }
    }
}

/// A member's card, as stored. [`Card::wire`] is the `DirectoryCard` its
/// subject reads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub entry_id: String,
    /// The member's current membership DID. The index `entry:<did>` points
    /// back here; both move together on a rotation (VTI-DIR-122).
    pub did: String,
    /// `member`-, `admin`- and `credential`-sourced values. Never a derived
    /// one (VTI-DIR-011).
    #[serde(default)]
    pub values: BTreeMap<String, Value>,
    #[serde(default)]
    pub visibility: BTreeMap<String, Audience>,
    pub discoverability: Discoverability,
    pub introductions: Introductions,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_audience: Option<Vec<String>>,
    pub revision: u64,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_update: Option<AppliedUpdate>,
    /// Set by `card/publish` and by a withdrawal; `None` while
    /// `discoverability.external` is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_card: Option<ExternalCard>,
}

impl Card {
    /// The `DirectoryCard` for its subject: every stored value, every recorded
    /// choice. `values` and `visibility` hold only what is stored and chosen
    /// (a field with no choice takes its default, which `fields/list` states).
    pub fn wire(&self) -> Value {
        let mut out = serde_json::json!({
            "entryId": self.entry_id,
            "values": self.values,
            "visibility": self.visibility,
            "discoverability": self.discoverability,
            "introductions": self.introductions,
            "revision": self.revision,
            "updatedAt": self.updated_at,
        });
        if let Some(groups) = &self.group_audience {
            out["groupAudience"] = serde_json::json!(groups);
        }
        if self.discoverability.external {
            let external = self
                .external_card
                .clone()
                .unwrap_or_else(ExternalCard::awaiting_signature);
            out["externalCard"] = serde_json::json!(external);
        }
        out
    }

    /// The digest of the card served, while it is published.
    pub fn published_digest(&self) -> Option<&str> {
        self.external_card
            .as_ref()
            .filter(|e| e.state == ExternalState::Published)
            .and_then(|e| e.card_digest.as_deref())
    }

    /// The audience a field reaches on this card before any ceiling: the
    /// subject's choice, else the field's default.
    pub fn chosen(&self, field: &FieldDef) -> Audience {
        self.visibility
            .get(&field.key)
            .copied()
            .unwrap_or(field.default_visibility)
    }
}

/// The community's directory settings — runtime configuration
/// (`directory.*`, [`super::settings`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// The listing a new card starts with (`ListingDefaults.defaultListing`).
    pub default_listing: Listing,
    /// Days a retired field's values are kept before they are erased.
    pub retention_days: u32,
    /// The facet threshold *k*: a count below it is never disclosed exactly.
    pub facet_threshold: u32,
    /// `entries/list` requests one caller may make per minute.
    pub list_rate_per_minute: u32,
    /// Whether members may publish their card beyond the community
    /// (`card/publish`, VTI-DIR-046).
    pub external_cards: bool,
    /// Images one writer may upload per hour (`images/upload` item 7).
    pub image_uploads_per_hour: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_listing: Listing::Listed,
            retention_days: 30,
            facet_threshold: 5,
            list_rate_per_minute: 60,
            external_cards: true,
            image_uploads_per_hour: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_and_connections_do_not_cover_each_other() {
        use Audience::*;
        assert!(!Groups.within(Connections));
        assert!(!Connections.within(Groups));
        assert!(Groups.reaches_beyond(Connections));
        assert!(Admins.within(Groups) && Admins.within(Connections));
        assert!(Groups.within(Members) && Connections.within(Public));
        assert!(!Public.within(Members));
        for a in Audience::ALL {
            assert!(a.within(a) && a.within(Public) && Admins.within(a));
        }
    }

    #[test]
    fn audiences_round_trip_their_wire_names() {
        for a in Audience::ALL {
            assert_eq!(Audience::parse(a.as_str()), Some(a));
            assert_eq!(serde_json::to_value(a).unwrap(), a.as_str());
        }
    }
}
