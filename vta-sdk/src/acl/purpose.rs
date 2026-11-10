//! Purpose of use (VTI-ACL-100 – 110): what an ACL entry's subject may use
//! the content it reads **for**.
//!
//! An entry says who may do what, where and until when; [`PurposeScope`] says
//! what for. A node cannot see what a subject does with content once it has
//! it, so a purpose is a declaration the subject is held to: a read is refused
//! for a purpose the entry does not grant ([`PurposeScope::admit`]), and the
//! purpose of every read is recorded ([`PurposeDecision::audit_label`]).
//!
//! The wire shape is `acl/_shared/0.3/acl-entry#PurposeScope`; the stored shape
//! here serialises identically.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// The registered purpose that `any` never grants (VTI-ACL-105): training,
/// fine-tuning or evaluating a machine-learning model on the content.
pub const MODEL_TRAINING: &str = "modelTraining";

/// The purposes registered in the specification's Appendix H.
pub const REGISTERED_PURPOSES: &[&str] = &[
    "personalisation",
    "taskExecution",
    "analytics",
    MODEL_TRAINING,
];

/// The most purposes one entry may list (`PurposeScopeListed.purposes`
/// `maxItems`).
pub const MAX_LISTED_PURPOSES: usize = 32;

/// The longest purpose (`Purpose.maxLength`).
pub const MAX_PURPOSE_LEN: usize = 2048;

/// An entry's purposes — `acl/_shared/0.3/acl-entry#PurposeScope`.
///
/// Exactly one of two shapes (VTI-ACL-100). There is no empty list: a
/// `Listed` set is never empty, and [`PurposeScope::listed`] refuses one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
pub enum PurposeScope {
    /// Every purpose except [`MODEL_TRAINING`] (VTI-ACL-105).
    Any,
    /// Exactly these purposes, compared by exact string equality
    /// (VTI-ACL-109). Never empty.
    Listed { purposes: BTreeSet<String> },
}

/// Why a purpose scope cannot be written (VTI-ACL-100, VTI-ACL-109).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PurposeScopeError {
    /// A `listed` scope with no purposes. An empty list is not `any`.
    #[error("a listed purpose scope must name at least one purpose")]
    Empty,
    /// More than [`MAX_LISTED_PURPOSES`].
    #[error("a purpose scope may list at most {MAX_LISTED_PURPOSES} purposes")]
    TooMany,
    /// The same purpose named twice.
    #[error("purpose '{0}' is listed twice")]
    Duplicate(String),
    /// Neither a registered name nor an absolute IRI.
    #[error(
        "'{0}' is not a purpose: name a registered purpose ({registered}) or an absolute IRI",
        registered = REGISTERED_PURPOSES.join(", ")
    )]
    Malformed(String),
}

/// Check one purpose's form: a lowerCamelCase name of at most 64 characters
/// (`^[a-z][a-zA-Z0-9]{0,63}$`) or an absolute IRI
/// (`^[a-zA-Z][a-zA-Z0-9+.-]*:[^\s]+$`), at most [`MAX_PURPOSE_LEN`] long.
///
/// A well-formed name that is not registered is accepted: the registry can
/// grow without a new schema, and an unrecognised purpose is only ever equal
/// to itself (VTI-ACL-109).
pub fn validate_purpose(p: &str) -> Result<(), PurposeScopeError> {
    let bad = || PurposeScopeError::Malformed(p.to_string());
    if p.is_empty() || p.len() > MAX_PURPOSE_LEN {
        return Err(bad());
    }
    let mut chars = p.chars();
    let first = chars.next().ok_or_else(bad)?;
    if let Some((scheme, rest)) = p.split_once(':') {
        // An absolute IRI: a scheme, a colon, and no whitespace after it.
        let scheme_ok = first.is_ascii_alphabetic()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
        if scheme_ok && !rest.is_empty() && !rest.chars().any(char::is_whitespace) {
            return Ok(());
        }
        return Err(bad());
    }
    if first.is_ascii_lowercase() && p.len() <= 64 && chars.all(|c| c.is_ascii_alphanumeric()) {
        return Ok(());
    }
    Err(bad())
}

impl Default for PurposeScope {
    /// `any` — the authority an entry written before purposes existed already
    /// held (VTI-ACL-101). Used only to read such an entry; every entry the
    /// node writes states its purposes.
    fn default() -> Self {
        Self::Any
    }
}

/// How a request's purpose fares against an entry (VTI-ACL-103, -104).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurposeDecision {
    /// Served, for this purpose: the one the request named, or the entry's
    /// only listed purpose where the request named none.
    Granted(String),
    /// Served under `any` for a request that named no purpose: its purpose is
    /// recorded as unstated.
    Unstated,
    /// Refused: the request named a purpose the entry does not grant.
    NotGranted(String),
    /// Refused: the request named no purpose, and the entry lists more than
    /// one.
    Unnamed,
}

impl PurposeDecision {
    /// Whether the request is served.
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted(_) | Self::Unstated)
    }

    /// The purpose an audit record carries (VTI-ACL-106): the purpose served
    /// or refused for, or `unstated` where the request named none.
    pub fn audit_label(&self) -> &str {
        match self {
            Self::Granted(p) | Self::NotGranted(p) => p,
            Self::Unstated | Self::Unnamed => "unstated",
        }
    }

    /// The `details` of a `purposeNotGranted` refusal: whether the request
    /// named a purpose, and which. `None` for a decision that is served.
    pub fn refusal_details(&self) -> Option<serde_json::Value> {
        match self {
            Self::NotGranted(p) => Some(serde_json::json!({ "purposeNamed": true, "purpose": p })),
            Self::Unnamed => Some(serde_json::json!({ "purposeNamed": false })),
            _ => None,
        }
    }
}

impl PurposeScope {
    /// A `listed` scope, checked (VTI-ACL-100, VTI-ACL-109): non-empty, at
    /// most [`MAX_LISTED_PURPOSES`], no duplicate, every purpose well formed.
    pub fn listed<I, S>(purposes: I) -> Result<Self, PurposeScopeError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut set = BTreeSet::new();
        for p in purposes {
            let p = p.into();
            validate_purpose(&p)?;
            if !set.insert(p.clone()) {
                return Err(PurposeScopeError::Duplicate(p));
            }
        }
        let scope = Self::Listed { purposes: set };
        scope.validate()?;
        Ok(scope)
    }

    /// Check a scope that arrived already built (deserialised): the rules
    /// [`PurposeScope::listed`] applies, minus duplicates, which a set cannot
    /// hold.
    pub fn validate(&self) -> Result<(), PurposeScopeError> {
        match self {
            Self::Any => Ok(()),
            Self::Listed { purposes } => {
                if purposes.is_empty() {
                    return Err(PurposeScopeError::Empty);
                }
                if purposes.len() > MAX_LISTED_PURPOSES {
                    return Err(PurposeScopeError::TooMany);
                }
                purposes.iter().try_for_each(|p| validate_purpose(p))
            }
        }
    }

    /// Whether this scope grants `purpose`. `any` grants every purpose but
    /// [`MODEL_TRAINING`] (VTI-ACL-105); a list grants exactly its members
    /// (VTI-ACL-109).
    pub fn grants(&self, purpose: &str) -> bool {
        match self {
            Self::Any => purpose != MODEL_TRAINING,
            Self::Listed { purposes } => purposes.contains(purpose),
        }
    }

    /// Decide a purpose-bound request that named `requested`, or none
    /// (VTI-ACL-103, VTI-ACL-104).
    pub fn admit(&self, requested: Option<&str>) -> PurposeDecision {
        match (self, requested) {
            (_, Some(p)) if self.grants(p) => PurposeDecision::Granted(p.to_string()),
            (_, Some(p)) => PurposeDecision::NotGranted(p.to_string()),
            (Self::Any, None) => PurposeDecision::Unstated,
            (Self::Listed { purposes }, None) if purposes.len() == 1 => {
                // Exactly one purpose listed: it applies (VTI-ACL-103).
                PurposeDecision::Granted(purposes.iter().next().cloned().unwrap_or_default())
            }
            (Self::Listed { .. }, None) => PurposeDecision::Unnamed,
        }
    }

    /// Whether an entry derived from one holding `held` may state `self`
    /// (VTI-ACL-107): `any` may delegate a list that leaves out
    /// [`MODEL_TRAINING`], or `any`; a list may delegate a subset of itself,
    /// never `any`.
    pub fn is_within(&self, held: &PurposeScope) -> bool {
        match (self, held) {
            (Self::Any, Self::Any) => true,
            (Self::Any, Self::Listed { .. }) => false,
            (Self::Listed { purposes }, held) => purposes.iter().all(|p| held.grants(p)),
        }
    }

    /// The purposes in `self` that `held` does not grant, for a refusal that
    /// names them. `["any"]` where `self` is `any` and `held` is a list.
    pub fn beyond(&self, held: &PurposeScope) -> Vec<String> {
        match (self, held) {
            (Self::Any, Self::Listed { .. }) => vec!["any".to_string()],
            (Self::Any, Self::Any) => Vec::new(),
            (Self::Listed { purposes }, held) => purposes
                .iter()
                .filter(|p| !held.grants(p))
                .cloned()
                .collect(),
        }
    }

    /// Whether this is `any`.
    pub fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }
}

impl std::fmt::Display for PurposeScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => f.write_str("any"),
            Self::Listed { purposes } => {
                let v: Vec<&str> = purposes.iter().map(String::as_str).collect();
                f.write_str(&v.join(","))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn listed(ps: &[&str]) -> PurposeScope {
        PurposeScope::listed(ps.iter().copied()).unwrap()
    }

    #[test]
    fn the_wire_shapes_round_trip() {
        assert_eq!(
            serde_json::to_value(PurposeScope::Any).unwrap(),
            json!({ "scope": "any" })
        );
        assert_eq!(
            serde_json::to_value(listed(&["taskExecution", "personalisation"])).unwrap(),
            json!({ "scope": "listed", "purposes": ["personalisation", "taskExecution"] })
        );
        let back: PurposeScope =
            serde_json::from_value(json!({ "scope": "listed", "purposes": ["analytics"] }))
                .unwrap();
        assert_eq!(back, listed(&["analytics"]));
    }

    /// VTI-ACL-100: an empty list is refused, never read as `any`.
    #[test]
    fn vti_acl_100_an_empty_list_is_refused() {
        assert_eq!(
            PurposeScope::listed(Vec::<String>::new()),
            Err(PurposeScopeError::Empty)
        );
        let empty: PurposeScope =
            serde_json::from_value(json!({ "scope": "listed", "purposes": [] })).unwrap();
        assert_eq!(empty.validate(), Err(PurposeScopeError::Empty));
        assert!(serde_json::from_value::<PurposeScope>(json!({ "scope": "none" })).is_err());
    }

    /// VTI-ACL-109: a purpose is a lowerCamelCase name or an absolute IRI.
    #[test]
    fn vti_acl_109_a_purpose_is_a_name_or_an_absolute_iri() {
        for ok in [
            "personalisation",
            "taskExecution",
            "someFuturePurpose",
            "https://w3id.org/dpv#ServicePersonalisation",
            "urn:example:purpose",
        ] {
            assert_eq!(validate_purpose(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "Personalisation",
            "task-execution",
            "a b",
            "1x",
            ":x",
            "https:",
        ] {
            assert!(validate_purpose(bad).is_err(), "{bad}");
        }
        assert_eq!(
            PurposeScope::listed(["analytics", "analytics"]),
            Err(PurposeScopeError::Duplicate("analytics".into()))
        );
    }

    /// VTI-ACL-103 / -104: what a request is served for.
    #[test]
    fn vti_acl_103_104_a_request_is_served_only_for_a_granted_purpose() {
        let one = listed(&["personalisation"]);
        let two = listed(&["personalisation", "analytics"]);
        assert_eq!(
            PurposeScope::Any.admit(None),
            PurposeDecision::Unstated,
            "under any, an unnamed purpose is served and recorded as unstated"
        );
        assert_eq!(
            one.admit(None),
            PurposeDecision::Granted("personalisation".into()),
            "a single listed purpose applies when none is named"
        );
        assert_eq!(two.admit(None), PurposeDecision::Unnamed);
        assert_eq!(
            two.admit(Some("analytics")),
            PurposeDecision::Granted("analytics".into())
        );
        assert_eq!(
            one.admit(Some("analytics")),
            PurposeDecision::NotGranted("analytics".into())
        );
        assert!(!PurposeDecision::Unnamed.is_granted());
        assert_eq!(PurposeDecision::Unnamed.audit_label(), "unstated");
    }

    /// VTI-ACL-105: `any` never grants model training.
    #[test]
    fn vti_acl_105_any_does_not_grant_model_training() {
        assert_eq!(
            PurposeScope::Any.admit(Some(MODEL_TRAINING)),
            PurposeDecision::NotGranted(MODEL_TRAINING.into())
        );
        assert!(listed(&[MODEL_TRAINING]).grants(MODEL_TRAINING));
    }

    /// VTI-ACL-109: an unrecognised purpose equals only itself.
    #[test]
    fn vti_acl_109_an_unrecognised_purpose_equals_only_itself() {
        let iri = "https://w3id.org/dpv#ServicePersonalisation";
        assert!(!listed(&["personalisation"]).grants(iri));
        assert!(listed(&[iri]).grants(iri));
    }

    /// VTI-ACL-107: delegation narrows.
    #[test]
    fn vti_acl_107_a_delegated_scope_is_within_the_one_it_derives_from() {
        let pa = listed(&["personalisation", "analytics"]);
        assert!(PurposeScope::Any.is_within(&PurposeScope::Any));
        assert!(pa.is_within(&PurposeScope::Any));
        assert!(listed(&["analytics"]).is_within(&pa));
        assert!(
            !PurposeScope::Any.is_within(&pa),
            "a list may not delegate any"
        );
        assert!(
            !listed(&[MODEL_TRAINING]).is_within(&PurposeScope::Any),
            "any may not delegate model training"
        );
        assert!(listed(&[MODEL_TRAINING]).is_within(&listed(&[MODEL_TRAINING])));
        assert_eq!(
            listed(&["analytics", "taskExecution"]).beyond(&pa),
            vec!["taskExecution".to_string()]
        );
        assert_eq!(PurposeScope::Any.beyond(&pa), vec!["any".to_string()]);
    }
}
