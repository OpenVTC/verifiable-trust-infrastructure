//! What an authority chain grants room content to be used for (VTI-ACL-100 – 110).
//!
//! A presented chain is a grant written as a credential, and the purposes it grants bound
//! what the presenter may use a record for (`rooms/records/get/0.4`, *Purpose of use*). A
//! chain stating none grants `any`, which never grants [`MODEL_TRAINING`], so every read is
//! held to the chain's purposes whether or not any link states them.
//!
//! The chain rule itself — a link stating none takes its parent's, a link stating purposes
//! its parent does not grant invalidates the chain — is the verifier's
//! ([`crate::authz::ChainVerifier`]); this module only decides a request against the
//! purposes a verified chain grants. Profile-neutral, and free of the credential library,
//! so the wasm build carries it.

use std::collections::BTreeSet;

/// The registered purpose that `any` never grants (VTI-ACL-105).
pub const MODEL_TRAINING: &str = "modelTraining";

/// The purposes a verified chain grants.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ChainPurposes {
    /// No link states purposes: every purpose but [`MODEL_TRAINING`].
    #[default]
    Any,
    /// Exactly these, compared by exact string equality (VTI-ACL-109).
    Listed(BTreeSet<String>),
}

impl ChainPurposes {
    /// Whether `purpose` is granted.
    pub fn grants(&self, purpose: &str) -> bool {
        match self {
            Self::Any => purpose != MODEL_TRAINING,
            Self::Listed(purposes) => purposes.contains(purpose),
        }
    }

    /// Decide a request naming `requested`, or none (VTI-ACL-103).
    pub fn admit(&self, requested: Option<&str>) -> PurposeDecision {
        match (self, requested) {
            (_, Some(p)) if self.grants(p) => PurposeDecision::Granted(p.to_string()),
            (_, Some(p)) => PurposeDecision::NotGranted(p.to_string()),
            (Self::Any, None) => PurposeDecision::Unstated,
            // Exactly one purpose granted: a request naming none is read as naming it.
            (Self::Listed(purposes), None) if purposes.len() == 1 => {
                PurposeDecision::Granted(purposes.iter().next().cloned().unwrap_or_default())
            }
            (Self::Listed(_), None) => PurposeDecision::Unnamed,
        }
    }
}

/// What a host decided about one request's purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurposeDecision {
    /// Served, for this purpose: the one named, or the chain's only one.
    Granted(String),
    /// Served under `any` to a request that named none.
    Unstated,
    /// Refused: the request named a purpose the chain does not grant.
    NotGranted(String),
    /// Refused: the request named none, and the chain lists more than one.
    Unnamed,
}

impl PurposeDecision {
    /// Whether the request is served.
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted(_) | Self::Unstated)
    }

    /// The purpose a read record carries (VTI-ACL-106): the one served or refused for, or
    /// `unstated` where the request named none.
    pub fn audit_label(&self) -> &str {
        match self {
            Self::Granted(p) | Self::NotGranted(p) => p,
            Self::Unstated | Self::Unnamed => "unstated",
        }
    }

    /// The `details` of a `purposeNotGranted` refusal, or `None` for a served request.
    pub fn refusal_details(&self) -> Option<serde_json::Value> {
        match self {
            Self::NotGranted(p) => Some(serde_json::json!({ "purposeNamed": true, "purpose": p })),
            Self::Unnamed => Some(serde_json::json!({ "purposeNamed": false })),
            Self::Granted(_) | Self::Unstated => None,
        }
    }

    /// The refusal's message, which names no content and says nothing about the record.
    pub fn refusal_message(&self) -> String {
        match self {
            Self::NotGranted(p) => {
                format!("the presented authority chain does not grant the purpose `{p}`")
            }
            Self::Unnamed => "the presented authority chain grants more than one purpose; \
                              name the one this read is for"
                .to_string(),
            Self::Granted(_) | Self::Unstated => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listed(ps: &[&str]) -> ChainPurposes {
        ChainPurposes::Listed(ps.iter().map(|p| p.to_string()).collect())
    }

    #[test]
    fn vti_acl_105_any_grants_everything_but_model_training() {
        let any = ChainPurposes::Any;
        assert_eq!(any.admit(None), PurposeDecision::Unstated);
        assert!(any.admit(Some("analytics")).is_granted());
        assert!(
            any.admit(Some("https://w3id.org/dpv#Marketing"))
                .is_granted()
        );
        assert_eq!(
            any.admit(Some(MODEL_TRAINING)),
            PurposeDecision::NotGranted(MODEL_TRAINING.into())
        );
    }

    #[test]
    fn vti_acl_103_one_listed_purpose_applies_to_a_request_naming_none() {
        let one = listed(&["taskExecution"]);
        assert_eq!(
            one.admit(None),
            PurposeDecision::Granted("taskExecution".into())
        );
        assert!(!one.admit(Some("analytics")).is_granted());
    }

    #[test]
    fn vti_acl_103_several_listed_purposes_need_one_named() {
        let two = listed(&["taskExecution", "personalisation"]);
        assert_eq!(two.admit(None), PurposeDecision::Unnamed);
        assert_eq!(
            two.admit(None).refusal_details(),
            Some(serde_json::json!({ "purposeNamed": false }))
        );
        assert!(two.admit(Some("personalisation")).is_granted());
    }

    #[test]
    fn vti_acl_109_an_unrecognised_purpose_equals_only_itself() {
        let iri = listed(&["https://w3id.org/dpv#ServicePersonalisation"]);
        assert!(!iri.admit(Some("personalisation")).is_granted());
        assert!(
            iri.admit(Some("https://w3id.org/dpv#ServicePersonalisation"))
                .is_granted()
        );
    }

    #[test]
    fn a_listed_model_training_is_granted() {
        assert!(listed(&[MODEL_TRAINING]).admit(None).is_granted());
    }
}
