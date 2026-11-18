//! May this DID become its context's own DID? One answer for every path that
//! sets one — `vta/contexts/update-did/1.2`, a create with `setPrimary` of any
//! method, provisioning — so no path is the one that skips the check.
//!
//! VTI-KEY-193: a DID belongs to one class only. A persona or relationship DID
//! is never adopted as a node's or a service's identity, and a service DID does
//! not replace a person's. Before this module the rule was enforced for
//! `vta/webs/dids/create` alone (`vta/webs/_shared/0.2` CONVENTIONS.md §1.2),
//! while a did:webvh create and `update-did` would repoint any context at any
//! DID.

use vti_common::error::AppError;

use super::DidStores;

/// The DID class `did` is recorded in, as far as this VTA's records say.
///
/// This VTA's own DID is a service identity whatever store holds it. A
/// `did:webs` carries the class it was created in. Every other identity has no
/// recorded class, and none is inferred (CONVENTIONS.md §20.3).
pub async fn recorded_class(
    stores: DidStores<'_>,
    config: &vta_config::AppConfig,
    did: &str,
) -> Result<Option<&'static str>, AppError> {
    if config.vta_did.as_deref() == Some(did) {
        return Ok(Some("service"));
    }
    #[cfg(feature = "webs")]
    if did.starts_with("did:webs:") {
        return Ok(crate::webs_store::get(stores.webs_ks, did)
            .await?
            .and_then(|r| r.did_class)
            .map(|c| c.as_str()));
    }
    let _ = stores;
    Ok(None)
}

/// Why a DID cannot become a context's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassConflict {
    /// The context's DID is a service identity, and the candidate is a
    /// persona or relationship DID. Only a service DID may take its place.
    NeedsService {
        current: String,
        class: &'static str,
    },
    /// The context's DID is a persona DID, and a service DID does not replace it.
    PersonaNotReplaced { current: String },
}

impl ClassConflict {
    /// The class a replacement would need, where one would be accepted.
    pub fn required_class(&self) -> Option<&'static str> {
        match self {
            Self::NeedsService { .. } => Some("service"),
            Self::PersonaNotReplaced { .. } => None,
        }
    }

    pub fn message(&self, context_id: &str) -> String {
        match self {
            Self::NeedsService { current, class } => format!(
                "context {context_id}'s DID {current} is a service identity: a {class} DID \
                 cannot become a node's or a service's identity (VTI-KEY-193)"
            ),
            Self::PersonaNotReplaced { current } => format!(
                "context {context_id}'s DID {current} is a persona DID: a service DID does not \
                 replace it (VTI-KEY-193)"
            ),
        }
    }
}

/// Whether a DID of `candidate_class` may become the DID of a context whose DID
/// is now `current`. A candidate with no recorded class is not refused on class.
pub async fn class_conflict(
    stores: DidStores<'_>,
    config: &vta_config::AppConfig,
    current: Option<&str>,
    candidate: &str,
    candidate_class: Option<&'static str>,
) -> Result<Option<ClassConflict>, AppError> {
    let (Some(current), Some(class)) = (current, candidate_class) else {
        return Ok(None);
    };
    if current == candidate {
        return Ok(None);
    }
    let current_class = recorded_class(stores, config, current).await?;
    Ok(match (class, current_class) {
        ("persona" | "relationship", Some("service")) => Some(ClassConflict::NeedsService {
            current: current.to_string(),
            class,
        }),
        ("service", Some("persona")) => Some(ClassConflict::PersonaNotReplaced {
            current: current.to_string(),
        }),
        _ => None,
    })
}

/// Whether a context's DID is this VTA's own identity, which no create may
/// replace: re-identifying a node installs new keys and tells its peers, which
/// setup does and a create that only repointed the context would not.
pub fn is_node_identity(config: &vta_config::AppConfig, current: Option<&str>) -> bool {
    current.is_some() && config.vta_did.as_deref() == current
}
