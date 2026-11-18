//! A stand-in event vocabulary for this module's own tests.
//!
//! The envelope and the writer are generic over the event payload, and no
//! service's vocabulary lives in this crate, so the tests bring their own: one
//! variant, tagged the way every service's vocabulary is
//! (`{"type": …, "data": …}`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data")]
pub(crate) enum TestEvent {
    CommunityProfileUpdated(ProfileUpdated),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProfileUpdated {
    pub fields_changed: Vec<String>,
}

impl TestEvent {
    pub(crate) fn profile(field: &str) -> Self {
        Self::CommunityProfileUpdated(ProfileUpdated {
            fields_changed: vec![field.to_string()],
        })
    }
}
