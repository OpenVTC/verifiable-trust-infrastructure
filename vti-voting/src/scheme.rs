//! The scheme instance and the labels.
//!
//! - The instance is hidden vetting's (BLS12-381, Σ-PS, `Tag_DDH`), reused by alias.
//! - The **deployment label is voting's own**, `<community>#voting-pcs`: its `pp`, its helper
//!   key and so every ticket are separate from the community's vetting keys. A vetting credential
//!   can never stand for a ticket, and the two keys rotate independently.
//! - The election is in the CLASS label, `voter/<election>`: one class per election, so a ticket
//!   is good for exactly one election, and the electoral roll is whoever was issued under it.

use predicate_credential_system::pcs::{Predicate, PredicateCredentialSystem, SetupParams};

pub use vti_vetting_pcs::scheme::{Base, E, Fr, G1, Hvk, Open, Tag, key_text, point_text};

use crate::{VotingError, election::ElectionId};

pub fn deployment_label(community: &str) -> Vec<u8> {
    format!("{community}#voting-pcs").into_bytes()
}

/// The voter class of one election.
pub fn voter_predicate(election: &ElectionId) -> Predicate {
    Predicate::root(format!("voter/{}", election.as_str()).into_bytes())
}

/// The scheme instance for `community`'s voting deployment.
///
/// # Errors
/// [`VotingError::Pcs`] if the deployment parameters cannot be derived.
pub fn open(community: &str) -> Result<Open, VotingError> {
    Ok(Open::setup(SetupParams::new(deployment_label(community)))?)
}

/// What a voter and a ballot box need of a community: its identifier, the scheme instance, and
/// the published helper key `hvk`. Nothing here is secret.
#[derive(Clone)]
pub struct VotingParams {
    community: String,
    open: Open,
    hvk: Hvk,
}

impl std::fmt::Debug for VotingParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VotingParams")
            .field("community", &self.community)
            .finish_non_exhaustive()
    }
}

impl VotingParams {
    /// From a community's published voting key.
    ///
    /// # Errors
    /// [`VotingError::InvalidCommunity`] for an unusable identifier; [`VotingError::Pcs`] if the
    /// deployment parameters cannot be derived.
    pub fn new(community: &str, hvk: Hvk) -> Result<Self, VotingError> {
        crate::election::check_community(community)?;
        Ok(Self {
            community: community.to_string(),
            open: open(community)?,
            hvk,
        })
    }

    pub fn community(&self) -> &str {
        &self.community
    }
    pub fn open(&self) -> &Open {
        &self.open
    }
    pub fn hvk(&self) -> &Hvk {
        &self.hvk
    }
}
