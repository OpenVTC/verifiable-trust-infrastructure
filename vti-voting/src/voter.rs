//! The member's half, which their VTA runs: a key for one election, the blinded ticket request,
//! and the cast.
//!
//! **One key per election.** A VTA derives the seed for [`Voter::from_seed`] from a fresh path
//! under the context's base for each election (VTI-KEY-030), so a tag recovered by a future
//! adversary links one election, never a member's voting history. One key may also not hold two
//! tickets for an election: the registrar's caller allows one ticket per member per election.

use predicate_credential_system::pcs::{
    Attestation, Credential, IssuanceState, PredicateCredentialSystem, RootRequest, UserSecretKey,
};
use rand::{CryptoRng, RngCore};

use crate::{
    VotingError,
    election::Election,
    registrar::PreTicket,
    scheme::{Base, E, G1, VotingParams, point_text},
};

/// The blinded request a voter sends the registrar for a ticket.
pub type TicketRequest = RootRequest<E, Base>;
/// What unblinds the registrar's answer. Secret, kept by the voter until the answer arrives.
pub type TicketState = IssuanceState<E, Base>;

pub struct Voter {
    usk: UserSecretKey<E>,
    id: G1,
}

impl std::fmt::Debug for Voter {
    /// Never `usk`: it is every tag this voter will make.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Voter").finish_non_exhaustive()
    }
}

/// A voter's ticket for one election. Secret: whoever holds it and the voter's key can vote.
pub struct Ticket {
    election: Election,
    cred: Credential<E, Base>,
}

impl std::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ticket")
            .field("election", &self.election.id())
            .finish_non_exhaustive()
    }
}

impl Ticket {
    pub fn election(&self) -> &Election {
        &self.election
    }
}

/// A cast: the attestation that admits one ballot. The ballot's bytes travel beside it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cast {
    pub attestation: Attestation<E, Base>,
}

impl Cast {
    /// The tag, multibase: this ticket's nullifier in this election.
    ///
    /// # Errors
    /// [`VotingError::Serialization`] if the point cannot be encoded.
    pub fn tag(&self) -> Result<String, VotingError> {
        point_text(&self.attestation.tag).map_err(|e| VotingError::Serialization(e.to_string()))
    }
}

impl Voter {
    /// A fresh key pair from `rng`.
    ///
    /// # Errors
    /// [`VotingError::Pcs`] if the key pair cannot be generated.
    pub fn generate<R: RngCore + CryptoRng>(
        params: &VotingParams,
        rng: &mut R,
    ) -> Result<Self, VotingError> {
        let (id, usk) = params.open().user_keygen(rng)?;
        Ok(Self { usk, id })
    }

    /// The key pair from a 32-byte seed: the same seed always gives the same key, so a VTA never
    /// stores it.
    ///
    /// # Errors
    /// As [`Self::generate`].
    pub fn from_seed(params: &VotingParams, seed: &[u8; 32]) -> Result<Self, VotingError> {
        Self::generate(params, &mut vti_vetting_pcs::scheme::seeded_rng(seed))
    }

    /// The voter's PCS identifier. The registrar sees it in the request; no cast reveals it.
    pub fn id(&self) -> &G1 {
        &self.id
    }

    /// The blinded request for a ticket to `election`, and the state that unblinds the answer.
    ///
    /// # Errors
    /// [`VotingError::WrongCommunity`], or [`VotingError::Pcs`] if the request cannot be built.
    pub fn ticket_request<R: RngCore + CryptoRng>(
        &self,
        params: &VotingParams,
        election: &Election,
        rng: &mut R,
    ) -> Result<(TicketRequest, TicketState), VotingError> {
        same_community(params, election)?;
        Ok(params.open().root_request(
            params.hvk(),
            &election.predicate(),
            &self.id,
            &self.usk,
            rng,
        )?)
    }

    /// Unblind the registrar's answer into this voter's ticket.
    ///
    /// # Errors
    /// [`VotingError::Pcs`] if it does not unblind under the published key, which is what a
    /// wrong or swapped answer looks like from here.
    pub fn accept_ticket(
        &self,
        params: &VotingParams,
        election: &Election,
        pre: &PreTicket,
        state: &TicketState,
    ) -> Result<Ticket, VotingError> {
        same_community(params, election)?;
        let cred =
            params
                .open()
                .unblind(params.hvk(), &self.usk, &election.predicate(), pre, state)?;
        Ok(Ticket {
            election: election.clone(),
            cred,
        })
    }

    /// Cast `ballot` with `ticket`: an attestation for the election's point, bound to the ballot.
    ///
    /// # Errors
    /// [`VotingError::WrongCommunity`], or [`VotingError::Pcs`] if the attestation cannot be made.
    pub fn cast<R: RngCore + CryptoRng>(
        &self,
        params: &VotingParams,
        ticket: &Ticket,
        ballot: &[u8],
        rng: &mut R,
    ) -> Result<Cast, VotingError> {
        let election = &ticket.election;
        same_community(params, election)?;
        let attestation = params.open().attest_in_context(
            params.hvk(),
            &self.usk,
            &election.predicate(),
            &ticket.cred,
            &election.point()?,
            &election.ballot_context(ballot),
            rng,
        )?;
        Ok(Cast { attestation })
    }
}

fn same_community(params: &VotingParams, election: &Election) -> Result<(), VotingError> {
    if params.community() == election.community() {
        Ok(())
    } else {
        Err(VotingError::WrongCommunity {
            expected: params.community().to_string(),
            actual: election.community().to_string(),
        })
    }
}
