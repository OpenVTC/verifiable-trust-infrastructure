//! The community's half: the voting helper key, and the one thing it signs — tickets.
//!
//! This type holds a key and signs; it counts nothing. Whether the requester is eligible for an
//! election, and whether they already hold a ticket for it, are facts about the community's
//! records: the caller checks them durably, and logs the member-signed request, before calling
//! [`Registrar::issue_ticket`] (VTI-VOT-022 requires that record).
//!
//! # The keys are derived, not stored
//!
//! As hidden vetting's issuer: [`Registrar::derive`] produces the key pair from a 32-byte secret
//! over ChaCha20 seeded with `SHA-256(info ‖ len ‖ community ‖ secret)`. The info string is
//! voting's own, so the same master secret gives a vetting key and a voting key that are
//! unrelated. Change the secret and `hvk` changes: every ticket of an open election stops
//! verifying.

use std::sync::Mutex;

use predicate_credential_system::{
    cred::CredentialBase,
    pcs::{HelperSecretKey, PredicateCredentialSystem},
};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::{
    VotingError,
    election::{Election, check_community},
    scheme::{Base, G1, Hvk, Open, VotingParams, key_text, open},
    voter::TicketRequest,
};

pub const KEY_DERIVATION_INFO: &[u8] = b"vti-voting-pcs-keys/v1\0";

/// What [`Registrar::issue_ticket`] returns: the voter unblinds it into their ticket.
pub type PreTicket = <Base as CredentialBase>::PreCredential;

pub struct Registrar {
    community: String,
    open: Open,
    hvk: Hvk,
    hsk: HelperSecretKey<Base>,
    /// Issuance is sequential: the scheme's security argument holds for sequential issuance
    /// under one helper key, and the library does not enforce it.
    hsk_lock: Mutex<()>,
}

impl std::fmt::Debug for Registrar {
    /// Never the key: a `{:?}` in a log line is how a signing key reaches a log file.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registrar")
            .field("community", &self.community)
            .finish_non_exhaustive()
    }
}

impl Registrar {
    /// The key pair from one secret, deterministically.
    ///
    /// # Errors
    /// [`VotingError::InvalidCommunity`] or [`VotingError::Pcs`].
    pub fn derive(community: &str, secret: &[u8; 32]) -> Result<Self, VotingError> {
        check_community(community)?;
        let mut h = Sha256::new();
        h.update(KEY_DERIVATION_INFO);
        h.update((community.len() as u64).to_le_bytes());
        h.update(community.as_bytes());
        h.update(secret);
        let seed: [u8; 32] = h.finalize().into();
        Self::generate(community, &mut ChaCha20Rng::from_seed(seed))
    }

    /// Fresh keys from `rng`. Tests use this; a service uses [`Self::derive`].
    ///
    /// # Errors
    /// [`VotingError::InvalidCommunity`] or [`VotingError::Pcs`].
    pub fn generate<R: RngCore + CryptoRng>(
        community: &str,
        rng: &mut R,
    ) -> Result<Self, VotingError> {
        check_community(community)?;
        let open = open(community)?;
        let (hvk, hsk) = open.helper_keygen(rng);
        Ok(Self {
            community: community.to_string(),
            open,
            hvk,
            hsk,
            hsk_lock: Mutex::new(()),
        })
    }

    pub fn community(&self) -> &str {
        &self.community
    }
    pub fn hvk(&self) -> &Hvk {
        &self.hvk
    }

    /// The public half, as voters and ballot boxes take it.
    pub fn params(&self) -> VotingParams {
        VotingParams::new(&self.community, self.hvk.clone())
            .expect("the community was checked at construction")
    }

    /// `hvk` as the community publishes it, multibase.
    ///
    /// # Errors
    /// [`VotingError::Serialization`] if the key cannot be encoded.
    pub fn public_text(&self) -> Result<String, VotingError> {
        key_text(&self.hvk).map_err(|e| VotingError::Serialization(e.to_string()))
    }

    /// Sign one voter's blinded request for a ticket to `election`.
    ///
    /// The request carries a commitment; what comes back is a pre-credential only the voter can
    /// unblind. The registrar never sees the ticket it made, which is why it cannot recognise
    /// the ticket's casts later.
    ///
    /// # Errors
    /// - [`VotingError::WrongCommunity`] if `election` is another community's.
    /// - [`VotingError::Pcs`] if the request does not verify.
    pub fn issue_ticket<R: RngCore + CryptoRng>(
        &self,
        election: &Election,
        id: &G1,
        request: &TicketRequest,
        rng: &mut R,
    ) -> Result<PreTicket, VotingError> {
        if election.community() != self.community {
            return Err(VotingError::WrongCommunity {
                expected: self.community.clone(),
                actual: election.community().to_string(),
            });
        }
        let f = election.predicate();
        let _guard = self.hsk_lock.lock().expect("helper signing lock");
        Ok(self
            .open
            .issue_root(&self.hvk, &self.hsk, &f, id, request, rng)?)
    }
}
