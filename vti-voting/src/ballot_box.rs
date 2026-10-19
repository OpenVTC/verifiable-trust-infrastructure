//! The voting service's half: admit a cast, then count its ticket once.
//!
//! [`BallotBox::verify`] is pure and holds no secret, only the community's published `hvk`, so
//! it runs in parallel and any auditor can run it again over the board (VTI-VOT-044,
//! VTI-VOT-070). [`BallotBox::admit`] adds the one stateful step, recording the tag in a
//! [`NullifierStore`] under the election's revote rule (VTI-VOT-041).

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::{
    VotingError,
    election::Election,
    scheme::{Fr, G1, Hvk, Open, VotingParams},
    voter::Cast,
};

/// SHA-256 of a ballot's bytes.
pub type BallotDigest = [u8; 32];

/// What a second ballot under one ticket does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Revote {
    /// The later ballot replaces the earlier one.
    Replace,
    /// The first ballot stands; a different later one is refused.
    Refuse,
}

/// The outcome of admitting a cast.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Admission {
    /// The first ballot under this tag.
    Counted { tag: String },
    /// This ballot replaced the earlier one under its tag.
    Replaced { tag: String, previous: BallotDigest },
    /// The same ballot again: a resend, answered as the first time (the cast is idempotent).
    AlreadyCounted { tag: String },
}

/// Where a ballot box records which tags have a ballot, keyed by tag. Each method is ONE atomic
/// operation on the store: two casts racing under one tag must not both read "absent".
pub trait NullifierStore {
    /// The digest recorded under `tag`, if any.
    ///
    /// # Errors
    /// [`VotingError::Store`] if the store cannot be read.
    fn get(&self, tag: &str) -> Result<Option<BallotDigest>, VotingError>;
    /// Record `digest` under `tag` unless one is there; return what was there.
    ///
    /// # Errors
    /// [`VotingError::Store`] if the store cannot be written.
    fn insert_if_absent(
        &mut self,
        tag: &str,
        digest: BallotDigest,
    ) -> Result<Option<BallotDigest>, VotingError>;
    /// Record `digest` under `tag`, replacing any; return what was there.
    ///
    /// # Errors
    /// [`VotingError::Store`] if the store cannot be written.
    fn swap(
        &mut self,
        tag: &str,
        digest: BallotDigest,
    ) -> Result<Option<BallotDigest>, VotingError>;
}

/// An in-memory store, for tests and the benchmark.
#[derive(Debug, Default)]
pub struct MemoryNullifiers(HashMap<String, BallotDigest>);

impl MemoryNullifiers {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl NullifierStore for MemoryNullifiers {
    fn get(&self, tag: &str) -> Result<Option<BallotDigest>, VotingError> {
        Ok(self.0.get(tag).copied())
    }
    fn insert_if_absent(
        &mut self,
        tag: &str,
        digest: BallotDigest,
    ) -> Result<Option<BallotDigest>, VotingError> {
        if let Some(d) = self.0.get(tag) {
            return Ok(Some(*d));
        }
        self.0.insert(tag.to_string(), digest);
        Ok(None)
    }
    fn swap(
        &mut self,
        tag: &str,
        digest: BallotDigest,
    ) -> Result<Option<BallotDigest>, VotingError> {
        Ok(self.0.insert(tag.to_string(), digest))
    }
}

pub struct BallotBox<S> {
    open: Open,
    hvk: Hvk,
    election: Election,
    phi: Fr,
    point: G1,
    revote: Revote,
    store: S,
}

impl<S> std::fmt::Debug for BallotBox<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BallotBox")
            .field("election", &self.election)
            .field("revote", &self.revote)
            .finish_non_exhaustive()
    }
}

impl<S: NullifierStore> BallotBox<S> {
    /// A ballot box for `election`, admitting tickets of the community `params` names.
    ///
    /// # Errors
    /// [`VotingError::WrongCommunity`] if `election` is another community's; [`VotingError::Pcs`]
    /// if the class or the point cannot be derived.
    pub fn new(
        params: &VotingParams,
        election: Election,
        revote: Revote,
        store: S,
    ) -> Result<Self, VotingError> {
        if params.community() != election.community() {
            return Err(VotingError::WrongCommunity {
                expected: params.community().to_string(),
                actual: election.community().to_string(),
            });
        }
        Ok(Self {
            phi: params.open().enc_pred(&election.predicate())?,
            point: election.point()?,
            open: params.open().clone(),
            hvk: params.hvk().clone(),
            election,
            revote,
            store,
        })
    }

    pub fn election(&self) -> &Election {
        &self.election
    }
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Check a cast against this election, statelessly: its class is this election's, and its
    /// attestation verifies for this election's point with `ballot` bound into it. Returns the
    /// tag.
    ///
    /// # Errors
    /// - [`VotingError::WrongClass`] for a ticket of another election, or another credential.
    /// - [`VotingError::ProofRejected`] if the attestation does not verify: a forged ticket,
    ///   another community's, or a ballot other than the one it was cast with.
    pub fn verify(&self, cast: &Cast, ballot: &[u8]) -> Result<String, VotingError> {
        // The class first: it is a field comparison, and the pairing check is not.
        if cast.attestation.phi != self.phi {
            return Err(VotingError::WrongClass);
        }
        self.open
            .check_attestation_in_context(
                &self.hvk,
                &self.point,
                &cast.attestation,
                &self.election.ballot_context(ballot),
            )
            .map_err(VotingError::ProofRejected)?;
        cast.tag()
    }

    /// Verify a cast, then count it once under the election's revote rule.
    ///
    /// # Errors
    /// As [`Self::verify`]; [`VotingError::AlreadyVoted`] for a different second ballot when the
    /// rule is [`Revote::Refuse`]; [`VotingError::Store`].
    pub fn admit(&mut self, cast: &Cast, ballot: &[u8]) -> Result<Admission, VotingError> {
        let digest: BallotDigest = Sha256::digest(ballot).into();
        // Cheap refusal before the pairing check: a tag is public on the board, so saying it is
        // taken tells a sender nothing new.
        if self.revote == Revote::Refuse {
            let tag = cast.tag()?;
            if let Some(held) = self.store.get(&tag)?
                && held != digest
            {
                return Err(VotingError::AlreadyVoted);
            }
        }
        let tag = self.verify(cast, ballot)?;
        let previous = match self.revote {
            Revote::Replace => self.store.swap(&tag, digest)?,
            Revote::Refuse => self.store.insert_if_absent(&tag, digest)?,
        };
        match previous {
            None => Ok(Admission::Counted { tag }),
            Some(p) if p == digest => Ok(Admission::AlreadyCounted { tag }),
            Some(_) if self.revote == Revote::Refuse => Err(VotingError::AlreadyVoted),
            Some(previous) => Ok(Admission::Replaced { tag, previous }),
        }
    }
}
