//! An election's public identity: the point a cast attests for, and the context a ballot is
//! bound into.
//!
//! Both are functions of the community, the election identifier and the **manifest digest**
//! (VTI-VOT-011). A member shown a different question than the one registered derives a
//! different point and context, so their ballot does not count in the registered election: what
//! a member answers is what was registered, or nothing.

use predicate_credential_system::hash::{HashToGroup, bls12_381::G1Hasher};

use crate::{
    VotingError,
    scheme::{G1, voter_predicate},
};

/// Domain of the election point oracle. A new derivation is a new domain, never a parameter.
pub const ELECTION_POINT_DOMAIN: &[u8] = b"vti/vote/election-point/v1";
/// Prefix of every ballot context.
pub const BALLOT_CONTEXT_TAG: &[u8] = b"vti/vote/ballot/v1\0";

/// SHA-256 of the election manifest as registered.
pub type ManifestDigest = [u8; 32];

/// An election identifier: 1 to 128 of `A-Z a-z 0-9 . _ -`. It appears in a class label and is
/// framed into every hash, so the alphabet is closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ElectionId(String);

impl ElectionId {
    /// # Errors
    /// [`VotingError::InvalidElectionId`] outside the alphabet or length.
    pub fn new(id: &str) -> Result<Self, VotingError> {
        let ok = (1..=128).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if ok {
            Ok(Self(id.to_string()))
        } else {
            Err(VotingError::InvalidElectionId(id.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn check_community(community: &str) -> Result<(), VotingError> {
    if community.is_empty() || community.chars().any(char::is_control) {
        Err(VotingError::InvalidCommunity)
    } else {
        Ok(())
    }
}

/// One election of one community, as registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Election {
    community: String,
    id: ElectionId,
    manifest_digest: ManifestDigest,
}

impl Election {
    /// # Errors
    /// [`VotingError::InvalidCommunity`] for an unusable community identifier.
    pub fn new(
        community: &str,
        id: ElectionId,
        manifest_digest: ManifestDigest,
    ) -> Result<Self, VotingError> {
        check_community(community)?;
        Ok(Self {
            community: community.to_string(),
            id,
            manifest_digest,
        })
    }

    pub fn community(&self) -> &str {
        &self.community
    }
    pub fn id(&self) -> &ElectionId {
        &self.id
    }
    pub fn manifest_digest(&self) -> &ManifestDigest {
        &self.manifest_digest
    }

    /// The voter class of this election.
    pub fn predicate(&self) -> predicate_credential_system::pcs::Predicate {
        voter_predicate(&self.id)
    }

    /// `id_E`: the public point every cast in this election attests for. A hash to the curve, so
    /// nobody knows its discrete logarithm; the scheme hashes it again before deriving a tag.
    ///
    /// # Errors
    /// [`VotingError::Pcs`] if the hash-to-curve suite cannot be instantiated.
    pub fn point(&self) -> Result<G1, VotingError> {
        let hasher = G1Hasher::new(ELECTION_POINT_DOMAIN)?;
        let mut msg = Vec::new();
        frame(&mut msg, self.community.as_bytes());
        frame(&mut msg, self.id.as_str().as_bytes());
        frame(&mut msg, &self.manifest_digest);
        Ok(hasher.hash(b"election", &msg))
    }

    /// The application context a cast is made under: this election and the ballot's exact bytes.
    /// The attestation cannot be moved to another ballot or another election.
    pub fn ballot_context(&self, ballot: &[u8]) -> Vec<u8> {
        let mut out = BALLOT_CONTEXT_TAG.to_vec();
        frame(&mut out, self.community.as_bytes());
        frame(&mut out, self.id.as_str().as_bytes());
        frame(&mut out, &self.manifest_digest);
        frame(&mut out, ballot);
        out
    }
}

impl Election {
    /// `ctx` of the encrypted levels (CONVENTIONS §9.2): every trustee proof, sealed payload and
    /// encrypted ballot of this election is bound to it.
    pub fn trustee_context(&self) -> Vec<u8> {
        let mut out = Vec::new();
        frame(&mut out, self.community.as_bytes());
        frame(&mut out, self.id.as_str().as_bytes());
        frame(&mut out, &self.manifest_digest);
        out
    }
}

/// Length-prefixed, so no two different field sequences encode alike.
pub(crate) fn frame(out: &mut Vec<u8>, field: &[u8]) {
    out.extend((field.len() as u64).to_be_bytes());
    out.extend(field);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn election_ids_are_a_closed_alphabet() {
        assert!(ElectionId::new("agm-2027.budget_1").is_ok());
        for bad in ["", "a/b", "a b", "ü", &"x".repeat(129)] {
            assert!(ElectionId::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_point_depends_on_every_field() {
        let e = |c: &str, id: &str, d: u8| {
            Election::new(c, ElectionId::new(id).unwrap(), [d; 32])
                .unwrap()
                .point()
                .unwrap()
        };
        let base = e("did:example:c", "e1", 0);
        assert_eq!(base, e("did:example:c", "e1", 0));
        assert_ne!(base, e("did:example:d", "e1", 0));
        assert_ne!(base, e("did:example:c", "e2", 0));
        assert_ne!(base, e("did:example:c", "e1", 1));
    }

    #[test]
    fn framing_keeps_fields_apart() {
        let a = Election::new("did:example:c", ElectionId::new("e1").unwrap(), [0; 32]).unwrap();
        assert_ne!(a.ballot_context(b"ab"), a.ballot_context(b"a"));
    }
}
