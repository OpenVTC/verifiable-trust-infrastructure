//! The match code two people read to each other at the start of a vetting
//! session.
//!
//! Same construction as the VTC's personhood match code
//! (`vtc-service/src/members/match_code.rs`) — derived from the session
//! document's `id`, never transmitted as a secret, Crockford base32 so nothing
//! can be misheard into another valid code — with its **own domain tag**. A
//! vetting session and a personhood challenge must never read out the same
//! eight characters, or a code confirmed for one ceremony would look like
//! confirmation of the other.
//!
//! What the code proves: the person in front of the vetter is driving the
//! client that received *this* session, and therefore controls the join DID
//! the card is signed by. Nothing verifies it server-side; `challenge` already
//! binds the card cryptographically. Reading it aloud is how the two humans
//! bind themselves to that.

use sha2::{Digest, Sha256};

/// Domain separation for the vetting derivation.
const DOMAIN_TAG: &[u8] = b"openvtc-vetting-match/v1\0";

/// Crockford base32 — no `I`, `L`, `O` or `U`.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Derive the `XXXX-XXXX` match code for a `vetting/session` document id.
#[must_use]
pub fn vetting_match_code(session_document_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_TAG);
    hasher.update(session_document_id.as_bytes());
    encode(&hasher.finalize())
}

/// First 40 bits of `digest` → eight Crockford characters, dash after four.
fn encode(digest: &[u8]) -> String {
    let bits = digest[..5]
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    let mut out = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            out.push('-');
        }
        let shift = 35 - 5 * i;
        out.push(char::from(CROCKFORD[((bits >> shift) & 0x1f) as usize]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_is_two_groups_of_four_crockford_characters() {
        let code = vetting_match_code("urn:uuid:5b0e1c2a-7d4f-4a51-9c6e-2f1b8d3a9e70");
        assert_eq!(code.len(), 9);
        assert_eq!(code.as_bytes()[4], b'-');
        assert!(
            code.chars()
                .filter(|c| *c != '-')
                .all(|c| CROCKFORD.contains(&(c as u8)))
        );
    }

    #[test]
    fn deterministic_and_input_sensitive() {
        let a = vetting_match_code("urn:uuid:a");
        assert_eq!(a, vetting_match_code("urn:uuid:a"));
        assert_ne!(a, vetting_match_code("urn:uuid:b"));
    }

    #[test]
    fn forty_bits_fill_eight_characters_exactly() {
        // 8 × 5 = 40 = 5 bytes. A change that narrowed this would weaken the
        // confirmation without failing anything else.
        assert_eq!(encode(&[0xff; 32]), "ZZZZ-ZZZZ");
        assert_eq!(encode(&[0x00; 32]), "0000-0000");
    }

    #[test]
    fn never_collides_with_the_personhood_derivation() {
        // The personhood code hashes `vtc-personhood-match/v1\0 || id`; for the
        // same input the two must differ, or one ceremony's spoken confirmation
        // would pass for the other's.
        let id = "5b0e1c2a-7d4f-4a51-9c6e-2f1b8d3a9e70";
        let mut personhood = Sha256::new();
        personhood.update(b"vtc-personhood-match/v1\0");
        personhood.update(id.as_bytes());
        assert_ne!(vetting_match_code(id), encode(&personhood.finalize()));
    }
}
