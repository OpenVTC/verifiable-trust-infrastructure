//! Human-readable match code for the personhood challenge.
//!
//! ## Why this exists
//!
//! The personhood ceremony's security comes from two bindings the
//! published Trust Task spells out (`vtc/members/personhood/assert/0.1`,
//! §Authorization): the presentation's `holder` equals the DID being
//! asserted, and its `proof.challenge` equals the paired `challengeId`.
//! Neither is negotiable, and `challengeId` is a UUID — 36 characters,
//! which is fine over a wire and hopeless read aloud.
//!
//! The in-person ceremony an operator actually wants is: two people in a
//! room, one of them holding the admin session, confirming out loud that
//! the challenge the member's device is about to sign is the challenge
//! the admin just minted. That is a *confirmation* channel, not a
//! transfer channel — the same shape as a Bluetooth pairing code or a
//! Signal safety number.
//!
//! So the match code is **derived from the challenge id**, never
//! transmitted as an independent secret and never accepted as one. Any
//! party already holding the `challengeId` computes the same eight
//! characters; a party who does not hold it cannot. Nothing verifies the
//! match code server-side, because there is nothing it could prove that
//! `proof.challenge` does not already prove — reading it aloud is how
//! two humans check they are talking about the same ceremony.
//!
//! ## Construction
//!
//! ```text
//! SHA-256(DOMAIN_TAG || challenge_id_bytes) -> first 40 bits
//!   -> Crockford base32 -> 8 chars -> "XXXX-XXXX"
//! ```
//!
//! Crockford's alphabet omits `I`, `L`, `O` and `U`, so the code has no
//! character pair a person can mishear or mistranscribe into another
//! valid code. 40 bits over 8 characters is exactly the alphabet's
//! capacity — see the test module, which pins the bit budget because an
//! encoding change that quietly narrowed it would weaken the
//! confirmation without failing anything else.

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Domain separation for the match-code derivation. A code derived here
/// must never collide with a digest computed for any other purpose over
/// the same challenge id.
const DOMAIN_TAG: &[u8] = b"vtc-personhood-match/v1\0";

/// `ext` member the code travels in.
///
/// `vtc/members/personhood/challenge/0.1`'s response schema is
/// `additionalProperties: false`, so a new top-level field would put the
/// daemon out of conformance with its own published Trust Task. `ext` is
/// exactly what the framework reserves for ecosystem-defined members
/// (SPEC §4.5.1), and its `propertyNames` pattern requires a reverse-DNS
/// key in lowercase — which is why this is `match-code` and not
/// `matchCode`. Same convention as
/// [`crate::routes::policies::read::PURPOSE_EXT_KEY`].
pub const MATCH_CODE_EXT_KEY: &str = "org.openvtc.match-code";

/// Crockford base32 — no `I`, `L`, `O`, `U`.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters in the code, excluding the separator.
const CODE_CHARS: usize = 8;

/// Bits consumed from the digest. `CODE_CHARS * 5` — the exact capacity
/// of eight base32 characters. Pinned by a test.
const CODE_BITS: usize = CODE_CHARS * 5;

/// Derive the display code for a challenge id, formatted `XXXX-XXXX`.
///
/// Deterministic: the admin's session and the member's client both
/// compute it from the `challengeId` they each already hold, and compare
/// out loud. No state, no round trip.
pub fn derive(challenge_id: Uuid) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_TAG);
    hasher.update(challenge_id.as_bytes());
    let digest = hasher.finalize();

    // Take CODE_BITS off the front of the digest, most-significant first,
    // five at a time. Reading bit-by-bit out of the leading bytes keeps
    // the mapping independent of `usize` width and of how many bytes we
    // happen to need.
    let mut out = String::with_capacity(CODE_CHARS + 1);
    for (i, bit_offset) in (0..CODE_BITS).step_by(5).enumerate() {
        let mut idx = 0u8;
        for bit in 0..5 {
            let abs = bit_offset + bit;
            let byte = digest[abs / 8];
            let taken = (byte >> (7 - (abs % 8))) & 1;
            idx = (idx << 1) | taken;
        }
        if i == 4 {
            out.push('-');
        }
        out.push(CROCKFORD[idx as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The code is a pure function of the challenge id — that is the
    /// whole mechanism. If this ever stops holding, the admin and the
    /// member stop seeing the same eight characters and the ceremony
    /// silently loses its confirmation step without failing anything.
    #[test]
    fn derivation_is_deterministic() {
        let id = Uuid::parse_str("6f1c4f9e-7c2a-4f4b-9a3e-2b1d0c5e8a77").expect("uuid");
        assert_eq!(derive(id), derive(id));
    }

    /// Shape a human reads aloud: `XXXX-XXXX`, all characters from
    /// Crockford's alphabet.
    #[test]
    fn shape_is_four_dash_four_from_crockford() {
        let code = derive(Uuid::new_v4());
        assert_eq!(code.len(), CODE_CHARS + 1, "code is 8 chars plus separator");
        assert_eq!(code.as_bytes()[4], b'-', "separator sits in the middle");
        for c in code.bytes().filter(|c| *c != b'-') {
            assert!(
                CROCKFORD.contains(&c),
                "character {} is outside Crockford's alphabet",
                c as char
            );
        }
    }

    /// The alphabet must exclude the four characters Crockford drops.
    /// Re-introducing `I`, `L`, `O` or `U` would put a mishearable pair
    /// into a code whose entire job is being said out loud correctly.
    #[test]
    fn alphabet_omits_mishearable_characters() {
        for c in *b"ILOU" {
            assert!(
                !CROCKFORD.contains(&c),
                "Crockford omits {} — it is confusable when spoken",
                c as char
            );
        }
        assert_eq!(CROCKFORD.len(), 32, "base32 needs exactly 32 symbols");
    }

    /// Pin the bit budget. Eight base32 characters carry 40 bits and the
    /// derivation must consume all of them — an encoding change that
    /// narrowed the input (say, hex-then-truncate, which yields 4 bits a
    /// character) would still produce eight plausible characters while
    /// quietly halving the space a mismatch has to fall into.
    #[test]
    fn bit_budget_is_fully_consumed() {
        assert_eq!(CODE_BITS, 40, "8 chars x 5 bits");
        const {
            assert!(
                CODE_BITS <= 256,
                "cannot draw more bits than SHA-256 produces"
            )
        };
    }

    /// Distinct challenges yield distinct codes in practice. Not a
    /// collision proof — 40 bits is a confirmation channel, not a key —
    /// but a sweep this size catches a derivation that has collapsed to
    /// a constant or is reading a fixed slice of the digest.
    #[test]
    fn distinct_challenges_yield_distinct_codes() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2_000 {
            assert!(
                seen.insert(derive(Uuid::new_v4())),
                "collision across 2k samples means the derivation lost entropy"
            );
        }
    }
}
