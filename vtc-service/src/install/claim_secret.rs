//! Claim-secret helpers for admin-invite install tokens.
//!
//! Each invite the daemon mints carries a server-generated **claim
//! secret** — a short alphanumeric string the operator delivers
//! out-of-band (the URL alone is insufficient to claim a passkey).
//! The plaintext is shown **once** in the create-invite response and
//! never persisted; the daemon keeps only an Argon2id PHC hash.
//!
//! Defense in depth — combined with the JWT signature, single-use
//! `Issued` → `Consumed` state machine, and 15-minute default TTL,
//! the claim secret means a stolen install URL is not enough to
//! impersonate the invited admin. The attacker also needs the code,
//! which travels through a separate channel (Signal/email/in
//! person).
//!
//! Alphabet is **unambiguous** — no `0`/`O`/`1`/`I`/`l`. 32-char
//! alphabet × 10 chars = 32^10 ≈ 2^50 combinations, far beyond what
//! the tower-governor rate limit on `/v1/install/claim/start`
//! (5 rps + 10 burst per IP) and the 15-min TTL allow an attacker
//! to brute-force.

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use rand::RngExt;
use vti_common::error::AppError;

/// Unambiguous alphanumeric alphabet — omits `0`, `O`, `1`, `I`, `l`
/// to keep the code readable when transcribed over voice or written
/// down. 32 chars total.
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Length of the generated claim code. 10 chars × log2(32) ≈ 50 bits
/// of entropy — comfortable margin against online brute-force under
/// the existing rate limit + TTL.
const CLAIM_SECRET_LEN: usize = 10;

/// Generate a fresh random claim code. The plaintext is shown to
/// the operator once and never persisted by the daemon.
pub fn generate() -> String {
    let mut rng = rand::rng();
    (0..CLAIM_SECRET_LEN)
        .map(|_| {
            let idx = rng.random_range(0..ALPHABET.len());
            ALPHABET[idx] as char
        })
        .collect()
}

/// Argon2id-hash a plaintext claim secret to a PHC string for
/// persistence. Uses Argon2's library defaults (currently
/// m=19456 KiB, t=2, p=1 — OWASP's recommended baseline). The
/// hashing cost is paid once at invite-mint and once at claim
/// time; well below operator-perceivable latency.
pub fn hash(secret: &str) -> Result<String, AppError> {
    // `password-hash` 0.6 generates the salt itself (`getrandom`, on by
    // default) rather than taking one. The 0.5 call passed an explicitly
    // generated `SaltString`; dropping it is not a weakening — the library
    // draws a large random salt from the same OS source.
    Argon2::default()
        .hash_password(secret.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(format!("claim secret hash failed: {e}")))
}

/// Constant-time verify `secret` against a stored Argon2id PHC
/// string. Returns `Ok(true)` on match, `Ok(false)` on mismatch,
/// and `Err` on malformed hash (which should not happen in
/// practice — we wrote the hash ourselves at mint time).
pub fn verify(secret: &str, stored_hash: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| AppError::Internal(format!("malformed claim secret hash: {e}")))?;
    match Argon2::default().verify_password(secret.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
        Err(e) => Err(AppError::Internal(format!(
            "claim secret verify failed: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_uses_unambiguous_alphabet_and_correct_length() {
        for _ in 0..100 {
            let code = generate();
            assert_eq!(code.len(), CLAIM_SECRET_LEN);
            for c in code.chars() {
                assert!(
                    ALPHABET.contains(&(c as u8)),
                    "char {c:?} not in unambiguous alphabet"
                );
            }
        }
    }

    #[test]
    fn generate_produces_distinct_codes() {
        let a = generate();
        let b = generate();
        // Collision probability across two draws from 32^10 is
        // 2^-50; effectively never. A failure here means rand
        // isn't actually random.
        assert_ne!(a, b);
    }

    #[test]
    fn hash_and_verify_round_trip() {
        let secret = generate();
        let stored = hash(&secret).unwrap();
        assert!(stored.starts_with("$argon2id$"));
        assert!(verify(&secret, &stored).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let stored = hash("CORRECT-SECRET").unwrap();
        assert!(!verify("WRONG-SECRET", &stored).unwrap());
    }

    #[test]
    fn verify_errors_on_malformed_hash() {
        let err = verify("anything", "not a phc string").unwrap_err();
        assert!(
            format!("{err}").contains("malformed claim secret hash"),
            "expected malformed-hash error, got: {err}"
        );
    }

    /// A PHC string written by **argon2 0.5**, verified by whatever version
    /// is linked now.
    ///
    /// Claim-secret hashes are persisted at invite-mint and read back at claim
    /// time, so they outlive any upgrade of the hashing crate. Every other test
    /// here hashes and verifies with the same linked version, which cannot fail
    /// on a format or parameter change — both sides move together. This one
    /// cannot move: the string is frozen, generated against 0.5 before the 0.6
    /// bump, so it fails if a future upgrade stops reading what we already
    /// wrote to disk.
    ///
    /// Regenerate only when deliberately migrating stored hashes, and then only
    /// alongside a migration for the rows already out there.
    #[test]
    fn verifies_a_hash_written_by_the_previous_argon2() {
        const WRITTEN_BY_0_5: &str = "$argon2id$v=19$m=19456,t=2,p=1$\
                                      rYUqQxBXAxmC08nsOcap4Q$\
                                      FO7Xh+ZqT32UeAoqfQtwb7dRcygZ8xxYYBS63AXGqkk";
        assert!(
            verify("CLAIM-SECRET-05", WRITTEN_BY_0_5).unwrap(),
            "a hash written by argon2 0.5 no longer verifies — every claim \
             secret minted before the upgrade is unusable"
        );
        assert!(!verify("WRONG-SECRET", WRITTEN_BY_0_5).unwrap());
    }

    #[test]
    fn two_hashes_of_same_secret_differ_due_to_salt() {
        let secret = "SAME-SECRET";
        let h1 = hash(secret).unwrap();
        let h2 = hash(secret).unwrap();
        assert_ne!(h1, h2, "salts must differ");
        // Both verify against the same plaintext.
        assert!(verify(secret, &h1).unwrap());
        assert!(verify(secret, &h2).unwrap());
    }
}
