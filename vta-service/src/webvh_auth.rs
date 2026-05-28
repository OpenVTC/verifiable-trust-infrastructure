//! Daemon REST authentication for webvh hosting servers.
//!
//! The webvh daemon (`affinidi-webvh-service/did-hosting-control`) exposes a
//! challenge/response auth flow over plain HTTP-over-TLS, but the
//! *body* of the `POST /api/auth/` and `POST /api/auth/refresh`
//! requests is a **JWS-signed DIDComm v2 envelope**, not plain JSON.
//! This module builds those envelopes; the actual HTTP plumbing lives
//! in [`crate::webvh_client::WebvhClient`].
//!
//! ## Wire shape
//!
//! 1. Client `POST /api/auth/challenge { did }` → daemon returns
//!    `{ session_id, data: { challenge } }`. The daemon binds the
//!    32-byte random `challenge` to `session_id` server-side with
//!    a TTL (default 5 min).
//! 2. Client signs a DIDComm `Message` of `type:
//!    https://trusttasks.org/spec/auth/authenticate/0.1` with body
//!    `{ session_id, challenge }`, packs it as JWS (EdDSA, Ed25519),
//!    and POSTs the JWS string to `/api/auth/`.
//! 3. Daemon `unpack_signed` verifies the JWS, asserts `from` matches
//!    the JWS signer, asserts `body.{session_id, challenge}` matches
//!    its stored session, and returns access + refresh tokens.
//!
//! Refresh follows the same shape with `type:
//! https://trusttasks.org/spec/auth/refresh/0.1` and
//! `body: { refresh_token }`.
//!
//! ## Audience binding
//!
//! Per the audit of PR #111, we want a cross-daemon-replay
//! defence so a JWS valid for one daemon can't be re-submitted to
//! a different daemon that happens to trust the same VTA DID. The
//! daemon's session_id is a UUIDv4 — astronomically unlikely to
//! collide across daemons — so the *practical* binding already
//! exists via "session_id + challenge live on this daemon, signed
//! response must match." For defence-in-depth we additionally
//! populate the DIDComm `to: [server_did]` field. Current
//! `did-hosting-control` does not verify `to:`, but a future verification
//! step would reject a JWS minted for daemon A when forwarded to
//! daemon B without us having to re-mint the envelope shape.
//!
//! ## Freshness
//!
//! `created_time` is set from the caller-supplied `now` value. The
//! daemon verifies it falls within a 5-minute past window and 60-
//! second future window. We never *trust* our own `created_time` for
//! anti-replay (the daemon's challenge is the authoritative
//! freshness primitive); the field is here so the daemon's
//! `unpack_signed` doesn't reject us as stale.

use affinidi_tdk::didcomm::Message;
use serde_json::json;
use zeroize::Zeroizing;

use crate::error::AppError;

/// DIDComm `type` URI for the initial authenticate request — the
/// canonical `spec/auth/authenticate/0.1` per dtgwg-trust-tasks-tf.
/// did-hosting accepts this natively (and recognises the historical
/// `affinidi.com/webvh/1.0/authenticate` form during the alias-table
/// migration window).
pub const AUTHENTICATE_TYPE: &str = "https://trusttasks.org/spec/auth/authenticate/0.1";

/// DIDComm `type` URI for the refresh request — `spec/auth/refresh/0.1`.
pub const REFRESH_TYPE: &str = "https://trusttasks.org/spec/auth/refresh/0.1";

/// Identifies who's signing the request. All fields are borrowed;
/// the caller owns the lifetime — important because `private_key`
/// is secret material that should be zeroized on drop in whatever
/// holds it.
#[derive(Debug)]
pub struct VtaSigningIdentity<'a> {
    /// VTA's base DID (no `#fragment`). Goes into the DIDComm `from:`.
    pub vta_did: &'a str,
    /// Fully-qualified key id including `#fragment`. Goes into the
    /// JWS protected-header `kid` — the daemon's `extract_signer_kid`
    /// reads this to resolve the verifying public key.
    pub signing_kid: &'a str,
    /// 32-byte Ed25519 seed. `pack_signed` derives the signing key
    /// from this on every call; we never hold the expanded key.
    pub private_key: &'a [u8; 32],
}

/// Daemon-side context for the authenticate redemption — values
/// returned by the prior `POST /api/auth/challenge` call.
#[derive(Debug)]
pub struct ChallengeContext<'a> {
    pub session_id: &'a str,
    pub challenge: &'a str,
    /// The daemon's DID. Goes into the DIDComm `to:` field for
    /// audience-binding (see module-level doc).
    pub server_did: &'a str,
}

/// Build the JWS-signed body for `POST /api/auth/`. Returns a
/// complete JWS string ready to be set as the HTTP request body.
pub fn build_authenticate_message(
    identity: &VtaSigningIdentity<'_>,
    ctx: &ChallengeContext<'_>,
    now_secs: u64,
) -> Result<String, AppError> {
    let msg = Message::new(
        AUTHENTICATE_TYPE,
        json!({
            "session_id": ctx.session_id,
            "challenge": ctx.challenge,
        }),
    )
    .from(identity.vta_did.to_string())
    .to(vec![ctx.server_did.to_string()])
    .created_time(now_secs);

    affinidi_tdk::didcomm::message::pack::pack_signed(
        &msg,
        identity.signing_kid,
        identity.private_key,
    )
    .map_err(|e| AppError::Internal(format!("failed to sign webvh authenticate message: {e}")))
}

/// Owned counterpart to [`VtaSigningIdentity`] — loads from the
/// VTA's key store and holds the 32-byte signing seed in a
/// `Zeroizing` wrapper so the bytes are wiped on drop.
///
/// Use [`as_ref`](Self::as_ref) to borrow into the lifetime-bound
/// [`VtaSigningIdentity`] view that the message builders take.
pub struct VtaSigningIdentityOwned {
    pub vta_did: String,
    pub signing_kid: String,
    pub private_key: Zeroizing<[u8; 32]>,
}

impl VtaSigningIdentityOwned {
    pub fn as_ref(&self) -> VtaSigningIdentity<'_> {
        VtaSigningIdentity {
            vta_did: &self.vta_did,
            signing_kid: &self.signing_kid,
            private_key: &self.private_key,
        }
    }
}

impl std::fmt::Debug for VtaSigningIdentityOwned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private key bytes — same hygiene as
        // `TokenData` / `WebvhServerAuthRecord`.
        f.debug_struct("VtaSigningIdentityOwned")
            .field("vta_did", &self.vta_did)
            .field("signing_kid", &self.signing_kid)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// Build the JWS-signed body for `POST /api/auth/refresh`.
pub fn build_refresh_message(
    identity: &VtaSigningIdentity<'_>,
    server_did: &str,
    refresh_token: &str,
    now_secs: u64,
) -> Result<String, AppError> {
    let msg = Message::new(
        REFRESH_TYPE,
        json!({
            "refresh_token": refresh_token,
        }),
    )
    .from(identity.vta_did.to_string())
    .to(vec![server_did.to_string()])
    .created_time(now_secs);

    affinidi_tdk::didcomm::message::pack::pack_signed(
        &msg,
        identity.signing_kid,
        identity.private_key,
    )
    .map_err(|e| AppError::Internal(format!("failed to sign webvh refresh message: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tdk::didcomm::message::unpack::{UnpackResult, unpack};
    use ed25519_dalek::SigningKey;

    /// Mint a deterministic test signing identity from a seed byte.
    /// Different seeds produce independent keypairs — sufficient for
    /// tests that want to assert "key A != key B" without pulling in
    /// the rand 0.10 RNG API surface.
    fn fixture_identity(seed_byte: u8) -> ([u8; 32], [u8; 32], String, String) {
        let seed = [seed_byte; 32];
        let sk = SigningKey::from_bytes(&seed);
        let private = sk.to_bytes();
        let public = sk.verifying_key().to_bytes();
        let vta_did = "did:webvh:scid123:vta.example".to_string();
        let kid = format!("{vta_did}#key-0");
        (private, public, vta_did, kid)
    }

    fn unpack_with(jws: &str, verifying_key: &[u8; 32]) -> Message {
        match unpack(jws, None, None, None, Some(verifying_key)).expect("unpack must succeed") {
            UnpackResult::Signed { message, .. } => message,
            UnpackResult::Plaintext(_) => panic!("expected Signed result, got Plaintext"),
            UnpackResult::Encrypted { .. } => panic!("expected Signed result, got Encrypted"),
        }
    }

    #[test]
    fn authenticate_message_round_trips_via_unpack() {
        // The daemon side calls the same `unpack` helper. If the
        // builder regresses to producing a JWS the daemon can't
        // verify, this catches it.
        let (private, public, vta_did, kid) = fixture_identity(7);
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };
        let ctx = ChallengeContext {
            session_id: "session-abc",
            challenge: "challenge-xyz",
            server_did: "did:web:daemon.example",
        };
        let jws = build_authenticate_message(&identity, &ctx, 1_700_000_000).unwrap();
        let msg = unpack_with(&jws, &public);

        assert_eq!(msg.typ, AUTHENTICATE_TYPE);
        assert_eq!(msg.from.as_deref(), Some(vta_did.as_str()));
        assert_eq!(
            msg.to.as_deref(),
            Some(&vec![ctx.server_did.to_string()][..])
        );
        assert_eq!(msg.body["session_id"], "session-abc");
        assert_eq!(msg.body["challenge"], "challenge-xyz");
        assert_eq!(msg.created_time, Some(1_700_000_000));
    }

    #[test]
    fn authenticate_message_binds_audience_via_to_field() {
        // Audit recommendation: include the daemon's DID in `to:` so
        // the JWS isn't replayable against a different daemon that
        // happens to verify `to:`. Today's did-hosting-control doesn't
        // verify `to:` but the binding must still be present.
        let (private, public, vta_did, kid) = fixture_identity(7);
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };
        let ctx = ChallengeContext {
            session_id: "s",
            challenge: "c",
            server_did: "did:web:daemon-A.example",
        };
        let jws = build_authenticate_message(&identity, &ctx, 1).unwrap();
        let msg = unpack_with(&jws, &public);
        assert_eq!(
            msg.to,
            Some(vec!["did:web:daemon-A.example".to_string()]),
            "to: must carry the daemon's DID for audience binding"
        );
    }

    #[test]
    fn authenticate_message_type_is_canonical_spec_uri() {
        // The VTA's outbound authenticate to did-hosting carries the
        // canonical Trust-Task spec URI per dtgwg-trust-tasks-tf.
        // did-hosting accepts both this and the historical
        // `affinidi.com/webvh/1.0/authenticate` form via its alias
        // table during the migration window; once that alias is
        // dropped (Phase 3 cleanup on did-hosting) this is the only
        // form on the wire.
        assert_eq!(
            AUTHENTICATE_TYPE,
            "https://trusttasks.org/spec/auth/authenticate/0.1",
        );
    }

    #[test]
    fn refresh_message_type_is_canonical_spec_uri() {
        assert_eq!(REFRESH_TYPE, "https://trusttasks.org/spec/auth/refresh/0.1",);
    }

    #[test]
    fn refresh_message_round_trips() {
        let (private, public, vta_did, kid) = fixture_identity(7);
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };
        let jws = build_refresh_message(&identity, "did:web:daemon.example", "rt-abc", 42).unwrap();
        let msg = unpack_with(&jws, &public);
        assert_eq!(msg.typ, REFRESH_TYPE);
        assert_eq!(msg.from.as_deref(), Some(vta_did.as_str()));
        assert_eq!(
            msg.to.as_deref(),
            Some(&vec!["did:web:daemon.example".to_string()][..])
        );
        assert_eq!(msg.body["refresh_token"], "rt-abc");
        assert_eq!(msg.created_time, Some(42));
    }

    #[test]
    fn refresh_message_type_is_distinct_from_authenticate() {
        // Mixing the two on the daemon side would let a captured
        // refresh JWS be replayed as an initial authenticate (or vice
        // versa) — the daemon's `typ` check is the defence.
        assert_ne!(AUTHENTICATE_TYPE, REFRESH_TYPE);
    }

    #[test]
    fn authenticate_message_signed_with_wrong_key_fails_unpack() {
        // Sanity: the signature is actually verified. Build with
        // identity A's key, attempt to verify with identity B's
        // public key, expect failure.
        let (private_a, _public_a, vta_did, kid) = fixture_identity(7);
        let (_private_b, public_b, _, _) = fixture_identity(42);
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private_a,
        };
        let ctx = ChallengeContext {
            session_id: "s",
            challenge: "c",
            server_did: "did:web:daemon.example",
        };
        let jws = build_authenticate_message(&identity, &ctx, 1).unwrap();
        let result = unpack(&jws, None, None, None, Some(&public_b));
        assert!(
            result.is_err(),
            "JWS signed by A must not verify under B's key"
        );
    }

    #[test]
    fn distinct_session_id_or_challenge_produces_distinct_jws() {
        // No accidental determinism: the daemon's session_id /
        // challenge is the freshness primitive; if our builder
        // produced a stable output for them, replay would be much
        // easier. (The JWS itself isn't deterministic anyway because
        // of the random message id, but pin the invariant.)
        let (private, _public, vta_did, kid) = fixture_identity(7);
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };
        let a = build_authenticate_message(
            &identity,
            &ChallengeContext {
                session_id: "s1",
                challenge: "c1",
                server_did: "did:web:x",
            },
            1,
        )
        .unwrap();
        let b = build_authenticate_message(
            &identity,
            &ChallengeContext {
                session_id: "s2",
                challenge: "c2",
                server_did: "did:web:x",
            },
            1,
        )
        .unwrap();
        assert_ne!(a, b, "session_id+challenge variation must affect the JWS");
    }
}
