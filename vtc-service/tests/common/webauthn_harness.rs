//! Deterministic soft authenticator for WebAuthn integration tests.
//!
//! Implements **M0.5.0** of the VTC MVP Phase 0 plan. The harness
//! produces real CTAP attestation objects + COSE OKP-Ed25519 public
//! keys that `webauthn-rs-core` can parse, so route-level integration
//! tests can drive a complete register + authenticate ceremony
//! without a browser.
//!
//! ## Why we ship our own instead of `webauthn-authenticator-rs::SoftPasskey`
//!
//! The upstream `SoftPasskey` (`webauthn-authenticator-rs` 0.5)
//! generates ES256/EC keys only — its key-generation code is
//! hard-coded to `openssl::ec`. VTC's install flow demands EdDSA
//! (spec §4.2: the passkey's COSE public key projects directly into
//! a `did:key`), so we need an authenticator that produces COSE OKP
//! Ed25519 credentials. This module is ~250 lines of CTAP-format
//! encoding on top of `ed25519-dalek` — small enough to ship and
//! understand in tree.
//!
//! ## Scope
//!
//! - Format: WebAuthn CTAP 2 "none" attestation. No attestation
//!   signature, no `attStmt`. Sufficient because `webauthn-rs`'s
//!   `start_passkey_registration` uses
//!   `AttestationConveyancePreference::None`.
//! - Algorithm: EdDSA only. `register()` panics if the challenge's
//!   `pub_key_cred_params` doesn't include `alg == -8` — the very
//!   contract `vtc_service::webauthn::start_eddsa_passkey_registration`
//!   enforces.
//! - Resident-key / discoverable-credential semantics are out of
//!   scope (start_passkey_registration sets
//!   `require_resident_key = false`).
//!
//! ## Encoding references
//!
//! - <https://www.w3.org/TR/webauthn-3/#attestation-object>
//! - <https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data>
//! - <https://datatracker.ietf.org/doc/html/rfc8152#section-13>
//!   (COSE Key — OKP)

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::{
    Base64UrlSafeData, CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use webauthn_rs_proto::{AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw};

/// Flags byte: User Present.
const FLAG_UP: u8 = 0x01;
/// Flags byte: User Verified.
const FLAG_UV: u8 = 0x04;
/// Flags byte: Attested Credential Data present.
const FLAG_AT: u8 = 0x40;

/// COSE algorithm identifier for EdDSA.
const COSE_ALG_EDDSA: i64 = -8;

/// Pinned AAGUID for the harness — distinctive enough to spot in
/// debug output without colliding with any real authenticator's
/// identifier.
const HARNESS_AAGUID: [u8; 16] = *b"vtc-soft-eddsa\0\0";

/// Soft Ed25519 authenticator. Owns the credentials it mints; pass
/// `&mut self` to `register()` to add a new one, `&mut self` to
/// `authenticate()` to sign + bump the per-credential counter.
pub struct SoftEd25519Authenticator {
    credentials: HashMap<Vec<u8>, CredentialEntry>,
}

struct CredentialEntry {
    signing_key: SigningKey,
    sign_count: u32,
}

impl Default for SoftEd25519Authenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftEd25519Authenticator {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    /// Process a [`CreationChallengeResponse`] and return a fake
    /// [`RegisterPublicKeyCredential`] plus the Ed25519 verifying-key
    /// bytes (32 bytes) of the credential just minted. The
    /// verifying-key bytes are what consumers project into a `did:key`.
    ///
    /// Asserts the challenge advertises EdDSA in
    /// `pubKeyCredParams` — `vtc_service::webauthn::start_eddsa_passkey_registration`
    /// is the only sanctioned producer of these challenges, and it
    /// always restricts to `[{public-key, -8}]`. Other test code that
    /// drives the upstream-default challenge directly will trip this
    /// panic, which is the intended failure mode.
    pub fn register(
        &mut self,
        ccr: &CreationChallengeResponse,
        origin: &str,
    ) -> (RegisterPublicKeyCredential, [u8; 32]) {
        let cred_params = &ccr.public_key.pub_key_cred_params;
        assert!(
            cred_params.iter().any(|p| p.alg == COSE_ALG_EDDSA),
            "soft authenticator only produces EdDSA credentials but challenge advertises {cred_params:?}",
        );

        // Deterministic seed: SHA-256 of the challenge bytes + the
        // RP id. Tests that want distinct credentials for the same
        // challenge can mutate either side; the default gives a
        // stable, reproducible key per ceremony.
        let mut seed_input = Vec::new();
        seed_input.extend_from_slice(ccr.public_key.challenge.as_ref());
        seed_input.extend_from_slice(ccr.public_key.rp.id.as_bytes());
        seed_input.extend_from_slice(b"soft-eddsa-seed/v1");
        let seed: [u8; 32] = Sha256::digest(&seed_input).into();
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key().to_bytes();

        // 16-byte credential ID — short enough to look like a passkey
        // synced credential, deterministic for reproducibility.
        let mut cred_id_input = Vec::new();
        cred_id_input.extend_from_slice(&verifying_key);
        cred_id_input.extend_from_slice(b"cred-id/v1");
        let cred_id = Sha256::digest(&cred_id_input)[..16].to_vec();

        let client_data_json =
            client_data_json("webauthn.create", ccr.public_key.challenge.as_ref(), origin);

        let auth_data = authenticator_data(
            &ccr.public_key.rp.id,
            FLAG_UP | FLAG_UV | FLAG_AT,
            0,
            Some(AttestedCredentialData {
                aaguid: &HARNESS_AAGUID,
                credential_id: &cred_id,
                cose_public_key: &cose_okp_ed25519(&verifying_key),
            }),
        );

        let attestation_object = attestation_object_none(&auth_data);

        self.credentials.insert(
            cred_id.clone(),
            CredentialEntry {
                signing_key,
                sign_count: 0,
            },
        );

        let credential = RegisterPublicKeyCredential {
            id: B64.encode(&cred_id),
            raw_id: Base64UrlSafeData::from(cred_id),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData::from(attestation_object),
                client_data_json: Base64UrlSafeData::from(client_data_json),
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: Default::default(),
        };

        (credential, verifying_key)
    }

    /// Process a [`RequestChallengeResponse`] and produce a signed
    /// [`PublicKeyCredential`] for one of the credentials this
    /// authenticator owns. Increments the credential's `sign_count`
    /// on success.
    ///
    /// Picks the first credential in `allowCredentials` that this
    /// authenticator owns. Panics if none match — a programming bug
    /// in the calling test.
    pub fn authenticate(
        &mut self,
        rcr: &RequestChallengeResponse,
        origin: &str,
    ) -> PublicKeyCredential {
        let cred_id = rcr
            .public_key
            .allow_credentials
            .iter()
            .find_map(|allow| {
                let id_bytes: Vec<u8> = allow.id.as_ref().to_vec();
                if self.credentials.contains_key(&id_bytes) {
                    Some(id_bytes)
                } else {
                    None
                }
            })
            .expect("no credential in allowCredentials is known to this authenticator");

        let entry = self
            .credentials
            .get_mut(&cred_id)
            .expect("cred_id resolved above");
        entry.sign_count = entry.sign_count.wrapping_add(1);
        let sign_count = entry.sign_count;

        let client_data_json =
            client_data_json("webauthn.get", rcr.public_key.challenge.as_ref(), origin);
        let client_data_hash = Sha256::digest(&client_data_json);

        let auth_data =
            authenticator_data(&rcr.public_key.rp_id, FLAG_UP | FLAG_UV, sign_count, None);

        // EdDSA signature is over `authenticatorData || clientDataHash`.
        let mut signed = Vec::with_capacity(auth_data.len() + client_data_hash.len());
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(&client_data_hash);
        let signature = entry.signing_key.sign(&signed).to_bytes();

        PublicKeyCredential {
            id: B64.encode(&cred_id),
            raw_id: Base64UrlSafeData::from(cred_id),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: Base64UrlSafeData::from(auth_data),
                client_data_json: Base64UrlSafeData::from(client_data_json),
                signature: Base64UrlSafeData::from(signature.to_vec()),
                user_handle: None,
            },
            type_: "public-key".to_string(),
            extensions: Default::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

struct AttestedCredentialData<'a> {
    aaguid: &'a [u8; 16],
    credential_id: &'a [u8],
    cose_public_key: &'a [u8],
}

/// Build the WebAuthn `authenticatorData` byte string. Spec ref:
/// <https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data>.
fn authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested: Option<AttestedCredentialData<'_>>,
) -> Vec<u8> {
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());

    let mut out = Vec::with_capacity(37 + 16 + 2 + 16 + 64);
    out.extend_from_slice(&rp_id_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());

    if let Some(data) = attested {
        debug_assert!(
            flags & FLAG_AT != 0,
            "AT flag must be set with attested data"
        );
        out.extend_from_slice(data.aaguid);
        out.extend_from_slice(
            &u16::try_from(data.credential_id.len())
                .expect("credential ID fits in u16")
                .to_be_bytes(),
        );
        out.extend_from_slice(data.credential_id);
        out.extend_from_slice(data.cose_public_key);
    }

    out
}

/// Encode the CTAP attestation object using format `"none"`. Spec ref:
/// <https://www.w3.org/TR/webauthn-3/#sctn-attestation-formats>.
fn attestation_object_none(auth_data: &[u8]) -> Vec<u8> {
    use ciborium::Value;
    let map = Value::Map(vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("none".to_string()),
        ),
        (Value::Text("attStmt".to_string()), Value::Map(vec![])),
        (
            Value::Text("authData".to_string()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&map, &mut out).expect("CBOR encode never fails for owned Value");
    out
}

/// Encode a COSE OKP Ed25519 public key. Spec ref:
/// <https://datatracker.ietf.org/doc/html/rfc8152#section-13.2>.
fn cose_okp_ed25519(public_key: &[u8; 32]) -> Vec<u8> {
    use ciborium::Value;
    // Key parameters (CBOR integer keys):
    //   1 (kty)  = 1 (OKP)
    //   3 (alg)  = -8 (EdDSA)
    //  -1 (crv)  = 6 (Ed25519)
    //  -2 (x)    = <32-byte public key>
    let map = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(1.into())),
        (Value::Integer(3.into()), Value::Integer((-8).into())),
        (Value::Integer((-1).into()), Value::Integer(6.into())),
        (
            Value::Integer((-2).into()),
            Value::Bytes(public_key.to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&map, &mut out).expect("CBOR encode never fails for owned Value");
    out
}

/// Build the WebAuthn `clientDataJSON` byte string. Spec ref:
/// <https://www.w3.org/TR/webauthn-3/#dictionary-client-data>.
fn client_data_json(type_: &str, challenge_bytes: &[u8], origin: &str) -> Vec<u8> {
    let challenge = B64.encode(challenge_bytes);
    serde_json::to_vec(&serde_json::json!({
        "type": type_,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    }))
    .expect("static JSON serialises")
}
