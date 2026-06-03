//! Sealed transfer — unified envelope for moving sensitive bundles between
//! workspace tools.
//!
//! See `sealed-bootstrap.md` at the repo root for the full design. The short
//! version: every secret-bearing artifact (admin credentials, context
//! provisioning bundles, DID secret exports, raw key material) is encrypted
//! end-to-end to a recipient-chosen ephemeral X25519 public key using HPKE
//! (RFC 9180), framed in a PGP/SSH-style ASCII armor with strict integrity
//! checks. Producer authenticity is established via one of three assertion
//! types depending on the trust mode (DID-signed, attestation quote, or
//! pinned-pubkey + out-of-band digest).

pub mod armor;
pub mod bundle;
pub mod chunk;
pub mod error;
pub mod hpke;
pub mod nonce;
pub mod request;
pub mod template_bootstrap;
pub mod verify;

pub use bundle::{
    ArmoredChunk, AssertionProof, AttestationQuoteAssertion, DidSignedAssertion,
    IssuedCredentialBundle, LabeledKey, ProducerAssertion, RawPrivateKey, SealedBundle,
    SealedPayloadV1,
};
pub use chunk::{ChunkPlaintext, MAX_PAYLOAD_FRAGMENT, VERSION};
pub use error::SealedTransferError;
pub use hpke::{HpkeSealed, generate_keypair, open as hpke_open, seal as hpke_seal};
pub use nonce::{InMemoryNonceStore, NonceStore};
pub use request::BootstrapRequest;
pub use template_bootstrap::{
    AdminRotationPayload, DidKeyMaterial, KeyPair, TemplateBootstrapConfig,
    TemplateBootstrapPayload, TemplateOutput, VtaTrustBundle,
};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Generate a fresh Ed25519 keypair for a consumer bootstrap request.
///
/// Returns `(seed, pubkey)`. The seed is the 32-byte Ed25519 private key that
/// the consumer persists (e.g. on disk under `bootstrap-secrets/`) to open the
/// eventual sealed bundle; the pubkey is what goes into
/// [`BootstrapRequest::new`] and is encoded as a `did:key` on the wire.
///
/// At open time the consumer passes the seed to
/// [`ed25519_seed_to_x25519_secret`] and hands the result to [`open_bundle`].
/// Keeping the seed (rather than pre-deriving the X25519 secret) means the
/// same identity can later be used for signing without regenerating.
pub fn generate_ed25519_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS CSPRNG failed — see hpke::OsCsprng docs");
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pubkey = signing.verifying_key().to_bytes();
    (Zeroizing::new(seed), pubkey)
}

/// Derive the X25519 HPKE secret that pairs with an Ed25519 seed. Thin wrapper
/// around [`affinidi_crypto::ed25519::ed25519_private_to_x25519`] that keeps
/// the returned bytes in a [`Zeroizing`] wrapper so the call site doesn't
/// accidentally leave the derived scalar on the stack.
pub fn ed25519_seed_to_x25519_secret(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(affinidi_crypto::ed25519::ed25519_private_to_x25519(seed))
}

/// Default digest algorithm for new bundles.
pub const DEFAULT_DIGEST_ALGO: &str = "sha256";

/// Compute the canonical bundle digest used for out-of-band verification.
///
/// `sha256(sealed_bytes_chunk_0 || sealed_bytes_chunk_1 || ...)`. The chunks
/// are concatenated in chunk-index order; the digest is over the post-HPKE
/// ciphertexts, so any tamper to the armored bytes invalidates it. Returned as
/// lowercase hex.
pub fn bundle_digest(bundle: &SealedBundle) -> String {
    let mut chunks: Vec<&ArmoredChunk> = bundle.chunks.iter().collect();
    chunks.sort_by_key(|c| c.chunk_index);
    let mut hasher = Sha256::new();
    for c in chunks {
        hasher.update(&c.sealed_bytes);
    }
    // sha2 0.11's `finalize()` returns a hybrid-array `Array<u8, _>` which
    // doesn't implement `LowerHex`. Encode the bytes explicitly.
    crate::hex::lower(hasher.finalize().as_slice())
}

/// Seal a [`SealedPayloadV1`] for delivery to `recipient_pubkey`.
///
/// `bundle_id` should be the consumer's request nonce. The producer's
/// [`NonceStore`] is consulted to enforce single-use semantics: re-sealing the
/// same `bundle_id` returns [`SealedTransferError::NonceReplay`].
pub async fn seal_payload(
    recipient_pubkey: &[u8; 32],
    bundle_id: [u8; 16],
    producer: ProducerAssertion,
    payload: &SealedPayloadV1,
    nonce_store: &dyn NonceStore,
) -> Result<SealedBundle, SealedTransferError> {
    nonce_store.check_and_record(&bundle_id).await?;

    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(payload, &mut payload_bytes)
        .map_err(|e| SealedTransferError::CborEncode(e.to_string()))?;

    let total_chunks_usize = payload_bytes.len().div_ceil(MAX_PAYLOAD_FRAGMENT).max(1);
    let total_chunks: u16 = total_chunks_usize
        .try_into()
        .map_err(|_| SealedTransferError::Wire("payload too large for u16 chunk count".into()))?;

    let mut chunks: Vec<ArmoredChunk> = Vec::with_capacity(total_chunks_usize);
    for i in 0..total_chunks_usize {
        let start = i * MAX_PAYLOAD_FRAGMENT;
        let end = (start + MAX_PAYLOAD_FRAGMENT).min(payload_bytes.len());
        let fragment = payload_bytes[start..end].to_vec();
        let chunk_index = i as u16;
        let plaintext = ChunkPlaintext {
            version: VERSION,
            bundle_id,
            chunk_index,
            total_chunks,
            producer_did: if i == 0 {
                Some(producer.producer_did.clone())
            } else {
                None
            },
            producer_assertion: if i == 0 { Some(producer.clone()) } else { None },
            payload_fragment: fragment,
        };
        let aad = plaintext.aad(DEFAULT_DIGEST_ALGO);
        let mut pt_cbor = Vec::new();
        ciborium::ser::into_writer(&plaintext, &mut pt_cbor)
            .map_err(|e| SealedTransferError::CborEncode(e.to_string()))?;
        let sealed = hpke_seal(recipient_pubkey, &pt_cbor, &aad)?;
        let mut sealed_cbor = Vec::new();
        ciborium::ser::into_writer(&sealed, &mut sealed_cbor)
            .map_err(|e| SealedTransferError::CborEncode(e.to_string()))?;
        chunks.push(ArmoredChunk {
            chunk_index,
            total_chunks,
            sealed_bytes: sealed_cbor,
        });
    }

    Ok(SealedBundle {
        bundle_id,
        digest_algo: DEFAULT_DIGEST_ALGO.to_string(),
        chunks,
    })
}

/// The result of opening a sealed bundle: the payload, plus the producer
/// assertion the caller must verify against its trust policy.
#[derive(Debug)]
pub struct OpenedBundle {
    pub payload: SealedPayloadV1,
    pub producer: ProducerAssertion,
    pub bundle_id: [u8; 16],
}

/// Policy for opening a bundle whose producer uses the `PinnedOnly`
/// assertion (no in-band integrity anchor).
///
/// PinnedOnly tells the opener "the bundle itself carries no proof of
/// who produced it — rely on something outside the bundle for that".
/// If that "something outside" is missing, opening the bundle means
/// trusting anyone who happened to know the recipient's X25519 public
/// key. The enum forces the caller to name what the outside trust
/// anchor is.
#[derive(Debug, Clone, Copy)]
pub enum PinnedOnlyPolicy {
    /// Require the caller to supply `expect_digest` to
    /// [`open_bundle_with_policy`]. The OOB digest is the integrity
    /// anchor. This is the safe default and what `open_bundle` uses.
    RequireOobDigest,
    /// The caller has an independent trust anchor — e.g. the bundle
    /// arrived over an authenticated HTTP session, or is consumed
    /// inside a single-process key-import handshake where the peer is
    /// the same authenticated caller. Document the anchor at the call
    /// site. Using this variant without a real anchor is equivalent to
    /// accepting bundles from anyone who knows the recipient pubkey.
    CallerHasIndependentTrustAnchor,
}

/// Open a [`SealedBundle`] with the recipient's secret. Performs:
///
/// 1. Optional canonical-digest verification when `expect_digest` is `Some`.
/// 2. Per-chunk HPKE open with header AAD binding.
/// 3. Chunk header consistency + reassembly.
/// 4. Extraction of the chunk-0 producer assertion.
/// 5. Coupling check: if the producer's assertion is `PinnedOnly`,
///    `expect_digest` **must** have been supplied. PinnedOnly carries
///    no in-band integrity anchor, so the out-of-band digest is the
///    only thing preventing a party with the recipient's X25519 public
///    key from forging a bundle. See
///    [`SealedTransferError::PinnedOnlyRequiresDigest`].
///
/// The caller is then responsible for verifying the producer assertion against
/// its trust policy via
/// [`crate::sealed_transfer::verify::verify_producer_assertion_with_pubkey`].
///
/// For flows where the trust anchor is elsewhere (HTTP session auth on
/// a key-import endpoint, in-process handoff, etc.), use
/// [`open_bundle_with_policy`] with
/// [`PinnedOnlyPolicy::CallerHasIndependentTrustAnchor`].
pub fn open_bundle(
    recipient_secret: &[u8; 32],
    bundle: &SealedBundle,
    expect_digest: Option<&str>,
) -> Result<OpenedBundle, SealedTransferError> {
    open_bundle_with_policy(
        recipient_secret,
        bundle,
        expect_digest,
        PinnedOnlyPolicy::RequireOobDigest,
    )
}

/// Variant of [`open_bundle`] that accepts an explicit policy for
/// PinnedOnly producer assertions. Prefer `open_bundle` unless the
/// trust anchor is explicitly elsewhere.
pub fn open_bundle_with_policy(
    recipient_secret: &[u8; 32],
    bundle: &SealedBundle,
    expect_digest: Option<&str>,
    pinned_policy: PinnedOnlyPolicy,
) -> Result<OpenedBundle, SealedTransferError> {
    if let Some(expected) = expect_digest {
        let got = bundle_digest(bundle);
        if !constant_time_eq(expected.as_bytes(), got.as_bytes()) {
            return Err(SealedTransferError::DigestMismatch {
                expected: expected.to_string(),
                got,
            });
        }
    }

    let mut plaintexts: Vec<ChunkPlaintext> = Vec::with_capacity(bundle.chunks.len());
    for chunk in &bundle.chunks {
        let sealed: HpkeSealed = ciborium::de::from_reader(&chunk.sealed_bytes[..])
            .map_err(|e| SealedTransferError::CborDecode(e.to_string()))?;
        // Build the AAD from the *armor-declared* chunk header. If the AEAD
        // open succeeds, the inner header matches the outer (the inner header
        // was the AAD at seal time).
        let header_for_aad = ChunkPlaintext {
            version: VERSION,
            bundle_id: bundle.bundle_id,
            chunk_index: chunk.chunk_index,
            total_chunks: chunk.total_chunks,
            producer_did: None,
            producer_assertion: None,
            payload_fragment: Vec::new(),
        };
        let aad = header_for_aad.aad(&bundle.digest_algo);
        let pt_bytes = hpke_open(recipient_secret, &sealed, &aad)?;
        let pt: ChunkPlaintext = ciborium::de::from_reader(&pt_bytes[..])
            .map_err(|e| SealedTransferError::CborDecode(e.to_string()))?;
        if pt.bundle_id != bundle.bundle_id
            || pt.chunk_index != chunk.chunk_index
            || pt.total_chunks != chunk.total_chunks
        {
            return Err(SealedTransferError::ChunkMismatch(
                "inner header != armor header".into(),
            ));
        }
        plaintexts.push(pt);
    }

    // Extract chunk-0 assertion before consuming the vec for reassembly.
    let chunk0 = plaintexts
        .iter()
        .find(|p| p.chunk_index == 0)
        .ok_or(SealedTransferError::MissingAssertion)?;
    let producer = chunk0
        .producer_assertion
        .clone()
        .ok_or(SealedTransferError::MissingAssertion)?;
    let declared_did = chunk0
        .producer_did
        .clone()
        .ok_or(SealedTransferError::MissingAssertion)?;
    if declared_did != producer.producer_did {
        return Err(SealedTransferError::ProducerMismatch {
            declared: declared_did,
            expected: producer.producer_did.clone(),
        });
    }

    let payload_bytes = chunk::reassemble(plaintexts)?;
    let payload: SealedPayloadV1 = ciborium::de::from_reader(&payload_bytes[..])
        .map_err(|e| SealedTransferError::CborDecode(e.to_string()))?;

    // PinnedOnly + no OOB digest = no integrity anchor unless the
    // caller has named an out-of-band trust anchor (e.g. HTTP session
    // auth). DidSigned verifies via crypto in the caller; Attested via
    // nitro quote verification.
    if matches!(producer.proof, AssertionProof::PinnedOnly)
        && expect_digest.is_none()
        && matches!(pinned_policy, PinnedOnlyPolicy::RequireOobDigest)
    {
        return Err(SealedTransferError::PinnedOnlyRequiresDigest);
    }

    Ok(OpenedBundle {
        payload,
        producer,
        bundle_id: bundle.bundle_id,
    })
}

/// Constant-time byte-slice equality. Returns `false` for different-length
/// inputs without short-circuiting on content.
///
/// Exported so other crates can use a single, audited implementation for
/// secret-dependent comparisons (challenge matching, DID equality on
/// authenticate, etc.). Do not use `==` for anything derived from a
/// challenge, token, or other secret-adjacent material.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::CredentialBundle;

    fn sample_payload() -> SealedPayloadV1 {
        SealedPayloadV1::AdminCredential(Box::new(CredentialBundle::new(
            "did:key:z6Mk123",
            "z1234567890",
            "did:key:z6MkVTA",
        )))
    }

    fn sample_assertion(producer_did: String) -> ProducerAssertion {
        ProducerAssertion {
            producer_did,
            proof: AssertionProof::PinnedOnly,
        }
    }

    #[tokio::test]
    async fn round_trip_single_chunk() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_ed25519_keypair();
        let assertion =
            sample_assertion(affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_pk));
        let store = InMemoryNonceStore::new();
        let bundle_id = [7u8; 16];

        let bundle = seal_payload(&recip_pk, bundle_id, assertion, &sample_payload(), &store)
            .await
            .unwrap();

        assert_eq!(bundle.chunks.len(), 1);

        // PinnedOnly assertion requires an OOB digest — the bundle has
        // no in-band integrity anchor otherwise.
        let digest = bundle_digest(&bundle);
        let opened = open_bundle(&recip_sk, &bundle, Some(&digest)).unwrap();
        assert_eq!(opened.bundle_id, bundle_id);
        match opened.payload {
            SealedPayloadV1::AdminCredential(c) => assert_eq!(c.did, "did:key:z6Mk123"),
            _ => panic!("wrong payload variant"),
        }
    }

    #[tokio::test]
    async fn round_trip_multi_chunk() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_ed25519_keypair();
        let assertion =
            sample_assertion(affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_pk));
        let store = InMemoryNonceStore::new();
        let bundle_id = [9u8; 16];

        // Force multi-chunk by stuffing a large LabeledKey set.
        let big_keys: Vec<LabeledKey> = (0..2048)
            .map(|i| LabeledKey {
                label: format!("k-{i}"),
                key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                key_type: Some("ed25519".to_string()),
            })
            .collect();
        let payload = SealedPayloadV1::AdminKeySet(big_keys);

        let bundle = seal_payload(&recip_pk, bundle_id, assertion, &payload, &store)
            .await
            .unwrap();
        assert!(bundle.chunks.len() > 1, "expected multi-chunk bundle");

        let digest = bundle_digest(&bundle);
        let opened = open_bundle(&recip_sk, &bundle, Some(&digest)).unwrap();
        match opened.payload {
            SealedPayloadV1::AdminKeySet(keys) => assert_eq!(keys.len(), 2048),
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn replay_rejected_by_nonce_store() {
        let (_recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_ed25519_keypair();
        let assertion =
            sample_assertion(affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_pk));
        let store = InMemoryNonceStore::new();
        let bundle_id = [1u8; 16];

        seal_payload(
            &recip_pk,
            bundle_id,
            assertion.clone(),
            &sample_payload(),
            &store,
        )
        .await
        .unwrap();
        let err = seal_payload(&recip_pk, bundle_id, assertion, &sample_payload(), &store)
            .await
            .unwrap_err();
        assert!(matches!(err, SealedTransferError::NonceReplay));
    }

    #[tokio::test]
    async fn digest_mismatch_rejected() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_ed25519_keypair();
        let assertion =
            sample_assertion(affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_pk));
        let store = InMemoryNonceStore::new();

        let bundle = seal_payload(&recip_pk, [2u8; 16], assertion, &sample_payload(), &store)
            .await
            .unwrap();
        let err = open_bundle(&recip_sk, &bundle, Some("deadbeef")).unwrap_err();
        assert!(matches!(err, SealedTransferError::DigestMismatch { .. }));
    }

    #[tokio::test]
    async fn digest_match_accepted() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_ed25519_keypair();
        let assertion =
            sample_assertion(affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_pk));
        let store = InMemoryNonceStore::new();

        let bundle = seal_payload(&recip_pk, [3u8; 16], assertion, &sample_payload(), &store)
            .await
            .unwrap();
        let digest = bundle_digest(&bundle);
        open_bundle(&recip_sk, &bundle, Some(&digest)).unwrap();
    }

    #[tokio::test]
    async fn armor_round_trip() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_ed25519_keypair();
        let assertion =
            sample_assertion(affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_pk));
        let store = InMemoryNonceStore::new();

        let bundle = seal_payload(&recip_pk, [4u8; 16], assertion, &sample_payload(), &store)
            .await
            .unwrap();
        let armored = armor::encode(&bundle);
        assert!(armored.contains("BEGIN VTA SEALED BUNDLE"));
        let parsed = armor::decode(&armored).unwrap();
        assert_eq!(parsed.len(), 1);
        let digest = bundle_digest(&parsed[0]);
        let opened = open_bundle(&recip_sk, &parsed[0], Some(&digest)).unwrap();
        match opened.payload {
            SealedPayloadV1::AdminCredential(c) => assert_eq!(c.did, "did:key:z6Mk123"),
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn pinned_only_without_digest_rejected() {
        // The S-10 coupling: a bundle that uses PinnedOnly has no
        // in-band integrity anchor, so opening without supplying an
        // OOB digest must fail closed rather than silently succeed.
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_ed25519_keypair();
        let assertion =
            sample_assertion(affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_pk));
        let store = InMemoryNonceStore::new();

        let bundle = seal_payload(&recip_pk, [11u8; 16], assertion, &sample_payload(), &store)
            .await
            .unwrap();

        let err = open_bundle(&recip_sk, &bundle, None)
            .expect_err("PinnedOnly without OOB digest must be rejected");
        assert!(
            matches!(err, SealedTransferError::PinnedOnlyRequiresDigest),
            "expected PinnedOnlyRequiresDigest, got {err:?}"
        );
    }

    #[tokio::test]
    async fn armor_corruption_caught_by_crc24() {
        let (_recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_ed25519_keypair();
        let assertion =
            sample_assertion(affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_pk));
        let store = InMemoryNonceStore::new();

        let bundle = seal_payload(&recip_pk, [5u8; 16], assertion, &sample_payload(), &store)
            .await
            .unwrap();
        let mut armored = armor::encode(&bundle);
        // Flip one base64 character somewhere in the middle of the body.
        let body_offset = armored.find("\n\n").unwrap() + 2;
        let bytes = unsafe { armored.as_bytes_mut() };
        bytes[body_offset] = if bytes[body_offset] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let err = armor::decode(&armored).unwrap_err();
        assert!(
            matches!(err, SealedTransferError::Crc24Mismatch { .. }),
            "expected Crc24Mismatch, got {err:?}"
        );
    }

    #[tokio::test]
    async fn aad_tamper_caught_by_aead() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_ed25519_keypair();
        let assertion =
            sample_assertion(affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_pk));
        let store = InMemoryNonceStore::new();

        let bundle = seal_payload(&recip_pk, [6u8; 16], assertion, &sample_payload(), &store)
            .await
            .unwrap();
        // Tamper: rewrite the bundle.bundle_id without re-sealing. The inner
        // chunk's AAD will use the new bundle_id, which will not match the AAD
        // used at seal time.
        let mut tampered = bundle.clone();
        tampered.bundle_id = [0xff; 16];
        let err = open_bundle(&recip_sk, &tampered, None).unwrap_err();
        assert!(matches!(err, SealedTransferError::Hpke(_)));
    }

    /// Helper: round-trip a SealedBundle through armor → mutate text →
    /// decode → open. Returns the open error.
    async fn roundtrip_with_armor_mutation(
        mutate: impl FnOnce(&mut String),
    ) -> SealedTransferError {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_ed25519_keypair();
        let assertion =
            sample_assertion(affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_pk));
        let store = InMemoryNonceStore::new();

        let bundle = seal_payload(&recip_pk, [7u8; 16], assertion, &sample_payload(), &store)
            .await
            .expect("seal");

        let mut armored = armor::encode(&bundle);
        mutate(&mut armored);

        // Some mutations cause armor::decode to fail (e.g. Bundle-Id hex
        // invalidation); others land at AEAD-open. Either is acceptable —
        // the test asserts the open path NEVER returns an OpenedBundle for
        // mutated armor.
        match armor::decode(&armored) {
            Ok(bundles) => {
                let merged = bundles.into_iter().next().expect("at least one bundle");
                open_bundle(&recip_sk, &merged, None).expect_err("open must fail")
            }
            Err(e) => e,
        }
    }

    #[tokio::test]
    async fn armor_bundle_id_tamper_caught() {
        // Flip a hex char in the Bundle-Id header. Either the parser
        // rejects (still valid hex but different bytes) or AEAD fails on
        // open because AAD is built from the (tampered) armor header.
        let err = roundtrip_with_armor_mutation(|s| {
            let line = s.find("Bundle-Id: ").expect("Bundle-Id present");
            let hex_start = line + "Bundle-Id: ".len();
            let bytes = unsafe { s.as_bytes_mut() };
            // Flip one hex nibble. Valid hex → parser accepts → AEAD rejects.
            bytes[hex_start] = if bytes[hex_start] == b'0' { b'1' } else { b'0' };
        })
        .await;
        // Could be Hpke (AEAD AAD mismatch) or Armor (less likely path).
        // Both are acceptable — the test asserts open does not succeed.
        assert!(matches!(
            err,
            SealedTransferError::Hpke(_) | SealedTransferError::Armor(_)
        ));
    }

    #[tokio::test]
    async fn armor_chunk_count_tamper_caught() {
        // Mutate the Chunk header's total to claim more chunks than were
        // produced. Triggers either an "out of range" armor error (1/2 with
        // only one block) or chunk-mismatch on reassembly.
        let err = roundtrip_with_armor_mutation(|s| {
            let line = s.find("Chunk: 1/1").expect("Chunk: 1/1 present");
            let bytes = unsafe { s.as_bytes_mut() };
            // Rewrite "Chunk: 1/1" → "Chunk: 1/9" (claim 9 total chunks
            // when only 1 was sealed). AAD includes total_chunks → AEAD
            // open fails on the AAD mismatch.
            bytes[line + "Chunk: 1/".len()] = b'9';
        })
        .await;
        assert!(
            matches!(
                err,
                SealedTransferError::Hpke(_)
                    | SealedTransferError::ChunkMismatch(_)
                    | SealedTransferError::MissingChunks { .. }
                    | SealedTransferError::Armor(_)
            ),
            "expected Hpke / ChunkMismatch / MissingChunks / Armor, got {err:?}"
        );
    }

    #[tokio::test]
    async fn armor_digest_algo_tamper_caught() {
        // Swap "Digest-Algo: sha256" for a different (but plausible) algo.
        // AAD includes digest_algo → AEAD open fails on AAD mismatch.
        let err = roundtrip_with_armor_mutation(|s| {
            *s = s.replace("Digest-Algo: sha256", "Digest-Algo: sha512");
        })
        .await;
        assert!(matches!(err, SealedTransferError::Hpke(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn armor_unknown_header_rejected() {
        // Forward-compat hazard: prior to this guard, unknown headers were
        // silently dropped by the parser. A future header that participates
        // in AAD would be ignored on older parsers; an attacker could also
        // inject a header today with no covering AEAD. Reject at parse.
        let err = roundtrip_with_armor_mutation(|s| {
            // Insert a bogus header right after Version.
            *s = s.replace("Version: 1\n", "Version: 1\nX-Trust-Me: yes\n");
        })
        .await;
        match err {
            SealedTransferError::Armor(msg) => {
                assert!(
                    msg.contains("X-Trust-Me") || msg.contains("unknown header"),
                    "got {msg}"
                );
            }
            other => panic!("expected Armor(unknown header), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_chunk_rejected() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_ed25519_keypair();
        let assertion =
            sample_assertion(affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_pk));
        let store = InMemoryNonceStore::new();
        let big_keys: Vec<LabeledKey> = (0..2048)
            .map(|i| LabeledKey {
                label: format!("k-{i}"),
                key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                key_type: None,
            })
            .collect();
        let payload = SealedPayloadV1::AdminKeySet(big_keys);
        let mut bundle = seal_payload(&recip_pk, [10u8; 16], assertion, &payload, &store)
            .await
            .unwrap();
        assert!(bundle.chunks.len() > 1);
        // Drop the last chunk.
        bundle.chunks.pop();
        let err = open_bundle(&recip_sk, &bundle, None).unwrap_err();
        assert!(
            matches!(err, SealedTransferError::MissingChunks { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn bootstrap_request_round_trip() {
        let (_seed, ed_pub) = generate_ed25519_keypair();
        let req = BootstrapRequest::new(ed_pub, [42u8; 16], Some("test".into()));
        // Wire field is a did:key string, not a raw pubkey.
        assert!(req.client_did.starts_with("did:key:z6Mk"));
        let json = serde_json::to_string(&req).unwrap();
        let back: BootstrapRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decode_client_ed25519_pub().unwrap(), ed_pub);
        assert_eq!(back.decode_nonce().unwrap(), [42u8; 16]);
    }

    #[test]
    fn bootstrap_request_derives_x25519_pub_from_did_key() {
        // The producer only ever sees the did:key; it must derive the same
        // X25519 pubkey that would pair with the consumer-side X25519 secret
        // derived from the same Ed25519 seed.
        let (seed, ed_pub) = generate_ed25519_keypair();
        let req = BootstrapRequest::new(ed_pub, [1u8; 16], None);

        let producer_x25519 = req.decode_client_x25519_pub().unwrap();
        let consumer_x25519 = ed25519_seed_to_x25519_secret(&seed);

        // Round-trip through HPKE's own primitives to confirm the pair agrees.
        let sealed = hpke_seal(&producer_x25519, b"payload", b"aad").unwrap();
        let opened = hpke_open(&consumer_x25519, &sealed, b"aad").unwrap();
        assert_eq!(&opened, b"payload");
    }

    #[test]
    fn bootstrap_request_rejects_unknown_fields() {
        let json = r#"{
            "version": 1,
            "client_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "nonce": "AA",
            "requested_role": "Admin"
        }"#;
        assert!(serde_json::from_str::<BootstrapRequest>(json).is_err());
    }
}
