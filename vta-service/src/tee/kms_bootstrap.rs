//! KMS-based secret bootstrap for Nitro Enclaves.
//!
//! On first boot (no existing ciphertext), generates a BIP-39 seed and JWT
//! signing key inside the TEE, encrypts them with KMS, writes the ciphertext
//! to external storage, and stores a JWT key fingerprint for tamper detection.
//!
//! On subsequent boots, decrypts the ciphertext using KMS, verifies the JWT
//! key fingerprint, and returns the secrets for use.
//!
//! # Attestation
//!
//! Both encrypt and decrypt paths use Nitro attestation when `/dev/nsm` is
//! available (real Nitro hardware):
//!
//! - **Encrypt** uses `GenerateDataKey` with a `Recipient` parameter. KMS
//!   generates a random data key and returns it encrypted to an ephemeral RSA
//!   key bound to the enclave's attestation document (CMS envelope). The
//!   enclave unwraps the data key locally and uses it to AES-GCM encrypt the
//!   secret. The stored blob contains the KMS-encrypted data key + AES-GCM
//!   ciphertext ("sealed blob" format).
//!
//! - **Decrypt** uses `Decrypt` with a `Recipient` parameter. KMS re-encrypts
//!   the plaintext to an ephemeral RSA key bound to the attestation document.
//!
//! This ensures the KMS key policy's PCR conditions (PCR0 image hash, PCR8
//! signing cert hash) are enforced on **both** encrypt and decrypt, preventing
//! an attacker with IAM role access from encrypting rogue data that could
//! overwrite legitimate ciphertexts in storage.
//!
//! When NSM is not available (simulated mode or development), both paths fall
//! back to direct KMS calls without attestation.

use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;

use crate::config::TeeKmsConfig;
use crate::error::{AppError, tee_attestation_error};

/// Secrets bootstrapped from KMS, held only in TEE memory.
///
/// All secret fields are zeroed on drop via the `Drop` implementation.
pub struct BootstrappedSecrets {
    /// BIP-39 seed (32 bytes).
    pub seed: Vec<u8>,
    /// JWT signing key (32 bytes).
    pub jwt_signing_key: [u8; 32],
    /// AES-256 storage encryption key (32 bytes), derived from seed via HKDF.
    pub storage_key: [u8; 32],
    /// BIP-39 entropy bytes (only on first boot — `None` on subsequent boots).
    pub entropy: Option<[u8; 32]>,
    /// Whether this is a first boot (new secrets generated).
    pub is_first_boot: bool,
}

impl Drop for BootstrappedSecrets {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.jwt_signing_key.zeroize();
        self.storage_key.zeroize();
        if let Some(ref mut e) = self.entropy {
            e.zeroize();
        }
    }
}

/// Well-known keys in the bootstrap keyspace.
///
/// The data key is generated via KMS `GenerateDataKey` (with attestation when
/// available). Both secrets are AES-GCM encrypted with the same data key but
/// unique nonces. The nonce is prepended to each ciphertext entry.
const BOOTSTRAP_DK_CT_KEY: &str = "bootstrap:data_key_ciphertext";
const BOOTSTRAP_SEED_CT_KEY: &str = "bootstrap:seed_ciphertext";
const BOOTSTRAP_JWT_CT_KEY: &str = "bootstrap:jwt_ciphertext";
const BOOTSTRAP_JWT_FINGERPRINT_KEY: &str = "bootstrap:jwt_fingerprint";

/// Bootstrap secrets from KMS.
///
/// - If ciphertext files exist: decrypt via KMS, verify JWT fingerprint (subsequent boot)
/// - If no ciphertext files: generate new secrets, encrypt with KMS, store (first boot)
pub async fn bootstrap_secrets(
    kms_config: &TeeKmsConfig,
    storage_key_salt: &str,
    store: &crate::store::Store,
) -> Result<BootstrappedSecrets, AppError> {
    // Bootstrap keyspace — no encryption (data is KMS-protected)
    let bs_ks = store.keyspace("bootstrap")?;

    let dk_ct = bs_ks.get_raw(BOOTSTRAP_DK_CT_KEY).await?;
    let seed_ct = bs_ks.get_raw(BOOTSTRAP_SEED_CT_KEY).await?;
    let jwt_ct = bs_ks.get_raw(BOOTSTRAP_JWT_CT_KEY).await?;

    if let (Some(dk_ciphertext), Some(seed_ciphertext), Some(jwt_ciphertext)) =
        (dk_ct, seed_ct, jwt_ct)
    {
        // ── Subsequent boot: decrypt existing ciphertexts ──
        info!("found existing secret ciphertexts in store — decrypting via KMS");

        match kms_decrypt_data_key(kms_config, &dk_ciphertext).await {
            Ok(data_key) => {
                let seed = aes_gcm_decrypt(&data_key, &seed_ciphertext)?;
                let jwt_bytes = aes_gcm_decrypt(&data_key, &jwt_ciphertext)?;
                let jwt_key: [u8; 32] = jwt_bytes
                    .try_into()
                    .map_err(|_| tee_attestation_error("JWT key must be exactly 32 bytes"))?;

                verify_jwt_fingerprint(&bs_ks, &jwt_key, kms_config.allow_fingerprint_init).await?;
                info!("secrets decrypted from KMS — subsequent boot");

                let storage_key = derive_storage_key(&seed, storage_key_salt);
                return Ok(BootstrappedSecrets {
                    seed,
                    jwt_signing_key: jwt_key,
                    storage_key,
                    entropy: None,
                    is_first_boot: false,
                });
            }
            Err((class, e)) => {
                // Auto-clearing the bootstrap keyspace silently re-issues the
                // VTA's identity. Only ACCESS_DENIED is a legitimate signal
                // for "expected after an image rebuild with a new PCR0" —
                // every other class (KMS_INTERNAL, NETWORK, INVALID_CIPHERTEXT,
                // UNKNOWN) could be a transient outage or active tampering,
                // and silently nuking the identity would be the wrong move.
                // Operators who deliberately want to reset must set
                // `tee.kms.allow_kms_reinit = true` in config.
                let auto_clear =
                    matches!(class, KmsErrorClass::AccessDenied) || kms_config.allow_kms_reinit;
                if !auto_clear {
                    error!(
                        error = %e,
                        class = ?class,
                        "KMS decrypt of existing ciphertexts failed with a non-ACCESS_DENIED \
                         class. Refusing to auto-clear the bootstrap keyspace because doing \
                         so would silently reset the VTA's identity. Diagnose the cause \
                         (KMS health, vsock proxy reachability, ciphertext integrity) and, \
                         if you are certain the existing identity is unrecoverable, set \
                         tee.kms.allow_kms_reinit = true for a one-time reset."
                    );
                    return Err(e);
                }
                warn!(
                    error = %e,
                    class = ?class,
                    "KMS decrypt of existing ciphertexts failed — clearing stale \
                     bootstrap data and starting fresh. ACCESS_DENIED is expected after \
                     an image rebuild with a new PCR0; other classes were authorized \
                     by allow_kms_reinit. The VTA will generate a new identity."
                );
                bs_ks.remove(BOOTSTRAP_DK_CT_KEY).await?;
                bs_ks.remove(BOOTSTRAP_SEED_CT_KEY).await?;
                bs_ks.remove(BOOTSTRAP_JWT_CT_KEY).await?;
                bs_ks.remove(BOOTSTRAP_JWT_FINGERPRINT_KEY).await?;
                store.persist().await?;
                // Fall through to first boot path below
            }
        }
    }

    // ── First boot: generate new secrets inside the TEE ──
    info!("first boot — generating new secrets in TEE");

    let mut entropy = [0u8; 32];
    rand::fill(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .map_err(|e| tee_attestation_error(format!("failed to generate mnemonic: {e}")))?;

    info!("master seed generated inside TEE (mnemonic NOT displayed)");
    info!("to export the mnemonic, restart with VTA_MNEMONIC_EXPORT_WINDOW=<seconds>");

    let full_seed = mnemonic.to_seed("").to_vec();
    let seed = full_seed[..32].to_vec();

    let mut jwt_key_bytes = [0u8; 32];
    rand::fill(&mut jwt_key_bytes);
    let jwt_key = jwt_key_bytes;

    // Generate a data key via KMS, encrypt both secrets with it
    let (dk_ciphertext, data_key) = kms_generate_data_key(kms_config).await?;
    let seed_ciphertext = aes_gcm_encrypt(&data_key, &seed)?;
    let jwt_ciphertext = aes_gcm_encrypt(&data_key, &jwt_key)?;

    bs_ks.insert_raw(BOOTSTRAP_DK_CT_KEY, dk_ciphertext).await?;
    bs_ks
        .insert_raw(BOOTSTRAP_SEED_CT_KEY, seed_ciphertext)
        .await?;
    bs_ks
        .insert_raw(BOOTSTRAP_JWT_CT_KEY, jwt_ciphertext)
        .await?;
    store_jwt_fingerprint(&bs_ks, &jwt_key).await?;

    // Flush to ensure ciphertexts survive if the enclave crashes during startup
    store.persist().await?;

    info!("secrets generated and encrypted to KMS — ciphertexts stored");

    Ok(BootstrappedSecrets {
        storage_key: derive_storage_key(&seed, storage_key_salt),
        seed,
        jwt_signing_key: jwt_key,
        entropy: Some(entropy),
        is_first_boot: true,
    })
}

// ---------------------------------------------------------------------------
// Re-encrypt secrets for backup import
// ---------------------------------------------------------------------------

/// Re-encrypt an imported seed and JWT key with KMS.
///
/// Called during backup import in TEE mode. Generates a new KMS data key,
/// AES-GCM encrypts both secrets, and stores the ciphertexts in the bootstrap
/// keyspace. On next restart, `bootstrap_secrets()` finds existing ciphertexts
/// and takes the normal "subsequent boot" decrypt path.
pub async fn re_encrypt_bootstrap_secrets(
    kms_config: &TeeKmsConfig,
    store: &crate::store::Store,
    seed: &[u8],
    jwt_key: &[u8; 32],
) -> Result<(), AppError> {
    let bs_ks = store.keyspace("bootstrap")?;

    // Clear any existing ciphertexts first
    let _ = bs_ks.remove(BOOTSTRAP_DK_CT_KEY).await;
    let _ = bs_ks.remove(BOOTSTRAP_SEED_CT_KEY).await;
    let _ = bs_ks.remove(BOOTSTRAP_JWT_CT_KEY).await;
    let _ = bs_ks.remove(BOOTSTRAP_JWT_FINGERPRINT_KEY).await;

    // Generate a new data key via KMS (with attestation if on real Nitro)
    let (dk_ciphertext, data_key) = kms_generate_data_key(kms_config).await?;

    // AES-GCM encrypt both secrets with the data key
    let seed_ciphertext = aes_gcm_encrypt(&data_key, seed)?;
    let jwt_ciphertext = aes_gcm_encrypt(&data_key, jwt_key)?;

    // Store everything in the bootstrap keyspace
    bs_ks.insert_raw(BOOTSTRAP_DK_CT_KEY, dk_ciphertext).await?;
    bs_ks
        .insert_raw(BOOTSTRAP_SEED_CT_KEY, seed_ciphertext)
        .await?;
    bs_ks
        .insert_raw(BOOTSTRAP_JWT_CT_KEY, jwt_ciphertext)
        .await?;
    store_jwt_fingerprint(&bs_ks, jwt_key).await?;

    // Flush immediately so ciphertexts survive if enclave restarts
    store.persist().await?;

    info!("imported secrets re-encrypted to KMS — stored in bootstrap keyspace");
    Ok(())
}

// ---------------------------------------------------------------------------
// JWT key fingerprint (tamper detection)
// ---------------------------------------------------------------------------

/// Compute a SHA-256 fingerprint of the JWT signing key.
fn jwt_fingerprint(key: &[u8; 32]) -> String {
    let hash = Sha256::digest(key);
    hex::encode(&hash[..16]) // First 16 bytes = 32 hex chars
}

// ---------------------------------------------------------------------------
// JWT key fingerprint (tamper detection)
// ---------------------------------------------------------------------------

/// Store the JWT key fingerprint in the bootstrap keyspace.
async fn store_jwt_fingerprint(
    bs_ks: &crate::store::KeyspaceHandle,
    key: &[u8; 32],
) -> Result<(), AppError> {
    let fingerprint = jwt_fingerprint(key);
    bs_ks
        .insert_raw(
            BOOTSTRAP_JWT_FINGERPRINT_KEY,
            fingerprint.as_bytes().to_vec(),
        )
        .await?;
    debug!(fingerprint = %fingerprint, "JWT key fingerprint stored");
    Ok(())
}

/// Verify the JWT key matches the stored fingerprint.
///
/// A missing fingerprint is treated the same as a mismatch by default —
/// silently re-baselining on a missing record would let an attacker with
/// write access to the bootstrap keyspace delete the fingerprint and
/// substitute a rogue key that passes verification on the next restart.
///
/// Operators upgrading from a pre-fingerprint VTA version can opt into a
/// one-time init by setting `tee.kms.allow_fingerprint_init = true` in
/// config; they should disable it again after the first successful boot.
async fn verify_jwt_fingerprint(
    bs_ks: &crate::store::KeyspaceHandle,
    key: &[u8; 32],
    allow_init: bool,
) -> Result<(), AppError> {
    let stored_bytes = match bs_ks.get_raw(BOOTSTRAP_JWT_FINGERPRINT_KEY).await? {
        Some(bytes) => bytes,
        None if allow_init => {
            warn!(
                "no JWT fingerprint found and allow_fingerprint_init=true — storing one \
                 now. Disable allow_fingerprint_init after this boot."
            );
            return store_jwt_fingerprint(bs_ks, key).await;
        }
        None => {
            error!(
                "no JWT fingerprint found — refusing to silently initialize. If this is \
                 a first boot after upgrading from a pre-fingerprint VTA, set \
                 tee.kms.allow_fingerprint_init = true, boot once, then disable."
            );
            return Err(tee_attestation_error(
                "JWT key fingerprint missing — refusing to auto-initialize. Either (a) \
                 set tee.kms.allow_fingerprint_init = true for a one-time migration, or \
                 (b) clear the bootstrap keyspace to start fresh if this is disaster \
                 recovery. A missing fingerprint on a running VTA is suspicious.",
            ));
        }
    };

    let stored = String::from_utf8_lossy(&stored_bytes);
    let computed = jwt_fingerprint(key);

    if stored.trim() != computed {
        error!(
            stored = %stored.trim(),
            computed = %computed,
            "JWT key fingerprint MISMATCH — possible key tampering or KMS key rotation"
        );
        return Err(tee_attestation_error(
            "JWT key fingerprint mismatch — the decrypted JWT key does not match the key \
             used on first boot. This could indicate tampering with the ciphertext \
             or a KMS key change. If this is intentional (e.g., disaster recovery), \
             clear the bootstrap keyspace and restart.",
        ));
    }

    debug!(fingerprint = %computed, "JWT key fingerprint verified");
    Ok(())
}

// ---------------------------------------------------------------------------
// Storage key derivation
// ---------------------------------------------------------------------------

/// Derive the AES-256 storage encryption key from the master seed using HKDF.
///
/// Uses HMAC-SHA256 as the PRF. The salt and info strings ensure domain separation.
/// Deterministic: same seed + salt → same key (survives enclave restarts).
pub(crate) fn derive_storage_key(seed: &[u8], salt: &str) -> [u8; 32] {
    // hmac 0.13 moved `new_from_slice` behind the `KeyInit` trait.
    use hmac::{Hmac, KeyInit, Mac};
    type HmacSha256 = Hmac<Sha256>;

    // HKDF-Extract: PRK = HMAC-SHA256(salt, seed)
    let mut mac = HmacSha256::new_from_slice(salt.as_bytes()).expect("HMAC accepts any key length");
    mac.update(seed);
    let prk = mac.finalize().into_bytes();

    // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
    let info = b"aes-256-gcm-storage";
    let mut mac = HmacSha256::new_from_slice(&prk).expect("HMAC accepts any key length");
    mac.update(info);
    mac.update(&[0x01]);
    let okm = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    key
}

// ---------------------------------------------------------------------------
// KMS helpers
// ---------------------------------------------------------------------------

/// Create a KMS client for the configured region.
async fn kms_client(config: &TeeKmsConfig) -> aws_sdk_kms::Client {
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(config.region.clone()))
        .load()
        .await;
    aws_sdk_kms::Client::new(&sdk_config)
}

/// Generate an ephemeral RSA-2048 keypair and obtain an NSM attestation
/// document binding the public key. Returns `(pkcs8_der, recipient_info)`
/// for use with KMS attested operations.
///
/// The private key is returned as PKCS#8 DER bytes rather than the
/// `PrivateDecryptingKey` object directly because that object is `!Send`
/// (wraps a raw BoringSSL `EVP_PKEY` pointer) and would poison the Send
/// bound on any async future that holds it across a KMS `.await`. DER
/// bytes are `Vec<u8>` — trivially Send — and the caller deserializes
/// right before the synchronous OAEP decrypt step.
fn nsm_attested_recipient() -> Result<(Vec<u8>, aws_sdk_kms::types::RecipientInfo), AppError> {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};

    let private_key = PrivateDecryptingKey::generate(KeySize::Rsa2048)
        .map_err(|e| tee_attestation_error(format!("RSA key generation failed: {e}")))?;

    // KMS requires the pubkey as X.509 SubjectPublicKeyInfo DER.
    let public_key_der = private_key
        .public_key()
        .as_der()
        .map_err(|e| tee_attestation_error(format!("RSA public key DER encoding failed: {e}")))?;

    // Private key as PKCS#8 for round-tripping across await boundaries.
    let pkcs8_der = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&private_key)
        .map_err(|e| tee_attestation_error(format!("RSA private key PKCS#8 encoding failed: {e}")))?
        .as_ref()
        .to_vec();

    let attestation_doc = super::nitro::request_nsm_attestation_for_kms(public_key_der.as_ref())?;

    let recipient = aws_sdk_kms::types::RecipientInfo::builder()
        .attestation_document(aws_sdk_kms::primitives::Blob::new(attestation_doc))
        .key_encryption_algorithm(aws_sdk_kms::types::KeyEncryptionMechanism::RsaesOaepSha256)
        .build();

    Ok((pkcs8_der, recipient))
}

/// Extract the plaintext from an attested KMS response's CMS envelope.
///
/// When a `Recipient` is provided, KMS returns `CiphertextForRecipient`
/// (CMS EnvelopedData, RFC 5652) instead of `Plaintext`. This function
/// unwraps that envelope using the ephemeral RSA private key.
fn unwrap_cms_response(
    cms_blob: Option<&aws_sdk_kms::primitives::Blob>,
    private_key_pkcs8: &[u8],
) -> Result<Vec<u8>, AppError> {
    let cms_bytes = cms_blob.ok_or_else(|| {
        tee_attestation_error(
            "KMS response missing CiphertextForRecipient — \
             the KMS key may not support attestation-based operations",
        )
    })?;
    decrypt_cms_envelope(cms_bytes.as_ref(), private_key_pkcs8)
}

// ---------------------------------------------------------------------------
// KMS operations
// ---------------------------------------------------------------------------

/// Decrypt a KMS data key ciphertext (the `CiphertextBlob` from `GenerateDataKey`).
///
/// Attested KMS `Decrypt` of an arbitrary ciphertext sealed under the bootstrap
/// KMS key, for callers outside the seed/data-key path (P0.2c: the anchor
/// writer credential). Same attestation semantics as the data-key decrypt — on
/// real Nitro hardware the PCR-gated `Recipient` path is mandatory unless
/// `allow_unattested_fallback` is set — but flattens the typed error class the
/// bootstrap state machine needs into a plain [`AppError`].
pub(crate) async fn attested_decrypt(
    config: &TeeKmsConfig,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AppError> {
    kms_decrypt_data_key(config, ciphertext)
        .await
        .map_err(|(_, e)| e)
}

/// On real Nitro hardware (`/dev/nsm` available), uses attestation-based
/// KMS Decrypt with the `Recipient` parameter. If attestation fails, the
/// call is **terminal** unless `allow_unattested_fallback` is explicitly
/// enabled — silent downgrade to IAM-only Decrypt would bypass the KMS
/// key policy's PCR conditions.
///
/// Without `/dev/nsm` (simulated mode), uses direct KMS Decrypt.
///
/// Returns `(class, AppError)` on failure so the bootstrap path can
/// branch on `KmsErrorClass::AccessDenied` (legitimate post-rebuild
/// PCR mismatch) without auto-clearing on every other class.
async fn kms_decrypt_data_key(
    config: &TeeKmsConfig,
    ciphertext: &[u8],
) -> Result<Vec<u8>, (KmsErrorClass, AppError)> {
    if std::path::Path::new("/dev/nsm").exists() {
        match kms_decrypt_attested(config, ciphertext).await {
            Ok(plaintext) => {
                info!("KMS Decrypt succeeded with Nitro attestation");
                return Ok(plaintext);
            }
            Err((class, e)) if config.allow_unattested_fallback => {
                warn!(
                    error = %e,
                    class = ?class,
                    "attestation-based KMS Decrypt failed — falling back to direct Decrypt \
                     (allow_unattested_fallback = true). PCR policy is NOT enforced on this call."
                );
            }
            Err((class, e)) => {
                error!(
                    error = %e,
                    "attestation-based KMS Decrypt failed on Nitro hardware — refusing to \
                     fall back. Set tee.kms.allow_unattested_fallback = true only as a \
                     break-glass measure."
                );
                return Err((class, e));
            }
        }
    }

    kms_decrypt_direct(config, ciphertext).await
}

/// KMS Decrypt with Nitro attestation via the Recipient parameter.
async fn kms_decrypt_attested(
    config: &TeeKmsConfig,
    ciphertext: &[u8],
) -> Result<Vec<u8>, (KmsErrorClass, AppError)> {
    let (private_key, recipient) =
        nsm_attested_recipient().map_err(|e| (KmsErrorClass::Unknown, e))?;
    let client = kms_client(config).await;

    let resp = client
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
        .key_id(&config.key_arn)
        .recipient(recipient)
        .send()
        .await
        .map_err(|e| classify_kms_error_typed("Decrypt(attested)", e))?;

    unwrap_cms_response(resp.ciphertext_for_recipient(), &private_key)
        .map_err(|e| (KmsErrorClass::InvalidCiphertext, e))
}

/// Direct KMS Decrypt without the Recipient parameter.
async fn kms_decrypt_direct(
    config: &TeeKmsConfig,
    ciphertext: &[u8],
) -> Result<Vec<u8>, (KmsErrorClass, AppError)> {
    let client = kms_client(config).await;

    let resp = client
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
        .key_id(&config.key_arn)
        .send()
        .await
        .map_err(|e| classify_kms_error_typed("Decrypt", e))?;

    resp.plaintext()
        .map(|b| b.as_ref().to_vec())
        .ok_or_else(|| {
            (
                KmsErrorClass::InvalidCiphertext,
                tee_attestation_error("KMS Decrypt returned no plaintext"),
            )
        })
}

/// Generate a KMS data key, returning (kms_ciphertext, plaintext_key).
///
/// On real Nitro hardware, uses the `Recipient` parameter so KMS enforces
/// PCR conditions on `kms:GenerateDataKey`. The plaintext key is returned
/// via a CMS envelope decrypted with an ephemeral RSA key inside the enclave.
/// If attestation fails, the call is **terminal** unless
/// `allow_unattested_fallback` is explicitly enabled — silent downgrade
/// would let an attacker with IAM (but not PCR) access encrypt rogue data
/// that could overwrite legitimate ciphertexts.
///
/// Without NSM, calls `GenerateDataKey` directly (simulated/development mode).
async fn kms_generate_data_key(config: &TeeKmsConfig) -> Result<(Vec<u8>, [u8; 32]), AppError> {
    if std::path::Path::new("/dev/nsm").exists() {
        match kms_generate_data_key_attested(config).await {
            Ok(result) => {
                info!("KMS GenerateDataKey succeeded with Nitro attestation");
                return Ok(result);
            }
            Err(e) if config.allow_unattested_fallback => {
                warn!(
                    error = %e,
                    "attestation-based GenerateDataKey failed — falling back to direct \
                     (allow_unattested_fallback = true). PCR policy is NOT enforced on this call."
                );
            }
            Err(e) => {
                error!(
                    error = %e,
                    "attestation-based GenerateDataKey failed on Nitro hardware — refusing \
                     to fall back. Set tee.kms.allow_unattested_fallback = true only as a \
                     break-glass measure."
                );
                return Err(e);
            }
        }
    }

    kms_generate_data_key_direct(config).await
}

/// `GenerateDataKey` with Nitro attestation via the `Recipient` parameter.
async fn kms_generate_data_key_attested(
    config: &TeeKmsConfig,
) -> Result<(Vec<u8>, [u8; 32]), AppError> {
    let (private_key, recipient) = nsm_attested_recipient()?;
    let client = kms_client(config).await;

    let resp = client
        .generate_data_key()
        .key_id(&config.key_arn)
        .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
        .recipient(recipient)
        .send()
        .await
        .map_err(|e| classify_kms_error("GenerateDataKey(attested)", e))?;

    let kms_ciphertext = resp
        .ciphertext_blob()
        .ok_or_else(|| tee_attestation_error("GenerateDataKey returned no CiphertextBlob"))?
        .as_ref()
        .to_vec();

    let data_key_vec = unwrap_cms_response(resp.ciphertext_for_recipient(), &private_key)?;
    let data_key: [u8; 32] = data_key_vec
        .try_into()
        .map_err(|_| tee_attestation_error("data key is not 32 bytes"))?;

    debug!(
        kms_ct_len = kms_ciphertext.len(),
        "obtained attested data key"
    );
    Ok((kms_ciphertext, data_key))
}

/// `GenerateDataKey` without attestation (development/simulated mode).
async fn kms_generate_data_key_direct(
    config: &TeeKmsConfig,
) -> Result<(Vec<u8>, [u8; 32]), AppError> {
    let client = kms_client(config).await;

    let resp = client
        .generate_data_key()
        .key_id(&config.key_arn)
        .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
        .send()
        .await
        .map_err(|e| classify_kms_error("GenerateDataKey", e))?;

    let kms_ciphertext = resp
        .ciphertext_blob()
        .ok_or_else(|| tee_attestation_error("GenerateDataKey returned no CiphertextBlob"))?
        .as_ref()
        .to_vec();

    let plaintext = resp
        .plaintext()
        .ok_or_else(|| tee_attestation_error("GenerateDataKey returned no Plaintext"))?;
    let data_key: [u8; 32] = plaintext
        .as_ref()
        .try_into()
        .map_err(|_| tee_attestation_error("data key is not 32 bytes"))?;

    Ok((kms_ciphertext, data_key))
}

// ---------------------------------------------------------------------------
// Local AES-GCM envelope (nonce-prepended)
// ---------------------------------------------------------------------------

/// AES-256-GCM encrypt, returning `[nonce: 12 bytes][ciphertext]`.
fn aes_gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| tee_attestation_error(format!("AES-GCM encryption failed: {e}")))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// AES-256-GCM decrypt a `[nonce: 12 bytes][ciphertext]` blob.
fn aes_gcm_decrypt(key: &[u8], blob: &[u8]) -> Result<Vec<u8>, AppError> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};

    if key.len() != 32 {
        return Err(tee_attestation_error(format!(
            "data key is {} bytes, expected 32",
            key.len()
        )));
    }
    if blob.len() < 12 + 1 {
        return Err(tee_attestation_error("AES-GCM blob too short"));
    }

    let nonce = GenericArray::from_slice(&blob[..12]);
    let ciphertext = &blob[12..];
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| tee_attestation_error(format!("AES-GCM decryption failed: {e}")))
}

// ---------------------------------------------------------------------------
// CMS EnvelopedData decryption (RFC 5652)
// ---------------------------------------------------------------------------

/// Decrypt a CMS EnvelopedData envelope returned by KMS CiphertextForRecipient.
///
/// KMS produces a CMS EnvelopedData (RFC 5652) with:
/// - One `KeyTransRecipientInfo` containing the CEK encrypted with RSA-OAEP-SHA256
/// - `EncryptedContentInfo` with AES-256-GCM encrypted plaintext
///
/// We parse the DER structure manually (the format from KMS is fixed), unwrap the
/// CEK with the ephemeral RSA private key, then decrypt the content with AES-256-GCM.
fn decrypt_cms_envelope(cms_bytes: &[u8], private_key_pkcs8: &[u8]) -> Result<Vec<u8>, AppError> {
    // Log first bytes for diagnosing BER structure issues with real KMS responses
    debug!(
        cms_len = cms_bytes.len(),
        cms_hex_head = %hex::encode(cms_bytes),
        "raw CMS envelope"
    );

    // Parse the CMS EnvelopedData to extract the three fields we need
    let fields = cms_der::parse_enveloped_data(cms_bytes)?;

    // RSA-OAEP decrypt the content-encryption key (CEK). We request
    // RSAES_OAEP_SHA_256 in the Recipient parameter; per AWS KMS
    // documentation this always produces symmetric OAEP-SHA256
    // (SHA-256 hash + MGF1-SHA-256), so no algorithm fallback is needed.
    use aws_lc_rs::rsa::{OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey};

    let private_key = PrivateDecryptingKey::from_pkcs8(private_key_pkcs8).map_err(|e| {
        tee_attestation_error(format!(
            "RSA private key PKCS#8 deserialization failed: {e:?}"
        ))
    })?;
    let key_size = private_key.key_size_bytes();
    let oaep_key = OaepPrivateDecryptingKey::new(private_key)
        .map_err(|e| tee_attestation_error(format!("OAEP private key wrap failed: {e:?}")))?;
    // Output buffer sized to the key modulus length (upper bound on
    // plaintext size; OAEP overhead is subtracted internally).
    let mut plaintext_buf = vec![0u8; key_size];
    let cek = oaep_key
        .decrypt(
            &OAEP_SHA256_MGF1SHA256,
            &fields.encrypted_key,
            &mut plaintext_buf,
            None,
        )
        .map_err(|e| tee_attestation_error(format!("RSA-OAEP decryption of CEK failed: {e:?}")))?
        .to_vec();

    debug!(
        cek_len = cek.len(),
        oid_hex = %hex::encode(&fields.content_encryption_oid),
        iv_hex = %hex::encode(&fields.iv),
        ciphertext_len = fields.ciphertext.len(),
        encrypted_key_len = fields.encrypted_key.len(),
        "CMS envelope fields extracted"
    );

    if cek.len() != 32 {
        return Err(tee_attestation_error(format!(
            "unexpected CEK length: {} (expected 32 for AES-256)",
            cek.len()
        )));
    }

    // KMS uses AES-256-CBC for CMS CiphertextForRecipient content encryption.
    // OID 2.16.840.1.101.3.4.1.42 = AES-256-CBC
    // OID 2.16.840.1.101.3.4.1.46 = AES-256-GCM (also supported)
    let aes_256_cbc_oid: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];
    let aes_256_gcm_oid: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2e];

    let plaintext = if fields.content_encryption_oid == aes_256_cbc_oid {
        // AES-256-CBC with PKCS#7 padding.
        // cbc 0.2 / cipher 0.5: `BlockDecryptMut` was renamed to
        // `BlockModeDecrypt`, and `decrypt_padded_mut` was renamed to
        // `decrypt_padded` (which now consumes `self`).
        use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

        if fields.iv.len() != 16 {
            return Err(tee_attestation_error(format!(
                "AES-256-CBC IV must be 16 bytes, got {}",
                fields.iv.len()
            )));
        }

        let mut buf = fields.ciphertext.clone();
        let decryptor = Aes256CbcDec::new_from_slices(&cek, &fields.iv)
            .map_err(|e| tee_attestation_error(format!("AES-256-CBC init failed: {e}")))?;
        let plaintext = decryptor
            .decrypt_padded::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
            .map_err(|e| {
                tee_attestation_error(format!("AES-256-CBC decryption of CMS content failed: {e}"))
            })?;
        plaintext.to_vec()
    } else if fields.content_encryption_oid == aes_256_gcm_oid {
        // AES-256-GCM
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{AesGcm, KeyInit, aead::Aead};

        match fields.iv.len() {
            12 => {
                let cipher = AesGcm::<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U12>::new(
                    GenericArray::from_slice(&cek),
                );
                cipher
                    .decrypt(
                        GenericArray::from_slice(&fields.iv),
                        fields.ciphertext.as_ref(),
                    )
                    .map_err(|e| tee_attestation_error(format!("AES-GCM decryption failed: {e}")))?
            }
            16 => {
                let cipher = AesGcm::<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U16>::new(
                    GenericArray::from_slice(&cek),
                );
                cipher
                    .decrypt(
                        GenericArray::from_slice(&fields.iv),
                        fields.ciphertext.as_ref(),
                    )
                    .map_err(|e| tee_attestation_error(format!("AES-GCM decryption failed: {e}")))?
            }
            n => {
                return Err(tee_attestation_error(format!(
                    "unsupported GCM nonce length: {n}"
                )));
            }
        }
    } else {
        return Err(tee_attestation_error(format!(
            "unsupported content encryption algorithm OID: {}",
            hex::encode(&fields.content_encryption_oid)
        )));
    };

    debug!(
        plaintext_len = plaintext.len(),
        "CMS envelope decrypted successfully"
    );
    Ok(plaintext)
}

/// Minimal DER parser for the CMS EnvelopedData structure from KMS.
///
/// Parses just enough ASN.1 to extract the encrypted CEK, AES-GCM nonce,
/// and ciphertext. No external DER/ASN.1 crate needed — the structure
/// from KMS is predictable and constrained.
mod cms_der {
    use crate::error::{AppError, tee_attestation_error};

    /// Parsed fields from a CMS EnvelopedData needed for decryption.
    pub(super) struct CmsFields {
        pub encrypted_key: Vec<u8>,
        /// Algorithm OID bytes (e.g., AES-256-CBC or AES-256-GCM).
        pub content_encryption_oid: Vec<u8>,
        /// IV (for CBC) or nonce (for GCM).
        pub iv: Vec<u8>,
        pub ciphertext: Vec<u8>,
    }

    /// Parse a CMS ContentInfo → EnvelopedData and extract the three fields needed
    /// for decryption.
    ///
    /// ASN.1 structure (simplified):
    /// ```text
    /// ContentInfo ::= SEQUENCE {
    ///   contentType  OID (envelopedData)
    ///   content      [0] EXPLICIT EnvelopedData
    /// }
    /// EnvelopedData ::= SEQUENCE {
    ///   version          INTEGER
    ///   recipientInfos   SET { KeyTransRecipientInfo SEQUENCE {
    ///     version          INTEGER
    ///     rid              RecipientIdentifier
    ///     keyEncAlg        AlgorithmIdentifier
    ///     encryptedKey     OCTET STRING
    ///   }}
    ///   encryptedContentInfo SEQUENCE {
    ///     contentType      OID
    ///     contentEncAlg    SEQUENCE { OID, SEQUENCE { nonce OCTET STRING, ... } }
    ///     encryptedContent [0] IMPLICIT OCTET STRING
    ///   }
    /// }
    /// ```
    pub(super) fn parse_enveloped_data(data: &[u8]) -> Result<CmsFields, AppError> {
        let mut pos = 0;

        // ContentInfo SEQUENCE
        let (_, ci_body) = read_tlv(data, &mut pos, "ContentInfo")?;

        let mut ci_pos = 0;
        // contentType OID — skip
        let _ = read_tlv(ci_body, &mut ci_pos, "contentType OID")?;
        // content [0] EXPLICIT
        let (_, ctx0_body) = read_tlv(ci_body, &mut ci_pos, "[0] content")?;

        // EnvelopedData SEQUENCE
        let mut env_pos = 0;
        let (_, env_body) = read_tlv(ctx0_body, &mut env_pos, "EnvelopedData")?;

        let mut ed_pos = 0;
        // version INTEGER — skip
        let _ = read_tlv(env_body, &mut ed_pos, "EnvelopedData version")?;
        // recipientInfos SET
        let (_, ri_set) = read_tlv(env_body, &mut ed_pos, "recipientInfos SET")?;
        // encryptedContentInfo SEQUENCE
        let (_, eci_body) = read_tlv(env_body, &mut ed_pos, "encryptedContentInfo")?;

        // Parse KeyTransRecipientInfo (first element in SET)
        let encrypted_key = parse_key_trans_ri(ri_set)?;

        // Parse EncryptedContentInfo
        let (oid, iv, ciphertext) = parse_encrypted_content_info(eci_body)?;

        Ok(CmsFields {
            encrypted_key,
            content_encryption_oid: oid,
            iv,
            ciphertext,
        })
    }

    fn parse_key_trans_ri(set_data: &[u8]) -> Result<Vec<u8>, AppError> {
        let mut pos = 0;
        // KeyTransRecipientInfo SEQUENCE
        let (_, ktri_body) = read_tlv(set_data, &mut pos, "KeyTransRI")?;

        let mut kp = 0;
        // version INTEGER — skip
        let _ = read_tlv(ktri_body, &mut kp, "KeyTransRI version")?;
        // rid (RecipientIdentifier) — skip
        let _ = read_tlv(ktri_body, &mut kp, "KeyTransRI rid")?;
        // keyEncryptionAlgorithm — skip
        let _ = read_tlv(ktri_body, &mut kp, "KeyTransRI keyEncAlg")?;
        // encryptedKey OCTET STRING
        let (_, ek_value) = read_tlv(ktri_body, &mut kp, "encryptedKey")?;

        Ok(ek_value.to_vec())
    }

    /// (algorithm_oid, iv_or_nonce, ciphertext) parsed from CMS EncryptedContentInfo.
    type EncryptedContentParts = (Vec<u8>, Vec<u8>, Vec<u8>);

    /// Returns (algorithm_oid, iv_or_nonce, ciphertext).
    fn parse_encrypted_content_info(eci_data: &[u8]) -> Result<EncryptedContentParts, AppError> {
        let mut pos = 0;
        // contentType OID — skip
        let _ = read_tlv(eci_data, &mut pos, "ECI contentType")?;
        // contentEncryptionAlgorithm SEQUENCE
        let (_, alg_body) = read_tlv(eci_data, &mut pos, "ECI algorithm")?;

        // encryptedContent [0] IMPLICIT OCTET STRING
        //
        // This is raw ciphertext, not structured ASN.1. If it uses BER
        // indefinite-length (tag 0xA0, length 0x80), the generic read_tlv
        // would try to walk TLV children inside raw bytes and fail.
        //
        // Handle it directly: read the tag+length, and for indefinite-length
        // take all remaining data (stripping trailing EOC if present).
        if pos >= eci_data.len() {
            return Err(tee_attestation_error(
                "CMS: missing encryptedContent in EncryptedContentInfo",
            ));
        }
        let _tag = eci_data[pos];
        pos += 1;

        if pos >= eci_data.len() {
            return Err(tee_attestation_error(
                "CMS: truncated encryptedContent length",
            ));
        }
        let first_len = eci_data[pos];
        pos += 1;

        let ct_value = if first_len < 0x80 {
            let len = first_len as usize;
            &eci_data[pos..pos + len]
        } else if first_len == 0x80 {
            // Indefinite length on raw octets — take everything remaining,
            // strip trailing 0x00 0x00 EOC if present.
            let remaining = &eci_data[pos..];
            if remaining.len() >= 2
                && remaining[remaining.len() - 2] == 0x00
                && remaining[remaining.len() - 1] == 0x00
            {
                &remaining[..remaining.len() - 2]
            } else {
                remaining
            }
        } else {
            let num_bytes = (first_len & 0x7F) as usize;
            let mut len = 0usize;
            for i in 0..num_bytes {
                len = (len << 8) | (eci_data[pos + i] as usize);
            }
            pos += num_bytes;
            &eci_data[pos..pos + len]
        };

        // Parse algorithm to get the OID and IV/nonce
        let (oid, iv) = parse_content_encryption_params(alg_body)?;

        // The ciphertext may be wrapped in an inner OCTET STRING if KMS used
        // EXPLICIT tagging on [0] instead of IMPLICIT. Unwrap if present.
        let ciphertext = if ct_value.len() > 2 && ct_value[0] == 0x04 {
            let mut inner_pos = 0;
            let (_, inner) = read_tlv(ct_value, &mut inner_pos, "inner encryptedContent")?;
            inner.to_vec()
        } else {
            ct_value.to_vec()
        };

        Ok((oid, iv, ciphertext))
    }

    /// Parse the AlgorithmIdentifier to extract the OID and IV/nonce.
    /// Returns (algorithm_oid_bytes, iv_or_nonce).
    fn parse_content_encryption_params(alg_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AppError> {
        let mut pos = 0;
        // algorithm OID
        let (_, oid_bytes) = read_tlv(alg_data, &mut pos, "algorithm OID")?;
        // parameters: OCTET STRING (CBC IV) or SEQUENCE (GCM params)
        let (param_tag, params_body) = read_tlv(alg_data, &mut pos, "algorithm parameters")?;

        let iv = if param_tag == 0x04 {
            // OCTET STRING — direct IV (CBC) or bare nonce (some GCM encodings)
            params_body.to_vec()
        } else {
            // SEQUENCE wrapper (GCMParameters): first child is nonce OCTET STRING
            let mut pp = 0;
            let (_, nonce_value) = read_tlv(params_body, &mut pp, "GCM nonce")?;
            nonce_value.to_vec()
        };

        Ok((oid_bytes.to_vec(), iv))
    }

    /// Read a BER/DER TLV (tag-length-value) at the given position.
    ///
    /// Returns (tag_byte, value_bytes) and advances `pos` past the TLV.
    /// Handles both definite-length (DER) and indefinite-length (BER)
    /// encoding — KMS CiphertextForRecipient uses BER with indefinite
    /// length on multiple constructed elements.
    fn read_tlv<'a>(
        data: &'a [u8],
        pos: &mut usize,
        context: &str,
    ) -> Result<(u8, &'a [u8]), AppError> {
        if *pos >= data.len() {
            return Err(tee_attestation_error(format!(
                "CMS: unexpected end of data reading {context}"
            )));
        }

        let tag = data[*pos];
        *pos += 1;

        // Read length
        if *pos >= data.len() {
            return Err(tee_attestation_error(format!(
                "CMS: truncated length for {context}"
            )));
        }

        let first_len = data[*pos];
        *pos += 1;

        let len: usize = if first_len < 0x80 {
            // Short form: length in single byte
            first_len as usize
        } else if first_len == 0x80 {
            // BER indefinite length: content ends at a matching EOC (0x00 0x00).
            // Walk through child TLVs to find it (0x00 0x00 can appear inside
            // primitive values like ciphertext, so we can't just scan for it).
            let content_start = *pos;
            while *pos + 1 < data.len() {
                // Check for EOC marker
                if data[*pos] == 0x00 && data[*pos + 1] == 0x00 {
                    let value = &data[content_start..*pos];
                    *pos += 2; // skip EOC
                    return Ok((tag, value));
                }
                // Skip one child TLV
                skip_ber_tlv(data, pos).map_err(|_| {
                    tee_attestation_error(format!(
                        "CMS: malformed BER child element inside {context}"
                    ))
                })?;
            }
            return Err(tee_attestation_error(format!(
                "CMS: no EOC marker found for indefinite-length {context}"
            )));
        } else {
            // Long form: first_len & 0x7F = number of length bytes
            let num_bytes = (first_len & 0x7F) as usize;
            if *pos + num_bytes > data.len() {
                return Err(tee_attestation_error(format!(
                    "CMS: truncated length bytes for {context}"
                )));
            }
            let mut len: usize = 0;
            for i in 0..num_bytes {
                len = (len << 8) | (data[*pos + i] as usize);
            }
            *pos += num_bytes;
            len
        };

        if *pos + len > data.len() {
            return Err(tee_attestation_error(format!(
                "CMS: value overflows buffer for {context} (need {len} bytes at offset {pos}, have {})",
                data.len()
            )));
        }

        let value = &data[*pos..*pos + len];
        *pos += len;

        Ok((tag, value))
    }

    /// Skip one complete BER/DER TLV element, advancing `pos` past it.
    /// Handles indefinite-length by recursively skipping child elements.
    fn skip_ber_tlv(data: &[u8], pos: &mut usize) -> Result<(), ()> {
        if *pos + 1 >= data.len() {
            return Err(());
        }

        // Skip tag
        *pos += 1;

        // Read length
        let first_len = data[*pos];
        *pos += 1;

        if first_len < 0x80 {
            // Definite short form
            let len = first_len as usize;
            if *pos + len > data.len() {
                return Err(());
            }
            *pos += len;
        } else if first_len == 0x80 {
            // Indefinite length — skip children until EOC
            while *pos + 1 < data.len() {
                if data[*pos] == 0x00 && data[*pos + 1] == 0x00 {
                    *pos += 2; // skip EOC
                    return Ok(());
                }
                skip_ber_tlv(data, pos)?;
            }
            return Err(());
        } else {
            // Definite long form
            let num_bytes = (first_len & 0x7F) as usize;
            if *pos + num_bytes > data.len() {
                return Err(());
            }
            let mut len: usize = 0;
            for i in 0..num_bytes {
                len = (len << 8) | (data[*pos + i] as usize);
            }
            *pos += num_bytes;
            if *pos + len > data.len() {
                return Err(());
            }
            *pos += len;
        }

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_read_tlv_short_form() {
            // OCTET STRING, length 3, value [0x01, 0x02, 0x03]
            let data = [0x04, 0x03, 0x01, 0x02, 0x03];
            let mut pos = 0;
            let (tag, value) = read_tlv(&data, &mut pos, "test").unwrap();
            assert_eq!(tag, 0x04);
            assert_eq!(value, &[0x01, 0x02, 0x03]);
            assert_eq!(pos, 5);
        }

        #[test]
        fn test_read_tlv_long_form() {
            // OCTET STRING, length 128 (0x81 0x80), then 128 bytes of 0xAA
            let mut data = vec![0x04, 0x81, 0x80];
            data.extend_from_slice(&[0xAA; 128]);
            let mut pos = 0;
            let (tag, value) = read_tlv(&data, &mut pos, "test").unwrap();
            assert_eq!(tag, 0x04);
            assert_eq!(value.len(), 128);
            assert_eq!(pos, 131);
        }

        #[test]
        fn test_read_tlv_truncated() {
            let data = [0x04, 0x05, 0x01]; // claims 5 bytes but only 1
            let mut pos = 0;
            assert!(read_tlv(&data, &mut pos, "test").is_err());
        }
    }
}

/// Typed classification of a KMS error. The bootstrap path branches
/// on this to decide whether to auto-clear stale ciphertexts: only
/// `AccessDenied` (the post-rebuild PCR-mismatch signal) is treated
/// as legitimate; anything else preserves the VTA's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KmsErrorClass {
    AccessDenied,
    KeyNotFound,
    InvalidCiphertext,
    KmsInternal,
    Network,
    Unknown,
}

impl KmsErrorClass {
    fn label(self) -> &'static str {
        match self {
            Self::AccessDenied => {
                "ACCESS_DENIED — check KMS key policy allows this action and PCR conditions match"
            }
            Self::KeyNotFound => "KEY_NOT_FOUND — verify the KMS key ARN in config.toml",
            Self::InvalidCiphertext => {
                "INVALID_CIPHERTEXT — ciphertext may be corrupt or encrypted with a different key"
            }
            Self::KmsInternal => "KMS_INTERNAL — transient AWS error, retry may help",
            Self::Network => "NETWORK — cannot reach KMS endpoint, check vsock proxy and allowlist",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Classify KMS errors for operator diagnostics.
fn classify_kms_error<E: std::error::Error>(operation: &str, err: E) -> AppError {
    classify_kms_error_typed(operation, err).1
}

/// Classify a KMS error into a typed class + an `AppError` ready to
/// propagate. The class is what the bootstrap path branches on; the
/// `AppError` is what the caller returns/logs.
pub(crate) fn classify_kms_error_typed<E: std::error::Error>(
    operation: &str,
    err: E,
) -> (KmsErrorClass, AppError) {
    // Build the full error chain string so classification catches nested causes
    // (the AWS SDK wraps the actual error type several layers deep).
    let mut full_msg = format!("{err}");
    let mut source = std::error::Error::source(&err);
    while let Some(cause) = source {
        full_msg.push_str(&format!("\n  caused by: {cause}"));
        source = cause.source();
    }

    let class = if full_msg.contains("AccessDeniedException") {
        KmsErrorClass::AccessDenied
    } else if full_msg.contains("NotFoundException") || full_msg.contains("not found") {
        KmsErrorClass::KeyNotFound
    } else if full_msg.contains("InvalidCiphertextException") {
        KmsErrorClass::InvalidCiphertext
    } else if full_msg.contains("KMSInternalException") {
        KmsErrorClass::KmsInternal
    } else if full_msg.contains("connect") || full_msg.contains("timeout") {
        KmsErrorClass::Network
    } else {
        KmsErrorClass::Unknown
    };

    let label = class.label();
    let msg = format!("KMS {operation} failed [{label}]: {full_msg}");

    error!(operation, classification = label, "KMS error");
    (class, tee_attestation_error(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drift guard (P0.2a): the integrity manifest in `vti-common` reads the
    /// carve-out sentinel and JWT-fingerprint rows by hard-coded key string
    /// (it can't import these `vta-service` constants). If either key string
    /// is ever changed here, the manifest would silently stop covering it —
    /// this test fails the moment they diverge.
    #[test]
    fn integrity_manifest_key_strings_match() {
        assert_eq!(
            BOOTSTRAP_JWT_FINGERPRINT_KEY,
            vti_common::integrity::JWT_FINGERPRINT_KEY,
            "JWT fingerprint key drifted from vti_common::integrity"
        );
        assert_eq!(
            crate::tee::admin_bootstrap::BOOTSTRAP_CARVEOUT_CLOSED_KEY,
            vti_common::integrity::CARVEOUT_KEY,
            "carve-out sentinel key drifted from vti_common::integrity"
        );
    }

    /// Build a synthetic CMS EnvelopedData that mimics what KMS returns
    /// with CiphertextForRecipient. This allows us to test the full
    /// decrypt_cms_envelope round-trip without needing real KMS or NSM.
    #[test]
    fn test_cms_envelope_roundtrip() {
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        use aws_lc_rs::rsa::{
            KeySize, OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey, PrivateDecryptingKey,
        };

        // Generate RSA keypair (the "ephemeral" key the enclave would create)
        let private_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();

        // The plaintext KMS would return (e.g., a 32-byte seed)
        let original_plaintext = b"this is a secret seed value!!!!!"; // 32 bytes

        // Generate random AES-256 CEK and GCM nonce
        let mut cek = [0u8; 32];
        rand::fill(&mut cek);
        let mut nonce_bytes = [0u8; 12];
        rand::fill(&mut nonce_bytes);

        // AES-GCM encrypt the plaintext
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&cek));
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let aes_ciphertext = cipher.encrypt(nonce, original_plaintext.as_ref()).unwrap();

        // RSA-OAEP-SHA256 encrypt the CEK using the public key — mirrors
        // what KMS does server-side before returning CiphertextForRecipient.
        let oaep_pub = OaepPublicEncryptingKey::new(private_key.public_key().clone()).unwrap();
        let mut encrypted_cek_buf = vec![0u8; private_key.key_size_bytes()];
        let encrypted_cek_slice = oaep_pub
            .encrypt(&OAEP_SHA256_MGF1SHA256, &cek, &mut encrypted_cek_buf, None)
            .unwrap();
        let encrypted_cek = encrypted_cek_slice.to_vec();

        // Build the CMS EnvelopedData DER structure
        let cms_bytes = build_test_cms_envelope(&encrypted_cek, &nonce_bytes, &aes_ciphertext);

        // Serialize the private key to PKCS#8 so decrypt_cms_envelope
        // can round-trip it (mirrors the production path, where the key
        // crosses async await boundaries as bytes rather than as the
        // non-Send PrivateDecryptingKey object).
        use aws_lc_rs::encoding::AsDer;
        let pkcs8 = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&private_key)
            .unwrap()
            .as_ref()
            .to_vec();

        // Now decrypt it using our implementation
        let recovered = decrypt_cms_envelope(&cms_bytes, &pkcs8).unwrap();

        assert_eq!(recovered, original_plaintext);
    }

    /// Construct a minimal CMS ContentInfo/EnvelopedData DER structure.
    fn build_test_cms_envelope(
        encrypted_cek: &[u8],
        nonce: &[u8],
        aes_ciphertext: &[u8],
    ) -> Vec<u8> {
        // OID for envelopedData: 1.2.840.113549.1.7.3
        let enveloped_data_oid = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03,
        ];

        // OID for data: 1.2.840.113549.1.7.1
        let data_oid = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
        ];

        // OID for AES-256-GCM: 2.16.840.1.101.3.4.1.46
        let aes_256_gcm_oid = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2E,
        ];

        // OID for RSAES-OAEP: 1.2.840.113549.1.1.7
        let rsaes_oaep_oid = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07,
        ];

        // GCMParameters SEQUENCE { nonce OCTET STRING }
        let nonce_tlv = der_octet_string(nonce);
        let gcm_params = der_sequence(&nonce_tlv);

        // AlgorithmIdentifier SEQUENCE { OID, GCMParameters }
        let mut alg_id_content = Vec::new();
        alg_id_content.extend_from_slice(aes_256_gcm_oid);
        alg_id_content.extend_from_slice(&gcm_params);
        let alg_id = der_sequence(&alg_id_content);

        // encryptedContent [0] IMPLICIT OCTET STRING
        let encrypted_content = der_context_implicit(0, aes_ciphertext);

        // EncryptedContentInfo SEQUENCE
        let mut eci_content = Vec::new();
        eci_content.extend_from_slice(data_oid);
        eci_content.extend_from_slice(&alg_id);
        eci_content.extend_from_slice(&encrypted_content);
        let eci = der_sequence(&eci_content);

        // Fake RecipientIdentifier (IssuerAndSerialNumber — minimal)
        let fake_rid = der_sequence(&[0x30, 0x00, 0x02, 0x01, 0x01]); // SEQUENCE{SEQUENCE{}, INTEGER 1}

        // KeyEncryptionAlgorithm (RSAES-OAEP — simplified, just OID)
        let key_enc_alg = der_sequence(rsaes_oaep_oid);

        // KeyTransRecipientInfo SEQUENCE
        let mut ktri_content = Vec::new();
        ktri_content.extend_from_slice(&[0x02, 0x01, 0x00]); // version INTEGER 0
        ktri_content.extend_from_slice(&fake_rid);
        ktri_content.extend_from_slice(&key_enc_alg);
        ktri_content.extend_from_slice(&der_octet_string(encrypted_cek));
        let ktri = der_sequence(&ktri_content);

        // RecipientInfos SET
        let ri_set = der_set(&ktri);

        // EnvelopedData SEQUENCE
        let mut env_content = Vec::new();
        env_content.extend_from_slice(&[0x02, 0x01, 0x00]); // version INTEGER 0
        env_content.extend_from_slice(&ri_set);
        env_content.extend_from_slice(&eci);
        let enveloped_data = der_sequence(&env_content);

        // [0] EXPLICIT EnvelopedData
        let ctx0 = der_context_explicit(0, &enveloped_data);

        // ContentInfo SEQUENCE
        let mut ci_content = Vec::new();
        ci_content.extend_from_slice(enveloped_data_oid);
        ci_content.extend_from_slice(&ctx0);
        der_sequence(&ci_content)
    }

    fn der_sequence(content: &[u8]) -> Vec<u8> {
        der_tlv(0x30, content)
    }

    fn der_set(content: &[u8]) -> Vec<u8> {
        der_tlv(0x31, content)
    }

    fn der_octet_string(content: &[u8]) -> Vec<u8> {
        der_tlv(0x04, content)
    }

    fn der_context_explicit(tag_num: u8, content: &[u8]) -> Vec<u8> {
        der_tlv(0xA0 | tag_num, content) // constructed context-specific
    }

    fn der_context_implicit(tag_num: u8, content: &[u8]) -> Vec<u8> {
        der_tlv(0x80 | tag_num, content) // primitive context-specific
    }

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut buf = vec![tag];
        let len = content.len();
        if len < 0x80 {
            buf.push(len as u8);
        } else if len < 0x100 {
            buf.push(0x81);
            buf.push(len as u8);
        } else if len < 0x10000 {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        } else {
            buf.push(0x83);
            buf.push((len >> 16) as u8);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        }
        buf.extend_from_slice(content);
        buf
    }

    #[test]
    fn test_derive_storage_key_deterministic() {
        let seed = [0x42u8; 32];
        let key1 = derive_storage_key(&seed, "test-salt");
        let key2 = derive_storage_key(&seed, "test-salt");
        assert_eq!(key1, key2, "same seed + salt must produce same key");
    }

    #[test]
    fn test_derive_storage_key_different_salts() {
        let seed = [0x42u8; 32];
        let key1 = derive_storage_key(&seed, "salt-a");
        let key2 = derive_storage_key(&seed, "salt-b");
        assert_ne!(key1, key2, "different salts must produce different keys");
    }

    #[test]
    fn test_derive_storage_key_different_seeds() {
        let key1 = derive_storage_key(&[0x01u8; 32], "same-salt");
        let key2 = derive_storage_key(&[0x02u8; 32], "same-salt");
        assert_ne!(key1, key2, "different seeds must produce different keys");
    }

    #[test]
    fn test_jwt_fingerprint_deterministic() {
        let key = [0xABu8; 32];
        let fp1 = jwt_fingerprint(&key);
        let fp2 = jwt_fingerprint(&key);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 32); // 16 bytes = 32 hex chars
    }

    // ── decrypt_cms_envelope failure paths ──────────────────────────────
    //
    // Negative tests for CMS unwrap. The happy path is covered by
    // `test_cms_envelope_roundtrip`; these tests assert each failure
    // surface returns a typed `AppError` rather than panicking, and
    // catches the specific class of corruption an attacker (or an
    // unreliable network) might introduce between KMS and the enclave.

    /// Helper: build a known-good encrypted CMS plus its matching PKCS#8
    /// private key, then return both. Tests then mutate one or the
    /// other to test specific tamper classes.
    fn cms_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::rsa::{
            KeySize, OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey, PrivateDecryptingKey,
        };

        let private_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let plaintext = b"this is a secret seed value!!!!!"; // 32 bytes
        let mut cek = [0u8; 32];
        rand::fill(&mut cek);
        let mut nonce_bytes = [0u8; 12];
        rand::fill(&mut nonce_bytes);

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&cek));
        let aes_ct = cipher
            .encrypt(GenericArray::from_slice(&nonce_bytes), plaintext.as_ref())
            .unwrap();

        let oaep_pub = OaepPublicEncryptingKey::new(private_key.public_key().clone()).unwrap();
        let mut buf = vec![0u8; private_key.key_size_bytes()];
        let enc_cek = oaep_pub
            .encrypt(&OAEP_SHA256_MGF1SHA256, &cek, &mut buf, None)
            .unwrap()
            .to_vec();

        let cms = build_test_cms_envelope(&enc_cek, &nonce_bytes, &aes_ct);
        let pkcs8 = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&private_key)
            .unwrap()
            .as_ref()
            .to_vec();
        (cms, pkcs8, plaintext.to_vec())
    }

    #[test]
    fn cms_decrypt_with_wrong_private_key_fails() {
        // Threat: an attacker substitutes a different KMS response. The
        // CEK was OAEP-encrypted to the enclave's ephemeral pubkey;
        // decrypting with any other private key MUST fail at the OAEP
        // unwrap before AES decryption is attempted.
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};

        let (cms, _correct_pkcs8, _) = cms_fixture();

        // Generate a *different* private key — the OAEP unwrap will fail.
        let wrong_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let wrong_pkcs8 = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&wrong_key)
            .unwrap()
            .as_ref()
            .to_vec();

        let err = decrypt_cms_envelope(&cms, &wrong_pkcs8).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("RSA-OAEP") || msg.contains("CEK") || msg.contains("decryption"),
            "expected OAEP-unwrap error, got: {msg}"
        );
    }

    #[test]
    fn cms_decrypt_with_corrupted_cek_fails() {
        // Threat: in-flight tampering of the encrypted CEK. OAEP carries
        // padding-style integrity, so a single bit flip in the encrypted
        // CEK causes unwrap to fail with very high probability. This
        // catches a regression where someone moves to a non-OAEP padding
        // scheme without updating the assumption.
        let (mut cms, pkcs8, _) = cms_fixture();
        // Corrupt a byte in the middle of the structure. Any byte will
        // do; we choose mid-buffer to avoid hitting the outer ASN.1 tags
        // (which would surface as a parse error rather than an unwrap
        // error — also a valid failure mode but a different one).
        let mid = cms.len() / 2;
        cms[mid] ^= 0xFF;
        let err = decrypt_cms_envelope(&cms, &pkcs8).unwrap_err();
        // Either a parse failure (if the byte was structural) or an
        // OAEP-unwrap failure (if the byte was inside the encrypted
        // CEK). Both are typed errors, neither is a panic.
        let _ = format!("{err}");
    }

    #[test]
    fn cms_decrypt_with_tampered_aes_ciphertext_fails() {
        // Threat: in-flight modification of the encrypted plaintext.
        // AES-GCM's auth tag must catch this regardless of where the
        // bit flip lands inside the ciphertext. Without the tag check,
        // tampered key material would be loaded silently — fatal.
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::rsa::{
            KeySize, OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey, PrivateDecryptingKey,
        };

        let private_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let plaintext = b"a different secret of length 32!"; // 32 bytes
        let mut cek = [0u8; 32];
        rand::fill(&mut cek);
        let mut nonce_bytes = [0u8; 12];
        rand::fill(&mut nonce_bytes);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&cek));
        let mut aes_ct = cipher
            .encrypt(GenericArray::from_slice(&nonce_bytes), plaintext.as_ref())
            .unwrap();
        // Flip a bit inside the AES-GCM ciphertext (before the auth tag).
        aes_ct[0] ^= 0x01;

        let oaep_pub = OaepPublicEncryptingKey::new(private_key.public_key().clone()).unwrap();
        let mut buf = vec![0u8; private_key.key_size_bytes()];
        let enc_cek = oaep_pub
            .encrypt(&OAEP_SHA256_MGF1SHA256, &cek, &mut buf, None)
            .unwrap()
            .to_vec();
        let cms = build_test_cms_envelope(&enc_cek, &nonce_bytes, &aes_ct);
        let pkcs8 = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&private_key)
            .unwrap()
            .as_ref()
            .to_vec();

        let err = decrypt_cms_envelope(&cms, &pkcs8).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("aes") || msg.to_lowercase().contains("decrypt"),
            "expected AES decrypt failure, got: {msg}"
        );
    }

    #[test]
    fn cms_decrypt_with_empty_envelope_fails_cleanly() {
        // Threat: KMS returns success but the `CiphertextForRecipient`
        // field is empty (or KMS API change drops the field). Must
        // surface a typed parse error, not a panic.
        let (_, pkcs8, _) = cms_fixture();
        let err = decrypt_cms_envelope(&[], &pkcs8).unwrap_err();
        let _ = format!("{err}");
    }

    #[test]
    fn cms_decrypt_with_malformed_pkcs8_fails_cleanly() {
        // Threat: the persisted ephemeral RSA key is corrupted (storage
        // bit-flip, vsock-store proxy bug). Must surface a typed
        // PKCS#8-deserialisation error, not a panic.
        let (cms, _, _) = cms_fixture();
        let err = decrypt_cms_envelope(&cms, &[0u8; 16]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("pkcs"),
            "expected PKCS#8 parse error, got: {msg}"
        );
    }
}
