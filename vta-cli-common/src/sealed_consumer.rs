//! CLI-side consumer helpers for `vta_sdk::sealed_transfer`.
//!
//! Generates ephemeral Ed25519 keypairs (exposed as `did:key` on the wire)
//! and persists the seed under `<config_dir>/bootstrap-secrets/<bundle_id>.key`
//! (mode 0600 on Unix) so a subsequent open call can retrieve it. At open
//! time the X25519 HPKE secret is derived from the seed via
//! [`vta_sdk::sealed_transfer::ed25519_seed_to_x25519_secret`].
//!
//! The pnm-cli and cnm-cli bootstrap subcommands both route through this
//! module — the only per-CLI concern is which `config_dir` to use.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use vta_sdk::credentials::CredentialBundle;
use vta_sdk::sealed_transfer::{
    BootstrapRequest, SealedPayloadV1, armor, bundle_digest, ed25519_seed_to_x25519_secret,
    generate_ed25519_keypair, open_bundle,
};

const SECRETS_SUBDIR: &str = "bootstrap-secrets";

/// Resolve the per-config bootstrap secrets directory, creating it on first
/// use with owner-only permissions (0700 on Unix, user-only DACL on
/// Windows via `icacls`). See [`crate::secure_file::restrict_dir_to_owner`].
pub fn secrets_dir(config_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = config_dir.join(SECRETS_SUBDIR);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        if let Err(e) = crate::secure_file::restrict_dir_to_owner(&dir) {
            eprintln!(
                "warning: could not restrict {} to owner ({e}) — contents may be \
                 accessible to other local users",
                dir.display()
            );
        }
    }
    Ok(dir)
}

fn secret_path(
    config_dir: &Path,
    bundle_id_hex: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(secrets_dir(config_dir)?.join(format!("{bundle_id_hex}.key")))
}

fn write_secret(path: &Path, secret: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    // Unix: open with 0600 atomically so the file is never publicly
    // readable between create and chmod. Windows: we can't set a DACL
    // at open time via `OpenOptions`, so the file briefly exists with
    // the directory's inherited ACL (already owner-only courtesy of
    // `secrets_dir`). Post-open we tighten via `restrict_file_to_owner`.
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(path)?;
    file.write_all(secret)?;
    drop(file);
    if let Err(e) = crate::secure_file::restrict_file_to_owner(path) {
        eprintln!(
            "warning: could not restrict {} to owner ({e}) — secret may be readable by \
             other local users",
            path.display()
        );
    }
    Ok(())
}

fn read_secret(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("secret file {} is not 32 bytes", path.display()).into())
}

/// Overwrite a file's bytes with zeros, fsync, then unlink.
///
/// This is a best-effort forensic-resistance measure: on rotating media
/// it overwrites the sectors that held the secret before we forget
/// where they are. On modern SSDs with wear-levelling the write may be
/// remapped rather than overwriting the physical cells — still no worse
/// than plain unlink, and meaningfully better on the platforms where
/// direct overwrite wins (HDDs, ramdisk, most filesystems on older
/// kernels). Defence-in-depth, not a hard guarantee.
///
/// Errors at any step are non-fatal for the surrounding flow: the
/// caller gets a `Result` so it can log, but the bundle has already
/// been consumed. Callers typically print a warning and continue.
pub fn zero_overwrite_and_remove(path: &Path) -> std::io::Result<()> {
    // Stat for size *before* we open to write — truncating via OpenOptions
    // would drop the old bytes before we get a chance to overwrite them.
    let metadata = fs::metadata(path)?;
    let len = metadata.len() as usize;

    if len > 0 {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .open(path)?;
        // Stream zeros rather than allocating a `vec![0u8; len]` — a
        // single page buffer handles keys (32 B) and armored bundles
        // (~KB) without surprises on tiny embedded targets.
        const ZEROS: [u8; 4096] = [0u8; 4096];
        let mut remaining = len;
        while remaining > 0 {
            let chunk = remaining.min(ZEROS.len());
            file.write_all(&ZEROS[..chunk])?;
            remaining -= chunk;
        }
        file.flush()?;
        file.sync_all()?;
    }

    fs::remove_file(path)
}

/// The outcome of [`create_bootstrap_request`]: the serialized request body
/// and the bundle id (for the `secret stored at <path>` banner).
pub struct CreatedRequest {
    pub request: BootstrapRequest,
    pub bundle_id_hex: String,
    pub secret_path: PathBuf,
}

/// Generate a fresh Ed25519 keypair + nonce, persist the **seed** (not the
/// derived X25519 secret) under `config_dir`, and return a
/// [`BootstrapRequest`] ready to hand to the producer.
///
/// Persisting the Ed25519 seed (rather than the X25519 secret) means the
/// same stored material can later be reused as a signing identity without
/// regenerating.
pub fn create_bootstrap_request(
    config_dir: &Path,
    label: Option<String>,
) -> Result<CreatedRequest, Box<dyn std::error::Error>> {
    let (seed, public) = generate_ed25519_keypair();
    let nonce: [u8; 16] = rand::random();
    let bundle_id_hex = hex_lower(&nonce);
    let sp = secret_path(config_dir, &bundle_id_hex)?;
    write_secret(&sp, &seed)?;
    let request = BootstrapRequest::new(public, nonce, label);
    Ok(CreatedRequest {
        request,
        bundle_id_hex,
        secret_path: sp,
    })
}

/// The result of [`open_armored_bundle`] — the full sealed payload plus the
/// producer assertion, ready for caller-specific trust verification.
#[derive(Debug)]
pub struct OpenedArmored {
    pub payload: SealedPayloadV1,
    pub producer: vta_sdk::sealed_transfer::ProducerAssertion,
    pub bundle_id: [u8; 16],
    pub bundle_id_hex: String,
    pub digest: String,
    /// Consumer's X25519 public key — the `client_x25519_pub` the
    /// producer signed over in a `DidSigned` assertion. Derived from the
    /// stored Ed25519 seed that opened the bundle
    /// (`ed25519_pub_to_x25519_bytes(ed25519_pub)`), captured here
    /// because the seed file is zeroized+removed on successful open.
    ///
    /// Downstream verification of the producer assertion feeds this
    /// into
    /// [`vta_sdk::sealed_transfer::verify::verify_producer_assertion_with_pubkey`].
    pub client_x25519_pub: [u8; 32],
}

/// Read an armored sealed bundle from `bundle_path`, load the corresponding
/// secret from `config_dir`, open and verify. The caller is responsible for
/// passing an `expect_digest` unless `no_verify_digest` is set.
///
/// Best-effort removal of the used secret file on success — the bundle id is
/// single-use, and keeping the secret around only widens blast radius.
pub fn open_armored_bundle(
    bundle_path: &Path,
    config_dir: &Path,
    expect_digest: Option<&str>,
    no_verify_digest: bool,
) -> Result<OpenedArmored, Box<dyn std::error::Error>> {
    if expect_digest.is_none() && !no_verify_digest {
        return Err(
            "--expect-digest <hex> is required (or pass --no-verify-digest to opt out)".into(),
        );
    }

    let armored = fs::read_to_string(bundle_path)
        .map_err(|e| format!("read {}: {e}", bundle_path.display()))?;
    let bundles = armor::decode(&armored)?;
    if bundles.len() != 1 {
        return Err(format!(
            "expected exactly one bundle in {}, found {}",
            bundle_path.display(),
            bundles.len()
        )
        .into());
    }
    let bundle = &bundles[0];
    let bundle_id_hex = hex_lower(&bundle.bundle_id);

    let sp = secret_path(config_dir, &bundle_id_hex)?;
    if !sp.exists() {
        return Err(format!(
            "no stored secret for bundle_id {bundle_id_hex} (expected at {}). \
             Did you run `bootstrap request` on this host?",
            sp.display()
        )
        .into());
    }
    let ed_seed = read_secret(&sp)?;
    let x_secret = ed25519_seed_to_x25519_secret(&ed_seed);

    // Derive the consumer's X25519 pubkey — the producer signed over
    // this in its DidSigned assertion. Derived here (while we still
    // have the seed) rather than forcing the CLI caller to re-read
    // the secret file, which we're about to delete.
    let client_x25519_pub = {
        let signing = ed25519_dalek::SigningKey::from_bytes(&ed_seed);
        let ed_pub = signing.verifying_key().to_bytes();
        affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&ed_pub).map_err(
            |e| -> Box<dyn std::error::Error> {
                format!("derive consumer X25519 pubkey from seed: {e}").into()
            },
        )?
    };

    let digest = bundle_digest(bundle);
    let opened = open_bundle(&x_secret, bundle, expect_digest)?;

    // Best-effort cleanup. If the caller later fails, the secret is gone —
    // that's fine because the bundle id is single-use anyway; a retry would
    // need a fresh request. Overwrite-then-unlink so the old bytes aren't
    // left sitting on disk after unlink (see `zero_overwrite_and_remove`).
    if let Err(e) = zero_overwrite_and_remove(&sp) {
        eprintln!(
            "warning: could not remove used secret {}: {e}",
            sp.display()
        );
    }

    Ok(OpenedArmored {
        payload: opened.payload,
        producer: opened.producer,
        bundle_id: opened.bundle_id,
        bundle_id_hex,
        digest,
        client_x25519_pub,
    })
}

/// The outcome of [`create_provision_request`]: the signed VP plus the
/// bookkeeping fields callers need to hand to the operator / match the
/// returned sealed bundle.
pub struct CreatedProvisionRequest {
    /// Signed VP (VC Data Model 2.0 `VerifiablePresentation` +
    /// `BootstrapRequest` types) — serialize and hand to the VTA
    /// operator for `vta bootstrap provision-integration --request ...`.
    pub request: vta_sdk::provision_integration::BootstrapRequest,
    /// `did:key:z6Mk...` derived from the ephemeral keypair; mirrors
    /// `request.holder`.
    pub client_did: String,
    /// Hex-encoded 16-byte bundle id (== the VP's `nonce`). Also the
    /// filename stem under which the seed was persisted.
    pub bundle_id_hex: String,
    /// Absolute path to the persisted Ed25519 seed. Read-restricted to
    /// the owner (0600 on Unix).
    pub secret_path: PathBuf,
}

/// Generate a fresh ephemeral Ed25519 keypair, persist the seed under
/// `<config_dir>/bootstrap-secrets/<bundle_id_hex>.key`, and return a
/// signed VP-framed [`vta_sdk::provision_integration::BootstrapRequest`]
/// ready to hand to the VTA operator's
/// `vta bootstrap provision-integration` CLI.
///
/// Thin wrapper over
/// [`vta_sdk::provision_integration::ProvisionRequestBuilder::sign_ephemeral`]
/// that adds the CLI-common seed-persistence convention — matching the
/// layout used by the v1 [`create_bootstrap_request`] path, so the same
/// `<config_dir>` lets [`open_armored_bundle`] find the secret at
/// open-time regardless of which request flavour produced it.
pub async fn create_provision_request(
    config_dir: &Path,
    builder: vta_sdk::provision_integration::ProvisionRequestBuilder,
) -> Result<CreatedProvisionRequest, Box<dyn std::error::Error>> {
    let signed = builder.sign_ephemeral().await?;
    let bundle_id_hex = hex_lower(&signed.bundle_id);
    let sp = secret_path(config_dir, &bundle_id_hex)?;
    write_secret(&sp, &signed.seed)?;
    Ok(CreatedProvisionRequest {
        request: signed.request,
        client_did: signed.client_did,
        bundle_id_hex,
        secret_path: sp,
    })
}

/// Extract the [`CredentialBundle`] from an opened payload.
///
/// Accepts `AdminCredential` directly and `ContextProvision` (unwrapping the
/// inner admin credential) — both are "install an admin identity" flows for a
/// consumer. Other variants are rejected with a descriptive error.
pub fn extract_admin_credential(
    payload: SealedPayloadV1,
) -> Result<CredentialBundle, Box<dyn std::error::Error>> {
    match payload {
        SealedPayloadV1::AdminCredential(c) => Ok(*c),
        SealedPayloadV1::ContextProvision(p) => Ok(p.credential),
        SealedPayloadV1::DidSecrets(_) => Err(
            "cannot install a DidSecrets bundle as an admin credential — use `bootstrap open` to inspect it"
                .into(),
        ),
        SealedPayloadV1::AdminKeySet(_) => Err(
            "cannot install an AdminKeySet bundle as an admin credential — use `bootstrap open` to inspect it"
                .into(),
        ),
        SealedPayloadV1::RawPrivateKey(_) => Err(
            "cannot install a RawPrivateKey bundle as an admin credential".into(),
        ),
        SealedPayloadV1::TemplateBootstrap(_) => Err(
            "TemplateBootstrap payloads carry a VC-issued admin authorization, not a \
             CredentialBundle — open via `pnm bootstrap open` and use the provision-integration \
             flow to install"
                .into(),
        ),
        SealedPayloadV1::AdminRotation(_) => Err(
            "AdminRotation payloads carry a VC-issued admin authorization, not a \
             CredentialBundle — open via `pnm bootstrap open` and use the provision-integration \
             flow to install"
                .into(),
        ),
        SealedPayloadV1::IssuedCredential(_) => Err(
            "IssuedCredential payloads carry a holder credential, not an admin CredentialBundle \
             — receive it into the holder vault via the credential-exchange flow"
                .into(),
        ),
        SealedPayloadV1::MessagingBridgeCredentials(_) => Err(
            "MessagingBridgeCredentials payloads carry a connector's platform secrets, not an \
             admin CredentialBundle — open via `pnm bootstrap open` and load them into the \
             connector's secret store"
                .into(),
        ),
    }
}

pub use vta_sdk::hex::lower as hex_lower;

/// Emit the canonical `--no-verify-digest` warning to stderr.
///
/// Single source of truth for the wording — every CLI surface that
/// accepts `--no-verify-digest` should call this so a future tweak to
/// the message lands everywhere at once. Per CLAUDE.md, digest pinning
/// is mandatory at the CLI; this helper is what the opt-out fires when
/// the operator explicitly chose to disable it.
pub fn warn_no_verify_digest() {
    eprintln!(
        "WARNING: --no-verify-digest disables out-of-band integrity verification.\n\
         You are trusting the producer pubkey embedded in the bundle without\n\
         any external anchor. Use only for testing."
    );
}

/// Validate the `(--expect-digest, --no-verify-digest)` combination and
/// fire the opt-out warning when applicable.
///
/// Rules:
/// - One of the two must be supplied (no silent TOFU).
/// - They cannot both be supplied — that's an operator error.
/// - On `--no-verify-digest`, the warning is printed.
///
/// Returns `Ok(())` when the flags are coherent; otherwise an error
/// message suitable for surfacing to the operator verbatim.
pub fn validate_digest_flags(
    expect_digest: Option<&str>,
    no_verify_digest: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match (expect_digest, no_verify_digest) {
        (Some(_), false) => Ok(()),
        (None, true) => {
            warn_no_verify_digest();
            Ok(())
        }
        (Some(_), true) => {
            Err("--no-verify-digest may not be combined with --expect-digest; pick one".into())
        }
        (None, false) => Err(
            "--expect-digest <hex> is required (or pass --no-verify-digest to opt out \
             with a warning)"
                .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_producer::{SealedRecipient, seal_for_recipient};

    #[test]
    fn secrets_dir_creates_when_missing() {
        let tmp = std::env::temp_dir().join(format!("vta-test-{}", rand::random::<u32>()));
        let dir = secrets_dir(&tmp).unwrap();
        assert!(dir.exists());
        assert!(dir.ends_with("bootstrap-secrets"));
        // Clean up — test only uses the dir once.
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_request_persists_secret() {
        let tmp = std::env::temp_dir().join(format!("vta-test-{}", rand::random::<u32>()));
        let req = create_bootstrap_request(&tmp, Some("unit-test".into())).unwrap();
        assert!(req.secret_path.exists());
        let bytes = fs::read(&req.secret_path).unwrap();
        assert_eq!(bytes.len(), 32);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn request_seal_open_round_trip() {
        let tmp = std::env::temp_dir().join(format!("vta-test-{}", rand::random::<u32>()));

        // Consumer: create request + persist secret.
        let created = create_bootstrap_request(&tmp, None).unwrap();

        // Producer: seal to the request's pubkey.
        let recipient =
            SealedRecipient::from_json_str(&serde_json::to_string(&created.request).unwrap())
                .unwrap();
        let payload = SealedPayloadV1::AdminCredential(Box::new(
            vta_sdk::credentials::CredentialBundle::new(
                "did:key:z6Mk123",
                "z1234567890",
                "did:key:z6MkVTA",
            ),
        ));
        let sealed = seal_for_recipient(&recipient, &payload).await.unwrap();

        // Write armored to file.
        let bundle_path = tmp.join("bundle.armor");
        fs::write(&bundle_path, sealed.armored.as_bytes()).unwrap();

        // Consumer: open.
        let opened = open_armored_bundle(&bundle_path, &tmp, Some(&sealed.digest), false).unwrap();
        assert_eq!(opened.bundle_id, created.request.decode_nonce().unwrap());

        let cred = extract_admin_credential(opened.payload).unwrap();
        assert_eq!(cred.did, "did:key:z6Mk123");

        // Secret file is removed after successful open.
        assert!(!created.secret_path.exists());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn create_provision_request_persists_seed_and_signs() {
        use vta_sdk::provision_integration::{BootstrapAsk, ProvisionRequestBuilder};

        let tmp = std::env::temp_dir().join(format!("vta-test-{}", rand::random::<u32>()));

        let builder = ProvisionRequestBuilder::new("didcomm-mediator")
            .var("URL", "https://mediator.example.com")
            .context_hint("mediator-prod")
            .admin_template("vta-admin")
            .label("cli-common-test");

        let created = create_provision_request(&tmp, builder).await.unwrap();

        // Seed persisted under bootstrap-secrets/<bundle_id>.key, 32 bytes.
        assert!(created.secret_path.exists(), "secret must be persisted");
        let stem = created.secret_path.file_stem().unwrap().to_str().unwrap();
        assert_eq!(stem, created.bundle_id_hex);
        let bytes = fs::read(&created.secret_path).unwrap();
        assert_eq!(bytes.len(), 32);

        // Bundle id matches the VP nonce (what the producer will use as
        // the sealed-bundle id).
        let verified = created.request.clone().verify().expect("verify VP");
        assert_eq!(
            hex_lower(&verified.decode_nonce().unwrap()),
            created.bundle_id_hex
        );

        // Ask shape preserved through the SDK builder.
        match verified.ask() {
            BootstrapAsk::TemplateBootstrap(ask) => {
                assert_eq!(ask.template.name, "didcomm-mediator");
                assert_eq!(
                    ask.template.vars.get("URL").and_then(|v| v.as_str()),
                    Some("https://mediator.example.com")
                );
                assert_eq!(ask.context_hint.as_deref(), Some("mediator-prod"));
                assert_eq!(
                    ask.admin_template.as_ref().map(|t| t.name.as_str()),
                    Some("vta-admin")
                );
            }
            other => panic!("expected TemplateBootstrap, got {other:?}"),
        }

        // client_did returned matches the VP holder.
        assert_eq!(created.client_did, verified.holder());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn create_provision_request_seed_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        use vta_sdk::provision_integration::ProvisionRequestBuilder;

        let tmp = std::env::temp_dir().join(format!("vta-test-{}", rand::random::<u32>()));
        let builder =
            ProvisionRequestBuilder::new("didcomm-mediator").var("URL", "https://m.example.com");
        let created = create_provision_request(&tmp, builder).await.unwrap();

        let mode = fs::metadata(&created.secret_path)
            .unwrap()
            .permissions()
            .mode();
        // mode & 0o777 isolates the permission bits; must be 0o600.
        assert_eq!(
            mode & 0o777,
            0o600,
            "seed file must be 0600, got {:o}",
            mode & 0o777
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn zero_overwrite_removes_file_and_scrubs_bytes() {
        // Write some non-zero contents, stat the backing storage, run
        // the scrub-then-unlink, confirm the file is gone. We can't
        // reliably probe unlinked blocks from user-space, so the test
        // checks the observable invariant: file is removed. The
        // "bytes zeroed first" property is what item 21 actually
        // wants — proven structurally by the helper's source.
        let tmp = std::env::temp_dir().join(format!("vta-test-zero-{}", rand::random::<u32>()));
        fs::create_dir_all(&tmp).unwrap();
        let f = tmp.join("secret.bin");
        let original: Vec<u8> = (0u8..32).collect();
        fs::write(&f, &original).unwrap();
        assert!(f.exists());

        zero_overwrite_and_remove(&f).expect("remove succeeds");
        assert!(!f.exists(), "file must be removed");
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn zero_overwrite_errors_on_missing_file() {
        let tmp = std::env::temp_dir().join(format!("vta-test-zero-{}", rand::random::<u32>()));
        let missing = tmp.join("does-not-exist");
        let err = zero_overwrite_and_remove(&missing).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn zero_overwrite_handles_empty_file() {
        // A zero-byte file triggers the `len > 0` short-circuit — no
        // write pass, but the unlink must still succeed.
        let tmp = std::env::temp_dir().join(format!("vta-test-zero-{}", rand::random::<u32>()));
        fs::create_dir_all(&tmp).unwrap();
        let f = tmp.join("empty.bin");
        fs::write(&f, b"").unwrap();
        zero_overwrite_and_remove(&f).expect("remove succeeds");
        assert!(!f.exists());
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn open_rejects_missing_digest_without_opt_out() {
        let tmp = std::env::temp_dir().join(format!("vta-test-{}", rand::random::<u32>()));
        fs::create_dir_all(&tmp).unwrap();
        let bundle_path = tmp.join("bundle.armor");
        fs::write(&bundle_path, b"armor placeholder").unwrap();
        let err = open_armored_bundle(&bundle_path, &tmp, None, false).unwrap_err();
        assert!(err.to_string().contains("expect-digest"));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn extract_rejects_did_secrets() {
        let payload =
            SealedPayloadV1::DidSecrets(Box::new(vta_sdk::did_secrets::DidSecretsBundle {
                did: "did:key:z6Mk".into(),
                secrets: vec![],
            }));
        let err = extract_admin_credential(payload).unwrap_err();
        assert!(err.to_string().contains("DidSecrets"));
    }

    #[test]
    fn extract_accepts_context_provision() {
        let payload = SealedPayloadV1::ContextProvision(Box::new(
            vta_sdk::context_provision::ContextProvisionBundle {
                context_id: "app".into(),
                context_name: "App".into(),
                vta_url: None,
                vta_did: None,
                credential: vta_sdk::credentials::CredentialBundle::new(
                    "did:key:z6Mk123",
                    "z1234567890",
                    "did:key:z6MkVTA",
                ),
                admin_did: "did:key:z6Mk123".into(),
                did: None,
            },
        ));
        let cred = extract_admin_credential(payload).unwrap();
        assert_eq!(cred.did, "did:key:z6Mk123");
    }
}
