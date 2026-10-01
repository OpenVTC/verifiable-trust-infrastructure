//! `pnm vta mnemonic open` — decrypt a sealed `vta/attestation/mnemonic-export/1.0`
//! bundle locally, with the key that requested it.
//!
//! Thin, payload-specific wrapper over [`vta_cli_common::sealed_consumer`] (the
//! same armor-decode / HPKE-open pipeline `pnm bootstrap open` uses). It exists
//! because the generic `bootstrap open` prints *any* sealed-bundle kind and,
//! for an installable credential, offers to write it to `--out` — behaviour
//! that is actively wrong for a root seed. This command only accepts a
//! `SeedMnemonic` payload, never writes it anywhere unless `--out` is passed
//! explicitly, and always warns the words are a one-time, offline-only secret.

use std::path::{Path, PathBuf};

use vta_sdk::sealed_transfer::SealedPayloadV1;

use crate::cli::MnemonicCommands;
use crate::config;

pub(crate) async fn run(command: &MnemonicCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        MnemonicCommands::Open {
            bundle,
            expect_digest,
            no_verify_digest,
            out,
            force,
        } => {
            let config_dir = config::config_dir()?;
            run_open_in(
                &config_dir,
                bundle.clone(),
                expect_digest.clone(),
                *no_verify_digest,
                out.clone(),
                *force,
            )
            .await
        }
    }
}

/// [`run`]'s body, with the profile directory taken as a parameter rather
/// than resolved from `$PNM_HOME` — so a test can point it at a tempdir
/// instead of mutating a process-wide env var.
async fn run_open_in(
    config_dir: &Path,
    bundle_path: PathBuf,
    expect_digest: Option<String>,
    no_verify_digest: bool,
    out: Option<PathBuf>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // The seed stored at request time is the only key that opens this
    // bundle; a wrong/missing one fails here with no payload ever decrypted.
    let (opened, secret) = vta_cli_common::sealed_consumer::open_armored_bundle_keeping_secret(
        &bundle_path,
        config_dir,
        expect_digest.as_deref(),
        no_verify_digest,
    )?;

    let mnemonic = match opened.payload {
        SealedPayloadV1::SeedMnemonic(m) => m,
        other => {
            return Err(format!(
                "expected a mnemonic-export bundle (vta/attestation/mnemonic-export/1.0), got {}; \
                 use `pnm bootstrap open` for other sealed-bundle kinds",
                payload_kind(&other)
            )
            .into());
        }
    };

    println!("Mnemonic export opened.");
    println!("  Bundle-Id:       {}", opened.bundle_id_hex);
    println!("  Digest (sha256): {}", opened.digest);
    if let Some(ref did) = mnemonic.vta_did {
        println!("  VTA DID:         {did}");
    }
    println!();
    println!(
        "\x1b[1;33m⚠ This is the VTA's root seed. Anyone who has it can re-derive every key \
         the VTA holds. Write the words down on paper, offline — not a screenshot, not a \
         synced note — then clear this terminal's scrollback. The VTA will not release it \
         again.\x1b[0m"
    );
    println!();
    println!("  {}", mnemonic.mnemonic);

    // The bundle is single-use server-side; consuming the local request seed
    // now matches that on this side too — nothing is left that can decrypt
    // it again (or anything else) once the words are shown.
    vta_cli_common::sealed_consumer::consume_request_secret(&secret);

    if let Some(path) = out {
        vta_cli_common::secure_file::write_secret_export(
            &path,
            mnemonic.mnemonic.as_bytes(),
            force,
        )?;
        println!();
        println!(
            "WARNING: the mnemonic was also written to {} (0600). A file can be synced, \
             backed up, or copied without your noticing — prefer writing it down by hand \
             and deleting this file once you have.",
            path.display()
        );
    } else {
        println!();
        println!(
            "Nothing was written to disk. Re-run with --out <path> only if you understand \
             that risk; the terminal above is the safer copy."
        );
    }

    Ok(())
}

fn payload_kind(p: &SealedPayloadV1) -> &'static str {
    match p {
        SealedPayloadV1::AdminCredential(_) => "AdminCredential",
        SealedPayloadV1::ContextProvision(_) => "ContextProvision",
        SealedPayloadV1::DidSecrets(_) => "DidSecrets",
        SealedPayloadV1::AdminKeySet(_) => "AdminKeySet",
        SealedPayloadV1::RawPrivateKey(_) => "RawPrivateKey",
        SealedPayloadV1::TemplateBootstrap(_) => "TemplateBootstrap",
        SealedPayloadV1::TemplateBootstrapV2(_) => "TemplateBootstrapV2",
        SealedPayloadV1::AdminRotation(_) => "AdminRotation",
        SealedPayloadV1::IssuedCredential(_) => "IssuedCredential",
        SealedPayloadV1::MessagingBridgeCredentials(_) => "MessagingBridgeCredentials",
        SealedPayloadV1::SeedMnemonic(_) => "SeedMnemonic",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use vta_cli_common::sealed_consumer::create_bootstrap_request;
    use vta_cli_common::sealed_producer::{SealedRecipient, seal_for_recipient};
    use vta_sdk::sealed_transfer::SeedMnemonicBundle;

    use super::*;

    fn tmp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("pnm-mnemonic-test-{}", rand::random::<u32>()))
    }

    /// Request a bundle (persists the local ephemeral seed under
    /// `config_dir`), then seal a `SeedMnemonic` payload to it — the shape a
    /// real VTA export response takes. Returns the armored bundle's path, its
    /// out-of-band digest (`seal_for_recipient` uses a `PinnedOnly` producer
    /// assertion, which `open_bundle` always requires a pinned digest for),
    /// and the request, so a test can still reach the persisted seed file.
    async fn seal_mnemonic_bundle(
        config_dir: &Path,
        vta_did: Option<&str>,
    ) -> (
        PathBuf,
        String,
        vta_cli_common::sealed_consumer::CreatedRequest,
    ) {
        let created = create_bootstrap_request(config_dir, None).expect("create request");
        let recipient =
            SealedRecipient::from_json_str(&serde_json::to_string(&created.request).unwrap())
                .unwrap();
        let payload = SealedPayloadV1::SeedMnemonic(Box::new(SeedMnemonicBundle {
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon art"
                .to_string(),
            vta_did: vta_did.map(str::to_string),
        }));
        let sealed = seal_for_recipient(&recipient, &payload).await.unwrap();
        let bundle_path = config_dir.join("bundle.armor");
        fs::write(&bundle_path, sealed.armored.as_bytes()).unwrap();
        (bundle_path, sealed.digest, created)
    }

    /// The happy path: the words come back, the terminal-vs-file contract
    /// holds (no `--out` ⇒ nothing written), and the one-time local secret
    /// is consumed so the bundle cannot be opened again.
    #[tokio::test]
    async fn opens_a_mnemonic_bundle_and_consumes_the_request_secret() {
        let dir = tmp_dir();
        let (bundle_path, digest, created) =
            seal_mnemonic_bundle(&dir, Some("did:example:vta")).await;

        run_open_in(
            &dir,
            bundle_path.clone(),
            Some(digest.clone()),
            false,
            None,
            false,
        )
        .await
        .expect("opens the mnemonic bundle");

        assert!(
            !created.secret_path.exists(),
            "the local request secret must be consumed on a successful open"
        );

        // A second open has no secret left to decrypt with.
        let err = run_open_in(&dir, bundle_path, Some(digest), false, None, false)
            .await
            .expect_err("a consumed request secret must not open a second time");
        assert!(err.to_string().contains("no stored secret"), "{err}");

        let _ = fs::remove_dir_all(&dir);
    }

    /// A wrong key under the right name — the secret file HPKE would use to
    /// open this exact bundle id is not the one the bundle was sealed to
    /// (corrupted store, or a tampered file) — must fail to decrypt rather
    /// than silently returning garbage.
    #[tokio::test]
    async fn a_bundle_opened_with_the_wrong_key_fails() {
        let dir = tmp_dir();
        let (bundle_path, digest, created) = seal_mnemonic_bundle(&dir, None).await;

        // Swap the correct seed for an unrelated one, under the same
        // filename (same bundle id) — the lookup still finds *a* secret,
        // just not the one HPKE needs.
        let wrong_seed: [u8; 32] = rand::random();
        fs::write(&created.secret_path, wrong_seed).expect("overwrite with a wrong seed");

        let err = run_open_in(&dir, bundle_path, Some(digest), false, None, false)
            .await
            .expect_err("a wrong key must not open the bundle");
        // The request secret survives a failed open — nothing was consumed,
        // since nothing was decrypted.
        assert!(created.secret_path.exists());
        drop(err);

        let _ = fs::remove_dir_all(&dir);
    }

    /// Any other sealed-bundle kind is refused by name, pointing at the
    /// generic `pnm bootstrap open` instead of silently mis-handling it.
    #[tokio::test]
    async fn a_non_mnemonic_payload_is_refused() {
        let dir = tmp_dir();
        let created = create_bootstrap_request(&dir, None).expect("create request");
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
        let bundle_path = dir.join("bundle.armor");
        fs::write(&bundle_path, sealed.armored.as_bytes()).unwrap();

        let err = run_open_in(&dir, bundle_path, Some(sealed.digest), false, None, false)
            .await
            .expect_err("an AdminCredential bundle is not a mnemonic export");
        assert!(err.to_string().contains("AdminCredential"), "{err}");
        // Refusing to handle the wrong kind must not burn the one-time
        // secret — the operator can still open it correctly, or with the
        // generic command this error names.
        assert!(created.secret_path.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    /// `--out` writes the words to a file (0600), with an explicit warning;
    /// omitting it writes nothing to disk.
    #[cfg(unix)]
    #[tokio::test]
    async fn out_writes_the_mnemonic_file_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp_dir();
        let (bundle_path, digest, _created) = seal_mnemonic_bundle(&dir, None).await;
        let out_path = dir.join("mnemonic.txt");

        run_open_in(
            &dir,
            bundle_path,
            Some(digest),
            false,
            Some(out_path.clone()),
            false,
        )
        .await
        .expect("opens and writes --out");

        let written = fs::read_to_string(&out_path).unwrap();
        assert!(written.contains("abandon"), "{written}");
        let mode = fs::metadata(&out_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mnemonic file must be 0600");

        let _ = fs::remove_dir_all(&dir);
    }
}
