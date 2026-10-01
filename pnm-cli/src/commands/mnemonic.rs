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

use std::path::PathBuf;

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
            run_open(
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

async fn run_open(
    bundle_path: PathBuf,
    expect_digest: Option<String>,
    no_verify_digest: bool,
    out: Option<PathBuf>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = config::config_dir()?;

    // The seed stored at request time is the only key that opens this
    // bundle; a wrong/missing one fails here with no payload ever decrypted.
    let (opened, secret) = vta_cli_common::sealed_consumer::open_armored_bundle_keeping_secret(
        &bundle_path,
        &config_dir,
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
