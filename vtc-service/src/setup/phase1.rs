//! Phase 1 of the headless (no-TTY) two-phase setup: mint the ephemeral
//! setup key.
//!
//! `vtc setup --setup-key-out <path> [--context <id>]` mints a fresh
//! ephemeral `did:key`, persists it to `<path>` (0600), and prints the
//! `pnm contexts create … --admin-did <did>` command the operator (or a
//! CI step holding VTA admin) runs to enrol that DID at the VTA. It
//! touches nothing else — no config, no VTA round-trip.
//!
//! This is the counterpart to phase 2
//! ([`run_setup_from_file`](super::run_setup_from_file)), which loads the
//! now-authorised key via `setup_key_file` and provisions end-to-end. The
//! split mirrors the mediator (`mediator-setup --setup-key-out`) and
//! did-hosting (`did-hosting-daemon setup --setup-key-out`) flows: the
//! ACL grant between phases is inherently operator-gated, so a fully
//! headless run persists the key here, an out-of-band step grants it, and
//! phase 2 finishes the job.
//!
//! The heavy lifting (mint → `persist_to` → print the grant block) is the
//! shared SDK helper [`vta_sdk::provision_client::driver::run_phase1_init`];
//! this module only supplies the VTC-specific
//! [`OperatorMessages`](vta_sdk::provision_client::OperatorMessages) impl
//! and the phase-2 finalise hint.

use std::path::Path;

use vti_common::error::AppError;

use super::wizard::VtcHostMessages;

/// `vtc setup --setup-key-out <out_path> --context <context_id>`: mint +
/// persist an ephemeral setup key and print the grant command. `context_id`
/// only shapes the printed `pnm contexts create` line — it must match the
/// `context` in the phase-2 setup TOML.
pub async fn run_setup_phase1(out_path: &Path, context_id: &str) -> Result<(), AppError> {
    let finalise = format!(
        "vtc setup --from <your-setup.toml>   (with setup_key_file = \"{}\")",
        out_path.display()
    );
    vta_sdk::provision_client::driver::run_phase1_init(
        &mut std::io::stderr(),
        out_path,
        context_id,
        &VtcHostMessages,
        Some(&finalise),
    )
    .await
    .map_err(|e| AppError::Internal(format!("phase-1 setup-key mint failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::provision_client::{EphemeralSetupKey, OperatorMessages, driver::run_phase1_init};

    /// Phase 1 writes a loadable, 0600 ephemeral key at the requested path.
    #[tokio::test]
    async fn phase1_persists_loadable_setup_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("vtc-setup-key.json");

        run_setup_phase1(&out, "default")
            .await
            .expect("phase 1 succeeds");

        // Loadable back as an EphemeralSetupKey with a did:key DID.
        let key = EphemeralSetupKey::load_from(&out).expect("load persisted key");
        assert!(
            key.did.starts_with("did:key:z6Mk"),
            "expected an Ed25519 did:key, got {}",
            key.did
        );

        // Owner-only permissions on unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "setup key must be 0600");
        }
    }

    /// The printed block names the context id and the `--admin-did` grant
    /// so the operator can copy-paste it. Drive the shared helper directly
    /// with a capturing writer (the VTC entry hard-codes stderr).
    #[tokio::test]
    async fn phase1_prints_context_scoped_grant_command() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("key.json");
        let mut buf: Vec<u8> = Vec::new();

        run_phase1_init(&mut buf, &out, "acme", &VtcHostMessages, None)
            .await
            .expect("run_phase1_init");

        let printed = String::from_utf8(buf).expect("utf8");
        let did = EphemeralSetupKey::load_from(&out).unwrap().did;
        assert!(printed.contains("pnm contexts create"), "{printed}");
        assert!(printed.contains("--id acme"), "{printed}");
        assert!(printed.contains(&format!("--admin-did {did}")), "{printed}");
        // Sanity: the VTC label drives the printed context wording.
        assert_eq!(VtcHostMessages.integration_label(), "VTC");
    }
}
