//! Auto-detect enclave CID from nitro-cli.
//!
//! # Why the helper is named by absolute path
//!
//! `nitro-cli` is a privileged helper: it talks to `/dev/nitro_enclaves` and
//! reports which enclave is running, and the proxy believes what it says about
//! the CID it then bridges vsock traffic to. Spawning it as the bare name
//! `nitro-cli` hands the choice of binary to `$PATH`, so anyone who can write
//! to a directory earlier on the proxy user's `PATH` decides what runs
//! (CWE-426). That is a small window — writing there already implies code
//! execution as that user — but the resolution costs nothing, so there is no
//! reason to leave the lookup in the environment's hands.
//!
//! So: an absolute path, or nothing. `NITRO_CLI` overrides the location for a
//! deployment that installs it elsewhere, but only when it names a plausible
//! helper (absolute, a real file, not writable by group or others) — an
//! override that accepts anything is the same trust decision wearing a
//! different name.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

/// Where `nitro-cli` is installed, tried in order.
///
/// `/usr/bin` is where the `aws-nitro-enclaves-cli` package puts it on AL2 /
/// AL2023, which is what the shipped deployment runs; `/usr/local/bin` covers
/// a source install. Both are root-owned directories on a sane host, which is
/// the property that makes naming them worth anything.
const NITRO_CLI_CANDIDATES: [&str; 2] = ["/usr/bin/nitro-cli", "/usr/local/bin/nitro-cli"];

/// `PATH` handed to the child.
///
/// The child gets a minimal environment rather than the proxy's own, so a
/// `PATH` (or `LD_PRELOAD`, or `IFS`) that influenced *this* process cannot
/// influence whatever `nitro-cli` goes on to execute. `describe-enclaves`
/// reads local state and needs no AWS credentials or region, so there is
/// nothing here worth inheriting.
const CHILD_PATH: &str = "/usr/bin:/bin";

/// Is `path` a helper worth executing as-is?
///
/// `Err` carries the reason so a refusal can be logged: an operator who set
/// `NITRO_CLI` and saw it silently ignored has no way to tell that from "no
/// enclave is running".
fn vet_helper(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute() {
        return Err("not an absolute path");
    }
    let meta = std::fs::metadata(path).map_err(|_| "does not exist")?;
    if !meta.is_file() {
        return Err("not a regular file");
    }
    if group_or_world_writable(&meta) {
        return Err("writable by group or others");
    }
    Ok(())
}

/// Could someone other than the owner rewrite this file?
///
/// A helper anyone can overwrite is no better than one found on `$PATH`: the
/// path is fixed, but what it resolves to is still someone else's choice.
#[cfg(unix)]
fn group_or_world_writable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o022 != 0
}

/// Windows has no mode bits, and this crate is Linux-only in any case (see
/// `Cargo.toml`). The arm exists so the module still compiles under a
/// maintainer's `cargo check`.
#[cfg(not(unix))]
fn group_or_world_writable(_meta: &std::fs::Metadata) -> bool {
    false
}

/// Resolve `nitro-cli` to an absolute path, or `None` if no usable helper is
/// installed.
///
/// Never returns a bare name, and never consults `$PATH`.
fn nitro_cli_path() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("NITRO_CLI") {
        let path = PathBuf::from(configured);
        match vet_helper(&path) {
            Ok(()) => {
                info!(path = %path.display(), "using the nitro-cli named by NITRO_CLI");
                return Some(path);
            }
            Err(reason) => {
                // Refused rather than silently accepted, and refused rather
                // than fatal: the candidates below are still the right answer
                // on a host where NITRO_CLI is a leftover.
                warn!(
                    path = %path.display(),
                    reason,
                    "ignoring NITRO_CLI and looking in the standard locations"
                );
            }
        }
    }

    for candidate in NITRO_CLI_CANDIDATES {
        let path = PathBuf::from(candidate);
        match vet_helper(&path) {
            Ok(()) => {
                info!(path = %path.display(), "resolved nitro-cli");
                return Some(path);
            }
            Err(reason) => {
                // Debug, not warn: on a host with `/usr/bin/nitro-cli` the miss
                // on `/usr/local/bin` is the normal case.
                tracing::debug!(path = %path.display(), reason, "nitro-cli not usable here");
            }
        }
    }

    warn!(
        candidates = ?NITRO_CLI_CANDIDATES,
        "no usable nitro-cli found; set NITRO_CLI to an absolute path if it is installed elsewhere"
    );
    None
}

/// Auto-detect the CID of a running Nitro Enclave.
///
/// Runs `nitro-cli describe-enclaves` and parses the JSON output.
/// Returns `None` if no running enclave is found or nitro-cli isn't available.
pub fn detect_enclave_cid() -> Option<u32> {
    let nitro_cli = nitro_cli_path()?;

    let output = std::process::Command::new(&nitro_cli)
        .arg("describe-enclaves")
        .env_clear()
        .env("PATH", CHILD_PATH)
        .output()
        .ok()?;

    if !output.status.success() {
        warn!(path = %nitro_cli.display(), "nitro-cli describe-enclaves failed");
        return None;
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let enclaves = json.as_array()?;

    for enclave in enclaves {
        if enclave.get("State")?.as_str()? == "RUNNING" {
            let cid = enclave.get("EnclaveCID")?.as_u64()? as u32;
            info!(cid, "auto-detected running enclave");
            return Some(cid);
        }
    }

    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Write an executable `name` in `dir` that touches `marker` and prints an
    /// empty enclave list — a plausible `nitro-cli` whose only observable
    /// effect is evidence that it ran.
    fn plant_fake_helper(dir: &Path, name: &str, marker: &Path, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\n/usr/bin/touch '{}'\necho '[]'\n",
                marker.display()
            ),
        )
        .expect("write the fake helper");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("make the fake helper executable");
        path
    }

    /// `$PATH` must not decide which `nitro-cli` runs, and an unvettable
    /// `NITRO_CLI` must not either.
    ///
    /// One test rather than three because all of it mutates process-global
    /// environment, which `cargo test` would otherwise interleave across
    /// threads — a flake in the one place where a false pass means the
    /// hardening silently is not there.
    ///
    /// The marker file is the real assertion. `nitro_cli_path()` returning
    /// something else proves the *lookup* changed; the marker proves nothing
    /// executed the planted binary, which is the property that matters and the
    /// one a later refactor (back to `Command::new("nitro-cli")`, say) would
    /// break while the path assertion still passed.
    #[test]
    fn path_and_an_unvettable_override_are_both_ignored() {
        let dir = std::env::temp_dir().join(format!(
            "enclave-proxy-detect-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("create the test directory");
        let marker = dir.join("ran");

        let planted = plant_fake_helper(&dir, "nitro-cli", &marker, 0o755);
        // World-writable on purpose: the shape `NITRO_CLI` must refuse.
        let world_writable = plant_fake_helper(&dir, "nitro-cli-loose", &marker, 0o777);

        let restore_path = std::env::var_os("PATH");
        let restore_nitro = std::env::var_os("NITRO_CLI");
        // SAFETY (edition 2024): this test owns these two variables for its
        // duration and restores them before returning.
        unsafe {
            let prepended = match &restore_path {
                Some(existing) => format!("{}:{}", dir.display(), existing.to_string_lossy()),
                None => dir.display().to_string(),
            };
            std::env::set_var("PATH", prepended);
            std::env::remove_var("NITRO_CLI");
        }

        let resolved = nitro_cli_path();
        assert_ne!(
            resolved.as_deref(),
            Some(planted.as_path()),
            "a nitro-cli earlier on $PATH must never be chosen: {resolved:?}"
        );
        assert!(
            resolved
                .as_ref()
                .is_none_or(|p| NITRO_CLI_CANDIDATES.iter().any(|c| p == Path::new(c))),
            "only the vetted absolute candidates may be returned, got {resolved:?}"
        );

        // SAFETY: as above.
        unsafe { std::env::set_var("NITRO_CLI", &world_writable) }
        let with_loose_override = nitro_cli_path();
        assert_ne!(
            with_loose_override.as_deref(),
            Some(world_writable.as_path()),
            "NITRO_CLI naming a group/world-writable file must be refused: \
             {with_loose_override:?}"
        );

        // SAFETY: as above.
        unsafe { std::env::remove_var("NITRO_CLI") }
        let _ = detect_enclave_cid();
        assert!(
            !marker.exists(),
            "detect_enclave_cid() executed the planted nitro-cli — the helper \
             is still being resolved through the environment"
        );

        // SAFETY: as above.
        unsafe {
            match restore_path {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
            if let Some(n) = restore_nitro {
                std::env::set_var("NITRO_CLI", n);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A relative `NITRO_CLI` is refused outright: resolving it would reopen
    /// the working directory as a second search path.
    #[test]
    fn a_relative_helper_is_refused() {
        assert_eq!(
            vet_helper(Path::new("nitro-cli")),
            Err("not an absolute path")
        );
        assert_eq!(
            vet_helper(Path::new("./bin/nitro-cli")),
            Err("not an absolute path")
        );
    }

    #[test]
    fn a_missing_helper_is_refused() {
        assert_eq!(
            vet_helper(Path::new("/nonexistent/nitro-cli")),
            Err("does not exist")
        );
    }

    #[test]
    fn a_directory_is_not_a_helper() {
        assert_eq!(vet_helper(Path::new("/tmp")), Err("not a regular file"));
    }
}
