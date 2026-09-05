//! Regression guard for #1243 — `cargo build -p vtc-service` must
//! be a no-op when nothing changed.
//!
//! It wasn't, for two compounding reasons, and both were writes
//! `build.rs` made into the source tree:
//!
//!  1. `npm install` rewrote `admin-ui/package-lock.json` — same
//!     bytes, new mtime — and that file is a `rerun-if-changed`
//!     input of the script that just rewrote it. The build script
//!     was therefore dirty the instant it finished, so it re-ran on
//!     every single `cargo build`.
//!  2. `include_dir!` makes every baked file a compile input of the
//!     lib, and `npm run build` regenerated all of them into
//!     `admin-ui/dist`. So each re-run of (1) refreshed those
//!     mtimes and forced a full recompile of the crate.
//!
//! The honest end-to-end test is "build twice, assert the second is
//! `Fresh`", which needs a nested cargo invocation and minutes of
//! wall clock. CI does that (`.github/workflows/ci.yml`, the
//! "vtc-service rebuild is a no-op" step). These tests instead pin
//! the two *structural* properties that made it possible, cheaply
//! enough to run on every `cargo test` and with a far more specific
//! failure message than a timing test could give.
//!
//! Both read state left behind by the build script that produced
//! this test binary, so they describe the build actually running
//! them.

use std::path::PathBuf;

/// `OUT_DIR` is `<target>/<profile>/build/vtc-service-<hash>/out`.
fn out_dir() -> PathBuf {
    PathBuf::from(env!("OUT_DIR"))
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Cause 2: the baked admin-UI bundle must live under `OUT_DIR`,
/// never in the source tree.
///
/// `include_dir!` expands to one `include_bytes!` per file, so
/// every one of the 78 baked files is a compile input of the lib
/// (312 entries across `vtc_service-*.d`). A build script that
/// regenerates those files where cargo is watching them turns every
/// build into a full recompile. Keeping the directory in `OUT_DIR`
/// is what makes that structurally impossible.
#[test]
fn baked_admin_ui_lives_outside_the_source_tree() {
    let baked = out_dir().join("admin-ui-dist");
    assert!(
        baked.is_dir(),
        "expected the baked admin-UI bundle at {}; build.rs's BAKED_DIR and the include_dir! \
         path in src/admin_ui.rs have to agree",
        baked.display()
    );
    assert!(
        !baked.starts_with(manifest_dir()),
        "the baked admin-UI bundle is inside the source tree at {}. include_dir! makes every \
         file in it a compile input, so regenerating it there recompiles the whole crate on \
         every build (#1243). Point vite's --outDir at OUT_DIR.",
        baked.display()
    );
}

/// Cause 1: a content-preserving `npm install` must not leave
/// `package-lock.json`'s mtime moved.
///
/// The lockfile is one of the build script's own
/// `rerun-if-changed` inputs, so moving its mtime makes the script
/// dirty the moment it finishes — and it failed silently, because
/// the content never changed and `git status` stayed clean.
///
/// This reads the verdict `build.rs` recorded rather than comparing
/// mtimes here, because an mtime comparison cannot tell the bug
/// apart from the legitimate case beside it: npm *re-resolving* the
/// lockfile for real, which moves the mtime, is supposed to rebuild,
/// and happens on a fresh checkout whenever the local npm
/// normalises a lockfile written by a different version. Asserting
/// on mtimes failed in CI for exactly that reason. `build.rs` knows
/// which case it was in; the test just asks.
#[test]
fn content_preserving_npm_install_does_not_move_the_lockfile() {
    let verdict_path = out_dir().join("lockfile-verdict");
    let Ok(verdict) = std::fs::read_to_string(&verdict_path) else {
        // Written unconditionally on every path through build.rs,
        // so its absence means the script predates this guard.
        panic!(
            "build.rs recorded no lockfile verdict at {}; it must write one on every path",
            verdict_path.display()
        );
    };
    let verdict = verdict.trim();

    if let Some(err) = verdict.strip_prefix("restore-failed: ") {
        panic!(
            "build.rs could not restore package-lock.json's mtime after a content-preserving \
             `npm install`: {err}\nThe lockfile is a `cargo:rerun-if-changed` input of the \
             build script itself, so the script is now dirty and will re-run on every `cargo \
             build` — regenerating the baked admin UI and recompiling the crate (#1243)."
        );
    }

    assert!(
        matches!(verdict, "restored" | "content-changed" | "not-run"),
        "unrecognised lockfile verdict {verdict:?} from build.rs; teach this test the new \
         variant rather than widening the match"
    );
}
