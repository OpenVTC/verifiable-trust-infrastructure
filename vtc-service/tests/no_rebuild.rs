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
//! the two *structural* properties that made it possible, which is
//! cheap enough to run on every `cargo test` and fails with a much
//! more specific message than a slow timing test would.
//!
//! Both read state left behind by the build script that produced
//! this test binary, so they describe the build that is actually
//! running them.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// `OUT_DIR` is `<target>/<profile>/build/vtc-service-<hash>/out`.
fn out_dir() -> PathBuf {
    PathBuf::from(env!("OUT_DIR"))
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
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

/// Cause 1: the build script must not leave a `rerun-if-changed`
/// input newer than its own output stamp.
///
/// That comparison — every watched path against
/// `build/<pkg>-<hash>/output` — is literally how cargo decides to
/// re-run a build script, so asserting it here asserts the real
/// condition rather than a proxy for it. `npm install` rewriting
/// the lockfile with identical bytes was enough to fail it, and it
/// failed silently: the content never changed, so `git status`
/// stayed clean and nothing looked wrong.
///
/// Vacuous under `VTC_SKIP_ADMIN_UI_BUILD=1`, which is correct —
/// that path never runs npm, so there is nothing to have moved.
#[test]
fn build_script_left_no_watched_input_newer_than_its_stamp() {
    // OUT_DIR is `<...>/vtc-service-<hash>/out`; the stamp cargo
    // compares against is its sibling.
    let Some(stamp) = out_dir().parent().map(|p| p.join("output")) else {
        panic!("OUT_DIR has no parent: {}", out_dir().display());
    };
    let Some(stamp_mtime) = mtime(&stamp) else {
        // No stamp means the script never ran for this build (a
        // fully cached artifact reused from elsewhere). Nothing to
        // assert.
        return;
    };

    // The six paths build.rs declares, in the same order.
    let watched = [
        "admin-ui/src",
        "admin-ui/index.html",
        "admin-ui/package.json",
        "admin-ui/package-lock.json",
        "admin-ui/vite.config.ts",
        "admin-ui/tsconfig.json",
    ];

    let mut offenders = Vec::new();
    for rel in watched {
        let path = manifest_dir().join(rel);
        let Some(path_mtime) = mtime(&path) else {
            continue;
        };
        if path_mtime > stamp_mtime {
            let by = path_mtime
                .duration_since(stamp_mtime)
                .map(|d| format!("{:.3}s", d.as_secs_f64()))
                .unwrap_or_else(|_| "?".to_string());
            offenders.push(format!("{rel} (newer by {by})"));
        }
    }

    assert!(
        offenders.is_empty(),
        "build.rs left these watched inputs newer than its own output stamp: {}.\ncargo \
         compares exactly these mtimes against {}, so the build script is now dirty and will \
         re-run on every `cargo build` — which regenerates the baked admin UI and recompiles \
         the crate (#1243). A build script must not write into the source tree; if npm has to \
         touch a watched file, restore its mtime when the content is unchanged.",
        offenders.join(", "),
        stamp.display()
    );
}
