// build.rs — builds the admin SPA before `include_dir!` reads it.
//
// The admin UI is a Vite/React/TS project under `admin-ui/`. Vite
// produces a bundle that `src/admin_ui.rs` bakes into the binary
// via `include_dir!`. To keep `cargo build` self-contained,
// build.rs invokes `npm install` + `npm run build` before src/
// compiles.
//
// Trade-off accepted: Rust devs need a working node + npm install
// to build vtc-service. This is the workspace's first npm-in-build
// dependency. Skipping the build is supported via an env var
// (`VTC_SKIP_ADMIN_UI_BUILD=1`) so CI matrices or air-gapped
// environments that ship a pre-built `admin-ui/dist/` can opt out.
//
// `cargo:rerun-if-changed` directives are scoped to admin-ui
// sources only, so building unrelated parts of vtc-service doesn't
// re-trigger npm.
//
// # Why nothing here writes into the source tree (#1243)
//
// A build script must only write under `OUT_DIR`. Writing to the
// source tree feeds the next build's staleness check, and this
// crate hit both halves of that trap: `cargo build -p vtc-service`
// was never a no-op — it re-ran npm and recompiled the crate from
// scratch every single time, so every local build, test, clippy run
// and rust-analyzer check-on-save paid for it.
//
// Two writes caused it:
//
//  1. `npm install` rewrites `admin-ui/package-lock.json`. The
//     content is unchanged — `git status` stays clean, which is why
//     nothing looked wrong — but the mtime is not, and the lockfile
//     is a `rerun-if-changed` input of the very script that just
//     rewrote it. So the script was dirty the instant it finished
//     and re-ran on every build. Of the six watched paths this is
//     the only one npm moves, which makes it the whole pump.
//
//  2. `npm run build` regenerated `admin-ui/dist`, and
//     `include_dir!` expands to one `include_bytes!` per file, so
//     all 78 of them are compile inputs of the lib (312 entries in
//     `vtc_service-*.d`). Every re-run of (1) refreshed their
//     mtimes, turning a cheap script re-run into a full recompile.
//
// So, two fixes, and they are not interchangeable:
//
//  a. `run_npm_preserving_lockfile` restores the lockfile's mtime
//     when npm left the content byte-identical. This is the one
//     that actually closes the loop — with the script no longer
//     re-running, nothing regenerates the bundle either.
//  b. Vite writes to `$OUT_DIR`, never `admin-ui/dist`. This is the
//     Cargo rule rather than the bug fix, and it earns its keep
//     independently: `admin-ui/README.md` tells developers to run
//     `npm run build` by hand, and while the bundle lived in the
//     source tree doing so refreshed 78 compile inputs and forced a
//     full rebuild of the crate.
//
// Note what is deliberately *not* here: an attempt to keep mtimes
// stable across a re-run so the lib survives it. That was measured
// and it does nothing — cargo rebuilds a build script's dependents
// whenever the script re-runs, whether or not its output changed.
// The only thing that helps is not re-running it.
//
// Regression test: `tests/no_rebuild.rs`, plus the "vtc-service
// rebuild is a no-op" step in `.github/workflows/ci.yml`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Directory under `OUT_DIR` that `src/admin_ui.rs` bakes in via
/// `include_dir!("$OUT_DIR/admin-ui-dist")`. Keep the two in sync.
const BAKED_DIR: &str = "admin-ui-dist";

/// File under `OUT_DIR` where this script records what it did to
/// the lockfile, for `tests/no_rebuild.rs` to check. See
/// [`LockfileVerdict`].
const LOCKFILE_VERDICT: &str = "lockfile-verdict";

/// What happened to `package-lock.json` on this run.
///
/// The test needs to distinguish "npm moved the mtime and we failed
/// to put it back" — the #1243 bug — from "npm genuinely re-resolved
/// the lockfile", which is a legitimate one-off rebuild and happens
/// on a fresh checkout whenever the runner's npm normalises a
/// lockfile written by a different version. Comparing mtimes from
/// the test can't tell those apart; this script can, so it says so
/// rather than leaving the test to guess.
enum LockfileVerdict {
    /// npm never ran (skip flag, or no `admin-ui` feature).
    NotRun,
    /// npm left the content byte-identical and the mtime is back
    /// where it was. The steady state.
    Restored,
    /// npm re-resolved the lockfile for real. The mtime is
    /// deliberately left alone so the change is picked up; the next
    /// build settles.
    ContentChanged,
    /// The mtime restore itself failed. This is the one that means
    /// the crate will rebuild on every `cargo build`.
    RestoreFailed(String),
}

impl LockfileVerdict {
    fn record(&self) {
        let line = match self {
            Self::NotRun => "not-run".to_string(),
            Self::Restored => "restored".to_string(),
            Self::ContentChanged => "content-changed".to_string(),
            Self::RestoreFailed(e) => format!("restore-failed: {e}"),
        };
        let _ = std::fs::write(out_dir().join(LOCKFILE_VERDICT), line);
    }
}

fn main() {
    // Re-run when admin-ui source changes; leave the rest of the
    // crate alone.
    println!("cargo:rerun-if-changed=admin-ui/src");
    println!("cargo:rerun-if-changed=admin-ui/index.html");
    println!("cargo:rerun-if-changed=admin-ui/package.json");
    println!("cargo:rerun-if-changed=admin-ui/package-lock.json");
    println!("cargo:rerun-if-changed=admin-ui/vite.config.ts");
    println!("cargo:rerun-if-changed=admin-ui/tsconfig.json");
    println!("cargo:rerun-if-env-changed=VTC_SKIP_ADMIN_UI_BUILD");

    if std::env::var("VTC_SKIP_ADMIN_UI_BUILD").is_ok() {
        eprintln!(
            "build.rs: VTC_SKIP_ADMIN_UI_BUILD set, skipping admin-ui build (expecting a \
             pre-built admin-ui/dist/)"
        );
        LockfileVerdict::NotRun.record();
        adopt_prebuilt_dist();
        return;
    }

    if std::env::var("CARGO_FEATURE_ADMIN_UI").is_err() {
        // Crate built without `admin-ui` feature — `include_dir!`
        // isn't referencing the baked dir, so no need to build.
        // Still make sure the directory exists as an empty stub so
        // the `include_dir!` macro doesn't error if it ever gets
        // evaluated.
        LockfileVerdict::NotRun.record();
        ensure_baked_dir_exists();
        return;
    }

    build_admin_ui();
}

fn admin_ui_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("admin-ui")
}

fn out_dir() -> PathBuf {
    PathBuf::from(std::env::var("OUT_DIR").expect("build.rs: OUT_DIR is always set by cargo"))
}

/// The directory `include_dir!` bakes in. Lives under `OUT_DIR`, so
/// producing it never dirties the source tree.
fn baked_dir() -> PathBuf {
    out_dir().join(BAKED_DIR)
}

/// Guarantee the baked directory exists with at least one file —
/// `include_dir!` on a missing directory is a hard compile error.
fn ensure_baked_dir_exists() {
    let baked = baked_dir();
    if baked.join("index.html").exists() {
        return;
    }
    std::fs::create_dir_all(&baked).ok();
    let placeholder = baked.join(".gitkeep");
    if !placeholder.exists() {
        let _ = std::fs::write(
            &placeholder,
            "# admin-ui bundle not built — unset VTC_SKIP_ADMIN_UI_BUILD or ship a pre-built \
             admin-ui/dist/\n",
        );
    }
}

/// `VTC_SKIP_ADMIN_UI_BUILD=1` path. The documented contract is
/// "ship a pre-built `admin-ui/dist/`", so honour it by copying that
/// directory into the baked one. Air-gapped builds keep working; CI
/// jobs that only want npm skipped (and bake nothing) fall through
/// to the placeholder.
fn adopt_prebuilt_dist() {
    let prebuilt = admin_ui_dir().join("dist");
    if prebuilt.join("index.html").exists() {
        // Read-only on this path: a pre-built dist is an *input*
        // here, so watching it is honest and nothing is written back
        // into the source tree.
        println!("cargo:rerun-if-changed=admin-ui/dist");
        copy_dir(&prebuilt, &baked_dir());
        return;
    }
    ensure_baked_dir_exists();
}

fn build_admin_ui() {
    let admin_ui = admin_ui_dir();

    if !admin_ui.exists() {
        panic!(
            "build.rs: admin-ui directory missing at {}",
            admin_ui.display()
        );
    }

    // npm install — idempotent; npm decides whether to do work.
    // Wrapped so a no-op install doesn't leave the lockfile newer
    // than this script's own output stamp (see the header).
    run_npm_preserving_lockfile(&admin_ui);

    // npm run build — vite writes straight into OUT_DIR, never the
    // source tree. `--emptyOutDir` is required because the target
    // sits outside the vite project root.
    let baked = baked_dir();
    let baked_arg = baked
        .to_str()
        .expect("build.rs: OUT_DIR is not valid UTF-8")
        .to_string();
    run_npm(
        &admin_ui,
        &[
            "run",
            "build",
            "--",
            "--outDir",
            &baked_arg,
            "--emptyOutDir",
        ],
    );

    // Sanity: index.html must exist or include_dir! has nothing to
    // bake. Fail loud rather than silently shipping an empty admin
    // UI.
    let index = baked.join("index.html");
    if !index.exists() {
        panic!(
            "build.rs: admin-ui build did not produce {}; check `npm run build` output",
            index.display()
        );
    }
}

/// `npm install`, with the lockfile's mtime restored if npm left the
/// content byte-identical.
///
/// npm rewrites `package-lock.json` on essentially every install,
/// usually with identical bytes. That file is a `rerun-if-changed`
/// input, so an unconditional rewrite keeps this script dirty
/// forever (#1243). Comparing content — rather than always restoring
/// the timestamp — keeps a *real* lockfile update (a dependency npm
/// re-resolved) triggering a rebuild the way it should.
fn run_npm_preserving_lockfile(admin_ui: &Path) {
    let lockfile = admin_ui.join("package-lock.json");
    let before = std::fs::read(&lockfile).ok();
    let mtime = std::fs::metadata(&lockfile).and_then(|m| m.modified()).ok();

    run_npm(admin_ui, &["install", "--no-audit", "--no-fund"]);

    let (Some(before), Some(mtime)) = (before, mtime) else {
        LockfileVerdict::NotRun.record();
        return;
    };
    if std::fs::read(&lockfile).ok().as_deref() != Some(&before[..]) {
        // npm genuinely re-resolved the lockfile. Leave the new
        // mtime alone so the next build picks the change up — one
        // rebuild, then it settles. Common on a fresh checkout when
        // the local npm normalises a lockfile written by another
        // version; if it happens on every clean checkout, regenerate
        // and commit the lockfile.
        LockfileVerdict::ContentChanged.record();
        return;
    }
    match std::fs::File::options()
        .write(true)
        .open(&lockfile)
        .and_then(|f| f.set_times(std::fs::FileTimes::new().set_modified(mtime)))
    {
        Ok(()) => LockfileVerdict::Restored.record(),
        Err(e) => {
            // Not fatal: the build is still correct, it just loses
            // the no-op-rebuild property. Say so rather than failing.
            println!(
                "cargo:warning=could not restore package-lock.json mtime ({e}); vtc-service will \
                 rebuild on every cargo invocation (see #1243)"
            );
            LockfileVerdict::RestoreFailed(e.to_string()).record();
        }
    }
}

/// Recursively copy `src` over `dst`, dropping anything in `dst`
/// that `src` no longer has so a renamed asset can't linger in the
/// baked output. Only used for the pre-built-dist path — vite writes
/// to `OUT_DIR` directly.
fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst)
        .unwrap_or_else(|e| panic!("build.rs: cannot create {}: {e}", dst.display()));

    if let Ok(entries) = std::fs::read_dir(dst) {
        for entry in entries.flatten() {
            if src.join(entry.file_name()).exists() {
                continue;
            }
            let path = entry.path();
            let _ = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
        }
    }

    let entries = std::fs::read_dir(src)
        .unwrap_or_else(|e| panic!("build.rs: cannot read {}: {e}", src.display()));
    for entry in entries.flatten() {
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir(&from, &to);
            continue;
        }
        std::fs::copy(&from, &to).unwrap_or_else(|e| {
            panic!(
                "build.rs: cannot copy {} to {}: {e}",
                from.display(),
                to.display()
            )
        });
    }
}

fn run_npm(cwd: &Path, args: &[&str]) {
    let npm = std::env::var("VTC_NPM").unwrap_or_else(|_| "npm".to_string());
    eprintln!(
        "build.rs: running `{npm} {args}` in {cwd}",
        npm = npm,
        args = args.join(" "),
        cwd = cwd.display()
    );
    let status = Command::new(&npm)
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "build.rs: failed to spawn `{npm}`: {e}. Install Node.js (https://nodejs.org) or \
                 set VTC_SKIP_ADMIN_UI_BUILD=1 and ship a pre-built dist/."
            )
        });
    if !status.success() {
        panic!(
            "build.rs: `{npm} {}` exited with {status}. Re-run manually in admin-ui/ for full \
             output.",
            args.join(" ")
        );
    }
}
