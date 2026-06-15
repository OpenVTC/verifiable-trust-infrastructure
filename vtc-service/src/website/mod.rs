//! Public community website (§12.1, Phase 5 M5.4).
//!
//! Filesystem-backed static hosting at
//! [`crate::config::WebsiteConfig::root_dir`]. No template engine,
//! no opinions about site structure — operators populate the
//! directory via `scp` / `rsync` / `git` or via the management API
//! shipping in M5.5.
//!
//! ## Deploy modes
//!
//! - **`live`** (default): files served as-is from `root_dir`.
//!   Bundle deploys (M5.5) extract via a staging directory +
//!   atomic rename to avoid partial reads under concurrent
//!   serving.
//! - **`managed`**: `root_dir/gen-N/` directories with a
//!   `root_dir/current` symlink. Bundle deploys extract to a fresh
//!   generation; rollback flips the symlink. Older generations
//!   beyond `managed_generations_keep` are pruned by the management
//!   API.
//!
//! ## Path safety
//!
//! Everything in [`paths`] runs in front of the filesystem open.
//! Path safety failures surface as `WebsitePathRejected` /
//! `WebsiteBlockedExtension` from [`crate::error`] — never bare
//! 404s — so the audit trail records the rejection rationale.

#[cfg(feature = "website")]
pub mod bundle;
#[cfg(feature = "website")]
pub mod cache;
#[cfg(feature = "website")]
pub mod default_site;
#[cfg(feature = "website")]
pub mod paths;
#[cfg(feature = "website")]
pub mod serve;
#[cfg(feature = "website")]
pub mod storage;

#[cfg(feature = "website")]
pub use serve::{CspOverrideCache, WebsiteState, serve};
#[cfg(feature = "website")]
pub use storage::WebsiteRoot;
