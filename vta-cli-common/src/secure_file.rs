//! Cross-platform file / directory permission tightening for secret-bearing
//! paths (bootstrap seeds, keystores, export bundles).
//!
//! The implementation is homed in [`vti_common::secure_file`] so it can be
//! shared by every consumer (CLIs, services, and the `vti-secrets` crate's
//! plaintext backend) without duplication. This module re-exports it for
//! backwards-compatible `vta_cli_common::secure_file::*` call sites.

pub use vti_common::secure_file::{restrict_dir_to_owner, restrict_file_to_owner};
