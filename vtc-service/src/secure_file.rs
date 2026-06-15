//! Owner-only permission hardening for secret-bearing files written by the
//! VTC service (`config.toml` — carries `auth.jwt_signing_key` and, under the
//! config-secret backend, the hex `VtcKeyBundle`; `secret.plaintext` — the
//! dev secret store).
//!
//! The implementation is homed in [`vti_common::secure_file`] (shared
//! workspace-wide); this module re-exports it for the existing
//! `crate::secure_file::restrict_file_to_owner` call sites.

pub use vti_common::secure_file::{restrict_dir_to_owner, restrict_file_to_owner};
