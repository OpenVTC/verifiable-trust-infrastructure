//! Shared test fixtures for vtc-service integration tests.
//!
//! Pulled in via `mod common;` from each integration test file —
//! every binary under `tests/` is its own crate, so importable
//! helpers live here.

#[allow(dead_code)] // pulled into different test binaries; not every file uses every helper
pub mod webauthn_harness;
