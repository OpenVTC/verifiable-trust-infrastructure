//! Per-subcommand dispatchers for the `pnm` CLI.
//!
//! Each module owns the dispatch table for one top-level (or nested)
//! `Commands::*` arm. `main.rs` is intentionally a thin router: parse
//! → dispatch into one of these modules → exit.
//!
//! Authentication routing lives in [`crate::cli::requires_auth`]; the
//! modules below assume the caller already built (or skipped building)
//! a `VtaClient` per that decision.

pub(crate) mod acl;
pub(crate) mod audit;
pub(crate) mod auth;
pub(crate) mod auth_credential;
pub(crate) mod backup;
pub(crate) mod bootstrap;
pub(crate) mod config;
pub(crate) mod contexts;
pub(crate) mod cred_vault;
pub(crate) mod device;
pub(crate) mod did_templates;
pub(crate) mod health;
pub(crate) mod keys;
pub(crate) mod services;
pub(crate) mod setup;
pub(crate) mod step_up;
pub(crate) mod vault;
pub(crate) mod vta;
pub(crate) mod webvh;
