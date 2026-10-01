//! Single integration-test binary for vta-service.
//!
//! Every file that used to be its own `tests/*.rs` binary is a `mod` here
//! instead. Each one used to compile and link the whole crate into its own
//! test binary — 37 binaries doing the vast majority of their work (linking
//! `libvta_service`) over and over. One binary, one link.
//!
//! A file's own `#![cfg(feature = "...")]` keeps working unchanged: an inner
//! attribute at the top of a file included via `mod foo;` applies to the
//! `foo` module itself, exactly as if it had been written
//! `#[cfg(feature = "...")] mod foo;` here.
//!
//! Run a single module's tests with `cargo test -p vta-service --test it --
//! <module>::`; see `.github/workflows/ci.yml` for the feature-gated
//! examples.

mod api_integration;
mod app_state_single_construction;
mod approvals_breakglass_cli;
mod atm_profile_mediator_census;
mod audit_sink;
mod auth_authcrypt_sender_binding;
mod auth_flow;
mod authenticate_trust_task;
mod client_round_trip;
mod delegated_consent_e2e;
mod idempotency_trust_task;
mod key_custody_census;
mod keyring_vti_09_23_https;
mod mock_vta;
mod openapi_schema_names;
mod pending_presentation_trust_task;
mod persona_trust_task;
mod producer_payload_conformance;
mod provision_integration_provisionable;
mod push_new_attempt_freshness;
mod refresh_trust_task;
mod revoke_session_trust_task;
mod security;
mod session_jti_pin;
mod sessions_list_trust_task;
mod step_up_approve_response;
mod trust_task_admin;
mod trust_task_did_management;
mod tsp_mediator_account_acl;
mod vault_consent;
mod vault_present;
mod vault_receive;
mod vault_release_didcomm;
mod vault_sign_trust_task_purpose;
mod vault_trust_task;
mod vault_unseal_authcrypt;
mod whoami_trust_task;
