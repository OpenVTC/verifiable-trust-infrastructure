//! Single integration-test binary for vtc-service.
//!
//! Every file that used to be its own `tests/*.rs` binary is a `mod` here
//! instead. Each one used to compile and link the whole crate into its own
//! test binary — 82 binaries doing the vast majority of their work (linking
//! `libvtc_service`) over and over. One binary, one link.
//!
//! A file's own `#![cfg(feature = "...")]` keeps working unchanged: an inner
//! attribute at the top of a file included via `mod foo;` applies to the
//! `foo` module itself, exactly as if it had been written
//! `#[cfg(feature = "...")] mod foo;` here.
//!
//! Run a single module's tests with `cargo test -p vtc-service --test it --
//! <module>::`; see `.github/workflows/ci.yml` for the mediator-backed
//! examples.

mod common;

mod acl_canonical;
mod acl_cli;
mod acl_trust_tasks;
mod acl_vtc_client;
mod admin_authority_stopgaps;
mod admin_bootstrap;
mod admin_config;
mod admin_invites;
mod admin_passkeys;
mod admin_verbs_spine;
mod audit_list;
mod audit_signout;
mod audit_verify;
mod auth_acl_roles;
mod auth_audience;
mod auth_authcrypt_sender_binding;
mod auth_di_trust_task;
mod auth_forged_plaintext;
mod backup;
mod backup_didcomm;
mod ceremonies_list;
mod ceremony_execute;
mod cnm_vtc_admin_live;
mod community_profile;
mod community_verbs_spine;
mod config_identity;
mod console_signed_document;
mod cookie_session;
mod diagnostics;
mod did_log;
mod did_register;
mod didcomm_envelope_binding;
mod directory;
mod emergency_bootstrap;
mod endorsements;
mod git_ns_vtc_client;
mod hidden_vetting_tasks;
mod install_claim;
mod install_flow;
mod invitations;
mod join_didcomm;
mod join_requests;
mod join_tsp;
mod member_push_didcomm;
mod members_crud;
mod no_rebuild;
mod openapi_response_census;
mod openapi_schema_names;
mod openapi_snapshot;
mod passkey_state;
mod passkey_step_up;
mod personhood;
mod policies;
mod policy_canonical;
mod policy_spine;
mod rate_limit_source;
mod recognise;
mod registry_admin;
mod registry_didcomm;
mod relationships;
mod removal;
mod removal_notice_didcomm;
mod renewal;
mod rotation;
mod routing_cors;
mod routing_modes;
mod session_idle_timeout;
mod signed_step_up;
mod status_lists;
mod step_up_passkey_notice_didcomm;
mod step_up_passkey_priority;
mod step_up_passkeys;
mod surface_verbs_spine;
mod test_support_smoke;
mod trust_task_manifest;
mod trust_task_size;
mod unrestricted_admin_consent;
mod vetting_journey;
mod vtc_client_live;
mod wallet_login_siop;
mod webauthn_harness;
mod website_spine;
mod website_task_gating;
