//! # `vta-sdk` — SDK for Verifiable Trust Agents
//!
//! A Verifiable Trust Agent (VTA) holds a BIP-39 master seed, derives keys
//! via BIP-32, and exposes a REST + DIDComm API to operators and integrations.
//! This crate is the typed client that lets a Rust service:
//!
//! * authenticate against a VTA over REST or DIDComm,
//! * call into every management surface (keys, contexts, ACL, DID templates,
//!   audit, backup, WebVH),
//! * receive secret-bearing bundles via the `sealed_transfer` envelope
//!   (HPKE + ASCII armor + producer assertion),
//! * provision integrations (mediators, WebVH hosts, app identities) end-to-end
//!   via VP-framed bootstrap requests + VC-issued admin authorization.
//!
//! ## Quick start
//!
//! Two-step pattern: import a credential, then call the typed client.
//!
//! ```rust,no_run,ignore
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use vta_sdk::client::VtaClient;
//! use vta_sdk::credentials::CredentialBundle;
//!
//! // The credential is what the operator hands you (a base64 blob the VTA
//! // setup wizard printed, or the result of `pnm bootstrap connect`).
//! let credential = CredentialBundle::decode("<base64-credential>")?;
//! let client = VtaClient::from_credential(&credential, None).await?;
//!
//! // Typed REST surface — `?` returns a `VtaError` with HTTP-aware variants
//! // (Conflict, Gone, Forbidden, NotFound, …) so callers can surface targeted
//! // operator errors instead of stringifying generic failures.
//! let contexts = client.list_contexts().await?;
//! for ctx in contexts {
//!     println!("{} — {}", ctx.id, ctx.label);
//! }
//! # Ok(()) }
//! ```
//!
//! ## Sealed-transfer round-trip
//!
//! See [`sealed_transfer`] for the HPKE envelope used to move credentials,
//! mediator secrets, and DID-secrets bundles between operator hosts:
//!
//! ```rust,ignore
//! use vta_sdk::sealed_transfer::{seal_payload, open_bundle, generate_keypair, ...};
//! ```
//!
//! ## Feature flags
//!
//! The crate is split into opt-in features so a thin types-only consumer
//! doesn't pay the dependency cost of the full client. Pick the smallest
//! set that compiles for your use case.
//!
//! | Feature | What it enables |
//! |---|---|
//! | `client` | Synchronous REST [`client::VtaClient`] (depends on reqwest, ed25519) |
//! | `didcomm` | DIDComm transport types and message helpers |
//! | `session` | Session storage + auth state machine. Needs a persistence backend (`keyring` or `config-session`). |
//! | `keyring` | OS-native session storage via `keyring-core` (macOS Keychain / Windows Credential Manager / Linux Secret Service) |
//! | `config-session` | Plaintext on-disk session storage (dev / non-sensitive contexts only) |
//! | `azure-secrets` | Azure Key Vault session backend (requires `azure-secrets` env). Mutually exclusive with `keyring` at the SDK level. |
//! | `sealed-transfer` | HPKE-sealed bundle envelope (seal, open, armor, producer assertions) |
//! | `provision-integration` | VP-framed bootstrap requests + VC-issued admin authorization |
//! | `provision-client` | Higher-level orchestration over `provision-integration` (TUI-agnostic) |
//! | `attest-verify` | Full AWS Nitro attestation verification (cert chain to AWS root) |
//! | `integration` | Pull-bundle service-startup pattern (combines `client` + `session`) |
//! | `test-support` | In-memory mocks (`SessionBackend`, fixtures) for downstream tests |
//!
//! ## Module map
//!
//! * [`client`] — synchronous REST client + typed request/response shapes
//! * [`didcomm_session`] / [`didcomm_light`] — DIDComm transport
//! * [`session`] — credential storage, login, refresh-token rotation
//! * [`sealed_transfer`] — HPKE envelope (seal/open/armor/verify)
//! * [`provision_integration`] — VP/VC bootstrap flow + typestate verifier
//! * `integration` (feature-gated) — service-startup pull pattern with offline-cache resilience
//! * [`did_templates`] — render-side helpers for the VTA's template registry
//! * [`error`] — [`error::VtaError`] (typed, HTTP-aware, DIDComm-aware)

pub mod error;
pub mod hex;

#[cfg(feature = "attest-verify")]
pub mod attestation;
#[cfg(feature = "client")]
pub mod auth_light;
#[cfg(feature = "client")]
pub mod client;
pub mod context_provision;
pub mod contexts;
pub mod credentials;
pub mod did_key;
pub mod did_secrets;
pub mod did_templates;
#[cfg(feature = "client")]
pub mod didcomm_light;
#[cfg(feature = "session")]
pub mod didcomm_session;
#[cfg(feature = "keyring")]
pub mod keyring_init;
pub mod keys;
pub mod prelude;
pub mod resolver;
// `protocol` itself is always-on (its `services` submodule holds pure
// wire types + the shared `validate_service_url` validator that
// vta-service uses without ever talking to a `VtaClient`). The
// `impl VtaClient` blocks inside are individually `cfg(feature = "client")`-
// gated, so disabling the `client` feature still drops the network
// machinery — but consumers no longer need to flip the feature on
// just to import `protocol::services::validate_service_url`.
pub mod protocol;
pub mod protocols;
#[cfg(feature = "provision-client")]
pub mod provision_client;
#[cfg(feature = "provision-integration")]
pub mod provision_integration;
#[cfg(feature = "sealed-transfer")]
pub mod sealed_transfer;
#[cfg(feature = "session")]
pub mod session;
/// Canonical Trust-Task URLs for VTA operations. Mirrors
/// `did-hosting-common::did_hosting_tasks` for the webvh-service side.
pub mod trust_tasks;
pub mod webvh;

#[cfg(feature = "integration")]
pub mod integration;
