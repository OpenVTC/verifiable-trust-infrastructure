//! Integration-side online provisioning workflow.
//!
//! This module is the orchestration layer **above**
//! [`crate::provision_integration`] (wire types) and below the consumer-side
//! UI (TUI, headless CLI, custom). A setup tool that needs to onboard a new
//! integration (mediator, webvh control/daemon/server, future app) against a running VTA
//! drives the workflow through [`run_provision`] (or the lower-level
//! [`provision_via_didcomm`] / [`provision_via_rest`] entry points) and
//! consumes [`VtaEvent`]s on a channel it owns.
//!
//! # Provisioning vs runtime startup
//!
//! Don't confuse this module with [`crate::integration::startup`]. They sit
//! at different points in an integration's lifecycle:
//!
//! - **`provision_client`** (this module) — *one-shot, first-boot*. Mints a
//!   setup `did:key`, asks the VTA to provision a new integration via a DID
//!   template, opens the sealed response bundle, and returns the integration
//!   DID + private keys + admin credential. Runs once per integration.
//!
//! - **`integration::startup`** — *every-boot, runtime*. Loads
//!   already-provisioned credentials and opens a steady-state authenticated
//!   session with the VTA. Runs on every process start.
//!
//! If you're writing setup tooling, you want this module. If you're writing
//! the integration itself, you want `integration::startup`.
//!
//! # TUI-agnostic
//!
//! Nothing in this module depends on a TUI library and nothing writes to
//! stdout/stderr outside [`driver`] (the bundled headless helper, which
//! takes a `&mut dyn Write`). All operator-visible progress is emitted as
//! [`VtaEvent`] values on a consumer-owned `mpsc::Sender`. Consumers route
//! those events into ratatui state, log lines, structured telemetry, or
//! whatever else they need.
//!
//! # Wire format
//!
//! This module never invents wire shapes. The bootstrap request, sealed
//! response, and producer assertion all sit on top of the formats defined
//! by [`crate::provision_integration`] and [`crate::sealed_transfer`]. See
//! the workspace `docs/02-vta/provision-integration.md` for the
//! end-to-end flow.

pub mod ask;
pub(crate) mod auth_rest;
pub mod diagnostics;
pub mod driver;
pub mod error;
pub mod event;
pub mod intent;
pub mod messages;
pub mod resolve;
pub mod result;
pub mod runner;
pub mod runner_didcomm;
pub(crate) mod runner_rest;
pub mod setup_key;

/// Test fixtures available to downstream integration tests.
/// Gated by both `provision-client` (this module) and `test-support`.
#[cfg(any(test, feature = "test-support"))]
pub mod test_helpers;

pub use runner::{
    InitialChoice, provision_admin_rotated_via_rest, provision_via_rest, run_connection_test,
    run_provision, select_initial_transport,
};
pub use runner_didcomm::{
    provision_admin_rotation_via_didcomm, provision_via_didcomm, run_provision_flight,
};

pub use ask::{
    BUILTIN_DID_HOST_DIDCOMM_TEMPLATE, BUILTIN_DID_HOST_HTTP_DIDCOMM_TEMPLATE,
    BUILTIN_DID_HOST_HTTP_TEMPLATE, BUILTIN_MEDIATOR_TEMPLATE, BUILTIN_VTA_ADMIN_TEMPLATE,
    DEFAULT_VALIDITY, ProvisionAsk,
};
/// Cryptographically-sound DI-signed (`eddsa-jcs-2022`) REST authentication for
/// any client holding a key (e.g. a fleet manager authenticating as a per-VTA
/// super-admin). The key signs an `auth/authenticate/0.1` Trust Task — no
/// DIDComm/mediator, and unlike the anoncrypt light path the sender is proven.
pub use auth_rest::challenge_response_di;
pub use diagnostics::{
    ConnectedInfo, DiagCheck, DiagEntry, DiagStatus, Protocol, apply_update, pending_list,
};
pub use error::ProvisionError;
pub use event::{AttemptLog, AttemptResult, AttemptResultKind, VtaEvent};
pub use intent::{AdminCredentialReply, VtaIntent, VtaReply};
pub use messages::{MediatorMessages, OperatorMessages, WebvhServerMessages};
pub use resolve::{ResolvedVta, resolve_vta};
pub use result::{ProvisionResult, admin_rotation_response_to_reply, response_to_result};
pub use setup_key::EphemeralSetupKey;
