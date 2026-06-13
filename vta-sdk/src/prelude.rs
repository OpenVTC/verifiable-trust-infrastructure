//! Convenience re-exports for the most commonly used VTA SDK types.
//!
//! ```ignore
//! use vta_sdk::prelude::*;
//! ```

// Error
pub use crate::error::VtaError;

// Keys
pub use crate::keys::{KeyRecord, KeyStatus, KeyType};

// Contexts
pub use crate::contexts::ContextRecord;

// Credentials
pub use crate::credentials::CredentialBundle;

// DID secrets
pub use crate::did_secrets::{DidSecretsBundle, SecretEntry};

// Client (feature-gated)
#[cfg(feature = "client")]
pub use crate::client::{
    AclEntryResponse, AclListResponse, ConfigResponse, ContextListResponse, ContextResponse,
    CreateAclRequest, CreateContextRequest, CreateDidWebvhResponse, CreateKeyRequest,
    CreateKeyResponse, DeleteContextPreviewResponse, DeleteContextResponse, DidTemplate,
    DidTemplateError, DidTemplateRecord, DidTemplateScope, GetKeySecretResponse, HealthResponse,
    ImportKeyRequest, ImportKeyResponse, InvalidateKeyResponse, ListDidsWebvhResponse,
    ListKeysResponse, ListWebvhServersResponse, RenameKeyResponse, SignResponse, TemplateVars,
    UpdateAclRequest, UpdateConfigRequest, UpdateContextDidRequest, VtaClient, WrappingKeyResponse,
};

// Transport-agnostic connect (feature-gated)
#[cfg(feature = "session")]
pub use crate::client::{AutoConnect, ConnectedVta, TokenResult};

// DID key utilities
pub use crate::did_key::{decode_private_key_multibase, ed25519_multibase_pubkey};

#[cfg(feature = "client")]
pub use crate::did_key::secret_from_key_response;

// Integration (feature-gated)
#[cfg(feature = "integration")]
pub use crate::integration::{
    SecretCache, SecretSource, StartupResult, VtaIntegrationError, VtaServiceConfig, authenticate,
    startup,
};

// Protocols — commonly used request/response bodies
pub use crate::protocols::audit_management::list::ListAuditLogsBody;

// Provision client (feature-gated) — integration-side online provisioning
// workflow. See `vta_sdk::provision_client` for the contrast with
// `integration::startup` (provisioning vs runtime startup).
#[cfg(feature = "provision-client")]
pub use crate::provision_client::{
    AdminCredentialReply, AttemptLog, AttemptResult, AttemptResultKind, ConnectedInfo, DiagCheck,
    DiagEntry, DiagStatus, EphemeralSetupKey, InitialChoice, MediatorMessages, OperatorMessages,
    Protocol, ProvisionAsk, ProvisionError, ProvisionResult, ResolvedVta, VtaEvent, VtaIntent,
    VtaReply, WebvhServerMessages, provision_admin_rotated_via_rest, provision_via_didcomm,
    provision_via_rest, resolve_vta, run_connection_test, run_provision, run_provision_flight,
    select_initial_transport,
};
