pub mod acl;
#[cfg(feature = "tee")]
pub mod attestation;
pub mod audit;
pub mod backup;
pub mod cache;
pub mod config;
pub mod contexts;
pub mod credential_exchange;
pub mod device;
pub mod did_templates;
#[cfg(feature = "webvh")]
pub mod did_webvh;
/// Offline state-assembly helpers: read the VTA's local store and
/// produce the same wire-shape bundles (`DidSecretsBundle`,
/// `ContextProvisionBundle`) that the equivalent `VtaClient` flows
/// build over REST. Used by the on-host `vta context reprovision` /
/// `vta keys bundle` CLIs for cold-start environments where PNM can't
/// reach the VTA over the network.
pub mod export;
/// ACL-gated holder-key resolution for credential presentation — derive the
/// VTA-managed subject key (kb-jwt signer + consent secret), refusing keys
/// outside the caller's authorised context.
pub mod holder_keys;
pub mod internal_authority;
pub mod keys;
/// Passkey login — DID-VM-resolved WebAuthn assertion verification.
/// Drives `vta/auth/passkey-login-{start,finish}/1.0` trust-tasks.
/// Distinct from [`passkey_vms`] which handles VM *enrolment*.
pub mod passkey_login;
/// Passkey-as-verificationMethod enrolment. Lets a browser wallet
/// (`pnm-browser-plugin`) add a WebAuthn passkey as a Multikey VM
/// (purpose `authentication`) on a VTA-managed webvh DID. See
/// `docs/02-vta/passkey-verification-methods.md`.
#[cfg(feature = "webvh")]
pub mod passkey_vms;
/// DIDComm protocol management: enable/disable/migrate operations that
/// patch the VTA's own DID document service array. See
/// `docs/05-design-notes/didcomm-protocol-management.md`.
#[cfg(feature = "webvh")]
pub mod protocol;
/// Generic template-driven integration bootstrap. See
/// `docs/02-vta/provision-integration.md`. Feature-gated on `webvh`
/// because the phase-1 implementation delegates minting to
/// `create_did_webvh`.
#[cfg(feature = "webvh")]
pub mod provision_integration;
pub mod seeds;
pub mod step_up_approval;
pub mod step_up_policy;
pub mod vault;

use crate::store::KeyspaceHandle;

/// Shared keyspace handles passed to operations that need multiple keyspaces.
pub struct Keyspaces<'a> {
    pub keys: &'a KeyspaceHandle,
    pub acl: &'a KeyspaceHandle,
    pub contexts: &'a KeyspaceHandle,
    pub did_templates: &'a KeyspaceHandle,
    pub audit: &'a KeyspaceHandle,
    pub imported: &'a KeyspaceHandle,
    #[cfg(feature = "webvh")]
    pub webvh: &'a KeyspaceHandle,
}

impl<'a> Keyspaces<'a> {
    /// Borrow keyspaces from an `AppState`.
    pub fn from_app_state(s: &'a crate::server::AppState) -> Self {
        Self {
            keys: &s.keys_ks,
            acl: &s.acl_ks,
            contexts: &s.contexts_ks,
            did_templates: &s.did_templates_ks,
            audit: &s.audit_ks,
            imported: &s.imported_ks,
            #[cfg(feature = "webvh")]
            webvh: &s.webvh_ks,
        }
    }

    /// Borrow keyspaces from a `VtaState` (DIDComm handlers).
    #[cfg(feature = "didcomm")]
    pub fn from_vta_state(s: &'a crate::messaging::router::VtaState) -> Self {
        Self {
            keys: &s.keys_ks,
            acl: &s.acl_ks,
            contexts: &s.contexts_ks,
            did_templates: &s.did_templates_ks,
            audit: &s.audit_ks,
            imported: &s.imported_ks,
            #[cfg(feature = "webvh")]
            webvh: &s.webvh_ks,
        }
    }
}
