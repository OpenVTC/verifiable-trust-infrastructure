pub mod backend;
pub mod credentials;

pub use backend::VtaAuthBackend;
pub use vti_common::auth::extractor::{
    AdminAuth, AuthClaims, AuthState, ManageAuth, SuperAdminAuth,
};
pub use vti_common::auth::jwt;
pub use vti_common::auth::session;
/// The shared Trust-Task DI-proof verifier. Owned by `vta-sdk` since a *client*
/// needed the same check a service does — `vti-common` re-exports it, and this
/// re-exports that, so `crate::auth::verify_trust_task_proof` still resolves for
/// the step-up gate, task consent, and the REST auth route.
pub use vti_common::auth::{
    DiProofError, TrustTaskVmResolver, verify_trust_task_proof, verify_trust_task_proof_with,
};
