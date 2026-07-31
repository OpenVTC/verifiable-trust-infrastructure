pub mod backend;
pub mod credentials;

pub use backend::VtaAuthBackend;
/// The shared Trust-Task DI-proof verifier, now owned by `vti-common` so the
/// VTA and the VTC verify a holder proof identically. Re-exported at its
/// original path — `crate::auth::di_proof::verify_trust_task_proof` still
/// resolves for the step-up gate, task consent, and the REST auth route.
pub use vti_common::auth::di_proof;
pub use vti_common::auth::extractor::{
    AdminAuth, AuthClaims, AuthState, ManageAuth, SuperAdminAuth,
};
pub use vti_common::auth::jwt;
pub use vti_common::auth::session;
