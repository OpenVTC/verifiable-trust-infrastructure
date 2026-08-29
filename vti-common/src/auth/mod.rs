pub mod backend;
pub mod di_proof;
pub mod didcomm;
pub mod extractor;
pub mod handlers;
pub mod jwt;
#[cfg(feature = "passkey")]
pub mod passkey;
pub mod session;
pub mod siop;
pub mod step_up;
pub mod vm_resolver;

pub use backend::{
    AttestationOutcome, AuthAuditEvent, AuthBackend, AuthError, AuthenticateInput, ChallengeInput,
    RefreshInput, RoleResolution, SessionStore,
};
pub use di_proof::{DiProofError, verify_trust_task_proof, verify_trust_task_proof_with};
pub use didcomm::{AuthcryptError, bind_authcrypt_sender};
pub use extractor::{
    AdminAuth, AuthClaims, AuthState, ManageAuth, StepUpAuth, SuperAdminAuth, WriteAuth,
};
pub use siop::{SiopError, VerifiedSiopIdToken, parse_unverified_iss, verify_siop_id_token};
pub use vm_resolver::TrustTaskVmResolver;
