pub mod backend;
pub mod didcomm;
pub mod extractor;
pub mod handlers;
pub mod jwt;
#[cfg(feature = "passkey")]
pub mod passkey;
pub mod session;
pub mod siop;
pub mod step_up;

pub use backend::{
    AttestationOutcome, AuthAuditEvent, AuthBackend, AuthError, AuthenticateInput, ChallengeInput,
    RefreshInput, RoleResolution, SessionStore,
};
// Moved down to `vta-sdk` when a client needed the same verifier a service
// does — re-exported so every call site here is unchanged, and so the
// `verificationMethod` resolution subtlety exists exactly once.
pub use didcomm::{AuthcryptError, bind_authcrypt_sender};
pub use extractor::{
    AdminAuth, AuthClaims, AuthState, ManageAuth, StepUpAuth, SuperAdminAuth, WriteAuth,
};
pub use siop::{SiopError, VerifiedSiopIdToken, parse_unverified_iss, verify_siop_id_token};
pub use vta_sdk::trust_task_proof::TrustTaskVmResolver;
pub use vta_sdk::trust_task_proof::{
    DiProofError, verify_trust_task_proof, verify_trust_task_proof_with,
};
