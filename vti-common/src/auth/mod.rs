pub mod backend;
pub mod extractor;
pub mod handlers;
pub mod jwt;
#[cfg(feature = "passkey")]
pub mod passkey;
pub mod session;
pub mod siop;

pub use backend::{
    AttestationOutcome, AuthAuditEvent, AuthBackend, AuthError, AuthenticateInput, ChallengeInput,
    RefreshInput, RoleResolution, SessionStore,
};
pub use extractor::{
    AdminAuth, AuthClaims, AuthState, ManageAuth, StepUpAuth, SuperAdminAuth, WriteAuth,
};
pub use siop::{SiopError, VerifiedSiopIdToken, verify_siop_id_token};
