/// An administrator's own passkeys (`auth/passkey/*`).
pub(crate) mod admin_passkeys;
pub mod backend;

pub use backend::VtcAuthBackend;
pub use vti_common::auth::extractor::{
    AdminAuth, AuthClaims, AuthState, ManageAuth, SuperAdminAuth,
};
pub use vti_common::auth::jwt;
pub use vti_common::auth::session;
