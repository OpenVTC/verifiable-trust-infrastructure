//! The member portal's sessions: who may sign in, what they are issued, and how
//! a member request is authenticated.
//!
//! The admin console and the member portal are separate applications
//! (`/admin/`, `/members/`), and their sessions are kept apart **by
//! construction**, not by a role check somebody has to remember:
//!
//! - **Who.** Only an *active member* signs in here ([`active`]): a live ACL
//!   entry that is neither expired, suspended nor an `application` entry, and a
//!   member record that has not been removed. That is checked when the
//!   challenge is issued (so a non-member gets an unusable one, VTI-SES-006/007
//!   via the shared handler), at authentication, at every refresh, and on every
//!   request ([`extractor::MemberAuth`]) — authority is read from the live
//!   records, never from the session (VTI-SES-020/022).
//! - **What.** Access tokens carry the audience [`MEMBER_AUDIENCE`], not
//!   `VTC`. Every administrator extractor validates `aud = VTC`, so a member
//!   token is refused by the whole console surface exactly as a VTA token is,
//!   with no route needing to know the member portal exists.
//! - **Where.** Sessions live in the `member_sessions` keyspace and portal
//!   passkeys in `member_passkeys`. The administrator auth path reads
//!   `sessions` and `passkey` only, so a member's refresh token cannot be
//!   redeemed at `/v1/auth/refresh` — not even by a member who is also an
//!   administrator — and a portal passkey can neither open a console session
//!   nor answer a step-up.
//! - **Cookies.** `vtc_member_session` and `vtc_member_refresh` are scoped to
//!   `Path=/v1/member`, so they are never sent to an administrator route at
//!   all; `vtc_member_csrf` is `Path=/` only because the portal's script must
//!   read it, and the CSRF gate pairs it with `/v1/member/*` requests alone.
//!
//! The portal itself is the `/members/` bundle; its routes are
//! [`crate::routes::member_portal`].

pub mod active;
pub mod backend;
pub mod cookies;
pub mod extractor;

pub use active::{ActiveMember, active_member, require_active_member};
pub use backend::MemberAuthBackend;
pub use extractor::MemberAuth;

/// JWT audience of a member-portal access token. Distinct from the console's
/// `VTC`, which is what keeps the two token classes from being accepted for
/// one another.
pub const MEMBER_AUDIENCE: &str = "VTC-member";

/// The portal's access-token cookie.
pub const MEMBER_SESSION_COOKIE: &str = "vtc_member_session";

/// The portal's refresh-token cookie.
pub const MEMBER_REFRESH_COOKIE: &str = "vtc_member_refresh";

/// The portal's CSRF double-submit cookie. Not the console's `csrf`: the two
/// applications share an origin, and one signing in must not overwrite the
/// value the other has already mirrored into its request headers.
pub const MEMBER_CSRF_COOKIE: &str = "vtc_member_csrf";

/// Path the session and refresh cookies are scoped to — every member API route
/// sits under it, and no administrator route does.
pub const MEMBER_COOKIE_PATH: &str = "/v1/member";

/// The member-audience JWT keys: the VTC's signing key, bound to
/// [`MEMBER_AUDIENCE`].
pub fn member_jwt_keys(
    state: &crate::server::AppState,
) -> Result<vti_common::auth::jwt::JwtKeys, crate::error::AppError> {
    state
        .jwt_keys
        .as_ref()
        .map(|k| k.for_audience(MEMBER_AUDIENCE))
        .ok_or_else(|| crate::error::AppError::Internal("JWT keys not configured".into()))
}
