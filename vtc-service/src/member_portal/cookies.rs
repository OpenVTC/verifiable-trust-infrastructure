//! The member portal's cookies — see the module doc of [`super`] for why each
//! is scoped as it is.

use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue};

use super::{MEMBER_COOKIE_PATH, MEMBER_CSRF_COOKIE, MEMBER_REFRESH_COOKIE, MEMBER_SESSION_COOKIE};
use crate::error::AppError;

pub fn session_cookie(access_token: &str, max_age: u64) -> String {
    format!(
        "{MEMBER_SESSION_COOKIE}={access_token}; Path={MEMBER_COOKIE_PATH}; Max-Age={max_age}; SameSite=Strict; Secure; HttpOnly"
    )
}

pub fn refresh_cookie(refresh_token: &str, max_age: u64) -> String {
    format!(
        "{MEMBER_REFRESH_COOKIE}={refresh_token}; Path={MEMBER_COOKIE_PATH}; Max-Age={max_age}; SameSite=Strict; Secure; HttpOnly"
    )
}

/// Not `HttpOnly`: the portal reads it into `X-CSRF-Token`. `Path=/` so the
/// page at `/members/` can see it.
pub fn csrf_cookie(csrf: &str, max_age: u64) -> String {
    format!("{MEMBER_CSRF_COOKIE}={csrf}; Path=/; Max-Age={max_age}; SameSite=Strict; Secure")
}

/// The three cookies, expired — what sign-out sends.
pub fn cleared() -> [String; 3] {
    [
        session_cookie("", 0),
        refresh_cookie("", 0),
        csrf_cookie("", 0),
    ]
}

/// A fresh random CSRF value.
pub fn new_csrf() -> String {
    use rand::RngExt;
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Read one cookie's value out of a request's `Cookie` headers.
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(str::trim)
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty())
}

/// Append `Set-Cookie` headers.
pub fn append(
    headers: &mut HeaderMap,
    cookies: impl IntoIterator<Item = String>,
) -> Result<(), AppError> {
    for c in cookies {
        headers.append(
            SET_COOKIE,
            HeaderValue::try_from(c)
                .map_err(|e| AppError::Internal(format!("invalid cookie: {e}")))?,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_and_refresh_cookies_never_reach_admin_routes() {
        for c in [session_cookie("t", 60), refresh_cookie("r", 60)] {
            assert!(c.contains("Path=/v1/member;"), "{c}");
            assert!(
                c.contains("HttpOnly") && c.contains("Secure") && c.contains("SameSite=Strict")
            );
        }
    }

    #[test]
    fn csrf_cookie_is_readable_and_not_the_consoles() {
        let c = csrf_cookie("x", 60);
        assert!(c.starts_with("vtc_member_csrf=x;"));
        assert!(!c.contains("HttpOnly"));
    }
}
