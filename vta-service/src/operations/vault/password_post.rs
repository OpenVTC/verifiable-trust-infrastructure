//! Password POST driver for `vault/proxy-login/0.1`.
//!
//! When the vault entry's `VaultSecret::Password` carries a
//! `loginConfig`, the maintainer performs an HTTP POST against
//! `loginConfig.login_url` with the entry's credentials, captures the
//! resulting `Set-Cookie` headers, and returns them in the SessionBlob
//! that the consumer authcrypt-unseals. The long-term password leaves
//! the VTA only as the body of one outbound HTTPS request — it never
//! travels back to the consumer.
//!
//! Scope (per `vault/_shared/0.1/vault-secret#/$defs/PasswordLoginConfig`):
//!
//! - JSON or `application/x-www-form-urlencoded` request body.
//! - Optional caller-configurable field names (`username`, `password`,
//!   `totp`); defaults match the most common consumer APIs.
//! - Optional constant extra fields the site expects.
//! - Caller-configurable HTTP success status (default `[200, 204]`);
//!   anything outside the success set maps to `credential_rejected`
//!   (4xx) or `target_unreachable` (5xx).
//! - Captured cookies are filtered to the loginUrl's host (defense
//!   against malicious sites setting cookies for unrelated origins).
//!
//! Out of scope for M2B.5 — these need a richer driver (future spec):
//!
//! - CSRF tokens fetched in a separate round-trip before the POST.
//! - Multi-step MFA / 2FA prompts beyond a single TOTP field.
//! - Anti-bot challenges (Cloudflare, reCAPTCHA, hCaptcha).
//! - Cookies the maintainer's HTTP client receives during pre-fetch
//!   (the driver issues exactly one POST and reads `Set-Cookie` from
//!   that response).

use std::collections::BTreeMap;

use reqwest::header::{CONTENT_TYPE, COOKIE, SET_COOKIE};

use vti_common::vault::{
    CookieJarEntry, PasswordLoginConfig, PasswordLoginFormat, SameSite, TotpSeed,
};

use crate::error::AppError;

/// Per-request timeout. Consumer-site login APIs typically respond in
/// well under a second; 15 s gives us margin for slow links without
/// letting a misbehaving target hold a worker indefinitely.
const POST_TIMEOUT_SECS: u64 = 15;

/// Outcome categories for the Password POST driver. Map onto the
/// canonical `vault/proxy-login/0.1` error codes at the handler
/// boundary.
#[derive(Debug, thiserror::Error)]
pub enum PasswordPostError {
    /// `loginConfig.login_url` is malformed or unsupported (e.g.
    /// `http://` against a non-loopback host).
    #[error("login_url invalid: {0}")]
    InvalidLoginUrl(String),
    /// TOTP code was required by config but couldn't be generated
    /// (e.g. no `TotpSeed` populated, or the algorithm isn't
    /// implemented yet — TOTP generation lands in a follow-up).
    #[error("totp generation not supported in this maintainer build: {0}")]
    TotpNotImplemented(String),
    /// HTTP-level failure before the response — DNS, connection
    /// refused, TLS handshake, etc. Maps to `target_unreachable`.
    #[error("HTTP request to {url} failed: {source}")]
    Transport {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    /// Server returned a status the loginConfig declared as failure.
    /// 4xx maps to `credential_rejected`, 5xx maps to
    /// `target_unreachable`. Body excerpt is captured for diagnostics
    /// but NEVER logged unredacted (it could echo back parts of the
    /// credential — sites do varying things on auth failure).
    #[error("login rejected with HTTP {status}")]
    NonSuccessStatus { status: u16 },
    /// Response was 2xx-ish but the body / headers can't be parsed
    /// (e.g. malformed Set-Cookie). Maps to `target_unreachable` —
    /// the consumer SHOULD retry; if it keeps failing, the entry's
    /// loginConfig is probably mis-shaped for this site and the user
    /// needs to update it.
    #[error("response parse failure: {0}")]
    ResponseParse(String),
}

/// Map a [`PasswordPostError`] to the right `AppError` shape so the
/// trust-task handler emits the canonical proxy-login error code.
/// `Transport` and 5xx `NonSuccessStatus` both become
/// `target_unreachable` (retryable); 4xx becomes `credential_rejected`
/// (not retryable); everything else is `Internal`.
impl From<PasswordPostError> for AppError {
    fn from(value: PasswordPostError) -> Self {
        match value {
            PasswordPostError::NonSuccessStatus { status } if (400..500).contains(&status) => {
                AppError::Validation(format!("vault/proxy-login: credential_rejected ({status})"))
            }
            PasswordPostError::NonSuccessStatus { status } => {
                AppError::Internal(format!("vault/proxy-login: target_unreachable ({status})"))
            }
            PasswordPostError::Transport { url, source } => AppError::Internal(format!(
                "vault/proxy-login: target_unreachable {url}: {source}"
            )),
            PasswordPostError::InvalidLoginUrl(msg) => {
                AppError::Validation(format!("vault/proxy-login: invalid login_url — {msg}"))
            }
            PasswordPostError::TotpNotImplemented(msg) => {
                AppError::Internal(format!("vault/proxy-login: {msg}"))
            }
            PasswordPostError::ResponseParse(msg) => {
                AppError::Internal(format!("vault/proxy-login: response parse — {msg}"))
            }
        }
    }
}

/// Validate the loginConfig's URL is one we're willing to POST to.
/// Per the canonical spec, `http://` is permitted only for the
/// localhost loopback — anywhere else, the credentials would leak in
/// transit. The check accepts `127.0.0.0/8`, `::1`, and the literal
/// hostname `localhost`.
pub fn validate_login_url(login_url: &str) -> Result<url::Url, PasswordPostError> {
    let url = url::Url::parse(login_url)
        .map_err(|e| PasswordPostError::InvalidLoginUrl(format!("not a URL: {e}")))?;
    match url.scheme() {
        "https" => Ok(url),
        "http" => {
            // `url::Url::host_str` strips the IPv6 brackets, but
            // host_str() returns the inner address — e.g. "::1" for
            // `http://[::1]:8080/`. Defense in depth: handle both
            // bracketed and bare in case future url-crate behaviour
            // changes.
            let host = url
                .host_str()
                .unwrap_or("")
                .trim_start_matches('[')
                .trim_end_matches(']');
            let is_loopback = host == "localhost"
                || host == "::1"
                || host.starts_with("127.")
                || host == "0.0.0.0";
            if is_loopback {
                Ok(url)
            } else {
                Err(PasswordPostError::InvalidLoginUrl(format!(
                    "http:// is permitted only for loopback hosts; got {host}"
                )))
            }
        }
        other => Err(PasswordPostError::InvalidLoginUrl(format!(
            "unsupported scheme {other}"
        ))),
    }
}

/// Build the request body the driver POSTs to the login URL. Returns
/// the (Content-Type, serialised body) tuple. JSON uses serde_json's
/// canonical encoding; form-urlencoded uses `application/x-www-form-
/// urlencoded` with stable key ordering (BTreeMap iteration).
pub fn build_request_body(
    config: &PasswordLoginConfig,
    username: Option<&str>,
    password: &str,
    totp_code: Option<&str>,
) -> Result<(&'static str, String), PasswordPostError> {
    // Build the field map in a stable order — sorted by key — so the
    // wire shape is deterministic. Some sites do simple integrity
    // checks on body shape; deterministic ordering avoids silent
    // breakage from BTreeMap-vs-HashMap iteration differences.
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    if let Some(u) = username {
        fields.insert(config.effective_username_field().to_string(), u.to_string());
    }
    fields.insert(
        config.effective_password_field().to_string(),
        password.to_string(),
    );
    if let Some(field) = config.totp_field.as_deref() {
        match totp_code {
            Some(code) => {
                fields.insert(field.to_string(), code.to_string());
            }
            None => {
                return Err(PasswordPostError::TotpNotImplemented(
                    "loginConfig.totpField is set but no TOTP seed is available or TOTP \
                     generation is not yet implemented in this maintainer build"
                        .into(),
                ));
            }
        }
    }
    if let Some(extra) = config.extra_fields.as_ref() {
        for (k, v) in extra {
            fields.insert(k.clone(), v.clone());
        }
    }

    match config.format {
        PasswordLoginFormat::Json => {
            let body = serde_json::to_string(&fields).map_err(|e| {
                PasswordPostError::ResponseParse(format!("serialise JSON body: {e}"))
            })?;
            Ok(("application/json", body))
        }
        PasswordLoginFormat::FormUrlencoded => {
            // Hand-encode rather than pulling in form_urlencoded just
            // for this — keys + values are utf-8 already.
            let mut buf = String::new();
            for (k, v) in &fields {
                if !buf.is_empty() {
                    buf.push('&');
                }
                buf.push_str(&urlencoding::encode(k));
                buf.push('=');
                buf.push_str(&urlencoding::encode(v));
            }
            Ok(("application/x-www-form-urlencoded", buf))
        }
    }
}

/// Parse a `Set-Cookie` response-header value into a `CookieJarEntry`.
/// Spec'd permissively per RFC 6265 §5.2 — unknown attributes are
/// ignored; missing attributes get the canonical defaults
/// (`path: "/"`, no `domain` → host-only, no `expires` → session
/// cookie). Returns `None` if the header doesn't carry a valid
/// name=value pair.
///
/// Domain filtering: when the response's Set-Cookie carries a `Domain`
/// attribute, the maintainer SHOULD only accept it if the domain is
/// equal to or a parent of the login URL's host. We enforce this at
/// the caller (in `run_password_post`), not here — this parser is
/// shape-only.
pub fn parse_set_cookie(header: &str) -> Option<CookieJarEntry> {
    let mut parts = header.split(';').map(str::trim);
    let nv = parts.next()?;
    let (name, value) = nv.split_once('=')?;
    let name = name.trim().to_string();
    let value = value.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let mut domain: Option<String> = None;
    let mut path: Option<String> = None;
    let mut expires: Option<String> = None;
    let mut secure = false;
    let mut http_only = false;
    let mut same_site: Option<SameSite> = None;

    for attr in parts {
        if attr.is_empty() {
            continue;
        }
        let (k, v) = match attr.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim())),
            None => (attr.trim(), None),
        };
        let kl = k.to_ascii_lowercase();
        match (kl.as_str(), v) {
            ("domain", Some(v)) => domain = Some(v.trim_start_matches('.').to_string()),
            ("path", Some(v)) => path = Some(v.to_string()),
            ("expires", Some(v)) => expires = Some(v.to_string()),
            ("max-age", Some(_)) => {} // RFC 6265 Max-Age supersedes Expires but we
            // forward the cookie unconditionally — the browser
            // re-derives expiry from whichever attribute is present
            ("secure", _) => secure = true,
            ("httponly", _) => http_only = true,
            ("samesite", Some(v)) => {
                same_site = match v.to_ascii_lowercase().as_str() {
                    "strict" => Some(SameSite::Strict),
                    "lax" => Some(SameSite::Lax),
                    "none" => Some(SameSite::None),
                    _ => None,
                };
            }
            _ => {}
        }
    }

    Some(CookieJarEntry {
        name,
        value,
        domain: domain.unwrap_or_default(),
        path: path.unwrap_or_else(|| "/".to_string()),
        expires,
        secure: if secure { Some(true) } else { None },
        http_only: if http_only { Some(true) } else { None },
        same_site,
    })
}

/// True iff `cookie_domain` is the same as or a child of `host`.
/// RFC 6265 §5.1.3 — a cookie with `Domain=example.com` is sent for
/// `*.example.com` AND `example.com`. We accept the cookie iff the
/// cookie's declared domain doesn't *extend* the trust to an
/// unrelated host. When the cookie has no Domain attribute, it's
/// host-only — we set `domain = host` for the consumer.
pub fn cookie_domain_matches(host: &str, cookie_domain: &str) -> bool {
    if cookie_domain.is_empty() {
        return true; // host-only — caller fills in `host`
    }
    let h = host.trim_start_matches('.').to_ascii_lowercase();
    let cd = cookie_domain.trim_start_matches('.').to_ascii_lowercase();
    h == cd || h.ends_with(&format!(".{cd}"))
}

/// Perform the proxy login. Returns the cookie list the maintainer
/// should put into the SessionBlob, or a [`PasswordPostError`] that
/// the caller maps to a canonical Trust Task error code.
///
/// TOTP: this driver does NOT yet generate TOTP codes from a
/// `TotpSeed`. A future patch wires in `totp-lite` (or equivalent)
/// behind a feature flag. For now, presence of `totpField` in the
/// config when no TOTP code can be supplied is an error so the user
/// sees a clear `not_implemented` message rather than a silent
/// auth-without-TOTP failure at the third party.
pub async fn run_password_post(
    config: &PasswordLoginConfig,
    username: Option<&str>,
    password: &str,
    totp: Option<&TotpSeed>,
) -> Result<Vec<CookieJarEntry>, PasswordPostError> {
    // 1. Validate URL.
    let url = validate_login_url(&config.login_url)?;
    let host = url
        .host_str()
        .ok_or_else(|| PasswordPostError::InvalidLoginUrl("URL has no host".into()))?
        .to_string();

    // 2. TOTP generation — punt unless we explicitly support it.
    let totp_code: Option<&str> = match (config.totp_field.as_deref(), totp) {
        (None, _) => None,
        (Some(_), None) => {
            return Err(PasswordPostError::TotpNotImplemented(
                "config.totpField set but entry has no totp seed".into(),
            ));
        }
        (Some(_), Some(_seed)) => {
            return Err(PasswordPostError::TotpNotImplemented(
                "TOTP code generation lands in a follow-up patch — use entries without \
                 loginConfig.totpField for M2B.5"
                    .into(),
            ));
        }
    };

    // 3. Build body.
    let (content_type, body) = build_request_body(config, username, password, totp_code)?;

    // 4. POST.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(POST_TIMEOUT_SECS))
        // No cookie store — we capture cookies from the immediate
        // response. The maintainer issues exactly one POST; persistent
        // cookies don't apply to this driver.
        //
        // No redirect following — when the loginConfig declares 3xx
        // statuses (e.g. 302) as success, we want to surface that
        // response with its Set-Cookie headers, not chase the
        // Location URL into a logged-in dashboard the maintainer
        // shouldn't actually fetch (and which would echo bytes back
        // to the operator). Sites that legitimately need redirect-
        // following on the login response are an edge case worth a
        // future driver flag.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| PasswordPostError::Transport {
            url: url.to_string(),
            source: e,
        })?;
    let resp = client
        .post(url.clone())
        .header(CONTENT_TYPE, content_type)
        .body(body)
        .send()
        .await
        .map_err(|e| PasswordPostError::Transport {
            url: url.to_string(),
            source: e,
        })?;

    let status = resp.status().as_u16();
    let success = config.effective_success_status();
    if !success.contains(&status) {
        return Err(PasswordPostError::NonSuccessStatus { status });
    }

    // 5. Parse Set-Cookie headers. reqwest exposes them via the multi-
    // valued header iterator — there can be many on one response.
    let mut cookies = Vec::new();
    for header_value in resp.headers().get_all(SET_COOKIE).iter() {
        let raw = header_value
            .to_str()
            .map_err(|e| PasswordPostError::ResponseParse(format!("Set-Cookie not utf-8: {e}")))?;
        let Some(mut cookie) = parse_set_cookie(raw) else {
            continue;
        };
        // Domain filter. If the cookie declared a Domain attribute
        // that doesn't match the login URL's host, discard it —
        // defense against a malicious target setting cookies for
        // unrelated origins.
        if !cookie.domain.is_empty() && !cookie_domain_matches(&host, &cookie.domain) {
            tracing::warn!(
                login_host = %host,
                cookie_domain = %cookie.domain,
                cookie_name = %cookie.name,
                "discarding Set-Cookie whose Domain doesn't match login URL host"
            );
            continue;
        }
        if cookie.domain.is_empty() {
            cookie.domain = host.clone();
        }
        cookies.push(cookie);
    }

    // No cookies on a 2xx is suspicious but not fatal — some sites
    // return 200 with a body-carried token instead. Future drivers
    // for those cases can extract the token by JSON path; this M2B.5
    // driver just returns an empty cookie list and the caller decides.
    Ok(cookies)
}

// `COOKIE` is imported above for symmetry with `SET_COOKIE`; not used
// at the moment but lets a follow-up that pre-fetches a CSRF token
// (and threads it into the POST) compile without re-importing.
const _: Option<&reqwest::header::HeaderName> = Some(&COOKIE);

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_min(url: &str) -> PasswordLoginConfig {
        PasswordLoginConfig {
            login_url: url.to_string(),
            format: PasswordLoginFormat::Json,
            username_field: None,
            password_field: None,
            totp_field: None,
            extra_fields: None,
            success_status: None,
        }
    }

    #[test]
    fn validate_login_url_accepts_https() {
        assert!(validate_login_url("https://example.com/login").is_ok());
    }

    #[test]
    fn validate_login_url_accepts_http_to_loopback() {
        for url in [
            "http://localhost:3000/login",
            "http://127.0.0.1/api/login",
            "http://[::1]:8080/login",
        ] {
            assert!(
                validate_login_url(url).is_ok(),
                "loopback http should be accepted: {url}"
            );
        }
    }

    #[test]
    fn validate_login_url_rejects_http_to_non_loopback() {
        let err = validate_login_url("http://example.com/login").unwrap_err();
        assert!(
            matches!(err, PasswordPostError::InvalidLoginUrl(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_login_url_rejects_unsupported_scheme() {
        assert!(matches!(
            validate_login_url("ftp://example.com/login"),
            Err(PasswordPostError::InvalidLoginUrl(_))
        ));
    }

    #[test]
    fn build_request_body_json_default_fields() {
        let (ct, body) = build_request_body(
            &cfg_min("https://example.com/login"),
            Some("alice"),
            "hunter2",
            None,
        )
        .unwrap();
        assert_eq!(ct, "application/json");
        // BTreeMap iteration is alphabetical, so the JSON has
        // deterministic key order: password, username.
        assert_eq!(body, r#"{"password":"hunter2","username":"alice"}"#);
    }

    #[test]
    fn build_request_body_form_urlencoded_with_extras() {
        let mut config = cfg_min("https://example.com/login");
        config.format = PasswordLoginFormat::FormUrlencoded;
        config.username_field = Some("email".into());
        let mut extras = BTreeMap::new();
        extras.insert("grantType".to_string(), "password".to_string());
        config.extra_fields = Some(extras);

        let (ct, body) = build_request_body(&config, Some("a@b.com"), "p ass!", None).unwrap();
        assert_eq!(ct, "application/x-www-form-urlencoded");
        // url-encoded — '@' → %40, ' ' → %20 (urlencoding crate), '!' → %21
        // Alphabetical ordering by key: email, grantType, password.
        assert_eq!(
            body,
            "email=a%40b.com&grantType=password&password=p%20ass%21"
        );
    }

    #[test]
    fn build_request_body_omits_username_when_none() {
        let (_ct, body) =
            build_request_body(&cfg_min("https://example.com/login"), None, "secret", None)
                .unwrap();
        assert_eq!(body, r#"{"password":"secret"}"#);
    }

    #[test]
    fn build_request_body_errors_when_totp_field_set_but_no_code() {
        let mut config = cfg_min("https://example.com/login");
        config.totp_field = Some("otp".into());
        let err = build_request_body(&config, Some("a"), "p", None).unwrap_err();
        assert!(matches!(err, PasswordPostError::TotpNotImplemented(_)));
    }

    #[test]
    fn parse_set_cookie_minimal() {
        let c = parse_set_cookie("session=abc123").unwrap();
        assert_eq!(c.name, "session");
        assert_eq!(c.value, "abc123");
        assert_eq!(c.path, "/"); // default
        assert!(c.domain.is_empty()); // caller fills host
        assert_eq!(c.secure, None);
        assert_eq!(c.http_only, None);
    }

    #[test]
    fn parse_set_cookie_full() {
        let c = parse_set_cookie(
            "session=xyz; Domain=.example.com; Path=/api; Secure; HttpOnly; SameSite=Lax; Expires=Wed, 09 Jun 2027 10:18:14 GMT",
        )
        .unwrap();
        assert_eq!(c.name, "session");
        assert_eq!(c.value, "xyz");
        assert_eq!(c.domain, "example.com"); // leading dot stripped
        assert_eq!(c.path, "/api");
        assert_eq!(c.secure, Some(true));
        assert_eq!(c.http_only, Some(true));
        assert_eq!(c.same_site, Some(SameSite::Lax));
        assert_eq!(c.expires.as_deref(), Some("Wed, 09 Jun 2027 10:18:14 GMT"));
    }

    #[test]
    fn parse_set_cookie_rejects_empty_name() {
        assert!(parse_set_cookie("=abc; Path=/").is_none());
    }

    #[test]
    fn cookie_domain_matches_canonical_cases() {
        // Exact match.
        assert!(cookie_domain_matches("api.example.com", "api.example.com"));
        // Parent-domain Set-Cookie applies to subdomain.
        assert!(cookie_domain_matches("api.example.com", "example.com"));
        // Unrelated domain.
        assert!(!cookie_domain_matches("api.example.com", "evil.com"));
        // Sibling domain (Domain=example.org should NOT match
        // example.com's subdomain).
        assert!(!cookie_domain_matches("api.example.com", "example.org"));
        // Leading dot on the cookie's Domain attribute is permitted.
        assert!(cookie_domain_matches("api.example.com", ".example.com"));
        // Case-insensitive.
        assert!(cookie_domain_matches("API.example.COM", "example.com"));
        // Empty cookie_domain treated as host-only — match anything;
        // caller fills the host afterwards.
        assert!(cookie_domain_matches("anything.example", ""));
    }

    // ─── HTTP integration tests via wiremock ──────────────────────
    // Drive the full POST round-trip against a real local server so
    // the request shape (content-type, body), success-status logic,
    // and Set-Cookie capture are all exercised together.
    mod http {
        use super::*;
        use wiremock::matchers::{body_string_contains, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn make_cfg(login_url: String) -> PasswordLoginConfig {
            PasswordLoginConfig {
                login_url,
                format: PasswordLoginFormat::Json,
                username_field: None,
                password_field: None,
                totp_field: None,
                extra_fields: None,
                success_status: None,
            }
        }

        #[tokio::test]
        async fn success_2xx_captures_cookies_and_fills_host_only_domain() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/api/login"))
                .and(header("content-type", "application/json"))
                .and(body_string_contains("\"username\":\"alice\""))
                .and(body_string_contains("\"password\":\"hunter2\""))
                .respond_with(
                    ResponseTemplate::new(200)
                        // Two cookies: one host-only (no Domain), one with a
                        // matching Domain attribute. Both should be captured.
                        .append_header("set-cookie", "session=abc; Path=/; HttpOnly")
                        .append_header("set-cookie", "csrf=xyz; Path=/; Secure"),
                )
                .mount(&server)
                .await;

            let cfg = make_cfg(format!("{}/api/login", server.uri()));
            let cookies = run_password_post(&cfg, Some("alice"), "hunter2", None)
                .await
                .expect("password POST should succeed");
            assert_eq!(cookies.len(), 2);
            // Host-only cookies get the loginUrl's host filled in.
            let host = url::Url::parse(&cfg.login_url)
                .unwrap()
                .host_str()
                .unwrap()
                .to_string();
            for c in &cookies {
                assert_eq!(c.domain, host, "host-only cookie's domain should be filled");
            }
            assert!(cookies.iter().any(|c| c.name == "session"));
            assert!(cookies.iter().any(|c| c.name == "csrf"));
        }

        #[tokio::test]
        async fn http_4xx_maps_to_credential_rejected() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/login"))
                .respond_with(ResponseTemplate::new(401))
                .mount(&server)
                .await;
            let cfg = make_cfg(format!("{}/login", server.uri()));
            let err = run_password_post(&cfg, Some("a"), "b", None)
                .await
                .unwrap_err();
            assert!(
                matches!(err, PasswordPostError::NonSuccessStatus { status: 401 }),
                "got {err:?}"
            );
        }

        #[tokio::test]
        async fn http_5xx_maps_to_target_unreachable() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/login"))
                .respond_with(ResponseTemplate::new(503))
                .mount(&server)
                .await;
            let cfg = make_cfg(format!("{}/login", server.uri()));
            let err = run_password_post(&cfg, Some("a"), "b", None)
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                PasswordPostError::NonSuccessStatus { status: 503 }
            ));
        }

        #[tokio::test]
        async fn form_urlencoded_body_shape() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/api/login"))
                .and(header("content-type", "application/x-www-form-urlencoded"))
                .and(body_string_contains("username=alice"))
                .and(body_string_contains("password=hunter2"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;
            let mut cfg = make_cfg(format!("{}/api/login", server.uri()));
            cfg.format = PasswordLoginFormat::FormUrlencoded;
            let cookies = run_password_post(&cfg, Some("alice"), "hunter2", None)
                .await
                .expect("form-urlencoded POST should succeed");
            assert_eq!(cookies.len(), 0, "no Set-Cookie on this response");
        }

        #[tokio::test]
        async fn custom_success_status_treats_302_as_success() {
            // Some sites respond with 302 + Set-Cookie on successful
            // login (legacy form-post pattern). The maintainer
            // declares 302 in success_status so the driver accepts
            // it without following the redirect.
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/login"))
                .respond_with(
                    ResponseTemplate::new(302)
                        .append_header("set-cookie", "session=ok; Path=/")
                        .append_header("location", "/dashboard"),
                )
                .mount(&server)
                .await;
            let mut cfg = make_cfg(format!("{}/login", server.uri()));
            cfg.success_status = Some(vec![302]);
            let cookies = run_password_post(&cfg, Some("a"), "b", None)
                .await
                .expect("302 should be treated as success per config");
            assert_eq!(cookies.len(), 1);
            assert_eq!(cookies[0].name, "session");
        }

        #[tokio::test]
        async fn cookie_with_unrelated_domain_is_discarded() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/login"))
                .respond_with(
                    ResponseTemplate::new(200)
                        // Two cookies: one host-matched (kept), one with
                        // Domain=evil.com (discarded — defense against a
                        // malicious target setting cookies for unrelated
                        // origins).
                        .append_header("set-cookie", "kept=a; Path=/")
                        .append_header("set-cookie", "evil=b; Domain=evil.com; Path=/"),
                )
                .mount(&server)
                .await;
            let cfg = make_cfg(format!("{}/login", server.uri()));
            let cookies = run_password_post(&cfg, Some("a"), "b", None).await.unwrap();
            assert_eq!(cookies.len(), 1, "evil-domain cookie must be discarded");
            assert_eq!(cookies[0].name, "kept");
        }
    }
}
