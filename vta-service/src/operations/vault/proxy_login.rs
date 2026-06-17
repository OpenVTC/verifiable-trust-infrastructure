//! `vault/proxy-login/0.1` business logic — mint a session credential on a
//! stored entry's behalf and seal it to the holder (P2.4).
//!
//! Two drivers:
//! - **`did-self-issued`**: VTA mints a SIOPv2 id_token and wraps it in a
//!   [`SessionBlob`] with a single `Authorization: Bearer …` header.
//! - **`password`** with a `loginConfig` (webvh): VTA performs the configured
//!   HTTP-POST login and captures the resulting cookies into a `SessionBlob`.
//!
//! Moved out of `routes/trust_tasks/vault.rs` so the route handler is a thin
//! adapter: it keeps the capability/context/step-up gates, the nonce-bounds
//! check, the `atm`/`vta_did` readiness checks, and the `ProxyLoginError` →
//! reject mapping; the driver dispatch + sealing live here.

use affinidi_tdk::messaging::ATM;
use serde_json::Value;

use vti_common::vault::{
    RequestHeader, SessionBlob, SiteTarget, StoredVaultEntry, VaultSecret, put_stored_vault_entry,
};

use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::store::KeyspaceHandle;
use crate::trust_tasks::wire_v0_2::{WireVersion, camelize_paths};

/// Password-POST session TTL ceiling (seconds). The caller's `ttlSecondsHint`
/// is honoured up to this and silently truncated above it.
#[cfg(feature = "webvh")]
pub const PASSWORD_POST_TTL_CEILING_SECS: u64 = 900;

/// The sealed session blob + metadata the route needs to build the
/// `vault/proxy-login/0.1#response`.
pub struct ProxyLoginOutput {
    /// DIDComm-authcrypt JWE carrying the `SessionBlob` cleartext.
    pub jwe: String,
    pub session_id: String,
    pub expires_at: String,
}

/// Driver-level failure modes. The route maps each onto the canonical
/// `vault/proxy-login/0.1` reject reason (preserving the spec error codes).
pub enum ProxyLoginError {
    /// Entry has no DID or web-origin target to use as a SIOP audience.
    NoAudience { entry_targets: Vec<SiteTarget> },
    /// `password` entry with no `loginConfig` — consumer should fall back to
    /// `vault/release` for browser-fill.
    NotProxyable,
    /// Entry kind has no proxy-login driver (yet, or in this build).
    NotImplemented { kind: &'static str },
    /// The password-POST driver failed (webvh only).
    #[cfg(feature = "webvh")]
    PasswordPost(crate::operations::vault::password_post::PasswordPostError),
    /// An internal failure (key load, SIOP build, serialise, pack).
    App(AppError),
}

impl From<AppError> for ProxyLoginError {
    fn from(e: AppError) -> Self {
        ProxyLoginError::App(e)
    }
}

/// Run the proxy-login driver for `stored` and seal the resulting session blob
/// to `holder_did`. Bumps `lastUsedAt` (best-effort, not a version bump).
///
/// The caller has already gated capability + context scope + step-up,
/// bounds-checked `nonce`, and resolved `atm` / `vta_did`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_login(
    atm: &ATM,
    vault_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    vta_did: &str,
    holder_did: &str,
    mut stored: StoredVaultEntry,
    target: Option<SiteTarget>,
    nonce: Option<String>,
    ttl_hint: Option<u32>,
    wire: WireVersion,
) -> Result<ProxyLoginOutput, ProxyLoginError> {
    // Driver dispatch. Each arm produces a `SessionBlob` (+ session_id +
    // expires_at); the shared tail below authcrypts + persists.
    let (session_blob, session_id, expires_at) = match &stored.secret {
        // ─── did-self-issued (SIOP id_token) ───
        VaultSecret::DidSelfIssued {
            did: siop_did,
            signing_key_id,
            ..
        } => {
            let (audience, bind_origin) = resolve_siop_audience(&target, &stored.entry.targets)
                .ok_or_else(|| ProxyLoginError::NoAudience {
                    entry_targets: stored.entry.targets.clone(),
                })?;
            let ttl_secs = ttl_hint
                .map(|t| (t as u64).min(super::PROXY_LOGIN_ID_TOKEN_TTL_SECS))
                .unwrap_or(super::PROXY_LOGIN_ID_TOKEN_TTL_SECS);
            let signing_key = super::load_signing_key_by_id(
                keys_ks,
                imported_ks,
                seed_store,
                audit_ks,
                signing_key_id,
            )
            .await?;
            let iat = chrono::Utc::now().timestamp().max(0) as u64;
            let id_token = super::build_siop_id_token(
                siop_did,
                signing_key_id,
                &audience,
                nonce.as_deref(),
                iat,
                ttl_secs,
                &signing_key,
            )?;
            build_session_blob_with_bearer(id_token, bind_origin, ttl_secs)
        }
        // ─── password (HTTP-POST driver) ───
        VaultSecret::Password {
            username,
            password,
            totp,
            login_config: Some(login_config),
            ..
        } => {
            #[cfg(feature = "webvh")]
            {
                let cookies = crate::operations::vault::password_post::run_password_post(
                    login_config,
                    username.as_deref(),
                    password,
                    totp.as_ref(),
                )
                .await
                .map_err(ProxyLoginError::PasswordPost)?;
                let ttl_secs = ttl_hint
                    .map(|t| (t as u64).min(PASSWORD_POST_TTL_CEILING_SECS))
                    .unwrap_or(PASSWORD_POST_TTL_CEILING_SECS);
                // bind_origin: prefer the entry's first WebOrigin (where the
                // user browses); fall back to the loginUrl's origin when the
                // entry only carries DID / app targets.
                let bind_origin = first_web_origin(&stored.entry.targets).or_else(|| {
                    url::Url::parse(&login_config.login_url)
                        .ok()
                        .and_then(|u| u.origin().ascii_serialization().into())
                });
                build_session_blob_with_cookies(cookies, bind_origin, ttl_secs)
            }
            #[cfg(not(feature = "webvh"))]
            {
                let _ = (username, password, totp, login_config);
                return Err(ProxyLoginError::NotImplemented { kind: "password" });
            }
        }
        VaultSecret::Password {
            login_config: None, ..
        } => return Err(ProxyLoginError::NotProxyable),
        other => {
            return Err(ProxyLoginError::NotImplemented {
                kind: super::secret_kind_label(other.kind()),
            });
        }
    };

    // The SessionBlob rides inside the opaque JWE, so the edge transform can't
    // reach its `refreshHint`; emit the version-appropriate casing here.
    let session_body =
        session_blob_cleartext_for_wire(&session_blob, wire).map_err(ProxyLoginError::App)?;

    let jwe = super::authcrypt_to_holder(
        atm,
        vta_did,
        holder_did,
        super::PROXY_LOGIN_INNER_MSG_TYPE,
        session_body,
    )
    .await?;

    // Same lastUsedAt update as release — server-managed metadata, NOT a
    // version bump.
    stored.entry.last_used_at = Some(chrono::Utc::now().to_rfc3339());
    if let Err(e) = put_stored_vault_entry(vault_ks, &stored).await {
        tracing::warn!(
            entry_id = %stored.entry.id,
            error = %e,
            "vault/proxy-login: lastUsedAt update failed; session release proceeded"
        );
    }

    Ok(ProxyLoginOutput {
        jwe,
        session_id,
        expires_at,
    })
}

/// Construct a `SessionBlob` carrying a bearer-token `Authorization` header —
/// the SIOP driver's output shape. Returns `(blob, session_id, expires_at)`.
fn build_session_blob_with_bearer(
    bearer: String,
    bind_origin: Option<String>,
    ttl_secs: u64,
) -> (SessionBlob, String, String) {
    let session_id = uuid::Uuid::new_v4().to_string();
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64)).to_rfc3339();
    let blob = SessionBlob {
        session_id: session_id.clone(),
        expires_at: expires_at.clone(),
        cookies: Vec::new(),
        headers: vec![RequestHeader {
            name: "Authorization".to_string(),
            value: format!("Bearer {bearer}"),
        }],
        local_storage: Vec::new(),
        session_storage: Vec::new(),
        bind_origin,
        // SIOP id_tokens are one-shot — the wallet calls vault/proxy-login
        // again when the token expires.
        refresh_hint: None,
    };
    (blob, session_id, expires_at)
}

/// Construct a `SessionBlob` carrying cookies — the Password POST driver's
/// output shape (the cookies ARE the session). Returns
/// `(blob, session_id, expires_at)`.
#[cfg(feature = "webvh")]
fn build_session_blob_with_cookies(
    cookies: Vec<vti_common::vault::CookieJarEntry>,
    bind_origin: Option<String>,
    ttl_secs: u64,
) -> (SessionBlob, String, String) {
    let session_id = uuid::Uuid::new_v4().to_string();
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64)).to_rfc3339();
    let blob = SessionBlob {
        session_id: session_id.clone(),
        expires_at: expires_at.clone(),
        cookies,
        headers: Vec::new(),
        local_storage: Vec::new(),
        session_storage: Vec::new(),
        bind_origin,
        // Password POST sessions hint the wallet to refresh on 401 (the third
        // party's cookie expired); the maintainer then re-runs proxy-login.
        refresh_hint: Some(vti_common::vault::RefreshHint::On401),
    };
    (blob, session_id, expires_at)
}

/// Pick the first `web-origin` target on the entry — the password driver's
/// `bind_origin` source.
#[cfg(feature = "webvh")]
fn first_web_origin(targets: &[SiteTarget]) -> Option<String> {
    targets.iter().find_map(|t| match t {
        SiteTarget::WebOrigin { origin } => Some(origin.clone()),
        _ => None,
    })
}

/// Resolve the SIOP audience (and the SessionBlob's `bind_origin`) from the
/// optional request target + the entry's declared targets.
///
/// Priority: explicit `target` (must be `Did` or `WebOrigin`) → first `Did`
/// target on the entry → first `WebOrigin` target → `None`. `bind_origin` is
/// the entry's first web origin whenever it has one.
fn resolve_siop_audience(
    explicit: &Option<SiteTarget>,
    entry_targets: &[SiteTarget],
) -> Option<(String, Option<String>)> {
    let entry_origin: Option<String> = entry_targets.iter().find_map(|t| match t {
        SiteTarget::WebOrigin { origin } => Some(origin.clone()),
        _ => None,
    });

    if let Some(t) = explicit {
        return match t {
            SiteTarget::Did { did } => Some((did.clone(), entry_origin)),
            SiteTarget::WebOrigin { origin } => Some((origin.clone(), Some(origin.clone()))),
            // App targets aren't SIOP audiences.
            _ => None,
        };
    }

    let entry_did: Option<String> = entry_targets.iter().find_map(|t| match t {
        SiteTarget::Did { did } => Some(did.clone()),
        _ => None,
    });
    if let Some(did) = entry_did {
        return Some((did, entry_origin));
    }
    entry_origin.clone().map(|o| (o, entry_origin))
}

/// Serialise a `SessionBlob` into the JWE cleartext JSON in the casing the
/// negotiated wire version requires. `SessionBlob` always serialises its 0.1
/// (kebab) `refreshHint` value; for a 0.2 session we up-convert it (the field
/// name `refreshHint` is already camelCase via the struct's `rename_all`).
/// Pure + synchronous so the casing is unit-testable without an ATM/JWE.
fn session_blob_cleartext_for_wire(
    blob: &SessionBlob,
    wire: WireVersion,
) -> Result<Value, AppError> {
    let mut body = serde_json::to_value(blob).map_err(|e| {
        AppError::Internal(format!(
            "vault/proxy-login: failed to serialise SessionBlob: {e}"
        ))
    })?;
    if wire == WireVersion::V0_2 {
        camelize_paths(&mut body, &["refreshHint"]);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::vault::RefreshHint;

    fn blob_with_hint(hint: Option<RefreshHint>) -> SessionBlob {
        SessionBlob {
            session_id: "s1".into(),
            expires_at: "2026-06-17T00:00:00Z".into(),
            cookies: vec![],
            headers: vec![],
            local_storage: vec![],
            session_storage: vec![],
            bind_origin: None,
            refresh_hint: hint,
        }
    }

    #[test]
    fn v0_1_session_blob_keeps_kebab_refresh_hint() {
        let body = session_blob_cleartext_for_wire(
            &blob_with_hint(Some(RefreshHint::BeforeExpiry)),
            WireVersion::V0_1,
        )
        .unwrap();
        assert_eq!(body["refreshHint"], "before-expiry");
    }

    #[test]
    fn v0_2_session_blob_camelizes_refresh_hint() {
        let body = session_blob_cleartext_for_wire(
            &blob_with_hint(Some(RefreshHint::BeforeExpiry)),
            WireVersion::V0_2,
        )
        .unwrap();
        assert_eq!(body["refreshHint"], "beforeExpiry");
        // `on401` is identical in both casings; `maintainer-only` → `maintainerOnly`.
        let on401 = session_blob_cleartext_for_wire(
            &blob_with_hint(Some(RefreshHint::On401)),
            WireVersion::V0_2,
        )
        .unwrap();
        assert_eq!(on401["refreshHint"], "on401");
        let maint = session_blob_cleartext_for_wire(
            &blob_with_hint(Some(RefreshHint::MaintainerOnly)),
            WireVersion::V0_2,
        )
        .unwrap();
        assert_eq!(maint["refreshHint"], "maintainerOnly");
    }

    #[test]
    fn session_blob_without_hint_is_unaffected() {
        // `refresh_hint: None` is skipped on the wire — camelize is a safe no-op.
        let body =
            session_blob_cleartext_for_wire(&blob_with_hint(None), WireVersion::V0_2).unwrap();
        assert!(body.get("refreshHint").is_none());
    }

    fn web(o: &str) -> SiteTarget {
        SiteTarget::WebOrigin {
            origin: o.to_string(),
        }
    }
    fn did(d: &str) -> SiteTarget {
        SiteTarget::Did { did: d.to_string() }
    }
    fn ios() -> SiteTarget {
        SiteTarget::IosApp {
            bundle_id: "com.example.app".into(),
            team_id: None,
        }
    }

    #[test]
    fn explicit_did_target_uses_did_as_audience_with_entry_origin_as_bind() {
        let entry_targets = vec![did("did:web:rp.example"), web("https://rp.example")];
        let (aud, bind) = resolve_siop_audience(&Some(did("did:web:rp.example")), &entry_targets)
            .expect("audience");
        assert_eq!(aud, "did:web:rp.example");
        assert_eq!(bind.as_deref(), Some("https://rp.example"));
    }

    #[test]
    fn explicit_web_origin_target_audience_equals_bind() {
        let entry_targets = vec![web("https://rp.example")];
        let (aud, bind) = resolve_siop_audience(&Some(web("https://rp.example")), &entry_targets)
            .expect("audience");
        assert_eq!(aud, "https://rp.example");
        assert_eq!(bind.as_deref(), Some("https://rp.example"));
    }

    #[test]
    fn explicit_app_target_rejects_for_siop() {
        let entry_targets = vec![did("did:web:rp.example")];
        assert!(
            resolve_siop_audience(&Some(ios()), &entry_targets).is_none(),
            "app targets aren't SIOP audiences"
        );
    }

    #[test]
    fn no_explicit_target_prefers_first_did_on_entry() {
        let entry_targets = vec![
            web("https://rp.example"),
            did("did:web:rp.example"),
            did("did:web:other"),
        ];
        let (aud, bind) = resolve_siop_audience(&None, &entry_targets).expect("audience");
        assert_eq!(aud, "did:web:rp.example", "first DID wins over later DIDs");
        assert_eq!(bind.as_deref(), Some("https://rp.example"));
    }

    #[test]
    fn no_explicit_target_falls_back_to_first_web_origin_when_no_did() {
        let entry_targets = vec![web("https://rp.example")];
        let (aud, bind) = resolve_siop_audience(&None, &entry_targets).expect("audience");
        assert_eq!(aud, "https://rp.example");
        assert_eq!(bind.as_deref(), Some("https://rp.example"));
    }

    #[test]
    fn no_audience_when_entry_has_only_app_targets() {
        let entry_targets = vec![ios()];
        assert!(
            resolve_siop_audience(&None, &entry_targets).is_none(),
            "app-only entry yields no SIOP audience"
        );
    }
}
