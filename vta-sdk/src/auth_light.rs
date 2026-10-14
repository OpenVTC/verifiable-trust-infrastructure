//! Lightweight challenge-response authentication for VTA REST clients.
//!
//! Same challenge-response flow as `session::challenge_response()`, but with no
//! ATM/TDK runtime and no mediator: every step is a Trust-Task document
//! POSTed to `/trust-tasks` (see [`crate::auth_di`]), and the authenticate
//! step's DI-signed `auth/authenticate/0.2` document *is* the authentication —
//! the canonical transport the VTA tries before its DIDComm-envelope path.
//!
//! **This module used to pack an anoncrypt DIDComm envelope** via
//! `didcomm_light` and throw the caller's private key away — the sender was
//! merely *asserted* in a plaintext `from` header. VTI #771 hardened the
//! auth family to require an authenticated (authcrypt) envelope, which
//! rejected every anoncrypt message outright ("authenticate message must be
//! an authenticated (authcrypt) DIDComm envelope") and broke this whole tier:
//! the VTC setup wizard's did-hosting picker, `VtaClient`'s REST re-auth and
//! refresh, and `vtc-client`. Signing with the holder key both fixes that and
//! is what the server actually prefers.
//!
//! Consequence of the switch: the VTA verifies the proof with a `did:key`-only
//! resolver, so [`challenge_response_light`] requires a `did:key` holder and
//! returns [`VtaError::Validation`] for anything else. Callers holding another
//! DID method need `session::challenge_response` (DIDComm authcrypt), which
//! `integration::auth::try_rest` already falls back to.
//!
//! Feature gate: `client` (not `session`).

use crate::auth_di;
use crate::credentials::CredentialBundle;
use crate::error::VtaError;
use reqwest::Client;

/// The per-request Trust-Task URL header.
///
/// The **VTC gates every route on it** (`vtc-service/src/routes/mod.rs`, the
/// `tt(...)` wrapper) and answers 400 without it; the VTA does not read it. So
/// omitting it made this client VTC-incompatible at the *transport* layer,
/// independently of the body — `vtc-client::connect` could not even reach the
/// authenticate handler. Sending it on every call is what lets one auth client
/// speak to both services.
///
/// Not sent on the VTC's `/wallet/auth/*` aliases, which are deliberately
/// header-exempt for the browser extension; those aren't this client's paths.
const TRUST_TASK_HEADER: &str = "Trust-Task";

/// Result of a successful authentication.
#[derive(Clone)]
pub struct AuthResult {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: Option<String>,
    pub refresh_expires_at: Option<u64>,
}

/// Written by hand so the access and refresh tokens never reach a log: a derived `Debug` would print them.
impl std::fmt::Debug for AuthResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthResult")
            .field("access_token", &"<redacted>")
            .field("access_expires_at", &self.access_expires_at)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}

/// Perform challenge-response authentication without ATM/TDK runtime.
///
/// The lightweight equivalent of `session::challenge_response()`: every step
/// is a Trust-Task document POSTed to `/trust-tasks`, and the authenticate
/// step is a DI-signed `auth/authenticate/0.2` document, so the holder key
/// proves the sender and no mediator is involved.
///
/// `client_did` must be a `did:key` — see the module docs.
pub async fn challenge_response_light(
    http: &Client,
    base_url: &str,
    client_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
) -> Result<AuthResult, crate::error::VtaError> {
    // Step 1: Request challenge — a Trust-Task document, not the flat
    // `{ did }` shape the retired `/auth/challenge` route once accepted: the
    // pre-session family-owned dispatch on `/trust-tasks` only recognizes a
    // document by its `type`.
    let trust_tasks_url = format!("{base_url}/trust-tasks");
    let challenge_body = auth_di::build_challenge_doc(client_did, vta_did, client_did)
        .map_err(|e| VtaError::Validation(e.to_string()))?;
    let challenge_resp = http
        .post(&trust_tasks_url)
        .header("content-type", "application/json")
        .header(
            TRUST_TASK_HEADER,
            crate::trust_tasks::TASK_AUTH_CHALLENGE_0_1,
        )
        .body(challenge_body)
        .send()
        .await?;

    if !challenge_resp.status().is_success() {
        return Err(VtaError::from_response(challenge_resp).await);
    }

    let server_date = response_date(challenge_resp.headers());
    let challenge = auth_di::parse_challenge_response(&challenge_resp.text().await?)
        .map_err(|e| VtaError::Validation(e.to_string()))?;

    // Steps 2–3: sign and send the authenticate Trust Task, waiting out the
    // VTA's rate limit with the same challenge.
    let deadline = authenticate_deadline(
        &challenge.expires_at,
        server_date.as_deref(),
        chrono::Utc::now(),
    );
    let auth_text = redeem_challenge(
        http,
        &trust_tasks_url,
        client_did,
        private_key_multibase,
        vta_did,
        &challenge,
        deadline,
    )
    .await?;

    let auth_data = auth_di::parse_auth_response(&auth_text)
        .map_err(|e| VtaError::Validation(e.to_string()))?;

    let access_expires_at = auth_data.access_expires_at_epoch().ok_or_else(|| {
        VtaError::Validation(format!(
            "VTA returned unparseable session.issuedAt: '{}'",
            auth_data.session.issued_at
        ))
    })?;
    let refresh_expires_at = auth_data.refresh_expires_at_epoch();
    Ok(AuthResult {
        access_token: auth_data.tokens.access_token,
        access_expires_at,
        refresh_token: auth_data.tokens.refresh_token,
        refresh_expires_at,
    })
}

/// Redeem `challenge`: sign and send the `auth/authenticate/0.2` Trust Task,
/// and return the body of the response that accepted it.
///
/// Repeated while the authenticate step is rate limited. The challenge stays
/// redeemable until it expires, so wait and redeem *it*: a caller that starts
/// over spends the next token on a new challenge, and behind one busy IP no
/// login ever finishes. Bounded by `deadline` ([`authenticate_deadline`]), so
/// a server that kept refusing cannot hold the caller indefinitely. Shared by
/// every REST login in the SDK ([`challenge_response_light`] and
/// [`crate::provision_client::challenge_response_di`]).
pub(crate) async fn redeem_challenge(
    http: &Client,
    trust_tasks_url: &str,
    client_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
    challenge: &crate::protocols::auth::ChallengeResponse,
    deadline: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<String, VtaError> {
    loop {
        // Signed afresh on every attempt, so each is a new document. Signing
        // is local (no DID resolution, no I/O): the holder's key is right
        // here, and the VTA resolves the proof's `did:key` verification
        // method itself.
        let body = auth_di::sign_authenticate_doc(
            client_did,
            private_key_multibase,
            vta_did,
            &challenge.challenge,
            &challenge.session_id,
        )
        .await
        .map_err(|e| VtaError::Validation(e.to_string()))?;

        let resp = http
            .post(trust_tasks_url)
            .header("content-type", "application/json")
            .header(
                TRUST_TASK_HEADER,
                crate::trust_tasks::TASK_AUTH_AUTHENTICATE_0_2,
            )
            .body(body)
            .send()
            .await?;
        if resp.status().is_success() {
            return Ok(resp.text().await?);
        }
        let err = VtaError::from_response(resp).await;
        match authenticate_retry_wait(&err, deadline, chrono::Utc::now(), retry_jitter()) {
            Some(wait) => {
                tracing::info!(
                    wait_ms = wait.as_millis() as u64,
                    "authenticate rate limited; redeeming the same challenge again"
                );
                tokio::time::sleep(wait).await;
            }
            None => return Err(err),
        }
    }
}

/// The `Date` of a response, as sent: the server's clock when it answered.
pub(crate) fn response_date(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get(reqwest::header::DATE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Longest a login keeps redeeming one challenge, whatever its expiry says.
/// Well past the VTA's default challenge TTL (300 s), so it binds only on a
/// server that states a longer one and keeps refusing.
const MAX_AUTHENTICATE_RETRY_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);

/// Upper bound of the random spread added to each wait.
const MAX_AUTHENTICATE_RETRY_JITTER_MS: u64 = 1_000;

/// Shortest wait between attempts, whatever the server asked for — a
/// `Retry-After` of zero, or one already past, must not become a busy loop.
const MIN_AUTHENTICATE_RETRY_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// When to stop redeeming a challenge, on the local clock: when it expires,
/// or [`MAX_AUTHENTICATE_RETRY_WINDOW`] from `now` if that comes first.
///
/// `expires_at` (RFC 3339) is on the server's clock, so it is read against
/// `server_date` — the challenge response's `Date` header — and the lifetime
/// that leaves is counted from `now`. Comparing it with the local clock
/// instead would let skew decide: a client ahead of the server by more than
/// the TTL would never retry, and one behind would keep retrying a challenge
/// the server had already expired. A second comes off, because `Date` is
/// truncated to the second. Without a `Date`, `expires_at` is read against
/// `now`. `None` for an expiry that does not parse — not retried.
pub(crate) fn authenticate_deadline(
    expires_at: &str,
    server_date: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let expiry = chrono::DateTime::parse_from_rfc3339(expires_at)
        .ok()?
        .with_timezone(&chrono::Utc);
    let window = chrono::Duration::from_std(MAX_AUTHENTICATE_RETRY_WINDOW).ok()?;
    let lifetime = match server_date.and_then(|d| chrono::DateTime::parse_from_rfc2822(d).ok()) {
        Some(answered) => {
            expiry - answered.with_timezone(&chrono::Utc) - chrono::Duration::seconds(1)
        }
        None => expiry - now,
    };
    Some(now + lifetime.min(window))
}

/// Up to [`MAX_AUTHENTICATE_RETRY_JITTER_MS`] of spread, so clients behind one
/// address, refused together and told the same `Retry-After`, do not all come
/// back on the same instant for the one token that refilled. Not
/// security-sensitive: `RandomState` is seeded per process and advances per
/// call, which is all a spread needs.
fn retry_jitter() -> std::time::Duration {
    use std::hash::{BuildHasher, Hasher};
    let r = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    std::time::Duration::from_millis(r % MAX_AUTHENTICATE_RETRY_JITTER_MS)
}

/// How long to wait before redeeming the same challenge again, or `None` to
/// give up and return `err`.
///
/// Only a refusal by the service's own limiter is retried — the VTA's or a
/// VTC's (`x-rate-limit-source`), which refuse before any handler runs, so the
/// challenge is untouched. A proxy's 429 promises nothing of the kind.
/// The wait is the `Retry-After` (at least [`MIN_AUTHENTICATE_RETRY_WAIT`])
/// plus `jitter`, taken only if it ends before `deadline`
/// ([`authenticate_deadline`]), so a refused attempt is retried for as long as
/// the challenge it redeems is valid. No other ceiling applies: the VTA's
/// interval may be up to an hour per token, and a wait that fits the challenge
/// is always better spent than a new challenge. An unknown deadline is not
/// retried.
fn authenticate_retry_wait(
    err: &VtaError,
    deadline: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
    jitter: std::time::Duration,
) -> Option<std::time::Duration> {
    use crate::rate_limit::RateLimitSource;
    let VtaError::RateLimited {
        limited_by: RateLimitSource::Vta | RateLimitSource::Vtc,
        retry_after,
        ..
    } = err
    else {
        return None;
    };
    let wait = retry_after
        .and_then(|at| (at - now).to_std().ok())
        .unwrap_or_default()
        .max(MIN_AUTHENTICATE_RETRY_WAIT)
        + jitter;
    let resume = now + chrono::Duration::from_std(wait).ok()?;
    (resume < deadline?).then_some(wait)
}

/// Refresh an access token using the refresh token endpoint.
///
/// Returns a new `AuthResult` carrying a fresh access token **and a fresh
/// refresh token** — the VTA implements RFC 6749 §10.4 refresh-token
/// rotation, so the presented refresh token is single-use. Callers MUST
/// persist `result.refresh_token` and `result.refresh_expires_at` from
/// the returned value before the next refresh; replaying the original
/// token after a successful refresh fails with `Auth("refresh token not
/// found")`. The `VtaClient` handles this automatically (see
/// `client.rs::ensure_token_valid`).
///
/// Unlike [`challenge_response_light`] this carries no proof and works for a
/// holder of any DID method: the opaque refresh token *is* the credential
/// (RFC 6749 §10.4), so the VTA's Trust-Task refresh path verifies the token,
/// not a signer.
pub async fn refresh_token_light(
    http: &Client,
    base_url: &str,
    client_did: &str,
    vta_did: &str,
    refresh_token: &str,
) -> Result<AuthResult, crate::error::VtaError> {
    let body = auth_di::build_refresh_doc(client_did, vta_did, refresh_token)
        .map_err(|e| VtaError::Validation(e.to_string()))?;

    let refresh_url = format!("{base_url}/trust-tasks");
    let resp = http
        .post(&refresh_url)
        .header("content-type", "application/json")
        .header(TRUST_TASK_HEADER, crate::trust_tasks::TASK_AUTH_REFRESH_0_2)
        .body(body)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(VtaError::from_response(resp).await);
    }

    let auth_data = auth_di::parse_auth_response(&resp.text().await?)
        .map_err(|e| VtaError::Validation(e.to_string()))?;

    let access_expires_at = auth_data.access_expires_at_epoch().ok_or_else(|| {
        VtaError::Validation(format!(
            "VTA returned unparseable session.issuedAt: '{}'",
            auth_data.session.issued_at
        ))
    })?;
    let refresh_expires_at = auth_data.refresh_expires_at_epoch();
    Ok(AuthResult {
        access_token: auth_data.tokens.access_token,
        access_expires_at,
        refresh_token: auth_data.tokens.refresh_token,
        refresh_expires_at,
    })
}

/// Authenticate using an already-decoded credential bundle, returning an
/// `AuthResult`.
///
/// The second tuple element is a clone of the input bundle, echoed back for
/// callers that want a single expression yielding auth state + identity.
pub async fn authenticate_with_credential(
    credential: &CredentialBundle,
    url_override: Option<&str>,
) -> Result<(AuthResult, CredentialBundle, Client), crate::error::VtaError> {
    let url = url_override
        .or(credential.vta_url.as_deref())
        .ok_or_else(|| {
            VtaError::Validation("no VTA URL in credential and no override provided".into())
        })?;

    let http = Client::new();
    let result = challenge_response_light(
        &http,
        url,
        &credential.did,
        &credential.private_key_multibase,
        &credential.vta_did,
    )
    .await?;

    Ok((result, credential.clone(), http))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::RateLimitSource;
    use chrono::{Duration, TimeZone, Utc};

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn limited(limited_by: RateLimitSource, after_secs: Option<i64>) -> VtaError {
        VtaError::RateLimited {
            limited_by,
            retry_after: after_secs.map(|s| now() + Duration::seconds(s)),
            limiter: Some("auth-authenticate".into()),
            url: None,
        }
    }

    fn secs(s: u64) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_secs(s))
    }

    const NO_JITTER: std::time::Duration = std::time::Duration::ZERO;

    /// A client queued behind others keeps redeeming its challenge for as
    /// long as the challenge lives — there is no attempt count to run out of
    /// while the limiter still has capacity to give it.
    #[test]
    fn a_long_queue_is_retried_until_the_challenge_expires() {
        let expires = Some(now() + Duration::seconds(300));
        for elapsed in [0, 60, 200, 294] {
            let at = now() + Duration::seconds(elapsed);
            let err = VtaError::RateLimited {
                limited_by: RateLimitSource::Vta,
                retry_after: Some(at + Duration::seconds(5)),
                limiter: None,
                url: None,
            };
            assert_eq!(
                authenticate_retry_wait(&err, expires, at, NO_JITTER),
                secs(5),
                "{elapsed} s in"
            );
        }
    }

    #[test]
    fn jitter_is_added_and_counted_against_the_deadline() {
        let err = limited(RateLimitSource::Vta, Some(5));
        let jitter = std::time::Duration::from_millis(700);
        let roomy = Some(now() + Duration::seconds(60));
        assert_eq!(
            authenticate_retry_wait(&err, roomy, now(), jitter),
            Some(std::time::Duration::from_millis(5_700))
        );
        let tight = Some(now() + Duration::milliseconds(5_500));
        assert_eq!(authenticate_retry_wait(&err, tight, now(), jitter), None);
    }

    #[test]
    fn retry_jitter_stays_under_its_bound() {
        for _ in 0..1_000 {
            assert!(
                retry_jitter() < std::time::Duration::from_millis(MAX_AUTHENTICATE_RETRY_JITTER_MS)
            );
        }
    }

    #[test]
    fn a_vta_rate_limit_is_waited_out_while_the_challenge_lives() {
        let expires = Some(now() + Duration::seconds(60));
        let err = limited(RateLimitSource::Vta, Some(5));
        assert_eq!(
            authenticate_retry_wait(&err, expires, now(), NO_JITTER),
            secs(5)
        );
    }

    #[test]
    fn a_wait_that_outlives_the_challenge_is_not_taken() {
        let expires = Some(now() + Duration::seconds(5));
        let err = limited(RateLimitSource::Vta, Some(5));
        assert_eq!(
            authenticate_retry_wait(&err, expires, now(), NO_JITTER),
            None
        );
        assert_eq!(
            authenticate_retry_wait(&err, None, now(), NO_JITTER),
            None,
            "unknown expiry"
        );
    }

    /// The VTA's interval can be far longer than a generic retry ceiling;
    /// a wait that fits the challenge is taken whatever its length.
    #[test]
    fn a_long_wait_that_fits_the_challenge_is_taken() {
        let expires = Some(now() + Duration::seconds(300));
        let err = limited(RateLimitSource::Vta, Some(60));
        assert_eq!(
            authenticate_retry_wait(&err, expires, now(), NO_JITTER),
            secs(60)
        );
        let err = limited(RateLimitSource::Vta, Some(301));
        assert_eq!(
            authenticate_retry_wait(&err, expires, now(), NO_JITTER),
            None
        );
    }

    #[test]
    fn the_deadline_is_the_expiry_capped_by_the_retry_window() {
        let soon = (now() + Duration::seconds(300)).to_rfc3339();
        assert_eq!(
            authenticate_deadline(&soon, None, now()),
            Some(now() + Duration::seconds(300))
        );
        let late = (now() + Duration::hours(1)).to_rfc3339();
        assert_eq!(
            authenticate_deadline(&late, None, now()),
            Some(now() + Duration::seconds(600))
        );
        assert_eq!(authenticate_deadline("not a time", None, now()), None);
    }

    /// The expiry is on the server's clock: what counts is the lifetime it
    /// leaves from the server's `Date`, whichever way the clocks disagree.
    #[test]
    fn the_deadline_follows_the_servers_clock_not_ours() {
        for skew in [Duration::hours(1), Duration::hours(-1)] {
            let server_now = now() + skew;
            let expires = (server_now + Duration::seconds(300)).to_rfc3339();
            let date = server_now.to_rfc2822();
            assert_eq!(
                authenticate_deadline(&expires, Some(&date), now()),
                Some(now() + Duration::seconds(299)),
                "server clock {skew} from ours"
            );
        }
        let expires = (now() + Duration::hours(2)).to_rfc3339();
        assert_eq!(
            authenticate_deadline(&expires, Some(&now().to_rfc2822()), now()),
            Some(now() + Duration::seconds(600)),
            "still capped by the retry window"
        );
    }

    #[test]
    fn a_zero_or_missing_wait_still_waits_a_second() {
        let expires = Some(now() + Duration::seconds(60));
        for after in [Some(0), Some(-10), None] {
            let err = limited(RateLimitSource::Vta, after);
            assert_eq!(
                authenticate_retry_wait(&err, expires, now(), NO_JITTER),
                secs(1),
                "{after:?}"
            );
        }
    }

    #[test]
    fn only_the_services_own_rate_limit_is_retried() {
        let expires = Some(now() + Duration::seconds(60));
        let upstream = limited(RateLimitSource::Upstream, Some(5));
        assert_eq!(
            authenticate_retry_wait(&upstream, expires, now(), NO_JITTER),
            None
        );
        let auth = VtaError::Auth("authentication failed".into());
        assert_eq!(
            authenticate_retry_wait(&auth, expires, now(), NO_JITTER),
            None
        );
    }
}
