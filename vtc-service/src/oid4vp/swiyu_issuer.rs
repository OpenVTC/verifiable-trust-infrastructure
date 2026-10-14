//! swiyu issuer trust: an issuer the swiyu trust registry vouches for.
//!
//! Under swiyu Trust Protocol 2.0 a verifier trusts a credential's issuer when
//! the trust registry publishes an Identity Trust Statement about the issuer's
//! DID. With `[oid4vp.swiyu_trust]` configured, such an issuer counts as one
//! this community **recognises** — so a criterion whose `credentialIssuers` is
//! `recognised` admits it, and one asking for `community` still does not.
//!
//! [`trusted`] fetches the statement from the registry
//! (`GET {registry}/api/v2/identity-trust-statement/{did}`) and admits the
//! issuer only if all of these hold ([`check`]):
//!
//! - it is a compact JWS of `typ` `swiyu-identity-trust-statement+jwt`;
//! - its `kid` is a verification method of the configured trust-anchor DID,
//!   and it verifies under that key (resolved for `assertionMethod`);
//! - its `sub` is the issuer's DID, and it has not expired;
//! - its `status` names a Token Status List the anchor also signed, and the
//!   entry is valid. A statement with no `status` is refused: whether it was
//!   withdrawn could not be known.
//!
//! Like recognition through the community's own trust registry, the verdict is
//! never cached: a statement the registry withdraws stops counting at the next
//! presentation.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde_json::Value;
use tracing::warn;
use vta_sdk::jws::{JwsKey, sd_jwt_issuer_method};
use vti_common::auth::PurposeVmResolver;

use super::trust_statement::IDENTITY_TYP;
use crate::ceremony::CredentialStatus;
use crate::config::SwiyuTrustConfig;
use crate::recognition::StatusListFetcher;
use crate::server::AppState;

/// The largest statement accepted from the registry. One is a few kilobytes.
const MAX_STATEMENT_BYTES: usize = 64 * 1024;

/// Whether the swiyu trust registry `config` names vouches for `issuer`.
/// `false` for an issuer that is not a `did:webvh` (every swiyu actor's DID
/// is) and on any failure, which is logged.
pub async fn trusted(
    state: &AppState,
    config: &SwiyuTrustConfig,
    issuer: &str,
    now: DateTime<Utc>,
) -> bool {
    if !issuer.starts_with("did:webvh:") {
        return false;
    }
    let jwt = match fetch(config, issuer).await {
        Ok(jwt) => jwt,
        Err(e) => {
            warn!(%issuer, error = %e, "swiyu trust registry: no identity trust statement read");
            return false;
        }
    };
    let resolver = crate::credentials::vm_resolver::DidVmResolver::new(state.did_resolver.clone());
    let fetcher = crate::routes::join_requests::present::credential_status_fetcher(state);
    match check(
        &jwt,
        issuer,
        &config.trust_anchor_did,
        &resolver,
        &fetcher,
        now,
    )
    .await
    {
        Ok(()) => true,
        Err(e) => {
            warn!(%issuer, error = %e, "swiyu identity trust statement refused");
            false
        }
    }
}

/// The registry's address for `did`'s identity trust statement.
pub fn statement_url(registry_url: &str, did: &str) -> Result<url::Url, String> {
    let mut url = url::Url::parse(registry_url.trim_end_matches('/'))
        .map_err(|e| format!("registry_url `{registry_url}`: {e}"))?;
    url.path_segments_mut()
        .map_err(|()| format!("registry_url `{registry_url}` cannot take a path"))?
        .pop_if_empty()
        .extend(["api", "v2", "identity-trust-statement", did]);
    Ok(url)
}

async fn fetch(config: &SwiyuTrustConfig, did: &str) -> Result<String, String> {
    let url = statement_url(&config.registry_url, did)?;
    vta_sdk::http::guard_public_url(url.as_str()).map_err(|e| e.to_string())?;
    let response = vta_sdk::http::foreign_fetch_client()
        .get(url.clone())
        .header("accept", "application/jwt, text/plain, application/json")
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("{url}: HTTP {}", response.status()));
    }
    let body = vta_sdk::http::read_body_capped(response, MAX_STATEMENT_BYTES)
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    let text = String::from_utf8(body).map_err(|_| format!("{url}: not text"))?;
    // The registry answers with the token itself; a JSON string is accepted too.
    let text = text.trim();
    Ok(match serde_json::from_str::<String>(text) {
        Ok(token) => token,
        Err(_) => text.to_string(),
    })
}

fn header_of(jwt: &str) -> Result<Value, String> {
    let part = jwt.split('.').next().unwrap_or_default();
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| "the header is not base64url".to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| "the header is not JSON".to_string())
}

/// Check an identity trust statement about `issuer`, signed by `anchor` — see
/// the module docs.
pub async fn check(
    jwt: &str,
    issuer: &str,
    anchor: &str,
    resolver: &dyn PurposeVmResolver,
    fetcher: &dyn StatusListFetcher,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let jwt = jwt.trim();
    let header = header_of(jwt)?;
    if header.get("typ").and_then(Value::as_str) != Some(IDENTITY_TYP) {
        return Err(format!("it is not a `{IDENTITY_TYP}`"));
    }
    // The key must be the trust anchor's: a statement signed by anyone else
    // is not the registry's.
    let method = sd_jwt_issuer_method(&header, anchor)
        .map_err(|e| format!("not signed by the trust anchor: {e}"))?;
    let key = resolver
        .resolve_vm_for_purpose(&method, vti_common::auth::ProofPurpose::AssertionMethod)
        .await
        .map_err(|e| format!("the trust anchor's key {method}: {e}"))?;
    let key = JwsKey::from_resolved(&key).map_err(|e| format!("the trust anchor's key: {e}"))?;
    let payload = key
        .verify_compact(jwt)
        .map_err(|e| format!("its signature: {e}"))?;

    if payload.get("sub").and_then(Value::as_str) != Some(issuer) {
        return Err("it is about another DID".into());
    }
    let exp = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or("it has no `exp`")?;
    if exp <= now.timestamp() {
        return Err("it has expired".into());
    }
    let status = payload
        .get("status")
        .ok_or("it names no status list, so whether it was withdrawn cannot be known")?;
    match crate::routes::join_requests::present::resolve_presented_status(
        Some(status),
        Some(anchor),
        fetcher,
    )
    .await
    {
        CredentialStatus::Valid => Ok(()),
        other => Err(format!("its status is {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recognition::RecognitionError;
    use affinidi_status_list::token::{StatusListReference, TokenStatus};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const ISSUER: &str = "did:webvh:QmIssuer:identifier-reg.example:api:v1:did:issuer";

    struct Anchor {
        key: SigningKey,
        did: String,
    }

    fn anchor(seed: u8) -> Anchor {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let did = JwsKey::Ed25519(key.verifying_key().to_bytes()).did_key();
        Anchor { key, did }
    }

    impl Anchor {
        fn kid(&self) -> String {
            format!("{}#{}", self.did, self.did.trim_start_matches("did:key:"))
        }

        fn sign(&self, header: Value, payload: Value) -> String {
            let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
            let input = format!("{}.{}", enc(&header), enc(&payload));
            let sig = self.key.sign(input.as_bytes());
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
        }

        fn statement(&self, sub: &str, exp: i64, status: Option<Value>) -> String {
            let mut payload = json!({ "sub": sub, "exp": exp, "iat": 0, "jti": "j" });
            if let Some(status) = status {
                payload["status"] = status;
            }
            self.sign(
                json!({ "typ": IDENTITY_TYP, "alg": "EdDSA", "kid": self.kid() }),
                payload,
            )
        }
    }

    /// A Token Status List that answers `status`, and checks who signed it.
    struct Lists {
        status: TokenStatus,
        signer: String,
    }

    #[async_trait::async_trait]
    impl StatusListFetcher for Lists {
        async fn check_status_bit(
            &self,
            _: &str,
            _: usize,
            _: Option<&str>,
        ) -> Result<bool, RecognitionError> {
            unreachable!("a swiyu statement names a Token Status List")
        }

        async fn check_token_status(
            &self,
            _: &StatusListReference,
            expected_issuer: Option<&str>,
        ) -> Result<TokenStatus, RecognitionError> {
            if expected_issuer != Some(self.signer.as_str()) {
                return Err(RecognitionError::StatusListFailed("another signer".into()));
            }
            Ok(self.status)
        }
    }

    fn status_entry() -> Value {
        json!({ "status_list": { "idx": 3, "uri": "https://status.example/list.jwt" } })
    }

    fn resolver() -> crate::credentials::vm_resolver::DidVmResolver {
        crate::credentials::vm_resolver::DidVmResolver::new(None)
    }

    #[tokio::test]
    async fn a_current_statement_the_anchor_signed_admits_the_issuer() {
        let a = anchor(7);
        let now = Utc::now();
        let jwt = a.statement(ISSUER, now.timestamp() + 600, Some(status_entry()));
        let lists = Lists {
            status: TokenStatus::Valid,
            signer: a.did.clone(),
        };
        check(&jwt, ISSUER, &a.did, &resolver(), &lists, now)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_statement_that_does_not_hold_is_refused() {
        let a = anchor(7);
        let other = anchor(8);
        let now = Utc::now();
        let exp = now.timestamp() + 600;
        let valid = Lists {
            status: TokenStatus::Valid,
            signer: a.did.clone(),
        };
        let cases: Vec<(String, &Lists, &str)> = vec![
            // Signed by someone other than the anchor.
            (
                other.statement(ISSUER, exp, Some(status_entry())),
                &valid,
                "trust anchor",
            ),
            // About another DID.
            (
                a.statement("did:webvh:QmOther:x", exp, Some(status_entry())),
                &valid,
                "another DID",
            ),
            // Expired.
            (
                a.statement(ISSUER, now.timestamp() - 1, Some(status_entry())),
                &valid,
                "expired",
            ),
            // No status list to say it stands.
            (a.statement(ISSUER, exp, None), &valid, "no status list"),
            // Not an identity statement.
            (
                a.sign(
                    json!({ "typ": "JWT", "alg": "EdDSA", "kid": a.kid() }),
                    json!({ "sub": ISSUER, "exp": exp }),
                ),
                &valid,
                "not a",
            ),
        ];
        for (jwt, lists, says) in cases {
            let err = check(&jwt, ISSUER, &a.did, &resolver(), lists, now)
                .await
                .unwrap_err();
            assert!(err.contains(says), "{says}: {err}");
        }

        // Withdrawn, or its list signed by another than the anchor.
        let jwt = a.statement(ISSUER, exp, Some(status_entry()));
        for lists in [
            Lists {
                status: TokenStatus::Invalid,
                signer: a.did.clone(),
            },
            Lists {
                status: TokenStatus::Valid,
                signer: other.did.clone(),
            },
        ] {
            let err = check(&jwt, ISSUER, &a.did, &resolver(), &lists, now)
                .await
                .unwrap_err();
            assert!(err.contains("status"), "{err}");
        }

        // A tampered payload fails the signature.
        let mut parts: Vec<String> = jwt.split('.').map(str::to_string).collect();
        parts[1] = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({ "sub": ISSUER, "exp": exp + 1, "status": status_entry() }))
                .unwrap(),
        );
        let err = check(&parts.join("."), ISSUER, &a.did, &resolver(), &valid, now)
            .await
            .unwrap_err();
        assert!(err.contains("signature"), "{err}");
    }

    /// A configuration that would admit nobody is refused at boot.
    #[test]
    fn a_registry_that_is_not_https_or_an_anchor_that_is_not_a_did_is_refused() {
        let config = |url: &str, anchor: &str| SwiyuTrustConfig {
            registry_url: url.into(),
            trust_anchor_did: anchor.into(),
        };
        config("https://trust-reg.example", "did:webvh:QmA:x")
            .check()
            .unwrap();
        for bad in [
            config("http://trust-reg.example", "did:webvh:QmA:x"),
            config("not a url", "did:webvh:QmA:x"),
            config("https://trust-reg.example", "QmA"),
            config("https://trust-reg.example", "did:webvh:QmA:x#key-1"),
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_statement_is_read_from_the_registrys_v2_path() {
        let did = "did:webvh:QmX:identifier-reg.example:api:v1:did:abc";
        for base in ["https://trust-reg.example", "https://trust-reg.example/"] {
            assert_eq!(
                statement_url(base, did).unwrap().as_str(),
                format!("https://trust-reg.example/api/v2/identity-trust-statement/{did}")
            );
        }
    }
}
