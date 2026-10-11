//! Reading an IETF Token Status List (`statuslist+jwt`) for a credential — the
//! one path the vault and the VTC both take (#1988).
//!
//! The decoding and the §8.3 claim checks are the TDK's
//! ([`affinidi_status_list::token`]). What this adds is the trust decision the
//! TDK leaves to its caller: **whose** signature makes a list authoritative.
//!
//! # The list must be signed by the credential's issuer
//!
//! A status list decides whether a credential is revoked, so a list anyone can
//! sign is a list anyone can use to revoke — or un-revoke — someone else's
//! credential. The token's `kid` must therefore name a verification method of
//! the credential's own issuer (or be that `did:key`'s one key), resolved for
//! `assertionMethod`, and a token that names an `iss` must name that issuer. The
//! signature is checked with the key's own algorithm ([`JwsKey`]) before
//! anything in the payload is read.
//!
//! The draft also lets a separate Status Issuer sign, its key linked to the
//! issuer's through a certificate chain (§13.5). That model is not supported: a
//! list signed by any other key is refused, and its credential's status is
//! indeterminate (VTI-CRD-012), never valid.

use affinidi_status_list::token::{StatusListReference, VerifiedStatusListToken, VerifyOptions};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use crate::jws::{JwsKey, sd_jwt_issuer_method};
use crate::trust_task_proof::{ProofPurpose, PurposeVmResolver};

pub use affinidi_status_list::token::{STATUS_LIST_JWT_MEDIA_TYPE, TokenStatus};

/// Why a Status List Token could not be fetched or trusted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenStatusListError {
    /// The token could not be fetched.
    #[error("status list token {uri} could not be fetched: {detail}")]
    Fetch { uri: String, detail: String },
    /// The token is not a JWS with a readable header.
    #[error("status list token is malformed: {0}")]
    Malformed(String),
    /// The token is not signed by the credential's issuer, or names another
    /// issuer.
    #[error("status list token is not the credential issuer's: {0}")]
    Issuer(String),
    /// The signing key did not resolve, or cannot verify a JWS.
    #[error("status list token signing key: {0}")]
    Key(String),
    /// The signature, `typ`, `sub`, `iat`, `exp` or list was refused.
    #[error("status list token refused: {0}")]
    Rejected(#[from] affinidi_status_list::StatusListError),
}

/// Verify a compact `statuslist+jwt` served for `reference`, as the list of
/// `credential_issuer`'s credential.
///
/// The token's header is read, unverified, only to select the signing key: its
/// `kid` must be a method of `credential_issuer`
/// ([`sd_jwt_issuer_method`]). That key is resolved through `resolver` for
/// `assertionMethod`, and the TDK's
/// [`VerifiedStatusListToken::verify`] checks the signature with it before
/// reading `typ`, `sub` (= `reference.uri`), `iat`, `exp` and the list. A token
/// whose `iss` names anyone but `credential_issuer` is then refused.
pub async fn verify_status_list_token(
    jwt: &str,
    reference: &StatusListReference,
    credential_issuer: &str,
    resolver: &(dyn PurposeVmResolver + '_),
    now_unix: i64,
) -> Result<VerifiedStatusListToken, TokenStatusListError> {
    let header = jwt
        .split('.')
        .next()
        .and_then(|segment| URL_SAFE_NO_PAD.decode(segment).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(Value::is_object)
        .ok_or_else(|| TokenStatusListError::Malformed("no JSON header".into()))?;

    let method = sd_jwt_issuer_method(&header, credential_issuer)
        .map_err(|e| TokenStatusListError::Issuer(e.to_string()))?;
    let resolved = resolver
        .resolve_vm_for_purpose(&method, ProofPurpose::AssertionMethod)
        .await
        .map_err(|e| TokenStatusListError::Key(e.to_string()))?;
    let key =
        JwsKey::from_resolved(&resolved).map_err(|e| TokenStatusListError::Key(e.to_string()))?;

    let token = VerifiedStatusListToken::verify(
        jwt,
        reference,
        &VerifyOptions::at(now_unix),
        |compact, _header| key.verify_compact(compact),
    )?;

    if let Some(iss) = token.issuer()
        && iss != credential_issuer
    {
        return Err(TokenStatusListError::Issuer(format!(
            "the token's `iss` ({iss}) is not the credential's issuer ({credential_issuer})"
        )));
    }
    Ok(token)
}

/// Fetch, verify and read the status of `reference` — the whole holder- or
/// verifier-side check for one credential.
///
/// The `uri` comes from the credential, so it is attacker-influenced: it is
/// checked by [`crate::http::guard_public_url`] before dialling, fetched with
/// the hardened foreign-fetch `client` (no redirects), and read under
/// [`crate::http::DEFAULT_MAX_FOREIGN_BODY`].
#[cfg(feature = "client")]
pub async fn resolve_token_status(
    client: &reqwest::Client,
    reference: &StatusListReference,
    credential_issuer: &str,
    resolver: &(dyn PurposeVmResolver + '_),
    now_unix: i64,
) -> Result<TokenStatus, TokenStatusListError> {
    let uri = reference.uri.as_str();
    let fetch_failed = |detail: String| TokenStatusListError::Fetch {
        uri: uri.to_string(),
        detail,
    };
    crate::http::guard_public_url(uri).map_err(|e| fetch_failed(e.to_string()))?;
    let response = client
        .get(uri)
        .header(reqwest::header::ACCEPT, STATUS_LIST_JWT_MEDIA_TYPE)
        .send()
        .await
        .map_err(|e| fetch_failed(e.to_string()))?
        .error_for_status()
        .map_err(|e| fetch_failed(e.to_string()))?;
    let body = crate::http::read_body_capped(response, crate::http::DEFAULT_MAX_FOREIGN_BODY)
        .await
        .map_err(|e| fetch_failed(e.to_string()))?;
    let jwt = std::str::from_utf8(&body)
        .map_err(|_| fetch_failed("the body is not UTF-8".into()))?
        .trim();

    let token =
        verify_status_list_token(jwt, reference, credential_issuer, resolver, now_unix).await?;
    Ok(token.status_of(reference)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_data_integrity::{DataIntegrityError, ResolvedKey};
    use affinidi_secrets_resolver::secrets::KeyType;
    use affinidi_status_list::token::{TokenStatusList, status_list_token_payload};
    use serde_json::json;

    const ISSUER: &str = "did:web:issuer.example";
    const URI: &str = "https://issuer.example/statuslists/1";

    /// The issuer's DID document without the network: one P-256 assertion key.
    struct IssuerKeys(String, ResolvedKey);

    #[async_trait::async_trait]
    impl PurposeVmResolver for IssuerKeys {
        async fn resolve_vm_for_purpose(
            &self,
            vm: &str,
            purpose: ProofPurpose,
        ) -> Result<ResolvedKey, DataIntegrityError> {
            if vm == self.0 && purpose == ProofPurpose::AssertionMethod {
                Ok(self.1.clone())
            } else {
                Err(DataIntegrityError::Resolver(format!("{vm} not listed")))
            }
        }
    }

    struct Issuer {
        private: Vec<u8>,
        keys: IssuerKeys,
    }

    fn issuer(seed: u8) -> Issuer {
        let kp = affinidi_crypto::p256::generate(Some(&[seed; 32])).unwrap();
        Issuer {
            private: kp.private_bytes,
            keys: IssuerKeys(
                format!("{ISSUER}#k1"),
                ResolvedKey::new(KeyType::P256, kp.public_bytes),
            ),
        }
    }

    fn reference(idx: u64) -> StatusListReference {
        StatusListReference {
            idx,
            uri: URI.to_string(),
        }
    }

    fn sign(private: &[u8], header: &Value, payload: &Value) -> String {
        let encode = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        let input = format!("{}.{}", encode(header), encode(payload));
        let sig = affinidi_crypto::p256::sign(private, input.as_bytes()).unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    fn list() -> TokenStatusList {
        let mut list = TokenStatusList::new(2, 64).unwrap();
        list.set(3, TokenStatus::Invalid).unwrap();
        list.set(4, TokenStatus::Suspended).unwrap();
        list
    }

    fn token(private: &[u8], kid: &str, iss: Option<&str>) -> String {
        let mut payload =
            status_list_token_payload(URI, 1_000, Some(9_000), None, &list()).unwrap();
        if let Some(iss) = iss {
            payload["iss"] = json!(iss);
        }
        sign(
            private,
            &json!({ "alg": "ES256", "typ": "statuslist+jwt", "kid": kid }),
            &payload,
        )
    }

    /// The issuer's own key signs its list; the entries read back.
    #[tokio::test]
    async fn the_issuers_signed_list_is_read() {
        let issuer = issuer(0x11);
        let jwt = token(&issuer.private, &format!("{ISSUER}#k1"), Some(ISSUER));
        let verified = verify_status_list_token(&jwt, &reference(3), ISSUER, &issuer.keys, 2_000)
            .await
            .expect("the issuer's list");
        assert_eq!(
            verified.status_of(&reference(3)).unwrap(),
            TokenStatus::Invalid
        );
        assert_eq!(
            verified.status_of(&reference(4)).unwrap(),
            TokenStatus::Suspended
        );
        assert_eq!(
            verified.status_of(&reference(5)).unwrap(),
            TokenStatus::Valid
        );
    }

    /// A list signed by another DID's key is refused before any key is
    /// resolved: anyone able to sign it could otherwise revoke the credential.
    #[tokio::test]
    async fn a_list_signed_under_another_did_is_refused() {
        let other = issuer(0x12);
        let jwt = token(&other.private, "did:web:attacker.example#k1", None);
        let err = verify_status_list_token(&jwt, &reference(3), ISSUER, &other.keys, 2_000)
            .await
            .unwrap_err();
        assert!(matches!(err, TokenStatusListError::Issuer(_)), "{err}");
    }

    /// The right `kid` but the wrong key: the signature fails.
    #[tokio::test]
    async fn a_forged_signature_is_refused() {
        let real = issuer(0x13);
        let forger = issuer(0x14);
        let jwt = token(&forger.private, &format!("{ISSUER}#k1"), None);
        let err = verify_status_list_token(&jwt, &reference(3), ISSUER, &real.keys, 2_000)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                TokenStatusListError::Rejected(affinidi_status_list::StatusListError::Signature(_))
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_token_naming_another_iss_is_refused() {
        let issuer = issuer(0x15);
        let jwt = token(
            &issuer.private,
            &format!("{ISSUER}#k1"),
            Some("did:web:other.example"),
        );
        let err = verify_status_list_token(&jwt, &reference(3), ISSUER, &issuer.keys, 2_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("`iss`"), "{err}");
    }

    /// A token served for another URI does not answer for this reference.
    #[tokio::test]
    async fn sub_must_be_the_referenced_uri() {
        let issuer = issuer(0x16);
        let jwt = token(&issuer.private, &format!("{ISSUER}#k1"), None);
        let elsewhere = StatusListReference {
            idx: 3,
            uri: "https://issuer.example/statuslists/2".into(),
        };
        let err = verify_status_list_token(&jwt, &elsewhere, ISSUER, &issuer.keys, 2_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("sub"), "{err}");
    }

    #[tokio::test]
    async fn an_expired_list_is_refused() {
        let issuer = issuer(0x17);
        let jwt = token(&issuer.private, &format!("{ISSUER}#k1"), None);
        let err = verify_status_list_token(&jwt, &reference(3), ISSUER, &issuer.keys, 10_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }
}
