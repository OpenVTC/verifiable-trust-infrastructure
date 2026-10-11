//! Sealed payloads of the `external/*` family — the VTA as the key authority for
//! cloud and third-party accounts (`docs/05-design-notes/vta-external-accounts.md`).
//!
//! Two directions, one rule: a provider secret or an issued provider credential
//! crosses the wire only inside a sealed-transfer bundle. The shapes are the
//! specification's `ExternalSecretPayload` and `ExternalCredentialPayload`
//! (`external/_shared/0.1/accounts.schema.json`), member for member, so a
//! client in another language opens what this one seals.
//!
//! - [`ExternalSecretPayload`] — an administrator's client seals an account's
//!   secret half (an S3 secret access key, an API key) to a single-use wrapping
//!   key from `keys/import-wrapping-key`, for `external/accounts/secret/set/0.1`.
//! - [`ExternalCredentialPayload`] — the custodian seals a short-lived,
//!   downscoped credential to the consumer that asked for it in
//!   `external/credentials/issue/0.1`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `ExternalSecretPayload`: the payload of
/// [`SealedPayloadV1::ExternalSecret`](super::SealedPayloadV1::ExternalSecret).
///
/// Names the account it is for, inside the seal, so a bundle sealed for one
/// account cannot be replayed into `secret/set` for another: the custodian
/// refuses a bundle whose `context` or `account` differs from the request's,
/// and — for `s3-static-presign` — whose `accessKeyId` differs from the
/// account's.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalSecretPayload {
    /// The custodian context that owns the account.
    pub context: String,
    /// The account's id within that context.
    pub account: String,
    /// The secret, as the provider issued it.
    pub secret: String,
    /// `s3-static-presign`: the access key id the secret belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
}

impl Drop for ExternalSecretPayload {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

/// Written by hand so the secret never reaches a log.
impl std::fmt::Debug for ExternalSecretPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalSecretPayload")
            .field("context", &self.context)
            .field("account", &self.account)
            .field("secret", &"<redacted>")
            .field("access_key_id", &self.access_key_id)
            .finish()
    }
}

/// `ExternalCredentialPayload`: the payload of
/// [`SealedPayloadV1::ExternalCredential`](super::SealedPayloadV1::ExternalCredential),
/// one issued provider credential, discriminated by `kind`.
///
/// A consumer keeps it in memory only, re-issues before it expires, and drops
/// it on shutdown. Instants are RFC 3339 strings, as on the wire.
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum ExternalCredentialPayload {
    /// AWS session credentials (`aws-roles-anywhere`).
    AwsSession {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        expiration: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        region: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_request_id: Option<String>,
    },
    /// An access token (`gcp-wif-pinned`, `azure-cert`,
    /// `oauth2-private-key-jwt`).
    BearerToken {
        token: String,
        token_type: String,
        expires_at: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_request_id: Option<String>,
    },
    /// One presigned request (`s3-static-presign`): exactly one method on one
    /// object. The URL carries its own signature; `headers` are the ones the
    /// request must carry for it to verify.
    PresignedRequest {
        method: String,
        url: String,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        headers: BTreeMap<String, String>,
        expires_at: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_request_id: Option<String>,
    },
}

impl ExternalCredentialPayload {
    /// The credential's expiry, whichever kind it is.
    pub fn expires_at(&self) -> &str {
        match self {
            Self::AwsSession { expiration, .. } => expiration,
            Self::BearerToken { expires_at, .. } | Self::PresignedRequest { expires_at, .. } => {
                expires_at
            }
        }
    }
}

impl Drop for ExternalCredentialPayload {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            Self::AwsSession {
                secret_access_key,
                session_token,
                ..
            } => {
                secret_access_key.zeroize();
                session_token.zeroize();
            }
            Self::BearerToken { token, .. } => token.zeroize(),
            // A presigned URL is a bearer credential for one operation.
            Self::PresignedRequest { url, .. } => url.zeroize(),
        }
    }
}

/// Written by hand so the credential never reaches a log.
impl std::fmt::Debug for ExternalCredentialPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::AwsSession { .. } => "awsSession",
            Self::BearerToken { .. } => "bearerToken",
            Self::PresignedRequest { .. } => "presignedRequest",
        };
        f.debug_struct("ExternalCredentialPayload")
            .field("kind", &kind)
            .field("expires_at", &self.expires_at())
            .field("credential", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The JSON form is the specification's, member for member.
    #[test]
    fn the_shapes_are_the_specifications() {
        let secret = ExternalSecretPayload {
            context: "community".into(),
            account: "r2".into(),
            secret: "s".into(),
            access_key_id: Some("AKID".into()),
        };
        assert_eq!(
            serde_json::to_value(&secret).unwrap(),
            json!({ "context": "community", "account": "r2", "secret": "s", "accessKeyId": "AKID" })
        );
        let cred = ExternalCredentialPayload::PresignedRequest {
            method: "GET".into(),
            url: "https://b.example/k?X-Amz-Signature=x".into(),
            headers: BTreeMap::new(),
            expires_at: "2026-10-10T09:00:00Z".into(),
            provider_request_id: None,
        };
        assert_eq!(
            serde_json::to_value(&cred).unwrap(),
            json!({ "kind": "presignedRequest", "method": "GET",
                    "url": "https://b.example/k?X-Amz-Signature=x", "expiresAt": "2026-10-10T09:00:00Z" })
        );
        let aws: ExternalCredentialPayload = serde_json::from_value(json!({
            "kind": "awsSession", "accessKeyId": "ASIA", "secretAccessKey": "k",
            "sessionToken": "t", "expiration": "2026-10-10T09:00:00Z", "region": "eu-west-1",
            "providerRequestId": "req-1",
        }))
        .unwrap();
        assert_eq!(aws.expires_at(), "2026-10-10T09:00:00Z");
        assert!(format!("{aws:?}").contains("<redacted>"));
        assert!(
            serde_json::from_value::<ExternalCredentialPayload>(json!({
                "kind": "bearerToken", "token": "t", "tokenType": "Bearer",
                "expiresAt": "2026-10-10T09:00:00Z", "unexpected": 1,
            }))
            .is_err(),
            "unknown members are refused"
        );
    }
}
