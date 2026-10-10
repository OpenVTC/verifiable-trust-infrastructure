//! Sealed payloads of the `external/*` family — the VTA as the key authority for
//! cloud and third-party accounts (`docs/05-design-notes/vta-external-accounts.md`).
//!
//! Two directions, one rule: a provider secret or an issued provider credential
//! crosses the wire only inside a sealed-transfer bundle.
//!
//! - [`ExternalSecretBundle`] — an administrator's client seals an account's
//!   secret half (an S3 secret access key, an API key) to the custodian for
//!   `external/accounts/secret/set/0.1`.
//! - [`ExternalCredentialBundle`] — the custodian seals a short-lived,
//!   downscoped credential to the consumer that asked for it in
//!   `external/credentials/issue/0.1`.

use serde::{Deserialize, Serialize};

/// The payload of
/// [`SealedPayloadV1::ExternalSecret`](super::SealedPayloadV1::ExternalSecret).
///
/// Names the account it is for, so a bundle sealed for one account cannot be
/// replayed into `secret/set` for another: the custodian refuses a bundle whose
/// `context` and `account` differ from the request's.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSecretBundle {
    /// The custodian context that owns the account.
    pub context: String,
    /// The account's id within that context.
    pub account: String,
    /// The secret, as the provider issued it.
    pub secret: String,
}

impl Drop for ExternalSecretBundle {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

/// Written by hand so the secret never reaches a log.
impl std::fmt::Debug for ExternalSecretBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalSecretBundle")
            .field("context", &self.context)
            .field("account", &self.account)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The payload of
/// [`SealedPayloadV1::ExternalCredential`](super::SealedPayloadV1::ExternalCredential):
/// one issued provider credential and what it is good for.
///
/// A consumer keeps it in memory only, re-issues before `expires_at`, and drops
/// it on shutdown.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCredentialBundle {
    /// The custodian context that owns the account.
    pub context: String,
    /// The account the credential was issued under.
    pub account: String,
    /// The scope it was downscoped to, exactly as the issue response reports
    /// it (`CredentialScope`, camelCase JSON).
    pub scope: serde_json::Value,
    /// RFC 3339; the provider's actual expiry.
    pub expires_at: String,
    /// The provider's session or request id, where it gave one, so a provider
    /// audit-log entry traces back to the custodian's issuance row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_request_id: Option<String>,
    /// The credential itself.
    pub credential: ExternalCredential,
}

/// Written by hand so the credential never reaches a log.
impl std::fmt::Debug for ExternalCredentialBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalCredentialBundle")
            .field("context", &self.context)
            .field("account", &self.account)
            .field("scope", &self.scope)
            .field("expires_at", &self.expires_at)
            .field("provider_request_id", &self.provider_request_id)
            .field("credential", &"<redacted>")
            .finish()
    }
}

/// One model-specific credential. New kinds are additive variants.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ExternalCredential {
    /// AWS session credentials (`aws-roles-anywhere`).
    AwsSession {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        region: String,
    },
    /// A bearer access token (`gcp-wif-pinned`, `azure-cert`,
    /// `oauth2-private-key-jwt`).
    BearerToken {
        access_token: String,
        token_type: String,
    },
    /// One presigned request (`s3-static-presign`): exactly one method on one
    /// object. The URL carries its own signature; `headers` are the ones the
    /// consumer must send with it.
    PresignedRequest {
        method: String,
        url: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        headers: Vec<(String, String)>,
    },
}

impl Drop for ExternalCredential {
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
            Self::BearerToken { access_token, .. } => access_token.zeroize(),
            // A presigned URL is a bearer credential for one operation.
            Self::PresignedRequest { url, .. } => url.zeroize(),
        }
    }
}
