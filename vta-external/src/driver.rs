//! Auth-model drivers.
//!
//! One driver per `AuthModel`. The trait is the whole of what the service
//! spine knows about a model: how to check its settings, what the provider-side
//! setup is, how to issue a credential and how to probe it. A model this build
//! has no driver for cannot be created, so no account can exist that nothing
//! can use.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use vta_sdk::sealed_transfer::ExternalCredentialPayload;

use crate::model::AccountRecord;
use crate::scope::RequestedScope;

/// What an issuance asks of a driver. The binding and scope checks have
/// already passed; a driver only builds what it was asked for.
pub struct IssueRequest<'a> {
    pub account: &'a AccountRecord,
    /// The account's secret, for the static models. Unwrapped for this call
    /// only and zeroized by the caller afterwards.
    pub secret: Option<&'a str>,
    pub scope: &'a RequestedScope,
    pub ttl_seconds: u32,
    /// The binding's `sourceCidrs`, for providers that can pin a credential to
    /// a network.
    pub source_cidrs: &'a [String],
    pub now: DateTime<Utc>,
}

/// What a presign-batch issuance (`external/credentials/issue/0.2`, `presign`)
/// asks of a driver. The binding and batch checks have already passed.
pub struct BatchIssueRequest<'a> {
    pub account: &'a AccountRecord,
    /// The account's secret, unwrapped for this call only.
    pub secret: Option<&'a str>,
    pub batch: &'a crate::batch::PresignBatch,
    pub ttl_seconds: u32,
    pub now: DateTime<Utc>,
}

/// An issued credential, before sealing. The payload carries the provider's
/// request id, when there is one.
pub struct Issued {
    pub credential: ExternalCredentialPayload,
    pub expires_at: DateTime<Utc>,
}

/// A setting this custodian cannot use, naming the member at fault
/// (`external:invalidSettings`, `details.member`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsError {
    pub member: &'static str,
    pub why: String,
}

impl SettingsError {
    pub fn new(member: &'static str, why: impl Into<String>) -> Self {
        Self {
            member,
            why: why.into(),
        }
    }
}

/// Why a driver could not issue. Each maps onto a family error code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DriverError {
    /// `external:providerSetupRequired` — the account cannot be used until its
    /// provider-side setup (or its secret) is done.
    SetupRequired(String),
    /// `external:providerRefused` — the provider answered, and said no.
    Refused(String),
    /// `external:providerUnavailable` — the provider did not answer usefully.
    Unavailable(String),
    /// A fault of the custodian's own.
    Internal(String),
}

impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SetupRequired(m)
            | Self::Refused(m)
            | Self::Unavailable(m)
            | Self::Internal(m) => f.write_str(m),
        }
    }
}

/// One auth model.
#[async_trait]
pub trait ExternalAuthDriver: Send + Sync {
    /// The `AuthModel` this driver serves.
    fn model(&self) -> &'static str;

    /// Whether `external/credentials/issue` serves this model. A sign-only
    /// model (`sui-signer`) is not brokered.
    fn brokered(&self) -> bool;

    /// Whether the model holds a secret, set by `secret/set`, rather than a key.
    fn holds_secret(&self) -> bool;

    /// Checks beyond the schema: whatever the settings must satisfy for this
    /// custodian to drive them.
    fn validate_settings(&self, settings: &Value) -> Result<(), SettingsError>;

    /// The provider hosts this account's use connects to (`egressHosts`).
    fn egress_hosts(&self, settings: &Value) -> Vec<String>;

    /// The provider-side setup, as `AccountSetupArtifacts` JSON. Public
    /// material and policy only.
    fn setup(&self, account: &AccountRecord) -> Value;

    /// Build one credential.
    async fn issue(&self, req: IssueRequest<'_>) -> Result<Issued, DriverError>;

    /// Whether this model takes `presign` rather than `scope` in
    /// `external/credentials/issue/0.2` (item 4).
    fn takes_presign(&self) -> bool {
        false
    }

    /// Presign every operation of a batch (`issue/0.2`, `presign`). Only a model
    /// that [`takes_presign`](Self::takes_presign) is asked.
    async fn issue_batch(&self, req: BatchIssueRequest<'_>) -> Result<Issued, DriverError> {
        let _ = req;
        Err(DriverError::Internal(format!(
            "the {} model does not presign batches",
            self.model()
        )))
    }

    /// Exercise the account end to end; `AccountProbeReport` JSON. `complete`
    /// is true only when the canary steps ran.
    async fn probe(
        &self,
        account: &AccountRecord,
        secret: Option<&str>,
        http: &reqwest::Client,
        now: DateTime<Utc>,
    ) -> Value;
}

/// The driver for `model`, when this build serves it.
pub fn driver_for(model: &str) -> Option<&'static dyn ExternalAuthDriver> {
    static S3_PRESIGN: crate::s3_presign::S3StaticPresign = crate::s3_presign::S3StaticPresign;
    match model {
        "s3-static-presign" => Some(&S3_PRESIGN),
        _ => None,
    }
}

/// Every model this build serves, for operator tooling and error messages.
pub const SUPPORTED_MODELS: &[&str] = &["s3-static-presign"];

/// One process-wide client for probes: the SSRF-hardened foreign-fetch
/// profile (no redirects, no proxy, vetted DNS answers), since a provider
/// endpoint is administrator-supplied — under the process's endpoint policy,
/// so a store on a private network or loopback (MinIO on a LAN, LocalStack) is
/// reachable only when the operator set `VTA_ALLOW_PRIVATE_ENDPOINTS`, the same
/// switch that lets this VTA resolve a DID on such a host. Public-only otherwise.
pub fn probe_client() -> &'static reqwest::Client {
    probe_client_for(vta_sdk::http::EndpointPolicy::process_default())
}

/// [`probe_client`] under an explicit endpoint policy.
pub fn probe_client_for(policy: vta_sdk::http::EndpointPolicy) -> &'static reqwest::Client {
    static PUBLIC: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    static PRIVATE: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let cell = if policy.allow_private {
        &PRIVATE
    } else {
        &PUBLIC
    };
    cell.get_or_init(|| vta_sdk::http::foreign_fetch_client_for(policy))
}
