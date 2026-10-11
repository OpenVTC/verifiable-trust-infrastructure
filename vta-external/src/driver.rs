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
/// profile, since a provider endpoint is administrator-supplied.
pub fn probe_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(vta_sdk::http::foreign_fetch_client)
}
