use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use vti_common::error::AppError;

// Re-export shared config types
pub use vti_common::config::{
    AuditConfig, AuthConfig, LogConfig, LogFormat, MessagingConfig, StoreConfig, VaultConfig,
};
// The `[secrets]` config shape + its seed-store backends live in the shared
// `vti-secrets` crate (issue #501). Re-exported here so `AppConfig.secrets`
// and every `crate::config::SecretsConfig` reference are unchanged.
pub use vti_secrets::{SecretBackend, SecretsConfig};

/// Typed, allowlisted tenant-config overlay for un-baked TEE (`BAKE_CONFIG=false`)
/// deployments. See `docs/05-design-notes/tenant-config-allowlist.md`.
pub mod tenant_overlay;
pub use tenant_overlay::{
    TenantConfigOverlay, TenantKmsOverlay, TenantMessagingOverlay, TenantOverlayError,
};

/// Policy Decision Point configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PolicyConfig {
    /// When true, every dispatched Trust Task is evaluated by the PDP before its
    /// handler runs, and a non-`allow` decision rejects the task. **Default
    /// false** — enforcement is opt-in so a deployment turns it on deliberately,
    /// after authoring policies. The boot-installed baseline allows current
    /// flows, so enabling this changes nothing until an operator adds a
    /// restrictive, higher-priority policy (expand-before-contract).
    #[serde(default)]
    pub enforcement: bool,
    /// Named approver sets a policy's `requireConsent` references by name; each
    /// maps to the DIDs permitted to approve a task's execution. Empty by
    /// default — a `requireConsent` naming an unknown or empty set can never be
    /// satisfied (fail-closed), so operators define sets before using them.
    ///
    /// **Seed, not source of truth.** Approver sets now live on the declarative
    /// approvals row in the policy keyspace, editable at runtime with
    /// `pnm approvals approvers`. What is here is copied into that row the first
    /// time the VTA boots without one, so an IaC-provisioned or freshly-restored
    /// VTA comes up already configured. After that the row wins and this is
    /// inert: re-reading it every boot would silently undo runtime edits on the
    /// next restart, which is the trap the old reconcile-every-boot consent
    /// policy had.
    #[serde(default)]
    pub approver_sets: std::collections::HashMap<String, Vec<String>>,
    /// Declarative approval rules — which tasks require re-authentication or
    /// consent before they run.
    ///
    /// Same seed-once semantics as [`PolicyConfig::approver_sets`]: this is the
    /// bring-up path for a VTA with no declarative row yet, not a second place
    /// the rules live. Read them back (and change them) with `pnm approvals`.
    #[serde(default)]
    pub approvals: Vec<vta_sdk::approvals::ApprovalRule>,
    /// Refuse any task for which this build knows no payload schema.
    ///
    /// Payload validation always runs where a schema *is* known — that is not
    /// optional and has no switch. This governs the other case: 62 of the tasks
    /// this VTA dispatches have no published spec yet, and refusing them outright
    /// would break them.
    ///
    /// So the default is to validate what we can, warn about what we cannot, and
    /// proceed. An operator who would rather fail closed sets this — and should
    /// understand what they are choosing: "no schema" currently means "no spec has
    /// been written", not "this task is suspicious".
    ///
    /// **Default false.** It is a stopgap, and the honest fix is to write the
    /// missing specs.
    #[serde(default)]
    pub require_payload_schema: bool,
    /// Retired: `[[policy.require_consent]]`.
    ///
    /// Present only to **refuse** a config that still declares it. It was the
    /// third way to tell a VTA an operation needs a human — alongside the
    /// `[auth.step_up]` floors and [`Self::approvals`] — and it behaved
    /// differently from both: reconciled from the file on every boot, so it
    /// silently reverted anything an operator changed at runtime.
    ///
    /// [`Self::approvals`] replaces it and is seeded once, then owned by
    /// `pnm approvals` — which is the difference that matters. A rule you can
    /// change at runtime and read back is a rule you can diagnose.
    ///
    /// Absent (the only accepted state) deserializes to `()` via `default`.
    #[serde(
        default,
        deserialize_with = "refuse_retired_require_consent",
        skip_serializing
    )]
    pub require_consent: (),
}

/// Reject `[[policy.require_consent]]` with the migration the operator needs.
///
/// Only ever called when the key is present — `#[serde(default)]` covers its
/// absence — so reaching this function *is* the error.
fn refuse_retired_require_consent<'de, D>(_: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    Err(serde::de::Error::custom(
        "`[[policy.require_consent]]` has been retired. It was a third, separate \
         way to say \"this task needs a human\", reconciled from the file on \
         every boot — so it silently reverted anything changed at runtime. \
         Declare the same requirements under `[policy.approvals]` (seeded once, \
         then owned by `pnm approvals require <task-uri> --consent --set \
         <approver-set>`), and delete this section. A VTA upgraded with the old \
         section still present drops the rule it synthesized on first boot, so \
         leaving it in place would enforce nothing regardless.",
    ))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub vta_did: Option<String>,
    #[serde(alias = "community_name")]
    pub vta_name: Option<String>,
    pub public_url: Option<String>,
    /// WebSocket URL of a remote DID resolver (network mode).
    /// When set, the VTA uses the remote resolver instead of resolving locally.
    /// Format: `ws://host:port/did/v1/ws`
    /// In TEE mode, this points to the affinidi-did-resolver-cache-server
    /// sidecar on the parent, bridged via vsock.
    #[serde(default)]
    pub resolver_url: Option<String>,
    #[serde(default = "default_server_config")]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default = "default_store_config")]
    pub store: StoreConfig,
    pub messaging: Option<MessagingConfig>,
    /// Startup readiness gate + reconnect policy for the mediator DIDComm
    /// connection: wait until the VTA's own DID resolves over the network before
    /// initiating the outbound mediator handshake, then keep the connection up.
    /// See `docs/02-vta/mediator-connection.md`.
    #[serde(default)]
    pub mediator_readiness: MediatorReadinessConfig,
    #[serde(default)]
    pub services: ServicesConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    /// Vault lifecycle tuning (soft-delete grace window). Shared by the
    /// password vault and the credential store.
    #[serde(default)]
    pub vault: VaultConfig,
    /// Policy Decision Point settings (enforcement toggle).
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    /// Verifier DIDs the holder **auto-consents** to when answering a
    /// `credential-exchange/query` (`present_or_defer`'s `ConsentPolicy`). Any
    /// verifier not listed **defers** to an out-of-band approval. Default empty
    /// (defer everything) — a safe default; operators trust specific verifiers.
    #[serde(default)]
    pub trusted_presentation_verifiers: Vec<String>,
    /// The VTA-managed holder identity (a registered derived `subject_did`) the
    /// VTA **auto-accepts** offered credentials for: when set, an inbound
    /// `credential-exchange/offer` is answered with a `request` binding the new
    /// credential to this DID. Default unset — the VTA does **not** accept
    /// unsolicited offers (a safe default; opt in by naming the holder identity).
    #[serde(default)]
    pub credential_holder_did: Option<String>,
    #[cfg(feature = "tee")]
    #[serde(default)]
    pub tee: TeeConfig,
    /// Non-TEE hardened configuration: derive the storage-encryption key and JWT signing
    /// key from the master seed at boot, keeping both secrets out of
    /// `config.toml`. See `hardened.rs` for details.
    #[serde(default)]
    pub hardened: HardenedConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
    /// Dotted paths of keys present in the parsed `config.toml` that no
    /// field of `AppConfig` claims — typos, removed/renamed settings, or
    /// keys meant for a different section. Collected by `load()` (via
    /// `serde_ignored`) and surfaced as advisory warnings in `validate()`.
    /// `#[serde(skip)]` so it never round-trips through the file itself.
    /// We *warn* rather than reject (no `deny_unknown_fields`): an existing
    /// deployment may legitimately carry a legacy/extra key, and a config
    /// that boots fine today must keep booting (P0.9b).
    #[serde(skip)]
    pub unknown_keys: Vec<String>,
}

/// How the mediator self-readiness gate behaves when it times out.
/// See [`MediatorReadinessConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessTimeoutPolicy {
    /// Skip DIDComm startup this boot. `/health` stays live so the LB can turn
    /// the target healthy; a later restart reconnects. Default.
    #[default]
    Skip,
    /// Connect to the mediator anyway (best-effort), accepting that the
    /// handshake may be rejected because the mediator can't resolve us yet.
    Proceed,
    /// Treat a DID that won't resolve as fatal and shut the process down.
    Fail,
}

/// Startup readiness gate for the mediator DIDComm connection.
///
/// On cold start a VTA can initiate its outbound mediator handshake before its
/// own DID document is resolvable — the DID host hasn't published it, or the
/// load-balancer target fronting it isn't healthy yet. The mediator
/// authenticates the VTA by resolving that DID itself, so it can't get the key
/// to decrypt the authcrypt handshake and rejects it, producing a burst of 403s.
///
/// This gate makes the VTA wait until its own DID **fully resolves over the
/// network** — through the configured resolver, so it exercises the same path
/// the mediator takes — before connecting. Only network-resolved methods
/// (`did:webvh`, `did:web`) are gated; a `did:key` VTA resolves from its own
/// identifier with no network fetch and skips the wait.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MediatorReadinessConfig {
    /// Enable the gate. Default `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Base (initial) seconds between probe attempts. The actual wait uses
    /// capped exponential backoff with full jitter — attempt `n` sleeps a
    /// random duration in `[0, min(backoff_cap_secs, retry_secs * 2^n)]` — so a
    /// fleet of VTAs coming up together doesn't probe in lock-step. Default 5.
    #[serde(default = "default_readiness_retry_secs")]
    pub retry_secs: u64,
    /// Upper bound on the per-attempt backoff interval (the "cap" in the
    /// exponential-backoff-with-jitter scheme). The jittered wait never exceeds
    /// this. Default 30.
    #[serde(default = "default_readiness_backoff_cap_secs")]
    pub backoff_cap_secs: u64,
    /// Maximum seconds the gate waits before applying `on_timeout`. The wait is
    /// cancellable: a shutdown signal abandons it immediately rather than
    /// holding the process open for the remainder. Default 300.
    #[serde(default = "default_readiness_max_wait_secs")]
    pub max_wait_secs: u64,
    /// What to do when the gate times out. Default `skip`.
    #[serde(default)]
    pub on_timeout: ReadinessTimeoutPolicy,
    /// Persistent reconnect supervisor. After the self-readiness gate passes,
    /// the mediator connect can still fail — most commonly because the
    /// mediator's *own* resolver holds a negative-cache entry for the VTA host
    /// and can't fetch our DID document to complete the authcrypt handshake
    /// (a `NetworkError{status_code:None}` → 403). That clears itself once the
    /// mediator's negative cache expires, so rather than give up until the next
    /// restart, keep retrying with capped exponential backoff + full jitter.
    /// Each attempt first re-confirms the VTA can resolve its own DID, so the
    /// mediator is never touched while the VTA is unresolvable.
    ///
    /// This also covers an *established* session whose inbound loop ends: the
    /// supervisor tears the session down and reconnects, instead of leaving the
    /// VTA silently deaf until an operator restarts it. Setting this `false`
    /// restores the legacy single-shot behaviour (one attempt, then nothing
    /// until the next restart). Default `true`.
    #[serde(default = "default_true")]
    pub reconnect: bool,
    /// Upper bound on the reconnect backoff interval (seconds) — the "cap" for
    /// the persistent-reconnect scheme. The jittered retry wait never exceeds
    /// this. Larger than `backoff_cap_secs` (the gate's cap) because the
    /// reconnect horizon must comfortably outlast a resolver negative-cache TTL,
    /// which can be many minutes. Default 60.
    #[serde(default = "default_reconnect_backoff_cap_secs")]
    pub reconnect_backoff_cap_secs: u64,
    /// Give up reconnecting after this many seconds of *continuous* failure.
    /// `0` = never give up (retry forever at the capped, jittered interval).
    /// A bounded retry rate is safe to run indefinitely and lets the VTA
    /// self-heal without any operator restart.
    ///
    /// The clock is measured from the start of the current run of failures, not
    /// from process start, and resets after any session that stayed up long
    /// enough to count as healthy — so a VTA that ran for a week and then
    /// dropped gets the full budget rather than one it exhausted days ago.
    /// Default 0.
    #[serde(default)]
    pub reconnect_max_elapsed_secs: u64,
}

fn default_readiness_retry_secs() -> u64 {
    5
}

fn default_reconnect_backoff_cap_secs() -> u64 {
    60
}

fn default_readiness_backoff_cap_secs() -> u64 {
    30
}

fn default_readiness_max_wait_secs() -> u64 {
    300
}

impl Default for MediatorReadinessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retry_secs: default_readiness_retry_secs(),
            backoff_cap_secs: default_readiness_backoff_cap_secs(),
            max_wait_secs: default_readiness_max_wait_secs(),
            on_timeout: ReadinessTimeoutPolicy::Skip,
            reconnect: true,
            reconnect_backoff_cap_secs: default_reconnect_backoff_cap_secs(),
            reconnect_max_elapsed_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServicesConfig {
    #[serde(default = "default_true")]
    pub rest: bool,
    #[serde(default = "default_true")]
    pub didcomm: bool,
    /// WebAuthn-RP service — the dedicated `/auth/portal` +
    /// `/auth/passkey-login/*` + `/did/verification-methods/passkey/*`
    /// surface. Distinct from `rest` so an operator can run a
    /// REST-less, browser-facing-only VTA (e.g. one that only
    /// publishes WebAuthn flows for end-users plus DIDComm for
    /// programmatic peers). Defaults to `false` because legacy
    /// installs don't have this surface enabled; new installs that
    /// want browser-side passkey login flip this on explicitly.
    #[serde(default)]
    pub webauthn: bool,
    /// Trust Spanning Protocol transport. Additive and `false` by
    /// default while TSP rolls out gated — DIDComm stays the default
    /// transport. When enabled, the VTA advertises a `#tsp`
    /// `TSPTransport` service (pointing at the same mediator as
    /// DIDComm). See `docs/05-design-notes/tsp-enablement.md`.
    #[serde(default)]
    pub tsp: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ServicesConfig {
    fn default() -> Self {
        Self {
            rest: true,
            didcomm: true,
            webauthn: false,
            tsp: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Origins permitted to make cross-origin requests against the
    /// VTA's REST surface. Empty (default) disables the CORS layer
    /// entirely — a fresh-install VTA refuses cross-origin requests
    /// the way the legacy behaviour did. Production deployments
    /// typically leave this empty (programmatic clients send the
    /// bearer token directly and don't need browser-side CORS); the
    /// demo at `examples/vta-auth-demo/` sets it to
    /// `["http://localhost:8000"]` so an operator can drive the
    /// auth flow from a browser running on a different localhost
    /// port.
    ///
    /// Each entry is matched exactly against the request's `Origin`
    /// header. Wildcards are not accepted — bearer credentials must
    /// not flow to arbitrary origins.
    #[serde(default)]
    pub cors_origins: Vec<String>,
    /// Whether to trust `X-Forwarded-For` / `Forwarded` headers
    /// for client-IP attribution in the per-IP rate limiter.
    ///
    /// Default `false` — the rate limiter keys on the socket
    /// peer-IP (`PeerIpKeyExtractor`). This is the safe default
    /// for direct-binding deployments where an attacker can spoof
    /// `X-Forwarded-For` to evade rate limiting.
    ///
    /// Set `true` only when the VTA runs behind a trust-boundary
    /// reverse proxy (Nginx, Envoy, ALB) that overwrites or
    /// strips these headers from external requests — the rate
    /// limiter switches to `SmartIpKeyExtractor` and walks the
    /// `X-Forwarded-For` chain. Misconfiguring this (`trust_xff =
    /// true` with no proxy, or a misconfigured proxy that doesn't
    /// strip the header) is a silent rate-limit bypass.
    ///
    /// Closes L2 from the May 2026 security review.
    #[serde(default)]
    pub trust_xff: bool,
    /// Token replenishment interval for the unauth rate limiter, in **seconds
    /// per token** — not requests per second. One new token every
    /// `rate_limit_interval_secs`, so *lower is more permissive*. Default: 5.
    ///
    /// With the default `rate_limit_burst = 10`: 10 rapid requests, then one
    /// every 5 s. Local dev that fires a bootstrap flow in a burst wants
    /// `rate_limit_interval_secs = 1` and a larger `rate_limit_burst`.
    ///
    /// Zero is clamped to 1 at router build (`routes::apply_unauth_governor`);
    /// the limiter cannot be turned off from config.
    #[serde(default = "default_rate_limit_interval_secs")]
    pub rate_limit_interval_secs: u64,
    /// Burst capacity for the unauth rate limiter — how many requests can
    /// arrive back-to-back before throttling starts. Default: 10. Zero is
    /// clamped to 1.
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8100
}

fn default_rate_limit_interval_secs() -> u64 {
    5
}

fn default_rate_limit_burst() -> u32 {
    10
}

fn default_server_config() -> ServerConfig {
    ServerConfig::default()
}

fn default_store_config() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/vta"),
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            cors_origins: Vec::new(),
            trust_xff: false,
            rate_limit_interval_secs: default_rate_limit_interval_secs(),
            rate_limit_burst: default_rate_limit_burst(),
        }
    }
}

/// TEE attestation configuration.
#[cfg(feature = "tee")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeeConfig {
    /// Enforcement mode: required, optional, disabled, simulated.
    #[serde(default)]
    pub mode: TeeMode,
    /// Whether to embed attestation info as a DID document service.
    #[serde(default)]
    pub embed_in_did: bool,
    /// Attestation report cache TTL in seconds (generation is expensive).
    #[serde(default = "default_attestation_cache_ttl")]
    pub attestation_cache_ttl: u64,
    /// KMS-based secret bootstrap configuration (for Nitro Enclaves).
    #[serde(default)]
    pub kms: Option<TeeKmsConfig>,
    /// Storage encryption salt (change to invalidate all stored data).
    /// WARNING: Changing this value invalidates all encrypted storage.
    #[serde(default = "default_storage_key_salt")]
    pub storage_key_salt: String,
    /// Restrict which DID methods are accepted for ACL entries and authentication.
    /// When set, only DIDs matching these prefixes are allowed (e.g., `["did:key", "did:webvh"]`).
    /// When `None`, all DID methods are accepted (less secure with parent-side resolver).
    #[serde(default)]
    pub allowed_did_methods: Option<Vec<String>>,
    /// AWS account IDs this image's tenant overlay may hand a `tee.kms.key_arn`
    /// from (un-baked fleet mode — see `crate::tenant_overlay` and
    /// `docs/05-design-notes/tenant-config-allowlist.md` §3.5).
    ///
    /// Baked, PCR0-committed — the parent cannot extend this list at runtime.
    /// **Empty means "no tenant overlay `key_arn` accepted"** (fail closed, not
    /// "allow all"). Irrelevant for `BAKE_CONFIG=true`/self-host builds, which
    /// never accept an overlay.
    #[serde(default)]
    pub allowed_kms_accounts: Vec<String>,
}

/// KMS configuration for TEE secret bootstrap.
#[cfg(feature = "tee")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeeKmsConfig {
    /// AWS region for KMS calls.
    pub region: String,
    /// KMS key ARN used to encrypt/decrypt VTA secrets.
    pub key_arn: String,
    /// Template for auto-generating a did:webvh identity on first boot.
    ///
    /// Use `{SCID}` as a placeholder for the self-certifying identifier:
    ///   `did:webvh:{SCID}:example.com:vta`
    ///
    /// On first boot, the VTA derives keys from the bootstrapped seed,
    /// creates the DID, and persists it in the encrypted store.
    ///
    /// Ignored if `vta_did` is already set in config or the store.
    #[serde(default)]
    pub vta_did_template: Option<String>,
    /// Context ID used for the auto-bootstrapped admin (default: "default").
    ///
    /// On first boot, the VTA auto-creates this context and grants the
    /// admin_did super-admin access.
    #[serde(default = "default_admin_context_id")]
    pub admin_context_id: String,
    /// DID to grant super-admin access on first boot.
    ///
    /// The operator generates a `did:key` locally (e.g., via `pnm setup`),
    /// sets it here before building the EIF, and connects to the VTA using
    /// the corresponding private key after boot. The private key never
    /// touches the TEE or the parent instance.
    ///
    /// If not set, the VTA auto-generates a random `did:key` and stores
    /// the credential in the bootstrap keyspace (retrievable via REST).
    #[serde(default)]
    pub admin_did: Option<String>,
    /// Allow falling back to non-attested KMS calls when the attested path
    /// fails on real Nitro hardware (`/dev/nsm` present).
    ///
    /// **Default: false.** On production hardware a failure to use the
    /// Nitro `Recipient` parameter must be terminal — otherwise a transient
    /// NSM hiccup silently downgrades to an IAM-only KMS call, bypassing
    /// the key policy's PCR conditions (PCR0/PCR8). The fallback path stays
    /// available for simulated mode (no `/dev/nsm`), which uses the direct
    /// KMS call regardless of this flag.
    ///
    /// Set to `true` only as a break-glass measure during incident response,
    /// understanding that decrypts will then only require the enclave's IAM
    /// role, not an attested PCR match.
    #[serde(default)]
    pub allow_unattested_fallback: bool,
    /// Allow initializing the JWT key fingerprint when none is stored.
    ///
    /// **Default: false.** A missing fingerprint on a subsequent boot is
    /// suspicious — the only legitimate cause is first boot after upgrading
    /// from a pre-fingerprint VTA version. Left unguarded, an attacker with
    /// write access to the bootstrap keyspace (parent-host / vsock proxy
    /// compromise) could delete the fingerprint and then substitute a
    /// rogue key that the enclave would accept as canonical on the next
    /// restart.
    ///
    /// Operators migrating from a pre-fingerprint VTA: set `true`, boot
    /// once to store the fingerprint, then set back to `false`.
    #[serde(default)]
    pub allow_fingerprint_init: bool,
    /// Allow auto-clearing existing bootstrap ciphertexts when a KMS
    /// decrypt **other than ACCESS_DENIED** fails on a subsequent boot.
    ///
    /// **Default: false.** ACCESS_DENIED is the legitimate post-rebuild
    /// signal (PCR mismatch — the enclave's measurements changed and KMS
    /// won't decrypt the old data key); the bootstrap keyspace is
    /// auto-cleared without this flag in that case. Any other class
    /// of decrypt failure (transient KMS error, network glitch,
    /// ciphertext corruption, attacker-induced byte flip) is *not*
    /// auto-cleared, because doing so would silently delete the VTA's
    /// identity. Set to `true` only when you have diagnosed the cause
    /// and intend to reset the VTA to a fresh first-boot state.
    #[serde(default)]
    pub allow_kms_reinit: bool,
    /// Allow establishing the TEE integrity-manifest baseline when none is
    /// stored (P0.2a anti-rollback anchor).
    ///
    /// **Default: false.** The integrity manifest is the MAC'd snapshot of the
    /// rollback-protected singletons (carve-out sentinel, ACL root, JWT
    /// fingerprint, key counters). A missing manifest on a configured VTA is
    /// indistinguishable from a parent-deleted one, so the enclave refuses to
    /// boot rather than silently baseline whatever (possibly rolled-back) state
    /// the parent presents.
    ///
    /// Operators on first boot, or migrating from a pre-manifest VTA: set
    /// `true`, boot once to establish the baseline, then set back to `false`.
    /// Mirrors [`Self::allow_fingerprint_init`].
    #[serde(default)]
    pub allow_anchor_init: bool,
    /// External anti-rollback counter (P0.2b). When set, the integrity manifest
    /// version is pinned to a DynamoDB single-item counter the parent can't roll
    /// back, upgrading detection from "deletion / inconsistent tamper" (P0.2a)
    /// to "consistent storage rollback". Absent → manifest-only (P0.2a).
    #[serde(default)]
    pub anchor: Option<TeeAnchorConfig>,
    /// Break-glass: boot even when the external anchor counter can't be reached
    /// or disagrees with the local manifest (P0.2b).
    ///
    /// **Default: false.** If the parent denies egress to the counter the
    /// enclave fails closed (a DoS, not an integrity breach). Setting this true
    /// lets it boot manifest-only when the counter is unreachable, or re-anchor
    /// the counter to the MAC-trusted local manifest when they diverge — for
    /// incident recovery only. Safe to leave as a config flag because the parent
    /// cannot flip it at runtime: a baked config commits it to PCR0, and an
    /// un-baked (fleet) config cannot carry it — the typed tenant overlay
    /// (`tenant_overlay`, `deny_unknown_fields`) has no `allow_*` field, so there
    /// is no channel for the parent to set it.
    #[serde(default)]
    pub allow_unanchored: bool,
}

/// External anti-rollback anchor configuration (P0.2b counter + P0.2c writer).
#[cfg(feature = "tee")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeeAnchorConfig {
    /// DynamoDB table holding the single-item monotonic version counter (one
    /// item per VTA DID). The region is reused from [`TeeKmsConfig::region`].
    pub table_name: String,
    /// KMS-attestation-gated writer credential (P0.2c — root-on-parent
    /// resistance). Base64 of the `vta-anchor-writer` IAM credentials
    /// (`{"access_key_id","secret_access_key"}`) sealed under the PCR-gated KMS
    /// key ([`TeeKmsConfig::key_arn`]): only the genuine enclave image can
    /// `kms:Decrypt` it, so a root-on-parent attacker — who holds the
    /// *instance-role* credentials but cannot produce a valid attestation —
    /// cannot obtain the only principal allowed to write the counter (the
    /// instance role is explicitly denied on the table; see the operator
    /// runbook). Unset → P0.2b: the counter is written with the instance role
    /// (resists storage/backup rollback, **not** root-on-parent).
    #[serde(default)]
    pub writer_credential_ciphertext: Option<String>,
}

// KMS ciphertexts (seed, JWT key, fingerprint) are stored as K/V entries
// in the "bootstrap" keyspace — no file paths needed.

#[cfg(feature = "tee")]
fn default_admin_context_id() -> String {
    "default".to_string()
}

#[cfg(feature = "tee")]
fn default_attestation_cache_ttl() -> u64 {
    300
}

#[cfg(feature = "tee")]
fn default_storage_key_salt() -> String {
    "vta-tee-storage-v1".to_string()
}

/// Fallback salt for configs that predate per-VTA salt generation.
///
/// **Do not change this value.** It is not a "default" in the sense of a
/// recommended setting — it is the compatibility constant that keeps any VTA
/// whose `config.toml` omits `storage_key_salt` able to re-derive its own
/// storage key. Changing it makes those deployments unable to read their store.
///
/// New installs do not use it: `vta setup` mints a random per-VTA salt
/// (`hardened_bootstrap::generate_storage_key_salt`) and writes it into
/// `config.toml`.
fn default_hardened_storage_key_salt() -> String {
    "vta-storage-v1".to_string()
}

/// Non-TEE hardened configuration: derive storage-encryption and JWT signing keys from
/// the master seed, so neither secret lives in `config.toml` or on disk.
///
/// This PoC mirrors the key-derivation that `vta-enclave` performs inside the
/// Nitro enclave (see `tee::kms_bootstrap`), without requiring KMS or an
/// enclave. The seed must reside in a real secret-store backend — the
/// plaintext file fallback (`PlaintextSeedStore`) defeats the protection.
///
/// Enable in `config.toml`:
/// ```toml
/// [hardened]
/// enabled = true
/// storage_key_salt = "my-unique-per-vta-salt"
/// ```
///
/// **Enabling on an existing VTA is handled automatically.** The first boot
/// after setting this flag converts the existing plaintext rows to the
/// encrypted format before anything reads them
/// (`hardened_bootstrap::migrate_store_to_encrypted`). The pass is idempotent
/// and crash-safe, so it costs one prefix scan per keyspace on later boots and
/// an interrupted run is finished by the next one.
///
/// It has to be automatic: the store's decrypt path is deliberately
/// fail-closed with no plaintext fallback, so a VTA that started reading an
/// unconverted store would fail on every pre-existing row — including its own
/// ACL entries. Take a backup first regardless; the conversion rewrites every
/// row in place.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardenedConfig {
    /// When `true`, enables hardened non-TEE configuration:
    /// - All 23 fjall keyspaces are encrypted with AES-256-GCM (`VAE1` format,
    ///   same as TEE mode). The storage-encryption key is derived from the
    ///   master seed via HKDF.
    /// - The JWT signing key is generated randomly on first boot, AES-GCM
    ///   sealed under the storage key, and stored in the `bootstrap` keyspace.
    ///   It is injected into memory only — `[auth] jwt_signing_key` in
    ///   `config.toml` is absent and ignored.
    ///
    /// Default `false` (standard non-TEE behaviour — plaintext fjall, JWT key
    /// in `config.toml`).
    #[serde(default)]
    pub enabled: bool,

    /// Salt for the HKDF storage-key derivation.
    ///
    /// **Changing this invalidates all encrypted data.** Set it once at
    /// initial setup and treat it as permanent. Ignored when
    /// `enabled = false`.
    #[serde(default = "default_hardened_storage_key_salt")]
    pub storage_key_salt: String,
}

impl Default for HardenedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            storage_key_salt: default_hardened_storage_key_salt(),
        }
    }
}

#[cfg(feature = "tee")]
impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            mode: TeeMode::default(),
            embed_in_did: false,
            attestation_cache_ttl: default_attestation_cache_ttl(),
            kms: None,
            storage_key_salt: default_storage_key_salt(),
            allowed_did_methods: None,
            allowed_kms_accounts: Vec::new(),
        }
    }
}

/// TEE enforcement mode.
#[cfg(feature = "tee")]
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TeeMode {
    /// TEE hardware required — VTA refuses to start without it.
    Required,
    /// TEE used if available, continues without it.
    #[default]
    Optional,
    /// Simulated TEE for development/testing (NOT for production).
    Simulated,
}

impl AppConfig {
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| std::env::var("VTA_CONFIG_PATH").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("config.toml"));

        if !path.exists() {
            return Err(AppError::Config(format!(
                "configuration file not found: {}",
                path.display()
            )));
        }

        let contents = std::fs::read_to_string(&path).map_err(AppError::Io)?;

        // Deserialize through `serde_ignored` so we can *record* every key the
        // schema doesn't recognise (typo'd / legacy / mis-sectioned) instead of
        // silently dropping it. We don't reject — `validate()` warns. (P0.9b)
        let de = toml::Deserializer::parse(&contents)
            .map_err(|e| AppError::Config(format!("failed to parse {}: {e}", path.display())))?;
        let mut unknown_keys: Vec<String> = Vec::new();
        let mut config: AppConfig = serde_ignored::deserialize(de, |key_path| {
            unknown_keys.push(key_path.to_string());
        })
        .map_err(|e| AppError::Config(format!("failed to parse {}: {e}", path.display())))?;

        config.config_path = path.clone();
        config.unknown_keys = unknown_keys;

        // =====================================================================
        // SECURITY: When KMS bootstrap is configured (TEE mode), the config
        // baked into the EIF is authoritative. ALL env var overrides are blocked
        // except VTA_LOG_LEVEL and VTA_LOG_FORMAT (operational, no security impact).
        //
        // This prevents an attacker with server access from overriding identity
        // (VTA_DID), endpoints (VTA_PUBLIC_URL, VTA_MESSAGING_*), secrets
        // (VTA_SECRETS_*, VTA_AUTH_JWT_SIGNING_KEY), or security settings
        // (VTA_TEE_MODE) via environment variables.
        //
        // In Nitro Enclaves, env var injection is already blocked by the enclave
        // model (no --env flag on nitro-cli run-enclave). This gate provides
        // defense in depth for non-Nitro TEE deployments (e.g., SEV-SNP).
        // =====================================================================
        #[cfg(feature = "tee")]
        let kms_locked = config.tee.kms.is_some();
        #[cfg(not(feature = "tee"))]
        let kms_locked = false;

        if kms_locked {
            // In KMS mode, only allow log settings
            if let Ok(level) = std::env::var("VTA_LOG_LEVEL") {
                config.log.level = level;
            }
            if let Ok(format) = std::env::var("VTA_LOG_FORMAT") {
                config.log.format = match format.to_lowercase().as_str() {
                    "json" => LogFormat::Json,
                    "text" => LogFormat::Text,
                    other => {
                        return Err(AppError::Config(format!(
                            "invalid VTA_LOG_FORMAT '{other}', expected 'text' or 'json'"
                        )));
                    }
                };
            }

            // Log warnings for any env vars that would have been applied
            let blocked_vars = [
                "VTA_DID",
                "VTA_SERVER_HOST",
                "VTA_SERVER_PORT",
                "VTA_PUBLIC_URL",
                "VTA_STORE_DATA_DIR",
                "VTA_MESSAGING_MEDIATOR_URL",
                "VTA_MESSAGING_MEDIATOR_DID",
                "VTA_SECRETS_SEED",
                "VTA_SECRETS_AWS_SECRET_NAME",
                "VTA_SECRETS_AWS_REGION",
                "VTA_SECRETS_GCP_PROJECT",
                "VTA_SECRETS_GCP_SECRET_NAME",
                "VTA_SECRETS_AZURE_VAULT_URL",
                "VTA_SECRETS_AZURE_SECRET_NAME",
                "VTA_SECRETS_KEYRING_SERVICE",
                "VTA_SECRETS_K8S_SECRET_NAME",
                "VTA_SECRETS_K8S_NAMESPACE",
                "VTA_SECRETS_K8S_SECRET_KEY",
                "VTA_AUTH_ACCESS_EXPIRY",
                "VTA_AUTH_REFRESH_EXPIRY",
                "VTA_AUTH_CHALLENGE_TTL",
                "VTA_AUTH_SESSION_CLEANUP_INTERVAL",
                "VTA_AUTH_JWT_SIGNING_KEY",
                "VTA_TEE_MODE",
                "VTA_TEE_EMBED_IN_DID",
                "VTA_TEE_ATTESTATION_CACHE_TTL",
            ];
            for var in &blocked_vars {
                if std::env::var(var).is_ok() {
                    tracing::warn!(
                        "SECURITY: {var} env var ignored — config is locked when KMS bootstrap is active"
                    );
                }
            }
        } else {
            // Non-KMS mode: apply all env var overrides (existing behavior)
            Self::apply_env_overrides(&mut config)?;
        }

        Ok(config)
    }

    /// Apply environment variable overrides to the config.
    ///
    /// Only called in non-KMS mode. When KMS bootstrap is active,
    /// the baked-in config is authoritative and env overrides are blocked.
    fn apply_env_overrides(config: &mut AppConfig) -> Result<(), AppError> {
        if let Ok(vta_did) = std::env::var("VTA_DID") {
            config.vta_did = Some(vta_did);
        }
        if let Ok(host) = std::env::var("VTA_SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var("VTA_SERVER_PORT") {
            config.server.port = port
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_SERVER_PORT: {e}")))?;
        }
        if let Ok(level) = std::env::var("VTA_LOG_LEVEL") {
            config.log.level = level;
        }
        if let Ok(format) = std::env::var("VTA_LOG_FORMAT") {
            config.log.format = match format.to_lowercase().as_str() {
                "json" => LogFormat::Json,
                "text" => LogFormat::Text,
                other => {
                    return Err(AppError::Config(format!(
                        "invalid VTA_LOG_FORMAT '{other}', expected 'text' or 'json'"
                    )));
                }
            };
        }
        if let Ok(public_url) = std::env::var("VTA_PUBLIC_URL") {
            config.public_url = Some(public_url);
        }
        if let Ok(data_dir) = std::env::var("VTA_STORE_DATA_DIR") {
            config.store.data_dir = PathBuf::from(data_dir);
        }

        // Messaging
        match (
            std::env::var("VTA_MESSAGING_MEDIATOR_URL"),
            std::env::var("VTA_MESSAGING_MEDIATOR_DID"),
        ) {
            (Ok(url), Ok(did)) => {
                config.messaging = Some(MessagingConfig {
                    mediator_url: url,
                    mediator_did: did,
                    mediator_host: None,
                    setup_acl: false,
                    drain_inbox_on_start: false,
                });
            }
            (Ok(url), Err(_)) => {
                let messaging = config.messaging.get_or_insert(MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                    mediator_host: None,
                    setup_acl: false,
                    drain_inbox_on_start: false,
                });
                messaging.mediator_url = url;
            }
            (Err(_), Ok(did)) => {
                let messaging = config.messaging.get_or_insert(MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                    mediator_host: None,
                    setup_acl: false,
                    drain_inbox_on_start: false,
                });
                messaging.mediator_did = did;
            }
            (Err(_), Err(_)) => {}
        }

        // Secrets
        if let Ok(seed) = std::env::var("VTA_SECRETS_SEED") {
            config.secrets.seed = Some(seed);
        }
        if let Ok(name) = std::env::var("VTA_SECRETS_AWS_SECRET_NAME") {
            config.secrets.aws_secret_name = Some(name);
        }
        if let Ok(region) = std::env::var("VTA_SECRETS_AWS_REGION") {
            config.secrets.aws_region = Some(region);
        }
        if let Ok(project) = std::env::var("VTA_SECRETS_GCP_PROJECT") {
            config.secrets.gcp_project = Some(project);
        }
        if let Ok(name) = std::env::var("VTA_SECRETS_GCP_SECRET_NAME") {
            config.secrets.gcp_secret_name = Some(name);
        }
        if let Ok(url) = std::env::var("VTA_SECRETS_AZURE_VAULT_URL") {
            config.secrets.azure_vault_url = Some(url);
        }
        if let Ok(name) = std::env::var("VTA_SECRETS_AZURE_SECRET_NAME") {
            config.secrets.azure_secret_name = Some(name);
        }
        if let Ok(service) = std::env::var("VTA_SECRETS_KEYRING_SERVICE") {
            config.secrets.keyring_service = service;
        }

        // Vault. K8s deployments commonly inject these via Secret /
        // ConfigMap so envs override file-config. `VAULT_ADDR` /
        // `VAULT_NAMESPACE` / `VAULT_TOKEN` are the canonical names
        // Vault itself uses; we accept those alongside the
        // VTA_SECRETS_* prefix for symmetry.
        if let Ok(addr) =
            std::env::var("VAULT_ADDR").or_else(|_| std::env::var("VTA_SECRETS_VAULT_ADDR"))
        {
            config.secrets.vault_addr = Some(addr);
        }
        if let Ok(ns) = std::env::var("VAULT_NAMESPACE")
            .or_else(|_| std::env::var("VTA_SECRETS_VAULT_NAMESPACE"))
        {
            config.secrets.vault_namespace = Some(ns);
        }
        if let Ok(path) = std::env::var("VTA_SECRETS_VAULT_SECRET_PATH") {
            config.secrets.vault_secret_path = Some(path);
        }
        if let Ok(key) = std::env::var("VTA_SECRETS_VAULT_SECRET_KEY") {
            config.secrets.vault_secret_key = key;
        }
        if let Ok(mount) = std::env::var("VTA_SECRETS_VAULT_KV_MOUNT") {
            config.secrets.vault_kv_mount = mount;
        }
        if let Ok(method) = std::env::var("VTA_SECRETS_VAULT_AUTH_METHOD") {
            config.secrets.vault_auth_method = method;
        }
        if let Ok(role) = std::env::var("VTA_SECRETS_VAULT_K8S_ROLE") {
            config.secrets.vault_k8s_role = Some(role);
        }
        if let Ok(mount) = std::env::var("VTA_SECRETS_VAULT_K8S_MOUNT") {
            config.secrets.vault_k8s_mount = mount;
        }
        if let Ok(jwt) = std::env::var("VTA_SECRETS_VAULT_K8S_JWT_PATH") {
            config.secrets.vault_k8s_jwt_path = jwt;
        }
        if let Ok(token) = std::env::var("VAULT_TOKEN") {
            config.secrets.vault_token = Some(token);
        }
        if let Ok(rid) = std::env::var("VTA_SECRETS_VAULT_APPROLE_ROLE_ID") {
            config.secrets.vault_approle_role_id = Some(rid);
        }
        if let Ok(sid) = std::env::var("VTA_SECRETS_VAULT_APPROLE_SECRET_ID") {
            config.secrets.vault_approle_secret_id = Some(sid);
        }
        if let Ok(mount) = std::env::var("VTA_SECRETS_VAULT_APPROLE_MOUNT") {
            config.secrets.vault_approle_mount = mount;
        }
        if let Ok(skip) = std::env::var("VAULT_SKIP_VERIFY")
            .or_else(|_| std::env::var("VTA_SECRETS_VAULT_SKIP_VERIFY"))
        {
            config.secrets.vault_skip_verify =
                matches!(skip.to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        }

        // Kubernetes Secret backend. K8s deployments commonly inject the
        // namespace from the pod's own metadata via the Downward API, so an
        // env override is the natural way to set it.
        if let Ok(name) = std::env::var("VTA_SECRETS_K8S_SECRET_NAME") {
            config.secrets.k8s_secret_name = Some(name);
        }
        if let Ok(ns) = std::env::var("VTA_SECRETS_K8S_NAMESPACE") {
            config.secrets.k8s_namespace = Some(ns);
        }
        if let Ok(key) = std::env::var("VTA_SECRETS_K8S_SECRET_KEY") {
            config.secrets.k8s_secret_key = key;
        }

        // Auth
        if let Ok(expiry) = std::env::var("VTA_AUTH_ACCESS_EXPIRY") {
            config.auth.access_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_AUTH_ACCESS_EXPIRY: {e}")))?;
        }
        if let Ok(expiry) = std::env::var("VTA_AUTH_REFRESH_EXPIRY") {
            config.auth.refresh_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_AUTH_REFRESH_EXPIRY: {e}")))?;
        }
        if let Ok(ttl) = std::env::var("VTA_AUTH_CHALLENGE_TTL") {
            config.auth.challenge_ttl = ttl
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_AUTH_CHALLENGE_TTL: {e}")))?;
        }
        if let Ok(interval) = std::env::var("VTA_AUTH_SESSION_CLEANUP_INTERVAL") {
            config.auth.session_cleanup_interval = interval.parse().map_err(|e| {
                AppError::Config(format!("invalid VTA_AUTH_SESSION_CLEANUP_INTERVAL: {e}"))
            })?;
        }
        if let Ok(key) = std::env::var("VTA_AUTH_JWT_SIGNING_KEY") {
            config.auth.jwt_signing_key = Some(key);
        }

        // Audit
        if let Ok(val) = std::env::var("VTA_AUDIT_RETENTION_DAYS")
            && let Ok(days) = val.parse::<u32>()
        {
            config.audit.retention_days = days;
        }

        // TEE (non-KMS mode — all overrides allowed)
        #[cfg(feature = "tee")]
        {
            if let Ok(mode) = std::env::var("VTA_TEE_MODE") {
                config.tee.mode = match mode.to_lowercase().as_str() {
                    "required" => TeeMode::Required,
                    "optional" => TeeMode::Optional,
                    "simulated" => TeeMode::Simulated,
                    "disabled" => {
                        tracing::warn!(
                            "VTA_TEE_MODE=disabled is deprecated — use 'optional' instead"
                        );
                        TeeMode::Optional
                    }
                    other => {
                        return Err(AppError::Config(format!(
                            "invalid VTA_TEE_MODE '{other}', expected 'required', 'optional', or 'simulated'"
                        )));
                    }
                };
            }
            if let Ok(val) = std::env::var("VTA_TEE_EMBED_IN_DID") {
                config.tee.embed_in_did = val
                    .parse()
                    .map_err(|e| AppError::Config(format!("invalid VTA_TEE_EMBED_IN_DID: {e}")))?;
            }
            if let Ok(val) = std::env::var("VTA_TEE_ATTESTATION_CACHE_TTL") {
                config.tee.attestation_cache_ttl = val.parse().map_err(|e| {
                    AppError::Config(format!("invalid VTA_TEE_ATTESTATION_CACHE_TTL: {e}"))
                })?;
            }
        }

        Ok(())
    }

    /// Validate the loaded runtime config, called at daemon boot
    /// (`server::run`). Catches misconfigurations that would otherwise
    /// produce a half-started or misbehaving service — the setup wizard
    /// validates its *inputs*, but a hand-edited `config.toml` never went
    /// through that gate.
    ///
    /// Conservative by design: it hard-errors only on values that are
    /// unambiguously broken (a present-but-empty URL, a zero retention
    /// window the sweeper can't honour) and *warns* — never blocks — on
    /// cross-field advisories that a working deployment might legitimately
    /// have, so it can't reject a config that boots fine today.
    pub fn validate(&self) -> Result<(), AppError> {
        // Advisory (non-blocking): keys the schema doesn't recognise. Emitted
        // here rather than in `load()` because `load()` runs before the tracing
        // subscriber is installed, so a warn there would be dropped. A typo'd
        // key means the operator's intended setting silently took its default —
        // worth flagging, but never a reason to refuse a config that otherwise
        // boots (P0.9b — softer than `deny_unknown_fields`).
        for key in &self.unknown_keys {
            tracing::warn!(
                "unknown configuration key `{key}` in {} — ignored. Check for a typo, \
                 a removed/renamed setting, or a key placed in the wrong [section].",
                self.config_path.display()
            );
        }

        let mut errors: Vec<String> = Vec::new();

        // A present-but-empty URL is always a mistake (the operator set the
        // key and left it blank); an *absent* key is fine (the default /
        // serverless path).
        if self
            .public_url
            .as_deref()
            .is_some_and(|u| u.trim().is_empty())
        {
            errors.push(
                "public_url is set to an empty string — remove the key for a \
                 serverless VTA, or give it a value (e.g. https://vta.example.com)"
                    .into(),
            );
        }
        if self
            .resolver_url
            .as_deref()
            .is_some_and(|u| u.trim().is_empty())
        {
            errors.push(
                "resolver_url is set to an empty string — remove the key to resolve \
                 DIDs locally, or give it a ws:// or wss:// URL"
                    .into(),
            );
        }
        // retention_days = 0 would silently disable audit retention; the
        // sweeper assumes a positive window. (Mirrors the setup-time rule.)
        if self.audit.retention_days == 0 {
            errors.push("audit.retention_days must be > 0 (default is 28)".into());
        }

        if !errors.is_empty() {
            return Err(AppError::Config(format!(
                "invalid configuration in {}:\n  - {}",
                self.config_path.display(),
                errors.join("\n  - ")
            )));
        }

        // Advisory (non-blocking): a REST-advertising VTA with no public_url
        // publishes a DID document with no reachable REST endpoint. We don't
        // hard-fail — a dev VTA legitimately runs REST without publishing —
        // but the operator should see it.
        if self.services.rest && self.public_url.is_none() {
            tracing::warn!(
                "services.rest = true but public_url is unset — the VTA DID document \
                 will advertise no reachable REST endpoint"
            );
        }

        Ok(())
    }

    pub fn save(&self) -> Result<(), AppError> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
        std::fs::write(&self.config_path, contents).map_err(AppError::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod validate_tests {
    use super::*;

    /// Parse a (possibly empty) TOML snippet into an `AppConfig`. An empty
    /// document is valid — every field defaults (Options to None, server /
    /// store / audit to their default fns).
    fn cfg(toml_str: &str) -> AppConfig {
        toml::from_str::<AppConfig>(toml_str).expect("parse test config")
    }

    #[test]
    fn default_config_validates() {
        cfg("")
            .validate()
            .expect("a fully-defaulted config must validate");
    }

    #[test]
    fn zero_retention_days_is_rejected() {
        let err = cfg("[audit]\nretention_days = 0\n")
            .validate()
            .expect_err("retention_days = 0 must be rejected");
        assert!(format!("{err:?}").contains("retention_days"), "{err:?}");
    }

    #[test]
    fn present_but_empty_public_url_is_rejected() {
        let err = cfg("public_url = \"\"\n")
            .validate()
            .expect_err("empty public_url must be rejected");
        assert!(format!("{err:?}").contains("public_url"), "{err:?}");
    }

    #[test]
    fn present_but_empty_resolver_url_is_rejected() {
        let err = cfg("resolver_url = \"   \"\n")
            .validate()
            .expect_err("whitespace-only resolver_url must be rejected");
        assert!(format!("{err:?}").contains("resolver_url"), "{err:?}");
    }

    #[test]
    fn rest_without_public_url_only_warns_does_not_fail() {
        // services.rest defaults to true and public_url is absent — this is
        // an advisory (a dev VTA legitimately runs REST without publishing),
        // so validate must NOT hard-fail.
        cfg("")
            .validate()
            .expect("rest-without-public_url is advisory, not an error");
    }

    /// Write `contents` to a `config.toml` in a fresh tempdir and run it
    /// through the real `AppConfig::load` path (the only path that populates
    /// `unknown_keys` — `toml::from_str` doesn't). Returns the loaded config;
    /// the `TempDir` is returned too so the file outlives the call.
    fn load(contents: &str) -> (AppConfig, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, contents).expect("write config");
        let config = AppConfig::load(Some(path)).expect("load config");
        (config, dir)
    }

    #[test]
    fn unknown_keys_are_collected_not_rejected() {
        // A typo'd top-level key and a typo inside a nested table. `load`
        // must succeed (no rejection) and record both as dotted paths.
        let (config, _dir) = load(
            "vta_naem = \"oops\"\n\
             [secrets]\nkyring_service = \"vta-2\"\n",
        );
        assert!(
            config.unknown_keys.iter().any(|k| k == "vta_naem"),
            "top-level typo should be flagged: {:?}",
            config.unknown_keys
        );
        assert!(
            config
                .unknown_keys
                .iter()
                .any(|k| k == "secrets.kyring_service"),
            "nested typo should be flagged with a dotted path: {:?}",
            config.unknown_keys
        );
        // Advisory only — a config with unknown keys still validates.
        config
            .validate()
            .expect("unknown keys are advisory, not a hard error");
    }

    #[test]
    fn known_keys_and_aliases_are_not_flagged() {
        // `community_name` is a serde alias for `vta_name`; a real nested
        // key must not be reported. Nothing should land in `unknown_keys`.
        let (config, _dir) = load(
            "community_name = \"acme\"\n\
             [server]\nport = 9000\n",
        );
        assert!(
            config.unknown_keys.is_empty(),
            "known keys + aliases must not be flagged: {:?}",
            config.unknown_keys
        );
        assert_eq!(config.vta_name.as_deref(), Some("acme"));
        assert_eq!(config.server.port, 9000);
    }
}
