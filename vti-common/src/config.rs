use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    /// Port number. No default — each service must provide its own via
    /// `#[serde(default = "...")]` or by composing this struct.
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoreConfig {
    /// Data directory. No default — each service provides its own
    /// (e.g., "data/vta" vs "data/vtc").
    pub data_dir: PathBuf,
}

/// Optional Fjall memory settings, shared by every service that opens a
/// local fjall store (currently the VTA and the VTC; DID Hosting is a
/// separate repo). Exists so a pod's Kubernetes memory limit can be kept
/// clear of fjall's block cache, buffered writes and startup journal
/// replay — all three grow with the data set and, left at fjall's
/// defaults, are sized for a workstation rather than a constrained pod.
///
/// Deliberately **not** a field of [`StoreConfig`]: that type is
/// constructed as a bare struct literal (`StoreConfig { data_dir: .. }`)
/// at hundreds of call sites across the workspace, mostly tests opening
/// an ad hoc store, and adding a field there would force every one of
/// them to change. Instead this is a sibling value each service loads
/// separately (a `[fjall]` config-file table, see below) and threads
/// explicitly into [`crate::store::Store::open_with`] alongside the
/// `StoreConfig` it already had. [`crate::store::Store::open`] — what
/// every existing call site still uses — is `open_with` with
/// [`FjallTuning::default()`], so nothing already opening a store needed
/// to change to keep behaving exactly as before.
///
/// Every field is optional and defaults to `None`: unset, byte for byte,
/// leaves fjall's own defaults (and this codebase's behaviour before this
/// type existed) unchanged. Settable in a service's config file under
/// `[fjall]` (a bare integer byte count, or a string like `"64MiB"` /
/// `"512MB"` / `"1GiB"`), and overridable per field by the environment
/// variables named on each field below — the env var wins when both are
/// set.
///
/// Validated before use ([`FjallTuning::validate`]): zero, a value fjall
/// itself would refuse (its own `Builder` asserts under 1 MiB for the
/// write buffer and under 64 MiB for the journal — panics this type
/// exists to turn into an ordinary startup error instead), or anything
/// that fails to parse is refused with a message naming the setting,
/// never silently ignored or clamped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FjallTuning {
    /// fjall's shared block cache size, in bytes
    /// (`fjall::Database::builder(..).cache_size(..)`). fjall's own
    /// default is 32 MiB. Env override: `STORAGE_FJALL_BLOCK_CACHE`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_block_cache"
    )]
    pub block_cache: Option<u64>,
    /// Maximum size of all active memtables across every keyspace this
    /// process opens, in bytes
    /// (`fjall::Database::builder(..).max_write_buffer_size(Some(..))`).
    /// fjall's own default is unbounded. Env override:
    /// `STORAGE_FJALL_WRITE_BUFFER`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_write_buffer"
    )]
    pub write_buffer: Option<u64>,
    /// Maximum size of all journals — the write-ahead log fjall replays
    /// on startup — in bytes
    /// (`fjall::Database::builder(..).max_journaling_size(..)`). fjall's
    /// own default is 512 MiB. Env override: `STORAGE_FJALL_MAX_JOURNAL`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_max_journal"
    )]
    pub max_journal: Option<u64>,
}

/// Floor for [`FjallTuning::block_cache`]. fjall places no lower bound on
/// its cache size itself, but a cache below this buys nothing meaningful
/// and is far more likely to be a fat-fingered value (bytes typed where
/// mebibytes were meant) than an intentional setting.
pub const MIN_BLOCK_CACHE_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Floor for [`FjallTuning::write_buffer`] — mirrors fjall's own
/// `Builder::max_write_buffer_size`, which panics below this.
pub const MIN_WRITE_BUFFER_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Floor for [`FjallTuning::max_journal`] — mirrors fjall's own
/// `Builder::max_journaling_size`, which panics below this.
pub const MIN_MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

/// Byte-size suffixes this module accepts, longest first so e.g. `"MiB"`
/// is tried before the bare `"B"` it also ends with. IEC (binary, 1024-based)
/// before SI (decimal, 1000-based) is an arbitrary but fixed tie-break —
/// there is no overlap between the two suffix spellings, so it never
/// actually matters which list comes first.
const BYTE_SIZE_SUFFIXES: &[(&str, u64)] = &[
    ("TiB", 1024 * 1024 * 1024 * 1024),
    ("GiB", 1024 * 1024 * 1024),
    ("MiB", 1024 * 1024),
    ("KiB", 1024),
    ("TB", 1_000_000_000_000),
    ("GB", 1_000_000_000),
    ("MB", 1_000_000),
    ("KB", 1_000),
    ("B", 1),
];

/// Parse a byte-size value: a plain byte count (`"67108864"`), or a
/// number followed by a binary (`KiB`/`MiB`/`GiB`/`TiB`) or decimal
/// (`KB`/`MB`/`GB`/`TB`/`B`) suffix, case-insensitively. Never validates
/// range — callers combine this with a minimum (see
/// [`parse_and_validate_fjall_bytes`]).
pub fn parse_byte_size(raw: &str) -> Result<u64, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("value is empty".to_string());
    }
    if trimmed.starts_with('-') {
        return Err(format!(
            "{trimmed:?} is negative; a byte size cannot be negative"
        ));
    }
    for (suffix, multiplier) in BYTE_SIZE_SUFFIXES {
        if trimmed.len() > suffix.len()
            && trimmed[trimmed.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        {
            let number_part = trimmed[..trimmed.len() - suffix.len()].trim();
            let value: f64 = number_part.parse().map_err(|_| {
                format!(
                    "{trimmed:?} is not a valid byte size (expected a number before the {suffix:?} suffix)"
                )
            })?;
            if !value.is_finite() || value < 0.0 {
                return Err(format!("{trimmed:?} is not a valid byte size"));
            }
            return Ok((value * (*multiplier as f64)).round() as u64);
        }
    }
    trimmed.parse::<u64>().map_err(|_| {
        format!(
            "{trimmed:?} is not a valid byte size (expected a plain byte count, or a number with \
             a B/KB/MB/GB/TB or KiB/MiB/GiB/TiB suffix)"
        )
    })
}

/// Render a byte count the way this module's error messages and startup
/// log line do: the most natural binary unit, two decimal places.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: &[(&str, u64)] = &[
        ("TiB", 1024 * 1024 * 1024 * 1024),
        ("GiB", 1024 * 1024 * 1024),
        ("MiB", 1024 * 1024),
        ("KiB", 1024),
    ];
    for (unit, size) in UNITS {
        if bytes >= *size {
            return format!("{:.2} {unit}", bytes as f64 / *size as f64);
        }
    }
    format!("{bytes} B")
}

/// Parse then range-check a byte-size value against `minimum`, producing
/// an error that names `field` (an env var name or a config key path) —
/// used identically by the config-file deserializer and the env var
/// overrides so a bad value is refused wherever it came from, with the
/// same message shape.
pub fn parse_and_validate_fjall_bytes(field: &str, raw: &str, minimum: u64) -> Result<u64, String> {
    let bytes = parse_byte_size(raw).map_err(|e| format!("invalid {field} value {raw:?}: {e}"))?;
    validate_fjall_bytes(field, bytes, minimum, raw)
}

fn validate_fjall_bytes(
    field: &str,
    bytes: u64,
    minimum: u64,
    raw_display: &str,
) -> Result<u64, String> {
    if bytes == 0 {
        return Err(format!(
            "{field} must not be zero (got {raw_display:?}); fjall needs a positive size here"
        ));
    }
    if bytes < minimum {
        return Err(format!(
            "{field} value {raw_display:?} ({bytes} bytes) is too small; must be at least \
             {minimum} bytes ({})",
            human_bytes(minimum)
        ));
    }
    Ok(bytes)
}

/// A `[fjall]` field is either a bare integer byte count or a suffixed
/// string — accept both.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawByteSize {
    Number(u64),
    Text(String),
}

fn deserialize_optional_fjall_byte_size<'de, D>(
    deserializer: D,
    field: &str,
    minimum: u64,
) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<RawByteSize>::deserialize(deserializer)? {
        None => Ok(None),
        Some(RawByteSize::Number(n)) => validate_fjall_bytes(field, n, minimum, &n.to_string())
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(RawByteSize::Text(s)) => {
            let bytes = parse_byte_size(&s).map_err(|e| {
                serde::de::Error::custom(format!("invalid {field} value {s:?}: {e}"))
            })?;
            validate_fjall_bytes(field, bytes, minimum, &s)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
    }
}

fn deserialize_block_cache<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_fjall_byte_size(deserializer, "fjall.block_cache", MIN_BLOCK_CACHE_BYTES)
}

fn deserialize_write_buffer<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_fjall_byte_size(deserializer, "fjall.write_buffer", MIN_WRITE_BUFFER_BYTES)
}

fn deserialize_max_journal<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_fjall_byte_size(deserializer, "fjall.max_journal", MIN_MAX_JOURNAL_BYTES)
}

impl FjallTuning {
    /// Re-check every set field against its floor. Called from
    /// [`crate::store::Store::open_with`] right before the values are
    /// handed to fjall's builder, so a `FjallTuning` built any other way
    /// than through the deserializer or [`apply_fjall_env_overrides`]
    /// (a test fixture, a future caller) still can never reach fjall's
    /// own asserting `Builder` methods with a value that would panic.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(bytes) = self.block_cache {
            validate_fjall_bytes(
                "fjall.block_cache",
                bytes,
                MIN_BLOCK_CACHE_BYTES,
                &bytes.to_string(),
            )?;
        }
        if let Some(bytes) = self.write_buffer {
            validate_fjall_bytes(
                "fjall.write_buffer",
                bytes,
                MIN_WRITE_BUFFER_BYTES,
                &bytes.to_string(),
            )?;
        }
        if let Some(bytes) = self.max_journal {
            validate_fjall_bytes(
                "fjall.max_journal",
                bytes,
                MIN_MAX_JOURNAL_BYTES,
                &bytes.to_string(),
            )?;
        }
        Ok(())
    }
}

/// Apply `STORAGE_FJALL_BLOCK_CACHE` / `STORAGE_FJALL_WRITE_BUFFER` /
/// `STORAGE_FJALL_MAX_JOURNAL` onto `config`, one field at a time, if set.
/// The **same** three env var names for every consumer (the VTA, the VTC,
/// and any future one) — this is a pod-level Kubernetes memory-limit knob,
/// not a per-service setting, so there is deliberately no `VTA_`/`VTC_`
/// prefix. Called by each service's own config loader, after the config
/// file is parsed, so an env var overrides the file — an unset var leaves
/// whatever the file (or the type's `None` default) already set untouched.
pub fn apply_fjall_env_overrides(config: &mut FjallTuning) -> Result<(), String> {
    if let Ok(raw) = std::env::var("STORAGE_FJALL_BLOCK_CACHE") {
        config.block_cache = Some(parse_and_validate_fjall_bytes(
            "STORAGE_FJALL_BLOCK_CACHE",
            &raw,
            MIN_BLOCK_CACHE_BYTES,
        )?);
    }
    if let Ok(raw) = std::env::var("STORAGE_FJALL_WRITE_BUFFER") {
        config.write_buffer = Some(parse_and_validate_fjall_bytes(
            "STORAGE_FJALL_WRITE_BUFFER",
            &raw,
            MIN_WRITE_BUFFER_BYTES,
        )?);
    }
    if let Ok(raw) = std::env::var("STORAGE_FJALL_MAX_JOURNAL") {
        config.max_journal = Some(parse_and_validate_fjall_bytes(
            "STORAGE_FJALL_MAX_JOURNAL",
            &raw,
            MIN_MAX_JOURNAL_BYTES,
        )?);
    }
    Ok(())
}

#[derive(Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default = "default_access_token_expiry")]
    pub access_token_expiry: u64,
    #[serde(default = "default_refresh_token_expiry")]
    pub refresh_token_expiry: u64,
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl: u64,
    /// How long an admin session may go without user activity before it
    /// may no longer be renewed, in seconds.
    ///
    /// Distinct from [`Self::access_token_expiry`], which is how often a
    /// live session rotates its token. A console that renews on a timer
    /// would never lapse if the two were the same clock, so this is the
    /// value that actually decides when an operator who walked away is
    /// signed out. Enforced in `auth::handlers::handle_refresh` against
    /// `Session::last_seen`.
    #[serde(default = "default_admin_idle_timeout")]
    pub admin_idle_timeout: u64,
    /// How long after a refresh-token rotation the token it replaced may
    /// still be presented without being treated as reuse, in seconds.
    ///
    /// Exists for one failure that is not an attack: a client whose
    /// rotation response was lost in flight still holds only the old
    /// token, and retrying with it is the correct thing for it to do.
    /// Inside this window — and only while the replacement token is
    /// still unspent — such a retry is answered with the same pair
    /// instead of revoking the session.
    ///
    /// **The trade-off is real.** While the window is open and the
    /// replacement unused, someone who stole the old token gets that
    /// same pair too. It buys tolerance of a common network fault at the
    /// cost of a narrow race, and the alternative is worse in the other
    /// direction: at `0`, every dropped connection signs a user out and
    /// reports a compromise, so the alarm fires for the routine fault
    /// while a patient attacker — who simply waits out the window —
    /// never trips it.
    ///
    /// Does **not** apply to a token retired by a fresh login
    /// ([`crate::auth::session::TombstoneCause::Superseded`]): a client
    /// that has just logged in holds its new token, so a replay of the
    /// old one has no innocent reading and is always a compromise
    /// signal.
    ///
    /// Set to `0` to disable the concession and treat every replay as a
    /// compromise signal. Enforced in
    /// `auth::handlers::handle_refresh`.
    #[serde(default = "default_refresh_reuse_grace")]
    pub refresh_reuse_grace: u64,
    #[serde(default = "default_session_cleanup_interval")]
    pub session_cleanup_interval: u64,
    /// Base64url-no-pad encoded 32-byte Ed25519 private key for JWT signing.
    pub jwt_signing_key: Option<String>,
    /// Retired: the `[auth.step_up]` policy floors.
    ///
    /// This field exists only to **refuse** a config that still carries the
    /// section, rather than parse it and silently ignore it. An operator whose
    /// `config.toml` says `[auth.step_up] enabled = true` believes their VTA is
    /// gating operations. Dropping the field outright would leave them
    /// believing it, with the file still saying so and nothing enforcing it —
    /// the worst of the three outcomes. A VTA that will not start is at least
    /// unambiguous, and the error names the command that replaces it.
    ///
    /// Absent (the only accepted state) deserializes to `()` via `default`.
    #[serde(default, deserialize_with = "refuse_retired_step_up", skip_serializing)]
    pub step_up: (),
}

/// Reject `[auth.step_up]` with the migration the operator needs.
///
/// Only ever called when the key is present — `#[serde(default)]` covers its
/// absence — so reaching this function *is* the error.
fn refuse_retired_step_up<'de, D>(_: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    Err(serde::de::Error::custom(
        "`[auth.step_up]` has been retired. The step-up floors were a second, \
         parallel answer to \"does this operation need another human decision?\", \
         resolved separately from the policy rules — which is how a VTA could \
         demand a step-up that no rule explained. Approvals are now one model: \
         delete the `[auth.step_up]` section and express the same requirement as \
         a rule with `pnm approvals require <task-uri> --reauth` (or \
         `--consent`). `pnm approvals list` then shows every gated operation, \
         which the floors never could.",
    ))
}

// Manual Debug so a `tracing::debug!(?config, ...)`, panic-with-debug,
// or `format!("{:?}", app_config)` in a downstream crate cannot dump
// the JWT signing key into logs (which in enclave mode are forwarded
// over vsock to the host). Non-secret fields stay visible for
// diagnostics; `Serialize` is intentionally untouched since these
// structs round-trip to the on-disk config file.
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("access_token_expiry", &self.access_token_expiry)
            .field("refresh_token_expiry", &self.refresh_token_expiry)
            .field("challenge_ttl", &self.challenge_ttl)
            .field("admin_idle_timeout", &self.admin_idle_timeout)
            .field("session_cleanup_interval", &self.session_cleanup_interval)
            .field(
                "jwt_signing_key",
                &self.jwt_signing_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessagingConfig {
    /// Mediator URL. Optional — the TDK resolves the endpoint from mediator_did.
    /// Kept for display/status purposes and backward compatibility.
    #[serde(default)]
    pub mediator_url: String,
    pub mediator_did: String,
    /// Real external hostname of the mediator (e.g., "mediator.example.com").
    /// Used by the parent proxy to establish the TLS connection.
    /// Not used by the VTA itself (which connects via the local vsock proxy).
    #[serde(default)]
    pub mediator_host: Option<String>,
    /// Automatically provision a per-DID allow-all ACL on the mediator after
    /// establishing the DIDComm connection. Required when the mediator uses
    /// `ExplicitAllow` mode; harmless (and default-off) with `ExplicitDeny`.
    /// Set `setup_acl = true` during setup to enable. Defaults to `false`.
    #[serde(default)]
    pub setup_acl: bool,
    /// Drain this DID's mediator inbox over REST at startup, *before* the live
    /// DIDComm/TSP listener enables live delivery.
    ///
    /// Recovery lever for a wedged listener: the mediator enforces one live
    /// websocket stream per DID, and an undeliverable/poison message queued for
    /// this DID can stall the live-delivery handshake so the listener never comes
    /// up (taking DIDComm *and* TSP down, since they share the socket). Because
    /// REST auth + pickup work even when the websocket stalls, the VTA can fetch
    /// and clear its own queued messages first: each is best-effort processed,
    /// and anything that fails to unpack/handle is logged loudly and deleted so
    /// it can't wedge startup again.
    ///
    /// **Default off** — it deletes queued messages that can't be handled, so it
    /// is opt-in. Turn it on when a mediator-side backlog is blocking boot.
    #[serde(default)]
    pub drain_inbox_on_start: bool,
}

/// Default time a verifier may hold a mutable DID's document before resolving
/// it again, in seconds. See [`DidCacheConfig::ttl_secs`].
pub const DID_CACHE_TTL_DEFAULT_SECS: u32 = 60;
/// The longest a node may be configured to hold one. See
/// [`DidCacheConfig::ttl_secs`].
pub const DID_CACHE_TTL_MAX_SECS: u32 = 300;
/// Default number of DID documents held.
pub const DID_CACHE_CAPACITY_DEFAULT: u32 = 1000;

/// The node's DID-document cache — how long, and how many, documents it holds
/// as a verifier (`[did_cache]`).
///
/// Shared by the VTA and the VTC so the two cannot disagree about how stale a
/// key they accept may be.
///
/// Unknown keys are not refused here: each service's loader already warns on
/// every key it ignores, and a mistyped key leaves the bounded default in force.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DidCacheConfig {
    /// Seconds a mutable DID's document (`did:webvh`, `did:web`, …) is served
    /// from the cache before it is resolved again. Immutable methods
    /// (`did:key`, `did:peer`) carry their keys in the identifier and are not
    /// subject to it.
    ///
    /// **This bounds how long a revoked key keeps verifying here.** A
    /// revocation for compromise takes the key out of the document with no
    /// overlap (VTI-KEY-123), so until this node re-resolves it accepts what
    /// that key signs. A *new* key is not what the TTL is for: a proof naming a
    /// key the cached document lacks, or failing under a cached key, forces one
    /// fresh re-resolution before it is refused (VTI-KEY-134), so a planned
    /// rotation (VTI-KEY-122) is followed at once whatever this says.
    ///
    /// Default [`DID_CACHE_TTL_DEFAULT_SECS`] (60): a compromised key is
    /// accepted for at most a minute after its revocation is published, at the
    /// cost of one resolution per active DID per minute. Must be between 1 and
    /// [`DID_CACHE_TTL_MAX_SECS`] (300, the SDK's own default, which this
    /// narrows); a longer window is refused rather than honoured.
    ///
    /// **In network mode (`resolver_url`) the window is this TTL plus the
    /// remote resolver's own.** The node then resolves through a cache server
    /// that keeps its own copy of each document for its own `expire` (300 s by
    /// default), and a forced refresh clears only this node's cache — the
    /// remote answers from its copy until that expires too. A revoked key can
    /// therefore keep verifying for up to `ttl_secs` + the remote TTL, and a
    /// rotation is followed only once the remote copy is current. The node
    /// cannot read the remote's setting; set the cache server's `expire` no
    /// higher than you would set this.
    #[serde(default = "default_did_cache_ttl_secs")]
    pub ttl_secs: u32,
    /// Most documents held. Only a performance knob: an evicted document is
    /// resolved again, never trusted less. Default
    /// [`DID_CACHE_CAPACITY_DEFAULT`].
    #[serde(default = "default_did_cache_capacity")]
    pub capacity: u32,
}

fn default_did_cache_ttl_secs() -> u32 {
    DID_CACHE_TTL_DEFAULT_SECS
}

fn default_did_cache_capacity() -> u32 {
    DID_CACHE_CAPACITY_DEFAULT
}

impl Default for DidCacheConfig {
    fn default() -> Self {
        Self {
            ttl_secs: DID_CACHE_TTL_DEFAULT_SECS,
            capacity: DID_CACHE_CAPACITY_DEFAULT,
        }
    }
}

impl DidCacheConfig {
    /// Every problem with this section, as operator-facing sentences.
    pub fn validation_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.ttl_secs == 0 || self.ttl_secs > DID_CACHE_TTL_MAX_SECS {
            errors.push(format!(
                "did_cache.ttl_secs = {} is outside 1..={DID_CACHE_TTL_MAX_SECS}: it bounds how \
                 long a revoked key keeps verifying on this node, so it may not be longer than \
                 {DID_CACHE_TTL_MAX_SECS} seconds (and 0 would disable the cache the node relies \
                 on). The default is {DID_CACHE_TTL_DEFAULT_SECS}.",
                self.ttl_secs
            ));
        }
        if self.capacity == 0 {
            errors.push(
                "did_cache.capacity = 0 would cache nothing and resolve every DID on every \
                 request; remove the key for the default"
                    .into(),
            );
        }
        errors
    }
}

#[cfg(test)]
mod did_cache_config_tests {
    use super::*;

    #[test]
    fn defaults_are_bounded_and_valid() {
        let c: DidCacheConfig = toml::from_str("").unwrap();
        assert_eq!(c.ttl_secs, DID_CACHE_TTL_DEFAULT_SECS);
        assert!(c.ttl_secs <= DID_CACHE_TTL_MAX_SECS);
        assert!(c.validation_errors().is_empty());
    }

    #[test]
    fn a_ttl_past_the_bound_or_zero_is_refused() {
        for ttl in [0, DID_CACHE_TTL_MAX_SECS + 1, 86_400] {
            let c = DidCacheConfig {
                ttl_secs: ttl,
                ..Default::default()
            };
            assert_eq!(c.validation_errors().len(), 1, "ttl {ttl}");
        }
        let c = DidCacheConfig {
            ttl_secs: DID_CACHE_TTL_MAX_SECS,
            ..Default::default()
        };
        assert!(c.validation_errors().is_empty());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Number of days to retain audit logs (default 28).
    #[serde(default = "default_audit_retention_days")]
    pub retention_days: u32,
}

fn default_audit_retention_days() -> u32 {
    28
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            retention_days: default_audit_retention_days(),
        }
    }
}

/// Vault lifecycle tuning. Shared shape so both the VTA password vault and
/// the VTA credential store read the same grace window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Days a soft-deleted (tombstoned) vault entry or credential remains
    /// recoverable before the sweeper hard-purges it. Applied at delete time
    /// (`grace_until = now + grace_days`); the sweeper only compares against
    /// the stored `grace_until`. Default 30. A `delete --force` / `purge`
    /// bypasses the window entirely.
    #[serde(default = "default_vault_grace_days")]
    pub grace_days: u32,

    /// PEM-encoded **IACA root certificates** this VTA accepts as mdoc issuers
    /// (ISO/IEC 18013-5). Each entry may hold several `CERTIFICATE` blocks, so
    /// a Member State trusted-list bundle can be pasted as one value.
    ///
    /// Inline PEM rather than file paths, for two reasons: an enclave has no
    /// convenient filesystem to read them from, and inline values are covered
    /// by the effective-config digest that boot attestation commits to — so a
    /// verifier can see *which issuers a TEE VTA was trusting* at the time it
    /// was attested. A path would leave that outside the measurement.
    ///
    /// **Empty means mdoc receive is unavailable, not "trust anything".** The
    /// resolver fails closed on an empty anchor set. mdoc is the one credential
    /// format here whose issuer is not a resolvable DID, so there is no safe
    /// default to fall back to.
    #[serde(default)]
    pub mdoc_iaca_trust_anchors: Vec<String>,
}

fn default_vault_grace_days() -> u32 {
    30
}

/// Application-state store tuning (`vta/app-state/*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStateConfig {
    /// Days a deleted record's **tombstone** is retained before the sweeper
    /// reaps it. Default 30, matching the vault's grace window.
    ///
    /// This is a correctness parameter, not just housekeeping. A tombstone is
    /// how a consumer syncing from a watermark learns a record was deleted;
    /// once it is reaped, any watermark from before that point can no longer
    /// converge, and the VTA answers such a resume with
    /// `vta/app-state/list:watermarkTooOld` so the consumer rebuilds instead of
    /// being served a feed that silently omits deletions.
    ///
    /// So the window is really "how long may a consumer be offline and still
    /// resume incrementally". Too short and a client that was away for a
    /// weekend pays for a full rebuild; too long and deletions are not real.
    /// Raising it is always safe; lowering it strands consumers whose
    /// watermarks predate the new cutoff.
    ///
    /// `0` disables reaping entirely — tombstones are kept forever, no watermark
    /// ever expires, and the keyspace grows without bound. Legitimate for a
    /// deployment that would rather spend disk than ever force a rebuild.
    #[serde(default = "default_tombstone_retention_days")]
    pub tombstone_retention_days: u32,
}

fn default_tombstone_retention_days() -> u32 {
    30
}

impl Default for AppStateConfig {
    fn default() -> Self {
        Self {
            tombstone_retention_days: default_tombstone_retention_days(),
        }
    }
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            grace_days: default_vault_grace_days(),
            mdoc_iaca_trust_anchors: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_access_token_expiry() -> u64 {
    900
}

fn default_refresh_token_expiry() -> u64 {
    86400
}

fn default_challenge_ttl() -> u64 {
    300
}

/// 15 minutes. Chosen to be *longer* than the cliff it replaces: before
/// this existed a passkey console session died at 300s of wall-clock
/// regardless of activity, because the cookie's life was the aal2 access
/// token's. An idle timeout of 900s is both the documented intent of
/// `access_token_expiry` and a strictly kinder default than the observed
/// behaviour.
fn default_admin_idle_timeout() -> u64 {
    900
}

fn default_session_cleanup_interval() -> u64 {
    600
}

/// 30 seconds — long enough to cover a retry after a dropped response
/// (a client that lost one retries in seconds, not minutes), short
/// enough that it is not a meaningful window to an attacker who has to
/// both hold a stolen token and beat the legitimate client to the
/// replacement.
///
/// Raise to 60 if real clients turn out to retry later than this. A
/// client only discovers a lost response when its own HTTP timeout
/// fires, and 30s is a common default — a retry landing just outside
/// the window is refused and signs the user out, which is the outcome
/// the concession exists to avoid. It is a user-experience call, not a
/// security one: the successor-unspent condition is what keeps the
/// concession narrow, and it holds at either value.
fn default_refresh_reuse_grace() -> u64 {
    30
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            access_token_expiry: default_access_token_expiry(),
            refresh_token_expiry: default_refresh_token_expiry(),
            challenge_ttl: default_challenge_ttl(),
            admin_idle_timeout: default_admin_idle_timeout(),
            refresh_reuse_grace: default_refresh_reuse_grace(),
            session_cleanup_interval: default_session_cleanup_interval(),
            jwt_signing_key: None,
            step_up: (),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `AuthConfig`'s Debug impl MUST NOT print the JWT signing key —
    /// it's the Ed25519 private key used to sign every access token. A
    /// stray `tracing::debug!(?config, ...)` or panic-with-debug
    /// formatter would otherwise dump it into logs.
    #[test]
    fn auth_config_debug_redacts_jwt_signing_key() {
        let cfg = AuthConfig {
            access_token_expiry: 900,
            refresh_token_expiry: 86400,
            challenge_ttl: 300,
            admin_idle_timeout: 900,
            refresh_reuse_grace: 30,
            session_cleanup_interval: 600,
            jwt_signing_key: Some("SUPER_SECRET_KEY_MATERIAL_MUST_NOT_LEAK".into()),
            step_up: (),
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("SUPER_SECRET_KEY_MATERIAL"),
            "AuthConfig Debug leaked jwt_signing_key contents: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker in Debug, got: {dbg}"
        );
        // Non-secret fields must remain visible for diagnostics.
        assert!(
            dbg.contains("900"),
            "access_token_expiry must still be visible: {dbg}"
        );
    }

    #[test]
    fn auth_config_debug_none_signing_key_renders_none() {
        let cfg = AuthConfig::default();
        let dbg = format!("{cfg:?}");
        // `Option<&str>` Debug prints `None` for the absent case.
        assert!(dbg.contains("jwt_signing_key: None"), "got: {dbg}");
    }

    /// Serialize must remain unaffected — these structs round-trip to
    /// the config file, and redacting them on serialize would break
    /// persistence. Use JSON here since serde_json is already a
    /// dev-dep; the wire format (TOML on disk) shares the same serde
    /// derive so this is sufficient to prove non-redaction.
    #[test]
    fn auth_config_serialize_still_carries_jwt_signing_key() {
        let cfg = AuthConfig {
            access_token_expiry: 900,
            refresh_token_expiry: 86400,
            challenge_ttl: 300,
            admin_idle_timeout: 900,
            refresh_reuse_grace: 30,
            session_cleanup_interval: 600,
            jwt_signing_key: Some("key-material".into()),
            step_up: (),
        };
        let json = serde_json::to_string(&cfg).expect("serialize");
        assert!(
            json.contains("key-material"),
            "Serialize must not redact — config persistence relies on round-trip: {json}"
        );
    }

    /// A config still carrying `[auth.step_up]` refuses to load.
    ///
    /// Silently ignoring it is the outcome to avoid: the file would keep
    /// asserting that operations are gated, the operator would keep believing
    /// it, and nothing would enforce it. Failing to start is unambiguous, and
    /// the message has to carry the migration or it just moves the confusion.
    #[test]
    fn a_config_still_carrying_the_retired_floors_is_refused() {
        let with_floors = r#"{
            "jwt_signing_key": null,
            "step_up": { "enabled": true, "floors": [{ "operation": "*", "mode": "self" }] }
        }"#;
        let err = serde_json::from_str::<AuthConfig>(with_floors)
            .expect_err("`[auth.step_up]` must be refused, not ignored");
        let msg = err.to_string();
        assert!(msg.contains("retired"), "got: {msg}");
        assert!(
            msg.contains("pnm approvals require"),
            "the refusal must name what replaces it, got: {msg}"
        );

        // Even an empty section is refused — an operator who wrote
        // `[auth.step_up]` and nothing else still has a stale file to fix.
        assert!(
            serde_json::from_str::<AuthConfig>(r#"{"jwt_signing_key":null,"step_up":{}}"#).is_err()
        );
    }

    /// …and the ordinary case, a config with no such section, still loads.
    #[test]
    fn a_config_without_the_retired_section_loads() {
        let cfg: AuthConfig =
            serde_json::from_str(r#"{ "jwt_signing_key": null }"#).expect("loads");
        assert_eq!(cfg.access_token_expiry, default_access_token_expiry());
    }
}

#[cfg(test)]
mod mdoc_trust_anchor_config_tests {
    use super::*;

    /// The field must default to empty, so an existing config that predates it
    /// still loads. Combined with the resolver failing closed, that means an
    /// upgrade neither breaks a deployment nor silently starts trusting mdocs.
    #[test]
    fn trust_anchors_default_to_empty_and_an_old_config_still_loads() {
        let cfg: VaultConfig = toml::from_str("grace_days = 30").expect("legacy config loads");
        assert_eq!(cfg.grace_days, 30);
        assert!(
            cfg.mdoc_iaca_trust_anchors.is_empty(),
            "absent means no mdoc issuer is trusted, not a permissive default"
        );
    }

    /// An existing deployment's config has no `[app_state]` section at all, and
    /// must keep loading with the documented default rather than failing or
    /// silently disabling retention.
    #[test]
    fn app_state_config_defaults_when_absent() {
        let cfg: AppStateConfig = toml::from_str("").expect("an absent section loads");
        assert_eq!(cfg.tombstone_retention_days, 30);
        assert_eq!(AppStateConfig::default().tombstone_retention_days, 30);
    }

    /// `0` is a meaningful value, not a missing one: it disables reaping. The
    /// distinction matters because the sweeper treats a zero *cutoff* as "expire
    /// everything", so this must survive as 0 rather than falling back to 30.
    #[test]
    fn app_state_retention_zero_survives_as_zero() {
        let cfg: AppStateConfig =
            toml::from_str("tombstone_retention_days = 0").expect("explicit zero loads");
        assert_eq!(
            cfg.tombstone_retention_days, 0,
            "an explicit 0 must not be rewritten to the default"
        );
    }

    #[test]
    fn trust_anchors_round_trip_through_toml() {
        let cfg: VaultConfig = toml::from_str(
            r#"
            grace_days = 7
            mdoc_iaca_trust_anchors = ["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"]
            "#,
        )
        .expect("config with anchors loads");
        assert_eq!(cfg.mdoc_iaca_trust_anchors.len(), 1);
        assert!(cfg.mdoc_iaca_trust_anchors[0].contains("BEGIN CERTIFICATE"));
    }
}

#[cfg(test)]
mod fjall_config_tests {
    use super::*;
    use std::sync::Mutex;

    // `apply_fjall_env_overrides` reads process-wide env vars; `cargo test`
    // runs test functions concurrently within one process, so every test
    // here that sets/removes `STORAGE_FJALL_*` serializes on this lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const FJALL_ENV_VARS: [&str; 3] = [
        "STORAGE_FJALL_BLOCK_CACHE",
        "STORAGE_FJALL_WRITE_BUFFER",
        "STORAGE_FJALL_MAX_JOURNAL",
    ];

    fn clear_fjall_env() {
        // SAFETY: guarded by `ENV_LOCK`, held by every test in this module
        // that touches these vars — no other test in this crate reads or
        // writes the `STORAGE_FJALL_*` names.
        unsafe {
            for var in FJALL_ENV_VARS {
                std::env::remove_var(var);
            }
        }
    }

    // -----------------------------------------------------------------
    // parse_byte_size: every suffix, plus the error cases
    // -----------------------------------------------------------------

    #[test]
    fn parse_byte_size_accepts_a_plain_byte_count() {
        assert_eq!(parse_byte_size("67108864").unwrap(), 67_108_864);
        assert_eq!(parse_byte_size("0").unwrap(), 0);
        assert_eq!(
            parse_byte_size("  1024  ").unwrap(),
            1024,
            "whitespace is trimmed"
        );
    }

    #[test]
    fn parse_byte_size_accepts_every_binary_suffix() {
        assert_eq!(parse_byte_size("1KiB").unwrap(), 1024);
        assert_eq!(parse_byte_size("64MiB").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_byte_size("1GiB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(
            parse_byte_size("2TiB").unwrap(),
            2 * 1024 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn parse_byte_size_accepts_every_decimal_suffix() {
        assert_eq!(parse_byte_size("512B").unwrap(), 512);
        assert_eq!(parse_byte_size("1KB").unwrap(), 1_000);
        assert_eq!(parse_byte_size("512MB").unwrap(), 512_000_000);
        assert_eq!(parse_byte_size("1GB").unwrap(), 1_000_000_000);
        assert_eq!(parse_byte_size("1TB").unwrap(), 1_000_000_000_000);
    }

    #[test]
    fn parse_byte_size_is_case_insensitive_and_accepts_fractions() {
        assert_eq!(parse_byte_size("64mib").unwrap(), 64 * 1024 * 1024);
        assert_eq!(
            parse_byte_size("1.5GiB").unwrap(),
            (1.5 * 1024.0 * 1024.0 * 1024.0) as u64
        );
    }

    #[test]
    fn parse_byte_size_rejects_garbage_and_unknown_suffixes() {
        assert!(parse_byte_size("").is_err(), "empty");
        assert!(parse_byte_size("   ").is_err(), "whitespace only");
        assert!(parse_byte_size("not-a-size").is_err(), "non-numeric");
        assert!(parse_byte_size("64XiB").is_err(), "unrecognised suffix");
        assert!(parse_byte_size("-64MiB").is_err(), "negative");
        assert!(parse_byte_size("-1").is_err(), "negative, no suffix");
        assert!(parse_byte_size("MiB").is_err(), "suffix with no number");
    }

    // -----------------------------------------------------------------
    // Range validation
    // -----------------------------------------------------------------

    #[test]
    fn parse_and_validate_rejects_zero_naming_the_field() {
        let err =
            parse_and_validate_fjall_bytes("STORAGE_FJALL_BLOCK_CACHE", "0", MIN_BLOCK_CACHE_BYTES)
                .unwrap_err();
        assert!(err.contains("STORAGE_FJALL_BLOCK_CACHE"), "got: {err}");
        assert!(err.contains("zero"), "got: {err}");
    }

    #[test]
    fn parse_and_validate_rejects_an_absurdly_small_value_naming_the_field() {
        let err = parse_and_validate_fjall_bytes(
            "STORAGE_FJALL_MAX_JOURNAL",
            "1KiB",
            MIN_MAX_JOURNAL_BYTES,
        )
        .unwrap_err();
        assert!(err.contains("STORAGE_FJALL_MAX_JOURNAL"), "got: {err}");
        assert!(err.contains("too small"), "got: {err}");
    }

    #[test]
    fn parse_and_validate_rejects_an_unparseable_value_naming_the_field() {
        let err = parse_and_validate_fjall_bytes(
            "STORAGE_FJALL_WRITE_BUFFER",
            "garbage",
            MIN_WRITE_BUFFER_BYTES,
        )
        .unwrap_err();
        assert!(err.contains("STORAGE_FJALL_WRITE_BUFFER"), "got: {err}");
    }

    #[test]
    fn parse_and_validate_accepts_a_value_at_exactly_the_floor() {
        assert_eq!(
            parse_and_validate_fjall_bytes(
                "STORAGE_FJALL_MAX_JOURNAL",
                "64MiB",
                MIN_MAX_JOURNAL_BYTES
            )
            .unwrap(),
            MIN_MAX_JOURNAL_BYTES
        );
    }

    #[test]
    fn fjall_tuning_validate_passes_when_every_field_is_unset() {
        assert!(FjallTuning::default().validate().is_ok());
    }

    #[test]
    fn fjall_tuning_validate_reports_a_below_floor_field() {
        let cfg = FjallTuning {
            block_cache: None,
            write_buffer: Some(1024),
            max_journal: None,
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("fjall.write_buffer"), "got: {err}");
    }

    // -----------------------------------------------------------------
    // Config-file (de)serialization: `[fjall]`, plain int or suffixed string
    // -----------------------------------------------------------------

    #[test]
    fn an_absent_fjall_table_defaults_every_field_to_unset() {
        let cfg: FjallTuning = toml::from_str("").expect("loads");
        assert_eq!(cfg, FjallTuning::default());
    }

    #[test]
    fn fjall_table_accepts_suffixed_strings_and_plain_integers() {
        let cfg: FjallTuning = toml::from_str(
            r#"
            block_cache = "64MiB"
            write_buffer = "16MiB"
            max_journal = 134217728
            "#,
        )
        .expect("loads");
        assert_eq!(cfg.block_cache, Some(64 * 1024 * 1024));
        assert_eq!(cfg.write_buffer, Some(16 * 1024 * 1024));
        assert_eq!(cfg.max_journal, Some(134_217_728));
    }

    #[test]
    fn fjall_table_refuses_a_below_floor_value_at_parse_time() {
        let err = toml::from_str::<FjallTuning>(r#"block_cache = "1B""#)
            .expect_err("a below-floor block_cache must be refused when the file is parsed");
        let msg = err.to_string();
        assert!(msg.contains("fjall.block_cache"), "got: {msg}");
    }

    #[test]
    fn fjall_table_refuses_an_unknown_suffix_at_parse_time() {
        let err = toml::from_str::<FjallTuning>(r#"max_journal = "64XiB""#)
            .expect_err("an unparseable size must be refused when the file is parsed");
        assert!(err.to_string().contains("fjall.max_journal"));
    }

    // -----------------------------------------------------------------
    // Env overrides the file
    // -----------------------------------------------------------------

    #[test]
    fn env_override_wins_over_the_file_value() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_fjall_env();

        let mut cfg = FjallTuning {
            block_cache: Some(32 * 1024 * 1024),
            write_buffer: None,
            max_journal: None,
        };
        // SAFETY: serialized by `ENV_LOCK`.
        unsafe {
            std::env::set_var("STORAGE_FJALL_BLOCK_CACHE", "8MiB");
        }
        apply_fjall_env_overrides(&mut cfg).expect("valid override applies");
        assert_eq!(
            cfg.block_cache,
            Some(8 * 1024 * 1024),
            "the env var must win over whatever the file set"
        );

        clear_fjall_env();
    }

    #[test]
    fn an_unset_env_var_leaves_the_file_value_untouched() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_fjall_env();

        let mut cfg = FjallTuning {
            block_cache: Some(32 * 1024 * 1024),
            write_buffer: Some(MIN_WRITE_BUFFER_BYTES),
            max_journal: None,
        };
        let before = cfg;
        apply_fjall_env_overrides(&mut cfg).expect("no env vars set: nothing to apply");
        assert_eq!(
            cfg, before,
            "with no STORAGE_FJALL_* vars set, nothing changes"
        );
    }

    #[test]
    fn env_override_refuses_an_invalid_value_naming_the_var() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_fjall_env();

        // SAFETY: serialized by `ENV_LOCK`.
        unsafe {
            std::env::set_var("STORAGE_FJALL_MAX_JOURNAL", "1KiB");
        }
        let err = apply_fjall_env_overrides(&mut FjallTuning::default())
            .expect_err("a below-floor journal size must be refused");
        assert!(err.contains("STORAGE_FJALL_MAX_JOURNAL"), "got: {err}");

        clear_fjall_env();
    }

    #[test]
    fn human_bytes_renders_the_natural_unit() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(64 * 1024 * 1024), "64.00 MiB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.00 GiB");
    }
}
