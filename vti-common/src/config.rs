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

#[derive(Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default = "default_access_token_expiry")]
    pub access_token_expiry: u64,
    #[serde(default = "default_refresh_token_expiry")]
    pub refresh_token_expiry: u64,
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl: u64,
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

fn default_session_cleanup_interval() -> u64 {
    600
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            access_token_expiry: default_access_token_expiry(),
            refresh_token_expiry: default_refresh_token_expiry(),
            challenge_ttl: default_challenge_ttl(),
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
