//! `config.toml`: the witness service's runtime configuration.
//!
//! The witness has no administrator surface on the wire (design note §3.1):
//! its policy is this file — which identities exist, where each is reached,
//! whether it serves, and what it will witness (§3.2–§3.3): the communities
//! whose members it witnesses, an optional allow-list, the DIDs excluded for
//! independence, and the session caps.
//!
//! Every policy default is the most restrictive reading (CLAUDE.md R5.1): an
//! identity is off, an identity with no `communities` witnesses nobody, and
//! "anyone" is only ever the explicit `communities = ["*"]`.
//!
//! Keys are snake_case, as in the VTC's `config.toml`, and every table this
//! crate defines refuses an unknown key (`deny_unknown_fields`). The
//! `[secrets]` table is `vti_secrets::SecretsConfig`, which accepts unknown
//! keys itself, so [`WitnessConfig::from_toml_str`] reads the whole file
//! through `serde_ignored` and refuses whatever it ignored: a typo in a
//! secret-store setting would otherwise select a different backend in
//! silence.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vti_secrets::{SecretBackend, SecretsConfig};

/// The most witness identities one service runs (design note §3.1, §5 item 3).
///
/// Each identity holds its own mediator socket, so the bound is also a bound
/// on the sockets and reconnect loops one process keeps.
pub const MAX_WITNESS_IDENTITIES: usize = 10;

/// The whole `config.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessConfig {
    /// Where the service keeps local state: the plaintext secret store when
    /// one is explicitly chosen, and the `did/<name>.jsonl` logs setup wrote
    /// for identities the operator publishes themselves.
    pub data_dir: PathBuf,

    /// The DID of the operator's VTA — the custodian that minted every
    /// identity below. Read only to warn about correlators (§3.6): the
    /// witness never acts as this DID and never signs anything naming it.
    pub operator_vta_did: String,

    /// A DID resolver sidecar to resolve through (network mode). Unset
    /// resolves locally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_url: Option<String>,

    /// Where the identities' private keys live. Required: there is no safe
    /// implicit default, and `backend = "config_seed"` is refused because it
    /// would put key material in this file.
    pub secrets: SecretsConfig,

    /// DIDs no identity of this service witnesses (§3.2), on top of each
    /// identity's own `[witness.independence]`. The service's own witness DIDs
    /// and `operator_vta_did` are always excluded and need not be listed.
    #[serde(default, skip_serializing_if = "Independence::is_empty")]
    pub independence: Independence,

    /// The witness identities, at most [`MAX_WITNESS_IDENTITIES`]. Written
    /// as `[[witness]]` tables.
    #[serde(default, rename = "witness", skip_serializing_if = "Vec::is_empty")]
    pub witnesses: Vec<WitnessIdentity>,
}

/// `[independence]`: DIDs excluded from being witnessed (design note §3.2) —
/// typically the operator's community DIDs and its own relationship DIDs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Independence {
    /// Exact DIDs. A session naming one in `parties` is refused, and a
    /// presentation carrying a credential issued by one is not witnessed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

impl Independence {
    fn is_empty(&self) -> bool {
        self.exclude.is_empty()
    }
}

/// The value of `communities` that means "witness anyone who passes the
/// cheap checks" (design note §3.3, §6 item 2). Never a default.
pub const ANY_COMMUNITY: &str = "*";

/// Default session time-to-live: ten minutes, the same as the acceptance
/// window a party's `submit` must arrive in anyway.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 600;
/// Default cap on one identity's open sessions.
pub const DEFAULT_MAX_OPEN_SESSIONS: usize = 1000;
/// Default cap on one opener's open sessions at one identity.
pub const DEFAULT_MAX_OPEN_SESSIONS_PER_PARTY: usize = 4;
/// The longest session time-to-live a configuration may set: a session is
/// one occasion, not a standing grant.
pub const MAX_SESSION_TTL_SECS: u64 = 24 * 60 * 60;

/// `[witness.sessions]`: one identity's session caps and lifetime (§3.3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLimits {
    /// Seconds an open session stays submittable. The spec leaves the expiry
    /// to the witness's own policy (`witness/session` Retention).
    #[serde(default = "default_ttl")]
    pub ttl_secs: u64,
    /// The most sessions this identity holds open at once.
    #[serde(default = "default_max_open")]
    pub max_open: usize,
    /// The most sessions one opener holds open at this identity at once.
    #[serde(default = "default_max_open_per_party")]
    pub max_open_per_party: usize,
}

fn default_ttl() -> u64 {
    DEFAULT_SESSION_TTL_SECS
}
fn default_max_open() -> usize {
    DEFAULT_MAX_OPEN_SESSIONS
}
fn default_max_open_per_party() -> usize {
    DEFAULT_MAX_OPEN_SESSIONS_PER_PARTY
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_SESSION_TTL_SECS,
            max_open: DEFAULT_MAX_OPEN_SESSIONS,
            max_open_per_party: DEFAULT_MAX_OPEN_SESSIONS_PER_PARTY,
        }
    }
}

/// One `[[witness]]` table: a witness identity this service runs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessIdentity {
    /// The operator's name for this identity. Local only: it appears in logs
    /// and nowhere on the wire.
    pub name: String,
    /// The identity's own `did:webvh`, minted by the operator's VTA from the
    /// `dtg-witness` template.
    pub did: String,
    /// The mediator this identity's DID document names for `#tsp` and
    /// `#didcomm`, and the one its socket connects to.
    pub mediator_did: String,
    /// Whether `vti-witness run` connects and serves this identity. Off
    /// unless the operator turns it on.
    #[serde(default)]
    pub enabled: bool,
    /// The VTC DIDs whose members this identity witnesses (§3.3): a submit
    /// must carry a valid membership credential issued by one of them to the
    /// submitter. `["*"]` witnesses anyone who passes the cheap checks, with no
    /// membership evidence asked for. **Empty witnesses nobody.**
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub communities: Vec<String>,
    /// An optional exact-DID allow-list of openers, for a closed deployment.
    /// Unset admits any opener the other rules admit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_parties: Option<Vec<String>>,
    /// DIDs this identity alone excludes, on top of the service-wide list.
    #[serde(default, skip_serializing_if = "Independence::is_empty")]
    pub independence: Independence,
    /// Session caps and lifetime.
    #[serde(default)]
    pub sessions: SessionLimits,
}

impl WitnessIdentity {
    /// A newly provisioned identity: off, witnessing nobody, default caps.
    pub fn provisioned(name: String, did: String, mediator_did: String, enabled: bool) -> Self {
        Self {
            name,
            did,
            mediator_did,
            enabled,
            communities: Vec::new(),
            allowed_parties: None,
            independence: Independence::default(),
            sessions: SessionLimits::default(),
        }
    }

    /// Whether `communities` is the explicit "anyone".
    pub fn witnesses_anyone(&self) -> bool {
        self.communities.iter().any(|c| c == ANY_COMMUNITY)
    }
}

/// A configuration that cannot be served.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl WitnessConfig {
    /// Read, parse and validate `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("read {}: {e}", path.display())))?;
        Self::from_toml_str(&raw)
            .map_err(|ConfigError(e)| ConfigError(format!("{}: {e}", path.display())))
    }

    /// Parse and validate a configuration — refusing any key it does not
    /// know, at any depth, and anything [`Self::validate`] refuses.
    pub fn from_toml_str(raw: &str) -> Result<Self, ConfigError> {
        let mut ignored = Vec::new();
        let de = toml::Deserializer::parse(raw).map_err(|e| ConfigError(e.to_string()))?;
        let config: Self = serde_ignored::deserialize(de, |path| ignored.push(path.to_string()))
            .map_err(|e| ConfigError(e.to_string()))?;
        if !ignored.is_empty() {
            return Err(ConfigError(format!(
                "unknown key(s): {} — refused rather than ignored, because a misspelt setting \
                 would otherwise take its default in silence",
                ignored.join(", ")
            )));
        }
        config.validate()?;
        Ok(config)
    }

    /// Every rule the file must meet, reported together so an operator fixes
    /// them in one pass.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        if !self.operator_vta_did.starts_with("did:") {
            errors.push(format!(
                "operator_vta_did must be a DID (got {:?})",
                self.operator_vta_did
            ));
        }
        if matches!(self.secrets.backend, Some(SecretBackend::ConfigSeed)) {
            errors.push(
                "secrets.backend = \"config_seed\" would keep the witness keys in config.toml; \
                 choose keyring, aws, gcp, azure, vault or kubernetes (or plaintext, for a \
                 test deployment only)"
                    .to_string(),
            );
        }
        errors.extend(did_list_errors(
            "independence.exclude",
            &self.independence.exclude,
        ));
        for w in &self.witnesses {
            errors.extend(policy_errors(w));
        }
        errors.extend(identity_errors(
            self.witnesses.iter().map(|w| {
                (
                    w.name.as_str(),
                    Some(w.did.as_str()),
                    w.mediator_did.as_str(),
                )
            }),
            Some(self.operator_vta_did.as_str()),
        ));

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError(format!(
                "{} configuration error(s):\n  - {}",
                errors.len(),
                errors.join("\n  - ")
            )))
        }
    }

    /// The identities `run` serves.
    pub fn enabled(&self) -> impl Iterator<Item = &WitnessIdentity> {
        self.witnesses.iter().filter(|w| w.enabled)
    }

    /// Serialise for writing.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError(e.to_string()))
    }
}

/// Every entry of a DID list is a DID, and none repeats.
fn did_list_errors(what: &str, dids: &[String]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    for did in dids {
        if !did.starts_with("did:") {
            errors.push(format!("{what}: {did:?} is not a DID"));
        } else if !seen.insert(did.as_str()) {
            errors.push(format!("{what}: {did} is listed twice"));
        }
    }
    errors
}

/// One identity's witnessing policy (§3.2–§3.3).
fn policy_errors(w: &WitnessIdentity) -> Vec<String> {
    let name = &w.name;
    let mut errors = Vec::new();

    // `*` is the explicit "anyone", and means nothing beside a DID: a list
    // naming both would read as a restriction an operator thinks they set.
    let wildcard = w.witnesses_anyone();
    if wildcard && w.communities.len() > 1 {
        errors.push(format!(
            "witness {name:?}: communities = [\"*\"] means anyone and cannot be combined \
             with community DIDs"
        ));
    } else if !wildcard {
        errors.extend(did_list_errors(
            &format!("witness {name:?}: communities"),
            &w.communities,
        ));
    }
    if let Some(allowed) = &w.allowed_parties {
        if allowed.is_empty() {
            errors.push(format!(
                "witness {name:?}: allowed_parties is empty, which admits nobody; remove the \
                 key to admit any party, or set enabled = false"
            ));
        }
        errors.extend(did_list_errors(
            &format!("witness {name:?}: allowed_parties"),
            allowed,
        ));
    }
    errors.extend(did_list_errors(
        &format!("witness {name:?}: independence.exclude"),
        &w.independence.exclude,
    ));

    let s = &w.sessions;
    if s.ttl_secs == 0 || s.ttl_secs > MAX_SESSION_TTL_SECS {
        errors.push(format!(
            "witness {name:?}: sessions.ttl_secs must be 1..={MAX_SESSION_TTL_SECS} (got {})",
            s.ttl_secs
        ));
    }
    if s.max_open == 0 {
        errors.push(format!(
            "witness {name:?}: sessions.max_open must be at least 1"
        ));
    }
    if s.max_open_per_party == 0 || s.max_open_per_party > s.max_open {
        errors.push(format!(
            "witness {name:?}: sessions.max_open_per_party must be 1..=sessions.max_open (got {})",
            s.max_open_per_party
        ));
    }
    errors
}

/// The rules every set of witness identities meets, shared by `config.toml`
/// and the setup file (which has no DIDs yet: `did` is `None` there).
///
/// `(name, did, mediator_did)` per identity; `operator_vta_did` when known.
pub(crate) fn identity_errors<'a>(
    identities: impl Iterator<Item = (&'a str, Option<&'a str>, &'a str)>,
    operator_vta_did: Option<&str>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut names = BTreeSet::new();
    let mut dids = BTreeSet::new();
    let mut count = 0usize;

    for (name, did, mediator_did) in identities {
        count += 1;
        if !is_valid_name(name) {
            errors.push(format!(
                "witness name {name:?} must be 1-64 characters of a-z, 0-9, '-' or '_'"
            ));
        } else if !names.insert(name) {
            errors.push(format!("witness name {name:?} is used twice"));
        }
        if !mediator_did.starts_with("did:") {
            errors.push(format!(
                "witness {name:?}: mediator_did must be a DID (got {mediator_did:?})"
            ));
        }
        if let Some(did) = did {
            if !did.starts_with("did:") {
                errors.push(format!("witness {name:?}: did must be a DID (got {did:?})"));
            } else if !dids.insert(did) {
                errors.push(format!("witness {name:?}: did {did} is used twice"));
            }
            // VTI-KEY-007: the witness is public by design, so the node's own
            // durable DID must never be the one it answers as.
            if Some(did) == operator_vta_did {
                errors.push(format!(
                    "witness {name:?}: did is the operator VTA's own DID. A witness answers \
                     and issues as an identity of its own (VTI-KEY-007); provision one with \
                     `vti-witness setup`"
                ));
            }
        }
    }

    if count > MAX_WITNESS_IDENTITIES {
        errors.push(format!(
            "{count} witness identities are configured; a service runs at most \
             {MAX_WITNESS_IDENTITIES}. Run a second service for the rest"
        ));
    }
    errors
}

/// A witness name: a short local label, safe in a file name and a log field.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    const VTA: &str = "did:webvh:QmVTA:vta.operator.example";

    fn witness_table(i: usize) -> String {
        format!(
            r#"
[[witness]]
name = "w{i}"
did = "did:webvh:QmW{i}:witness.example.net:w{i}"
mediator_did = "did:webvh:QmMED:mediator.example.org"
"#
        )
    }

    fn config_with(witnesses: usize) -> String {
        let mut s = format!(
            r#"
data_dir = "/var/lib/vti-witness"
operator_vta_did = "{VTA}"

[secrets]
backend = "keyring"
keyring_service = "vti-witness"
"#
        );
        for i in 0..witnesses {
            s.push_str(&witness_table(i));
        }
        s
    }

    #[test]
    fn a_minimal_config_parses_and_identities_default_to_disabled() {
        let config = WitnessConfig::from_toml_str(&config_with(2)).expect("parses");
        assert_eq!(config.witnesses.len(), 2);
        assert_eq!(config.witnesses[0].name, "w0");
        assert!(
            config.witnesses.iter().all(|w| !w.enabled),
            "an identity serves only when the operator turns it on"
        );
        assert_eq!(config.enabled().count(), 0);
    }

    #[test]
    fn ten_identities_are_accepted() {
        let config = WitnessConfig::from_toml_str(&config_with(MAX_WITNESS_IDENTITIES))
            .expect("ten is the limit, not past it");
        assert_eq!(config.witnesses.len(), MAX_WITNESS_IDENTITIES);
    }

    /// Design note §3.1: "The limit of 10 is enforced at configuration load."
    #[test]
    fn an_eleventh_identity_is_a_configuration_error_at_load() {
        let err = WitnessConfig::from_toml_str(&config_with(MAX_WITNESS_IDENTITIES + 1))
            .expect_err("eleven identities must not load");
        assert!(err.0.contains("11 witness identities"), "{err}");
        assert!(err.0.contains("at most 10"), "{err}");
    }

    #[test]
    fn an_unknown_top_level_key_is_refused() {
        let raw = format!("{}\nbogus = true\n", config_with(0))
            .replace("data_dir = ", "colour = \"blue\"\ndata_dir = ");
        let err = WitnessConfig::from_toml_str(&raw).expect_err("unknown key");
        assert!(err.0.contains("colour"), "{err}");
    }

    #[test]
    fn an_unknown_key_in_a_witness_table_is_refused() {
        let raw = format!("{}enabeld = true\n", config_with(1));
        let err = WitnessConfig::from_toml_str(&raw).expect_err("misspelt `enabled`");
        assert!(err.0.contains("enabeld"), "{err}");
    }

    /// `SecretsConfig` does not refuse unknown keys itself; the file-level
    /// `serde_ignored` pass does, so a misspelt backend setting is caught.
    #[test]
    fn an_unknown_key_in_the_secrets_table_is_refused() {
        let raw = config_with(0).replace(
            "keyring_service = \"vti-witness\"",
            "keyring_servise = \"vti-witness\"",
        );
        let err = WitnessConfig::from_toml_str(&raw).expect_err("misspelt secrets key");
        assert!(err.0.contains("keyring_servise"), "{err}");
    }

    #[test]
    fn duplicate_names_and_dids_are_refused() {
        let raw = format!("{}{}", config_with(0), witness_table(1) + &witness_table(1));
        let err = WitnessConfig::from_toml_str(&raw).expect_err("duplicates");
        assert!(err.0.contains("\"w1\" is used twice"), "{err}");
        assert!(err.0.contains("is used twice"), "{err}");
    }

    /// VTI-KEY-007: a node's durable DID is never the witness's.
    #[test]
    fn the_operator_vtas_own_did_cannot_be_a_witness() {
        let raw = format!(
            "{}\n[[witness]]\nname = \"me\"\ndid = \"{VTA}\"\nmediator_did = \"did:web:m.example\"\n",
            config_with(0)
        );
        let err = WitnessConfig::from_toml_str(&raw).expect_err("VTI-KEY-007");
        assert!(err.0.contains("VTI-KEY-007"), "{err}");
    }

    #[test]
    fn keys_in_config_are_refused() {
        let raw = config_with(0).replace("backend = \"keyring\"", "backend = \"config_seed\"");
        let err = WitnessConfig::from_toml_str(&raw).expect_err("config_seed");
        assert!(err.0.contains("config_seed"), "{err}");
    }

    #[test]
    fn a_config_round_trips_through_its_own_serialisation() {
        let config = WitnessConfig::from_toml_str(&config_with(3)).unwrap();
        let again = WitnessConfig::from_toml_str(&config.to_toml_string().unwrap())
            .expect("what setup writes, run reads");
        assert_eq!(config.witnesses, again.witnesses);
        assert_eq!(config.operator_vta_did, again.operator_vta_did);
    }

    /// R5.1: every witnessing default is the restrictive one.
    #[test]
    fn witnessing_defaults_are_the_most_restrictive() {
        let config = WitnessConfig::from_toml_str(&config_with(1)).unwrap();
        let w = &config.witnesses[0];
        assert!(!w.enabled);
        assert!(w.communities.is_empty(), "empty witnesses nobody");
        assert!(!w.witnesses_anyone());
        assert_eq!(w.allowed_parties, None);
        assert!(config.independence.exclude.is_empty());
        assert_eq!(w.sessions, SessionLimits::default());
        assert_eq!(w.sessions.ttl_secs, 600);
    }

    #[test]
    fn a_full_witnessing_policy_parses() {
        let raw = format!(
            r#"{}
[independence]
exclude = ["did:webvh:QmC:community.operator.example"]

[[witness]]
name = "p"
did = "did:webvh:QmP:witness.example.net:p"
mediator_did = "did:webvh:QmMED:mediator.example.org"
enabled = true
communities = ["did:webvh:QmV:vtc.example.org"]
allowed_parties = ["did:key:z6MkA"]

[witness.independence]
exclude = ["did:key:z6MkB"]

[witness.sessions]
ttl_secs = 120
max_open = 10
max_open_per_party = 2
"#,
            config_with(0)
        );
        let config = WitnessConfig::from_toml_str(&raw).expect("parses");
        let w = &config.witnesses[0];
        assert_eq!(w.communities, vec!["did:webvh:QmV:vtc.example.org"]);
        assert_eq!(
            w.allowed_parties.as_deref(),
            Some(&["did:key:z6MkA".to_string()][..])
        );
        assert_eq!(w.independence.exclude, vec!["did:key:z6MkB"]);
        assert_eq!(w.sessions.max_open_per_party, 2);
        assert_eq!(config.independence.exclude.len(), 1);
        let again = WitnessConfig::from_toml_str(&config.to_toml_string().unwrap()).unwrap();
        assert_eq!(again.witnesses, config.witnesses);
    }

    fn one_witness_with(extra: &str) -> String {
        format!(
            "{}\n[[witness]]\nname = \"w\"\ndid = \"did:webvh:QmW:w.example\"\n\
             mediator_did = \"did:webvh:QmM:m.example\"\n{extra}\n",
            config_with(0)
        )
    }

    #[test]
    fn the_wildcard_is_explicit_and_alone() {
        let ok = WitnessConfig::from_toml_str(&one_witness_with("communities = [\"*\"]")).unwrap();
        assert!(ok.witnesses[0].witnesses_anyone());

        let err = WitnessConfig::from_toml_str(&one_witness_with(
            "communities = [\"*\", \"did:webvh:QmV:vtc.example\"]",
        ))
        .unwrap_err();
        assert!(err.0.contains("cannot be combined"), "{err}");
    }

    #[test]
    fn policy_lists_must_hold_dids() {
        for extra in [
            "communities = [\"vtc.example\"]",
            "allowed_parties = [\"alice\"]",
            "[witness.independence]\nexclude = [\"bob\"]",
        ] {
            let err = WitnessConfig::from_toml_str(&one_witness_with(extra)).unwrap_err();
            assert!(err.0.contains("is not a DID"), "{extra}: {err}");
        }
        let err = WitnessConfig::from_toml_str(&format!(
            "{}\n[independence]\nexclude = [\"x\"]\n",
            config_with(0)
        ))
        .unwrap_err();
        assert!(err.0.contains("independence.exclude"), "{err}");
    }

    #[test]
    fn an_empty_allow_list_is_refused_rather_than_admitting_nobody_quietly() {
        let err =
            WitnessConfig::from_toml_str(&one_witness_with("allowed_parties = []")).unwrap_err();
        assert!(err.0.contains("admits nobody"), "{err}");
    }

    #[test]
    fn session_limits_are_validated() {
        for (extra, expect) in [
            ("[witness.sessions]\nttl_secs = 0", "ttl_secs"),
            ("[witness.sessions]\nttl_secs = 100000", "ttl_secs"),
            ("[witness.sessions]\nmax_open = 0", "max_open must"),
            (
                "[witness.sessions]\nmax_open = 2\nmax_open_per_party = 3",
                "max_open_per_party",
            ),
            ("[witness.sessions]\nmax_opn = 3", "max_opn"),
        ] {
            let err = WitnessConfig::from_toml_str(&one_witness_with(extra)).unwrap_err();
            assert!(err.0.contains(expect), "{extra}: {err}");
        }
    }
}
