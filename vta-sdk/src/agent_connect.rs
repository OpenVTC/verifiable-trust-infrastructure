//! One connect ladder for agent-side bridges.
//!
//! Every tool that runs *beside* a user and talks to their VTA on their behalf
//! — an MCP bridge, an agent-memory service, a desktop helper — needs the same
//! four ways in, in the same order, with the same fail-fast rules. That ladder
//! was written once inside `vta-mcp`'s `main.rs` and then had nowhere else to
//! live, so the next bridge either copied 110 lines or invented a fifth way in.
//! This module is that ladder as SDK surface.
//!
//! The order, highest precedence first:
//!
//! 1. **did:webvh bundle** — [`AgentConnect::agent_secrets`], a
//!    [`DidSecretsBundle`](crate::did_secrets::DidSecretsBundle) (path or inline
//!    JSON) whose `#key-0` (Ed25519) signs and `#key-1` (X25519) decrypts.
//!    Needs `vta_did` + `mediator_did`.
//! 2. **did:key** — [`AgentConnect::agent_did`] + `agent_key`, a scoped agent
//!    key authenticating directly over DIDComm. Needs `vta_did` +
//!    `mediator_did`. Works against DIDComm-only VTAs with no REST endpoint.
//! 3. **Token** — `url` + `token`, a bearer-token REST client. No refresh;
//!    testing and short-lived use.
//! 4. **Session** — `session_key`, reusing an existing `pnm`/`cnm` login from
//!    the keyring/session store. Auto-refreshing, and the only rung that runs
//!    [`TransportChoice::Auto`], so it inherits the workspace preference order
//!    (TSP > DIDComm > REST) from what both DID documents advertise.
//!
//! Two rules the ladder enforces rather than documents:
//!
//! - The two DIDComm identity modes are **mutually exclusive** — passing both a
//!   bundle and a did:key is an error, not a silent precedence win.
//! - A **half-configured** rung fails fast. Three of the four did:key fields
//!   set is an error naming the missing one, never a quiet fall-through to
//!   session mode, which is how a misconfigured bridge ends up authenticated as
//!   the operator instead of as the scoped agent it was meant to be.
//!
//! ```no_run
//! # async fn run() -> Result<(), vta_sdk::error::VtaError> {
//! use vta_sdk::agent_connect::AgentConnect;
//!
//! let client = AgentConnect::default()
//!     .agent_did("did:key:z6Mk…")
//!     .agent_key("z3u2…")
//!     .vta_did("did:webvh:…")
//!     .mediator_did("did:web:mediator.example")
//!     .connect()
//!     .await?;
//! # let _ = client;
//! # Ok(()) }
//! ```

use std::path::PathBuf;

use crate::client::VtaClient;
use crate::did_secrets::DidSecretsBundle;
use crate::error::VtaError;
use crate::session::{SessionStore, TransportChoice};

/// Default service name the `pnm` CLI stores its sessions under.
pub const DEFAULT_SERVICE_NAME: &str = "pnm-cli";

/// Prefix `pnm` stores its VTA sessions under. `cnm` uses `community:` for the
/// same reason; neither session backend adds one for you.
const PNM_SESSION_PREFIX: &str = "vta:";

/// The keyring key a `pnm` login is stored under, given the VTA's local name.
///
/// `pnm` writes every session as **`vta:<slug>`** — see `vta_keyring_key` in
/// `pnm-cli/src/config.rs` — and neither the keyring nor the file backend
/// prefixes anything on the way in or out. So a bridge that passes the bare
/// slug an operator typed finds no session at all and reports an
/// *authentication* failure to somebody who is authenticated. That failure mode
/// is worth naming because it is indistinguishable, from the operator's side,
/// from an expired login: they run `pnm auth status`, are told they are fine,
/// and are none the wiser.
///
/// Idempotent — a value already carrying the prefix is returned unchanged, so
/// an operator who worked the bug out for themselves and passes `vta:mine`
/// keeps working.
///
/// ```
/// # use vta_sdk::agent_connect::pnm_session_key;
/// assert_eq!(pnm_session_key("mine"), "vta:mine");
/// assert_eq!(pnm_session_key("vta:mine"), "vta:mine");
/// ```
pub fn pnm_session_key(slug: &str) -> String {
    if slug.starts_with(PNM_SESSION_PREFIX) {
        slug.to_string()
    } else {
        format!("{PNM_SESSION_PREFIX}{slug}")
    }
}

/// Which rung of the ladder a configuration selects. Resolved by
/// [`AgentConnect::mode`] *before* any network call, so a bridge can log the
/// mode (and refuse a mode it doesn't support) without connecting first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectMode {
    /// did:webvh secrets bundle over DIDComm.
    DidWebvhBundle {
        /// The bundle's DID — the authenticated agent identity.
        agent_did: String,
        /// The mediator the agent receives through.
        mediator_did: String,
    },
    /// Scoped `did:key` over DIDComm.
    DidKey {
        /// The agent's `did:key`.
        agent_did: String,
        /// The mediator the agent receives through.
        mediator_did: String,
    },
    /// Bearer-token REST client.
    Token {
        /// The VTA's REST base URL.
        url: String,
    },
    /// An existing `pnm`/`cnm` login, replayed from the session store.
    Session {
        /// The session key (VTA slug) selected.
        key: String,
    },
}

impl ConnectMode {
    /// A short, stable label for logs and diagnostics.
    pub fn label(&self) -> &'static str {
        match self {
            Self::DidWebvhBundle { .. } => "did:webvh-didcomm",
            Self::DidKey { .. } => "did:key-didcomm",
            Self::Token { .. } => "token-rest",
            Self::Session { .. } => "session",
        }
    }

    /// Whether this mode authenticates as a **dedicated agent identity** rather
    /// than as the operator. Bridges that enroll themselves as a managed device
    /// — attaching a device binding to the authenticated DID's ACL entry —
    /// should only do so when this is true; doing it in session mode binds the
    /// device to the *operator's* entry, which is not what the operator asked
    /// for and is awkward to undo.
    pub fn is_dedicated_agent(&self) -> bool {
        matches!(self, Self::DidWebvhBundle { .. } | Self::DidKey { .. })
    }
}

/// Connection inputs for an agent-side bridge. Build with the chained setters
/// (or construct the struct directly — every field is public), then call
/// [`connect`](Self::connect).
///
/// Bridges are expected to populate this from their own CLI/env layer; the SDK
/// deliberately reads no environment variables of its own, so a library
/// embedding a bridge can't be reconfigured behind its back.
#[derive(Debug, Clone, Default)]
pub struct AgentConnect {
    /// did:webvh agent secrets bundle: a path to a JSON `DidSecretsBundle`, or
    /// the inline JSON itself.
    pub agent_secrets: Option<String>,
    /// Agent `did:key` to authenticate as.
    pub agent_did: Option<String>,
    /// The agent's Ed25519 signing key, multibase-encoded.
    pub agent_key: Option<String>,
    /// The VTA's DID (DIDComm modes).
    pub vta_did: Option<String>,
    /// The mediator DID to route through (DIDComm modes).
    pub mediator_did: Option<String>,
    /// VTA REST URL. Required in token mode; an optional override elsewhere.
    pub url: Option<String>,
    /// Bearer token (token mode).
    pub token: Option<String>,
    /// Session key / VTA slug of an existing `pnm` login (session mode).
    pub session_key: Option<String>,
    /// Service name the session was stored under. Defaults to
    /// [`DEFAULT_SERVICE_NAME`].
    pub service_name: Option<String>,
    /// Directory holding stored sessions. Defaults to `~/.config/pnm`.
    pub sessions_dir: Option<PathBuf>,
    /// Transport choice for **session mode**. The DIDComm rungs are DIDComm by
    /// construction and token mode is REST by construction, so this only
    /// applies to the session rung. Defaults to [`TransportChoice::Auto`].
    pub transport: TransportChoice,
}

macro_rules! setter {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        pub fn $name(mut self, v: impl Into<String>) -> Self {
            self.$name = Some(v.into());
            self
        }
    };
}

impl AgentConnect {
    setter!(
        agent_secrets,
        "Set the did:webvh secrets bundle (path or inline JSON)."
    );
    setter!(agent_did, "Set the agent `did:key`.");
    setter!(agent_key, "Set the agent Ed25519 signing key (multibase).");
    setter!(vta_did, "Set the VTA's DID.");
    setter!(mediator_did, "Set the mediator DID.");
    setter!(url, "Set the VTA REST URL.");
    setter!(token, "Set the bearer token (token mode).");
    setter!(
        session_key,
        "Set the session key / VTA slug (session mode)."
    );
    setter!(
        service_name,
        "Set the service name sessions are stored under."
    );

    /// Set the sessions directory (default `~/.config/pnm`).
    pub fn sessions_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.sessions_dir = Some(dir.into());
        self
    }

    /// Set the transport choice used by **session mode**.
    pub fn transport(mut self, transport: TransportChoice) -> Self {
        self.transport = transport;
        self
    }

    /// Which rung this configuration selects, resolved without any I/O.
    ///
    /// Returns [`VtaError::Validation`] for a contradictory configuration (both
    /// DIDComm identity modes) or a half-configured one (some but not all of a
    /// rung's required fields), naming what is missing.
    pub fn mode(&self) -> Result<ConnectMode, VtaError> {
        let has_didkey_identity = self.agent_did.is_some() || self.agent_key.is_some();
        if self.agent_secrets.is_some() && has_didkey_identity {
            return Err(VtaError::Validation(
                "agent_secrets (did:webvh bundle) and agent_did/agent_key (did:key) are \
                 mutually exclusive — supply one identity, not both"
                    .into(),
            ));
        }

        // 1. did:webvh bundle over DIDComm.
        if let Some(raw) = self.agent_secrets.as_deref() {
            let bundle = load_bundle(raw)?;
            let (_, mediator_did) = self.require_didcomm_targets("did:webvh (agent_secrets)")?;
            return Ok(ConnectMode::DidWebvhBundle {
                agent_did: bundle.did,
                mediator_did,
            });
        }

        // 2. did:key over DIDComm. All four fields, or none.
        match (
            self.agent_did.as_deref(),
            self.agent_key.as_deref(),
            self.vta_did.as_deref(),
            self.mediator_did.as_deref(),
        ) {
            (Some(agent_did), Some(_), Some(_), Some(mediator_did)) => {
                return Ok(ConnectMode::DidKey {
                    agent_did: agent_did.to_string(),
                    mediator_did: mediator_did.to_string(),
                });
            }
            (None, None, _, _) if !has_didkey_identity => {}
            _ => {
                return Err(VtaError::Validation(format!(
                    "did:key DIDComm mode needs all of agent_did, agent_key, vta_did, \
                     mediator_did (or none of them); missing: {}",
                    missing_fields(&[
                        ("agent_did", self.agent_did.is_some()),
                        ("agent_key", self.agent_key.is_some()),
                        ("vta_did", self.vta_did.is_some()),
                        ("mediator_did", self.mediator_did.is_some()),
                    ])
                )));
            }
        }

        // 3. Token mode: explicit URL + non-empty bearer token.
        if let (Some(url), Some(token)) = (self.url.as_deref(), self.token.as_deref())
            && !token.is_empty()
        {
            return Ok(ConnectMode::Token {
                url: url.to_string(),
            });
        }

        // 4. Session mode.
        let key = self.session_key.as_deref().ok_or_else(|| {
            VtaError::Validation(
                "no connection configured: supply a session_key (an existing `pnm` login), \
                 url + token, or an agent identity (agent_did + agent_key + vta_did + \
                 mediator_did)"
                    .into(),
            )
        })?;
        Ok(ConnectMode::Session {
            key: key.to_string(),
        })
    }

    /// Resolve the mode and connect, returning an authenticated [`VtaClient`].
    ///
    /// The returned client owns whatever transport its rung selected. A DIDComm
    /// or TSP client holds a live mediator socket that `Drop` cannot close —
    /// call [`VtaClient::shutdown`] before dropping it. (`shutdown` is
    /// idempotent and a no-op on a REST client, so a bridge can call it
    /// unconditionally on its way out.)
    pub async fn connect(&self) -> Result<VtaClient, VtaError> {
        match self.mode()? {
            ConnectMode::DidWebvhBundle { .. } => {
                let raw = self.agent_secrets.as_deref().expect("mode checked");
                let bundle = load_bundle(raw)?;
                let (vta_did, mediator_did) =
                    self.require_didcomm_targets("did:webvh (agent_secrets)")?;
                VtaClient::connect_didcomm_bundle(
                    &bundle,
                    &vta_did,
                    &mediator_did,
                    self.url.clone(),
                )
                .await
            }
            ConnectMode::DidKey { .. } => {
                VtaClient::connect_didcomm(
                    self.agent_did.as_deref().expect("mode checked"),
                    self.agent_key.as_deref().expect("mode checked"),
                    self.vta_did.as_deref().expect("mode checked"),
                    self.mediator_did.as_deref().expect("mode checked"),
                    self.url.clone(),
                )
                .await
            }
            ConnectMode::Token { url } => {
                let client = VtaClient::new(&url);
                client
                    .set_token_async(self.token.clone().expect("mode checked"))
                    .await;
                Ok(client)
            }
            ConnectMode::Session { key } => {
                let service = self
                    .service_name
                    .as_deref()
                    .unwrap_or(DEFAULT_SERVICE_NAME)
                    .to_string();
                let dir = match &self.sessions_dir {
                    Some(d) => d.clone(),
                    None => default_sessions_dir()?,
                };
                SessionStore::new(&service, dir)
                    .connect_with_transport(&key, self.url.as_deref(), None, self.transport)
                    .await
                    // `SessionStore::connect` predates the typed error surface and
                    // returns a boxed `dyn Error`; its messages are already
                    // operator-facing (they name the `auth login` command to run),
                    // so carry the text rather than replacing it.
                    .map_err(|e| VtaError::Auth(e.to_string()))
            }
        }
    }

    /// Both DIDComm targets, or a `Validation` error naming the missing one.
    fn require_didcomm_targets(&self, mode: &str) -> Result<(String, String), VtaError> {
        match (self.vta_did.as_deref(), self.mediator_did.as_deref()) {
            (Some(v), Some(m)) => Ok((v.to_string(), m.to_string())),
            _ => Err(VtaError::Validation(format!(
                "{mode} DIDComm mode needs vta_did and mediator_did; missing: {}",
                missing_fields(&[
                    ("vta_did", self.vta_did.is_some()),
                    ("mediator_did", self.mediator_did.is_some()),
                ])
            ))),
        }
    }
}

/// Comma-joined names of the fields that are absent.
fn missing_fields(fields: &[(&str, bool)]) -> String {
    let missing: Vec<&str> = fields
        .iter()
        .filter(|(_, present)| !present)
        .map(|(name, _)| *name)
        .collect();
    if missing.is_empty() {
        "(none)".to_string()
    } else {
        missing.join(", ")
    }
}

/// Load a [`DidSecretsBundle`] from a path or inline JSON. A value naming an
/// existing file is read from disk; anything else is parsed as JSON directly.
fn load_bundle(raw: &str) -> Result<DidSecretsBundle, VtaError> {
    let json = if std::path::Path::new(raw).exists() {
        std::fs::read_to_string(raw).map_err(|e| {
            VtaError::Validation(format!("reading agent secrets bundle from `{raw}`: {e}"))
        })?
    } else {
        raw.to_string()
    };
    serde_json::from_str(&json).map_err(|e| {
        VtaError::Validation(format!(
            "parsing agent secrets bundle (path or inline JSON expected): {e}"
        ))
    })
}

/// `~/.config/pnm`, the directory `pnm` stores sessions in by default.
fn default_sessions_dir() -> Result<PathBuf, VtaError> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| {
            VtaError::Validation(
                "HOME (or USERPROFILE) is not set; set sessions_dir explicitly".into(),
            )
        })?;
    Ok(PathBuf::from(home).join(".config").join("pnm"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn didkey() -> AgentConnect {
        AgentConnect::default()
            .agent_did("did:key:zAgent")
            .agent_key("zKey")
            .vta_did("did:key:zVta")
            .mediator_did("did:key:zMed")
    }

    #[test]
    fn didkey_mode_needs_all_four_fields() {
        assert_eq!(
            didkey().mode().unwrap(),
            ConnectMode::DidKey {
                agent_did: "did:key:zAgent".into(),
                mediator_did: "did:key:zMed".into(),
            }
        );
    }

    #[test]
    fn half_configured_didkey_is_an_error_naming_the_gap() {
        // The important half of this: it must NOT fall through to session mode.
        // A bridge that silently authenticated as the operator because one flag
        // was missing is the failure this rung exists to prevent.
        let err = AgentConnect::default()
            .agent_did("did:key:zAgent")
            .session_key("my-vta")
            .mode()
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("agent_key"), "{msg}");
        assert!(msg.contains("vta_did"), "{msg}");
        assert!(!msg.contains("session"), "must not fall through: {msg}");
    }

    #[test]
    fn bundle_and_didkey_together_are_rejected() {
        let err = AgentConnect::default()
            .agent_secrets(r#"{"did":"did:webvh:a:b","secrets":[]}"#)
            .agent_did("did:key:zAgent")
            .mode()
            .unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn bundle_mode_reports_the_bundle_did() {
        let mode = AgentConnect::default()
            .agent_secrets(r#"{"did":"did:webvh:abc:example.com:a","secrets":[]}"#)
            .vta_did("did:key:zVta")
            .mediator_did("did:key:zMed")
            .mode()
            .unwrap();
        assert_eq!(
            mode,
            ConnectMode::DidWebvhBundle {
                agent_did: "did:webvh:abc:example.com:a".into(),
                mediator_did: "did:key:zMed".into(),
            }
        );
    }

    #[test]
    fn bundle_without_targets_names_them() {
        let err = AgentConnect::default()
            .agent_secrets(r#"{"did":"did:webvh:a:b","secrets":[]}"#)
            .mode()
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("vta_did"), "{msg}");
        assert!(msg.contains("mediator_did"), "{msg}");
    }

    #[test]
    fn token_mode_beats_session_mode() {
        let mode = AgentConnect::default()
            .url("https://vta.example")
            .token("jwt")
            .session_key("my-vta")
            .mode()
            .unwrap();
        assert_eq!(
            mode,
            ConnectMode::Token {
                url: "https://vta.example".into()
            }
        );
    }

    #[test]
    fn empty_token_falls_through_to_session() {
        // An exported-but-empty `VTA_TOKEN` is the common shell accident; it
        // must not select token mode and then fail at the first request.
        let mode = AgentConnect::default()
            .url("https://vta.example")
            .token("")
            .session_key("my-vta")
            .mode()
            .unwrap();
        assert_eq!(
            mode,
            ConnectMode::Session {
                key: "my-vta".into()
            }
        );
    }

    #[test]
    fn nothing_configured_names_every_way_in() {
        let err = AgentConnect::default().mode().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("session_key"), "{msg}");
        assert!(msg.contains("token"), "{msg}");
        assert!(msg.contains("agent_did"), "{msg}");
    }

    #[test]
    fn bundle_loads_from_a_file_path() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("agent-connect-bundle-{}.json", std::process::id()));
        std::fs::write(&path, r#"{"did":"did:webvh:f:example.com:b","secrets":[]}"#).unwrap();
        let bundle = load_bundle(path.to_str().unwrap()).unwrap();
        assert_eq!(bundle.did, "did:webvh:f:example.com:b");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pnm_session_keys_carry_the_prefix_and_are_idempotent() {
        assert_eq!(pnm_session_key("mine"), "vta:mine");
        assert_eq!(pnm_session_key("vta:mine"), "vta:mine");
        // A community key is `cnm`'s business, not this function's — it must
        // not be mistaken for an already-prefixed VTA key.
        assert_eq!(pnm_session_key("community:acme"), "vta:community:acme");
    }

    #[test]
    fn only_the_didcomm_modes_are_dedicated_agents() {
        assert!(didkey().mode().unwrap().is_dedicated_agent());
        assert!(
            !AgentConnect::default()
                .session_key("my-vta")
                .mode()
                .unwrap()
                .is_dedicated_agent()
        );
    }
}
