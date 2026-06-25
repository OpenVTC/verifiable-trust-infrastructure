//! VTA setup flows — split into focused submodules:
//!
//! - [`interactive`]: prompt-driven `vta setup` wizard.
//! - [`from_toml`]: non-interactive `vta setup --from <file>` loading a
//!   [`WizardInputs`] TOML schema.
//!
//! This file retains the small helpers both paths share (seed-context
//! bootstrap, webvh-URL prompt, silent mnemonic generation) and
//! re-exports the public entry points so callers keep importing from
//! `crate::setup::*` — `main.rs` and `did_webvh.rs` don't need to know
//! the internal layout.

use std::path::{Path, PathBuf};

use bip39::Mnemonic;
use dialoguer::{Confirm, Input};
use didwebvh_rs::url::WebVHURL;
use rand::Rng;
use serde_json::{Value as JsonValue, json};
use url::Url;

use crate::config::ServicesConfig;
use crate::contexts::{self, ContextRecord};
use crate::store::KeyspaceHandle;

mod from_toml;
mod interactive;

/// UI seam between the shared setup engine ([`apply_inputs`]) and the two
/// front-ends that drive it: the interactive `vta setup` wizard (real prompts)
/// and the non-interactive `vta setup --from <file>` path ([`SilentUi`]).
///
/// The engine owns all the *work* (mint keys, create DIDs, write the store,
/// seal); the few places where the interactive wizard needs operator input
/// that the TOML file can't express — confirming the displayed mnemonic, and
/// choosing where to write a freshly-minted DID's `did.jsonl` — are funnelled
/// through this trait so a single engine serves both front-ends (P1.2).
pub trait SetupUi {
    /// Called once, right after the master mnemonic is generated.
    ///
    /// The interactive wizard displays the phrase and requires the operator to
    /// confirm they've recorded it (returning an error aborts setup); the
    /// silent impl is a no-op — the `--from` path never displays the mnemonic,
    /// and the operator captures it via `pnm backup export` after the first
    /// admin connects.
    fn confirm_mnemonic(&self, mnemonic: &Mnemonic) -> Result<(), Box<dyn std::error::Error>>;

    /// Resolve where a freshly-created DID's `did.jsonl` log should be written,
    /// or `None` to skip writing it.
    ///
    /// `default` is the canonical in-store location
    /// (`<data_dir>/did-logs/<label>-did.jsonl`). The silent impl returns
    /// `Some(default)` — `--from` has always written the log to that canonical
    /// path. The interactive wizard prompts for a path (offering its own
    /// default) so the operator can place it wherever the hosting tool expects.
    fn did_log_path(&self, label: &str, default: &Path) -> Option<PathBuf>;
}

/// Non-interactive [`SetupUi`] for `vta setup --from <file>`: never displays
/// the mnemonic, always writes `did.jsonl` to the canonical in-store path.
/// Preserves the exact behaviour the `--from` path had before the engine was
/// shared with the interactive wizard.
pub struct SilentUi;

impl SetupUi for SilentUi {
    fn confirm_mnemonic(&self, _mnemonic: &Mnemonic) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    fn did_log_path(&self, _label: &str, default: &Path) -> Option<PathBuf> {
        Some(default.to_path_buf())
    }
}

// Submodules are private — external callers reach the entry points via
// the re-exports below. Allowed-unused because `WizardInputs` and its
// nested enums are referenced from doc-string links (including in
// `main.rs`) rather than imported directly; making them pub-use keeps
// the `vta_service::setup::WizardInputs` path in the published docs.
#[allow(unused_imports)]
pub use from_toml::{
    ExistingDataDirPolicy, MessagingInput, SecretsBackendInput, VtaDidInput, WizardInputs,
    apply_inputs, run_setup_from_file,
};
pub use interactive::run_setup_wizard;

/// Create a seed application context and store it. Shared by both the
/// interactive wizard and the non-interactive `--from <file>` path.
pub(crate) async fn create_seed_context(
    contexts_ks: &KeyspaceHandle,
    id: &str,
    name: &str,
) -> Result<ContextRecord, Box<dyn std::error::Error>> {
    contexts::create_context(contexts_ks, id, name).await
}

/// Generate a fresh 24-word BIP-39 mnemonic without displaying or
/// confirming it. Used by the non-interactive `--from <file>` path —
/// the operator captures the seed later via `pnm backup export` once
/// the first admin has connected.
///
/// The interactive wizard wraps this in a display+confirm prompt
/// (`interactive::generate_mnemonic_with_confirmation`) so the operator
/// must explicitly acknowledge they've recorded it before setup
/// continues.
pub(crate) fn generate_mnemonic_silent() -> Result<Mnemonic, Box<dyn std::error::Error>> {
    let mut entropy = [0u8; 32];
    rand::rng().fill_bytes(&mut entropy);
    Ok(Mnemonic::from_entropy(&entropy)?)
}

/// Build the `services` Vec passed to the WebVH DID builder for a
/// `CreateWebvh` VTA DID — i.e. everything the VTA DID document
/// publishes apart from the auto-injected DIDComm/Authentication
/// entries that `create_simple_webvh_did` adds itself.
///
/// Currently this is just the `VTARest` entry: present iff REST is
/// enabled and a `public_url` is configured. Returns `None` (rather
/// than `Some(vec![])`) when the array would be empty so the
/// downstream call can pass `None` through to the WebVH builder
/// without a special case.
///
/// The non-interactive setup path's `validate_inputs` rejects
/// `services.rest = true` + `public_url = None` at parse time, and
/// the interactive wizard makes the URL prompt mandatory when REST
/// is enabled, so in practice the absent branch only fires for
/// `services.rest = false`. The `is_some()` branch is still gated
/// on `services.rest` so a stray `public_url` set without REST
/// doesn't end up advertising a service the VTA isn't running.
///
/// Shared by both setup paths so the rule has one source of truth —
/// see the matrix test in this module's `tests` for the full
/// `(rest, public_url)` truth table.
pub(crate) fn build_vta_additional_services(
    services: &ServicesConfig,
    public_url: Option<&str>,
) -> Option<Vec<JsonValue>> {
    let mut additional = Vec::new();
    if services.rest
        && let Some(url) = public_url.map(str::trim).filter(|u| !u.is_empty())
    {
        additional.push(json!({
            "id": "{DID}#vta-rest",
            "type": "VTARest",
            "serviceEndpoint": url,
        }));
    }
    if additional.is_empty() {
        None
    } else {
        Some(additional)
    }
}

/// Derive the mediator's WebSocket endpoint from its HTTP endpoint by
/// swapping the scheme (`http`→`ws`, `https`→`wss`), trimming any
/// trailing slash, and appending `/ws`.
///
/// Returns `None` when `http_url` is not an `http(s)://` URL — callers
/// decide whether that's a hard error (the `--from <file>` path, which
/// has no operator to re-prompt) or merely "no default offered" (the
/// interactive wizard, which lets the operator type the WS URL anyway).
///
/// Mirrors the canonical convention in
/// `affinidi-messaging-mediator/tools/mediator-setup`
/// (`generators/did_peer.rs::websocket_service_uri`): the mediator
/// serves HTTP DIDComm at `{base}/` and the WebSocket upgrade at
/// `{base}/ws`. The `didcomm-mediator` template advertises both in a
/// single `#service` block, so a freshly-minted mediator's DID document
/// 404s on every WS upgrade without the `/ws` suffix.
///
/// Single source of truth shared by [`interactive`] and [`from_toml`]
/// so the two derivations cannot drift (PR #339 introduced two copies).
pub(crate) fn derive_ws_url(http_url: &str) -> Option<String> {
    let scheme_swapped = if let Some(rest) = http_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = http_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        return None;
    };
    Some(format!("{}/ws", scheme_swapped.trim_end_matches('/')))
}

/// Prompt the user for a URL (e.g. `https://example.com/dids/vta`) and
/// convert it to a [`WebVHURL`]. Re-prompts on invalid input.
///
/// Shared between the interactive wizard (for the VTA DID / mediator
/// DID URL) and `did_webvh.rs`'s standalone `vta create-did-webvh`
/// CLI. Kept at the module root (not inside `interactive`) because the
/// CLI is not conceptually part of the wizard flow.
pub(crate) fn prompt_webvh_url(label: &str) -> Result<WebVHURL, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  Enter the URL where the {label} DID document will be hosted.");
    eprintln!("  Examples:");
    eprintln!("    https://example.com                -> did:webvh:{{SCID}}:example.com");
    eprintln!("    https://example.com/dids/vta       -> did:webvh:{{SCID}}:example.com:dids:vta");
    eprintln!("    http://localhost:8000               -> did:webvh:{{SCID}}:localhost%3A8000");
    eprintln!();

    loop {
        let raw: String = Input::new()
            .with_prompt(format!("{label} DID URL"))
            .default("http://localhost:8000/".into())
            .interact_text()?;

        let parsed = match Url::parse(&raw) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("\x1b[31mInvalid URL: {e} — please try again.\x1b[0m");
                continue;
            }
        };

        match WebVHURL::parse_url(&parsed) {
            Ok(webvh_url) => {
                let did_display = webvh_url.to_string();
                let http_url = webvh_url.get_http_url(None).map_err(|e| format!("{e}"))?;

                eprintln!("  DID:  {did_display}");
                eprintln!("  URL:  {http_url}");

                if Confirm::new()
                    .with_prompt("Is this correct?")
                    .default(true)
                    .interact()?
                {
                    return Ok(webvh_url);
                }
            }
            Err(e) => {
                eprintln!(
                    "\x1b[31mCould not convert to a webvh DID: {e} — please try again.\x1b[0m"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Matrix coverage for the VTA DID document's `additional_services`
    /// array — the bug-prone surface that originally let a REST-only
    /// VTA ship a DID document with no service entries.
    ///
    /// Inputs sweep `(services.rest, public_url)`; `services.didcomm`
    /// is irrelevant to this helper (the DIDComm service is added by
    /// `create_simple_webvh_did` itself via the `add_mediator_service`
    /// flag, not via the `additional_services` Vec).
    #[test]
    fn build_vta_additional_services_matrix() {
        let url = Some("https://vta.example.com");

        // 1. REST + URL → exactly one VTARest entry pointing at the URL.
        let services = ServicesConfig {
            rest: true,
            didcomm: false,
            webauthn: false,
            tsp: false,
        };
        let out = build_vta_additional_services(&services, url)
            .expect("REST + URL must emit a service entry");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["type"], "VTARest");
        assert_eq!(out[0]["serviceEndpoint"], "https://vta.example.com");
        assert_eq!(out[0]["id"], "{DID}#vta-rest");

        // 2. REST + URL with surrounding whitespace → trimmed in the entry.
        let out = build_vta_additional_services(&services, Some("  https://vta.example.com  "))
            .expect("whitespace-padded URL must still emit");
        assert_eq!(out[0]["serviceEndpoint"], "https://vta.example.com");

        // 3. REST + None → empty (validate_inputs rejects this combo
        //    upstream, but the helper still must not produce a bogus
        //    entry if it ever sees it).
        assert!(build_vta_additional_services(&services, None).is_none());

        // 4. REST + empty string → empty (treated like None).
        assert!(build_vta_additional_services(&services, Some("")).is_none());
        assert!(build_vta_additional_services(&services, Some("   ")).is_none());

        // 5. REST disabled, URL set → no VTARest entry. The URL is
        //    still in `AppConfig.public_url` for other uses, but it
        //    must NOT be advertised as a service the VTA doesn't run.
        let services = ServicesConfig {
            rest: false,
            didcomm: true,
            webauthn: false,
            tsp: false,
        };
        assert!(
            build_vta_additional_services(&services, url).is_none(),
            "URL must not be published as a service when REST is disabled"
        );

        // 6. Both off, no URL → empty. (Edge case; a VTA with no
        //    services is degenerate but the helper must stay total.)
        let services = ServicesConfig {
            rest: false,
            didcomm: false,
            webauthn: false,
            tsp: false,
        };
        assert!(build_vta_additional_services(&services, None).is_none());
    }

    /// `derive_ws_url` is the single source of truth for the mediator's
    /// WebSocket endpoint default — both setup paths derive through it.
    #[test]
    fn derive_ws_url_swaps_scheme_trims_and_appends_ws() {
        // https → wss, plain host.
        assert_eq!(
            derive_ws_url("https://mediator.example.com").as_deref(),
            Some("wss://mediator.example.com/ws")
        );
        // http → ws.
        assert_eq!(
            derive_ws_url("http://localhost:8000").as_deref(),
            Some("ws://localhost:8000/ws")
        );
        // Trailing slash is trimmed before the suffix (no `//ws`).
        assert_eq!(
            derive_ws_url("https://mediator.example.com/").as_deref(),
            Some("wss://mediator.example.com/ws")
        );
        // Path is preserved; suffix appended once.
        assert_eq!(
            derive_ws_url("https://example.com/mediator/v1/").as_deref(),
            Some("wss://example.com/mediator/v1/ws")
        );
        // Non-http(s) schemes (and bare hosts) yield None — caller decides
        // whether that's fatal or just "offer no default".
        assert_eq!(derive_ws_url("wss://already.ws/ws"), None);
        assert_eq!(derive_ws_url("mediator.example.com"), None);
        assert_eq!(derive_ws_url(""), None);
    }
}
