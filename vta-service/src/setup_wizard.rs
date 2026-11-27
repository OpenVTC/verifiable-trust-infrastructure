//! The prompt-driven `vta setup` wizard.
//!
//! A front-end over the library's setup engine (`vta_service::setup`): it
//! gathers a `WizardInputs` with `dialoguer` prompts and hands it to
//! `apply_inputs`. Kept in the binary so the library carries no terminal UI.

use dialoguer::{Confirm, Input};
use didwebvh_rs::url::WebVHURL;
use url::Url;

// The engine items the wizard drives, re-exported at this module's root so
// `interactive` reaches them as `super::…` exactly as it did inside the engine.
pub(crate) use vta_service::setup::{
    MediatorTsp, SetupUi, apply_inputs, derive_ws_url, existing_mediator_tsp, from_toml,
};

mod interactive;

pub use interactive::run_setup_wizard;

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
