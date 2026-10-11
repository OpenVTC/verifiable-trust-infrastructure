//! The `SignInPortal` service a DID-hosting node publishes in its DID document.
//!
//! Wallet sign-in with a trigger link (`auth/oob`, sign-in trigger-link
//! contract C4 / C9) needs two entries in the service's DID document: a
//! `TrustTaskHTTPS` base the wallet POSTs `<base>/trust-tasks` to, and a
//! `SignInPortal` whose **origin** is the origin of the page the link was
//! activated from. A wallet compares the two and refuses a mismatch
//! (VTI-LNK-105) — and refuses a document with no `SignInPortal` at all, which
//! the user sees as "This code can't be used".
//!
//! A DID-hosting control plane (and a self-managed daemon) serves its console
//! login page at `<origin>/login` off its public URL, and publishes exactly
//! that when it builds its own document (`did-hosting-common`'s
//! `add_sign_in_portal_service`). A node whose DID was minted from a
//! `did-host-http*` template instead used to lack the entry, so wallet sign-in
//! to it failed. Those templates now declare [`SIGN_IN_PORTAL_SERVICE_VAR`] and
//! the renderer derives it from `URL` (see `render::render`).
//!
//! ## Https only
//!
//! The entry is emitted only when `URL` is an `https` URL with a host. A plain
//! `http` URL (a local dev node) has the element pruned: a wallet will not
//! sign in to a plain-http portal, and an entry it would refuse is worse than
//! none because it hides the real gap.

use serde_json::{Value, json};

use super::TemplateError;

/// DID-document service `type` naming the page where people sign in with a
/// wallet (sign-in trigger-link contract C4).
pub const SIGN_IN_PORTAL_SERVICE_TYPE: &str = "SignInPortal";

/// Template variable carrying the whole `SignInPortal` entry.
///
/// Declared in the `did-host-http*` templates' `optionalVars` with a `null`
/// default and placed as a bare array member, so it is pruned unless a value is
/// present. When a template declares it and the caller does not supply it, the
/// renderer derives it from `URL` with [`sign_in_portal_service`]. A caller
/// that supplies it explicitly wins — supply `null` to omit the entry.
pub const SIGN_IN_PORTAL_SERVICE_VAR: &str = "SERVICE_SIGN_IN_PORTAL";

/// Fragment appended to the DID to id the entry.
const SERVICE_ID_FRAGMENT: &str = "#sign-in-portal";

/// Path of the console login page off the public URL's origin.
const LOGIN_PATH: &str = "/login";

/// The `SignInPortal` endpoint for a DID-hosting node whose public URL is
/// `public_url`: `<origin>/login`.
///
/// # Errors
///
/// [`TemplateError::Invalid`] unless `public_url` is an `https` URL with a
/// host.
pub fn sign_in_portal_endpoint(public_url: &str) -> Result<String, TemplateError> {
    let url = url::Url::parse(public_url.trim()).map_err(|e| {
        TemplateError::Invalid(format!(
            "SignInPortal needs the node's public URL, got '{public_url}': {e}"
        ))
    })?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(TemplateError::Invalid(format!(
            "SignInPortal is only advertised for an https public URL, got '{public_url}'"
        )));
    }
    Ok(format!(
        "{}{LOGIN_PATH}",
        url.origin().ascii_serialization()
    ))
}

/// Build the `SignInPortal` entry for the DID `did` (usually the `{DID}`
/// sentinel the VTA resolves after SCID computation) at a node whose public
/// URL is `public_url`.
///
/// The shape is the one DID hosting publishes for itself:
/// `{ "id": "<did>#sign-in-portal", "type": "SignInPortal",
/// "serviceEndpoint": "<origin>/login" }`.
///
/// # Errors
///
/// As [`sign_in_portal_endpoint`].
pub fn sign_in_portal_service(did: &str, public_url: &str) -> Result<Value, TemplateError> {
    Ok(json!({
        "id": format!("{did}{SERVICE_ID_FRAGMENT}"),
        "type": SIGN_IN_PORTAL_SERVICE_TYPE,
        "serviceEndpoint": sign_in_portal_endpoint(public_url)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoint_is_the_login_page_on_the_url_origin() {
        assert_eq!(
            sign_in_portal_endpoint("https://webvh.storm.ws").unwrap(),
            "https://webvh.storm.ws/login"
        );
        assert_eq!(
            sign_in_portal_endpoint("https://Host.Example.com:8443/some/path/").unwrap(),
            "https://host.example.com:8443/login"
        );
        assert_eq!(
            sign_in_portal_endpoint("https://host.example.com:443/").unwrap(),
            "https://host.example.com/login"
        );
    }

    #[test]
    fn only_https_is_advertised() {
        for bad in [
            "http://localhost:8530",
            "http://host.example.com",
            "did:web:example.com",
            "not a url",
            "",
        ] {
            assert!(sign_in_portal_endpoint(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn the_entry_is_the_contract_shape() {
        let s = sign_in_portal_service("{DID}", "https://webvh.storm.ws").unwrap();
        assert_eq!(
            s,
            json!({
                "id": "{DID}#sign-in-portal",
                "type": "SignInPortal",
                "serviceEndpoint": "https://webvh.storm.ws/login",
            })
        );
    }
}
