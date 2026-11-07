//! Shared WebAuthn / passkey infrastructure (types + storage).
//!
//! The shape — `PasskeyState` trait, `build_webauthn(public_url)` helper,
//! `Enrollment` / `PasskeyUser` / `CredentialMapping` storage types,
//! `claimed_at` ceremony-lock pattern — is adopted from
//! [`affinidi/affinidi-webvh-service`](https://github.com/affinidi/affinidi-webvh-service)
//! (`webvh-common/src/server/passkey/`), which already proves the
//! pattern in production. Both VTA and VTC implement `PasskeyState`
//! on their `AppState` and reuse the same enrolment + login
//! primitives.
//!
//! ## Module scope
//!
//! This crate ships the **storage layer + supporting types**:
//!
//! - [`PasskeyState`] trait, defining what state services must expose.
//! - [`build_webauthn`] helper that turns a `public_url` config into a
//!   [`webauthn_rs::Webauthn`] instance using the URL's domain as the
//!   relying-party ID and the full URL as the origin.
//! - The persistence layer (see [`store`] sub-module) — enrolment
//!   tokens, passkey users, credential mappings, registration /
//!   authentication ceremony state.
//!
//! The matching route handlers (`enroll_start`, `enroll_finish`,
//! `login_start`, `login_finish`) ship in a follow-up; this PR is
//! intentionally storage-only so consumers can build their own
//! orchestration on top.

pub mod store;

use std::sync::Arc;

use url::Url;
use webauthn_rs::prelude::*;

use crate::auth::extractor::AuthState;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// How long an in-progress enrolment claim blocks other concurrent
/// claims on the same token. Sized for a generous WebAuthn ceremony
/// (browser dialog + key tap); a legitimate user retrying after a
/// failed ceremony only waits this long before the claim expires.
///
/// Lifted unchanged from `webvh-common`.
pub const ENROLLMENT_CLAIM_WINDOW_SECS: u64 = 300;

/// Trait that application states implement to support passkey routes.
///
/// Extends [`AuthState`] (which provides JWT keys + sessions keyspace)
/// with the WebAuthn and ACL access that the enrolment + login flows
/// need. The intentionally narrow surface keeps services free to add
/// their own state without leaking it into the shared module.
pub trait PasskeyState: AuthState {
    /// Returns the WebAuthn relying-party handle if configured. `None`
    /// means the service didn't supply a `public_url` at startup —
    /// passkey routes should 503 in that case.
    fn webauthn(&self) -> Option<&Arc<Webauthn>>;

    /// ACL keyspace. Used to confirm the enrolling DID has a matching
    /// ACL entry and to issue the post-ceremony session with the
    /// correct role.
    fn acl_ks(&self) -> &KeyspaceHandle;

    /// Access-token lifetime in seconds (returned by enrolment + login).
    fn access_token_expiry(&self) -> u64;

    /// Refresh-token lifetime in seconds.
    fn refresh_token_expiry(&self) -> u64;

    /// Public base URL used by admin endpoints to render enrolment
    /// links. `None` disables admin invite endpoints.
    fn public_url(&self) -> Option<&str>;

    /// Default enrolment-invite TTL in seconds, used when an admin
    /// creates a new invite without an explicit expiry.
    fn enrollment_ttl(&self) -> u64;
}

/// Build a [`Webauthn`] instance from the service's `public_url`.
///
/// - **Relying-party ID** = the URL's domain (e.g. `example.com`).
/// - **Origin** = the parsed URL (e.g. `https://example.com`).
///
/// Single-source derivation matches the workspace's spec decision
/// (see `docs/05-design-notes/vtc-mvp.md` §4.2 + the M0.1.6 plan
/// entry under D7). Operators who migrate to a different base domain
/// re-register every passkey — documented in the operator runbook.
pub fn build_webauthn(public_url: &str) -> Result<Webauthn, AppError> {
    let url = Url::parse(public_url)
        .map_err(|e| AppError::Config(format!("invalid public_url '{public_url}': {e}")))?;

    let rp_id = url
        .domain()
        .ok_or_else(|| AppError::Config("public_url has no domain".into()))?
        .to_string();

    let builder = WebauthnBuilder::new(&rp_id, &url)
        .map_err(|e| AppError::Config(format!("failed to build WebauthnBuilder: {e}")))?;

    let webauthn = builder
        .rp_name("Verifiable Trust Infrastructure")
        .build()
        .map_err(|e| AppError::Config(format!("failed to build Webauthn: {e}")))?;

    Ok(webauthn)
}

/// Longest WebAuthn `user.name` / `user.displayName`, in **bytes**, that we
/// send to an authenticator.
///
/// CTAP2 only requires an authenticator to accept 64 bytes, and some reject
/// more outright rather than truncating: a YubiKey 5 (firmware 5.7.4) answers
/// `CTAP1_ERR_INVALID_LENGTH` to a 65-byte `user.name` before it asks for a
/// touch, which Chrome reports only as "Passkey creation was cancelled".
/// WebAuthn L2 §5.4.3 lets an authenticator truncate `displayName` to the same
/// 64 bytes, so both are held to it.
pub const MAX_AUTHENTICATOR_NAME_BYTES: usize = 64;

/// What an authenticator shows a passkey for `did` as.
///
/// Display only: the credential is bound to the DID by the service's own
/// record and the stable `user.id`, never by this name.
///
/// * A `did:webvh` drops its `did:webvh:<scid>:` prefix. The host and path are
///   the part a person recognises; the SCID is ~46 characters they cannot, and
///   two DIDs on one host differ only after it.
/// * Any other DID is kept whole when it fits, else shown by its two ends, so
///   the method stays visible (`did:peer:2.Ez6L…`).
///
/// The result is at most [`MAX_AUTHENTICATOR_NAME_BYTES`] and never splits a
/// character.
pub fn authenticator_name_for_did(did: &str) -> String {
    if let Some(tail) = did
        .strip_prefix("did:webvh:")
        .and_then(|rest| rest.split_once(':'))
        .map(|(_scid, tail)| tail)
        .filter(|tail| !tail.is_empty())
    {
        return clamp_authenticator_name(tail);
    }
    if did.len() <= MAX_AUTHENTICATOR_NAME_BYTES {
        return did.to_string();
    }
    const HEAD_BYTES: usize = 40;
    const TAIL_BYTES: usize = MAX_AUTHENTICATOR_NAME_BYTES - HEAD_BYTES - ELLIPSIS.len();
    let head_end = floor_char_boundary(did, HEAD_BYTES);
    let tail_start = ceil_char_boundary(did, did.len() - TAIL_BYTES);
    format!("{}{ELLIPSIS}{}", &did[..head_end], &did[tail_start..])
}

/// Hold any name (an operator's label, say) to
/// [`MAX_AUTHENTICATOR_NAME_BYTES`], keeping its tail behind a leading `…`:
/// for a path-shaped name the distinguishing part is at the end. A name that
/// fits is returned unchanged; the cut never splits a character.
pub fn clamp_authenticator_name(name: &str) -> String {
    if name.len() <= MAX_AUTHENTICATOR_NAME_BYTES {
        return name.to_string();
    }
    let keep = MAX_AUTHENTICATOR_NAME_BYTES - ELLIPSIS.len();
    let start = ceil_char_boundary(name, name.len() - keep);
    format!("{ELLIPSIS}{}", &name[start..])
}

/// U+2026, three bytes in UTF-8.
const ELLIPSIS: &str = "\u{2026}";

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    while !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DID a YubiKey 5 refused as `user.name` (95 bytes).
    const PORTAL_DID: &str = "did:webvh:QmSyntheticExampleScid000000000000000000000000:dids.example.org:example-member-000001";

    #[test]
    fn a_webvh_did_is_named_by_its_host_and_path() {
        assert!(PORTAL_DID.len() > MAX_AUTHENTICATOR_NAME_BYTES);
        assert_eq!(
            authenticator_name_for_did(PORTAL_DID),
            "dids.example.org:example-member-000001"
        );
    }

    #[test]
    fn a_webvh_did_with_a_long_path_keeps_the_end_of_it() {
        let did = format!("did:webvh:QmScid:example.com:{}:persona", "a".repeat(80));
        let name = authenticator_name_for_did(&did);
        assert!(name.len() <= MAX_AUTHENTICATOR_NAME_BYTES, "{name}");
        assert!(
            name.starts_with('\u{2026}') && name.ends_with(":persona"),
            "{name}"
        );
    }

    #[test]
    fn a_short_did_is_left_whole() {
        assert_eq!(
            authenticator_name_for_did("did:key:z6Mkshort"),
            "did:key:z6Mkshort"
        );
        let exact = format!("did:key:{}", "z".repeat(MAX_AUTHENTICATOR_NAME_BYTES - 8));
        assert_eq!(authenticator_name_for_did(&exact), exact);
    }

    #[test]
    fn a_long_non_webvh_did_is_named_by_its_two_ends() {
        let long = format!("did:peer:2.{}", "V".repeat(900));
        let name = authenticator_name_for_did(&long);
        assert_eq!(name.len(), MAX_AUTHENTICATOR_NAME_BYTES, "{name}");
        assert!(name.starts_with("did:peer:2."), "{name}");
    }

    #[test]
    fn the_limit_is_in_bytes_and_cuts_on_char_boundaries() {
        // 2 bytes per char: 64 chars is 128 bytes, over the limit.
        let wide = format!("did:example:{}", "\u{e9}".repeat(100));
        assert!(authenticator_name_for_did(&wide).len() <= MAX_AUTHENTICATOR_NAME_BYTES);
        let label = "\u{e9}".repeat(200);
        let got = clamp_authenticator_name(&label);
        assert!(got.len() <= MAX_AUTHENTICATOR_NAME_BYTES, "{got}");
        assert!(got.starts_with('\u{2026}'));
        // A 3-byte char straddling every cut point.
        let cjk = format!("did:example:{}", "\u{4e2d}".repeat(50));
        assert!(authenticator_name_for_did(&cjk).len() <= MAX_AUTHENTICATOR_NAME_BYTES);
    }

    #[test]
    fn a_label_that_fits_is_unchanged() {
        assert_eq!(clamp_authenticator_name("Ops laptop"), "Ops laptop");
    }

    #[test]
    fn build_webauthn_happy_path() {
        let w = build_webauthn("https://vtc.example.com").expect("ok");
        // Sanity: the builder constructed something usable. The
        // webauthn-rs API doesn't expose its `rp_id` directly, but if
        // we got this far the URL parsing + builder both worked.
        // Subsequent ceremony-level tests cover the actual binding.
        drop(w);
    }

    #[test]
    fn build_webauthn_rejects_invalid_url() {
        let err = build_webauthn("not-a-url").expect_err("invalid URL");
        assert!(
            matches!(err, AppError::Config(ref m) if m.contains("invalid public_url")),
            "got: {err}"
        );
    }

    #[test]
    fn build_webauthn_rejects_url_without_domain() {
        let err = build_webauthn("file:///tmp/foo").expect_err("no domain");
        assert!(
            matches!(err, AppError::Config(ref m) if m.contains("no domain")),
            "got: {err}"
        );
    }
}
