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

/// What an authenticator shows a passkey as: its WebAuthn `user.name` and
/// `user.displayName`.
///
/// Only constructable through [`for_did`](Self::for_did),
/// [`from_label`](Self::from_label) and
/// [`for_did_or_label`](Self::for_did_or_label), each of which holds the name
/// to [`MAX_AUTHENTICATOR_NAME_BYTES`] without splitting a character — so a
/// registration started through [`start_passkey_registration`] cannot send an
/// authenticator a name it refuses.
///
/// Display only: the credential is bound to its subject by the service's own
/// record and the stable `user.id`, never by this name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorName(String);

impl AuthenticatorName {
    /// The name for a passkey whose subject is `did`.
    ///
    /// * A DID whose method puts its SCID first (`did:webvh`, and `did:tdw`,
    ///   webvh's earlier name) is shown by its host and path, the part a
    ///   person recognises, followed by the last characters of the SCID:
    ///   `dids.example.org:persona (wUF4kX)`. The SCID is ~46 characters
    ///   nobody can read, but without some of it two DIDs re-created at one
    ///   path would look identical in the picker. A host and path too long to
    ///   fit keep both ends, so the host stays visible.
    /// * Any other DID is kept whole when it fits, else shown by its two ends,
    ///   so the method stays visible (`did:peer:2.Ez6L…`).
    pub fn for_did(did: &str) -> Self {
        if let Some((scid, rest)) = scid_first_parts(did) {
            let suffix = format!(
                " ({})",
                &scid[scid.ceil_char_boundary(scid.len().saturating_sub(SCID_SUFFIX_BYTES))..]
            );
            let budget = MAX_AUTHENTICATOR_NAME_BYTES - suffix.len();
            // Keep the host (and its `:`) at the head when it fits in half the
            // budget; past that, half is all the head gets.
            let host_end = rest.find(':').map_or(rest.len(), |i| i + 1);
            let head = host_end.min((budget - ELLIPSIS.len()) / 2);
            return Self(format!("{}{suffix}", two_ends(rest, budget, head)));
        }
        Self(two_ends(did, MAX_AUTHENTICATOR_NAME_BYTES, DID_HEAD_BYTES))
    }

    /// The name for a passkey an operator or member labelled, held to the
    /// bound by keeping its tail behind a leading `…`: for a path-shaped label
    /// the distinguishing part is at the end. A label that fits is unchanged.
    pub fn from_label(label: &str) -> Self {
        if label.len() <= MAX_AUTHENTICATOR_NAME_BYTES {
            return Self(label.to_string());
        }
        let keep = MAX_AUTHENTICATOR_NAME_BYTES - ELLIPSIS.len();
        let start = label.ceil_char_boundary(label.len() - keep);
        Self(format!("{ELLIPSIS}{}", &label[start..]))
    }

    /// `label`, trimmed, when it is not blank; else the name for `did`.
    pub fn for_did_or_label(did: &str, label: Option<&str>) -> Self {
        match label.map(str::trim) {
            Some(l) if !l.is_empty() => Self::from_label(l),
            _ => Self::for_did(did),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AuthenticatorName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Start a passkey registration whose `user.name` and `user.displayName` are
/// `name`. Every registration in the VTA and the VTC starts here (the VTC's
/// wrapper adds its algorithm choices on top), so the
/// [`MAX_AUTHENTICATOR_NAME_BYTES`] bound holds in one place.
pub fn start_passkey_registration(
    webauthn: &Webauthn,
    user_unique_id: Uuid,
    name: &AuthenticatorName,
    exclude_credentials: Option<Vec<CredentialID>>,
) -> Result<(CreationChallengeResponse, PasskeyRegistration), WebauthnError> {
    webauthn.start_passkey_registration(
        user_unique_id,
        name.as_str(),
        name.as_str(),
        exclude_credentials,
    )
}

/// U+2026, three bytes in UTF-8.
const ELLIPSIS: &str = "\u{2026}";

/// How much of a non-SCID DID's start survives a cut: enough for the method
/// and the first characters of its identifier.
const DID_HEAD_BYTES: usize = 40;

/// How much of the SCID's end a `did:webvh` name keeps to tell two DIDs at one
/// path apart.
const SCID_SUFFIX_BYTES: usize = 6;

/// `(scid, host-and-path)` of a DID whose method puts its SCID first.
fn scid_first_parts(did: &str) -> Option<(&str, &str)> {
    let rest = did
        .strip_prefix("did:webvh:")
        .or_else(|| did.strip_prefix("did:tdw:"))?;
    let (scid, tail) = rest.split_once(':')?;
    (!scid.is_empty() && !tail.is_empty()).then_some((scid, tail))
}

/// `s` whole when it fits in `max` bytes, else its first `head` bytes and as
/// much of its end as fits, joined by `…`. Never splits a character.
fn two_ends(s: &str, max: usize, head: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let head_end = s.floor_char_boundary(head);
    let tail_bytes = max - head_end - ELLIPSIS.len();
    let tail_start = s.ceil_char_boundary(s.len() - tail_bytes);
    format!("{}{ELLIPSIS}{}", &s[..head_end], &s[tail_start..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DID a YubiKey 5 refused as `user.name` (95 bytes).
    const PORTAL_DID: &str = "did:webvh:QmSyntheticExampleScid000000000000000000000000:dids.example.org:example-member-000001";

    fn name(did: &str) -> String {
        AuthenticatorName::for_did(did).to_string()
    }

    /// Every name is in bounds and is a copy of its source's two ends: no
    /// character split, nothing invented.
    fn assert_two_ends_of(got: &str, source: &str) {
        assert!(
            got.len() <= MAX_AUTHENTICATOR_NAME_BYTES,
            "{} bytes: {got}",
            got.len()
        );
        match got.split_once(ELLIPSIS) {
            Some((head, tail)) => {
                assert!(source.starts_with(head), "{got} is not a head of {source}");
                assert!(source.ends_with(tail), "{got} is not a tail of {source}");
            }
            None => assert_eq!(got, source),
        }
    }

    #[test]
    fn a_webvh_did_is_named_by_its_host_path_and_scid_end() {
        assert!(PORTAL_DID.len() > MAX_AUTHENTICATOR_NAME_BYTES);
        assert_eq!(
            name(PORTAL_DID),
            "dids.example.org:example-member-000001 (000000)"
        );
    }

    /// Webvh's earlier method name puts its SCID in the same place.
    #[test]
    fn a_tdw_did_is_named_like_a_webvh_did() {
        assert_eq!(
            name("did:tdw:QmSRTjKQF54iQfv58QjbbcunzZ1GiDzvuFFPERVHwUF4kX:example.com:dids:x"),
            "example.com:dids:x (wUF4kX)"
        );
    }

    /// Two DIDs re-created at one path differ only in their SCID; the picker
    /// must still tell them apart.
    #[test]
    fn two_webvh_dids_at_one_path_get_different_names() {
        let a =
            name("did:webvh:QmSRTjKQF54iQfv58QjbbcunzZ1GiDzvuFFPERVHwUF4kX:example.com:persona");
        let b =
            name("did:webvh:QmZx9cLhKeVtF3t8bKQ1m2nY7pWq4rS5uV6wX8yZ9aB1cD:example.com:persona");
        assert_ne!(a, b);
    }

    #[test]
    fn a_webvh_did_with_a_long_path_keeps_its_host_and_the_end_of_its_path() {
        let rest = format!("example.com:{}:persona", "a".repeat(80));
        let got = name(&format!("did:webvh:QmScid:{rest}"));
        let (body, suffix) = got.rsplit_once(' ').unwrap();
        assert_eq!(suffix, "(QmScid)");
        assert!(body.starts_with("example.com:"), "{got}");
        assert!(body.ends_with(":persona"), "{got}");
        assert_two_ends_of(body, &rest);
        assert!(got.len() <= MAX_AUTHENTICATOR_NAME_BYTES, "{got}");
    }

    /// A host longer than half the budget gets half of it, not all.
    #[test]
    fn a_webvh_did_with_a_long_host_keeps_both_ends() {
        let rest = format!("{}.example.org:dids:persona", "h".repeat(60));
        let got = name(&format!("did:webvh:QmScid:{rest}"));
        let (body, _) = got.rsplit_once(' ').unwrap();
        assert!(body.starts_with("hhhh"), "{got}");
        assert!(body.ends_with(":dids:persona"), "{got}");
        assert_two_ends_of(body, &rest);
    }

    #[test]
    fn a_short_did_is_left_whole() {
        assert_eq!(name("did:key:z6Mkshort"), "did:key:z6Mkshort");
        let exact = format!("did:key:{}", "z".repeat(MAX_AUTHENTICATOR_NAME_BYTES - 8));
        assert_eq!(name(&exact), exact);
    }

    #[test]
    fn a_long_non_webvh_did_is_named_by_its_two_ends() {
        let long = format!("did:peer:2.{}", "V".repeat(900));
        let got = name(&long);
        assert_eq!(got.len(), MAX_AUTHENTICATOR_NAME_BYTES, "{got}");
        assert!(got.starts_with("did:peer:2."), "{got}");
        assert_two_ends_of(&got, &long);
    }

    #[test]
    fn the_limit_is_in_bytes_and_cuts_on_char_boundaries() {
        // 2 bytes per char: 64 chars is 128 bytes, over the limit.
        let wide = format!("did:example:{}", "\u{e9}".repeat(100));
        assert_two_ends_of(&name(&wide), &wide);
        // A 3-byte char straddling every cut point.
        let cjk = format!("did:example:{}", "\u{4e2d}".repeat(50));
        assert_two_ends_of(&name(&cjk), &cjk);
        let webvh = format!("did:webvh:QmScid:example.com:{}", "\u{4e2d}".repeat(50));
        assert!(name(&webvh).len() <= MAX_AUTHENTICATOR_NAME_BYTES);
    }

    #[test]
    fn an_over_long_label_keeps_its_tail_without_splitting_a_char() {
        let label = "\u{e9}".repeat(200);
        let got = AuthenticatorName::from_label(&label).to_string();
        assert!(got.len() <= MAX_AUTHENTICATOR_NAME_BYTES, "{got}");
        let tail = got.strip_prefix(ELLIPSIS).expect("starts with …");
        assert!(label.ends_with(tail), "{got}");
    }

    #[test]
    fn a_label_wins_unless_it_is_blank() {
        let did = "did:webvh:QmScid:example.com:dids:x";
        assert_eq!(
            AuthenticatorName::for_did_or_label(did, Some("  Ops laptop ")).as_str(),
            "Ops laptop"
        );
        assert_eq!(
            AuthenticatorName::for_did_or_label(did, Some("   ")).as_str(),
            "example.com:dids:x (QmScid)"
        );
        assert_eq!(
            AuthenticatorName::for_did_or_label(did, None).as_str(),
            "example.com:dids:x (QmScid)"
        );
    }

    #[test]
    fn registration_sends_the_name_for_both_fields() {
        let w = build_webauthn("https://vtc.example.com").expect("ok");
        let n = AuthenticatorName::for_did(PORTAL_DID);
        let (ccr, _) = start_passkey_registration(&w, Uuid::new_v4(), &n, None).expect("start");
        assert_eq!(ccr.public_key.user.name, n.as_str());
        assert_eq!(ccr.public_key.user.display_name, n.as_str());
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
