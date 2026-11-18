//! Wallet sign-in started by a **trigger link** — the `auth/oob/*` key-grant
//! flow, as this VTC hosts it.
//!
//! The browser (the *starter*) holds a non-extractable Ed25519 key `K_b` and
//! opens a request; a wallet (the *approver*) claims it with a throwaway key
//! `K_a`, proves membership and the number on the screen, and returns a grant
//! signed by the member's DID that names `K_b`. Only the holder of `K_b` can
//! turn that grant into a session (`redeem`).
//!
//! The flow itself — the request store, compare-and-set, the two clocks, the
//! long poll, the HTTPS connection details and the check order of every step —
//! is the shared [`vti_oob_server`] crate, re-exported here under the names
//! the VTC has always used. What is the VTC's own:
//!
//! - **Which session.** [`SessionAudience`]: a member-portal session (the
//!   default) or an operator-console one, read from
//!   `ext["org.openvtc.session"]`.
//! - **Where the rows live.** The member session keyspace, swept with the
//!   sessions ([`sweep`]).
//! - **What a wallet needs to find.** The `SignInPortal` and `TrustTaskHTTPS`
//!   DID-document services this VTC must publish ([`check_sign_in_portal`],
//!   [`check_trust_task_https`]).
//!
//! The gates, the signer, the audit and the sessions `redeem` issues are the
//! VTC's [`vti_oob_server::OobHost`], in [`crate::trust_tasks::oob_tasks`].
//!
//! Design: `design-docs/vtc-qr-login-design.md` §7 and §12, with the trigger
//! link contract (`sign-in-trigger-link-contract.md`, C1–C5) and VTI spec
//! §7a (VTI-LNK-*).

use serde::{Deserialize, Serialize};
use vti_common::store::KeyspaceHandle;

use crate::error::AppError;

pub use vti_oob_server::types;
pub use vti_oob_server::{
    CLAIM_WINDOW_SECS, DECISION_WINDOW_SECS, DEFAULT_LINK_HOST, ENDED_RETENTION_SECS, HttpContext,
    MAX_LINK_BYTES_LEVEL_M, MAX_PENDING_PER_ADDRESS, MAX_POLLS_PER_ADDRESS, NOTIFIER, Notifier,
    OobState, PollGuard, PollRefused, RequesterDetails, SESSION_EXT, SIGN_IN_FLOW, TransitionError,
    browser_and_os, check_link_host, context_digest, did_key_multikey, encode_from, epoch_of,
    is_ed25519_did_key, new_match_number, new_request_id, origin_of, portal_origin, record_key,
    redeem_hold, rfc3339, same_digest, same_network, set_redeem_hold_for_tests, trigger_link,
};

// ── Which session a request asks for ────────────────────────────────────────

/// Which session `redeem` issues. `member` is the default: a request with no
/// [`SESSION_EXT`] member, and every request stored before the field existed,
/// is a member-portal sign-in exactly as before.
///
/// A VTC extension, not a `purpose`: `auth/oob/0.1`'s `Purpose` is a closed
/// enum (`login`), and both sessions are a login. Carried on `request` by the
/// starter, and repeated by the VTC in the signed step 1 and step 2 responses
/// so the wallet can show it and the grant's `contextDigest` covers it.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SessionAudience {
    /// A member-portal session (`VTC-member` audience, `member_sessions`).
    #[default]
    Member,
    /// An operator-console session (`VTC` audience, `sessions`), for a DID
    /// the ACL holds as an administrator.
    Admin,
}

impl SessionAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionAudience::Member => "member",
            SessionAudience::Admin => "admin",
        }
    }

    pub fn is_member(&self) -> bool {
        *self == SessionAudience::Member
    }

    /// Read the audience a `request` asks for from its `ext`. No `ext`, or
    /// no [`SESSION_EXT`] member in it, is `member`. A [`SESSION_EXT`] member
    /// that is present but does not name a known audience is refused rather
    /// than read as either: a page that asked for something this VTC does not
    /// serve should learn so, not get a session it did not ask for.
    pub fn from_ext(ext: Option<&serde_json::Value>) -> Result<Self, String> {
        let Some(ns) = ext.and_then(|e| e.get(SESSION_EXT)) else {
            return Ok(SessionAudience::Member);
        };
        match ns.get("audience").and_then(serde_json::Value::as_str) {
            Some("member") => Ok(SessionAudience::Member),
            Some("admin") => Ok(SessionAudience::Admin),
            Some(other) => Err(format!(
                "ext[\"{SESSION_EXT}\"].audience `{other}` is not served; use `member` or `admin`"
            )),
            None => Err(format!(
                "ext[\"{SESSION_EXT}\"] must be an object with an `audience` of `member` or `admin`"
            )),
        }
    }

    /// The `ext` the VTC puts on its responses for this audience. `None` for
    /// `member`, so a member sign-in's responses — and so their signatures
    /// and the `contextDigest` a wallet computes — are byte for byte what
    /// they were before the extension existed.
    pub fn to_ext(self) -> Option<serde_json::Value> {
        match self {
            SessionAudience::Member => None,
            SessionAudience::Admin => Some(serde_json::json!({
                SESSION_EXT: { "audience": self.as_str() }
            })),
        }
    }
}

impl vti_oob_server::Audience for SessionAudience {
    fn from_ext(ext: Option<&serde_json::Value>) -> Result<Self, String> {
        SessionAudience::from_ext(ext)
    }

    fn to_ext(self) -> Option<serde_json::Value> {
        SessionAudience::to_ext(self)
    }

    fn is_default(&self) -> bool {
        self.is_member()
    }
}

/// The decline reason `redeem` reports when the identity that approved an
/// operator-console sign-in is not an administrator.
pub const NOT_AN_ADMIN: &str = "notAnAdmin";

// ── The request record ──────────────────────────────────────────────────────

/// One request, as this VTC stores it (base design §7.2's stored fields).
pub type OobRequest = vti_oob_server::OobRequest<SessionAudience>;

pub async fn load(ks: &KeyspaceHandle, request_id: &str) -> Result<Option<OobRequest>, AppError> {
    vti_oob_server::load(ks, request_id).await
}

/// Compare-and-set on one request ([`vti_oob_server::transition`]).
pub async fn transition<T, E>(
    ks: &KeyspaceHandle,
    request_id: &str,
    f: impl FnOnce(&mut OobRequest) -> Result<T, E>,
) -> Result<(T, OobRequest), TransitionError<E>> {
    vti_oob_server::transition(ks, request_id, f).await
}

/// Drop ended requests past [`ENDED_RETENTION_SECS`], and end (and drop the
/// address of) requests whose clock has run out. Run beside
/// `cleanup_expired_sessions` on the member session keyspace.
pub async fn sweep(ks: &KeyspaceHandle) -> Result<usize, AppError> {
    vti_oob_server::sweep::<SessionAudience>(ks).await
}

// ── What a wallet needs to find in the VTC DID document ─────────────────────

/// The `SignInPortal` service endpoint for this VTC (contract C4): the member
/// portal under `public_url`.
pub fn sign_in_portal_endpoint(public_url: &str) -> String {
    format!("{}/members/", public_url.trim_end_matches('/'))
}

/// The `SignInPortal` DID-document service entry this VTC needs (contract C4,
/// VTI-LNK-102).
pub fn sign_in_portal_service(vtc_did: &str, public_url: &str) -> serde_json::Value {
    serde_json::json!({
        "id": format!("{vtc_did}#sign-in-portal"),
        "type": "SignInPortal",
        "serviceEndpoint": sign_in_portal_endpoint(public_url),
    })
}

/// Whether a resolved VTC DID document lists the `SignInPortal` service this
/// VTC's portal needs (contract C4, VTI-LNK-102). A wallet refuses a sign-in
/// link from a community whose document has none, and a browser plugin
/// refuses one clicked on any page whose origin differs from the endpoint's
/// (VTI-LNK-105), so a wrong endpoint breaks wallet sign-in as surely as a
/// missing one. `Err` says what to publish.
pub fn check_sign_in_portal(
    doc: &serde_json::Value,
    vtc_did: &str,
    public_url: &str,
) -> Result<(), String> {
    let want = sign_in_portal_endpoint(public_url);
    let services = doc
        .get("service")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let found: Vec<String> = services
        .iter()
        .filter(|s| match s.get("type") {
            Some(serde_json::Value::String(t)) => t == "SignInPortal",
            Some(serde_json::Value::Array(ts)) => ts.iter().any(|t| t == "SignInPortal"),
            _ => false,
        })
        .filter_map(|s| s.get("serviceEndpoint").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect();
    let fix = sign_in_portal_service(vtc_did, public_url);
    // A did:webs is changed only by the VTA that holds it, and nothing of it
    // is served here.
    let how = if vtc_did.starts_with("did:webs:") {
        "a `vta/webs/dids/update` at the VTA that holds it, stating the whole service set"
    } else {
        "a VTA-side `dids edit`, then `cnm did-log install` if this VTC serves its own \
         did.jsonl"
    };
    match found.first() {
        None => Err(format!(
            "no `SignInPortal` service; wallets will refuse sign-in links from this \
             community. Publish {fix} in the VTC DID document ({how})"
        )),
        Some(ep) if origin_of(ep) != origin_of(&want) => Err(format!(
            "`SignInPortal` points at {ep}, whose origin is not this portal's ({want}); \
             wallets will refuse sign-in from this portal. Publish {fix}"
        )),
        Some(_) => Ok(()),
    }
}

/// The trust-task HTTPS service type a wallet selects (contract C9,
/// VTI-LNK-053, matched on `type`).
pub const TRUST_TASK_HTTPS_TYPE: &str = "TrustTaskHTTPS";

/// The `TrustTaskHTTPS` endpoint: this VTC's **Trust-Task base**. HTTPS
/// binding 0.2 §6 makes the advertised `serviceEndpoint` the base and the
/// request URL `<base>/trust-tasks`, as every consumer in the workspace (and
/// the `vtc-host` template) composes it, so `{public_url}/v1` reaches the
/// `POST /v1/trust-tasks` door this service serves.
pub fn trust_task_https_endpoint(public_url: &str) -> String {
    format!("{}/v1", public_url.trim_end_matches('/'))
}

/// The `TrustTaskHTTPS` DID-document service entry this VTC needs.
pub fn trust_task_https_service(vtc_did: &str, public_url: &str) -> serde_json::Value {
    serde_json::json!({
        "id": format!("{vtc_did}#trust-tasks"),
        "type": TRUST_TASK_HTTPS_TYPE,
        "serviceEndpoint": trust_task_https_endpoint(public_url),
    })
}

/// Whether a resolved VTC DID document lists the `TrustTaskHTTPS` service a
/// wallet sends `auth/oob/*` to. `Err` says what to publish.
pub fn check_trust_task_https(
    doc: &serde_json::Value,
    vtc_did: &str,
    public_url: &str,
) -> Result<(), String> {
    let want = trust_task_https_endpoint(public_url);
    let found = doc
        .get("service")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|s| match s.get("type") {
            Some(serde_json::Value::String(t)) => t == TRUST_TASK_HTTPS_TYPE,
            Some(serde_json::Value::Array(ts)) => ts.iter().any(|t| t == TRUST_TASK_HTTPS_TYPE),
            _ => false,
        })
        .filter_map(|s| s.get("serviceEndpoint").and_then(serde_json::Value::as_str))
        .any(|ep| ep.trim_end_matches('/') == want);
    if found {
        Ok(())
    } else {
        Err(format!(
            "no `{TRUST_TASK_HTTPS_TYPE}` service at {want}; wallets cannot reach this \
             community for sign-in. Publish {}",
            trust_task_https_service(vtc_did, public_url)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_audience_is_read_from_ext_and_echoed_only_for_admin() {
        assert_eq!(SessionAudience::from_ext(None), Ok(SessionAudience::Member));
        let admin = serde_json::json!({ SESSION_EXT: { "audience": "admin" } });
        assert_eq!(
            SessionAudience::from_ext(Some(&admin)),
            Ok(SessionAudience::Admin)
        );
        assert_eq!(SessionAudience::Admin.to_ext(), Some(admin));
        assert_eq!(SessionAudience::Member.to_ext(), None);
        let other = serde_json::json!({ SESSION_EXT: { "audience": "root" } });
        assert!(SessionAudience::from_ext(Some(&other)).is_err());
        assert!(
            SessionAudience::from_ext(Some(&serde_json::json!({ SESSION_EXT: "admin" }))).is_err()
        );
    }

    #[test]
    fn sign_in_portal_check_needs_the_portal_origin() {
        let did = "did:webvh:x:vtc.example";
        let ok = serde_json::json!({ "service": [
            { "id": format!("{did}#vtc-rest"), "type": "VTCRest", "serviceEndpoint": "https://vtc.example/v1" },
            sign_in_portal_service(did, "https://vtc.example"),
        ]});
        assert!(check_sign_in_portal(&ok, did, "https://vtc.example").is_ok());
        let none = serde_json::json!({ "service": [] });
        assert!(check_sign_in_portal(&none, did, "https://vtc.example").is_err());
        let elsewhere = serde_json::json!({ "service": [
            { "id": "x", "type": "SignInPortal", "serviceEndpoint": "https://evil.example/members/" },
        ]});
        assert!(check_sign_in_portal(&elsewhere, did, "https://vtc.example").is_err());
    }

    #[test]
    fn trust_task_https_check_needs_the_trust_task_base() {
        let did = "did:webvh:x:vtc.example";
        let ok = serde_json::json!({ "service": [trust_task_https_service(did, "https://vtc.example")] });
        assert_eq!(
            ok["service"][0]["serviceEndpoint"],
            "https://vtc.example/v1"
        );
        assert!(check_trust_task_https(&ok, did, "https://vtc.example").is_ok());
        // The full request URL is not the base: a client appending
        // `/trust-tasks` to it would reach `/v1/trust-tasks/trust-tasks`.
        let full_url = serde_json::json!({ "service": [
            { "id": "x", "type": "TrustTaskHTTPS", "serviceEndpoint": "https://vtc.example/v1/trust-tasks" },
        ]});
        assert!(check_trust_task_https(&full_url, did, "https://vtc.example").is_err());
    }

    #[test]
    fn sign_in_portal_service_is_the_contract_shape() {
        let s = sign_in_portal_service("did:webvh:x:vtc.example", "https://vtc.example/");
        assert_eq!(s["id"], "did:webvh:x:vtc.example#sign-in-portal");
        assert_eq!(s["type"], "SignInPortal");
        assert_eq!(s["serviceEndpoint"], "https://vtc.example/members/");
    }
}
