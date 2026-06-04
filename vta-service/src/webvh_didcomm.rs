//! DIDComm transport for webvh server operations.
//!
//! ## Why this is *not* a mirror of `webvh_client.rs`
//!
//! The REST sibling (`crate::webvh_client::WebvhClient`) carries:
//! - explicit signing identity for the daemon challenge/response flow,
//! - typed errors with operator-facing hints (401 vs 403 split),
//! - HTTPS enforcement on the dialed URL,
//! - audience binding via the DIDComm `to:` field.
//!
//! This module deliberately carries none of those. It's not an
//! oversight — DIDComm authcrypt already gives us the equivalents
//! at the envelope layer:
//!
//! - **Signing identity** — the `DIDCommBridge` packs every outbound
//!   message with the VTA's existing DIDComm sender key; the daemon
//!   verifies it via `unpack_signed` exactly the same way it verifies
//!   the JWS-over-REST envelope.
//! - **Audience binding** — DIDComm messages are addressed to a
//!   specific `to:` DID intrinsically; replay against a different
//!   daemon fails because the message is encrypted to *this* daemon's
//!   key-agreement key.
//! - **Typed errors** — DIDComm replies carry `e.p.msg.*`
//!   problem-report codes which the SDK maps to typed `VtaError`
//!   variants via `VtaError::from_problem_report`. The CLI surfaces
//!   them with the same hint discipline as the REST path.
//! - **Transport security** — DIDComm over the mediator is
//!   end-to-end encrypted regardless of the underlying socket; there
//!   is no plaintext-leak surface to defend at this layer.
//!
//! **Do not "add parity" by porting the JWS-flow primitives into
//! this module.** They would duplicate what authcrypt already
//! provides, and the duplicate would drift out of sync with the
//! envelope-layer guarantees.

use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::webvh_client::RequestUriResponse;

// did-management Trust-Task URIs (v0.1, hosted-DID category).
//
// Replaces the legacy `https://affinidi.com/webvh/1.0/did/...` constants
// this client used through v0.6. The remote `did-hosting-control`
// accepts both URI families through its alias map during the v0.7
// deprecation window — see `did-hosting-common::v1_aliases` in
// affinidi-webvh-service — and drops the legacy ones in v0.8.0. We move
// outbound traffic to the v0.1 URIs now so this client isn't the source
// of deprecation-warn log lines on every hosting host the VTA talks to.
//
// Spec drafts live in `dtgwg-trust-tasks-tf` under
// `specs/did-management/...`.
//
// Notable shape changes from the legacy surface:
// - `did/request/1.0` (slot reservation) is absorbed by
//   `did/check-name/0.1` with `reserve: true`. The two-step
//   reservation-then-publish flow still works; one round-trip fewer.
// - Paired confirm/offer types collapse to `<base>#response`.
// - Every slot-touching task accepts an optional `domain` field so
//   the VTA can direct provisioning at the right hosting domain when
//   the same control plane serves multiple tenants.
const TASK_DID_CHECK_NAME: &str = "https://trusttasks.org/spec/did-management/did/check-name/0.1";
const TASK_DID_CHECK_NAME_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/did/check-name/0.1#response";
const TASK_DID_PUBLISH: &str = "https://trusttasks.org/spec/did-management/did/publish/0.1";
const TASK_DID_PUBLISH_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/did/publish/0.1#response";
const TASK_DID_REGISTER: &str = "https://trusttasks.org/spec/did-management/did/register/0.1";
const TASK_DID_REGISTER_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/did/register/0.1#response";
const TASK_DID_DELETE: &str = "https://trusttasks.org/spec/did-management/did/delete/0.1";
const TASK_DID_DELETE_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/did/delete/0.1#response";
const TASK_DID_PROBLEM_REPORT: &str =
    "https://trusttasks.org/spec/did-management/did/problem-report/0.1";

/// Build the `did/check-name/0.1` reservation body.
///
/// `path == None` is the auto-assign case: the `path` field is OMITTED
/// entirely so the host runs its server-generated-mnemonic branch. A
/// present-but-empty path is rejected by the host with
/// `e.p.did.path-invalid` ("path must not be empty"), so an absent path
/// must never be coerced to `""` — that coercion was the regression this
/// pins. Mirrors the REST `request_uri`, which omits the field for `None`.
fn build_check_name_body(
    path: Option<&str>,
    domain: Option<&str>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut body = serde_json::Map::new();
    if let Some(p) = path {
        body.insert("path".to_string(), serde_json::Value::String(p.to_string()));
    }
    body.insert("reserve".to_string(), serde_json::Value::Bool(true));
    if let Some(d) = domain {
        body.insert(
            "domain".to_string(),
            serde_json::Value::String(d.to_string()),
        );
    }
    body
}

/// DIDComm-based client for communicating with a WebVH server.
///
/// Routes messages through the DIDComm service's listener connection,
/// avoiding duplicate WebSocket connections to the mediator.
pub struct WebvhDIDCommClient<'a> {
    bridge: &'a DIDCommBridge,
    server_did: &'a str,
}

impl<'a> WebvhDIDCommClient<'a> {
    pub fn new(bridge: &'a DIDCommBridge, server_did: &'a str) -> Self {
        Self { bridge, server_did }
    }

    /// Reserve a path on the remote DID-hosting server (v0.1
    /// `did-management/did/check-name/0.1` with `reserve: true`).
    ///
    /// Replaces the legacy `did/request/1.0` round-trip. The
    /// `check-name` task absorbs both modes: a pure availability
    /// probe (omit `reserve`), and the atomic check-and-reserve
    /// (`reserve: true`). This client uses the reserve mode so the
    /// behaviour matches the prior `request_uri` semantics.
    ///
    /// `domain` is the optional hosting domain to target. When the
    /// remote serves multiple tenant domains (the common case for a
    /// VTA-managed `did-hosting-control` backplane), the operator
    /// supplies the target; otherwise the remote falls back to the
    /// caller's ACL default → system default. An unknown domain is
    /// rejected with `did-management:unknown_domain`.
    pub async fn request_uri(
        &self,
        path: Option<&str>,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        let body = build_check_name_body(path, domain);

        let response = self
            .bridge
            .send_and_wait(
                self.server_did,
                TASK_DID_CHECK_NAME,
                serde_json::Value::Object(body),
                TASK_DID_CHECK_NAME_RESPONSE,
                TASK_DID_PROBLEM_REPORT,
                30,
            )
            .await?;

        // The v0.1 check-name response shape carries `available`,
        // `reserved`, and (when reserved) `mnemonic` + `didUrl`.
        // Translate into the local `RequestUriResponse` shape the
        // rest of vta-service expects.
        let body: serde_json::Value = response.body;
        let reserved = body
            .get("reserved")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !reserved {
            let available = body
                .get("available")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            return Err(AppError::Internal(format!(
                "remote refused reservation (available={available}); \
                 check-name with reserve=true expected to succeed"
            )));
        }
        let mnemonic = body
            .get("mnemonic")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AppError::Internal("check-name response missing `mnemonic`".to_string())
            })?
            .to_string();
        let did_url = body
            .get("didUrl")
            .or_else(|| body.get("did_url"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("check-name response missing `didUrl`".to_string()))?
            .to_string();
        Ok(RequestUriResponse { mnemonic, did_url })
    }

    /// Atomic claim-and-publish (v0.1 `did-management/did/register/0.1`).
    ///
    /// Replaces the legacy `did/register/1.0` URI. Wire shape stays
    /// the same — `path`, `didData`, `force` — plus the optional
    /// `domain` and `method` discriminator the v0.1 surface introduces.
    pub async fn register_did_atomic(
        &self,
        path: &str,
        did_log: &str,
        force: bool,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        let mut body = serde_json::Map::new();
        body.insert(
            "path".to_string(),
            serde_json::Value::String(path.to_string()),
        );
        body.insert(
            "method".to_string(),
            serde_json::Value::String("webvh".to_string()),
        );
        // v0.1 spec names this field `didData`; the legacy
        // did-hosting-control alias map normalises legacy `did_log`
        // → `didData` server-side, so passing the canonical name
        // works on both old and new hosts.
        body.insert(
            "didData".to_string(),
            serde_json::Value::String(did_log.to_string()),
        );
        body.insert("force".to_string(), serde_json::Value::Bool(force));
        if let Some(d) = domain {
            body.insert(
                "domain".to_string(),
                serde_json::Value::String(d.to_string()),
            );
        }

        let response = self
            .bridge
            .send_and_wait(
                self.server_did,
                TASK_DID_REGISTER,
                serde_json::Value::Object(body),
                TASK_DID_REGISTER_RESPONSE,
                TASK_DID_PROBLEM_REPORT,
                30,
            )
            .await?;

        // v0.1 response carries `{ record: DidRecord }`; we project
        // the mnemonic + didUrl out of it for the local response shape.
        let record = response
            .body
            .get("record")
            .cloned()
            .or_else(|| {
                // Legacy did-hosting-control responses (still emitted
                // by pre-v0.7 hosts) flatten the fields at the top
                // level. Fall back to that shape transparently.
                Some(response.body.clone())
            })
            .unwrap_or(serde_json::Value::Null);
        let mnemonic = record
            .get("mnemonic")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("register response missing `mnemonic`".to_string()))?
            .to_string();
        let did_url = record
            .get("didUrl")
            .or_else(|| record.get("did_url"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("register response missing `didUrl`".to_string()))?
            .to_string();
        Ok(RequestUriResponse { mnemonic, did_url })
    }

    /// Publish a DID log to the remote (v0.1
    /// `did-management/did/publish/0.1`). The `domain` argument is
    /// accepted for disambiguation when the remote runs per-domain
    /// mnemonic namespaces; consumers that haven't enabled per-domain
    /// namespacing treat it as a no-op on the lookup.
    pub async fn publish_did(
        &self,
        mnemonic: &str,
        log_content: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        let mut body = serde_json::Map::new();
        body.insert(
            "mnemonic".to_string(),
            serde_json::Value::String(mnemonic.to_string()),
        );
        body.insert(
            "method".to_string(),
            serde_json::Value::String("webvh".to_string()),
        );
        body.insert(
            "didData".to_string(),
            serde_json::Value::String(log_content.to_string()),
        );
        if let Some(d) = domain {
            body.insert(
                "domain".to_string(),
                serde_json::Value::String(d.to_string()),
            );
        }

        self.bridge
            .send_and_wait(
                self.server_did,
                TASK_DID_PUBLISH,
                serde_json::Value::Object(body),
                TASK_DID_PUBLISH_RESPONSE,
                TASK_DID_PROBLEM_REPORT,
                30,
            )
            .await?;
        Ok(())
    }

    /// Soft-delete a DID on the remote (v0.1
    /// `did-management/did/delete/0.1`).
    pub async fn delete_did(&self, mnemonic: &str, domain: Option<&str>) -> Result<(), AppError> {
        let mut body = serde_json::Map::new();
        body.insert(
            "mnemonic".to_string(),
            serde_json::Value::String(mnemonic.to_string()),
        );
        if let Some(d) = domain {
            body.insert(
                "domain".to_string(),
                serde_json::Value::String(d.to_string()),
            );
        }

        self.bridge
            .send_and_wait(
                self.server_did,
                TASK_DID_DELETE,
                serde_json::Value::Object(body),
                TASK_DID_DELETE_RESPONSE,
                TASK_DID_PROBLEM_REPORT,
                30,
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::build_check_name_body;
    use serde_json::json;

    /// Regression for `e.p.did.path-invalid`: auto-assign (`path == None`)
    /// must OMIT the `path` field, not send `""`. The host rejects a
    /// present-but-empty path; only an absent one triggers
    /// server-side mnemonic generation.
    #[test]
    fn auto_assign_omits_path() {
        let body = build_check_name_body(None, None);
        assert!(
            !body.contains_key("path"),
            "auto-assign must omit `path`; got {body:?}"
        );
        assert_eq!(body.get("reserve"), Some(&json!(true)));
    }

    /// An explicit label travels verbatim under `reserve: true`.
    #[test]
    fn explicit_path_is_sent() {
        let body = build_check_name_body(Some("alice"), None);
        assert_eq!(body.get("path"), Some(&json!("alice")));
        assert_eq!(body.get("reserve"), Some(&json!(true)));
    }

    /// `.well-known` (the root-DID marker) is sent as a normal path —
    /// the host's `create_did` treats it as the reserved root slot.
    #[test]
    fn well_known_is_sent_as_path() {
        let body = build_check_name_body(Some(".well-known"), None);
        assert_eq!(body.get("path"), Some(&json!(".well-known")));
    }

    /// The optional `domain` rides along only when present.
    #[test]
    fn domain_included_only_when_present() {
        let with = build_check_name_body(Some("alice"), Some("acme.example.com"));
        assert_eq!(with.get("domain"), Some(&json!("acme.example.com")));
        let without = build_check_name_body(Some("alice"), None);
        assert!(!without.contains_key("domain"));
    }
}
