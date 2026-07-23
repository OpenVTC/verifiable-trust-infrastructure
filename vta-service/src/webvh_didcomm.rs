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

// Agent names. These had no DIDComm form until the hosting server gained
// them, so a DIDComm-transport VTA could not manage names at all — it either
// refused, or reached sideways to the server's REST control plane. Same
// `spec/did-management/...` family as the verbs above; the server answers
// them from the same `did_ops` functions its REST routes use, so the two
// transports return identical payloads.
const TASK_AGENT_NAME_SET: &str = "https://trusttasks.org/spec/did-management/agent-name/set/0.1";
const TASK_AGENT_NAME_SET_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/set/0.1#response";
const TASK_AGENT_NAME_REMOVE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/remove/0.1";
const TASK_AGENT_NAME_REMOVE_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/remove/0.1#response";
const TASK_AGENT_NAME_ENABLE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/enable/0.1";
const TASK_AGENT_NAME_ENABLE_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/enable/0.1#response";
const TASK_AGENT_NAME_DISABLE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/disable/0.1";
const TASK_AGENT_NAME_DISABLE_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/disable/0.1#response";
const TASK_AGENT_NAME_LIST: &str = "https://trusttasks.org/spec/did-management/agent-name/list/0.1";
const TASK_AGENT_NAME_LIST_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/list/0.1#response";
const TASK_AGENT_NAME_CHECK: &str =
    "https://trusttasks.org/spec/did-management/agent-name/check/0.1";
const TASK_AGENT_NAME_CHECK_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/check/0.1#response";

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

/// Project a `did/check-name/0.1#response` payload into the local
/// [`RequestUriResponse`].
///
/// The v0.1 response carries top-level `available` + `reserved`, and —
/// when reserved — a `record: DidRecord` whose `mnemonic` + `didUrl` we
/// project out. Legacy did-hosting-control hosts (pre-v0.7) flatten the
/// fields at the top level and omit `reserved`; we fall back to the flat
/// body and to the snake_case `did_url` alias so both wire dialects work,
/// mirroring `register_did_atomic`'s parser.
fn parse_check_name_response(body: serde_json::Value) -> Result<RequestUriResponse, AppError> {
    let reserved = body
        .get("reserved")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !reserved {
        let available = body
            .get("available")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        // `available == false` ⇒ the path is already taken: a clean,
        // client-facing conflict (409), not a server fault. (Before the
        // path-resolution fix, a deterministic URL-derived name collided
        // here on every re-run and surfaced — wrongly — as a 500.)
        // `available == true` but un-reserved is a genuine remote anomaly —
        // we asked for `reserve=true`, the slot was free, yet nothing was
        // granted — so that stays a 500.
        if !available {
            return Err(AppError::Conflict(
                "webvh path already taken on the hosting server — choose a different \
                 WEBVH_PATH, or omit it for a server-assigned path"
                    .to_string(),
            ));
        }
        return Err(AppError::Internal(format!(
            "remote refused reservation despite the path being available \
             (available={available}); check-name with reserve=true expected to succeed"
        )));
    }
    // Prefer the spec `record`; fall back to the flat legacy body.
    let record = body.get("record").cloned().unwrap_or_else(|| body.clone());
    let mnemonic = record
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal("check-name response missing `mnemonic`".to_string()))?
        .to_string();
    let did_url = record
        .get("didUrl")
        .or_else(|| record.get("did_url"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal("check-name response missing `didUrl`".to_string()))?
        .to_string();
    Ok(RequestUriResponse { mnemonic, did_url })
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

        parse_check_name_response(response.body)
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

    // ── Agent names ────────────────────────────────────────────────────
    //
    // The four mutating verbs share a body and a `{record}` response, so they
    // share one submit. `didLog` carries the newly signed document: the server
    // requires `set`/`enable` to claim the name in `alsoKnownAs` and
    // `remove`/`disable` not to, which is what makes the registry and the
    // document agree.

    async fn agent_name_verb(
        &self,
        task: &str,
        response_task: &str,
        mnemonic: &str,
        name: &str,
        did_log: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        let mut body = serde_json::Map::new();
        body.insert("mnemonic".to_string(), serde_json::json!(mnemonic));
        body.insert("name".to_string(), serde_json::json!(name));
        body.insert("didLog".to_string(), serde_json::json!(did_log));
        if let Some(d) = domain {
            body.insert("domain".to_string(), serde_json::json!(d));
        }
        self.bridge
            .send_and_wait(
                self.server_did,
                task,
                serde_json::Value::Object(body),
                response_task,
                TASK_DID_PROBLEM_REPORT,
                30,
            )
            .await?;
        Ok(())
    }

    /// Bind or refresh `name` on `mnemonic`.
    pub async fn set_agent_name(
        &self,
        mnemonic: &str,
        name: &str,
        did_log: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        self.agent_name_verb(
            TASK_AGENT_NAME_SET,
            TASK_AGENT_NAME_SET_RESPONSE,
            mnemonic,
            name,
            did_log,
            domain,
        )
        .await
    }

    /// Release `name` — it stops resolving and anyone may reclaim it.
    pub async fn remove_agent_name(
        &self,
        mnemonic: &str,
        name: &str,
        did_log: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        self.agent_name_verb(
            TASK_AGENT_NAME_REMOVE,
            TASK_AGENT_NAME_REMOVE_RESPONSE,
            mnemonic,
            name,
            did_log,
            domain,
        )
        .await
    }

    /// Resume serving a parked `name`.
    pub async fn enable_agent_name(
        &self,
        mnemonic: &str,
        name: &str,
        did_log: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        self.agent_name_verb(
            TASK_AGENT_NAME_ENABLE,
            TASK_AGENT_NAME_ENABLE_RESPONSE,
            mnemonic,
            name,
            did_log,
            domain,
        )
        .await
    }

    /// Park `name` — it stops resolving but stays reserved to this DID.
    pub async fn disable_agent_name(
        &self,
        mnemonic: &str,
        name: &str,
        did_log: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        self.agent_name_verb(
            TASK_AGENT_NAME_DISABLE,
            TASK_AGENT_NAME_DISABLE_RESPONSE,
            mnemonic,
            name,
            did_log,
            domain,
        )
        .await
    }

    /// Read the DID's agent-name registry, parked names included.
    ///
    /// The registry — not the DID document — is the only place a parked name
    /// is visible, since dropping the `alsoKnownAs` claim is *how* parking
    /// stops it resolving. `agentNames` is always present, so an absent field
    /// is a contract violation rather than an empty registry.
    pub async fn list_agent_names(
        &self,
        mnemonic: &str,
        domain: Option<&str>,
    ) -> Result<Vec<crate::webvh_client::AgentNameEntryWire>, AppError> {
        let mut body = serde_json::Map::new();
        body.insert("mnemonic".to_string(), serde_json::json!(mnemonic));
        if let Some(d) = domain {
            body.insert("domain".to_string(), serde_json::json!(d));
        }
        let resp = self
            .bridge
            .send_and_wait(
                self.server_did,
                TASK_AGENT_NAME_LIST,
                serde_json::Value::Object(body),
                TASK_AGENT_NAME_LIST_RESPONSE,
                TASK_DID_PROBLEM_REPORT,
                30,
            )
            .await?;
        let names = resp.body.get("agentNames").ok_or_else(|| {
            AppError::Internal("agent-name list response has no 'agentNames'".to_string())
        })?;
        serde_json::from_value(names.clone())
            .map_err(|e| AppError::Internal(format!("agent-name list response parse error: {e}")))
    }

    /// Is `name` free to claim on this domain?
    ///
    /// A reserved name answers `available: false, reserved: true` rather than
    /// erroring, so the caller can tell "taken" from "never allowed".
    pub async fn check_agent_name(
        &self,
        name: &str,
        domain: Option<&str>,
    ) -> Result<crate::webvh_client::AgentNameAvailabilityWire, AppError> {
        let mut body = serde_json::Map::new();
        body.insert("name".to_string(), serde_json::json!(name));
        if let Some(d) = domain {
            body.insert("domain".to_string(), serde_json::json!(d));
        }
        let resp = self
            .bridge
            .send_and_wait(
                self.server_did,
                TASK_AGENT_NAME_CHECK,
                serde_json::Value::Object(body),
                TASK_AGENT_NAME_CHECK_RESPONSE,
                TASK_DID_PROBLEM_REPORT,
                30,
            )
            .await?;
        serde_json::from_value(resp.body)
            .map_err(|e| AppError::Internal(format!("agent-name check response parse error: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::{build_check_name_body, parse_check_name_response};
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
        assert_eq!(body.get("reserve"), Some(&serde_json::json!(true)));
    }

    /// An explicit label travels verbatim under `reserve: true`.
    #[test]
    fn explicit_path_is_sent() {
        let body = build_check_name_body(Some("alice"), None);
        assert_eq!(body.get("path"), Some(&serde_json::json!("alice")));
        assert_eq!(body.get("reserve"), Some(&serde_json::json!(true)));
    }

    /// `.well-known` (the root-DID marker) is sent as a normal path —
    /// the host's `create_did` treats it as the reserved root slot.
    #[test]
    fn well_known_is_sent_as_path() {
        let body = build_check_name_body(Some(".well-known"), None);
        assert_eq!(body.get("path"), Some(&serde_json::json!(".well-known")));
    }

    /// The optional `domain` rides along only when present.
    #[test]
    fn domain_included_only_when_present() {
        let with = build_check_name_body(Some("alice"), Some("acme.example.com"));
        assert_eq!(
            with.get("domain"),
            Some(&serde_json::json!("acme.example.com"))
        );
        let without = build_check_name_body(Some("alice"), None);
        assert!(!without.contains_key("domain"));
    }

    /// The v0.1 (and current host) response nests the assigned mnemonic +
    /// didUrl inside `record`. This is the shape that the auto-assign fix
    /// makes the host emit; the parser must read through `record`.
    #[test]
    fn parses_spec_record_shaped_response() {
        let body = serde_json::json!({
            "available": true,
            "reserved": true,
            "record": {
                "mnemonic": "brave-otter",
                "owner": "did:key:z6MkAlice",
                "createdAt": "2026-06-04T10:00:01Z",
                "updatedAt": "2026-06-04T10:00:01Z",
                "versionCount": 0,
                "domain": "did.example.com",
                "didUrl": "https://did.example.com/brave-otter/did.jsonl",
                "disabled": false
            }
        });
        let resp = parse_check_name_response(body).expect("spec record parses");
        assert_eq!(resp.mnemonic, "brave-otter");
        assert_eq!(
            resp.did_url,
            "https://did.example.com/brave-otter/did.jsonl"
        );
    }

    /// Legacy did-hosting-control hosts (pre-v0.7) flatten the fields at
    /// the top level and use the snake_case `did_url` alias. The parser
    /// must still accept them so a VTA can talk to an un-upgraded host.
    #[test]
    fn parses_legacy_flat_response() {
        let body = serde_json::json!({
            "available": true,
            "reserved": true,
            "mnemonic": "alice",
            "did_url": "https://did.example.com/alice/did.jsonl"
        });
        let resp = parse_check_name_response(body).expect("legacy flat parses");
        assert_eq!(resp.mnemonic, "alice");
        assert_eq!(resp.did_url, "https://did.example.com/alice/did.jsonl");
    }

    /// `reserved: false` + `available: false` means the path is already
    /// taken — a clean client-facing conflict (409), not a server fault.
    /// (This is the case that, with a deterministic URL-derived name, used
    /// to surface — wrongly — as a 500 on every re-run.)
    #[test]
    fn not_reserved_and_unavailable_is_a_conflict() {
        let body = serde_json::json!({ "available": false, "reserved": false });
        let err = parse_check_name_response(body).expect_err("must error");
        assert!(
            matches!(err, crate::error::AppError::Conflict(_)),
            "taken path must be a 409 conflict, got: {err:?}"
        );
        assert!(
            err.to_string().contains("taken"),
            "conflict should explain the path is taken: {err}"
        );
    }

    /// `reserved: false` but `available: true` is a genuine remote anomaly
    /// — we asked for `reserve=true`, the slot was free, yet nothing was
    /// granted. That stays a 500 so it isn't mistaken for a normal
    /// already-taken conflict.
    #[test]
    fn not_reserved_but_available_is_an_internal_anomaly() {
        let body = serde_json::json!({ "available": true, "reserved": false });
        let err = parse_check_name_response(body).expect_err("must error");
        assert!(
            matches!(err, crate::error::AppError::Internal(_)),
            "free-but-ungranted slot must be a 500 anomaly, got: {err:?}"
        );
        assert!(
            err.to_string().contains("available=true"),
            "anomaly should surface availability: {err}"
        );
    }

    /// A reserved response that omits the locator is malformed — fail
    /// loudly rather than returning an empty `did_url` downstream.
    #[test]
    fn reserved_without_did_url_errors() {
        let body = serde_json::json!({
            "reserved": true,
            "record": { "mnemonic": "alice" }
        });
        let err = parse_check_name_response(body).expect_err("must error");
        assert!(err.to_string().contains("didUrl"), "got: {err}");
    }
}
