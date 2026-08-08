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
use crate::error::{AppError, bad_gateway_error};
use crate::webvh_client::RequestUriResponse;
// The one DIDComm message type this module names, taken from the binding crate
// rather than copied (#900). Every task URI below travels *inside* the envelope.
use trust_tasks_didcomm::ENVELOPE_TYPE as TRUST_TASK_ENVELOPE_TYPE;

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
// `did/publish/0.1` is NOT sent. did-hosting 0.8.3 retired it — spec
// `supersededBy: did/register` — so the host's DIDComm router has no arm for
// it and its fallback drops the message without replying, which cost every
// server-managed publish a 30s `send_and_wait` timeout surfaced as a 500
// (affinidi-webvh-service#144). `publish_did` below sends `did/register/0.1`
// instead: on the host, an owner re-registering their own slot IS a publish —
// same content replace, version bump, `created_at` preservation and
// agent-name reconcile, in one batch.
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
// One declarative `update` carrying `state: active | parked` replaced the
// `set` / `enable` / `disable` trio in did-hosting 0.8.3, alongside the
// `did/publish` retirement above and for the same reason — those three URIs
// now hit the host's silent fallback. `remove` stays a separate destructive
// task. The VTA's own *inbound* four-verb surface is unchanged; the collapse
// is a property of the host wire only (see `AgentNameVerb::host_endpoint`).
const TASK_AGENT_NAME_UPDATE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/update/0.1";
const TASK_AGENT_NAME_UPDATE_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/update/0.1#response";
const TASK_AGENT_NAME_REMOVE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/remove/0.1";
const TASK_AGENT_NAME_REMOVE_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/remove/0.1#response";
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

/// Build the `did/register/0.1` body.
///
/// Serves both callers of the register task: the atomic claim-and-publish and
/// — since did-hosting retired `did/publish/0.1` in favour of it — the plain
/// "publish the log for a slot I own" path, where `path` is the reserved
/// slot's mnemonic and `force` is false.
///
/// Extracted so the body is assertable without a live bridge; the publish
/// regression this pins was a silent 30s timeout, which no unit test built on
/// `send_and_wait` would have caught.
fn build_register_body(
    path: &str,
    did_log: &str,
    force: bool,
    domain: Option<&str>,
) -> serde_json::Map<String, serde_json::Value> {
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

/// The `trust-task-error/0.x` family the framework emits for transport-level
/// refusals (malformed body, proof required, wrong recipient). Matched by prefix
/// because the version floats — did-hosting emits `0.1` for a body-parse failure
/// and `0.2` from the typed §7.2 pipeline, in the same conversation.
const TRUST_TASK_ERROR_PREFIX: &str = "https://trusttasks.org/spec/trust-task-error/";

/// Build the complete outbound pair: the DIDComm **message type** and the
/// `TrustTask` document that rides in its body.
///
/// The message type is returned from here rather than written at the send site
/// on purpose. It is the value this entire change exists to get right, and a
/// wrong one fails *silently* — so it must come from somewhere a test can look
/// at. `send_task` destructures this and passes both through verbatim; putting
/// the literal back at the send site means bypassing this function, which is a
/// visible edit rather than a one-word slip.
fn build_outbound(
    task: &str,
    recipient: &str,
    issuer: Option<String>,
    payload: serde_json::Value,
) -> (&'static str, serde_json::Value) {
    (
        TRUST_TASK_ENVELOPE_TYPE,
        build_envelope_document(task, recipient, issuer, payload),
    )
}

/// Build the `TrustTask` document that rides inside the envelope.
///
/// Extracted so the outbound shape is assertable without a live bridge — the
/// same reason `build_register_body` exists, and for the same class of bug: the
/// failure this whole change addresses is a *silent* one, so nothing downstream
/// would have caught a malformed document either.
fn build_envelope_document(
    task: &str,
    recipient: &str,
    issuer: Option<String>,
    payload: serde_json::Value,
) -> serde_json::Value {
    let mut doc = serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        // The task type lives HERE, on the document — never on the DIDComm
        // message, which is always the envelope type.
        "type": task,
        // Addressed to the host, per SPEC §4.8. did-hosting does not enforce
        // `recipient` on the DID-management bridge (it authorizes the authcrypt
        // sender), but an unaddressed document is one a stricter peer is
        // entitled to refuse.
        "recipient": recipient,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    });
    // `issuer` only when we actually know it. SPEC §4.8.1 requires an in-band
    // issuer to match the transport-authenticated sender, so a guess would be
    // worse than the omission the spec permits.
    if let Some(vta_did) = issuer {
        doc["issuer"] = serde_json::Value::String(vta_did);
    }
    doc
}

/// Unwrap a reply document from a trust-task envelope into its `payload`.
///
/// On the envelope binding every reply arrives with the *same* DIDComm `type`
/// (`ENVELOPE_TYPE`), so `send_and_wait`'s type check can no longer tell success
/// from rejection — that decision moves in here, onto the document's own `type`.
/// Three outcomes, and the caller must not be able to confuse them:
///
/// - the expected `<task>#response` → its `payload`,
/// - `did/problem-report/0.1` → the typed [`AppError`] the REST path produces,
///   via the *same* mapping table `didcomm_bridge` uses for the bare framing,
/// - `trust-task-error/0.x` → a 502; the framework refused the envelope itself
///   rather than the task, so it is not an outcome the caller can act on.
///
/// Anything else is a 502 naming both types, because a reply that threads to our
/// request but answers a different task is a contract break, not a task failure.
fn unwrap_envelope_reply(
    doc: serde_json::Value,
    expected: &str,
) -> Result<serde_json::Value, AppError> {
    let doc_type = doc.get("type").and_then(|v| v.as_str()).unwrap_or_default();

    if doc_type == TASK_DID_PROBLEM_REPORT {
        let payload = doc.get("payload").unwrap_or(&serde_json::Value::Null);
        let code = payload
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("e.p.did.unknown");
        let comment = payload
            .get("comment")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        return Err(crate::didcomm_bridge::problem_report_to_app_error(
            code, comment,
        ));
    }

    if doc_type.starts_with(TRUST_TASK_ERROR_PREFIX) {
        let payload = doc.get("payload").unwrap_or(&serde_json::Value::Null);
        let code = payload
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let message = payload
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        return Err(bad_gateway_error(format!(
            "hosting peer refused the trust-task envelope: {message} [{code}]"
        )));
    }

    if doc_type != expected {
        return Err(bad_gateway_error(format!(
            "unexpected response document type: expected {expected}, got {doc_type}"
        )));
    }

    Ok(doc
        .get("payload")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

impl<'a> WebvhDIDCommClient<'a> {
    pub fn new(bridge: &'a DIDCommBridge, server_did: &'a str) -> Self {
        Self { bridge, server_did }
    }

    /// Send one DID-management task over the **DIDComm envelope binding** and
    /// return the response document's `payload`.
    ///
    /// The single place this client names a DIDComm message type, and it names
    /// `ENVELOPE_TYPE` both ways. Every verb below passes only its task URI, so
    /// no call site can put a task type on the wire — which is the mistake this
    /// whole change exists to make unrepresentable (#900, #903).
    ///
    /// The task type moves *into* the document, where the binding requires it.
    /// did-hosting reads it back out via `bridge_did_management` and dispatches
    /// through the same `dispatch_did_op` table the bare `MSG_*` framing hits, so
    /// the operation, its authorization and its responses are unchanged — only
    /// the framing differs.
    async fn send_task(
        &self,
        task: &str,
        response_task: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        // Both halves come from `build_outbound` — see its note on why the
        // message type is not written here.
        let (message_type, doc) =
            build_outbound(task, self.server_did, self.bridge.vta_did(), payload);

        let reply = self
            .bridge
            .send_and_wait(
                self.server_did,
                message_type,
                doc,
                // Expected *outer* type: the binding replies in the same
                // envelope, so the reply's type is the one we sent. The real
                // discrimination happens on the inner document, in
                // `unwrap_envelope_reply`.
                message_type,
                // A DIDComm-level problem report is still possible ahead of the
                // envelope (an unroutable message never reaches the dispatcher),
                // so keep mapping it; task-level rejections now arrive *inside*
                // the envelope instead.
                TASK_DID_PROBLEM_REPORT,
                30,
            )
            .await?;

        unwrap_envelope_reply(reply.body, response_task)
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

        let payload = self
            .send_task(
                TASK_DID_CHECK_NAME,
                TASK_DID_CHECK_NAME_RESPONSE,
                serde_json::Value::Object(body),
            )
            .await?;

        parse_check_name_response(payload)
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
        let payload = self
            .send_task(
                TASK_DID_REGISTER,
                TASK_DID_REGISTER_RESPONSE,
                serde_json::Value::Object(build_register_body(path, did_log, force, domain)),
            )
            .await?;

        // v0.1 response carries `{ record: DidRecord }`; we project
        // the mnemonic + didUrl out of it for the local response shape.
        let record = payload
            .get("record")
            .cloned()
            .or_else(|| {
                // Legacy did-hosting-control responses (still emitted
                // by pre-v0.7 hosts) flatten the fields at the top
                // level. Fall back to that shape transparently.
                Some(payload.clone())
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

    /// Publish a DID log to the remote as an owner re-register (v0.1
    /// `did-management/did/register/0.1`).
    ///
    /// Carries the slot's `mnemonic` as the register `path` — the host keys
    /// the slot on that path either way, and re-registering a slot you already
    /// own is idempotent: content is replaced in-batch (never a half-updated
    /// slot from a resolver's view), `version_count` bumps, `created_at` is
    /// preserved, and the agent-name registry is reconciled against the new
    /// document. That is the retired publish verb's behaviour exactly, which is
    /// why the spec supersedes one with the other.
    ///
    /// `force` is always false: this call means "publish the log for a slot I
    /// own", and forcing is how you'd take a slot from *another* owner. A
    /// genuine ownership conflict must surface as a conflict, not be papered
    /// over by a publish.
    ///
    /// The `domain` argument is accepted for disambiguation when the remote
    /// runs per-domain mnemonic namespaces; consumers that haven't enabled
    /// per-domain namespacing treat it as a no-op on the lookup.
    pub async fn publish_did(
        &self,
        mnemonic: &str,
        log_content: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        self.register_did_atomic(mnemonic, log_content, false, domain)
            .await
            .map(|_| ())
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

        self.send_task(
            TASK_DID_DELETE,
            TASK_DID_DELETE_RESPONSE,
            serde_json::Value::Object(body),
        )
        .await?;
        Ok(())
    }

    // ── Agent names ────────────────────────────────────────────────────
    //
    // Both mutating tasks share a body and a `{record}` response, so they
    // share one submit. `didLog` carries the newly signed document: the server
    // requires `state: active` to claim the name in `alsoKnownAs` and
    // `remove`/`state: parked` not to, which is what makes the registry and
    // the document agree.
    //
    // `didLog` — not the spec's `didData` — is deliberate: it is the canonical
    // field name on `remove` and an accepted alias on `update`, so one
    // spelling satisfies both tasks.

    async fn agent_name_verb(
        &self,
        task: &str,
        response_task: &str,
        mnemonic: &str,
        name: &str,
        state: Option<&str>,
        did_log: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        let mut body = serde_json::Map::new();
        body.insert("mnemonic".to_string(), serde_json::json!(mnemonic));
        body.insert("name".to_string(), serde_json::json!(name));
        body.insert("didLog".to_string(), serde_json::json!(did_log));
        if let Some(s) = state {
            body.insert("state".to_string(), serde_json::json!(s));
        }
        if let Some(d) = domain {
            body.insert("domain".to_string(), serde_json::json!(d));
        }
        self.send_task(task, response_task, serde_json::Value::Object(body))
            .await?;
        Ok(())
    }

    /// Set `name`'s binding state on `mnemonic` — `active` to bind, refresh,
    /// or resume it; `parked` to stop it resolving while keeping it reserved
    /// to this DID.
    ///
    /// One call for what used to be `set`, `enable`, and `disable`: the host
    /// takes the desired end state and the document that must agree with it,
    /// so "bind" and "resume" are the same request and idempotent by
    /// construction.
    pub async fn update_agent_name(
        &self,
        mnemonic: &str,
        name: &str,
        state: &str,
        did_log: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        self.agent_name_verb(
            TASK_AGENT_NAME_UPDATE,
            TASK_AGENT_NAME_UPDATE_RESPONSE,
            mnemonic,
            name,
            Some(state),
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
            None,
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
        let payload = self
            .send_task(
                TASK_AGENT_NAME_LIST,
                TASK_AGENT_NAME_LIST_RESPONSE,
                serde_json::Value::Object(body),
            )
            .await?;
        // A host predating the registry omits the field entirely. That is an
        // empty list, not a parse error — otherwise every read against an
        // older host fails. The REST path has always been tolerant here
        // (`webvh_client::list_agent_names`); erroring on one transport and
        // succeeding on the other made the same DID appear to have names or
        // not depending on how the VTA happened to reach its host.
        let Some(names) = payload.get("agentNames") else {
            return Ok(Vec::new());
        };
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
        let payload = self
            .send_task(
                TASK_AGENT_NAME_CHECK,
                TASK_AGENT_NAME_CHECK_RESPONSE,
                serde_json::Value::Object(body),
            )
            .await?;
        serde_json::from_value(payload)
            .map_err(|e| AppError::Internal(format!("agent-name check response parse error: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        TASK_AGENT_NAME_LIST, TASK_AGENT_NAME_REMOVE, TASK_AGENT_NAME_UPDATE, TASK_DID_CHECK_NAME,
        TASK_DID_DELETE, TASK_DID_REGISTER, build_check_name_body, build_register_body,
        parse_check_name_response,
    };

    /// None of the tasks this client sends may be one did-hosting retired in
    /// 0.8.3 (`did/publish`, `agent-name/{set,enable,disable}`). Those URIs
    /// have no route on the host, and its DIDComm fallback drops an unrouted
    /// type **without replying** — so the failure mode is a 30s `send_and_wait`
    /// timeout surfaced as a 500, not an error naming the task. That is what
    /// broke every server-managed publish, and what made it hard to see.
    ///
    /// Asserted over the constants rather than per-call-site: adding a retired
    /// URI back is the regression, and it can only enter through one of these.
    #[test]
    fn no_task_constant_names_a_retired_verb() {
        const RETIRED: &[&str] = &[
            "did/publish/",
            "agent-name/set/",
            "agent-name/enable/",
            "agent-name/disable/",
        ];
        for task in [
            TASK_DID_CHECK_NAME,
            TASK_DID_REGISTER,
            TASK_DID_DELETE,
            TASK_AGENT_NAME_UPDATE,
            TASK_AGENT_NAME_REMOVE,
            TASK_AGENT_NAME_LIST,
        ] {
            for retired in RETIRED {
                assert!(
                    !task.contains(retired),
                    "{task} names `{retired}`, retired by did-hosting 0.8.3 — \
                     the host will drop it silently and the caller will hang 30s"
                );
            }
        }
    }

    /// A publish is a register of the slot we already own: the mnemonic
    /// travels as `path`, the log as `didData`, and `force` is false.
    ///
    /// `force: false` is the load-bearing part. Forcing is how a *different*
    /// owner takes a slot, so a forced publish would convert a genuine
    /// ownership conflict into a silent takeover — the opposite of what a
    /// publish means.
    #[test]
    fn publish_registers_the_owned_slot_without_forcing() {
        let body = build_register_body("brave-otter", "<jsonl>", false, None);
        assert_eq!(body.get("path"), Some(&serde_json::json!("brave-otter")));
        assert_eq!(body.get("didData"), Some(&serde_json::json!("<jsonl>")));
        assert_eq!(body.get("force"), Some(&serde_json::json!(false)));
        assert_eq!(body.get("method"), Some(&serde_json::json!("webvh")));
        assert!(!body.contains_key("domain"));
        // The retired verb's field name must not leak into the register body:
        // the host keys the slot on `path`, and a `mnemonic` key would be
        // silently ignored, publishing nothing while appearing to succeed.
        assert!(!body.contains_key("mnemonic"));
    }

    /// `domain` rides along on register exactly as it does on check-name.
    #[test]
    fn register_body_includes_domain_when_present() {
        let body = build_register_body("brave-otter", "<jsonl>", true, Some("acme.example.com"));
        assert_eq!(
            body.get("domain"),
            Some(&serde_json::json!("acme.example.com"))
        );
        assert_eq!(body.get("force"), Some(&serde_json::json!(true)));
    }

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

#[cfg(test)]
mod envelope_binding_tests {
    use super::{
        TASK_DID_CHECK_NAME, TASK_DID_CHECK_NAME_RESPONSE, TASK_DID_PROBLEM_REPORT, build_outbound,
        unwrap_envelope_reply,
    };
    use crate::error::AppError;
    use serde_json::json;

    const SERVER: &str = "did:webvh:example.com:control";
    const VTA: &str = "did:webvh:example.com:vta";

    /// The whole point, in one assertion pair: the **envelope** type goes on the
    /// DIDComm message, the **task** type goes in the document.
    ///
    /// Both halves come from `build_outbound`, which is what makes this
    /// meaningful rather than circular — `send_task` destructures that function's
    /// return and passes both through, so putting a task type back on the wire
    /// means bypassing it, not editing one argument.
    #[test]
    fn the_envelope_is_on_the_message_and_the_task_is_in_the_document() {
        let (message_type, doc) = build_outbound(
            TASK_DID_CHECK_NAME,
            SERVER,
            Some(VTA.to_string()),
            json!({ "path": "bob", "reserve": true }),
        );

        assert_eq!(
            message_type,
            trust_tasks_didcomm::ENVELOPE_TYPE,
            "the DIDComm message must carry the binding's envelope type — a task \
             type here is rejected silently by a conformant host"
        );
        assert_ne!(
            message_type, TASK_DID_CHECK_NAME,
            "the task type must never be the message type"
        );
        assert_eq!(doc["type"], TASK_DID_CHECK_NAME);
        assert_eq!(doc["recipient"], SERVER);
        assert_eq!(doc["issuer"], VTA);
        // The body the host dispatches on must survive the wrap untouched — the
        // envelope adds framing, it does not reshape the request.
        assert_eq!(doc["payload"]["path"], "bob");
        assert_eq!(doc["payload"]["reserve"], true);
        assert!(
            doc["id"]
                .as_str()
                .unwrap_or_default()
                .starts_with("urn:uuid:"),
            "the document id is the thread anchor and must be a urn:uuid"
        );
    }

    /// No `issuer` rather than a wrong one. SPEC §4.8.1 makes an in-band issuer
    /// that disagrees with the transport sender a rejection, so omitting it when
    /// the bridge has no DID yet is the safe half of the choice.
    #[test]
    fn an_unknown_issuer_is_omitted_not_guessed() {
        let (_, doc) = build_outbound(TASK_DID_CHECK_NAME, SERVER, None, json!({}));
        assert!(
            doc.get("issuer").is_none(),
            "an unknown issuer must be absent, not empty or invented: {doc}"
        );
    }

    /// The happy path yields the response document's `payload`, which is what
    /// every verb's parser consumes.
    #[test]
    fn a_response_document_yields_its_payload() {
        let reply = json!({
            "id": "urn:uuid:2",
            "type": TASK_DID_CHECK_NAME_RESPONSE,
            "payload": { "available": true, "reserved": true, "record": { "mnemonic": "bob" } },
        });
        let payload = unwrap_envelope_reply(reply, TASK_DID_CHECK_NAME_RESPONSE)
            .expect("a matching response document unwraps");
        assert_eq!(payload["available"], true);
        assert_eq!(payload["record"]["mnemonic"], "bob");
    }

    /// A problem report inside the envelope maps through the *same* table the
    /// bare framing uses, so the operator-facing status does not depend on which
    /// framing carried the rejection.
    ///
    /// `path-unavailable` → 409 is the case that matters: it is a clean client
    /// conflict, and collapsing it to 502 was the bug the mapping table was
    /// introduced to fix.
    #[test]
    fn an_enveloped_problem_report_keeps_its_typed_meaning() {
        let reply = json!({
            "id": "urn:uuid:3",
            "type": TASK_DID_PROBLEM_REPORT,
            "payload": { "code": "e.p.did.path-unavailable", "comment": "taken" },
        });
        let err = unwrap_envelope_reply(reply, TASK_DID_CHECK_NAME_RESPONSE)
            .expect_err("a problem report is an error, not a payload");
        assert!(
            matches!(err, AppError::Conflict(_)),
            "path-unavailable must stay a 409, got: {err:?}"
        );
    }

    /// A framework-level refusal is not a task outcome, so it surfaces as a 502
    /// rather than being mistaken for a rejection the caller could act on. The
    /// version floats (0.1 from a body-parse failure, 0.2 from the typed
    /// pipeline), so the match is by prefix.
    #[test]
    fn a_trust_task_error_is_a_bad_gateway_at_either_version() {
        for version in ["0.1", "0.2"] {
            let reply = json!({
                "id": "urn:uuid:4",
                "type": format!("https://trusttasks.org/spec/trust-task-error/{version}"),
                "payload": { "code": "malformedRequest", "message": "nope" },
            });
            let err = unwrap_envelope_reply(reply, TASK_DID_CHECK_NAME_RESPONSE)
                .expect_err("a framework error is not a payload");
            let msg = format!("{err:?}");
            assert!(
                msg.contains("refused the trust-task envelope"),
                "trust-task-error/{version} must surface as an envelope refusal, got: {msg}"
            );
        }
    }

    /// A reply that threads to our request but answers a different task is a
    /// contract break, not a task failure — it must never be handed to a parser
    /// as though it were the expected payload.
    #[test]
    fn a_mismatched_response_type_is_refused() {
        let reply = json!({
            "id": "urn:uuid:5",
            "type": "https://trusttasks.org/spec/did-management/did/delete/0.1#response",
            "payload": { "deleted": true },
        });
        let err = unwrap_envelope_reply(reply, TASK_DID_CHECK_NAME_RESPONSE)
            .expect_err("an off-task response must not be accepted");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("unexpected response document type"),
            "got: {msg}"
        );
    }
}
