//! Signing in as yourself: the bridge as the starter of a wallet sign-in.
//!
//! The portal and the console sign a person in by the trigger-link flow: the
//! page holds a fresh key, opens an `auth/oob` request, the person approves it
//! in their wallet, and the page redeems a session bound to its key. This
//! bridge is that page. Its own `did:key` — the one it runs with — opens the
//! request, the operator opens the trigger link in the browser that has their
//! wallet (or scans it), compares the match number, and approves; the bridge
//! redeems.
//!
//! What that yields (`vtc_client::signin`):
//!
//! - **`member`**: the bridge's key is delegated to sign the portal's task
//!   families — the directory, boards, badges, … — as the member, for the
//!   session. No entry of its own, no role: the member's standing, read fresh
//!   at every call.
//! - **`admin`**: a console session for the bridge's key, so `auth/whoami`
//!   answers for it. Signed administrative documents still need a
//!   signing-key delegation of the administrator's DID; that is the next
//!   piece.
//!
//! Three tools, because MCP is request-and-answer and the person acts in
//! between: `vtc_sign_in` opens the request and returns the link;
//! `vtc_sign_in_finish` polls and returns as soon as there is something for
//! the person to do — the match number to confirm — or the session;
//! `vtc_sign_in_cancel` withdraws an open request.

use std::time::{Duration, Instant};

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::service::Peer;
use rmcp::{ErrorData as McpError, RoleServer, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use vtc_client::signin::{SignInAudience, SignInPoll, task};

use crate::server::VtcMcp;

/// How this bridge names itself to the approver: the wallet shows the
/// starter's user agent beside the request.
pub(crate) fn starter() -> String {
    format!("vtc-mcp/{}", env!("CARGO_PKG_VERSION"))
}

/// The longest one `finish` call waits before answering with where the
/// request stands.
const MAX_WAIT_SECS: u64 = 300;
/// The default.
const DEFAULT_WAIT_SECS: u64 = 90;
/// Between polls; the community holds each one for a while itself.
const POLL_GAP: Duration = Duration::from_millis(750);

/// An open request, kept so `finish` and `cancel` need no id.
#[derive(Debug, Clone)]
pub(crate) struct PendingSignIn {
    pub request_id: String,
    pub audience: SignInAudience,
    pub trigger_link: String,
    pub claim_closes_at: String,
    /// The match number already reported to the person, so a poll that sees
    /// it again keeps waiting rather than returning it twice.
    pub shown_match_number: Option<String>,
}

/// Who this bridge is signed in as.
#[derive(Debug, Clone)]
pub(crate) struct SignedInAs {
    pub subject: String,
    pub display_name: Option<String>,
    pub audience: SignInAudience,
    pub session_ends_at: Option<String>,
    pub amr: Vec<String>,
}

impl SignedInAs {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "subject": self.subject,
            "displayName": self.display_name,
            "audience": self.audience.as_str(),
            "sessionEndsAt": self.session_ends_at,
            "amr": self.amr,
        })
    }
}

/// The bridge's sign-in state.
#[derive(Debug, Default)]
pub(crate) struct SignInState {
    pub pending: Option<PendingSignIn>,
    pub signed_in: Option<SignedInAs>,
    /// The identity this bridge's key was enrolled to act for, this run.
    pub delegation_of: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SignInParams {
    /// `member` (default): the member portal's standing. `admin`: the
    /// operator console's.
    #[serde(default)]
    pub audience: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SignInFinishParams {
    /// The request to finish; the one `vtc_sign_in` opened when omitted.
    #[serde(default)]
    pub request_id: Option<String>,
    /// How long to wait for the person before answering with where the
    /// request stands (default 90, at most 300 seconds).
    #[serde(default)]
    pub wait_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SignInCancelParams {
    /// The request to cancel; the open one when omitted.
    #[serde(default)]
    pub request_id: Option<String>,
}

fn next_after_sign_in(audience: SignInAudience) -> &'static str {
    match audience {
        SignInAudience::Member => {
            "This bridge's key now signs the member portal's task families (directory, boards, \
             badges, …) as you, for this session. Ask vtc_whoami; vtc_list_operations marks \
             what the community serves."
        }
        SignInAudience::Admin => {
            "This bridge's key now holds your operator-console session, so vtc_whoami answers \
             for it. Signed administrative documents still need a signing-key delegation of \
             your DID; until that is enrolled, administrative writes are refused by the \
             community. A console session idles out (15 minutes by default) and a signed \
             document does not refresh it: sign in again when vtc_whoami stops answering."
        }
    }
}

impl VtcMcp {
    /// Open a request. The body of `vtc_sign_in`, without the MCP plumbing.
    pub(crate) async fn start_sign_in(&self, audience: SignInAudience) -> Result<Value, McpError> {
        let client = self.client()?;
        let request = client
            .sign_in_request(audience, &starter())
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let pending = PendingSignIn {
            request_id: request.request_id.clone(),
            audience,
            trigger_link: request.trigger_link.clone(),
            claim_closes_at: request.claim_closes_at.clone(),
            shown_match_number: None,
        };
        self.sign_in.write().await.pending = Some(pending);
        Ok(json!({
            "status": "opened",
            "requestId": request.request_id,
            "audience": audience.as_str(),
            "triggerLink": request.trigger_link,
            "claimClosesAt": request.claim_closes_at,
            "next": "Show the person the trigger link. They open it in the browser that holds \
                     their wallet, or scan it from a phone wallet; the wallet shows this \
                     bridge as the starter. Then call vtc_sign_in_finish: it answers with the \
                     match number the wallet also shows, which the person confirms there, and \
                     once more when the session is theirs.",
        }))
    }

    /// Poll a request until there is something for the person, or the
    /// session. The body of `vtc_sign_in_finish`.
    pub(crate) async fn finish_sign_in(
        &self,
        request_id: Option<&str>,
        wait: Duration,
    ) -> Result<Value, McpError> {
        let client = self.client()?;
        let pending = {
            let state = self.sign_in.read().await;
            match (request_id, &state.pending) {
                (Some(id), Some(p)) if p.request_id == id => p.clone(),
                (Some(id), _) => PendingSignIn {
                    request_id: id.to_string(),
                    audience: SignInAudience::Member,
                    trigger_link: String::new(),
                    claim_closes_at: String::new(),
                    shown_match_number: None,
                },
                (None, Some(p)) => p.clone(),
                (None, None) => {
                    return Err(McpError::invalid_request(
                        "no sign-in request is open; call vtc_sign_in first".to_string(),
                        None,
                    ));
                }
            }
        };
        let deadline = Instant::now() + wait;
        let mut last_state = "pending".to_string();
        loop {
            let poll = client
                .sign_in_redeem(&pending.request_id, &starter())
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            match poll {
                SignInPoll::Pending {
                    state,
                    match_number,
                } => {
                    last_state = state.clone();
                    if let Some(number) = match_number
                        && pending.shown_match_number.as_deref() != Some(number.as_str())
                    {
                        // Something for the person: confirm this number in
                        // the wallet. Remember it so the next call waits on.
                        let mut st = self.sign_in.write().await;
                        if let Some(p) = st.pending.as_mut()
                            && p.request_id == pending.request_id
                        {
                            p.shown_match_number = Some(number.clone());
                        }
                        return Ok(json!({
                            "status": "claimed",
                            "requestId": pending.request_id,
                            "state": state,
                            "matchNumber": number,
                            "next": "Tell the person this match number. Their wallet shows a \
                                     number too; they approve only if the two are the same. \
                                     Then call vtc_sign_in_finish again.",
                        }));
                    }
                }
                SignInPoll::SignedIn(s) => {
                    let signed_in = SignedInAs {
                        subject: s.subject.clone(),
                        display_name: s.display_name.clone(),
                        audience: s.audience,
                        session_ends_at: s.session_ends_at.clone(),
                        amr: s.amr.clone(),
                    };
                    let mut st = self.sign_in.write().await;
                    st.pending = None;
                    st.signed_in = Some(signed_in.clone());
                    tracing::info!(subject = %s.subject, audience = s.audience.as_str(), "signed in");
                    return Ok(json!({
                        "status": "signedIn",
                        "signedInAs": signed_in.to_json(),
                        "next": next_after_sign_in(s.audience),
                    }));
                }
                SignInPoll::Declined { reason } => {
                    self.sign_in.write().await.pending = None;
                    return Ok(json!({
                        "status": "declined",
                        "requestId": pending.request_id,
                        "reason": reason,
                        "next": "The wallet declined, or the request was cancelled. Call \
                                 vtc_sign_in to open a new one.",
                    }));
                }
                SignInPoll::Expired => {
                    self.sign_in.write().await.pending = None;
                    return Ok(json!({
                        "status": "expired",
                        "requestId": pending.request_id,
                        "next": "The claim window closed before the wallet approved. Call \
                                 vtc_sign_in to open a new one.",
                    }));
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                return Ok(json!({
                    "status": "waiting",
                    "requestId": pending.request_id,
                    "audience": pending.audience.as_str(),
                    "state": last_state,
                    "matchNumber": pending.shown_match_number,
                    "triggerLink": pending.trigger_link,
                    "claimClosesAt": pending.claim_closes_at,
                    "next": "Still waiting for the wallet. Call vtc_sign_in_finish again, or \
                             vtc_sign_in_cancel.",
                }));
            }
            tokio::time::sleep(POLL_GAP).await;
        }
    }

    /// Cancel an open request. The body of `vtc_sign_in_cancel`.
    pub(crate) async fn cancel_sign_in(&self, request_id: Option<&str>) -> Result<Value, McpError> {
        let client = self.client()?;
        let id = match request_id {
            Some(id) => id.to_string(),
            None => match &self.sign_in.read().await.pending {
                Some(p) => p.request_id.clone(),
                None => {
                    return Err(McpError::invalid_request(
                        "no sign-in request is open".to_string(),
                        None,
                    ));
                }
            },
        };
        let result = client.sign_in_cancel(&id, &starter()).await;
        let mut st = self.sign_in.write().await;
        if st.pending.as_ref().is_some_and(|p| p.request_id == id) {
            st.pending = None;
        }
        match result {
            Ok(()) => Ok(json!({ "status": "cancelled", "requestId": id })),
            // The request ends on its own clock either way.
            Err(e) => Ok(json!({ "status": "ended", "requestId": id, "detail": e.to_string() })),
        }
    }
}

#[tool_router(router = signin_router, vis = "pub(crate)")]
impl VtcMcp {
    #[tool(
        description = "Sign this bridge in as YOU, the way the member portal and the operator \
                       console sign in: it opens a wallet sign-in request with its own key and \
                       returns the trigger link for your wallet to approve. No entry and no \
                       role are created: once approved, the bridge's key acts with your \
                       standing. audience 'member' (default) gives it the member portal's \
                       standing, delegated for the portal's task families; 'admin' gives it \
                       your operator-console session. Follow with vtc_sign_in_finish.",
        annotations(
            title = "Sign in as yourself",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn vtc_sign_in(
        &self,
        Parameters(p): Parameters<SignInParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let audience = match p.audience.as_deref() {
            None => SignInAudience::Member,
            Some(a) => match SignInAudience::parse(a) {
                Some(a) => a,
                None => {
                    return Err(McpError::invalid_params(
                        format!("audience must be 'member' or 'admin', not '{a}'"),
                        None,
                    ));
                }
            },
        };
        let call = match self
            .begin(
                "vtc_sign_in",
                Some(task::REQUEST),
                json!({ "audience": audience.as_str() }),
                Some(&peer),
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = self.start_sign_in(audience).await;
        call.finish(result)
    }

    #[tool(
        description = "Finish a wallet sign-in: waits for the person's wallet and answers as \
                       soon as there is something for them to do — the match number to confirm \
                       in the wallet (then call again) — or with the session once approved. \
                       Also answers 'declined', 'expired', or 'waiting' after wait_seconds.",
        annotations(
            title = "Finish signing in",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vtc_sign_in_finish(
        &self,
        Parameters(p): Parameters<SignInFinishParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let wait = Duration::from_secs(
            p.wait_seconds
                .unwrap_or(DEFAULT_WAIT_SECS)
                .min(MAX_WAIT_SECS),
        );
        let call = match self
            .begin(
                "vtc_sign_in_finish",
                Some(task::REDEEM),
                json!({ "requestId": p.request_id, "waitSeconds": wait.as_secs() }),
                Some(&peer),
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = self.finish_sign_in(p.request_id.as_deref(), wait).await;
        call.finish(result)
    }

    #[tool(
        description = "Cancel an open wallet sign-in request.",
        annotations(
            title = "Cancel signing in",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vtc_sign_in_cancel(
        &self,
        Parameters(p): Parameters<SignInCancelParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin(
                "vtc_sign_in_cancel",
                Some(task::CANCEL),
                json!({ "requestId": p.request_id }),
                Some(&peer),
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = self.cancel_sign_in(p.request_id.as_deref()).await;
        call.finish(result)
    }

    #[tool(
        description = "Give this bridge YOUR administrative standing, as a signing-key \
                       delegation of your identity — the same delegation the operator console's \
                       key holds. Call it first with no authorization: it answers with this \
                       bridge's DID and the one command (`cnm access authorize-key …`) that signs \
                       the authorization as you. Then call it with that authorization (the JSON, \
                       or the file it was written to): the bridge enrols its own key with it. \
                       Creates no access-control entry; the key acts with your standing read at \
                       every call, never approves or answers a step-up, and expires within 30 \
                       days.",
        annotations(
            title = "Act with your administrative standing",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn vtc_enrol_signing_key(
        &self,
        Parameters(p): Parameters<EnrolParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin(
                "vtc_enrol_signing_key",
                Some(ENROLL),
                json!({ "authorizationFile": p.authorization_file, "given": p.authorization.is_some() }),
                Some(&peer),
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = self.enrol_signing_key(p).await;
        call.finish(result)
    }
}

/// `auth/signing-key/enroll/0.2`.
pub(crate) const ENROLL: &str = "https://trusttasks.org/spec/auth/signing-key/enroll/0.2";
/// `auth/signing-key/authorize/0.1`.
const AUTHORIZE: &str = "https://trusttasks.org/spec/auth/signing-key/authorize/0.1";

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EnrolParams {
    /// The signed `auth/signing-key/authorize/0.1` document `cnm access
    /// authorize-key` printed. Omit both this and `authorization_file` to be
    /// told the command to run.
    #[serde(default)]
    pub authorization: Option<Value>,
    /// The file `cnm access authorize-key --out` wrote it to.
    #[serde(default)]
    pub authorization_file: Option<String>,
}

impl VtcMcp {
    /// Enrol this bridge's key with the identity's authorization, or say how
    /// to get one. The body of `vtc_enrol_signing_key`.
    pub(crate) async fn enrol_signing_key(&self, p: EnrolParams) -> Result<Value, McpError> {
        let own_did = self.identity.agent_did.clone().ok_or_else(|| {
            McpError::internal_error(
                "this bridge has no key of its own to enrol; start it with --agent-did and \
                 --agent-key (a key from --mint-did-key)"
                    .to_string(),
                None,
            )
        })?;
        if !own_did.starts_with("did:key:") {
            return Err(McpError::invalid_request(
                format!(
                    "this bridge speaks as {own_did}, a persona, not a key of its own: a \
                     signing-key delegation is for a did:key (start the bridge with \
                     --mint-did-key's key instead)"
                ),
                None,
            ));
        }
        let authorization = match (p.authorization, p.authorization_file) {
            (Some(doc), _) => doc,
            (None, Some(path)) => {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| McpError::invalid_params(format!("reading {path}: {e}"), None))?;
                serde_json::from_str(&text).map_err(|e| {
                    McpError::invalid_params(format!("{path} is not a JSON document: {e}"), None)
                })?
            }
            (None, None) => {
                let vtc = self.identity.vtc_did.clone().unwrap_or_default();
                return Ok(json!({
                    "status": "needsAuthorization",
                    "signingKeyDid": own_did,
                    "command": format!(
                        "cnm --vtc-did {vtc} access authorize-key {own_did} --label \"vtc-mcp\" \
                         --expires 30d --out ~/.config/vtc-mcp/authorization.json"
                    ),
                    "next": "Run the command as the administrator whose standing this bridge \
                             should carry: cnm signs the authorization with that identity's key \
                             and nothing else. Then call vtc_enrol_signing_key with \
                             authorization_file set to the file it wrote. The authorization is \
                             single-use, only this bridge's key can use it, and it lapses in an \
                             hour unless sent.",
                }));
            }
        };
        if authorization["type"] != AUTHORIZE {
            return Err(McpError::invalid_params(
                format!(
                    "that is not an auth/signing-key/authorize/0.1 document (type {})",
                    authorization["type"]
                ),
                None,
            ));
        }
        let terms = authorization["payload"].clone();
        if terms["signingKeyDid"].as_str() != Some(own_did.as_str()) {
            return Err(McpError::invalid_params(
                format!(
                    "that authorization is for {}, not this bridge's key {own_did}",
                    terms["signingKeyDid"]
                ),
                None,
            ));
        }
        let identity_did = terms["identityDid"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        // The enrolment's payload is exactly the authorized terms, with the
        // authorization beside them; the community compares the two.
        let mut payload = terms;
        payload["authorization"] = authorization;
        let client = self.client()?;
        let answer = crate::server::outcome(client.send_task(ENROLL, payload).await)?;
        self.sign_in.write().await.delegation_of = Some(identity_did.clone());
        tracing::info!(identity = %identity_did, "enrolled as a signing-key delegation");
        Ok(json!({
            "status": "enrolled",
            "actsAs": identity_did,
            "signingKey": answer["signingKey"],
            "next": "This bridge's documents are now authorized by that identity's standing, \
                     read at every call. Acts that need your own factor — a step-up, approving \
                     an action — still go to the console or cnm. Revoke the key from the \
                     console's list of your signing keys, or with \
                     auth/signing-key/revoke.",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::BridgeIdentity;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vtc_client::{HolderKey, VtcClient};
    use vti_mcp_common::guard::{ConfirmLevel, Guard};
    use vti_mcp_common::observability::Recorder;

    const VTC_DID: &str = "did:webvh:Qm1:vtc.example.com:first";
    const REQUEST_ID: &str = "AAAAAAAAAAAAAAAAAAAAAA";

    fn holder() -> HolderKey {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
        );
        let private = multibase::encode(multibase::Base::Base58Btc, signing.to_bytes());
        HolderKey::from_did_key(&did, private).unwrap()
    }

    fn reply_doc(type_uri: &str, payload: Value) -> String {
        json!({
            "id": "urn:uuid:4d2c3f4e-1b2a-4c3d-8e9f-0a1b2c3d4e5f",
            "type": type_uri,
            "issuer": VTC_DID,
            "issuedAt": "2026-11-07T00:00:00Z",
            "payload": payload,
        })
        .to_string()
    }

    fn refusal(local: &str, details: Value) -> String {
        reply_doc(
            "https://trusttasks.org/spec/trust-task-error/0.3",
            json!({ "code": format!("auth/oob/redeem:{local}"), "message": "…", "details": details }),
        )
    }

    /// A community over loopback HTTP that answers a scripted sequence and
    /// hands back each request's head and body.
    async fn scripted_vtc(
        replies: Vec<(&'static str, String)>,
    ) -> (String, tokio::task::JoinHandle<Vec<(String, Vec<u8>)>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = tokio::spawn(async move {
            let mut received = Vec::new();
            for (status, body) in replies {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let head_end = loop {
                    let mut chunk = [0u8; 4096];
                    let n = sock.read(&mut chunk).await.unwrap();
                    assert!(n > 0);
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                let length: usize = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(str::to_owned)
                    })
                    .map(|v| v.trim().parse().unwrap())
                    .unwrap_or(0);
                let mut request = buf[head_end..].to_vec();
                while request.len() < length {
                    let mut chunk = [0u8; 4096];
                    let n = sock.read(&mut chunk).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&chunk[..n]);
                }
                request.truncate(length);
                received.push((head, request));
                sock.write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
                sock.shutdown().await.ok();
            }
            received
        });
        (format!("http://127.0.0.1:{port}/v1"), served)
    }

    fn config_body() -> String {
        json!({
            "vtcDid": VTC_DID,
            "linkHost": "link.trustoverip.org",
            "flow": "vtc-sign-in",
            "didDocument": { "status": "ok" },
        })
        .to_string()
    }

    fn bridge_at(base: &str) -> VtcMcp {
        VtcMcp::new(
            Arc::new(VtcClient::with_key(base, VTC_DID, holder())),
            BridgeIdentity {
                mode: "did:key".into(),
                agent_did: Some(holder().holder_did().to_string()),
                vtc_did: Some(VTC_DID.into()),
                transport_choice: "rest".into(),
            },
            Guard {
                confirm: ConfirmLevel::Never,
                ..Guard::default()
            },
            Arc::new(Recorder::default()),
        )
    }

    #[tokio::test]
    async fn a_sign_in_opens_as_the_portal_would_and_the_person_sees_the_number_then_the_session() {
        let (base, served) = scripted_vtc(vec![
            ("200 OK", config_body()),
            (
                "200 OK",
                reply_doc(
                    &format!("{}#response", task::REQUEST),
                    json!({ "requestId": REQUEST_ID, "claimClosesAt": "2030-03-17T17:46:40Z",
                            "ext": { "org.openvtc.session": { "audience": "admin" } } }),
                ),
            ),
            ("403 Forbidden", refusal("pending", json!({ "state": "pending" }))),
            ("403 Forbidden", refusal("pending", json!({ "state": "claimed", "matchNumber": "4213" }))),
            ("403 Forbidden", refusal("pending", json!({ "state": "claimed", "matchNumber": "4213" }))),
            (
                "200 OK",
                reply_doc(
                    &format!("{}#response", task::REDEEM),
                    json!({ "subject": "did:webvh:Qm2:webvh.example.com:glenn", "displayName": "Glenn",
                            "sessionEndsAt": "2030-03-18T17:46:40Z", "amr": ["did"],
                            "ext": { "org.openvtc.session": { "audience": "admin" } } }),
                ),
            ),
        ])
        .await;
        let bridge = bridge_at(&base);

        let opened = bridge.start_sign_in(SignInAudience::Admin).await.unwrap();
        assert_eq!(opened["status"], "opened");
        assert_eq!(opened["requestId"], REQUEST_ID);
        assert_eq!(
            opened["triggerLink"],
            format!(
                "https://link.trustoverip.org/t#_from={VTC_DID}&_id={REQUEST_ID}&_exp=1900000000&_type=vtc-sign-in"
            )
        );
        assert!(bridge.sign_in.read().await.pending.is_some());

        // The first finish sees pending, then claimed with a number: it returns
        // the number for the person to confirm.
        let claimed = bridge
            .finish_sign_in(None, Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(claimed["status"], "claimed", "{claimed}");
        assert_eq!(claimed["matchNumber"], "4213");

        // The second finish sees the same number (keeps waiting), then the session.
        let signed = bridge
            .finish_sign_in(None, Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(signed["status"], "signedIn", "{signed}");
        assert_eq!(
            signed["signedInAs"]["subject"],
            "did:webvh:Qm2:webvh.example.com:glenn"
        );
        assert_eq!(signed["signedInAs"]["audience"], "admin");
        let state = bridge.sign_in.read().await;
        assert!(state.pending.is_none());
        assert_eq!(
            state.signed_in.as_ref().unwrap().display_name.as_deref(),
            Some("Glenn")
        );
        drop(state);
        assert_eq!(
            bridge.status(0).await["signedInAs"]["subject"],
            "did:webvh:Qm2:webvh.example.com:glenn"
        );

        let received = served.await.unwrap();
        assert_eq!(received.len(), 6);
        assert!(received[0].0.starts_with("GET /v1/member/sign-in/config"));
        // The request is signed by the bridge's key, addressed to the
        // community, presents the portal origin and names the bridge.
        let head = received[1].0.to_ascii_lowercase();
        assert!(
            head.contains(&format!("origin: {}", base.trim_end_matches("/v1"))),
            "{head}"
        );
        assert!(head.contains("user-agent: vtc-mcp/"), "{head}");
        let request: Value = serde_json::from_slice(&received[1].1).unwrap();
        assert_eq!(request["type"], task::REQUEST);
        assert_eq!(request["recipient"], VTC_DID);
        assert_eq!(request["payload"]["purpose"], "login");
        assert_eq!(
            request["payload"]["ext"]["org.openvtc.session"]["audience"],
            "admin"
        );
        assert!(request["proof"].is_object());
    }

    #[tokio::test]
    async fn enrolling_names_the_command_refuses_another_keys_authorization_and_sends_the_terms() {
        let bridge_did = holder().holder_did().to_string();
        let authorization = |key_did: &str| {
            json!({
                "id": "urn:uuid:11111111-2222-4333-8444-555555555555",
                "type": AUTHORIZE,
                "issuer": "did:key:zAdmin",
                "recipient": VTC_DID,
                "issuedAt": "2026-11-07T00:00:00Z",
                "expiresAt": "2026-11-07T01:00:00Z",
                "payload": {
                    "identityDid": "did:key:zAdmin",
                    "signingKeyDid": key_did,
                    "scope": "console",
                    "deviceLabel": "vtc-mcp",
                },
                "proof": { "type": "DataIntegrityProof" },
            })
        };

        // No authorization: the bridge says what to run, naming its own key.
        let idle = bridge_at("http://192.0.2.1:9/v1");
        let told = idle
            .enrol_signing_key(EnrolParams {
                authorization: None,
                authorization_file: None,
            })
            .await
            .unwrap();
        assert_eq!(told["status"], "needsAuthorization");
        assert_eq!(told["signingKeyDid"], bridge_did);
        let command = told["command"].as_str().unwrap();
        assert!(
            command.contains(&format!("authorize-key {bridge_did}")),
            "{command}"
        );
        assert!(command.contains(VTC_DID), "{command}");

        // Another key's authorization is refused before anything is sent (the
        // base is unroutable: a send would fail differently).
        let err = idle
            .enrol_signing_key(EnrolParams {
                authorization: Some(authorization("did:key:zSomeoneElse")),
                authorization_file: None,
            })
            .await
            .unwrap_err();
        assert!(
            err.message.contains("not this bridge's key"),
            "{}",
            err.message
        );

        // Its own: the enrolment is the terms with the authorization beside them.
        let (base, served) = scripted_vtc(vec![(
            "200 OK",
            reply_doc(
                &format!("{ENROLL}#response"),
                json!({ "signingKey": { "signingKeyDid": bridge_did, "identityDid": "did:key:zAdmin",
                        "scope": "console", "active": true, "createdAt": "2026-11-07T00:00:00Z",
                        "expiresAt": "2026-12-07T00:00:00Z" } }),
            ),
        )])
        .await;
        let bridge = bridge_at(&base);
        let given = authorization(&bridge_did);
        let enrolled = bridge
            .enrol_signing_key(EnrolParams {
                authorization: Some(given.clone()),
                authorization_file: None,
            })
            .await
            .unwrap();
        assert_eq!(enrolled["status"], "enrolled", "{enrolled}");
        assert_eq!(enrolled["actsAs"], "did:key:zAdmin");
        assert_eq!(bridge.status(0).await["delegationOf"], "did:key:zAdmin");
        let received = served.await.unwrap();
        let doc: Value = serde_json::from_slice(&received[0].1).unwrap();
        assert_eq!(doc["type"], ENROLL);
        assert_eq!(doc["issuer"], bridge_did);
        let mut expected = given["payload"].clone();
        expected["authorization"] = given;
        assert_eq!(doc["payload"], expected);
        assert!(doc["proof"].is_object());
    }

    #[tokio::test]
    async fn a_declined_sign_in_clears_the_request_and_a_wrong_community_is_refused() {
        let (base, _served) = scripted_vtc(vec![
            ("200 OK", config_body()),
            (
                "200 OK",
                reply_doc(
                    &format!("{}#response", task::REQUEST),
                    json!({ "requestId": REQUEST_ID, "claimClosesAt": "2030-03-17T17:46:40Z" }),
                ),
            ),
            (
                "403 Forbidden",
                refusal(
                    "declined",
                    json!({ "state": "declined", "reason": "notAMember" }),
                ),
            ),
        ])
        .await;
        let bridge = bridge_at(&base);
        bridge.start_sign_in(SignInAudience::Member).await.unwrap();
        let declined = bridge
            .finish_sign_in(None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(declined["status"], "declined");
        assert_eq!(declined["reason"], "notAMember");
        assert!(bridge.sign_in.read().await.pending.is_none());
        let err = bridge
            .finish_sign_in(None, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(err.message.contains("no sign-in request is open"));

        // A portal naming another community is refused before a request opens.
        let (base, _served) = scripted_vtc(vec![(
            "200 OK",
            json!({ "vtcDid": "did:web:other", "linkHost": "link.trustoverip.org", "flow": "vtc-sign-in" })
                .to_string(),
        )])
        .await;
        let err = bridge_at(&base)
            .start_sign_in(SignInAudience::Member)
            .await
            .unwrap_err();
        assert!(err.message.contains("wrongCommunity"), "{}", err.message);
    }
}
