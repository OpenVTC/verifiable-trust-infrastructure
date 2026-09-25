//! Client SDK for a Verifiable Trust Community (VTC).
//!
//! The VTA SDK ([`vta_sdk`]) is the client for *VTAs*; this crate is the
//! equivalent for *VTCs*. It lets an operator or an integration drive a VTC's
//! member-facing and admin-facing surface: authenticate, list members
//! (the community roster), run the join ceremony, remove members, and manage
//! community policy.
//!
//! ## Two surfaces, and only one of them is a URL
//!
//! The VTC answers **holder verbs** — the applicant side of the join ceremony —
//! on a single document endpoint, routed by the document's own `type`. Those are
//! addressed to a community, not to a URL, so they travel over HTTPS, a mediated
//! DIDComm session or TSP without changing. Build the client with
//! `VtcClient::connect_didcomm` or `VtcClient::connect_tsp` (features
//! `didcomm` / `tsp`) and they go over the session; build it any other way and
//! they go over HTTPS.
//!
//! The **admin verbs** are split by what the VTC serves (#1641):
//!
//! - Those whose tasks the VTC binds as signed documents — a join decision,
//!   `members/{update,admin-remove,credentials}`, `backup/export` — go as
//!   documents too: over the session when there is one, otherwise signed with
//!   the operator's own key (the one [`VtcClient::connect`] authenticated with)
//!   and posted to `POST {base}/trust-tasks`. A client holding that key never
//!   falls back to the bearer route for them, even against a VTC too old to
//!   serve the document. A client built from a token alone
//!   ([`VtcClient::with_token`]) holds no key and uses the bearer routes.
//! - The rest are gated on a bearer token *and* a per-route `Trust-Task`
//!   header, which is a URL-shaped surface; a session-only client answers them
//!   with [`VtcError::NoRestTransport`] rather than failing obscurely.
//!
//! The session transports are **delegated to `vta_sdk::client::VtaClient`**,
//! which already owns session setup, `thid` demultiplexing, retry under one
//! idempotency key and reply-proof verification. A second copy of that here
//! would be a second thing to keep correct.
//!
//! ## Any DID method can be the holder
//!
//! [`VtcClient::submit_join_as`] takes a [`HolderKey`] and so signs as any DID
//! method; [`VtcClient::submit_join`] is the `did:key` convenience wrapper over
//! it. Over a session the question does not arise at all — the envelope proves
//! the sender and the VTC never reads a document proof.
//!
//! This matters because a persona minted by a VTA is a `did:webvh`. A client
//! that could sign only as a `did:key` made every such holder borrow an identity
//! it does not otherwise use, and the borrowed one is the DID that would have
//! become the member.
//!
//! It is deliberately thin: authentication reuses
//! [`vta_sdk::auth_light::challenge_response_light`] (the challenge-response
//! flow is audience-agnostic — pass the VTC's URL and DID and the server binds
//! `aud` to itself), and the join wire types are re-exported from
//! [`vta_sdk::protocols::join_requests`]. Only the VTC-specific REST shapes
//! (member records, pagination) are defined here.
//!
//! ## Mount path
//!
//! A VTC mounts its API under a configurable base (default `/v1`). Pass the
//! **full** API base to [`VtcClient::connect`] / [`VtcClient::with_token`] —
//! e.g. `https://vtc.example.com/v1` — so both `/auth/*` and `/members` resolve.
//!
//! ## The `Trust-Task` header is mandatory
//!
//! The VTC gates **every** route on a per-route `Trust-Task` URL header
//! (`vtc-service/src/routes/mod.rs`, the `tt(...)` wrapper) and answers `400`
//! without it — only `/health` and the browser wallet's `/wallet/auth/*`
//! aliases are exempt. This client sent it on nothing, so every method failed
//! at the transport layer regardless of its body. [`task`] holds the URL for
//! each route and `VtcClient::tt` attaches it; a new method must go through
//! that helper, not a bare `self.http.get(...)`.
//!
//! ## Scope
//!
//! Authentication, the member roster, the admin join queue, removal, policy,
//! the vetting admin surface (vetter grants, automatic grants, branding and
//! statement withdrawals — what `cnm vetting` drives), audit-chain verification
//! and encrypted backup / restore (what `cnm audit` / `cnm backup` drive), and
//! the applicant side
//! of the join ceremony
//! ([`VtcClient::submit_join`] / [`VtcClient::submit_join_as`], which sign
//! their own document and need no token).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Re-exported so a caller can name the holder key without also depending on
/// `vta-sdk` directly. A VTC client that has to reach past this crate for the
/// type its own method takes is a client with a seam in it.
pub use vta_sdk::trust_task_sign::HolderKey;

/// Round-trip budget for a holder verb sent over a session, in seconds.
///
/// A join submit is not a local read: the community evaluates its policy and,
/// on auto-admit, issues a VMC and a role VEC before it answers. The HTTPS path
/// inherits `reqwest`'s own timeout; this is the session path's equivalent, and
/// it exists at all because a call with no finite bound turns a community that
/// has stopped answering into a client that never returns.
#[cfg(feature = "didcomm")]
const SESSION_TIMEOUT_SECS: u64 = 60;

pub mod git_ns;

/// The `Trust-Task` URL each route this client calls is gated on, as declared
/// in `vtc-service/src/routes/mod.rs`.
///
/// Kept as one block so the mapping is auditable against the server's router in
/// a single read, rather than scattered as string literals down the file. A URL
/// that drifts from the server's is a 400 at runtime, so this list is part of
/// the client's contract, not decoration.
pub mod rooms;

pub mod task {
    pub const MEMBERS_LIST: &str = "https://trusttasks.org/spec/vtc/members/list/0.1";
    pub const MEMBERS_UPDATE: &str = "https://trusttasks.org/spec/vtc/members/update/0.1";
    pub const MEMBERS_ADMIN_REMOVE: &str =
        "https://trusttasks.org/spec/vtc/members/admin-remove/0.1";
    pub const JOIN_REQUESTS_LIST: &str = "https://trusttasks.org/spec/vtc/join-requests/list/0.1";
    pub const JOIN_REQUESTS_DECIDE: &str =
        "https://trusttasks.org/spec/vtc/join-requests/decide/0.1";
    pub const POLICY_LIST: &str = "https://trusttasks.org/spec/policy/list/0.2";
    pub const POLICY_GET: &str = "https://trusttasks.org/spec/policy/get/0.1";
    pub const POLICY_UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
    pub const POLICY_ACTIVATE: &str = "https://trusttasks.org/spec/policy/activate/0.1";
    pub const VETTING_VETTERS_GRANT: &str =
        "https://trusttasks.org/spec/vtc/vetting/vetters/grant/0.1";
    pub const VETTING_VETTERS_RESEND: &str =
        "https://trusttasks.org/spec/vtc/vetting/vetters/resend/0.1";
    pub const VETTING_VETTERS_SHOW: &str =
        "https://trusttasks.org/spec/vtc/vetting/vetters/show/0.1";
    pub const ENDORSEMENTS_REVOKE: &str = "https://trusttasks.org/spec/vtc/endorsements/revoke/0.1";
    pub const AUDIT_VERIFY: &str = "https://trusttasks.org/spec/audit/verify/0.1";
    pub const BACKUP_EXPORT: &str = "https://trusttasks.org/spec/vtc/backup/export/0.1";
    pub const BACKUP_IMPORT: &str = "https://trusttasks.org/spec/vtc/backup/import/0.1";
    pub const MEMBERS_CREDENTIALS: &str =
        <super::members_credentials::Payload as trust_tasks_rs::Payload>::TYPE_URI;
}

/// DID-document service `type` under which a VTC advertises its REST API base
/// (the `vtc-host` template's `#vtc-rest` entry, `{URL}{REST_PATH}`).
///
/// Matched on `type`, never on the `#id` fragment, which is an arbitrary label.
/// Deliberately not `VTARest`: a VTC is not a VTA, and a client that took one
/// for the other would send it the wrong requests.
pub const REST_SERVICE_TYPE: &str = "VTCRest";

/// The REST API base a VTC's DID document advertises, if it advertises one.
///
/// Reads the first service whose `type` is (or includes) [`REST_SERVICE_TYPE`]
/// and returns its endpoint with any trailing `/` removed. The endpoint is the
/// full API base including the mount (`https://vtc.example.com/v1`), which is
/// what [`VtcClient::connect`] takes.
///
/// This is the direction discovery has to run in: from the community's DID to
/// its URL. The reverse — asking a URL which DID it is — would let whoever
/// answers at that URL choose the audience a client signs for, and the audience
/// exists precisely so that the client, not the server, decides that.
pub fn api_base_from_did_document(doc: &serde_json::Value) -> Option<String> {
    let has_type = |svc: &serde_json::Value| match svc.get("type") {
        Some(serde_json::Value::String(t)) => t == REST_SERVICE_TYPE,
        Some(serde_json::Value::Array(ts)) => ts.iter().any(|t| t == REST_SERVICE_TYPE),
        _ => false,
    };
    fn uri(endpoint: &serde_json::Value) -> Option<String> {
        match endpoint {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Object(map) => map.get("uri")?.as_str().map(str::to_string),
            serde_json::Value::Array(items) => items.iter().find_map(uri),
            _ => None,
        }
    }
    doc.get("service")?
        .as_array()?
        .iter()
        .filter(|svc| has_type(svc))
        .find_map(|svc| uri(svc.get("serviceEndpoint")?))
        .map(|u| u.trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
}

/// Largest audit-verification report [`VtcClient::audit_verify`] reads. The
/// report is a handful of counters and identifiers; this is generous headroom.
const MAX_AUDIT_VERIFY_RESPONSE_BYTES: usize = 1024 * 1024;

/// Largest backup response [`VtcClient::export_backup`] /
/// [`VtcClient::import_backup`] read. Matches the VTC's cap on a backup import
/// request body, so an export larger than this could not be restored anyway.
const MAX_BACKUP_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// The `chunkedTrustTask` details [`VtcClient::export_backup`] and
/// [`VtcClient::import_backup`] share.
mod backup_chunks {
    use base64::Engine as _;
    use sha2::Digest as _;

    pub const ALGORITHM: &str = vta_sdk::protocols::backup_management::chunked::ALGORITHM_CHUNKED;
    /// The largest chunk the VTC accepts (its `MAX_CHUNK_SIZE`).
    pub const CHUNK_SIZE: u64 = 32 * 1024;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    pub fn digest(bytes: &[u8]) -> String {
        vta_sdk::protocols::backup_management::chunked::sha256_digest_multibase(
            &sha2::Sha256::digest(bytes).into(),
        )
    }

    pub fn sha256_hex(bytes: &[u8]) -> String {
        sha2::Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub fn encode(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    pub fn decode(text: &str) -> Option<Vec<u8>> {
        B64.decode(text).ok()
    }
}

/// The bound on any other `#response` document read from the document
/// endpoint. Generous for every verb that goes there — the largest, a join
/// decision, carries two credentials — and small enough that a misbehaving
/// endpoint cannot make this client buffer without limit.
const MAX_DOCUMENT_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Re-export of the published join-request protocol wire types, so a consumer
/// driving the join ceremony depends on one crate.
pub use vta_sdk::protocols::join_requests;

/// `did-management/did/register` — how a self-hosted community is handed a
/// new log for its own DID ([`VtcClient::install_did_log`]).
pub use trust_tasks_rs::specs::did_management::did::register as did_register;
/// Re-export of the peer identity vetting wire types — the vetter grant, the
/// grant listing and the automatic-grant configuration this client's vetting
/// admin verbs send and return.
pub use vta_sdk::protocols::vetting;

/// `policy/upsert/0.2` — the body [`VtcClient::upload_policy`] sends.
pub use trust_tasks_rs::specs::policy::upsert::v0_2 as policy_upsert;

/// `vtc/members/credentials/0.1` — what [`VtcClient::member_credentials`]
/// returns, and the error code it maps to [`VtcError::NotFound`].
pub use trust_tasks_rs::specs::vtc::members::credentials::v0_1 as members_credentials;

/// The `ext` key under which a VTC binds an uploaded policy module to the
/// decision slot (purpose) it serves.
///
/// Canonical `policy/upsert` has no `purpose`: a module there is
/// purpose-agnostic and gains meaning at activation. A VTC fixes the purpose
/// by the module's Rego package and requires it at upload, in this `ext` key.
pub const POLICY_PURPOSE_EXT_KEY: &str = "org.openvtc.purpose";

/// Errors surfaced by the VTC client.
///
/// `#[non_exhaustive]`: a typed answer the VTC gives is added here as the
/// client learns to read it, and a caller's `match` must carry a `_ =>` arm
/// rather than stop compiling on each one.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VtcError {
    /// A request needed a bearer token but the client has none — call
    /// [`VtcClient::connect`] (or construct via [`VtcClient::with_token`]).
    #[error("not authenticated — call VtcClient::connect first")]
    NotAuthenticated,
    /// The VTC returned a non-success HTTP status.
    #[error("VTC returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
    /// A request URL could not be built.
    #[error("invalid request url: {0}")]
    Url(String),
    /// A transport-level error talking to the VTC.
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    /// Challenge-response authentication failed.
    #[error("authentication failed: {0}")]
    Auth(#[from] vta_sdk::error::VtaError),
    /// The operation's route no longer exists on the VTC and this client has no
    /// replacement for it. Carries what to use instead.
    #[error("unsupported by this client: {0}")]
    Unsupported(&'static str),
    /// Building or signing a holder Trust Task failed — e.g. an applicant DID
    /// that is not a `did:key` passed to the `did:key` convenience wrapper, a
    /// verification method with no fragment, or an undecodable private key.
    #[error("could not sign the request document: {0}")]
    Signing(String),
    /// Opening or using a messaging session to the VTC failed.
    ///
    /// Distinct from [`Transport`](Self::Transport), which is HTTPS: a mediator
    /// that will not route and a URL that will not resolve are different
    /// faults with different fixes, and one error that covered both would send
    /// the reader to the wrong half of the system.
    #[error("session transport error: {0}")]
    Session(String),
    /// A verb that only exists on the HTTPS surface was called on a client
    /// built with no REST base.
    ///
    /// The admin verbs without a signed binding are gated on a bearer token
    /// *and* a per-route `Trust-Task` header, which is a URL-shaped surface —
    /// they cannot ride a session. Rather than fail at the transport with
    /// something obscure, say so: pass `rest_url` to the `connect_*`
    /// constructor.
    #[error("this client has no REST base — {0} needs one; pass rest_url when connecting")]
    NoRestTransport(&'static str),
    /// The VTC answered 404 with an error `code` the called task's
    /// specification declares for "no such resource" — e.g.
    /// `vtc/members/credentials:notFound` from
    /// [`VtcClient::member_credentials`].
    ///
    /// Only a 404 carrying a declared code becomes this. A bare 404 — a VTC
    /// that predates the route, a proxy in front of it — stays
    /// [`Http`](Self::Http): it does not say the resource is absent, and
    /// reading it as though it did would send an operator after a member that
    /// may well exist.
    #[error("not found ({code}): {message}")]
    NotFound {
        /// The declared error code, as the VTC sent it.
        code: String,
        /// The VTC's human-readable explanation.
        message: String,
    },
    /// A request payload this client built does not satisfy the task's
    /// published schema (an empty policy module, a name over the length
    /// bound, …). Caught before anything is sent.
    #[error("invalid request payload: {0}")]
    InvalidPayload(String),
}

/// A single member of the community, as returned by `GET /members`. Mirrors the
/// VTC's `MemberResponse` (the fields a fleet/operator typically needs);
/// unrecognised fields in the response are ignored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MemberRecord {
    /// The member's DID (for a fleet, the managed VTA's DID).
    pub did: String,
    /// The member's role on the wire (`"admin"`, `"moderator"`, `"member"`,
    /// `"custom:…"`, …).
    pub role: String,
    #[serde(default)]
    pub label: Option<String>,
    pub joined_at: DateTime<Utc>,
    /// Index of the member's revocation slot in the community status list, when
    /// allocated.
    #[serde(default)]
    pub status_list_index: Option<u32>,
    /// Id of the member's current membership credential (VMC), if issued.
    #[serde(default)]
    pub current_vmc_id: Option<String>,
    #[serde(default)]
    pub personhood: bool,
    #[serde(default)]
    pub joined_via_invitation: bool,
    /// Community-defined extensions (opaque JSON). A fleet manager can stash
    /// per-member operational state here — e.g. a `fleet_index` — at enrollment.
    #[serde(default)]
    pub extensions: serde_json::Value,
}

/// One page of a cursor-paginated VTC listing. Mirrors the server's
/// `Paginated<T>` (`items` + `nextCursor`); `totalEstimate` is ignored.
///
/// The wire names are camelCase, as R3.1 requires and as the published Trust
/// Task schemas have always said. The server sent `next_cursor` until the
/// conformance witness (#1059) caught it; this mirror had followed the server
/// rather than the schema, so both were wrong together and neither noticed.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<String>,
}

/// A join request in the admin work queue (subset of the VTC's `JoinRequest`).
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestSummary {
    /// The request id (used to approve / reject).
    pub id: String,
    /// The DID applying to join (for a fleet, the VTA being enrolled).
    pub applicant_did: String,
    /// Wire status: `"pending"`, `"approved"`, `"rejected"`, `"withdrawn"`.
    pub status: String,
    pub submitted_at: DateTime<Utc>,
}

/// Outcome of approving or rejecting a join request.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DecideResult {
    pub request_id: String,
    pub status: String,
    /// The issued membership credential (VMC) — present on approve.
    #[serde(default)]
    pub vmc: Option<serde_json::Value>,
    /// The issued role credential (VEC) — present on approve when a role applies.
    #[serde(default)]
    pub role_vec: Option<serde_json::Value>,
}

/// Outcome of removing a member (offboarding). The VTC flips the member's
/// status-list revocation bit as part of removal.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RemoveResult {
    pub did: String,
    /// Wire disposition: `"tombstone"`, `"purge"`, `"historical"`.
    pub disposition: String,
    pub removed: bool,
}

/// Outcome of naming a member a vetter (`POST /vetting/vetters`).
///
/// Granting converges: while the member holds a live grant, asking again
/// returns that grant rather than issuing a second. `created` says which
/// happened, so an operator is not told "granted" about a grant that already
/// stood.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VetterGrant {
    /// `true` when this call issued the grant (HTTP 201), `false` when the
    /// member already held a live one (HTTP 200).
    pub created: bool,
    /// The grant: the `vtc/vetting/vetters/grant/0.1#response` payload.
    pub grant: vetting::vetters::grant::v0_1::Response,
}

/// Outcome of revoking an endorsement (`DELETE /credentials/endorsements/{id}`)
/// — which is how a vetter grant is withdrawn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct EndorsementRevocation {
    /// The revoked endorsement's id.
    pub endorsement_id: String,
    /// The credential the revocation applies to, and when.
    pub revocation: RevocationDetail,
    /// The credential's index on the community's revocation status list.
    pub status_list_index: u32,
}

/// The credential a revocation applies to, and when it took effect.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RevocationDetail {
    /// The revoked credential's `id`.
    pub credential_id: String,
    /// When the revocation took effect (RFC 3339).
    pub revoked_at: String,
}

/// One vetting statement withdrawal notice, as `GET /vetting/revocations`
/// reports it, with the admissions it touches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct VettingRevocation {
    /// The vetter who withdrew the statement.
    pub issuer: String,
    /// The statement's `id`.
    pub statement_id: String,
    /// The statement's `digestMultibase`.
    pub statement_digest_multibase: String,
    /// The vetter's reason, when given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When the community recorded the notice.
    pub recorded_at: DateTime<Utc>,
    /// `needsReview` when a current member was admitted on the statement, else
    /// `noAdmission`.
    pub review_state: String,
    /// Approved join requests that counted the statement.
    #[serde(default)]
    pub affected_join_requests: Vec<String>,
    /// Of their applicants, those who are current members.
    #[serde(default)]
    pub affected_members: Vec<String>,
}

#[derive(Deserialize)]
struct VettingRevocationList {
    revocations: Vec<VettingRevocation>,
}

/// A client bound to one VTC's API base, holding a bearer token once
/// authenticated.
#[derive(Clone)]
pub struct VtcClient {
    http: reqwest::Client,
    /// The VTC API base, including the mount (e.g. `https://vtc.example.com/v1`),
    /// trailing slash trimmed.
    base_url: String,
    /// The VTC's own DID (the authentication audience / DIDComm recipient).
    vtc_did: String,
    /// Bearer access token, set after [`connect`](Self::connect).
    token: Option<String>,
    /// The operator's own key, held by a client built with
    /// [`connect`](Self::connect).
    ///
    /// The admin verbs whose tasks the VTC serves as signed documents are sent
    /// signed with it, and **only** that way: a client holding a key does not
    /// fall back to the bearer route, even against a VTC too old to serve the
    /// document. The VTC reads the signer's own ACL entry, so this is the
    /// operator acting as themselves — no delegation is involved. A client
    /// built from a token alone ([`with_token`](Self::with_token)) has no key
    /// and keeps using the bearer routes.
    ///
    /// Never printed: `VtcClient`'s `Debug` reports only whether one is held.
    signer: Option<HolderKey>,
    /// A messaging session to the VTC, when this client has one.
    ///
    /// Present only on a client built by [`connect_didcomm`](Self::connect_didcomm)
    /// or [`connect_tsp`](Self::connect_tsp). When it is set, the **holder
    /// verbs** — the ones the VTC routes by document `type` rather than by URL —
    /// go over it instead of to `POST {base}/trust-tasks`. The admin verbs keep
    /// using HTTPS regardless: they are gated on a bearer token and a
    /// `Trust-Task` header, which is a URL-shaped surface.
    ///
    /// A `VtaClient` rather than a session of our own, and the name is the only
    /// awkward part: that type is the SDK's *Trust-Task* client and the peer it
    /// addresses is whatever DID it was connected to. Pointing it at a VTC gets
    /// session setup, `thid` demultiplexing, retry under one idempotency key and
    /// reply-proof verification for free — four things this crate would
    /// otherwise own a second, drifting copy of.
    #[cfg(feature = "didcomm")]
    documents: Option<vta_sdk::client::VtaClient>,
}

/// Written by hand rather than derived, for two reasons.
///
/// The first is required: [`vta_sdk::client::VtaClient`] is not `Debug`, so a
/// derive stops compiling the moment a session is held.
///
/// The second is the one worth keeping. The derive printed `token` — the bearer
/// token, in full, into anything that formatted this struct: a `tracing` field,
/// a test failure, an `unwrap` on an enclosing type. A credential that reaches a
/// log is a credential that has left, and nothing about the derive said so. The
/// presence of a token is worth reporting; its value never is.
impl std::fmt::Debug for VtcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = f.debug_struct("VtcClient");
        out.field("base_url", &self.base_url)
            .field("vtc_did", &self.vtc_did)
            .field("authenticated", &self.token.is_some());
        #[cfg(feature = "didcomm")]
        out.field("session", &self.documents.is_some());
        out.finish()
    }
}

impl VtcClient {
    /// Authenticate to the VTC as `client_did` (challenge-response, reusing the
    /// VTA SDK's audience-agnostic flow) and return a ready client.
    ///
    /// `base_url` is the full API base including the mount (e.g.
    /// `https://vtc.example.com/v1`); `vtc_did` is the community's DID.
    pub async fn connect(
        base_url: &str,
        vtc_did: &str,
        client_did: &str,
        private_key_multibase: &str,
    ) -> Result<Self, VtcError> {
        // Finite request + connect timeouts (R1.2) — `reqwest::Client::new()`
        // has neither, so a blackholed VTC would hang an operator forever.
        let http = vta_sdk::http::rest_client();
        let base_url = base_url.trim_end_matches('/').to_string();
        // The same key signs the admin verbs that have a signed binding. Built
        // first, so a key that cannot sign fails here rather than on the first
        // admin call.
        let signer = HolderKey::from_did_key(client_did, private_key_multibase)
            .map_err(|e| VtcError::Signing(e.to_string()))?;
        let auth = vta_sdk::auth_light::challenge_response_light(
            &http,
            &base_url,
            client_did,
            private_key_multibase,
            vtc_did,
        )
        .await?;
        Ok(Self {
            http,
            base_url,
            vtc_did: vtc_did.to_string(),
            token: Some(auth.access_token),
            signer: Some(signer),
            #[cfg(feature = "didcomm")]
            documents: None,
        })
    }

    /// Construct a client from an already-obtained bearer token (e.g. a token
    /// minted out of band, or for testing). `base_url` includes the mount.
    pub fn with_token(base_url: &str, vtc_did: &str, token: impl Into<String>) -> Self {
        Self {
            http: vta_sdk::http::rest_client(),
            base_url: base_url.trim_end_matches('/').to_string(),
            vtc_did: vtc_did.to_string(),
            token: Some(token.into()),
            signer: None,
            #[cfg(feature = "didcomm")]
            documents: None,
        }
    }

    /// Construct a client with **no** bearer token, for the applicant side of
    /// the join ceremony.
    ///
    /// [`submit_join`](Self::submit_join) authenticates with the document's own
    /// holder proof, so an applicant — who is by definition not yet a member and
    /// has no token to get — needs exactly this. Every other method returns
    /// [`VtcError::NotAuthenticated`], which is the honest answer rather than a
    /// 401 from the server.
    ///
    /// `vtc_did` still matters: it is the audience the submitted document is
    /// addressed to, and the VTC rejects a document addressed elsewhere.
    pub fn anonymous(base_url: &str, vtc_did: &str) -> Self {
        Self {
            http: vta_sdk::http::rest_client(),
            base_url: base_url.trim_end_matches('/').to_string(),
            vtc_did: vtc_did.to_string(),
            token: None,
            signer: None,
            #[cfg(feature = "didcomm")]
            documents: None,
        }
    }

    /// Reach the VTC over a mediated **DIDComm** session rather than a URL.
    ///
    /// `client_did` is the identity the holder verbs will be attributed to —
    /// for a persona minted by a VTA, its `did:webvh`. It may be any DID method:
    /// over a session the VTC takes the *authcrypt sender* as the proven holder
    /// and never looks at a document proof, so nothing here has to be a
    /// `did:key` (`vtc-service/src/trust_tasks/mod.rs::resolve_holder` short-
    /// circuits on `sender_did`).
    ///
    /// `rest_url` is the HTTPS base, and stays optional but useful. The admin
    /// verbs the VTC serves as signed documents ride the session like the
    /// holder verbs do; the rest are token-and-header gated on a URL surface,
    /// so a client built with `None` here answers those with
    /// [`VtcError::NoRestTransport`]. Passing the base gives one client that can
    /// do both.
    #[cfg(feature = "didcomm")]
    pub async fn connect_didcomm(
        client_did: &str,
        private_key_multibase: &str,
        vtc_did: &str,
        mediator_did: &str,
        rest_url: Option<&str>,
    ) -> Result<Self, VtcError> {
        let documents = vta_sdk::client::VtaClient::connect_didcomm(
            client_did,
            private_key_multibase,
            vtc_did,
            mediator_did,
            None,
        )
        .await
        .map_err(|e| VtcError::Session(e.to_string()))?;
        Ok(Self::over_session(documents, vtc_did, rest_url))
    }

    /// The same, over **TSP**, for a community that advertises `#tsp`.
    ///
    /// A separate constructor rather than a flag because the choice is the
    /// community's, not the caller's: a VTC that does not advertise `#tsp`
    /// cannot answer here, and the caller is expected to have discovered that
    /// before choosing. The ceremony is identical either way — the same Trust
    /// Task document, addressed to the same audience — so this changes the wire
    /// and nothing else.
    #[cfg(feature = "tsp")]
    pub async fn connect_tsp(
        client_did: &str,
        private_key_multibase: &str,
        vtc_did: &str,
        mediator_did: &str,
        rest_url: Option<&str>,
    ) -> Result<Self, VtcError> {
        let documents = vta_sdk::client::VtaClient::connect_tsp(
            client_did,
            private_key_multibase,
            vtc_did,
            mediator_did,
            None,
        )
        .await
        .map_err(|e| VtcError::Session(e.to_string()))?;
        Ok(Self::over_session(documents, vtc_did, rest_url))
    }

    /// Wrap a connected session. One place to build the pairing, so a further
    /// `connect_*` variant cannot forget the REST half.
    #[cfg(feature = "didcomm")]
    fn over_session(
        documents: vta_sdk::client::VtaClient,
        vtc_did: &str,
        rest_url: Option<&str>,
    ) -> Self {
        Self {
            http: vta_sdk::http::rest_client(),
            base_url: rest_url
                .unwrap_or_default()
                .trim_end_matches('/')
                .to_string(),
            vtc_did: vtc_did.to_string(),
            token: None,
            signer: None,
            documents: Some(documents),
        }
    }

    /// The community's DID this client is bound to.
    pub fn vtc_did(&self) -> &str {
        &self.vtc_did
    }

    /// Start a request carrying the route's `Trust-Task` URL header and the
    /// bearer token.
    ///
    /// Every authenticated call goes through here. The VTC rejects a request
    /// with no `Trust-Task` header (400) before any handler sees it, so a
    /// method that builds its request by hand is broken on arrival — which is
    /// how every method in this client came to be.
    fn tt(
        &self,
        method: reqwest::Method,
        url: impl reqwest::IntoUrl,
        task: &str,
    ) -> Result<reqwest::RequestBuilder, VtcError> {
        // Said here rather than at each call site, because every admin verb
        // reaches the URL surface through this one helper. A client built for a
        // session and given no REST base would otherwise request against an
        // empty base and fail as a malformed URL — a fault that reads as a bug
        // in this crate rather than as a missing argument at the constructor.
        if self.base_url.is_empty() {
            return Err(VtcError::NoRestTransport("this verb"));
        }
        let token = self.token()?;
        Ok(self
            .http
            .request(method, url)
            .header("Trust-Task", task)
            .bearer_auth(token))
    }

    /// Send an admin verb as a Trust Task document, when this client can.
    ///
    /// Answers `Some(payload)` — the `#response` document's payload — when the
    /// verb went as a document, and `None` when this client holds neither a
    /// session nor a key, so the caller uses the task's bearer route.
    ///
    /// - **Over a session** the document goes on it, signed by the session's
    ///   own key, exactly as the holder verbs do.
    /// - **With a key** ([`connect`](Self::connect)) it is signed as the
    ///   operator and posted to `POST {base}/trust-tasks`. There is no fallback
    ///   from here to the bearer route: a VTC that answers `unsupportedType`
    ///   predates the task's signed binding, and that is reported as it is.
    ///
    /// `declared` is the task's declared error codes, so a refusal the VTC
    /// marks as "no such resource" becomes [`VtcError::NotFound`] on this path
    /// as it does on the bearer route. `max_bytes` bounds the reply read over
    /// HTTPS.
    async fn admin_document(
        &self,
        type_uri: &str,
        payload: serde_json::Value,
        declared: &[trust_tasks_rs::DeclaredErrorCode],
        max_bytes: usize,
    ) -> Result<Option<serde_json::Value>, VtcError> {
        #[cfg(feature = "didcomm")]
        if let Some(documents) = &self.documents {
            return documents
                .dispatch_trust_task(type_uri, payload, SESSION_TIMEOUT_SECS)
                .await
                .map(Some)
                .map_err(|e| VtcError::Session(e.to_string()));
        }
        let Some(key) = &self.signer else {
            return Ok(None);
        };
        if self.base_url.is_empty() {
            return Err(VtcError::NoRestTransport("this verb"));
        }
        let doc =
            vta_sdk::trust_task_sign::build_signed_with(type_uri, payload, key, &self.vtc_did)
                .await
                .map_err(|e| VtcError::Signing(e.to_string()))?;
        self.post_document(doc, declared, max_bytes).await.map(Some)
    }

    /// POST a signed document to the VTC's document endpoint and return the
    /// `#response` document's payload.
    ///
    /// The endpoint takes no `Trust-Task` header — the document's own `type` is
    /// the identity, which is exactly why one mount serves every verb bound
    /// there. A refusal is a `trust-task-error` document; its payload's `code`
    /// and `message` are what the caller sees. The reply is read under
    /// `max_bytes`, as every body this client reads is.
    async fn post_document(
        &self,
        doc: String,
        declared: &[trust_tasks_rs::DeclaredErrorCode],
        max_bytes: usize,
    ) -> Result<serde_json::Value, VtcError> {
        let resp = self
            .http
            .post(format!("{}/trust-tasks", self.base_url))
            .header("content-type", "application/json")
            .body(doc)
            .send()
            .await?;
        let status = resp.status().as_u16();
        let bytes = vta_sdk::http::read_body_capped(resp, max_bytes)
            .await
            .map_err(|e| VtcError::Http {
                status,
                body: e.to_string(),
            })?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let response_doc: trust_tasks_rs::TrustTask<serde_json::Value> =
            match serde_json::from_str(&text) {
                Ok(d) => d,
                Err(e) if (200..300).contains(&status) => {
                    return Err(VtcError::Http {
                        status,
                        body: format!(
                            "unexpected response (not a Trust Task document): {e}: {text}"
                        ),
                    });
                }
                Err(_) => return Err(VtcError::Http { status, body: text }),
            };
        if (200..300).contains(&status) {
            return Ok(response_doc.payload);
        }
        Err(document_error(
            status,
            &response_doc.payload,
            text,
            declared,
        ))
    }

    /// List every community member, optionally filtered by `role`, following the
    /// cursor to completion. Requires an admin token. This is the fleet roster
    /// when the community's members are managed VTAs.
    pub async fn list_members(&self, role: Option<&str>) -> Result<Vec<MemberRecord>, VtcError> {
        let mut out: Vec<MemberRecord> = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let mut params: Vec<(&str, &str)> = Vec::new();
            if let Some(role) = role {
                params.push(("role", role));
            }
            if let Some(cursor) = &cursor {
                params.push(("cursor", cursor.as_str()));
            }
            let url =
                reqwest::Url::parse_with_params(&format!("{}/members", self.base_url), &params)
                    .map_err(|e| VtcError::Url(e.to_string()))?;

            let resp = self
                .tt(reqwest::Method::GET, url, task::MEMBERS_LIST)?
                .send()
                .await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(VtcError::Http { status, body });
            }

            let page: Page<MemberRecord> = resp.json().await?;
            out.extend(page.items);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok(out)
    }

    /// List join requests (the admin work queue), optionally filtered by
    /// `status` (e.g. `"pending"`). Requires an admin token. For a fleet, these
    /// are VTAs awaiting enrollment.
    pub async fn list_join_requests(
        &self,
        status: Option<&str>,
    ) -> Result<Vec<JoinRequestSummary>, VtcError> {
        let mut out: Vec<JoinRequestSummary> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut params: Vec<(&str, &str)> = Vec::new();
            if let Some(status) = status {
                params.push(("status", status));
            }
            if let Some(cursor) = &cursor {
                params.push(("cursor", cursor.as_str()));
            }
            let url = reqwest::Url::parse_with_params(
                &format!("{}/join-requests", self.base_url),
                &params,
            )
            .map_err(|e| VtcError::Url(e.to_string()))?;

            let resp = self
                .tt(reqwest::Method::GET, url, task::JOIN_REQUESTS_LIST)?
                .send()
                .await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(VtcError::Http { status, body });
            }
            let page: Page<JoinRequestSummary> = resp.json().await?;
            out.extend(page.items);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok(out)
    }

    /// Approve a join request — admit the applicant and issue its membership
    /// credential (VMC). Requires an admin token. For a fleet, this enrolls a
    /// VTA that has applied to join.
    pub async fn approve_join(&self, request_id: &str) -> Result<DecideResult, VtcError> {
        self.decide(request_id, "approved", None).await
    }

    /// Reject a join request, optionally recording an operator rationale in the
    /// audit trail. Requires an admin token.
    pub async fn reject_join(
        &self,
        request_id: &str,
        reason: Option<&str>,
    ) -> Result<DecideResult, VtcError> {
        self.decide(request_id, "rejected", reason).await
    }

    /// `POST /join-requests/{id}/decide` with `{ decision, reason? }`.
    ///
    /// The VTC previously exposed a `/approve` + `/reject` mount pair; both were
    /// retired in favour of this single endpoint carrying the decision in the
    /// body, and the old mounts are **gone** — this client was still posting to
    /// them, so approve and reject were 404s independent of the missing header.
    /// `decision` is the server's `Decision` enum on the wire (`approved` /
    /// `rejected`), not the imperative verb the old paths used.
    async fn decide(
        &self,
        request_id: &str,
        decision: &str,
        reason: Option<&str>,
    ) -> Result<DecideResult, VtcError> {
        let mut document = serde_json::json!({ "id": request_id, "decision": decision });
        if let Some(reason) = reason {
            document["reason"] = serde_json::json!(reason);
        }
        if let Some(payload) = self
            .admin_document(
                task::JOIN_REQUESTS_DECIDE,
                document,
                &[],
                MAX_DOCUMENT_RESPONSE_BYTES,
            )
            .await?
        {
            return decode_payload(payload, "decide");
        }

        let url = format!("{}/join-requests/{request_id}/decide", self.base_url);
        let mut body = serde_json::json!({ "decision": decision });
        if let Some(reason) = reason {
            body["reason"] = serde_json::json!(reason);
        }
        let resp = self
            .tt(reqwest::Method::POST, url, task::JOIN_REQUESTS_DECIDE)?
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtcError::Http { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Remove a member (offboarding). The VTC applies its removal disposition and
    /// flips the member's status-list revocation bit. `reason` is an optional
    /// admin note. Requires an admin token. For a fleet, this decommissions a
    /// managed VTA.
    pub async fn remove_member(
        &self,
        did: &str,
        reason: Option<&str>,
    ) -> Result<RemoveResult, VtcError> {
        let mut document = serde_json::json!({ "did": did });
        if let Some(reason) = reason {
            document["reason"] = serde_json::json!(reason);
        }
        if let Some(payload) = self
            .admin_document(
                task::MEMBERS_ADMIN_REMOVE,
                document,
                &[],
                MAX_DOCUMENT_RESPONSE_BYTES,
            )
            .await?
        {
            return decode_payload(payload, "admin-remove");
        }

        let url = format!("{}/members/{did}", self.base_url);
        let mut req = self.tt(reqwest::Method::DELETE, url, task::MEMBERS_ADMIN_REMOVE)?;
        if let Some(reason) = reason {
            req = req.json(&serde_json::json!({ "reason": reason }));
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtcError::Http { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Update a member's community-defined `extensions` (opaque JSON) via
    /// `PATCH /members/{did}`. A fleet manager records per-member operational
    /// state here — e.g. the assigned `fleet_index` at enrollment, which the
    /// roster then carries (see [`MemberRecord::extensions`]). Admin token.
    pub async fn update_member_extensions(
        &self,
        did: &str,
        extensions: serde_json::Value,
    ) -> Result<(), VtcError> {
        if self
            .admin_document(
                task::MEMBERS_UPDATE,
                serde_json::json!({ "did": did, "extensions": extensions }),
                &[],
                MAX_DOCUMENT_RESPONSE_BYTES,
            )
            .await?
            .is_some()
        {
            return Ok(());
        }

        let resp = self
            .tt(
                reqwest::Method::PATCH,
                format!("{}/members/{did}", self.base_url),
                task::MEMBERS_UPDATE,
            )?
            .json(&serde_json::json!({ "extensions": extensions }))
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtcError::Http { status, body });
        }
        Ok(())
    }

    /// Submit a join request (the applicant side): sign a
    /// `join-requests/submit/0.1` Trust Task with the applicant's holder key and
    /// post it to the document endpoint. Returns the community's verdict —
    /// auto-admit carries the issued VMC + role VEC inline, otherwise the
    /// request is queued for an admin.
    ///
    /// **No bearer token.** The document's `eddsa-jcs-2022` proof *is* the
    /// authentication: the VTC takes the proof's `verificationMethod` DID as the
    /// applicant and requires the document `issuer` to match it
    /// (`vtc-service/src/trust_tasks/mod.rs::resolve_holder`). So this is the
    /// one method that works on a client built with neither
    /// [`connect`](Self::connect) nor [`with_token`](Self::with_token) — an
    /// applicant is by definition not yet a member.
    ///
    /// `applicant_did` is a `did:key` whose seed is `private_key_multibase`. It
    /// is the DID that becomes the member on admission, *not* whatever identity
    /// this client may hold a token for — a fleet manager submitting on behalf
    /// of a VTA signs with that VTA's key.
    ///
    /// **A holder on any other DID method uses
    /// [`submit_join_as`](Self::submit_join_as).** This method's `did:key`
    /// restriction is a property of *this signature* — it derives the
    /// verification method from the identifier — and not of the server, which
    /// resolves the proof's `verificationMethod` through a DID resolver and has
    /// accepted `did:webvh` since the vm-resolver work. A `did:webvh` persona is
    /// the normal case for a holder minted by a VTA, so it must not have to
    /// borrow a `did:key` to join.
    ///
    /// The document is addressed to [`vtc_did`](Self::vtc_did) (SPEC §4.8.2
    /// audience binding), so a signed submit captured from one community cannot
    /// be replayed into another.
    ///
    /// ## Why the key, and not just a body
    ///
    /// This used to POST the VP-framed body to `POST /join-requests`, a route
    /// that no longer exists — the holder-facing join verbs (`submit`/`request`,
    /// `manifest`, `status`) were folded into the single Trust-Task document
    /// endpoint, routed by document `type`. That fold moved the applicant's
    /// authentication from "a signature somewhere inside the body" to "a proof
    /// over the whole document", which is why this signature grew the key.
    pub async fn submit_join(
        &self,
        body: &join_requests::JoinRequestSubmitBody,
        applicant_did: &str,
        private_key_multibase: &str,
    ) -> Result<join_requests::VerdictResponse, VtcError> {
        let key = HolderKey::from_did_key(applicant_did, private_key_multibase)
            .map_err(|e| VtcError::Signing(e.to_string()))?;
        self.submit_join_as(body, &key).await
    }

    /// Submit a join request signed by a holder of **any** DID method.
    ///
    /// The general form of [`submit_join`](Self::submit_join), which is now a
    /// `did:key` convenience wrapper over it. Everything that method's
    /// documentation says about tokens, audience binding and which DID becomes
    /// the member applies here unchanged; the only difference is that the
    /// verification method is named rather than derived.
    ///
    /// A [`HolderKey`] names the verification method the proof will carry — for
    /// a `did:webvh` persona, `did:webvh:<scid>:example.com:glenn#key-0`. The
    /// server takes that method's DID as the applicant, so the key must be one
    /// the holder's *published document* names: a proof this client signs
    /// happily is still refused if the document does not carry the method.
    pub async fn submit_join_as(
        &self,
        body: &join_requests::JoinRequestSubmitBody,
        key: &HolderKey,
    ) -> Result<join_requests::VerdictResponse, VtcError> {
        let payload = serde_json::to_value(body)
            .map_err(|e| VtcError::Url(format!("serialise submit payload: {e}")))?;

        // Over a session the envelope proves the sender, so the VTC never reads
        // a document proof and the holder key is not needed at all — see
        // `resolve_holder`, which short-circuits on `sender_did`. The document
        // still carries its audience binding, which is what stops a submit
        // captured from one community being replayed into another.
        #[cfg(feature = "didcomm")]
        if let Some(documents) = &self.documents {
            let value = documents
                .dispatch_trust_task(
                    join_requests::JOIN_REQUEST_SUBMIT_TYPE,
                    payload,
                    SESSION_TIMEOUT_SECS,
                )
                .await
                .map_err(|e| VtcError::Session(e.to_string()))?;
            return serde_json::from_value(value).map_err(|e| VtcError::Http {
                status: 200,
                body: format!("unexpected submit verdict: {e}"),
            });
        }

        let doc = vta_sdk::trust_task_sign::build_signed_with(
            join_requests::JOIN_REQUEST_SUBMIT_TYPE,
            payload,
            key,
            &self.vtc_did,
        )
        .await
        .map_err(|e| VtcError::Signing(e.to_string()))?;

        // A Trust-Task request is answered with a `#response` document whose
        // payload is the verdict.
        let payload = self
            .post_document(doc, &[], MAX_DOCUMENT_RESPONSE_BYTES)
            .await?;
        serde_json::from_value(payload).map_err(|e| VtcError::Http {
            status: 200,
            body: format!("submit response payload is not a VerdictResponse: {e}"),
        })
    }

    /// List the community's policies (opaque JSON descriptors). Admin token.
    pub async fn list_policies(&self) -> Result<Vec<serde_json::Value>, VtcError> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut params: Vec<(&str, &str)> = Vec::new();
            if let Some(cursor) = &cursor {
                params.push(("cursor", cursor.as_str()));
            }
            let url =
                reqwest::Url::parse_with_params(&format!("{}/policies", self.base_url), &params)
                    .map_err(|e| VtcError::Url(e.to_string()))?;
            let resp = self
                .tt(reqwest::Method::GET, url, task::POLICY_LIST)?
                .send()
                .await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(VtcError::Http { status, body });
            }
            let page: Page<serde_json::Value> = resp.json().await?;
            out.extend(page.items);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok(out)
    }

    /// The membership pair's **bodies** for one member
    /// (`vtc/members/credentials/0.1`, over `GET /members/{did}/credentials`).
    /// Admin token.
    ///
    /// [`list_members`](Self::list_members) answers "who is a member" with
    /// identifiers; this answers "what did the community issue this member,
    /// and what did they acknowledge": the membership credential, the role
    /// credential, the member-issued acknowledgement, and whether that
    /// acknowledgement's digest was verified against the grant. A member who
    /// holds no credentials is a success with every document absent, not an
    /// error.
    ///
    /// # Errors
    ///
    /// [`VtcError::NotFound`] carrying `vtc/members/credentials:notFound` when
    /// the community has no member with this DID. A 404 without that code
    /// stays [`VtcError::Http`] (see [`VtcError::NotFound`]).
    pub async fn member_credentials(
        &self,
        did: &str,
    ) -> Result<members_credentials::Response, VtcError> {
        if let Some(payload) = self
            .admin_document(
                task::MEMBERS_CREDENTIALS,
                serde_json::json!({ "did": did }),
                members_credentials::ERROR_CODES,
                MAX_DOCUMENT_RESPONSE_BYTES,
            )
            .await?
        {
            return decode_payload(payload, "members/credentials");
        }

        let url = self.api_url(&["members", did, "credentials"])?;
        let resp = self
            .tt(reqwest::Method::GET, url, task::MEMBERS_CREDENTIALS)?
            .send()
            .await?;
        let resp = expect_success_declaring(resp, members_credentials::ERROR_CODES).await?;
        Ok(resp.json().await?)
    }

    /// Fetch one policy by id (opaque JSON, incl. the Rego source). Admin token.
    pub async fn get_policy(&self, id: &str) -> Result<serde_json::Value, VtcError> {
        self.get_json(&format!("policies/{id}"), task::POLICY_GET)
            .await
    }

    /// Upload a new Rego policy module for `purpose` (`"join"`, `"removal"`,
    /// …) — `policy/upsert/0.2`. Returns the `policy/upsert` response
    /// (`{ policy, created }`, with the id, version and source hash on
    /// `policy`). Admin token. Upload alone does not activate it — call
    /// [`activate_policy`](Self::activate_policy).
    ///
    /// The body is the generated [`policy_upsert::Payload`]: `name` (the
    /// purpose, as the admin console names modules), `module` (the Rego
    /// source) and the purpose again under `ext`
    /// ([`POLICY_PURPOSE_EXT_KEY`]), which is where a VTC reads it. A payload
    /// the schema refuses is [`VtcError::InvalidPayload`], before any request.
    pub async fn upload_policy(
        &self,
        purpose: &str,
        rego_source: &str,
    ) -> Result<serde_json::Value, VtcError> {
        let payload = policy_upload_payload(purpose, rego_source)?;
        let body =
            serde_json::to_value(&payload).map_err(|e| VtcError::InvalidPayload(e.to_string()))?;
        self.post_json("policies", task::POLICY_UPSERT, &body).await
    }

    /// Activate a previously-uploaded policy (make it live for decisions of its
    /// purpose). Admin token.
    pub async fn activate_policy(&self, id: &str) -> Result<serde_json::Value, VtcError> {
        self.post_json(
            &format!("policies/{id}/activate"),
            task::POLICY_ACTIVATE,
            &serde_json::json!({}),
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Peer identity vetting — the community-admin surface
    // -----------------------------------------------------------------------

    /// Every vetter grant, newest first (`GET /vetting/vetters`). Admin token.
    ///
    /// Each row carries the member, validity, revocation, whether it is live,
    /// whether an admin or the automatic sweep issued it, and the vetter's
    /// profile summary.
    pub async fn list_vetter_grants(&self) -> Result<vetting::VetterGrantListResponse, VtcError> {
        let url = self.api_url(&["vetting", "vetters"])?;
        let resp = self.untasked(reqwest::Method::GET, url)?.send().await?;
        Ok(expect_success(resp).await?.json().await?)
    }

    /// Install a delivered log for the community's own self-hosted DID
    /// (`did-management/did/register/0.1`, over `POST /admin/did/register`).
    /// Super-admin token.
    ///
    /// `register` carries the DID's complete `did:webvh` log as `didData`, at
    /// `path: ".well-known"` — the one slot a self-hosted community serves.
    /// The log is typically fetched from the VTA that holds the DID's keys
    /// with `pnm did-mgmt dids get-log`. The community verifies every entry,
    /// refuses a log that drops or rewrites one it serves, and serves the
    /// result at once; re-sending the log already served changes nothing. A
    /// community whose DID has a path is on a DID host, which gets new entries
    /// from the VTA directly, and is refused here.
    pub async fn install_did_log(
        &self,
        register: &did_register::v0_1::Payload,
    ) -> Result<did_register::v0_1::Response, VtcError> {
        let url = self.api_url(&["admin", "did", "register"])?;
        let resp = self
            .tt(
                reqwest::Method::POST,
                url,
                <did_register::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            )?
            .json(register)
            .send()
            .await?;
        Ok(expect_success(resp).await?.json().await?)
    }

    /// Name a current member a vetter (`vtc/vetting/vetters/grant/0.1`, over
    /// `POST /vetting/vetters`). Admin token.
    ///
    /// `grant` is the task's payload: `validitySeconds` is one day to two
    /// years, and absent takes the community's default of one year. A member
    /// already holding a live grant gets that grant back with
    /// [`VetterGrant::created`] `false`.
    pub async fn grant_vetter(
        &self,
        grant: &vetting::vetters::grant::v0_1::Payload,
    ) -> Result<VetterGrant, VtcError> {
        let url = self.api_url(&["vetting", "vetters"])?;
        let resp = self
            .tt(reqwest::Method::POST, url, task::VETTING_VETTERS_GRANT)?
            .json(grant)
            .send()
            .await?;
        let resp = expect_success(resp).await?;
        let created = resp.status() == reqwest::StatusCode::CREATED;
        Ok(VetterGrant {
            created,
            grant: resp.json().await?,
        })
    }

    /// One vetter's grant status by DID (`vtc/vetting/vetters/show/0.1`, over
    /// `POST /vetting/vetters/show`). Admin token.
    ///
    /// This is the question the grant listing cannot answer: a vetter who never
    /// published a profile and one whose grant was revoked are both simply
    /// absent from it. `status` separates them — `live`, `revoked`, `expired`
    /// or `none` — and for a live grant, `listed` says whether the vetter
    /// chose to appear in the directory.
    ///
    /// `none` is an answer, not a failure: it means this community holds no
    /// vetter grant for that DID, and deliberately says nothing about whether
    /// the DID is a member.
    ///
    /// A `live` answer is a reading at a moment, not evidence: a grant can be
    /// revoked a second later, and eligibility is proven by the vetter's own
    /// credential in `vetting/request`.
    pub async fn show_vetter(
        &self,
        vetter_did: &str,
    ) -> Result<vetting::vetters::show::v0_1::Response, VtcError> {
        let url = self.api_url(&["vetting", "vetters", "show"])?;
        let resp = self
            .tt(reqwest::Method::POST, url, task::VETTING_VETTERS_SHOW)?
            .json(&serde_json::json!({ "vetterDid": vetter_did }))
            .send()
            .await?;
        Ok(expect_success(resp).await?.json().await?)
    }

    /// Revoke an endorsement by id (`vtc/endorsements/revoke/0.1`, over
    /// `DELETE /credentials/endorsements/{id}`) — how a vetter grant is
    /// withdrawn. Admin token. Revoking a grant also deletes the vetter's
    /// profile.
    pub async fn revoke_endorsement(
        &self,
        endorsement_id: &str,
    ) -> Result<EndorsementRevocation, VtcError> {
        let url = self.api_url(&["credentials", "endorsements", endorsement_id])?;
        let resp = self
            .tt(reqwest::Method::DELETE, url, task::ENDORSEMENTS_REVOKE)?
            .send()
            .await?;
        Ok(expect_success(resp).await?.json().await?)
    }

    /// Deliver a vetter's live grant credential again
    /// (`vtc/vetting/vetters/resend/0.1`, over
    /// `POST /vetting/vetters/{memberDid}/resend`). Admin token.
    ///
    /// Success means the community handed the credential to its messaging
    /// transport — not that the member's wallet has it. A member with no live
    /// grant is a 404; a transport that would not take the delivery is a 503.
    pub async fn resend_vetter_grant(
        &self,
        member_did: &str,
    ) -> Result<vetting::vetters::resend::v0_1::Response, VtcError> {
        let url = self.api_url(&["vetting", "vetters", member_did, "resend"])?;
        let resp = self
            .tt(reqwest::Method::POST, url, task::VETTING_VETTERS_RESEND)?
            .send()
            .await?;
        Ok(expect_success(resp).await?.json().await?)
    }

    /// The automatic vetter-grant configuration and the last sweep
    /// (`GET /vetting/auto-grant`). Admin token.
    pub async fn auto_grant(&self) -> Result<vetting::AutoGrantStatus, VtcError> {
        let url = self.api_url(&["vetting", "auto-grant"])?;
        let resp = self.untasked(reqwest::Method::GET, url)?.send().await?;
        Ok(expect_success(resp).await?.json().await?)
    }

    /// Replace the automatic vetter-grant configuration
    /// (`PUT /vetting/auto-grant`). Admin token. An absent member takes its
    /// default, so read the current configuration first to change one value.
    pub async fn configure_auto_grant(
        &self,
        config: &vetting::AutoGrantConfig,
    ) -> Result<vetting::AutoGrantStatus, VtcError> {
        let url = self.api_url(&["vetting", "auto-grant"])?;
        let resp = self
            .untasked(reqwest::Method::PUT, url)?
            .json(config)
            .send()
            .await?;
        Ok(expect_success(resp).await?.json().await?)
    }

    /// How the community presents itself to an applicant's client
    /// (`GET /community/branding`) — the join manifest 0.2 `branding`. Admin
    /// token.
    pub async fn branding(
        &self,
    ) -> Result<join_requests::manifest::v0_2::CommunityBranding, VtcError> {
        let url = self.api_url(&["community", "branding"])?;
        let resp = self.untasked(reqwest::Method::GET, url)?.send().await?;
        Ok(expect_success(resp).await?.json().await?)
    }

    /// Replace the community's branding (`PUT /community/branding`) and return
    /// what was stored. Admin token. Every member is optional; an absent member
    /// is cleared.
    pub async fn set_branding(
        &self,
        branding: &join_requests::manifest::v0_2::CommunityBranding,
    ) -> Result<join_requests::manifest::v0_2::CommunityBranding, VtcError> {
        let url = self.api_url(&["community", "branding"])?;
        let resp = self
            .untasked(reqwest::Method::PUT, url)?
            .json(branding)
            .send()
            .await?;
        Ok(expect_success(resp).await?.json().await?)
    }

    /// What the community asks an applicant to tell it about themselves
    /// (`GET /community/requested-attributes`) — the join manifest 0.2
    /// `requestedAttributes`. Admin token.
    pub async fn requested_attributes(
        &self,
    ) -> Result<Vec<join_requests::manifest::v0_2::ResponseRequestedAttributesItem>, VtcError> {
        let url = self.api_url(&["community", "requested-attributes"])?;
        let resp = self.untasked(reqwest::Method::GET, url)?.send().await?;
        Ok(expect_success(resp).await?.json().await?)
    }

    /// Replace what the community asks applicants to tell it
    /// (`PUT /community/requested-attributes`). Admin token. An empty list asks
    /// for nothing.
    pub async fn set_requested_attributes(
        &self,
        requested: &[join_requests::manifest::v0_2::ResponseRequestedAttributesItem],
    ) -> Result<Vec<join_requests::manifest::v0_2::ResponseRequestedAttributesItem>, VtcError> {
        let url = self.api_url(&["community", "requested-attributes"])?;
        let resp = self
            .untasked(reqwest::Method::PUT, url)?
            .json(requested)
            .send()
            .await?;
        Ok(expect_success(resp).await?.json().await?)
    }

    /// Every vetting statement withdrawal notice, newest first, with the
    /// admissions each touches (`GET /vetting/revocations`). Admin token.
    pub async fn vetting_revocations(&self) -> Result<Vec<VettingRevocation>, VtcError> {
        let url = self.api_url(&["vetting", "revocations"])?;
        let resp = self.untasked(reqwest::Method::GET, url)?.send().await?;
        let list: VettingRevocationList = expect_success(resp).await?.json().await?;
        Ok(list.revocations)
    }

    // -----------------------------------------------------------------------
    // Audit and backup — the super-admin surface `cnm audit` / `cnm backup`
    // drive
    // -----------------------------------------------------------------------

    /// Walk the community's audit hash chain and its signed checkpoints
    /// (`audit/verify/0.1`, over `GET /audit/verify`). Super-admin token.
    ///
    /// Returns the report as the VTC sends it (`verified`, `entriesExamined`,
    /// `checkpoints`, `chainBreak`, …). A `200` is a report, not a pass: read
    /// `verified` and `checkpoints.status`.
    pub async fn audit_verify(&self) -> Result<serde_json::Value, VtcError> {
        let url = self.api_url(&["audit", "verify"])?;
        let resp = self
            .tt(reqwest::Method::GET, url, task::AUDIT_VERIFY)?
            .send()
            .await?;
        read_json_capped(expect_success(resp).await?, MAX_AUDIT_VERIFY_RESPONSE_BYTES).await
    }

    /// Export the community's state as an encrypted `vtc-backup-v1` envelope.
    /// Unrestricted administrator.
    ///
    /// **Over a DIDComm or TSP session only** (a client from
    /// [`connect_didcomm`](Self::connect_didcomm) or
    /// [`connect_tsp`](Self::connect_tsp)). The request carries the backup
    /// password and the reply is the backup it opens, so the VTC refuses both
    /// over REST, where they would exist in plaintext wherever TLS terminates
    /// (trustoverip/dtgwg-trust-tasks-tf#646). The bundle moves with the
    /// `backup/*` chunked transfer: `initiate-export`, one `get-chunk` per
    /// chunk (each checked against its manifest digest), the whole checked
    /// against the committed digest and size, then `complete-export`.
    ///
    /// Returns the **envelope itself** — the object [`import_backup`](Self::import_backup)
    /// takes back — as opaque JSON: it carries the community's signing key, and
    /// a caller only ever saves it or hands it back.
    pub async fn export_backup(
        &self,
        password: &str,
        include_audit: bool,
    ) -> Result<serde_json::Value, VtcError> {
        use trust_tasks_rs::specs::backup::{
            complete_export::v0_1 as complete, get_chunk::v0_1 as get_chunk,
            initiate_export::v0_1 as initiate,
        };
        let bad = |why: String| VtcError::Http {
            status: 200,
            body: why,
        };

        let started = self
            .backup_document(
                <initiate::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                serde_json::json!({
                    "password": password,
                    "includeAudit": include_audit,
                    "algorithm": backup_chunks::ALGORITHM,
                    "maxChunkSize": backup_chunks::CHUNK_SIZE,
                }),
                initiate::ERROR_CODES,
            )
            .await?;
        let d = &started["descriptor"];
        let bundle_id = d["bundleId"]
            .as_str()
            .ok_or_else(|| bad("the export descriptor names no bundle".into()))?
            .to_string();
        let digests: Vec<String> = d["chunks"]["chunkDigests"]
            .as_array()
            .ok_or_else(|| bad("the export descriptor carries no chunk manifest".into()))?
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect();
        let expected_sha = d["expectedSha256"].as_str().unwrap_or_default().to_string();
        let expected_size = d["expectedSizeBytes"].as_u64().unwrap_or(0);
        if expected_size as usize > MAX_BACKUP_RESPONSE_BYTES {
            return Err(bad(format!(
                "the export is {expected_size} bytes, over this client's {MAX_BACKUP_RESPONSE_BYTES}"
            )));
        }

        let mut bytes = Vec::with_capacity(expected_size as usize);
        for (index, digest) in digests.iter().enumerate() {
            let chunk = self
                .backup_document(
                    <get_chunk::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                    serde_json::json!({ "bundleId": bundle_id, "index": index }),
                    get_chunk::ERROR_CODES,
                )
                .await?;
            let data = backup_chunks::decode(chunk["data"].as_str().unwrap_or_default())
                .ok_or_else(|| bad(format!("chunk {index} is not base64url")))?;
            if backup_chunks::digest(&data) != *digest {
                return Err(bad(format!(
                    "chunk {index} does not match the manifest the export committed to"
                )));
            }
            bytes.extend_from_slice(&data);
            if bytes.len() as u64 > expected_size {
                return Err(bad("the chunks exceed the committed size".into()));
            }
        }
        if bytes.len() as u64 != expected_size || backup_chunks::sha256_hex(&bytes) != expected_sha
        {
            return Err(bad(
                "the assembled export does not match the committed digest and size".into(),
            ));
        }
        self.backup_document(
            <complete::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            serde_json::json!({ "bundleId": bundle_id }),
            complete::ERROR_CODES,
        )
        .await?;

        match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(envelope @ serde_json::Value::Object(_)) => Ok(envelope),
            _ => Err(bad("the exported bundle is not a backup envelope".into())),
        }
    }

    /// Restore the community's state from a backup envelope. Unrestricted
    /// administrator. **Over a DIDComm or TSP session only**, as
    /// [`export_backup`](Self::export_backup).
    ///
    /// The envelope is uploaded with the `backup/*` chunked transfer
    /// (`initiate-import`, `put-chunk` per chunk) and applied by
    /// `finalize-import`, which carries the password. With `confirm` false
    /// this is a preview: the VTC decrypts and counts the rows and changes
    /// nothing. With `confirm` true it **replaces** the community's state, and
    /// the reply's `status` is `committed`.
    pub async fn import_backup(
        &self,
        backup: &serde_json::Value,
        password: &str,
        confirm: bool,
    ) -> Result<serde_json::Value, VtcError> {
        use trust_tasks_rs::specs::backup::{
            finalize_import::v0_1 as finalize, initiate_import::v0_1 as initiate,
            put_chunk::v0_1 as put_chunk,
        };
        let bytes = serde_json::to_vec(backup).map_err(|e| VtcError::Http {
            status: 0,
            body: format!("serialise the backup: {e}"),
        })?;
        let chunks: Vec<&[u8]> = bytes.chunks(backup_chunks::CHUNK_SIZE as usize).collect();
        let digests: Vec<String> = chunks.iter().map(|c| backup_chunks::digest(c)).collect();

        let slot = self
            .backup_document(
                <initiate::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                serde_json::json!({
                    "algorithm": backup_chunks::ALGORITHM,
                    "expectedSha256": backup_chunks::sha256_hex(&bytes),
                    "expectedSizeBytes": bytes.len(),
                    "chunks": {
                        "chunkSize": backup_chunks::CHUNK_SIZE,
                        "chunkCount": chunks.len(),
                        "chunkDigests": digests,
                    },
                }),
                initiate::ERROR_CODES,
            )
            .await?;
        let bundle_id = slot["descriptor"]["bundleId"]
            .as_str()
            .ok_or_else(|| VtcError::Http {
                status: 200,
                body: "the import slot names no bundle".into(),
            })?
            .to_string();
        for (index, chunk) in chunks.iter().enumerate() {
            self.backup_document(
                <put_chunk::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                serde_json::json!({
                    "bundleId": bundle_id,
                    "index": index,
                    "digestMultibase": digests[index],
                    "data": backup_chunks::encode(chunk),
                }),
                put_chunk::ERROR_CODES,
            )
            .await?;
        }
        self.backup_document(
            <finalize::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            serde_json::json!({ "bundleId": bundle_id, "password": password, "confirm": confirm }),
            finalize::ERROR_CODES,
        )
        .await
    }

    /// One `backup/*` document over this client's session, or a refusal when
    /// the client has none: the VTC serves a backup only end to end.
    async fn backup_document(
        &self,
        type_uri: &str,
        payload: serde_json::Value,
        declared: &[trust_tasks_rs::DeclaredErrorCode],
    ) -> Result<serde_json::Value, VtcError> {
        #[cfg(feature = "didcomm")]
        if self.documents.is_some() {
            return self
                .admin_document(type_uri, payload, declared, MAX_BACKUP_RESPONSE_BYTES)
                .await?
                .ok_or_else(|| VtcError::Session("the session returned no reply".into()));
        }
        let _ = (type_uri, payload, declared);
        Err(VtcError::Session(
            "a community backup moves only over DIDComm or TSP: connect with connect_didcomm \
             or connect_tsp (the VTC refuses a backup over REST)"
                .into(),
        ))
    }

    /// `{base}/<segments…>`, each segment percent-encoded.
    ///
    /// A DID or an id interpolated into a path with `format!` is a path the
    /// caller controls: a `/` or `?` in it would address a different route.
    /// Pushing segments encodes them, so what is sent is what was meant.
    fn api_url(&self, segments: &[&str]) -> Result<reqwest::Url, VtcError> {
        if self.base_url.is_empty() {
            return Err(VtcError::NoRestTransport("this verb"));
        }
        let mut url =
            reqwest::Url::parse(&self.base_url).map_err(|e| VtcError::Url(e.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| VtcError::Url(format!("{} cannot be a base URL", self.base_url)))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }

    /// Start a bearer-authenticated request to an admin route that has **no**
    /// Trust Task of its own.
    ///
    /// The VTC mounts a few admin REST routes without a `Trust-Task` binding
    /// (the vetter listing, automatic grants, withdrawals, branding) rather
    /// than borrow a URI that describes something else. Those are the only
    /// callers of this; every route that does carry a task goes through
    /// [`tt`](Self::tt).
    fn untasked(
        &self,
        method: reqwest::Method,
        url: reqwest::Url,
    ) -> Result<reqwest::RequestBuilder, VtcError> {
        if self.base_url.is_empty() {
            return Err(VtcError::NoRestTransport("this verb"));
        }
        let token = self.token()?;
        Ok(self.http.request(method, url).bearer_auth(token))
    }

    /// Authenticated GET returning JSON, carrying `task` as the Trust-Task URL.
    async fn get_json(&self, path: &str, task: &str) -> Result<serde_json::Value, VtcError> {
        let resp = self
            .tt(
                reqwest::Method::GET,
                format!("{}/{path}", self.base_url),
                task,
            )?
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtcError::Http { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Authenticated POST of a JSON body returning JSON, carrying `task` as the
    /// Trust-Task URL.
    async fn post_json(
        &self,
        path: &str,
        task: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, VtcError> {
        let resp = self
            .tt(
                reqwest::Method::POST,
                format!("{}/{path}", self.base_url),
                task,
            )?
            .json(body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtcError::Http { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Bearer token or [`VtcError::NotAuthenticated`].
    fn token(&self) -> Result<&str, VtcError> {
        self.token.as_deref().ok_or(VtcError::NotAuthenticated)
    }
}

/// The response when its status is a success, else [`VtcError::Http`] carrying
/// the status and the body — the body is where the VTC says what was wrong, so
/// a caller that turns this into operator guidance needs both.
async fn expect_success(resp: reqwest::Response) -> Result<reqwest::Response, VtcError> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Err(VtcError::Http { status, body })
}

/// Like [`expect_success`], but a 404 whose JSON body carries one of
/// `declared` as its `code` becomes [`VtcError::NotFound`].
///
/// Only the task's *declared* codes are honoured, so a 404 cannot be mistaken
/// for "no such resource" merely because it is a 404.
async fn expect_success_declaring(
    resp: reqwest::Response,
    declared: &[trust_tasks_rs::DeclaredErrorCode],
) -> Result<reqwest::Response, VtcError> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Err(typed_error(status, body, declared))
}

/// Classify a non-success answer: [`VtcError::NotFound`] for a 404 naming a
/// declared code, [`VtcError::Http`] for everything else.
fn typed_error(
    status: u16,
    body: String,
    declared: &[trust_tasks_rs::DeclaredErrorCode],
) -> VtcError {
    if status == 404
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&body)
        && let Some(code) = v.get("code").and_then(serde_json::Value::as_str)
        && declared.iter().any(|d| d.code == code)
    {
        let message = v
            .get("error")
            .or_else(|| v.get("message"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        return VtcError::NotFound {
            code: code.to_string(),
            message,
        };
    }
    VtcError::Http { status, body }
}

/// Read a `#response` document's payload as the verb's result type.
fn decode_payload<T: serde::de::DeserializeOwned>(
    payload: serde_json::Value,
    verb: &str,
) -> Result<T, VtcError> {
    serde_json::from_value(payload).map_err(|e| VtcError::Http {
        status: 200,
        body: format!("{verb} response payload has an unexpected shape: {e}"),
    })
}

/// Classify a `trust-task-error` document from the document endpoint, the
/// counterpart of [`typed_error`] for the bearer routes.
///
/// [`VtcError::NotFound`] when the refusal carries one of the task's declared
/// codes **and** says the thing is absent — the spine marks that with
/// `details.reason` ([`vta_sdk::protocols::trust_task_reject_reasons::NOT_FOUND`]) beside the code (#1219) — and
/// [`VtcError::Http`] with the document's text otherwise.
fn document_error(
    status: u16,
    payload: &serde_json::Value,
    body: String,
    declared: &[trust_tasks_rs::DeclaredErrorCode],
) -> VtcError {
    let code = payload.get("code").and_then(serde_json::Value::as_str);
    let reason = payload
        .pointer("/details/reason")
        .and_then(serde_json::Value::as_str);
    if let Some(code) = code
        && declared.iter().any(|d| d.code == code)
        && (reason == Some(vta_sdk::protocols::trust_task_reject_reasons::NOT_FOUND)
            || status == 404)
    {
        return VtcError::NotFound {
            code: code.to_string(),
            message: payload
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
        };
    }
    VtcError::Http { status, body }
}

/// The `policy/upsert/0.2` payload for a module serving `purpose`, built on
/// the generated type so the schema's bounds are checked before sending.
fn policy_upload_payload(
    purpose: &str,
    rego_source: &str,
) -> Result<policy_upsert::Payload, VtcError> {
    let key: policy_upsert::ExtKey = POLICY_PURPOSE_EXT_KEY
        .parse()
        .map_err(|e| VtcError::InvalidPayload(format!("ext key: {e}")))?;
    let ext = policy_upsert::Ext::from(std::collections::HashMap::from([(
        key,
        serde_json::Value::String(purpose.to_string()),
    )]));
    policy_upsert::Payload::try_from(
        policy_upsert::Payload::builder()
            .name(purpose)
            .module(rego_source)
            .ext(Some(ext)),
    )
    .map_err(|e| VtcError::InvalidPayload(e.to_string()))
}

/// A success response's JSON body, refusing one larger than `max` bytes. The
/// oversized body is never fully buffered.
async fn read_json_capped(
    resp: reqwest::Response,
    max: usize,
) -> Result<serde_json::Value, VtcError> {
    let status = resp.status().as_u16();
    let bytes = vta_sdk::http::read_body_capped(resp, max)
        .await
        .map_err(|e| VtcError::Http {
            status,
            body: e.to_string(),
        })?;
    serde_json::from_slice(&bytes).map_err(|e| VtcError::Http {
        status,
        body: format!(
            "response is not JSON ({e}): {}",
            String::from_utf8_lossy(&bytes)
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Discovery reads the `VTCRest` service by `type`, whatever its `#id`,
    /// and never mistakes a VTA's `VTARest` for it.
    #[test]
    fn api_base_is_read_from_the_vtc_rest_service_by_type() {
        let doc = serde_json::json!({
            "id": "did:webvh:Qm:vtc.example.com",
            "service": [
                { "id": "#rest", "type": "VTARest", "serviceEndpoint": "https://vta.example.com" },
                { "id": "#anything", "type": ["VTCRest"], "serviceEndpoint": "https://vtc.example.com/v1/" },
            ],
        });
        assert_eq!(
            api_base_from_did_document(&doc).as_deref(),
            Some("https://vtc.example.com/v1")
        );
        let vta_only = serde_json::json!({
            "service": [{ "id": "#vtc-rest", "type": "VTARest", "serviceEndpoint": "https://x" }],
        });
        assert_eq!(api_base_from_did_document(&vta_only), None);
        assert_eq!(api_base_from_did_document(&serde_json::json!({})), None);
    }

    /// A DID or id placed in a path is one segment, whatever it contains.
    #[test]
    fn path_segments_are_encoded_not_interpolated() {
        let client = VtcClient::with_token("https://vtc.example.com/v1/", "did:web:vtc", "t");
        let url = client
            .api_url(&[
                "vetting",
                "vetters",
                "did:webvh:Qm:x.example/../admin?x",
                "resend",
            ])
            .unwrap();
        assert_eq!(
            url.as_str(),
            "https://vtc.example.com/v1/vetting/vetters/did:webvh:Qm:x.example%2F..%2Fadmin%3Fx/resend"
        );
    }

    #[tokio::test]
    async fn vetting_admin_methods_without_token_are_not_authenticated() {
        let client = VtcClient::anonymous("https://vtc.example.com/v1", "did:web:vtc");
        assert!(matches!(
            client.list_vetter_grants().await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client
                .grant_vetter(
                    &serde_json::from_value(serde_json::json!({ "memberDid": "did:key:z" }))
                        .unwrap()
                )
                .await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.revoke_endorsement("e1").await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.resend_vetter_grant("did:key:z").await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.auto_grant().await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.branding().await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.vetting_revocations().await,
            Err(VtcError::NotAuthenticated)
        ));
    }

    #[test]
    fn a_withdrawal_row_deserializes_from_the_vtc_shape() {
        let rows: VettingRevocationList = serde_json::from_value(serde_json::json!({
            "revocations": [{
                "issuer": "did:key:zCarol",
                "statementId": "urn:uuid:s1",
                "statementDigestMultibase": "zDigest",
                "reason": "mistake",
                "recordedAt": "2026-09-01T00:00:00Z",
                "reviewState": "needsReview",
                "affectedJoinRequests": ["3f1c9a52-8c1e-4f2b-9d7a-0b6e5c4d3a21"],
                "affectedMembers": ["did:key:zAlice"]
            }]
        }))
        .unwrap();
        assert_eq!(rows.revocations[0].review_state, "needsReview");
        assert_eq!(rows.revocations[0].affected_members, vec!["did:key:zAlice"]);
    }

    /// A holder on any DID method can name its verification method, which is
    /// the whole point of the general submit path.
    ///
    /// A `did:webvh` persona is what a VTA actually mints, so a client that
    /// could only sign as a `did:key` forced every such holder to borrow an
    /// identity it does not otherwise use — and the borrowed one is the DID
    /// that would have become the member.
    #[test]
    fn a_holder_key_names_any_did_method() {
        let webvh = HolderKey::new(
            "did:webvh:QmScid:example.com:glenn#key-0",
            "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
        )
        .expect("a did:webvh verification method is a verification method");
        assert_eq!(webvh.holder_did(), "did:webvh:QmScid:example.com:glenn");

        // …and the `did:key` wrapper still derives its own, so the common case
        // keeps its shorter call.
        let key = HolderKey::from_did_key(
            "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
            "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
        )
        .expect("a did:key derives its verification method");
        assert!(key.verification_method().starts_with("did:key:"));
    }

    /// A verification method with no fragment names no key, and is refused at
    /// construction rather than producing a proof nothing can resolve.
    #[test]
    fn a_did_without_a_fragment_is_not_a_verification_method() {
        assert!(HolderKey::new("did:webvh:QmScid:example.com:glenn", "z3u2").is_err());
    }

    /// The admin verbs say which argument is missing rather than failing as a
    /// malformed URL.
    ///
    /// A session-only client has no REST base, and every admin verb reaches the
    /// URL surface through `tt`. Without this the request is built against an
    /// empty base and the error reads as a bug in this crate rather than as a
    /// constructor that was not given `rest_url`.
    /// A refusal from the document endpoint that names a declared code and
    /// carries the `not_found` marker is the typed `NotFound` — whatever HTTP
    /// status it came with (the VTC answers a declared refusal with 422).
    #[test]
    fn a_declared_not_found_document_refusal_is_typed() {
        let code = members_credentials::error_codes::NOT_FOUND.code;
        let payload = serde_json::json!({
            "code": code,
            "message": "member not found",
            "details": { "reason": vta_sdk::protocols::trust_task_reject_reasons::NOT_FOUND },
        });
        match document_error(
            422,
            &payload,
            String::new(),
            members_credentials::ERROR_CODES,
        ) {
            VtcError::NotFound { code: got, message } => {
                assert_eq!(got, code);
                assert_eq!(message, "member not found");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    /// Neither half alone is enough: an undeclared code stays `Http`, and so
    /// does a declared code without the absence marker.
    #[test]
    fn a_document_refusal_is_not_found_only_when_both_halves_say_so() {
        let undeclared = serde_json::json!({
            "code": "permissionDenied",
            "details": { "reason": vta_sdk::protocols::trust_task_reject_reasons::NOT_FOUND },
        });
        assert!(matches!(
            document_error(
                403,
                &undeclared,
                "b".into(),
                members_credentials::ERROR_CODES
            ),
            VtcError::Http { status: 403, .. }
        ));
        let unmarked = serde_json::json!({
            "code": members_credentials::error_codes::NOT_FOUND.code,
        });
        assert!(matches!(
            document_error(422, &unmarked, "b".into(), members_credentials::ERROR_CODES),
            VtcError::Http { status: 422, .. }
        ));
    }

    #[test]
    fn an_admin_verb_without_a_rest_base_says_so() {
        let client = VtcClient {
            http: vta_sdk::http::rest_client(),
            base_url: String::new(),
            vtc_did: "did:webvh:QmScid:example.com:acme".to_string(),
            token: Some("t".to_string()),
            signer: None,
            #[cfg(feature = "didcomm")]
            documents: None,
        };
        let err = client
            .tt(reqwest::Method::GET, "http://x/members", task::MEMBERS_LIST)
            .expect_err("no REST base means no admin verb");
        assert!(
            matches!(err, VtcError::NoRestTransport(_)),
            "expected a missing-transport error, got {err:?}"
        );
    }

    /// `Debug` never prints the bearer token.
    ///
    /// The derive did. A credential that reaches a log has left, and the only
    /// thing worth reporting is whether one is held.
    #[test]
    fn debug_does_not_leak_the_token() {
        let client = VtcClient::with_token(
            "https://vtc.example.com/v1",
            "did:webvh:QmScid:example.com:acme",
            "super-secret-bearer-token",
        );
        let rendered = format!("{client:?}");
        assert!(
            !rendered.contains("super-secret-bearer-token"),
            "the token is in Debug output: {rendered}"
        );
        assert!(rendered.contains("authenticated: true"), "{rendered}");
    }

    #[test]
    fn member_page_deserializes_from_vtc_shape() {
        // A `Paginated<MemberResponse>` as the VTC serialises it (extra fields
        // present to prove they're ignored).
        let json = serde_json::json!({
            "items": [{
                "did": "did:key:z6MkStaffVta",
                "role": "member",
                "label": "Staff VTA",
                "joinedAt": "2026-06-23T00:00:00Z",
                "publishConsent": true,
                "departurePreference": "tombstone",
                "statusListIndex": 7,
                "currentVmcId": "urn:uuid:vmc-1",
                "extensions": {},
                "personhood": false,
                "joinedViaInvitation": true
            }],
            "nextCursor": null
        });
        let page: Page<MemberRecord> = serde_json::from_value(json).unwrap();
        assert_eq!(page.items.len(), 1);
        let m = &page.items[0];
        assert_eq!(m.did, "did:key:z6MkStaffVta");
        assert_eq!(m.role, "member");
        assert_eq!(m.status_list_index, Some(7));
        assert_eq!(m.current_vmc_id.as_deref(), Some("urn:uuid:vmc-1"));
        assert!(m.joined_via_invitation);
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn list_members_without_token_is_not_authenticated() {
        let client = VtcClient {
            http: reqwest::Client::new(),
            base_url: "https://vtc.example.com/v1".into(),
            vtc_did: "did:web:vtc.example.com".into(),
            token: None,
            signer: None,
            #[cfg(feature = "didcomm")]
            documents: None,
        };
        // The token guard returns before any network I/O.
        let err = client.list_members(None).await;
        assert!(matches!(err, Err(VtcError::NotAuthenticated)), "{err:?}");
    }

    #[test]
    fn decide_result_deserializes_camel_case() {
        let json = serde_json::json!({
            "requestId": "11111111-1111-1111-1111-111111111111",
            "status": "approved",
            "vmc": { "type": ["VerifiableCredential", "MembershipCredential"] },
            "roleVec": null
        });
        let d: DecideResult = serde_json::from_value(json).unwrap();
        assert_eq!(d.request_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(d.status, "approved");
        assert!(d.vmc.is_some());
        assert!(d.role_vec.is_none());
    }

    #[test]
    fn join_request_and_remove_results_deserialize() {
        let jr: JoinRequestSummary = serde_json::from_value(serde_json::json!({
            "id": "22222222-2222-2222-2222-222222222222",
            "applicantDid": "did:key:z6MkApplicant",
            "status": "pending",
            "submittedAt": "2026-06-23T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(jr.applicant_did, "did:key:z6MkApplicant");
        assert_eq!(jr.status, "pending");

        let rm: RemoveResult = serde_json::from_value(serde_json::json!({
            "did": "did:key:z6MkGone",
            "disposition": "tombstone",
            "removed": true
        }))
        .unwrap();
        assert_eq!(rm.did, "did:key:z6MkGone");
        assert!(rm.removed);
    }

    #[tokio::test]
    async fn admin_methods_without_token_are_not_authenticated() {
        let client = VtcClient {
            http: reqwest::Client::new(),
            base_url: "https://vtc.example.com/v1".into(),
            vtc_did: "did:web:vtc.example.com".into(),
            token: None,
            signer: None,
            #[cfg(feature = "didcomm")]
            documents: None,
        };
        assert!(matches!(
            client.list_join_requests(Some("pending")).await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.approve_join("req-1").await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.remove_member("did:key:x", Some("reason")).await,
            Err(VtcError::NotAuthenticated)
        ));
    }

    #[test]
    fn member_extensions_default_and_parse() {
        let none: MemberRecord = serde_json::from_value(serde_json::json!({
            "did": "did:key:z", "role": "member", "joinedAt": "2026-06-23T00:00:00Z"
        }))
        .unwrap();
        assert!(none.extensions.is_null());
        let with: MemberRecord = serde_json::from_value(serde_json::json!({
            "did": "did:key:z", "role": "member", "joinedAt": "2026-06-23T00:00:00Z",
            "extensions": { "fleet_index": 3 }
        }))
        .unwrap();
        assert_eq!(with.extensions["fleet_index"], 3);
    }

    #[tokio::test]
    async fn policy_admin_methods_without_token_are_not_authenticated() {
        let client = VtcClient {
            http: reqwest::Client::new(),
            base_url: "https://vtc.example.com/v1".into(),
            vtc_did: "did:web:vtc.example.com".into(),
            token: None,
            signer: None,
            #[cfg(feature = "didcomm")]
            documents: None,
        };
        assert!(matches!(
            client.list_policies().await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.get_policy("p1").await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.upload_policy("join", "package x").await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.member_credentials("did:key:z").await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.activate_policy("p1").await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client
                .update_member_extensions("did:key:z", serde_json::json!({}))
                .await,
            Err(VtcError::NotAuthenticated)
        ));
    }

    /// The upload body is the canonical `policy/upsert/0.2` shape, asserted on
    /// the serialised JSON — what the VTC's `deny_unknown_fields` body sees.
    #[test]
    fn policy_upload_sends_the_canonical_upsert_shape() {
        let body = serde_json::to_value(policy_upload_payload("join", "package vtc.join").unwrap())
            .unwrap();
        assert_eq!(body["name"], "join");
        assert_eq!(body["module"], "package vtc.join");
        assert_eq!(body["ext"][POLICY_PURPOSE_EXT_KEY], "join");
        assert!(
            body.get("purpose").is_none(),
            "not a canonical member: {body}"
        );
        assert!(
            body.get("regoSource").is_none(),
            "renamed to module: {body}"
        );
    }

    #[test]
    fn an_empty_policy_module_is_refused_before_sending() {
        assert!(matches!(
            policy_upload_payload("join", ""),
            Err(VtcError::InvalidPayload(_))
        ));
    }

    /// Only a 404 naming a *declared* code is a typed not-found; a bare 404 is
    /// not evidence the member is absent.
    #[test]
    fn only_a_declared_not_found_code_is_typed() {
        let declared = members_credentials::ERROR_CODES;
        let code = members_credentials::error_codes::NOT_FOUND.code;
        let typed = typed_error(
            404,
            serde_json::json!({ "error": "not found: x", "code": code }).to_string(),
            declared,
        );
        assert!(
            matches!(&typed, VtcError::NotFound { code: c, message } if c == code && message == "not found: x"),
            "{typed:?}"
        );
        for (status, body) in [
            (404, serde_json::json!({ "error": "not found" }).to_string()),
            (404, "no route".to_string()),
            (
                404,
                serde_json::json!({ "error": "x", "code": "vtc/other:notFound" }).to_string(),
            ),
            (
                403,
                serde_json::json!({ "error": "x", "code": code }).to_string(),
            ),
        ] {
            assert!(
                matches!(
                    typed_error(status, body.clone(), declared),
                    VtcError::Http { .. }
                ),
                "{status} {body} must stay Http"
            );
        }
    }

    /// A client with no session refuses a backup before anything is sent: the
    /// VTC serves a backup only over DIDComm or TSP.
    #[tokio::test]
    async fn a_backup_needs_a_session() {
        let client = VtcClient::with_token("https://vtc.example.com/v1", "did:web:vtc", "t");
        for err in [
            client
                .export_backup("a-long-enough-password", false)
                .await
                .unwrap_err(),
            client
                .import_backup(&serde_json::json!({}), "a-long-enough-password", false)
                .await
                .unwrap_err(),
        ] {
            assert!(
                matches!(&err, VtcError::Session(m) if m.contains("DIDComm or TSP")),
                "{err}"
            );
        }
    }

    /// The encoding round-trips, and the digests are those of the bytes.
    #[test]
    fn backup_chunks_encode_and_digest_consistently() {
        let bytes = b"community backup bytes";
        assert_eq!(
            backup_chunks::decode(&backup_chunks::encode(bytes)).unwrap(),
            bytes
        );
        assert_eq!(backup_chunks::digest(bytes), backup_chunks::digest(bytes));
        assert_ne!(
            backup_chunks::digest(bytes),
            backup_chunks::digest(b"other bytes")
        );
        assert_eq!(
            backup_chunks::sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
