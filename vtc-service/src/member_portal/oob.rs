//! Wallet sign-in started by a **trigger link** — the `auth/oob/*` key-grant
//! flow's state, clocks and connection details.
//!
//! The browser (the *starter*) holds a non-extractable Ed25519 key `K_b` and
//! opens a request; a wallet (the *approver*) claims it with a throwaway key
//! `K_a`, proves membership and the number on the screen, and returns a grant
//! signed by the member's DID that names `K_b`. Only the holder of `K_b` can
//! turn that grant into a member session (`redeem`). The handlers are
//! [`crate::trust_tasks::oob_tasks`]; this module is what they share:
//!
//! - **The request store.** One row per request in the member session
//!   keyspace (`oob_req:<requestId>`), swept with the sessions
//!   ([`sweep`]).
//! - **Compare-and-set.** Every change of state is made under one process-wide
//!   lock, against the state the caller read ([`transition`]). Exactly one of
//!   two racing claims, proofs, decisions or redemptions wins. The VTC is a
//!   single process (it never runs in a TEE), so a process lock is the whole
//!   story.
//! - **Two clocks.** A request must be claimed within [`CLAIM_WINDOW_SECS`] of
//!   creation; a claim starts a fresh [`DECISION_WINDOW_SECS`] window covering
//!   prove, respond and redeem (base design §7.2).
//! - **The long poll.** `redeem` waits on [`Notifier`] for a change of state,
//!   one open poll per request and a per-address cap ([`PollGuard`]).
//! - **Connection details** the handlers cannot read from a document: the
//!   client address, `User-Agent` and `Origin`, and the cookies a successful
//!   `redeem` sets ([`HttpContext`]). Only the HTTPS door supplies them, so
//!   `request` and `redeem` are HTTPS-only.
//!
//! Design: `design-docs/vtc-qr-login-design.md` §7 and §12, with the trigger
//! link contract (`sign-in-trigger-link-contract.md`, C1–C5) and VTI spec
//! §7a (VTI-LNK-*).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use vti_common::auth::session::now_epoch;
use vti_common::store::KeyspaceHandle;

use crate::error::AppError;

// ── Wire types ──────────────────────────────────────────────────────────────

/// The `auth/oob/*` 0.1 wire types, generated from the specification
/// (trust-tasks-tf #738) and re-exported under the names this module's callers
/// use. Behaviour stays hand-written over them; a type URI comes from the
/// generated payload's `TYPE_URI`.
pub mod types {
    use trust_tasks_rs::specs::auth::oob as spec;

    pub use spec::cancel::v0_1::{Payload as CancelPayload, Response as CancelResponse};
    pub use spec::claim::v0_1::{
        Payload as ClaimPayload, Response as Step1, Service as ServiceRef,
    };
    pub use spec::grant::v0_1::{Payload as GrantPayload, PayloadDecision as GrantDecision};
    pub use spec::identify::v0_1::Payload as IdentifyPayload;
    pub use spec::prove::v0_1::{Payload as ProvePayload, Requester, Response as Step2};
    pub use spec::redeem::v0_1::{Payload as RedeemPayload, Response as RedeemResponse};
    pub use spec::request::v0_1::{Payload as RequestPayload, Response as RequestResponse};
    pub use spec::respond::v0_1::{Payload as RespondPayload, Response as RespondResponse};

    pub const REQUEST_TYPE: &str = <RequestPayload as trust_tasks_rs::Payload>::TYPE_URI;
    pub const CLAIM_TYPE: &str = <ClaimPayload as trust_tasks_rs::Payload>::TYPE_URI;
    pub const PROVE_TYPE: &str = <ProvePayload as trust_tasks_rs::Payload>::TYPE_URI;
    pub const IDENTIFY_TYPE: &str = <IdentifyPayload as trust_tasks_rs::Payload>::TYPE_URI;
    pub const RESPOND_TYPE: &str = <RespondPayload as trust_tasks_rs::Payload>::TYPE_URI;
    pub const GRANT_TYPE: &str = <GrantPayload as trust_tasks_rs::Payload>::TYPE_URI;
    pub const REDEEM_TYPE: &str = <RedeemPayload as trust_tasks_rs::Payload>::TYPE_URI;
    pub const CANCEL_TYPE: &str = <CancelPayload as trust_tasks_rs::Payload>::TYPE_URI;
}

// ── Which session a request asks for ────────────────────────────────────────

/// The `ext` namespace that says which session a sign-in asks for. A VTC
/// extension, not a `purpose`: `auth/oob/0.1`'s `Purpose` is a closed enum
/// (`login`), and both sessions are a login. Carried on `request` by the
/// starter, and repeated by the VTC in the signed step 1 and step 2
/// responses so the wallet can show it and the grant's `contextDigest`
/// covers it.
pub const SESSION_EXT: &str = "org.openvtc.session";

/// Which session `redeem` issues. `member` is the default: a request with no
/// [`SESSION_EXT`] member, and every request stored before the field existed,
/// is a member-portal sign-in exactly as before.
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

/// The decline reason `redeem` reports when the identity that approved an
/// operator-console sign-in is not an administrator.
pub const NOT_AN_ADMIN: &str = "notAnAdmin";

// ── Clocks and limits ───────────────────────────────────────────────────────

/// A request must be claimed this long after it is made. VTI-LNK-100 allows a
/// sign-in link at most 300 s; base design §7.2 sets 120.
pub const CLAIM_WINDOW_SECS: u64 = 120;
/// A claim starts this window for prove, respond and redeem.
pub const DECISION_WINDOW_SECS: u64 = 120;
/// How long an ended request's row is kept before the sweeper drops it — the
/// acceptance window, so a late redelivery still finds a final state rather
/// than `requestNotFound`.
pub const ENDED_RETENTION_SECS: u64 = 600;
/// Open (pending) requests one address may hold at once (T17).
pub const MAX_PENDING_PER_ADDRESS: usize = 5;
/// Open `redeem` polls one address may hold at once (T17).
pub const MAX_POLLS_PER_ADDRESS: usize = 8;

static REDEEM_HOLD_MS: AtomicU64 = AtomicU64::new(25_000);

/// How long `redeem` holds a call open before answering `pending` (base
/// design §7.6: up to 25 s).
pub fn redeem_hold() -> Duration {
    Duration::from_millis(REDEEM_HOLD_MS.load(Ordering::Relaxed))
}

/// Shorten the long poll, for tests that would otherwise wait 25 s for a
/// `pending` answer. Not configuration.
#[doc(hidden)]
pub fn set_redeem_hold_for_tests(hold: Duration) {
    REDEEM_HOLD_MS.store(hold.as_millis() as u64, Ordering::Relaxed);
}

// ── The request record ──────────────────────────────────────────────────────

/// `pending → claimed → identified → approved → consumed`; `declined`,
/// `cancelled` and `expired` are final (base design §7.2).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OobState {
    Pending,
    Claimed,
    Identified,
    Approved,
    Consumed,
    Declined,
    Cancelled,
    Expired,
}

impl OobState {
    pub fn as_str(self) -> &'static str {
        match self {
            OobState::Pending => "pending",
            OobState::Claimed => "claimed",
            OobState::Identified => "identified",
            OobState::Approved => "approved",
            OobState::Consumed => "consumed",
            OobState::Declined => "declined",
            OobState::Cancelled => "cancelled",
            OobState::Expired => "expired",
        }
    }

    pub fn is_final(self) -> bool {
        matches!(
            self,
            OobState::Consumed | OobState::Declined | OobState::Cancelled | OobState::Expired
        )
    }

    /// States inside the decision window.
    fn decision_open(self) -> bool {
        matches!(
            self,
            OobState::Claimed | OobState::Identified | OobState::Approved
        )
    }
}

/// What the VTC records from the starter's connection at `request`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RequesterDetails {
    pub location: String,
    pub browser: String,
    pub os: String,
    pub created_at: String,
}

/// One request (base design §7.2's stored fields).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OobRequest {
    pub request_id: String,
    pub state: OobState,
    /// `K_b`, an Ed25519 `did:key`. Fixed for the life of the request.
    pub start_key: String,
    /// The starter's egress address, kept only until the request ends (T22).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_network: Option<String>,
    /// `K_a`, set at claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_key: Option<String>,
    pub purpose: String,
    pub mode: String,
    pub origin: String,
    /// Two digits, chosen at claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_number: Option<String>,
    /// Whether a `redeem` answer has carried the number yet. The first poll
    /// after the claim answers at once, so the number reaches the screen
    /// without waiting out a long poll; later polls wait for a change.
    #[serde(default)]
    pub match_number_delivered: bool,
    pub requester: RequesterDetails,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identified_did: Option<String>,
    /// [`context_digest`] of the signed step 2 response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step2_digest: Option<String>,
    /// The step 1 fields (`auth/oob/claim/0.1#response`) as signed, so step 2
    /// repeats them byte for byte. Kept as JSON: step 2 is a different
    /// generated type with the same members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step1: Option<serde_json::Value>,
    pub created_at: u64,
    pub claim_deadline: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_deadline: Option<u64>,
    /// The signed grant, once approved or declined by the member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<serde_json::Value>,
    /// When the request reached a final state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<u64>,
    /// Which session `redeem` issues, fixed at `request`. Absent on rows
    /// stored before the field existed, which are member sign-ins.
    #[serde(default, skip_serializing_if = "SessionAudience::is_member")]
    pub audience: SessionAudience,
    /// Why a request was declined, when the starter is told (today only
    /// [`NOT_AN_ADMIN`]). `redeem` reports it in `details.reason`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<String>,
}

impl OobRequest {
    /// The audience the VTC signed into step 1 (and so into step 2, which
    /// repeats it, and so into the grant's `contextDigest`). `None` before
    /// the claim, or if the stored extension cannot be read. A member
    /// request's step 1 carries no extension, which reads as `member`.
    pub fn signed_audience(&self) -> Option<SessionAudience> {
        self.step1
            .as_ref()
            .and_then(|s| SessionAudience::from_ext(s.get("ext")).ok())
    }
    /// The state as of `now`: a request past its clock is expired whether or
    /// not anything has written that down yet.
    pub fn effective_state(&self, now: u64) -> OobState {
        match self.state {
            OobState::Pending if now >= self.claim_deadline => OobState::Expired,
            s if s.decision_open() && self.decision_deadline.is_none_or(|d| now >= d) => {
                OobState::Expired
            }
            s => s,
        }
    }

    /// Move to a final state, dropping the starter's address (T22).
    pub fn end(&mut self, state: OobState, now: u64) {
        debug_assert!(state.is_final());
        self.state = state;
        self.start_network = None;
        self.ended_at.get_or_insert(now);
    }
}

/// The keyspace key of a request's row. Public so tests can age a request.
pub fn record_key(request_id: &str) -> String {
    format!("oob_req:{request_id}")
}

const RECORD_PREFIX: &str = "oob_req:";

pub async fn load(ks: &KeyspaceHandle, request_id: &str) -> Result<Option<OobRequest>, AppError> {
    ks.get::<OobRequest>(record_key(request_id)).await
}

async fn store(ks: &KeyspaceHandle, rec: &OobRequest) -> Result<(), AppError> {
    ks.insert(record_key(&rec.request_id), rec).await
}

/// Every state change goes through this lock: read, check, write.
static TRANSITIONS: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Why [`transition`] changed nothing.
#[derive(Debug)]
pub enum TransitionError<E> {
    /// No such request.
    NotFound,
    /// The closure refused, given the current record.
    Refused(E),
    Store(AppError),
}

impl<E> From<AppError> for TransitionError<E> {
    fn from(e: AppError) -> Self {
        TransitionError::Store(e)
    }
}

/// Compare-and-set on one request: under the transition lock, load the
/// current record, let `f` check it and change it, and write it back only if
/// `f` returns `Ok`. Waiters are woken after a write.
///
/// `f` sees the record as stored *now*, not as the caller read it earlier, so
/// it must re-check every precondition the caller relied on — that is what
/// makes it a compare-and-set rather than a blind write.
pub async fn transition<T, E>(
    ks: &KeyspaceHandle,
    request_id: &str,
    f: impl FnOnce(&mut OobRequest) -> Result<T, E>,
) -> Result<(T, OobRequest), TransitionError<E>> {
    let _guard = TRANSITIONS.lock().await;
    let Some(mut rec) = load(ks, request_id).await? else {
        return Err(TransitionError::NotFound);
    };
    let out = f(&mut rec).map_err(TransitionError::Refused)?;
    store(ks, &rec).await?;
    drop(_guard);
    NOTIFIER.wake(request_id);
    Ok((out, rec))
}

/// Create a request. Fails if the id exists (it never should: 128 random bits).
pub async fn create(ks: &KeyspaceHandle, rec: &OobRequest) -> Result<(), AppError> {
    let _guard = TRANSITIONS.lock().await;
    if load(ks, &rec.request_id).await?.is_some() {
        return Err(AppError::Conflict("request id collision".into()));
    }
    store(ks, rec).await
}

/// Write down an expiry the clock has already decided, so the row ends, the
/// address is dropped, and waiters learn. Returns `true` when this call was
/// the one that ended it (the caller audits once).
pub async fn settle_expiry(ks: &KeyspaceHandle, request_id: &str) -> Result<bool, AppError> {
    let now = now_epoch();
    match transition(ks, request_id, |rec| {
        if rec.state.is_final() || rec.effective_state(now) != OobState::Expired {
            return Err(());
        }
        rec.end(OobState::Expired, now);
        Ok(())
    })
    .await
    {
        Ok(_) => Ok(true),
        Err(TransitionError::Store(e)) => Err(e),
        Err(_) => Ok(false),
    }
}

/// How many requests `address` has open. A scan: the rows are few and short
/// lived, and a counter kept beside them could drift from them.
pub async fn open_requests_from(ks: &KeyspaceHandle, address: &str) -> Result<usize, AppError> {
    let now = now_epoch();
    let rows = ks.prefix_iter_raw(RECORD_PREFIX).await?;
    Ok(rows
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<OobRequest>(&v).ok())
        .filter(|r| {
            r.start_network.as_deref() == Some(address)
                && r.effective_state(now) == OobState::Pending
        })
        .count())
}

/// Drop ended requests past [`ENDED_RETENTION_SECS`], and end (and drop the
/// address of) requests whose clock has run out. Run beside
/// `cleanup_expired_sessions` on the member session keyspace.
pub async fn sweep(ks: &KeyspaceHandle) -> Result<usize, AppError> {
    let now = now_epoch();
    let rows = ks.prefix_iter_raw(RECORD_PREFIX).await?;
    let mut removed = 0;
    for (key, value) in rows {
        let Ok(rec) = serde_json::from_slice::<OobRequest>(&value) else {
            continue;
        };
        let ended_at = rec.ended_at.or_else(|| {
            (rec.effective_state(now) == OobState::Expired)
                .then(|| rec.decision_deadline.unwrap_or(rec.claim_deadline))
        });
        match ended_at {
            Some(t) if now.saturating_sub(t) > ENDED_RETENTION_SECS => {
                ks.remove(key).await?;
                removed += 1;
            }
            Some(_) if !rec.state.is_final() => {
                settle_expiry(ks, &rec.request_id).await?;
            }
            _ => {}
        }
    }
    Ok(removed)
}

// ── Waking long polls ───────────────────────────────────────────────────────

/// One [`Notify`] per request with a poll waiting on it.
pub struct Notifier {
    inner: std::sync::Mutex<HashMap<String, Arc<Notify>>>,
}

pub static NOTIFIER: LazyLock<Notifier> = LazyLock::new(|| Notifier {
    inner: std::sync::Mutex::new(HashMap::new()),
});

impl Notifier {
    /// The handle a poll waits on. Create the `notified()` future and
    /// `enable()` it **before** reading the record, or a change landing
    /// between the read and the wait is missed.
    pub fn handle(&self, request_id: &str) -> Arc<Notify> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(request_id.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    fn wake(&self, request_id: &str) {
        if let Some(n) = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(request_id)
        {
            n.notify_waiters();
        }
    }

    fn forget(&self, request_id: &str) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(request_id);
    }
}

struct PollBook {
    open: HashSet<String>,
    per_address: HashMap<IpAddr, usize>,
}

static POLLS: LazyLock<std::sync::Mutex<PollBook>> = LazyLock::new(|| {
    std::sync::Mutex::new(PollBook {
        open: HashSet::new(),
        per_address: HashMap::new(),
    })
});

/// Why a poll was not admitted.
#[derive(Debug, PartialEq, Eq)]
pub enum PollRefused {
    /// Another poll on this request is open.
    AlreadyOpen,
    /// The address holds [`MAX_POLLS_PER_ADDRESS`] polls.
    AddressCap,
}

/// An open `redeem` poll; dropping it closes the slot.
pub struct PollGuard {
    request_id: String,
    address: IpAddr,
}

impl PollGuard {
    /// One open poll per request (base design §7.6), and a per-address cap.
    pub fn open(request_id: &str, address: IpAddr) -> Result<Self, PollRefused> {
        let mut book = POLLS.lock().unwrap_or_else(|p| p.into_inner());
        if book.open.contains(request_id) {
            return Err(PollRefused::AlreadyOpen);
        }
        let n = book.per_address.get(&address).copied().unwrap_or(0);
        if n >= MAX_POLLS_PER_ADDRESS {
            return Err(PollRefused::AddressCap);
        }
        book.open.insert(request_id.to_string());
        *book.per_address.entry(address).or_default() += 1;
        Ok(Self {
            request_id: request_id.to_string(),
            address,
        })
    }
}

impl Drop for PollGuard {
    fn drop(&mut self) {
        let mut book = POLLS.lock().unwrap_or_else(|p| p.into_inner());
        book.open.remove(&self.request_id);
        if let Some(n) = book.per_address.get_mut(&self.address) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                book.per_address.remove(&self.address);
            }
        }
        drop(book);
        NOTIFIER.forget(&self.request_id);
    }
}

// ── The HTTPS connection ────────────────────────────────────────────────────

/// What the HTTPS door knows about the connection a document arrived on, and
/// the cookies a handler asks it to set. Absent on every other transport.
#[derive(Debug)]
pub struct HttpContext {
    pub client_ip: IpAddr,
    pub user_agent: Option<String>,
    pub origin: Option<String>,
    pub host: Option<String>,
    set_cookies: std::sync::Mutex<Vec<String>>,
}

tokio::task_local! {
    static HTTP: Arc<HttpContext>;
}

impl HttpContext {
    pub fn new(
        client_ip: IpAddr,
        user_agent: Option<String>,
        origin: Option<String>,
        host: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            client_ip,
            user_agent,
            origin,
            host,
            set_cookies: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Run `fut` with `ctx` visible to the `auth/oob` handlers.
    pub async fn scope<F: std::future::Future>(ctx: Arc<Self>, fut: F) -> F::Output {
        HTTP.scope(ctx, fut).await
    }

    /// The context of the document being handled, if it came over HTTPS.
    pub fn current() -> Option<Arc<Self>> {
        HTTP.try_with(Arc::clone).ok()
    }

    /// Ask the door to send these `Set-Cookie` values with the response.
    pub fn set_cookies(&self, cookies: impl IntoIterator<Item = String>) {
        self.set_cookies
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend(cookies);
    }

    /// The cookies a handler asked for, once.
    pub fn take_cookies(&self) -> Vec<String> {
        std::mem::take(&mut *self.set_cookies.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// A fresh `requestId`: 16 random bytes as unpadded base64url, 22 characters
/// (contract C1, VTI-LNK-033/034/103).
pub fn new_request_id() -> String {
    use base64::Engine;
    use rand::RngExt;
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The two-digit number the member types, `00`–`99`.
pub fn new_match_number() -> String {
    use rand::RngExt;
    format!("{:02}", rand::rng().random_range(0..100u32))
}

/// `true` when `did` is an Ed25519 `did:key` (multicodec `0xed01`, 32 bytes).
/// Decided from the identifier alone, before any proof is read (T21).
pub fn is_ed25519_did_key(did: &str) -> bool {
    if !did.starts_with("did:key:z6Mk") {
        return false;
    }
    let Ok((base, bytes)) = multibase::decode(&did["did:key:".len()..]) else {
        return false;
    };
    base == multibase::Base::Base58Btc && bytes.len() == 34 && bytes[..2] == [0xed, 0x01]
}

/// The Ed25519 multikey (`z6Mk…`) inside an Ed25519 `did:key`.
pub fn did_key_multikey(did: &str) -> Option<&str> {
    is_ed25519_did_key(did).then(|| &did["did:key:".len()..])
}

/// `contextDigest`: SHA-256 of the JCS-canonical signed step 2 response,
/// proof included, as a multibase (`z`, base58btc) sha2-256 multihash — the
/// registry's `DigestMultibase` form, as `payloadDigest` already uses.
pub fn context_digest(signed_step2: &serde_json::Value) -> Result<String, AppError> {
    use sha2::Digest;
    let jcs = serde_json_canonicalizer::to_vec(signed_step2)
        .map_err(|e| AppError::Internal(format!("canonicalise step 2: {e}")))?;
    let digest = sha2::Sha256::digest(&jcs);
    let mut buf = Vec::with_capacity(34);
    buf.extend_from_slice(&[0x12, 0x20]);
    buf.extend_from_slice(&digest);
    Ok(multibase::encode(multibase::Base::Base58Btc, &buf))
}

/// Whether two `DigestMultibase` values name the same multihash, whichever
/// of the two permitted headers each uses: `z` (base58btc) or `u` (base64url)
/// (contract C9).
pub fn same_digest(a: &str, b: &str) -> bool {
    fn bytes(s: &str) -> Option<Vec<u8>> {
        match multibase::decode(s) {
            Ok((multibase::Base::Base58Btc | multibase::Base::Base64Url, b)) => Some(b),
            _ => None,
        }
    }
    match (bytes(a), bytes(b)) {
        (Some(x), Some(y)) => x.len() == 34 && x == y,
        _ => false,
    }
}

/// An instant on the wire: integer epoch seconds only (contract C9).
pub fn epoch_of(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
}

/// RFC 3339 at whole seconds, UTC.
pub fn rfc3339(epoch: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(epoch as i64, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The network part compared for `sameNetwork`: the whole IPv4 address, or
/// the /64 of an IPv6 one (a phone and a laptop on one network share a
/// prefix, not an address).
fn network_of(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.octets().to_vec(),
            None => v6.octets()[..8].to_vec(),
        },
    }
}

/// `sameNetwork` from the starter's and the approver's egress addresses:
/// `true`, `false`, or `"unknown"` when either is missing.
pub fn same_network(start: Option<&str>, approver: Option<IpAddr>) -> serde_json::Value {
    match (start.and_then(|s| s.parse::<IpAddr>().ok()), approver) {
        (Some(a), Some(b)) => serde_json::Value::Bool(network_of(&a) == network_of(&b)),
        _ => serde_json::Value::String("unknown".into()),
    }
}

/// GeoIP hook. City and country from a **local** database only — never a
/// third-party call (base design §12.6). This repository carries no GeoIP
/// dependency or database, so every address is `"unknown"`, which the wallet
/// shows as a warning, not as neutral. Wire a local database in here.
pub fn locate(_ip: IpAddr) -> Option<String> {
    None
}

/// Browser family and OS from a `User-Agent`, never the full string (T5).
pub fn browser_and_os(user_agent: Option<&str>) -> (String, String) {
    let ua = user_agent.unwrap_or_default();
    let browser = if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("OPR/") || ua.contains("Opera") {
        "Opera"
    } else if ua.contains("Firefox/") || ua.contains("FxiOS/") {
        "Firefox"
    } else if ua.contains("Chrome/") || ua.contains("CriOS/") || ua.contains("Chromium/") {
        "Chrome"
    } else if ua.contains("Safari/") {
        "Safari"
    } else {
        "unknown"
    };
    let os = if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("CrOS") {
        "ChromeOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "unknown"
    };
    (browser.into(), os.into())
}

/// The origin (`scheme://host[:port]`) of an absolute URL.
pub fn origin_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    let origin = u.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// The portal's origin for a request arriving on `ctx`: `public_url`'s origin
/// when configured. Without one, the `Origin` header is accepted only when it
/// names the host the request was sent to — the browser's same-origin call.
pub fn portal_origin(public_url: Option<&str>, ctx: &HttpContext) -> Option<String> {
    if let Some(url) = public_url {
        return origin_of(url);
    }
    let origin = ctx.origin.as_deref()?;
    let host = ctx.host.as_deref()?;
    let parsed = url::Url::parse(origin).ok()?;
    let authority = match parsed.port() {
        Some(p) => format!("{}:{p}", parsed.host_str()?),
        None => parsed.host_str()?.to_string(),
    };
    (authority.eq_ignore_ascii_case(host)).then(|| parsed.origin().ascii_serialization())
}

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
    match found.first() {
        None => Err(format!(
            "no `SignInPortal` service; wallets will refuse sign-in links from this \
             community. Publish {fix} in the VTC DID document (a VTA-side `dids edit`, \
             then `cnm did-log install` if this VTC serves its own did.jsonl)"
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

/// The trigger link's flow, in path form (VTI-LNK-042).
pub const SIGN_IN_FLOW: &str = "/vti/flow/sign-in/0.1";

/// Default link host (contract C1).
pub const DEFAULT_LINK_HOST: &str = "link.trustoverip.org";

/// Check a configured link host: the host rules (VTI-LNK-060), and not the
/// portal's own domain (VTI-LNK-084) — a universal link tapped on a page of
/// the same domain opens in the browser, not the wallet.
pub fn check_link_host(link_host: &str, portal_host: Option<&str>) -> Result<(), String> {
    let labels: Vec<&str> = link_host.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if link_host.len() > 253
        || labels.len() < 2
        || !labels.iter().all(label_ok)
        || labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
        || link_host == "localhost"
        || link_host.ends_with(".localhost")
        || link_host.ends_with(".local")
        || link_host.ends_with(".home.arpa")
    {
        return Err(format!(
            "sign-in link host `{link_host}` is not a public DNS name (VTI-LNK-060)"
        ));
    }
    if let Some(portal) = portal_host.map(str::to_ascii_lowercase) {
        let under = |a: &str, b: &str| a == b || a.ends_with(&format!(".{b}"));
        if under(&portal, link_host) || under(link_host, &portal) {
            return Err(format!(
                "sign-in link host `{link_host}` is on the portal's own domain `{portal}`; a \
                 universal link tapped there opens in the browser, not the wallet \
                 (VTI-LNK-084). Use a separate host, such as `{DEFAULT_LINK_HOST}`."
            ));
        }
    }
    Ok(())
}

/// Percent-encode `&`, `=`, `#` and `%`, and nothing else (contract C1).
pub fn encode_from(did: &str) -> String {
    let mut out = String::with_capacity(did.len());
    for c in did.chars() {
        match c {
            '&' => out.push_str("%26"),
            '=' => out.push_str("%3D"),
            '#' => out.push_str("%23"),
            '%' => out.push_str("%25"),
            c => out.push(c),
        }
    }
    out
}

/// The trigger link for a request (contract C1). The portal builds the same
/// text in the browser; this is the reference the tests hold it to.
pub fn trigger_link(
    link_host: &str,
    vtc_did: &str,
    request_id: &str,
    claim_deadline: u64,
) -> String {
    format!(
        "https://{link_host}/t#_from={}&_id={request_id}&_exp={claim_deadline}&_type={SIGN_IN_FLOW}",
        encode_from(vtc_did)
    )
}

/// Largest trigger link a producer may emit at QR level M (VTI-LNK-081).
pub const MAX_LINK_BYTES_LEVEL_M: usize = 251;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_are_22_base64url_characters() {
        let id = new_request_id();
        assert_eq!(id.len(), 22);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_ne!(id, new_request_id());
    }

    #[test]
    fn match_numbers_are_two_digits() {
        for _ in 0..200 {
            let n = new_match_number();
            assert_eq!(n.len(), 2);
            assert!(n.bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn only_ed25519_did_keys_are_accepted() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
        );
        assert!(is_ed25519_did_key(&did));
        assert!(!is_ed25519_did_key("did:key:zDnaeexample"));
        assert!(!is_ed25519_did_key("did:webvh:abc:example.com"));
        assert!(!is_ed25519_did_key("did:key:z6Mk"));
    }

    #[test]
    fn effective_state_follows_both_clocks() {
        let mut r = OobRequest {
            request_id: "r".into(),
            state: OobState::Pending,
            start_key: "k".into(),
            start_network: None,
            approver_key: None,
            purpose: "login".into(),
            mode: "scan".into(),
            origin: "https://x.example".into(),
            match_number: None,
            match_number_delivered: false,
            requester: RequesterDetails {
                location: "unknown".into(),
                browser: "Chrome".into(),
                os: "macOS".into(),
                created_at: rfc3339(0),
            },
            identified_did: None,
            step2_digest: None,
            step1: None,
            created_at: 0,
            claim_deadline: 120,
            decision_deadline: None,
            grant: None,
            ended_at: None,
            audience: SessionAudience::Member,
            decline_reason: None,
        };
        assert_eq!(r.effective_state(119), OobState::Pending);
        assert_eq!(r.effective_state(120), OobState::Expired);
        r.state = OobState::Claimed;
        r.decision_deadline = Some(300);
        // A claimed request runs on the decision clock, not the claim clock.
        assert_eq!(r.effective_state(200), OobState::Claimed);
        assert_eq!(r.effective_state(300), OobState::Expired);
    }

    #[test]
    fn same_network_compares_v4_addresses_and_v6_prefixes() {
        let v4: IpAddr = "203.0.113.5".parse().unwrap();
        assert_eq!(same_network(Some("203.0.113.5"), Some(v4)), true);
        assert_eq!(same_network(Some("203.0.113.6"), Some(v4)), false);
        let a: IpAddr = "2001:db8:1:2::10".parse().unwrap();
        assert_eq!(same_network(Some("2001:db8:1:2::99"), Some(a)), true);
        assert_eq!(same_network(Some("2001:db8:1:3::99"), Some(a)), false);
        assert_eq!(same_network(None, Some(a)), "unknown");
    }

    #[test]
    fn browser_and_os_never_echo_the_user_agent() {
        let mac_chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
        assert_eq!(
            browser_and_os(Some(mac_chrome)),
            ("Chrome".into(), "macOS".into())
        );
        let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 \
                      (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
        assert_eq!(
            browser_and_os(Some(iphone)),
            ("Safari".into(), "iOS".into())
        );
        assert_eq!(browser_and_os(None), ("unknown".into(), "unknown".into()));
    }

    #[test]
    fn trigger_link_matches_the_contract_and_fits_level_m() {
        let did = "did:webvh:QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG:members.example.org";
        let link = trigger_link(DEFAULT_LINK_HOST, did, &new_request_id(), 1_760_000_000);
        assert!(link.starts_with("https://link.trustoverip.org/t#_from=did:webvh:"));
        assert!(link.ends_with("&_exp=1760000000&_type=/vti/flow/sign-in/0.1"));
        assert!(link.is_ascii());
        assert!(link.len() <= MAX_LINK_BYTES_LEVEL_M, "{} bytes", link.len());
        assert_eq!(encode_from("a&b=c#d%e"), "a%26b%3Dc%23d%25e");
    }

    #[test]
    fn link_host_must_be_public_and_off_the_portal_domain() {
        assert!(check_link_host(DEFAULT_LINK_HOST, Some("members.example.org")).is_ok());
        assert!(check_link_host("link.example.org", Some("example.org")).is_err());
        assert!(check_link_host("example.org", Some("members.example.org")).is_err());
        assert!(check_link_host("members.example.org", Some("members.example.org")).is_err());
        assert!(check_link_host("localhost", None).is_err());
        assert!(check_link_host("10.0.0.1", None).is_err());
        assert!(check_link_host("Link.Example.org", None).is_err());
    }

    #[test]
    fn context_digest_is_a_multibase_sha256_multihash() {
        let v = serde_json::json!({ "b": 1, "a": [true] });
        let d = context_digest(&v).unwrap();
        assert!(d.starts_with('z'));
        let (_, bytes) = multibase::decode(&d).unwrap();
        assert_eq!(&bytes[..2], &[0x12, 0x20]);
        // Key order does not matter; JCS sorts.
        assert_eq!(
            d,
            context_digest(&serde_json::json!({ "a": [true], "b": 1 })).unwrap()
        );
        let u = multibase::encode(multibase::Base::Base64Url, &bytes);
        assert!(same_digest(&d, &u));
        assert!(!same_digest(&d, &hex::encode(&bytes)));
        assert!(!same_digest(&d, "zabc"));
        assert_eq!(
            epoch_of(&serde_json::json!(1_760_000_000u64)),
            Some(1_760_000_000)
        );
        assert_eq!(epoch_of(&serde_json::json!("2025-10-09T08:53:20Z")), None);
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
