//! The request store, its compare-and-set, and the two clocks.
//!
//! - **The request store.** One row per request in the host's records
//!   keyspace (`oob_req:<requestId>`), swept by the host's timer ([`sweep`]).
//! - **Compare-and-set.** Every change of state is made under one process-wide
//!   lock, against the state the caller read ([`transition`]). Exactly one of
//!   two racing claims, proofs, decisions or redemptions wins. A host serving
//!   these tasks is a single process (the VTC never runs in a TEE), so a
//!   process lock is the whole story.
//! - **Two clocks.** A request must be claimed within [`CLAIM_WINDOW_SECS`] of
//!   creation; a claim starts a fresh [`DECISION_WINDOW_SECS`] window covering
//!   prove, respond and redeem (base design §7.2).

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vti_common::auth::session::now_epoch;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::audience::Audience;
use crate::poll::NOTIFIER;

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

/// What the service records from the starter's connection at `request`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RequesterDetails {
    pub location: String,
    pub browser: String,
    pub os: String,
    pub created_at: String,
}

/// One request (base design §7.2's stored fields), for a host whose
/// audiences are `A`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", bound = "A: Audience")]
pub struct OobRequest<A: Audience> {
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
    /// [`crate::context_digest`] of the signed step 2 response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step2_digest: Option<String>,
    /// The step 1 fields (`auth/oob/claim/0.2#response`) as signed, so step 2
    /// repeats them byte for byte. Kept as JSON: step 2 is a different
    /// generated type with the same members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step1: Option<serde_json::Value>,
    pub created_at: u64,
    pub claim_deadline: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_deadline: Option<u64>,
    /// The signed grant, once approved or declined by the approver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<serde_json::Value>,
    /// When the request reached a final state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<u64>,
    /// Which audience `redeem` issues for, fixed at `request`. Absent on rows
    /// of the default audience, and on rows stored before the field existed.
    #[serde(default, skip_serializing_if = "Audience::is_default")]
    pub audience: A,
    /// The task families step 2 offered to let `K_b` sign for, as the
    /// approver (`auth/oob/prove/0.3`). `None`: an audience that offers none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_scope: Option<Vec<String>>,
    /// Why a request was declined, when the starter is told
    /// ([`crate::Eligibility::RefusedTelling`]). `redeem` reports it in
    /// `details.reason`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<String>,
}

impl<A: Audience> OobRequest<A> {
    /// The audience the service signed into step 1 (and so into step 2, which
    /// repeats it, and so into the grant's `contextDigest`). `None` before
    /// the claim, or if the stored extension cannot be read. A default
    /// request's step 1 carries no extension, which reads as the default.
    pub fn signed_audience(&self) -> Option<A> {
        self.step1
            .as_ref()
            .and_then(|s| A::from_ext(s.get("ext")).ok())
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

pub async fn load<A: Audience>(
    ks: &KeyspaceHandle,
    request_id: &str,
) -> Result<Option<OobRequest<A>>, AppError> {
    ks.get::<OobRequest<A>>(record_key(request_id)).await
}

async fn store<A: Audience>(ks: &KeyspaceHandle, rec: &OobRequest<A>) -> Result<(), AppError> {
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
pub async fn transition<A: Audience, T, E>(
    ks: &KeyspaceHandle,
    request_id: &str,
    f: impl FnOnce(&mut OobRequest<A>) -> Result<T, E>,
) -> Result<(T, OobRequest<A>), TransitionError<E>> {
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
pub async fn create<A: Audience>(ks: &KeyspaceHandle, rec: &OobRequest<A>) -> Result<(), AppError> {
    let _guard = TRANSITIONS.lock().await;
    if load::<A>(ks, &rec.request_id).await?.is_some() {
        return Err(AppError::Conflict("request id collision".into()));
    }
    store(ks, rec).await
}

/// Write down an expiry the clock has already decided, so the row ends, the
/// address is dropped, and waiters learn. Returns `true` when this call was
/// the one that ended it (the caller audits once).
pub async fn settle_expiry<A: Audience>(
    ks: &KeyspaceHandle,
    request_id: &str,
) -> Result<bool, AppError> {
    let now = now_epoch();
    match transition::<A, _, _>(ks, request_id, |rec| {
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
pub async fn open_requests_from<A: Audience>(
    ks: &KeyspaceHandle,
    address: &str,
) -> Result<usize, AppError> {
    let now = now_epoch();
    let rows = ks.prefix_iter_raw(RECORD_PREFIX).await?;
    Ok(rows
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<OobRequest<A>>(&v).ok())
        .filter(|r| {
            r.start_network.as_deref() == Some(address)
                && r.effective_state(now) == OobState::Pending
        })
        .count())
}

/// Drop ended requests past [`ENDED_RETENTION_SECS`], and end (and drop the
/// address of) requests whose clock has run out. The host runs it on a timer
/// over its records keyspace (the VTC: beside `cleanup_expired_sessions`).
pub async fn sweep<A: Audience>(ks: &KeyspaceHandle) -> Result<usize, AppError> {
    let now = now_epoch();
    let rows = ks.prefix_iter_raw(RECORD_PREFIX).await?;
    let mut removed = 0;
    for (key, value) in rows {
        let Ok(rec) = serde_json::from_slice::<OobRequest<A>>(&value) else {
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
                settle_expiry::<A>(ks, &rec.request_id).await?;
            }
            _ => {}
        }
    }
    Ok(removed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::util::rfc3339;

    /// A host with one audience, as the VTN is.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) enum OneAudience {
        #[default]
        Only,
    }

    impl Audience for OneAudience {
        fn from_ext(_: Option<&serde_json::Value>) -> Result<Self, String> {
            Ok(Self::Only)
        }
        fn to_ext(self) -> Option<serde_json::Value> {
            None
        }
    }

    pub(crate) fn pending(id: &str) -> OobRequest<OneAudience> {
        OobRequest {
            request_id: id.into(),
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
            audience: OneAudience::Only,
            decline_reason: None,
            signing_scope: None,
        }
    }

    #[test]
    fn effective_state_follows_both_clocks() {
        let mut r = pending("r");
        assert_eq!(r.effective_state(119), OobState::Pending);
        assert_eq!(r.effective_state(120), OobState::Expired);
        r.state = OobState::Claimed;
        r.decision_deadline = Some(300);
        // A claimed request runs on the decision clock, not the claim clock.
        assert_eq!(r.effective_state(200), OobState::Claimed);
        assert_eq!(r.effective_state(300), OobState::Expired);
    }

    #[test]
    fn the_default_audience_is_never_written() {
        let v = serde_json::to_value(pending("r")).unwrap();
        assert!(v.get("audience").is_none());
        let back: OobRequest<OneAudience> = serde_json::from_value(v).unwrap();
        assert_eq!(back.audience, OneAudience::Only);
    }

    async fn keyspace() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        (store.keyspace("member_sessions").unwrap(), dir)
    }

    #[tokio::test]
    async fn exactly_one_of_two_racing_transitions_wins() {
        let (ks, _dir) = keyspace().await;
        let mut rec = pending("race");
        rec.claim_deadline = now_epoch() + 60;
        create(&ks, &rec).await.unwrap();
        assert!(create(&ks, &rec).await.is_err(), "an id is created once");
        let claim = |key: &'static str| {
            let ks = ks.clone();
            async move {
                transition::<OneAudience, _, _>(&ks, "race", |r| {
                    if r.state != OobState::Pending {
                        return Err(());
                    }
                    r.state = OobState::Claimed;
                    r.approver_key = Some(key.into());
                    Ok(())
                })
                .await
                .is_ok()
            }
        };
        let (a, b) = tokio::join!(claim("a"), claim("b"));
        assert!(a ^ b, "one claim wins: {a} {b}");
        assert!(matches!(
            transition::<OneAudience, (), ()>(&ks, "missing", |_| Ok(())).await,
            Err(TransitionError::NotFound)
        ));
    }

    #[tokio::test]
    async fn an_expired_request_is_settled_once_and_swept_after_retention() {
        let (ks, _dir) = keyspace().await;
        let mut rec = pending("old");
        rec.start_network = Some("203.0.113.9".into());
        // Ran out a moment ago.
        rec.claim_deadline = now_epoch() - 1;
        create(&ks, &rec).await.unwrap();
        assert_eq!(
            open_requests_from::<OneAudience>(&ks, "203.0.113.9")
                .await
                .unwrap(),
            0
        );
        assert_eq!(sweep::<OneAudience>(&ks).await.unwrap(), 0);
        let settled = load::<OneAudience>(&ks, "old").await.unwrap().unwrap();
        assert_eq!(settled.state, OobState::Expired);
        assert_eq!(
            settled.start_network, None,
            "the address goes at the end (T22)"
        );
        assert!(!settle_expiry::<OneAudience>(&ks, "old").await.unwrap());

        // Past retention, the row goes.
        let mut aged = settled;
        aged.ended_at = Some(now_epoch() - ENDED_RETENTION_SECS - 1);
        ks.insert(record_key("old"), &aged).await.unwrap();
        assert_eq!(sweep::<OneAudience>(&ks).await.unwrap(), 1);
        assert!(load::<OneAudience>(&ks, "old").await.unwrap().is_none());
    }
}
