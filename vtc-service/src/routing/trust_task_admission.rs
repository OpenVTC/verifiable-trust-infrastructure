//! Rate limits on the HTTPS Trust Task door, `POST /v1/trust-tasks`.
//!
//! The door serves anonymous and signed traffic alike, so one per-address
//! budget cannot fit both. The unauthenticated governor (a burst of 10, then
//! one request every 5 s) is right for a stranger making this service resolve
//! DIDs and verify signatures; an administrator whose console now signs every
//! read exhausts it while navigating. So a document is charged one of two
//! budgets, decided by who signed it:
//!
//! | the document | charged, and when |
//! |---|---|
//! | unsigned, or signed by a DID the community holds no entry for | the per-address governor ([`UNAUTH_LIMITER`]), **before** anything is verified |
//! | signed by a DID that holds a live ACL entry (or a console key delegated by one) | the signer's own bucket ([`SIGNER_LIMITER`]), **after** its proof verifies |
//! | claiming such a signer but not verifying as it | the per-address governor as well, as soon as the claim fails |
//!
//! # Why a fresh DID buys nothing
//!
//! Minting a `did:key` is free, so a bucket per signer would be a bucket per
//! request if any signer got one. Only a DID the community already knows does:
//! the ACL is written by administrators, so the number of signer buckets is
//! bounded by the community's own membership. A console key is charged to the
//! administrator it acts for, so several consoles share their admin's bucket.
//!
//! # Why the claim is trusted before it is verified
//!
//! Whether the claimed signer is known is decided from the document's `issuer`
//! before the proof is checked — it has to be, or the strict governor would
//! already have been charged. An attacker can name a member's DID and send
//! garbage; what that buys them is bounded twice:
//!
//! - every such document from an address is first charged that address's
//!   [`SIGNED_ADDRESS_LIMITER`] ceiling, generous enough for a console and
//!   small enough to bound the verification work one address can cause;
//! - one that then fails to verify as that signer is charged the strict
//!   per-address governor too, so an address sending forgeries loses its
//!   anonymous budget exactly as an anonymous flood would;
//! - and the signer's own bucket is charged only once the proof verifies, so
//!   nobody can drain a member's budget by naming them.
//!
//! The same per-address governor state backs the other unauthenticated routes
//! ([`crate::routes`]), so moving this door off the tower layer does not give
//! an address a second anonymous budget.
//!
//! # Room traffic
//!
//! A `rooms/*` document is neither anonymous nor a known signer's: its presenter
//! holds no ACL entry here, by design (`docs/02-vta/data-rooms.md` §8.2), and is
//! authorized by the credentials the room issued. Held to the anonymous governor,
//! one member reading a room or fetching a file of a few chunks was refused
//! within seconds, and so was everyone else behind the same address. So the
//! closed set of room task types ([`crate::rooms::handlers::serves`]) is charged
//! on what it proves, in two steps:
//!
//! | the document | charged, and when |
//! |---|---|
//! | any `rooms/*` document | the address's room ceiling ([`ROOM_ADDRESS_LIMITER`]), **before** anything is verified |
//! | one the room has authorized | its (room, presenter) budget ([`ROOM_PRESENTER_LIMITER`]), or for a file chunk the transfer budget ([`ROOM_TRANSFER_LIMITER`]), **after** the authorization and before the work |
//! | one that never verifies, or that its room never authorizes | the address's room ceiling again, [`ROOM_FAILURE_COST`] times |
//!
//! The (room, presenter) budget is what lets two members behind one NAT work
//! side by side: neither's burst is the other's. It is charged only once the
//! room's own chain has authorized the presenter, so its keys are bounded by
//! the rooms' memberships, not by how many `did:key`s a caller can mint — and
//! nobody can drain a member's budget by naming them. Its key is a hash under
//! a per-process secret, so this map holds no list of who is in which room.
//!
//! The address ceiling bounds the verification work one address can cause: it
//! is charged before the proof and the chain are checked, and a document that
//! fails either pays [`ROOM_FAILURE_COST`] more, so an address sending
//! documents nothing authorizes is held to a few a second once its burst is
//! spent. Room documents never touch the anonymous governor, so a room flood
//! does not cost an address its join or sign-in budget, nor the reverse.
//!
//! A file chunk is charged to the transfer budget once the presenter is shown to
//! hold the upload or download it names (`BlobHost::transfer_room`), and an upload
//! chunk admitted under the address ceiling skips the large-document budget
//! (`crate::trust_tasks::size::check_for_known_issuer_with`): those two together
//! are what lets a whole file move.
//!
//! The budgets are `[rooms.rate_limits]` ([`crate::config::RoomRateLimitsConfig`]),
//! read when the first room document arrives.
//!
//! # Sign-in traffic
//!
//! Every `auth/oob/*` document is signed by a throwaway `did:key` — the
//! portal's `K_b` for `request`, `redeem` and `cancel`, the wallet's `K_a` for
//! `claim`, `prove` and `respond` — so none is a known signer's, and on the
//! anonymous governor one sign-in spent most of an address's burst of 10: the
//! page's request and its redeem polls, the wallet's three steps, from the same
//! address when the wallet is on the same device. A second sign-in, or a
//! reload, within the minute was refused, and so was everyone else behind the
//! same NAT. So the closed set of sign-in task types ([`oob_tasks::URIS`]) is
//! charged to its own per-address ceiling, like rooms:
//!
//! | the document | charged, and when |
//! |---|---|
//! | any `auth/oob/*` document | the address's sign-in ceiling ([`SIGN_IN_ADDRESS_LIMITER`]), **before** anything is verified |
//! | one whose proof never verifies | the address's sign-in ceiling again, [`SIGN_IN_FAILURE_COST`] times |
//!
//! One sign-in is about ten documents (`request`, a redeem answer per state
//! change, `claim`, `prove`, `respond`, sometimes `cancel`), so a burst of
//! [`SIGN_IN_BURST`] fits several people signing in at once behind one address,
//! and one a second sustains several a minute. What a document can make the
//! service do before it is refused is one signature check over a key the
//! document carries (a `did:key` resolves locally), plus, for `prove`, the
//! member's own identify, so a flood of forgeries is held to one every
//! [`SIGN_IN_PERIOD`] × [`SIGN_IN_FAILURE_COST`] once its burst is spent. Sign-in
//! documents never touch the anonymous governor, so a join or recognise flood
//! does not cost an address its sign-ins, nor the reverse. The redeem
//! long-poll keeps its own cap on polls held open per address
//! (`oob_tasks::PollGuard`).

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tower_governor::key_extractor::KeyExtractor;
use vti_common::rate_limit::TrustedProxyKeyExtractor;

use super::rate_limit::{
    ROOM_ADDRESS_LIMITER, ROOM_PRESENTER_LIMITER, ROOM_TRANSFER_LIMITER, RateLimited,
    SIGN_IN_ADDRESS_LIMITER, SIGNED_ADDRESS_LIMITER, SIGNER_LIMITER, UNAUTH_LIMITER,
};
use crate::config::{RoomBudget, RoomRateLimitsConfig};
use crate::server::AppState;
use crate::trust_tasks::VerifiedAdmission;
use crate::trust_tasks::oob_tasks;

/// A known signer's bucket: a burst of 60, then one document every 500 ms.
pub const SIGNER_BURST: u32 = 60;
pub const SIGNER_PERIOD: Duration = Duration::from_millis(500);

/// The per-address ceiling on documents claiming a known signer: a burst of
/// 120, then one every 250 ms.
pub const SIGNED_ADDRESS_BURST: u32 = 120;
pub const SIGNED_ADDRESS_PERIOD: Duration = Duration::from_millis(250);

/// The per-address ceiling on sign-in documents: a burst of 60, then one a
/// second (see the module docs).
pub const SIGN_IN_BURST: u32 = 60;
pub const SIGN_IN_PERIOD: Duration = Duration::from_secs(1);

/// What a sign-in document whose proof never verifies costs the address's
/// sign-in ceiling on top of the one it paid on arrival.
pub const SIGN_IN_FAILURE_COST: u32 = 10;

/// Past this many tracked addresses, the sign-in limiter forgets the ones that
/// have refilled completely.
const SIGN_IN_TRACKED_KEYS: usize = 10_000;

/// The door's limiters, shared by every request.
#[derive(Clone)]
pub struct TrustTaskLimits {
    /// The unauthenticated governor's own state — the one the tower layer on
    /// the other unauthenticated routes charges.
    address: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    signed_address: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    signer: Arc<DefaultKeyedRateLimiter<String>>,
    /// The sign-in (`auth/oob/*`) ceiling, per address.
    sign_in: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    /// The room budgets, built from `[rooms.rate_limits]` when the first room
    /// document arrives (the router is built before the configuration is read).
    rooms: Arc<OnceLock<Arc<RoomLimiters>>>,
    key_extractor: TrustedProxyKeyExtractor,
}

impl TrustTaskLimits {
    /// `address` is the unauthenticated governor's limiter, so both charge one
    /// budget per address.
    pub fn new(
        address: Arc<DefaultKeyedRateLimiter<IpAddr>>,
        key_extractor: TrustedProxyKeyExtractor,
    ) -> Self {
        Self::with_quotas(
            address,
            key_extractor,
            quota(SIGNED_ADDRESS_PERIOD, SIGNED_ADDRESS_BURST),
            quota(SIGNER_PERIOD, SIGNER_BURST),
            quota(SIGN_IN_PERIOD, SIGN_IN_BURST),
        )
    }

    fn with_quotas(
        address: Arc<DefaultKeyedRateLimiter<IpAddr>>,
        key_extractor: TrustedProxyKeyExtractor,
        signed_address: Quota,
        signer: Quota,
        sign_in: Quota,
    ) -> Self {
        Self {
            address,
            signed_address: Arc::new(RateLimiter::keyed(signed_address)),
            signer: Arc::new(RateLimiter::keyed(signer)),
            sign_in: Arc::new(RateLimiter::keyed(sign_in)),
            rooms: Arc::new(OnceLock::new()),
            key_extractor,
        }
    }

    fn charge_sign_in(&self, address: &IpAddr) -> Result<(), RateLimited> {
        if self.sign_in.len() > SIGN_IN_TRACKED_KEYS {
            self.sign_in.retain_recent();
        }
        charge(&self.sign_in, address).map_err(|wait| {
            RateLimited::new(
                SIGN_IN_ADDRESS_LIMITER,
                wait,
                "too many sign-in documents from this address; wait for the \
                 Retry-After period before retrying",
            )
        })
    }

    /// Spend up to [`SIGN_IN_FAILURE_COST`] of the address's sign-in ceiling.
    fn penalize_sign_in(&self, address: &IpAddr) {
        for _ in 0..SIGN_IN_FAILURE_COST {
            if self.sign_in.check_key(address).is_err() {
                break;
            }
        }
    }

    /// The room budgets, built from the configuration on first use.
    async fn rooms(&self, state: &AppState) -> Arc<RoomLimiters> {
        if let Some(rooms) = self.rooms.get() {
            return rooms.clone();
        }
        let config = state.config.read().await.rooms.rate_limits.clone();
        self.rooms
            .get_or_init(|| Arc::new(RoomLimiters::new(&config)))
            .clone()
    }
}

/// What a document that never verifies, or that its room never authorizes,
/// costs the address's room ceiling on top of the one it paid on arrival.
/// With the default ceiling (one every 10 ms) such documents are held to about
/// four a second once the burst is spent — the known-signer ceiling's rate.
pub const ROOM_FAILURE_COST: u32 = 25;

/// Past this many tracked keys, a room limiter forgets the ones that have
/// refilled completely, so its map does not grow with every address that ever
/// sent a room document.
const ROOM_TRACKED_KEYS: usize = 10_000;

/// The room budgets (see the module docs).
pub(crate) struct RoomLimiters {
    address: DefaultKeyedRateLimiter<IpAddr>,
    presenter: DefaultKeyedRateLimiter<[u8; 16]>,
    transfer: DefaultKeyedRateLimiter<[u8; 16]>,
    /// Keys the (room, presenter) hash, so the maps name nobody.
    secret: [u8; 32],
}

impl RoomLimiters {
    fn new(config: &RoomRateLimitsConfig) -> Self {
        Self::with_budgets(config.address(), config.presenter(), config.transfer())
    }

    fn with_budgets(address: RoomBudget, presenter: RoomBudget, transfer: RoomBudget) -> Self {
        let q = |b: RoomBudget| quota(b.interval, b.burst);
        let mut secret = [0u8; 32];
        rand::fill(&mut secret);
        Self {
            address: RateLimiter::keyed(q(address)),
            presenter: RateLimiter::keyed(q(presenter)),
            transfer: RateLimiter::keyed(q(transfer)),
            secret,
        }
    }

    fn member_key(&self, room_id: &str, presenter: &str) -> [u8; 16] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.secret);
        h.update(room_id.as_bytes());
        h.update([0u8]);
        h.update(presenter.as_bytes());
        let digest = h.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);
        key
    }

    fn charge_address(&self, address: &IpAddr) -> Result<(), RateLimited> {
        if self.address.len() > ROOM_TRACKED_KEYS {
            self.address.retain_recent();
        }
        charge(&self.address, address).map_err(|wait| {
            RateLimited::new(
                ROOM_ADDRESS_LIMITER,
                wait,
                "too many room documents from this address; wait for the \
                 Retry-After period before retrying",
            )
        })
    }

    /// Spend up to [`ROOM_FAILURE_COST`] of the address's room ceiling.
    fn penalize(&self, address: &IpAddr) {
        for _ in 0..ROOM_FAILURE_COST {
            if self.address.check_key(address).is_err() {
                break;
            }
        }
    }

    fn charge_member(
        &self,
        room_id: &str,
        presenter: &str,
        traffic: RoomTraffic,
    ) -> Result<(), RateLimited> {
        let (limiter, name, what) = match traffic {
            RoomTraffic::Operation => (&self.presenter, ROOM_PRESENTER_LIMITER, "room operations"),
            RoomTraffic::Transfer => (&self.transfer, ROOM_TRANSFER_LIMITER, "file chunks"),
        };
        if limiter.len() > ROOM_TRACKED_KEYS {
            limiter.retain_recent();
        }
        charge(limiter, &self.member_key(room_id, presenter)).map_err(|wait| {
            RateLimited::new(
                name,
                wait,
                format!(
                    "too many {what} from this presenter in this room; wait for the \
                     Retry-After period before retrying"
                ),
            )
        })
    }
}

/// Which budget an operation a room has authorized is charged to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RoomTraffic {
    /// Every room task but a file chunk.
    Operation,
    /// `rooms/blobs/upload/chunk` and `rooms/blobs/chunk`.
    Transfer,
}

/// One room document's admission, reachable from the room handlers while the
/// spine runs it ([`admit_room`]).
pub(crate) struct RoomAdmission {
    limiters: Arc<RoomLimiters>,
    address: IpAddr,
    /// The room authorized the operation, and its budget was charged.
    authorized: AtomicBool,
    refusal: Mutex<Option<RateLimited>>,
}

tokio::task_local! {
    static ROOM_ADMISSION: Arc<RoomAdmission>;
}

/// Charge an operation the room has just authorized to `presenter`'s budget in
/// `room_id`. Called by the room handlers after the authorization and before
/// the work; `false` means refused, and the handler answers with
/// [`crate::trust_tasks::helpers::TrustTaskOutcome`] status `429` and no body,
/// which the HTTPS door replaces with the refusal recorded here.
///
/// Off the HTTPS door — DIDComm, TSP, a test calling a handler directly — no
/// admission is in scope and every operation is admitted.
pub(crate) fn admit_room(room_id: &str, presenter: &str, traffic: RoomTraffic) -> bool {
    ROOM_ADMISSION
        .try_with(|room| {
            room.authorized.store(true, Ordering::SeqCst);
            match room.limiters.charge_member(room_id, presenter, traffic) {
                Ok(()) => true,
                Err(limited) => {
                    if let Ok(mut slot) = room.refusal.lock() {
                        *slot = Some(limited);
                    }
                    false
                }
            }
        })
        .unwrap_or(true)
}

fn quota(period: Duration, burst: u32) -> Quota {
    Quota::with_period(period)
        .expect("the period is a non-zero constant")
        .allow_burst(NonZeroU32::new(burst).expect("the burst is a non-zero constant"))
}

/// Charge `key` one request, or say how long to wait.
fn charge<K>(limiter: &DefaultKeyedRateLimiter<K>, key: &K) -> Result<(), u64>
where
    K: std::hash::Hash + Eq + Clone,
{
    limiter.check_key(key).map_err(|not_until| {
        not_until
            .wait_time_from(DefaultClock::default().now())
            .as_secs_f64()
            .ceil() as u64
    })
}

fn unauth_refusal(wait: u64) -> RateLimited {
    RateLimited::new(
        UNAUTH_LIMITER,
        wait,
        "too many unauthenticated requests from this address; wait for the \
         Retry-After period before retrying",
    )
}

/// The address a request is charged to, as the governor keys it.
#[derive(Clone, Copy, Debug)]
pub struct ClientAddress(pub IpAddr);

/// Resolve the request's [`ClientAddress`] exactly as the tower governor does
/// (trusted proxies, then the peer), refusing as it does when there is none.
pub async fn client_address(
    axum::extract::State(limits): axum::extract::State<TrustTaskLimits>,
    mut request: Request,
    next: Next,
) -> Response {
    match limits.key_extractor.extract(&request) {
        Ok(ip) => {
            request.extensions_mut().insert(ClientAddress(ip));
            request.extensions_mut().insert(limits);
            next.run(request).await
        }
        Err(e) => super::rate_limit::governor_error_response(e),
    }
}

/// The known signer a document claims, and the principal it is charged to.
struct Claimed {
    signer: String,
    principal: String,
}

/// One document's admission.
pub struct Admission {
    limits: TrustTaskLimits,
    address: IpAddr,
    claimed: Option<Claimed>,
    /// The claimed signer's proof verified, and its bucket was charged.
    verified: AtomicBool,
    /// The strict governor has been charged for this document.
    address_charged: AtomicBool,
    refusal: Mutex<Option<RateLimited>>,
    /// Set for a `rooms/*` document, which none of the above is charged for.
    room: Option<Arc<RoomAdmission>>,
    /// An `auth/oob/*` document, charged to the sign-in ceiling and nothing
    /// else; `verified` records whether its proof verified.
    sign_in: bool,
}

impl Admission {
    /// Decide, before anything is verified, which budget `body` is charged
    /// to, and charge what is charged now. `Err` is the refusal to answer.
    pub async fn begin(
        state: &AppState,
        limits: &TrustTaskLimits,
        address: IpAddr,
        body: &[u8],
    ) -> Result<Self, RateLimited> {
        let claim = read_claim(body);
        if claim
            .type_uri
            .as_deref()
            .is_some_and(crate::rooms::handlers::serves)
        {
            let limiters = limits.rooms(state).await;
            limiters.charge_address(&address)?;
            return Ok(Self {
                limits: limits.clone(),
                address,
                claimed: None,
                verified: AtomicBool::new(false),
                address_charged: AtomicBool::new(false),
                refusal: Mutex::new(None),
                room: Some(Arc::new(RoomAdmission {
                    limiters,
                    address,
                    authorized: AtomicBool::new(false),
                    refusal: Mutex::new(None),
                })),
                sign_in: false,
            });
        }
        if claim
            .type_uri
            .as_deref()
            .is_some_and(|t| oob_tasks::URIS.contains(&t))
        {
            limits.charge_sign_in(&address)?;
            return Ok(Self {
                limits: limits.clone(),
                address,
                claimed: None,
                verified: AtomicBool::new(false),
                address_charged: AtomicBool::new(false),
                refusal: Mutex::new(None),
                room: None,
                sign_in: true,
            });
        }
        let claimed = match claim.signer() {
            Some(did) => known_principal(state, &did).await.map(|principal| Claimed {
                signer: did,
                principal,
            }),
            None => None,
        };
        let admission = Self {
            limits: limits.clone(),
            address,
            claimed,
            verified: AtomicBool::new(false),
            address_charged: AtomicBool::new(false),
            refusal: Mutex::new(None),
            room: None,
            sign_in: false,
        };
        if admission.claimed.is_some() {
            charge(&limits.signed_address, &address).map_err(|wait| {
                RateLimited::new(
                    SIGNED_ADDRESS_LIMITER,
                    wait,
                    "too many signed documents from this address; wait for the \
                     Retry-After period before retrying",
                )
            })?;
        } else {
            admission.charge_address()?;
        }
        Ok(admission)
    }

    fn charge_address(&self) -> Result<(), RateLimited> {
        self.address_charged.store(true, Ordering::SeqCst);
        charge(&self.limits.address, &self.address).map_err(unauth_refusal)
    }

    fn refuse(&self, limited: RateLimited) -> bool {
        if let Ok(mut slot) = self.refusal.lock() {
            *slot = Some(limited);
        }
        false
    }

    /// The principal this document was verified as: the signer itself, or
    /// the administrator a console key acts for. `None` until the proof has
    /// verified as the known signer the document claimed.
    pub fn verified_principal(&self) -> Option<&str> {
        self.claimed
            .as_ref()
            .filter(|_| self.verified.load(Ordering::SeqCst))
            .map(|claimed| claimed.principal.as_str())
    }

    /// Settle the document once the spine is done with it: the refusal the
    /// spine stopped on, or — for a document that claimed a known signer and
    /// never verified as it — the strict governor's charge, which may itself
    /// refuse.
    pub fn finish(self) -> Result<(), RateLimited> {
        if let Some(room) = &self.room {
            if let Some(limited) = room.refusal.lock().ok().and_then(|mut slot| slot.take()) {
                return Err(limited);
            }
            // Never verified, or verified and never authorized by its room: the
            // verification it cost is paid for out of the address's ceiling.
            if !room.authorized.load(Ordering::SeqCst) {
                room.limiters.penalize(&room.address);
            }
            return Ok(());
        }
        if let Some(limited) = self.refusal.lock().ok().and_then(|mut slot| slot.take()) {
            return Err(limited);
        }
        // A sign-in document whose proof never verified: the verification it
        // cost is paid for out of the address's sign-in ceiling.
        if self.sign_in {
            if !self.verified.load(Ordering::SeqCst) {
                self.limits.penalize_sign_in(&self.address);
            }
            return Ok(());
        }
        if self.claimed.is_some()
            && !self.verified.load(Ordering::SeqCst)
            && !self.address_charged.load(Ordering::SeqCst)
        {
            self.charge_address()?;
        }
        Ok(())
    }
}

impl Admission {
    /// Run the spine for this document with its room admission in scope, so the
    /// room handlers can charge what the room authorizes ([`admit_room`]).
    pub async fn scope<F: std::future::Future>(&self, fut: F) -> F::Output {
        match &self.room {
            Some(room) => ROOM_ADMISSION.scope(room.clone(), fut).await,
            None => fut.await,
        }
    }
}

impl VerifiedAdmission for Admission {
    fn room_precharged(&self) -> bool {
        self.room.is_some()
    }

    fn admit_verified(&self, signer: &str) -> bool {
        // A room document is charged when its room authorizes it, not here.
        if self.room.is_some() {
            return true;
        }
        // A sign-in document was charged on arrival; record that it verified.
        if self.sign_in {
            self.verified.store(true, Ordering::SeqCst);
            return true;
        }
        match &self.claimed {
            // Charged to the address before verification.
            None => true,
            Some(claimed) if claimed.signer == signer => {
                self.verified.store(true, Ordering::SeqCst);
                match charge(&self.limits.signer, &claimed.principal) {
                    Ok(()) => true,
                    Err(wait) => self.refuse(RateLimited::new(
                        SIGNER_LIMITER,
                        wait,
                        "too many documents from this signer; wait for the \
                         Retry-After period before retrying",
                    )),
                }
            }
            // Verified as someone other than the signer it was admitted as.
            // The spine binds the proof to `issuer`, which is what was read,
            // so this is unreachable today; if it is ever reached, the
            // document has not earned the signer's budget.
            Some(_) => match self.charge_address() {
                Ok(()) => true,
                Err(limited) => self.refuse(limited),
            },
        }
    }
}

/// The DID a signed document names as its `issuer` — the only DID the spine
/// accepts a proof from. `None` for an unsigned document or one that does not
/// parse; the spine refuses the latter, and the strict governor pays for it.
#[cfg(test)]
fn claimed_signer(body: &[u8]) -> Option<String> {
    read_claim(body).signer()
}

/// What admission reads off a document before anything is verified: its
/// `type`, and the signer it claims.
#[derive(Default, serde::Deserialize)]
struct Claim {
    #[serde(rename = "type")]
    type_uri: Option<String>,
    issuer: Option<String>,
    proof: Option<serde::de::IgnoredAny>,
}

impl Claim {
    fn signer(self) -> Option<String> {
        self.proof?;
        self.issuer.filter(|did| did.starts_with("did:"))
    }
}

fn read_claim(body: &[u8]) -> Claim {
    serde_json::from_slice(body).unwrap_or_default()
}

/// The principal `did`'s documents are charged to, when the community knows
/// it: itself for a live ACL entry, or the administrator a live console-key
/// delegation acts for, when that administrator's entry is live. Resolved as
/// [`crate::trust_tasks`]'s `admin_signer` resolves a signer: its own row
/// first. Any store error answers `None`, which is the strict budget.
async fn known_principal(state: &AppState, did: &str) -> Option<String> {
    let now = crate::auth::session::now_epoch();
    let live = |entry: Option<crate::acl::VtcAclEntry>| entry.is_some_and(|e| !e.is_expired(now));
    match crate::acl::get_acl_entry(&state.acl_ks, did).await {
        Ok(Some(entry)) => return live(Some(entry)).then(|| did.to_string()),
        Ok(None) => {}
        Err(_) => return None,
    }
    let delegation = crate::acl::console_key::resolve_delegated_admin(&state.console_keys_ks, did)
        .await
        .ok()??;
    let admin = crate::acl::get_acl_entry(&state.acl_ks, &delegation.admin_did)
        .await
        .ok()?;
    live(admin).then_some(delegation.admin_did)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(signed_address_burst: u32, signer_burst: u32) -> TrustTaskLimits {
        limits_with_sign_in(signed_address_burst, signer_burst, 10)
    }

    fn limits_with_sign_in(
        signed_address_burst: u32,
        signer_burst: u32,
        sign_in_burst: u32,
    ) -> TrustTaskLimits {
        let slow = Duration::from_secs(3600);
        TrustTaskLimits::with_quotas(
            Arc::new(RateLimiter::keyed(quota(slow, 2))),
            TrustedProxyKeyExtractor::new(Vec::new()),
            quota(slow, signed_address_burst),
            quota(slow, signer_burst),
            quota(slow, sign_in_burst),
        )
    }

    fn admission(limits: &TrustTaskLimits, claimed: Option<&str>) -> Admission {
        Admission {
            limits: limits.clone(),
            address: IpAddr::from([192, 0, 2, 1]),
            claimed: claimed.map(|did| Claimed {
                signer: did.to_string(),
                principal: did.to_string(),
            }),
            verified: AtomicBool::new(false),
            address_charged: AtomicBool::new(false),
            refusal: Mutex::new(None),
            room: None,
            sign_in: false,
        }
    }

    fn sign_in_admission(limits: &TrustTaskLimits) -> Admission {
        Admission {
            sign_in: true,
            ..admission(limits, None)
        }
    }

    const HERE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

    #[test]
    fn every_sign_in_task_type_is_charged_to_the_sign_in_ceiling() {
        for uri in oob_tasks::URIS {
            assert!(
                uri.starts_with("https://trusttasks.org/spec/auth/oob/"),
                "{uri}"
            );
        }
        // `identify` and `grant` only ever ride inside `prove` and `respond`.
        assert!(!oob_tasks::URIS.iter().any(|u| u.contains("/identify/")));
        assert!(!oob_tasks::URIS.iter().any(|u| u.contains("/grant/")));
    }

    #[test]
    fn sign_in_documents_never_spend_the_anonymous_budget() {
        let limits = limits_with_sign_in(10, 10, 20);
        // Twelve verified sign-in documents: past the anonymous burst of 2.
        for _ in 0..12 {
            limits
                .charge_sign_in(&HERE)
                .expect("within the sign-in burst");
            let a = sign_in_admission(&limits);
            assert!(a.admit_verified("did:key:zKa"));
            a.finish().expect("verified, so no penalty");
        }
        assert!(
            charge(&limits.address, &HERE).is_ok(),
            "anonymous budget untouched"
        );
        assert!(charge(&limits.address, &HERE).is_ok());
    }

    #[test]
    fn the_sign_in_ceiling_refuses_past_its_burst() {
        let limits = limits_with_sign_in(10, 10, 3);
        for _ in 0..3 {
            limits.charge_sign_in(&HERE).expect("within the burst");
        }
        assert_eq!(
            limits.charge_sign_in(&HERE).unwrap_err().limiter(),
            SIGN_IN_ADDRESS_LIMITER
        );
        // Another address has its own.
        assert!(limits.charge_sign_in(&IpAddr::from([192, 0, 2, 2])).is_ok());
    }

    #[test]
    fn an_anonymous_flood_does_not_cost_sign_ins() {
        let limits = limits_with_sign_in(10, 10, 3);
        while charge(&limits.address, &HERE).is_ok() {}
        assert!(limits.charge_sign_in(&HERE).is_ok());
    }

    #[test]
    fn a_sign_in_document_that_never_verifies_costs_extra() {
        let limits = limits_with_sign_in(10, 10, SIGN_IN_FAILURE_COST + 2);
        limits.charge_sign_in(&HERE).expect("arrival");
        sign_in_admission(&limits)
            .finish()
            .expect("the penalty is not a refusal");
        // One left after the arrival and the penalty.
        limits.charge_sign_in(&HERE).expect("the last token");
        assert!(limits.charge_sign_in(&HERE).is_err());
        assert!(
            charge(&limits.address, &HERE).is_ok(),
            "never the anonymous budget"
        );
    }

    #[test]
    fn the_claimed_signer_is_the_issuer_of_a_signed_document() {
        let signed = br#"{"issuer":"did:key:z6Mk1","proof":{"type":"DataIntegrityProof"}}"#;
        assert_eq!(claimed_signer(signed).as_deref(), Some("did:key:z6Mk1"));
        assert_eq!(claimed_signer(br#"{"issuer":"did:key:z6Mk1"}"#), None);
        assert_eq!(claimed_signer(br#"{"issuer":"nope","proof":{}}"#), None);
        assert_eq!(claimed_signer(b"not json"), None);
    }

    #[test]
    fn a_verified_known_signer_is_charged_its_own_bucket_not_the_address() {
        let limits = limits(10, 3);
        for _ in 0..3 {
            let a = admission(&limits, Some("did:key:zAdmin"));
            assert!(a.admit_verified("did:key:zAdmin"));
            a.finish().expect("within the signer's burst");
        }
        // The address's strict budget (2) is untouched by the three above.
        assert!(charge(&limits.address, &IpAddr::from([192, 0, 2, 1])).is_ok());
        let a = admission(&limits, Some("did:key:zAdmin"));
        assert!(!a.admit_verified("did:key:zAdmin"));
        assert_eq!(a.finish().unwrap_err().limiter(), SIGNER_LIMITER);
    }

    #[test]
    fn a_claim_that_never_verifies_is_charged_the_address() {
        let limits = limits(10, 10);
        // The strict budget is 2: two failed claims spend it, the third is
        // refused by the address limiter.
        for _ in 0..2 {
            admission(&limits, Some("did:key:zAdmin"))
                .finish()
                .expect("within the address's burst");
        }
        let refused = admission(&limits, Some("did:key:zAdmin"))
            .finish()
            .unwrap_err();
        assert_eq!(refused.limiter(), UNAUTH_LIMITER);
    }

    #[test]
    fn the_verified_principal_is_known_only_once_the_proof_verifies() {
        let limits = limits(10, 10);
        // A console key acting for its administrator.
        let mut a = admission(&limits, Some("did:key:zConsoleKey"));
        a.claimed.as_mut().expect("claimed").principal = "did:key:zAdmin".to_string();
        assert_eq!(
            a.verified_principal(),
            None,
            "a claim is not a verification"
        );
        assert!(a.admit_verified("did:key:zConsoleKey"));
        assert_eq!(a.verified_principal(), Some("did:key:zAdmin"));

        let other = admission(&limits, Some("did:key:zAdmin"));
        assert!(other.admit_verified("did:key:zSomeoneElse"));
        assert_eq!(other.verified_principal(), None);
        assert_eq!(admission(&limits, None).verified_principal(), None);
    }

    #[test]
    fn verifying_as_another_signer_is_charged_the_address() {
        let limits = limits(10, 10);
        let a = admission(&limits, Some("did:key:zAdmin"));
        assert!(a.admit_verified("did:key:zSomeoneElse"));
        assert!(a.finish().is_ok());
        assert!(
            charge(&limits.signer, &"did:key:zAdmin".to_string()).is_ok(),
            "the claimed signer's bucket is not charged"
        );
        assert!(charge(&limits.address, &IpAddr::from([192, 0, 2, 1])).is_ok());
        assert!(
            charge(&limits.address, &IpAddr::from([192, 0, 2, 1])).is_err(),
            "the mismatched document spent one of the address's two"
        );
    }

    fn rooms(address: u32, presenter: u32, transfer: u32) -> Arc<RoomLimiters> {
        let slow = Duration::from_secs(3600);
        let b = |burst| RoomBudget {
            burst,
            interval: slow,
        };
        Arc::new(RoomLimiters::with_budgets(
            b(address),
            b(presenter),
            b(transfer),
        ))
    }

    fn room_admission(limiters: &Arc<RoomLimiters>) -> Arc<RoomAdmission> {
        Arc::new(RoomAdmission {
            limiters: limiters.clone(),
            address: IpAddr::from([192, 0, 2, 9]),
            authorized: AtomicBool::new(false),
            refusal: Mutex::new(None),
        })
    }

    #[test]
    fn a_room_document_off_the_https_door_is_admitted() {
        assert!(admit_room(
            "did:key:zRoom",
            "did:key:zMember",
            RoomTraffic::Operation
        ));
    }

    #[tokio::test]
    async fn presenters_and_rooms_are_charged_apart() {
        let limiters = rooms(100, 2, 1);
        let room = room_admission(&limiters);
        ROOM_ADMISSION
            .scope(room.clone(), async {
                for _ in 0..2 {
                    assert!(admit_room("r1", "alice", RoomTraffic::Operation));
                }
                assert!(!admit_room("r1", "alice", RoomTraffic::Operation));
                // Another presenter, the same presenter in another room, and the
                // transfer budget are all their own.
                assert!(admit_room("r1", "bob", RoomTraffic::Operation));
                assert!(admit_room("r2", "alice", RoomTraffic::Operation));
                assert!(admit_room("r1", "alice", RoomTraffic::Transfer));
                assert!(!admit_room("r1", "alice", RoomTraffic::Transfer));
            })
            .await;
        let refused = room.refusal.lock().unwrap().take().expect("recorded");
        assert_eq!(
            refused.limiter(),
            super::super::rate_limit::ROOM_TRANSFER_LIMITER
        );
        assert!(room.authorized.load(Ordering::SeqCst));
    }

    #[test]
    fn a_room_document_never_authorized_costs_the_address_extra() {
        let limiters = rooms(ROOM_FAILURE_COST + 2, 10, 10);
        let address = IpAddr::from([192, 0, 2, 9]);
        limiters.charge_address(&address).expect("first");
        limiters.penalize(&address);
        // One left of the burst after the arrival and the penalty.
        limiters.charge_address(&address).expect("the last token");
        assert_eq!(
            limiters.charge_address(&address).unwrap_err().limiter(),
            super::super::rate_limit::ROOM_ADDRESS_LIMITER
        );
    }

    #[test]
    fn the_member_key_names_nobody_and_separates_room_from_presenter() {
        let limiters = rooms(1, 1, 1);
        let k = limiters.member_key("ab", "c");
        assert_ne!(k, limiters.member_key("a", "bc"));
        assert_ne!(k, rooms(1, 1, 1).member_key("ab", "c"), "keyed per process");
    }
}
