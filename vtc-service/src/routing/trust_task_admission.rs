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

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tower_governor::key_extractor::KeyExtractor;
use vti_common::rate_limit::TrustedProxyKeyExtractor;

use super::rate_limit::{RateLimited, SIGNED_ADDRESS_LIMITER, SIGNER_LIMITER, UNAUTH_LIMITER};
use crate::server::AppState;
use crate::trust_tasks::VerifiedAdmission;

/// A known signer's bucket: a burst of 60, then one document every 500 ms.
pub const SIGNER_BURST: u32 = 60;
pub const SIGNER_PERIOD: Duration = Duration::from_millis(500);

/// The per-address ceiling on documents claiming a known signer: a burst of
/// 120, then one every 250 ms.
pub const SIGNED_ADDRESS_BURST: u32 = 120;
pub const SIGNED_ADDRESS_PERIOD: Duration = Duration::from_millis(250);

/// The door's limiters, shared by every request.
#[derive(Clone)]
pub struct TrustTaskLimits {
    /// The unauthenticated governor's own state — the one the tower layer on
    /// the other unauthenticated routes charges.
    address: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    signed_address: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    signer: Arc<DefaultKeyedRateLimiter<String>>,
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
        )
    }

    fn with_quotas(
        address: Arc<DefaultKeyedRateLimiter<IpAddr>>,
        key_extractor: TrustedProxyKeyExtractor,
        signed_address: Quota,
        signer: Quota,
    ) -> Self {
        Self {
            address,
            signed_address: Arc::new(RateLimiter::keyed(signed_address)),
            signer: Arc::new(RateLimiter::keyed(signer)),
            key_extractor,
        }
    }
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
        let claimed = match claimed_signer(body) {
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

    /// Settle the document once the spine is done with it: the refusal the
    /// spine stopped on, or — for a document that claimed a known signer and
    /// never verified as it — the strict governor's charge, which may itself
    /// refuse.
    pub fn finish(self) -> Result<(), RateLimited> {
        if let Some(limited) = self.refusal.lock().ok().and_then(|mut slot| slot.take()) {
            return Err(limited);
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

impl VerifiedAdmission for Admission {
    fn admit_verified(&self, signer: &str) -> bool {
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
fn claimed_signer(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Claim {
        issuer: Option<String>,
        proof: Option<serde::de::IgnoredAny>,
    }
    let claim: Claim = serde_json::from_slice(body).ok()?;
    claim.proof?;
    claim.issuer.filter(|did| did.starts_with("did:"))
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
        let slow = Duration::from_secs(3600);
        TrustTaskLimits::with_quotas(
            Arc::new(RateLimiter::keyed(quota(slow, 2))),
            TrustedProxyKeyExtractor::new(Vec::new()),
            quota(slow, signed_address_burst),
            quota(slow, signer_burst),
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
        }
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
}
