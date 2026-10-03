//! The largest document each Trust Task type may be, checked before the
//! document is parsed.
//!
//! One cap for every type is either too small for the few tasks whose payload
//! is legitimately large (a Rego module, a DID's whole log, a chunk of a
//! website) or far too large for the many whose payload is a handful of
//! identifiers. The body is attacker-supplied and arrives unauthenticated, so
//! the cap is what bounds the parsing, schema validation and proof verification
//! the spine does before it knows who is asking.
//!
//! # Where a limit comes from
//!
//! From the task's own specification: its front matter's `maxDocumentBytes`,
//! which the codegen emits as `Payload::MAX_DOCUMENT_BYTES` and answers by Type
//! URI through [`trust_tasks_rs::schema_index::max_document_bytes_for`]. Every
//! type that declares nothing takes [`DEFAULT_MAX_DOCUMENT_BYTES`]. This module
//! keeps no table of its own, except [`AWAITING_DECLARATION`]: the two served
//! tasks that need more than the default and whose specifications do not yet
//! say so. Each entry is removed when its specification declares a limit, and
//! a test fails the build once one does.
//!
//! # Three rules on top of the number
//!
//! - **Served types only.** A limit is in force only while this node serves the
//!   type ([`super::DISPATCHED_URIS`]). The spine verifies a document's proof —
//!   canonicalising the whole document and resolving its signer's DID — before
//!   it refuses a type it does not route, so a raised limit on a type nobody
//!   serves would buy an unauthenticated caller that much more work for
//!   nothing.
//! - **Known issuers only.** A document above the default is admitted at its
//!   type's raised limit only when its claimed `issuer` holds a live ACL entry
//!   here, or is a signing key an active delegation names for such an entry
//!   ([`check`]). The lookup is one keyspace read, made before any signature is
//!   verified; a claimed issuer that then fails verification is refused as
//!   usual. Nobody without standing could be authorised for a raised task, so a
//!   stranger's large document is held to the default.
//! - **No echo.** A refusal names the caller's `type` only when it is short
//!   enough to be a Type URI.
//!
//! # Before the parse
//!
//! A body no larger than the default is admitted without looking at it: every
//! type accepts that much. A larger body has only its top-level `type` and
//! `issuer` read — a scan that keeps no other member — and is refused unless
//! that type's limit admits it and the issuer is known. Nothing else in it is
//! parsed, validated or verified. The refusal is a framework `trust-task-error`
//! with the standard `malformedRequest` code and the limit that applied under
//! `details.maxBytes`.
//!
//! The check sits in the spine, so it is the same on every transport. The
//! HTTPS door additionally caps its request body at
//! [`largest_max_document_bytes`], so no body larger than any served type
//! accepts is ever buffered.
//!
//! # A claimed issuer is not a verified one
//!
//! [`check_for_known_issuer`] grants the raised limit to a document whose
//! in-band `issuer` merely *names* a DID with standing here — the field is
//! read straight off the unparsed body, before any proof is checked. That is
//! deliberate (a stranger could never be authorised for a raised task anyway,
//! so refusing it earlier costs it nothing legitimate), but taken alone it is
//! a DoS amplifier: anyone who has ever seen an administrator's DID can claim
//! it as `issuer` and buy themselves the full raised limit's worth of parsing
//! and proof verification, over and over, whether or not they can actually
//! sign for it. [`LargeDocumentBudget`] closes that gap — the caller charges
//! one address-scoped budget (client IP over HTTPS, sender VID over DIDComm
//! and TSP) before granting the raised limit, and
//! [`settle_large_document_charge`] doubles that address's next cost whenever
//! the claim does not pan out (a verification failure, or a verified issuer
//! that turns out to be someone else). A service-wide cap on top bounds how
//! many raised-limit documents run the parse-and-verify path per window,
//! however many addresses — or freshly minted VIDs — a caller spreads across.

use trust_tasks_rs::{ErrorPayload, Payload, RejectReason};

use super::helpers::{TrustTaskOutcome, unrouted_error_response};
use crate::server::AppState;

/// Every type that declares nothing accepts a document of at most 64 KiB —
/// generous for a document of identifiers, a credential or a presentation, and
/// small enough that an unauthenticated flood of them is cheap to refuse.
pub(crate) const DEFAULT_MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// `policy/upsert/0.2`: 192 KiB.
///
/// The payload's `module` is a Rego source of up to
/// [`crate::policy::POLICY_SOURCE_MAX_BYTES`] (64 KiB). JSON escaping of
/// ordinary source (quotes, backslashes, newlines) at most doubles it, and the
/// rest — `name`, `ext`, the envelope and the proof — is well under a further
/// 64 KiB.
pub(crate) const POLICY_UPSERT_MAX_DOCUMENT_BYTES: usize =
    2 * crate::policy::POLICY_SOURCE_MAX_BYTES + 64 * 1024;

/// `did-management/did/register/0.1`: 1 MiB.
///
/// `didData` is the DID's complete `did:webvh` log — every entry it has ever
/// had, each a signed DID document — so it grows with the DID's age and cannot
/// be bounded by its shape. 1 MiB is what the HTTPS route for the same task
/// accepts ([`crate::routes::MAX_BODY_SIZE`]), and what the DID hosting
/// service's control plane accepts for it.
pub(crate) const DID_REGISTER_MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Served types that need more than the default and whose specification does
/// not declare `maxDocumentBytes` yet. Keyed by the full Type URI, so a new
/// version of a task takes its own declaration. An entry goes when the
/// specification declares a limit
/// (`every_awaiting_entry_is_still_undeclared_upstream`).
pub(crate) const AWAITING_DECLARATION: &[(&str, usize)] = &[
    (
        <trust_tasks_rs::specs::policy::upsert::v0_2::Payload as Payload>::TYPE_URI,
        POLICY_UPSERT_MAX_DOCUMENT_BYTES,
    ),
    (
        <trust_tasks_rs::specs::did_management::did::register::v0_1::Payload as Payload>::TYPE_URI,
        DID_REGISTER_MAX_DOCUMENT_BYTES,
    ),
];

/// What `type_uri`'s specification declares, or its [`AWAITING_DECLARATION`]
/// entry.
fn declared(type_uri: &str) -> Option<usize> {
    trust_tasks_rs::schema_index::max_document_bytes_for(type_uri).or_else(|| {
        AWAITING_DECLARATION
            .iter()
            .find(|(uri, _)| *uri == type_uri)
            .map(|(_, max)| *max)
    })
}

/// The largest document any **served** type accepts: the HTTPS door's body
/// cap.
pub(crate) fn largest_max_document_bytes() -> usize {
    largest_in(super::DISPATCHED_URIS, declared)
}

fn largest_in(served: &[&str], declared: impl Fn(&str) -> Option<usize>) -> usize {
    served
        .iter()
        .filter_map(|uri| declared(uri))
        .fold(DEFAULT_MAX_DOCUMENT_BYTES, usize::max)
}

/// The `details` member naming the limit a refused document exceeded.
pub(crate) const DETAILS_MAX_BYTES: &str = "maxBytes";

/// The largest document `type_uri` accepts, in bytes, from a known issuer.
pub(crate) fn max_document_bytes(type_uri: &str) -> usize {
    max_in(type_uri, super::DISPATCHED_URIS, declared)
}

fn max_in(type_uri: &str, served: &[&str], declared: impl Fn(&str) -> Option<usize>) -> usize {
    if served.contains(&type_uri) {
        declared(type_uri).unwrap_or(DEFAULT_MAX_DOCUMENT_BYTES)
    } else {
        DEFAULT_MAX_DOCUMENT_BYTES
    }
}

/// Large documents (over [`DEFAULT_MAX_DOCUMENT_BYTES`]) a single address may
/// have [`check_for_known_issuer`] grant the raised limit to per minute,
/// before its claimed issuer's proof has even been read. See the module docs:
/// this is what keeps naming a known administrator's DID from being free rein
/// to make this node parse and verify a raised-limit document indefinitely. 5
/// is generous for a legitimate high-frequency caller and cheap to hold an
/// attacker to.
pub(crate) const LARGE_DOCUMENT_BUDGET_PER_WINDOW: u64 = 5;

/// Fixed-window length, in seconds, for [`LargeDocumentBudget`].
pub(crate) const LARGE_DOCUMENT_BUDGET_WINDOW_SECS: u64 = 60;

/// Large documents admitted per window across *every* address together.
///
/// The per-address budget is keyed on something a caller can vary — a client
/// IP behind a large pool, or on the messaging transports a sender VID anyone
/// can mint — so it bounds one address, not the node. This bounds the node:
/// however many addresses a caller spreads across, the raised-limit
/// parse-and-verify path runs at most this many times a window. A legitimate
/// deployment sends far fewer raised-limit documents than this per minute.
pub(crate) const LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW: u64 = 60;

/// Hard cap on tracked-address map size. Past it, addresses with nothing at
/// stake — an expired window and no penalty — are evicted; if the map is
/// still full, a new address is refused rather than tracked. Clearing the map
/// wholesale would also wipe every penalty, which a novel-address flood could
/// then trigger on purpose.
const MAX_TRACKED_ADDRESSES: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Cost units spent in the current window.
    spent: u64,
    /// `now` (epoch seconds) of the window start.
    window_start: u64,
    /// The cost of this address's *next* charge — 1 until
    /// [`LargeDocumentBudget::penalize`] doubles it.
    cost: u64,
}

/// Per-address budget for documents [`check_for_known_issuer`] grants the
/// raised limit to before their claimed issuer is verified. See the module
/// docs.
// `pub`, not `pub(crate)`: `AppState::large_document_budget` holds one, and a
// couple of integration-test crates build an `AppState` literal directly, so
// they need to name this type and construct it. Everything else below stays
// `pub(crate)`.
#[derive(Debug, Default)]
pub struct LargeDocumentBudget {
    inner: std::sync::Mutex<BudgetState>,
}

#[derive(Debug, Default)]
struct BudgetState {
    buckets: std::collections::HashMap<String, Bucket>,
    /// The every-address window: see [`LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW`].
    global_spent: u64,
    global_window_start: u64,
}

impl LargeDocumentBudget {
    pub fn new() -> Self {
        Self::default()
    }

    /// Charge `address` for one large document, at its current per-charge
    /// cost. `Err` is the number of seconds until the window rolls over, once
    /// spending would exceed [`LARGE_DOCUMENT_BUDGET_PER_WINDOW`] for the
    /// current one (or the service-wide window is spent).
    fn try_charge(&self, address: &str, now: u64) -> Result<(), u64> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = &mut *state;

        if now.saturating_sub(state.global_window_start) >= LARGE_DOCUMENT_BUDGET_WINDOW_SECS {
            state.global_spent = 0;
            state.global_window_start = now;
        }
        let global_retry =
            (state.global_window_start + LARGE_DOCUMENT_BUDGET_WINDOW_SECS).saturating_sub(now);
        if state.global_spent >= LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW {
            return Err(global_retry);
        }

        let buckets = &mut state.buckets;
        if buckets.len() >= MAX_TRACKED_ADDRESSES && !buckets.contains_key(address) {
            buckets.retain(|_, b| {
                b.cost > 1 || now.saturating_sub(b.window_start) < LARGE_DOCUMENT_BUDGET_WINDOW_SECS
            });
            if buckets.len() >= MAX_TRACKED_ADDRESSES {
                return Err(global_retry);
            }
        }

        let entry = buckets.entry(address.to_string()).or_insert(Bucket {
            spent: 0,
            window_start: now,
            cost: 1,
        });

        if now.saturating_sub(entry.window_start) >= LARGE_DOCUMENT_BUDGET_WINDOW_SECS {
            entry.spent = 0;
            entry.window_start = now;
        }

        if entry.spent.saturating_add(entry.cost) > LARGE_DOCUMENT_BUDGET_PER_WINDOW {
            let retry_after_secs =
                (entry.window_start + LARGE_DOCUMENT_BUDGET_WINDOW_SECS).saturating_sub(now);
            return Err(retry_after_secs);
        }
        entry.spent += entry.cost;
        state.global_spent += 1;
        Ok(())
    }

    /// Double `address`'s per-charge cost — called once a claimed issuer this
    /// budget let through turns out to have failed verification, or proven to
    /// be someone else. Persists across windows (a penalty is against the
    /// address, not the minute it earned it); capped well short of overflow,
    /// since a handful of doublings already exhausts the window on its own.
    fn penalize(&self, address: &str) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = state.buckets.entry(address.to_string()).or_insert(Bucket {
            spent: 0,
            window_start: 0,
            cost: 1,
        });
        entry.cost = entry.cost.saturating_mul(2).min(1 << 20);
    }

    #[cfg(test)]
    fn cost(&self, address: &str) -> u64 {
        self.inner
            .lock()
            .unwrap()
            .buckets
            .get(address)
            .map(|b| b.cost)
            .unwrap_or(1)
    }
}

/// A per-address [`LargeDocumentBudget`] charge [`check_for_known_issuer`]
/// made before this document's proof was verified. Pass it to
/// [`settle_large_document_charge`] once the caller's own verification
/// concludes.
#[derive(Debug)]
pub(crate) struct LargeDocumentCharge {
    address: String,
    claimed_issuer: String,
}

/// Admit `body`, or refuse it for its size before it is parsed.
///
/// A document above the default is held to its type's limit only when its
/// claimed `issuer` is known here ([`is_known_issuer`]) — and even then, only
/// while `address`'s [`LargeDocumentBudget`] has room for it. A stranger's
/// large document is held to the default, with no charge against the budget:
/// the ACL/delegation lookup alone already holds it to the cheap path.
///
/// A known claimed issuer past its address's budget is refused `unavailable`
/// rather than admitted, even one that would have gone on to verify
/// correctly; that trade-off is what a budget is for.
///
/// Returns the charge to settle once verification concludes
/// ([`settle_large_document_charge`]), or `None` when no charge was made.
pub(crate) async fn check_for_known_issuer(
    state: &AppState,
    body: &[u8],
    address: &str,
    now: u64,
) -> Result<Option<LargeDocumentCharge>, TrustTaskOutcome> {
    if body.len() <= DEFAULT_MAX_DOCUMENT_BYTES {
        return Ok(None);
    }
    let claimed_issuer = match peek_issuer(body) {
        Some(issuer) if is_known_issuer(state, &issuer).await => Some(issuer),
        _ => None,
    };
    let Some(claimed_issuer) = claimed_issuer else {
        check_with(body, |_| DEFAULT_MAX_DOCUMENT_BYTES)?;
        return Ok(None);
    };
    if let Err(retry_after_secs) = state.large_document_budget.try_charge(address, now) {
        let payload: ErrorPayload = RejectReason::Unavailable {
            retry_after: Some(
                chrono::Utc::now() + chrono::Duration::seconds(retry_after_secs as i64),
            ),
        }
        .into();
        return Err(unrouted_error_response(payload));
    }
    check_with(body, max_document_bytes)?;
    Ok(Some(LargeDocumentCharge {
        address: address.to_string(),
        claimed_issuer,
    }))
}

/// Settle a [`LargeDocumentCharge`] once the caller's own proof verification
/// concludes. `verified_issuer` is the proven signer on success, or `None` on
/// any verification failure (including no proof at all). A `verified_issuer`
/// that is not exactly the one the charge was granted against — including a
/// failure, which proves none at all — doubles the address's cost for its
/// next large document ([`LargeDocumentBudget::penalize`]). A charge that
/// verified to exactly its claimed issuer costs nothing extra.
///
/// A no-op when `charge` is `None` — the document never carried one.
pub(crate) fn settle_large_document_charge(
    budget: &LargeDocumentBudget,
    charge: Option<&LargeDocumentCharge>,
    verified_issuer: Option<&str>,
) {
    let Some(charge) = charge else {
        return;
    };
    if verified_issuer != Some(charge.claimed_issuer.as_str()) {
        budget.penalize(&charge.address);
    }
}

/// Whether `issuer` holds standing here: a live ACL entry of its own, or an
/// active signing-key delegation to an identity that holds one.
///
/// A failed read counts as unknown, so a store error costs the caller the
/// raised limit rather than admitting an unbounded body.
async fn is_known_issuer(state: &AppState, issuer: &str) -> bool {
    let now = crate::auth::session::now_epoch();
    let live = |entry: Option<crate::acl::VtcAclEntry>| entry.is_some_and(|e| !e.is_expired(now));
    let did = issuer.split('#').next().unwrap_or(issuer);
    if live(
        crate::acl::get_acl_entry(&state.acl_ks, did)
            .await
            .ok()
            .flatten(),
    ) {
        return true;
    }
    match crate::acl::console_key::resolve_delegated_admin(&state.console_keys_ks, did).await {
        Ok(Some(delegation)) => live(
            crate::acl::get_acl_entry(&state.acl_ks, &delegation.admin_did)
                .await
                .ok()
                .flatten(),
        ),
        _ => false,
    }
}

/// The longest `type` a refusal names. A caller's own `type` is echoed back
/// only when it is short enough to be a Type URI; anything longer is not one,
/// and repeating it would turn the refusal into an echo of the caller's body.
const MAX_NAMED_TYPE_CHARS: usize = 256;

fn check_with(body: &[u8], limit: impl Fn(&str) -> usize) -> Result<(), TrustTaskOutcome> {
    if body.len() <= DEFAULT_MAX_DOCUMENT_BYTES {
        return Ok(());
    }
    let type_uri = peek_type(body);
    let max = type_uri
        .as_deref()
        .map_or(DEFAULT_MAX_DOCUMENT_BYTES, &limit);
    if body.len() <= max {
        return Ok(());
    }
    let named = match type_uri.as_deref() {
        Some(t) if t.chars().count() <= MAX_NAMED_TYPE_CHARS => t,
        Some(_) => "its type",
        None => "a document of no readable type",
    };
    let payload: ErrorPayload = RejectReason::MalformedRequest {
        reason: format!(
            "the document is {} bytes; {named} accepts at most {max}",
            body.len()
        ),
    }
    .into();
    Err(unrouted_error_response(payload.with_details(
        serde_json::json!({ DETAILS_MAX_BYTES: max }),
    )))
}

/// The document's top-level `type`, read without keeping anything else.
///
/// `None` for a body that is not a JSON object with a string `type` — which
/// then takes the default limit, as a type that declares nothing does.
fn peek_type(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct TypeOnly {
        #[serde(rename = "type")]
        type_uri: String,
    }
    serde_json::from_slice::<TypeOnly>(body)
        .ok()
        .map(|t| t.type_uri)
}

/// The document's top-level `issuer`, read the same way as [`peek_type`]: a
/// duplicated or non-string one reads as none, and the body is held to the
/// default.
fn peek_issuer(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct IssuerOnly {
        issuer: String,
    }
    serde_json::from_slice::<IssuerOnly>(body)
        .ok()
        .map(|t| t.issuer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY_UPSERT: &str =
        <trust_tasks_rs::specs::policy::upsert::v0_2::Payload as Payload>::TYPE_URI;
    const MEMBERS_UPDATE: &str =
        <trust_tasks_rs::specs::vtc::members::update::v0_1::Payload as Payload>::TYPE_URI;
    const WEBSITE_CHUNK: &str =
        <trust_tasks_rs::specs::vtc::website::upload::chunk::v0_1::Payload as Payload>::TYPE_URI;

    /// `policy/upsert` as though this node served it.
    fn served_upsert(type_uri: &str) -> usize {
        max_in(type_uri, &[POLICY_UPSERT], declared)
    }

    /// A document of `type_uri` from `issuer`, padded to exactly `len` bytes.
    fn document_from(issuer: &str, type_uri: &str, len: usize) -> Vec<u8> {
        let head = format!(r#"{{"type":"{type_uri}","issuer":"{issuer}","payload":{{"pad":""#);
        let tail = r#""}}"#;
        let pad = len - head.len() - tail.len();
        let body = format!("{head}{}{tail}", "x".repeat(pad));
        assert_eq!(body.len(), len);
        body.into_bytes()
    }

    fn document_of(type_uri: &str, len: usize) -> Vec<u8> {
        document_from("did:key:z6MkSizeSender", type_uri, len)
    }

    fn refusal(outcome: TrustTaskOutcome) -> serde_json::Value {
        assert_eq!(outcome.status, axum::http::StatusCode::BAD_REQUEST);
        payload_of(outcome)
    }

    /// [`refusal`], without asserting the status code — for a refusal that is
    /// not `malformedRequest` (400), such as the budget's `unavailable` (503).
    fn payload_of(outcome: TrustTaskOutcome) -> serde_json::Value {
        let doc: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        doc["payload"].clone()
    }

    /// An interim entry is for a specification that declares nothing; once it
    /// declares a limit, the declaration is the one in force and the entry goes.
    #[test]
    fn every_awaiting_entry_is_still_undeclared_upstream() {
        for (uri, max) in AWAITING_DECLARATION {
            assert!(
                trust_tasks_rs::schema_index::schema_for(uri).is_some(),
                "{uri} names no published specification"
            );
            assert!(
                trust_tasks_rs::schema_index::max_document_bytes_for(uri).is_none(),
                "{uri} now declares maxDocumentBytes; drop its AWAITING_DECLARATION entry"
            );
            assert!(
                *max > DEFAULT_MAX_DOCUMENT_BYTES,
                "{uri} awaits {max}, which is not above the default; drop it"
            );
        }
    }

    /// The codegen's declaration is the limit: the website chunk declares
    /// 352 KiB, and a type that declares nothing takes the default.
    #[test]
    fn a_declared_limit_is_the_specifications_own() {
        let chunk = trust_tasks_rs::schema_index::max_document_bytes_for(WEBSITE_CHUNK)
            .expect("the chunk declares a limit");
        assert_eq!(max_in(WEBSITE_CHUNK, &[WEBSITE_CHUNK], declared), chunk);
        assert_eq!(served_upsert(MEMBERS_UPDATE), DEFAULT_MAX_DOCUMENT_BYTES);
        assert_eq!(
            served_upsert(POLICY_UPSERT),
            POLICY_UPSERT_MAX_DOCUMENT_BYTES
        );
    }

    /// A raised limit on a type this node does not route would only let an
    /// unauthenticated caller make the spine canonicalise and verify a larger
    /// document before refusing it as unrouted.
    #[test]
    fn a_declared_type_that_is_not_served_takes_the_default() {
        assert_eq!(
            max_in(POLICY_UPSERT, &[], declared),
            DEFAULT_MAX_DOCUMENT_BYTES
        );
        assert_eq!(largest_in(&[], declared), DEFAULT_MAX_DOCUMENT_BYTES);
        assert_eq!(
            largest_in(&[POLICY_UPSERT, MEMBERS_UPDATE], declared),
            POLICY_UPSERT_MAX_DOCUMENT_BYTES
        );
        // And on this build, every served limit is at most the door's cap.
        for uri in super::super::DISPATCHED_URIS {
            assert!(
                max_document_bytes(uri) <= largest_max_document_bytes(),
                "{uri}"
            );
        }
    }

    #[test]
    fn a_document_at_its_types_limit_is_admitted() {
        assert!(
            check_with(
                &document_of(MEMBERS_UPDATE, DEFAULT_MAX_DOCUMENT_BYTES),
                max_document_bytes
            )
            .is_ok()
        );
        assert!(
            check_with(
                &document_of(POLICY_UPSERT, POLICY_UPSERT_MAX_DOCUMENT_BYTES),
                served_upsert
            )
            .is_ok()
        );
    }

    #[test]
    fn a_document_over_the_default_is_refused_for_a_type_that_declares_nothing() {
        let payload = refusal(
            check_with(
                &document_of(MEMBERS_UPDATE, DEFAULT_MAX_DOCUMENT_BYTES + 1),
                max_document_bytes,
            )
            .unwrap_err(),
        );
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    #[test]
    fn a_document_over_its_raised_limit_is_refused() {
        let payload = refusal(
            check_with(
                &document_of(POLICY_UPSERT, POLICY_UPSERT_MAX_DOCUMENT_BYTES + 1),
                served_upsert,
            )
            .unwrap_err(),
        );
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            POLICY_UPSERT_MAX_DOCUMENT_BYTES
        );
    }

    /// The `type` is read wherever it sits: one placed after a large member is
    /// still the one the limit is looked up by, and a nested `type` is not it.
    #[test]
    fn the_type_is_the_top_level_one_wherever_it_sits() {
        let pad = "x".repeat(DEFAULT_MAX_DOCUMENT_BYTES);
        let late = format!(
            r#"{{"payload":{{"type":"{MEMBERS_UPDATE}","pad":"{pad}"}},"type":"{POLICY_UPSERT}"}}"#
        );
        assert!(check_with(late.as_bytes(), served_upsert).is_ok());
        let nested_only = format!(r#"{{"payload":{{"type":"{POLICY_UPSERT}","pad":"{pad}"}}}}"#);
        assert_eq!(
            refusal(check_with(nested_only.as_bytes(), served_upsert).unwrap_err())["details"]
                [DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    /// Two top-level `type`s cannot claim the larger limit: the body reads as
    /// no type at all, and takes the default.
    #[test]
    fn a_duplicated_type_takes_the_default() {
        let pad = "x".repeat(DEFAULT_MAX_DOCUMENT_BYTES);
        let body =
            format!(r#"{{"type":"{MEMBERS_UPDATE}","type":"{POLICY_UPSERT}","pad":"{pad}"}}"#);
        assert_eq!(
            refusal(check_with(body.as_bytes(), served_upsert).unwrap_err())["details"]
                [DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    /// The refusal repeats a caller's `type` only when it could be a Type URI.
    #[test]
    fn a_refusal_does_not_echo_an_oversized_type() {
        let huge = "t".repeat(DEFAULT_MAX_DOCUMENT_BYTES + 1);
        let body = format!(r#"{{"type":"{huge}"}}"#);
        let payload = refusal(check_with(body.as_bytes(), max_document_bytes).unwrap_err());
        let text = payload.to_string();
        assert!(
            text.len() < 1024,
            "the refusal echoes the body: {} bytes",
            text.len()
        );
        assert_eq!(
            payload["details"],
            serde_json::json!({ DETAILS_MAX_BYTES: DEFAULT_MAX_DOCUMENT_BYTES })
        );
    }

    /// An oversized body with no readable `type` cannot claim a raised limit:
    /// it is held to the default, and refused without being parsed further.
    #[test]
    fn an_oversized_body_with_no_readable_type_takes_the_default() {
        let junk = vec![b'['; DEFAULT_MAX_DOCUMENT_BYTES + 1];
        let payload = refusal(check_with(&junk, max_document_bytes).unwrap_err());
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    /// Seed an ACL with one live administrator and a delegated console key,
    /// mirroring the fixture `a_raised_limit_needs_an_issuer_with_standing`
    /// used before the budget existed.
    async fn vtc_with_known_admin() -> (crate::test_support::TestVtc, &'static str, &'static str) {
        use crate::acl::{VtcAclEntry, VtcRole, store_acl_entry};
        let vtc = crate::test_support::TestVtc::builder().build().await;
        let admin = "did:key:z6MkSizeKnownAdmin";
        store_acl_entry(
            &vtc.state.acl_ks,
            &VtcAclEntry {
                did: admin.into(),
                role: VtcRole::Admin,
                label: None,
                admin: VtcRole::Admin.implied_authority(),
                delegated_by: None,
                created_at: 0,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();
        let key = "did:key:z6MkSizeDelegatedKey";
        crate::acl::console_key::enrol_delegation(
            &vtc.state.console_keys_ks,
            &vtc.state.acl_ks,
            key,
            admin,
            None,
            None,
        )
        .await
        .unwrap();
        (vtc, admin, key)
    }

    /// A raised limit is for a known issuer: a stranger's large document, and
    /// one naming no issuer, are held to the default (and never charge the
    /// budget); an administrator's, and a signing key's delegated by one, are
    /// admitted at the type's limit.
    #[tokio::test]
    async fn a_raised_limit_needs_an_issuer_with_standing() {
        let (vtc, admin, key) = vtc_with_known_admin().await;
        let len = DEFAULT_MAX_DOCUMENT_BYTES + 1;
        assert!(served_upsert(POLICY_UPSERT) >= len);
        let limit_for = |issuer: &str| document_from(issuer, POLICY_UPSERT, len);
        // `policy/upsert` is served on this build.
        assert!(super::super::DISPATCHED_URIS.contains(&POLICY_UPSERT));
        for (i, issuer) in [admin, key].into_iter().enumerate() {
            assert!(
                check_for_known_issuer(&vtc.state, &limit_for(issuer), &format!("ip:{i}"), 0)
                    .await
                    .is_ok(),
                "{issuer}"
            );
        }
        let stranger = refusal(
            check_for_known_issuer(
                &vtc.state,
                &limit_for("did:key:z6MkSizeStranger"),
                "ip:stranger",
                0,
            )
            .await
            .unwrap_err(),
        );
        assert_eq!(
            stranger["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
        assert_eq!(
            vtc.state.large_document_budget.cost("ip:stranger"),
            1,
            "an unknown issuer never charges the budget"
        );
        let pad = "x".repeat(DEFAULT_MAX_DOCUMENT_BYTES);
        let anonymous = format!(r#"{{"type":"{POLICY_UPSERT}","payload":{{"pad":"{pad}"}}}}"#);
        assert!(
            check_for_known_issuer(&vtc.state, anonymous.as_bytes(), "ip:anon", 0)
                .await
                .is_err(),
            "a document naming no issuer at all is held to the default"
        );
    }

    /// A document at or under the default is never charged against the
    /// budget, whatever it claims — the whole point of the default is that
    /// every type accepts that much for free.
    #[tokio::test]
    async fn small_documents_are_never_charged() {
        let (vtc, admin, _) = vtc_with_known_admin().await;
        let small = document_from(admin, POLICY_UPSERT, DEFAULT_MAX_DOCUMENT_BYTES);
        for _ in 0..(LARGE_DOCUMENT_BUDGET_PER_WINDOW * 3) {
            let charge = check_for_known_issuer(&vtc.state, &small, "ip:small", 0)
                .await
                .expect("small document admitted");
            assert!(
                charge.is_none(),
                "a small document never charges the budget"
            );
        }
    }

    /// Repeated raised-limit documents from one address, all naming the same
    /// known (but not yet verified) issuer, are refused once the address's
    /// budget is spent — the DoS amplification the module docs describe.
    #[tokio::test]
    async fn repeated_large_documents_from_one_address_are_refused_past_the_budget() {
        let (vtc, admin, _) = vtc_with_known_admin().await;
        let len = DEFAULT_MAX_DOCUMENT_BYTES + 1;
        let doc = document_from(admin, POLICY_UPSERT, len);
        for _ in 0..LARGE_DOCUMENT_BUDGET_PER_WINDOW {
            assert!(
                check_for_known_issuer(&vtc.state, &doc, "ip:9.9.9.9", 0)
                    .await
                    .is_ok()
            );
        }
        let err = check_for_known_issuer(&vtc.state, &doc, "ip:9.9.9.9", 0)
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(payload_of(err)["code"], "unavailable");
        // A different address is unaffected.
        assert!(
            check_for_known_issuer(&vtc.state, &doc, "ip:1.1.1.1", 0)
                .await
                .is_ok()
        );
    }

    /// A verified known issuer, still within its address's budget, settles
    /// for free — no penalty when the verified issuer is exactly the one it
    /// claimed.
    #[tokio::test]
    async fn a_verified_known_issuer_within_its_budget_settles_for_free() {
        let (vtc, admin, _) = vtc_with_known_admin().await;
        let len = DEFAULT_MAX_DOCUMENT_BYTES + 1;
        let doc = document_from(admin, POLICY_UPSERT, len);
        let charge = check_for_known_issuer(&vtc.state, &doc, "ip:1.2.3.4", 0)
            .await
            .expect("within budget")
            .expect("a large document charges the budget");
        settle_large_document_charge(&vtc.state.large_document_budget, Some(&charge), Some(admin));
        assert_eq!(
            vtc.state.large_document_budget.cost("ip:1.2.3.4"),
            1,
            "a verified claim is not penalised"
        );
    }

    /// Settling a charge whose claimed issuer did not verify — a mismatch, or
    /// an outright verification failure (`None`) — doubles the address's next
    /// cost, so repeating the same lie exhausts its budget faster.
    #[test]
    fn an_unverified_or_mismatched_issuer_penalises_the_address() {
        let budget = LargeDocumentBudget::new();
        let charge = LargeDocumentCharge {
            address: "ip:1.2.3.4".to_string(),
            claimed_issuer: "did:key:z6MkSizeKnownAdmin".to_string(),
        };
        settle_large_document_charge(&budget, Some(&charge), None);
        assert_eq!(budget.cost("ip:1.2.3.4"), 2);
        settle_large_document_charge(&budget, Some(&charge), Some("did:key:z6MkSizeSomeoneElse"));
        assert_eq!(budget.cost("ip:1.2.3.4"), 4);
        // A `None` charge (no large document was charged) never touches the
        // budget.
        settle_large_document_charge(&budget, None, None);
        assert_eq!(budget.cost("ip:1.2.3.4"), 4);
    }

    /// Many addresses together are held to the global budget: however many
    /// distinct addresses (or freshly minted VIDs) a caller spreads across,
    /// the raised-limit path runs at most the service-wide cap times a
    /// window.
    #[test]
    fn many_addresses_together_are_held_to_the_global_budget() {
        let budget = LargeDocumentBudget::new();
        for i in 0..LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW {
            assert!(budget.try_charge(&format!("vid:{i}"), 1_000).is_ok());
        }
        assert!(
            budget.try_charge("vid:fresh", 1_000).is_err(),
            "a fresh address does not escape the service-wide cap"
        );
        assert!(
            budget
                .try_charge("vid:fresh", 1_000 + LARGE_DOCUMENT_BUDGET_WINDOW_SECS)
                .is_ok(),
            "the next window has room again"
        );
    }

    #[test]
    fn a_full_map_keeps_its_penalties() {
        let budget = LargeDocumentBudget::new();
        budget.penalize("ip:abuser");
        {
            let mut state = budget.inner.lock().unwrap();
            for i in 0..MAX_TRACKED_ADDRESSES {
                state.buckets.insert(
                    format!("ip:{i}"),
                    Bucket {
                        spent: 0,
                        window_start: 0,
                        cost: 1,
                    },
                );
            }
        }
        // Every filler's window has expired: they are evicted, the penalty is not.
        assert!(budget.try_charge("ip:new", 10_000).is_ok());
        assert_eq!(budget.cost("ip:abuser"), 2);
    }

    #[test]
    fn a_full_map_of_live_addresses_refuses_a_new_one() {
        let budget = LargeDocumentBudget::new();
        {
            let mut state = budget.inner.lock().unwrap();
            for i in 0..MAX_TRACKED_ADDRESSES {
                state.buckets.insert(
                    format!("ip:{i}"),
                    Bucket {
                        spent: 1,
                        window_start: 10_000,
                        cost: 1,
                    },
                );
            }
        }
        assert!(budget.try_charge("ip:new", 10_000).is_err());
        assert!(
            budget.try_charge("ip:0", 10_000).is_ok(),
            "a tracked address still charges"
        );
    }

    /// The gate is the spine's, so a transport that is not HTTPS — which has
    /// no body cap of its own here — meets the same refusal.
    #[tokio::test]
    async fn every_transport_meets_the_same_refusal() {
        use crate::join::JoinTransport;
        let vtc = crate::test_support::TestVtc::builder().build().await;
        let body = document_of(MEMBERS_UPDATE, DEFAULT_MAX_DOCUMENT_BYTES + 1);
        for transport in [
            JoinTransport::Rest,
            JoinTransport::DIDComm,
            JoinTransport::Tsp,
        ] {
            let ctx = match transport {
                JoinTransport::Rest => super::super::JoinAuthCtx::rest(),
                _ => super::super::JoinAuthCtx {
                    transport,
                    sender_did: Some("did:key:z6MkSizeSender".into()),
                    verified_signer: None,
                },
            };
            let out = super::super::dispatch_trust_task_core(&vtc.state, &ctx, &body).await;
            let payload = refusal(out);
            assert_eq!(payload["code"], "malformedRequest", "{transport:?}");
            assert_eq!(
                payload["details"][DETAILS_MAX_BYTES], DEFAULT_MAX_DOCUMENT_BYTES,
                "{transport:?}"
            );
        }
    }
}
