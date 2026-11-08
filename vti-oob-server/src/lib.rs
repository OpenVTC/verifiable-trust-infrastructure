#![allow(clippy::result_large_err)]

//! The approving side of wallet sign-in started by a trigger link: the
//! `auth/oob/*` Trust Task family, where a wallet approves a key `K_b` that a
//! browser holds, independent of which service grants what for it.
//!
//! The browser (the *starter*) holds a non-extractable Ed25519 key `K_b` and
//! opens a request. A wallet (the *approver*) claims it with a throwaway key
//! `K_a`, proves who it is and the number on the screen, and returns a grant,
//! signed by the approver's DID, that names `K_b`. Only the holder of `K_b`
//! can turn that grant into whatever the service issues for it (`redeem`).
//!
//! A service supplies its own pieces through [`OobHost`] and gets the rest:
//!
//! | Piece | Where | What the host provides |
//! |---|---|---|
//! | Request rows | [`OobHost::records`] | The keyspace the `oob_req:*` rows live in |
//! | Identity | [`OobHost::service_did`], [`OobHost::public_url`], [`OobHost::service_name`] | Its DID, its public origin, the name a wallet shows |
//! | Step signer | [`OobHost::sign_step`] | Signs steps 1 and 2, `respond` and `cancel` for `assertionMethod` |
//! | Carried proofs | [`OobHost::verify_authentication`], [`OobHost::verify_assertion`] | Its DID resolver |
//! | Replay of carried documents | [`OobHost::accepted_ids`] | Its accepted-id record |
//! | Audiences | [`Audience`] | What a request may ask for (`ext["org.openvtc.session"]`) |
//! | Who may approve | [`OobHost::gate`] | The eligibility rule per audience and the refusal it gives |
//! | Delegation offered | [`OobHost::signing_scope`] | The `signingScope` step 2 offers, per audience |
//! | Audit | [`OobHost::audit`] | Its audit sink |
//! | What `redeem` issues | [`OobHost::complete`] | A session and cookies, a delegated key, … |
//!
//! [`precheck`] runs before the spine verifies a proof (T21). [`dispatch`]
//! runs the six served tasks in the check order of
//! `design-docs/vtc-qr-login-design.md` §7.3–7.6. [`delegation`] is how a key
//! a grant armed is later read as its approver.
//!
//! The crate depends on no service. It reads the generated `auth/oob` types
//! from `vti-specs-core` and nothing else of the specification crates.

pub mod audience;
pub mod delegation;
pub mod host;
pub mod http;
pub mod poll;
pub mod record;
pub mod tasks;
pub mod types;
pub mod util;

pub use audience::{Audience, SESSION_EXT};
pub use host::{Approved, Completion, Eligibility, Gate, OobHost, OobMessages, SignInEvent};
pub use http::HttpContext;
pub use poll::{NOTIFIER, Notifier, PollGuard, PollRefused};
pub use record::{
    CLAIM_WINDOW_SECS, DECISION_WINDOW_SECS, ENDED_RETENTION_SECS, MAX_PENDING_PER_ADDRESS,
    MAX_POLLS_PER_ADDRESS, OobRequest, OobState, RequesterDetails, TransitionError, create, load,
    open_requests_from, record_key, redeem_hold, set_redeem_hold_for_tests, settle_expiry, sweep,
    transition,
};
pub use tasks::{AMR, URIS, dispatch, precheck};
pub use util::{
    DEFAULT_LINK_HOST, MAX_LINK_BYTES_LEVEL_M, SIGN_IN_FLOW, browser_and_os, check_link_host,
    context_digest, did_key_multikey, encode_from, epoch_of, is_ed25519_did_key, new_match_number,
    new_request_id, origin_of, portal_origin, rfc3339, same_digest, same_network, trigger_link,
};
