#![allow(clippy::result_large_err)]

//! The VTC member-facing **Trust Task document** dispatcher.
//!
//! This is the wire adapter the join ceremony grew up into: each holder- or
//! public-facing verb (`submit`/`request`, `manifest`, `status`)
//! is a [`trust_tasks_rs::TrustTask`] document, as are the member-initiated
//! `members/self-remove` and `members/vmc` (whose optional `requestId`
//! closes an approved join — the retired `accept` verb's semantics). The
//! success reply is a framework `#response` document (a [`VerdictResponse`]
//! for `submit`, a read body for `manifest`/`status`); every failure — invalid
//! VIC, expired, malformed, duplicate — is a framework `trust-task-error`
//! document, never a DIDComm problem-report and never a `deny` verdict
//! (`deny` is a *policy* refusal of a verified request; an error means the
//! request never reached the policy). See
//! `docs/05-design-notes/vtc-ceremony-protocol.md` §3.
//!
//! ## Transports
//!
//! Both REST and DIDComm render from the one [`dispatch_trust_task_core`]:
//! - **REST**: the request body is the document; the holder is authenticated
//!   by the document's `eddsa-jcs-2022` proof ([`verify_trust_task_proof`]).
//! - **DIDComm**: the message `type` is the Trust Task URL, the body is the
//!   document, and the authcrypt sender authenticates the holder.
//!
//! ## Auth is per-verb (unlike the VTA's uniform-`AuthClaims` dispatcher)
//!
//! The join family is mostly unauthenticated/holder-bound: `submit` and
//! `status` are bound to the holder DID (no ACL entry needed);
//! `manifest` is public. `present` belongs to the `credential-exchange` family
//! and is handled there.
//!
//! **Administrator verbs are routed here too**, since #1641 phase 2 — the
//! admin-facing member verbs were the first batch, `join-requests/decide` and
//! `community/profile/update` the second, `config/{export,import}` the third —
//! the first whose bearer routes were removed rather than kept — and
//! `endorsement-types/{register,delete}` the fourth and `backup/export` the
//! fifth. Their authority is not a bearer token (this endpoint reads none) but
//! the **verified signer's ACL entry**, read at execution time; see
//! [`admin_signer`]. Every later batch followed, and the last (#1641) moved
//! an administrator's own passkeys (`auth/passkey/{list,enroll,revoke}`,
//! [`admin_passkey_tasks`]) and the console's bearer → cookie bridge
//! (`vtc/auth/admin-session/0.2`, [`admin_session_tasks`]) and session
//! introspection (`auth/whoami/0.1`, [`whoami_tasks`], answered for the key a
//! sign-in bound to the session). No task whose specification declares
//! `proof` REQUIRED is served on a bearer route any more
//! (`docs/05-design-notes/vtc-trust-task-proof-enforcement.md` §6c).
//! `vtc/backup/import/0.1` is not served at all: the chunked `backup/*` family
//! ([`backup_tasks`]) supersedes it.
//!
//! The personhood pair (`members/personhood/{challenge,assert}`) is the
//! member-facing half of the family; its `revoke` verb is served here too,
//! with the rest of the member-facing verbs, by [`member_tasks`]. Both carry their own gate — challenge requires the caller to be a
//! member, assert requires the sender to *be* the subject — because "an
//! authenticated session", which is what the REST routes rest on, has no
//! equivalent on a transport that only proves who sent the bytes.

// `pub(crate)` only so sibling modules' tests can take the framework error
// version from `framework_error_type_uri()` rather than each naming it. The
// module's items are individually `pub(crate)` already; this widens the path,
// not the surface.
pub(crate) mod helpers;
// The routing table every family registers its handlers on (#2579).
pub(crate) mod routing;

// The accepted-document-id record (VTI-OPS-025…027). `pub(crate)` because
// VTI-OPS-027 makes it every binding's, not this spine's: the dispatcher below
// is its first caller, a bearer REST route is its second (#1641 phase 2).
pub(crate) mod accepted_ids;
// The per-type document size limit, checked before the parse.
mod credential_exchange;
// `pub` (not `pub(crate)`) only so `AppState::large_document_budget`'s type
// is nameable from the integration-test crates that build an `AppState`
// literal directly (`tests/emergency_bootstrap.rs`, `tests/passkey_state.rs`)
// — every other item the module exports stays `pub(crate)`.
pub mod size;
// `trust-task-discovery/0.4` (and the superseded 0.3): what this VTC serves
// and the acceptance window it applies (VTI-TRN-047).
mod discovery;

// The canonical `acl/{show,list,update,revoke}` tasks, and the operation-bound
// gate `acl/grant` shares with `acl/update`.
mod acl_tasks;
// The administrator action list: `vtc/admin/actions/*` and the
// `task-consent/decision` that completes a parked operation (VTI-APV-017).
pub(crate) mod action_tasks;
// The administrator console's live channel: `vtc/admin/events/subscribe`,
// whose success opens an event stream on the HTTPS door
// (`crate::admin_events`).
pub(crate) mod event_tasks;
// The administrator's operational verbs: the registry reconciler, the audit
// log, the runtime configuration, admin invites and sessions.
pub(crate) mod admin_tasks;
// The administrator's community verbs: roster, join queue, graph, directory,
// recognition, and invitation credentials.
pub(crate) mod community_tasks;
// The community's policy log and its self-hosted DID log.
pub(crate) mod policy_tasks;
// The administration surfaces that had only bearer REST: presentation to
// applicants, the schema registry, vetting reads, edge suspend/restore, a join
// request's vetting and credential query, and the host's rooms.
pub(crate) mod surface_tasks;
// `auth/signing-key/*`: the console's signing keys, as delegations.
pub(crate) mod signing_key_tasks;
// An administrator's own login passkeys: `auth/passkey/list/0.1`,
// `enroll/{start,finish}/0.2`, `revoke/{start,finish}/0.1` (#1641, which
// removed their `/v1/admin/passkeys/*` bearer routes).
pub(crate) mod admin_passkey_tasks;
// The console's bearer → cookie bridge, `vtc/auth/admin-session/0.2` (#1641,
// which removed `POST /v1/auth/admin-session`). HTTPS only: it sets cookies.
pub(crate) mod admin_session_tasks;
// `auth/whoami/0.1`, answered for the key bound to a session at sign-in (or a
// console key acting for its administrator), never for a cookie (#1641).
pub(crate) mod whoami_tasks;
// The website's content: chunked upload, deploy, ranged reads, the listing,
// delete, generation history and rollback.
#[cfg(feature = "website")]
pub(crate) mod website_tasks;

// Pre-session auth: `auth/{challenge,authenticate/{0.2,0.3},refresh/0.2}`.
pub(crate) mod auth_tasks;
// Wallet sign-in started by a trigger link: `auth/oob/*` (the key-grant
// flow). Pre-session, like `auth_tasks`; its state is `member_portal::oob`.
pub(crate) mod oob_tasks;
// First-admin onboarding: `vtc/install/claim/{start,finish}/0.2`,
// `vtc/admin/bootstrap/0.1`. Pre-session, like `auth_tasks`.
mod install_tasks;
// Cross-community recognition: `vtc/auth/recognise/{challenge/0.2,0.3}`.
// Pre-session, like `auth_tasks`.
mod recognise_tasks;

// The member-facing verbs that were HTTPS REST only: renewal, DID rotation,
// personhood revocation, the relationship graph's member verbs and the
// endorsement verbs. Each calls the operation its bearer route calls.
mod member_tasks;

// An applicant's OpenID4VP wallet sessions (#1988): opening one for a join
// criterion, and reading its outcome. The wallet's own two calls are HTTPS
// endpoints (`routes::oid4vp`).
mod wallet_session_tasks;

// The node-neutral `backup/*` family (#1641): a backup too large for one
// document moves as a chunked bundle. `pub(crate)` for `blob_dir`, which the
// retention sweeper needs.
pub(crate) mod backup_tasks;

// Members' step-up passkeys: `auth/passkey/enroll/invite/0.3` (`purpose:
// stepUp`), `enroll/redeem/{start,finish}/0.1` and `revoke/{start,finish}/0.2`.
// The operations are `crate::step_up_passkey`'s; this is their only door.
pub(crate) mod step_up_passkey_tasks;

// Step-up approvers: `auth/step-up/approver/{invite,redeem/start,redeem/finish,
// enroll,list,revoke}/0.1`. The operations are `crate::step_up_approver`'s;
// this is their only door.
pub(crate) mod step_up_approver_tasks;
// The step-up hand-off: `auth/step-up/requests/show/0.1` (VTI-LNK-125 – 131).
// The pending step-ups are `crate::acl::bound_step_up`'s.
pub(crate) mod step_up_handoff_tasks;

// Custom administrative roles: `vtc/roles/{define,list,show,delete}/0.1`
// (`vtc-admin-roles.md` §6.2). The records are `crate::acl::roles`'s; this is
// their only door.
pub(crate) mod community_room_tasks;
// The member directory: `vtc/directory/{fields,card,entries}/*` (the
// `query/0.1` lookup stays in `community_tasks`, answered through the same
// projection). Its records are `crate::directory`'s.
pub(crate) mod directory_tasks;
pub(crate) mod group_tasks;
// The community's boards (`vtc/boards/*`, VTI-BRD-*): ideas, notes, and each accepted idea's
// election through `crate::elections`.
pub(crate) mod board_tasks;
/// Keyed offset cursors shared by the badge, board and election lists.
pub(crate) mod offset_cursor;
// Member badges (`vtc/badges/*`, VTI-BDG-*): badges backed by badge groups, awards accepted by
// their holders, kudos between members, through `crate::badges`.
pub(crate) mod badge_tasks;
pub(crate) mod role_tasks;
// `vtc/members/role/set/0.1` — the community-role move.
pub mod member_role_tasks;
pub(crate) mod room_admin_tasks;
// The administrators' view of the OpenID4VP verifier identities (#1988).
pub(crate) mod oid4vp_tasks;
pub(crate) mod storage_tasks;
// Direct admission: adding a member without a join request, and making an
// existing ACL entry a membership — decided by the community's `admission`
// policy, which may park either for approval (`crate::ceremony::admission`).
pub(crate) mod admission_tasks;

// Capability modules: `governance/capability/{list,enable,disable}/0.1`
// (`design-docs/vtc-capability-modules.md`). The decisions and their registry
// projection are `crate::capability_modules`'s; this is their only door.
pub(crate) mod capability_module_tasks;

// A community's side of Verifiable Trust Network membership: `vtc/networks/*`
// (`crate::networks`). `vtc/networks/notice` is sent, never served.
pub(crate) mod network_tasks;

// Community elections: `vtc/elections/*` (VTI-VOT-001 – 100). The registrar's
// records and its link to ballot boxes are `crate::elections`'s; feature-gated
// with the PCS key they issue tickets under.
#[cfg(feature = "voting")]
pub(crate) mod election_tasks;
pub(crate) mod notification_tasks;

// The handler groups that used to live in this file (#2579).
mod config_tasks;
#[cfg(feature = "vetting-pcs")]
mod hidden_vetting_tasks;
mod join_tasks;
mod member_admin_tasks;
mod personhood_tasks;
#[cfg(test)]
mod spine_proof_tests;
mod step_up_response_tasks;
#[cfg(test)]
pub(crate) mod test_fixtures;
mod vetting_tasks;
use config_tasks::refuse_hop_by_hop_backup;
use join_tasks::{caller_is_identified, discovery_refusal};

// The integration tests' soft WebAuthn authenticator, for the spine tests that
// drive a real passkey ceremony.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../tests/it/common/webauthn_harness.rs"]
mod soft_authenticator;

// The schema-conformance sweep (#1059): every bound, published `spec/vtc/*`
// URI must speak that URI's wire shape. Lives in `src` rather than `tests`
// because its census is derived from `dispatched_uris` below, which no
// integration test can see.
#[cfg(test)]
mod conformance;

// The declared-error-code census (#1600): every extended error code a bound,
// published `spec/vtc/*` task declares must be witnessed by a test that
// observes the service emitting it. Derived from the same census as
// `conformance`, and from `vti_specs::schema_index::error_codes_for`.
#[cfg(test)]
mod error_code_census;

// Every served Type URI is a version the generated `vti-specs` crates pin.
#[cfg(test)]
mod spec_pin_census;

// No served response carrying a token or secret member is kept in the
// duplicate-execution record.
#[cfg(test)]
mod response_record_census;

use serde_json::Value;
use vti_specs::vtc::members::personhood::{assert::v0_2 as pa, challenge::v0_1 as pc};
// The admin-facing member verbs (#1641 phase 2). Their wire types are
// generated from the published schemas, so there is no hand-written SDK
// constant to import and the Type URIs below are read off the payload types.
use vti_specs::vtc::members::{
    admin_remove::v0_1 as member_admin_remove, credentials::v0_1 as member_credentials,
    purge::v0_1 as member_purge, update::v0_1 as member_update,
};
// The admin verbs #1641 phase 2 batch 2 moved: the join decision and the
// community profile edit. Same story — generated wire types, Type URIs read
// off the payload types.
use vti_specs::vtc::community::profile::update::v0_1 as community_profile_update;
use vti_specs::vtc::join_requests::decide::v0_1 as join_decide;
// Batch 3: the portable-configuration pair.
use vti_specs::vtc::config::{
    did_hosting::list::v0_1 as did_hosting_list, export::v0_1 as config_export,
    import::v0_1 as config_import,
};
// Batch 4: the endorsement-type registry's two writes.
use vti_specs::vtc::endorsement_types::{
    delete::v0_1 as endorsement_type_delete, register::v0_1 as endorsement_type_register,
};
// Batch 5: the backup export. Its `import` partner waits — see the design note.
use vti_specs::vtc::backup::export::v0_1 as backup_export;
// The answer to the operation-bound step-up an ACL write asks for (#1641;
// design note `vtc-operation-bound-step-up.md`): a passkey assertion — the
// console's unsigned answer, or beside the subject's own proof — or a step-up
// approver's statement (design note `vtc-approver-step-up.md`).
use trust_tasks_rs::{RejectReason, TrustTask};
use vti_specs::auth::step_up::approve_response::v0_7 as step_up_approve_response;

use vta_sdk::protocols::trust_task_reject_reasons as reasons;
use vti_common::error::AppError;

use vta_sdk::protocols::join_requests::{
    self as jr, JoinRequestStatusBody, JoinRequestSubmitBody, VerdictResponse,
};
use vta_sdk::protocols::members::{MemberVmcBody, MemberVmcReceiptBody};
use vta_sdk::protocols::vetting::{
    self as vetting_wire, revoke_statement::v0_1 as revoke_statement,
};

use crate::join::{JoinSubmitOutcome, JoinTransport};
use crate::routing::trust_task_admission::MessagingRoomAdmission;
use crate::server::AppState;

pub(crate) use helpers::TrustTaskOutcome;
// The one spelling of the framework error document's Type URI in this crate.
// Re-exported so the messaging layer labels a type-less reply with the same
// value the reject path emits, rather than a second literal.
pub(crate) use helpers::framework_error_type_uri;
use helpers::{
    app_error_to_reject, extended_code, parse_payload, reject_with, reject_with_code,
    reject_with_code_because, success_response, task_error_to_reject, verdict_response,
    verify_trust_task_proof,
};

/// The transport-resolved caller identity threaded into the dispatcher: the
/// spine's own [`vti_trust_task_server::ArrivalCtx`].
///
/// `sender_did` is the transport-reported sender (DIDComm, TSP): a claim the
/// spine accepts only once the document's own proof binds it. `verified_signer`
/// is the DID that signed the document's proof, verified by the spine against
/// the document **as received** — see the crate's docs for why there and not
/// in a handler.
pub(crate) use vti_trust_task_server::ArrivalCtx as JoinAuthCtx;

/// The transport-neutral dispatch spine. Parses the document, holds it to the
/// specification it names, then routes by `type` to the matching verb handler.
///
/// In order: the acceptance window over `issuedAt` (VTI-OPS-024), expiry and
/// the recipient binding (VTI-OPS-023), the flag-driven rules the
/// specification itself declares — `proof`, `recipient` and `issuedAt`
/// REQUIRED, and audience binding (VTI-OPS-020, VTI-OPS-021), verification of
/// any `proof` present against the document's own `issuer`, and the
/// duplicate-execution record (VTI-OPS-025…027). Every one of them is reached
/// identically from REST, DIDComm and TSP, which is VTI-OPS-021's point.
///
/// Every one of those checks is unconditional. There is no configuration that
/// relaxes any of them — `docs/05-design-notes/vtc-trust-task-proof-enforcement.md`
/// has the whole argument, including the one transitional allowance #1641
/// shipped with and why it is gone.
pub(crate) async fn dispatch_trust_task_core(
    state: &AppState,
    ctx: &JoinAuthCtx,
    body: &[u8],
) -> TrustTaskOutcome {
    // Every answer is signed, refusals included — the early refusals as well
    // as the dispatched result (which the spine signs before recording it for
    // redelivery).
    let address = large_document_budget_address(ctx);
    // A room document is charged the room budgets here, as the HTTPS door
    // charges them (#2294): the sender's room ceiling before anything is
    // verified, then the (room, presenter) or transfer budget once its room
    // authorizes it — which is also what admits an upload chunk at its own size
    // instead of the large-document budget.
    let room = match MessagingRoomAdmission::begin(state, ctx.sender_did.as_deref(), body).await {
        Ok(room) => room,
        Err(limited) => return rate_limited_outcome(state, &limited).await,
    };
    let Some(room) = room else {
        return receive(state, ctx, body, None, &address).await;
    };
    let outcome = room
        .scope(receive(state, ctx, body, Some(&room), &address))
        .await;
    match room.finish() {
        Ok(()) => outcome,
        Err(limited) => rate_limited_outcome(state, &limited).await,
    }
}

/// A room limiter's refusal on a messaging transport, which has no `429`: the
/// framework's `unavailable` with the limiter's `retryAfter`, signed like every
/// other answer. The HTTPS door answers the same refusal as its `429` body.
async fn rate_limited_outcome(
    state: &AppState,
    limited: &crate::routing::rate_limit::RateLimited,
) -> TrustTaskOutcome {
    let retry_after = chrono::Utc::now()
        + chrono::Duration::seconds(i64::try_from(limited.retry_after_secs()).unwrap_or(i64::MAX));
    let payload: trust_tasks_rs::ErrorPayload = RejectReason::Unavailable {
        retry_after: Some(retry_after),
    }
    .into();
    vti_trust_task_server::sign_response(
        response_signer(state),
        helpers::unrouted_error_response(payload),
    )
    .await
}

/// The address [`size::check_for_known_issuer`] charges a raised-limit
/// document's budget to, for a caller that has no address of its own to pass
/// (every non-HTTPS transport, and any direct test call). DIDComm and TSP
/// already authenticate `ctx.sender_did` at the transport layer, before the
/// document's own proof is read — the same "claim, not yet a verified issuer"
/// standing [`size`]'s module docs describe — so that VID is this budget's
/// address. A caller with no transport-authenticated sender (REST reached
/// other than through [`dispatch_trust_task_core_admitted`], which passes the
/// client IP explicitly) shares one placeholder address rather than being
/// charged against nothing.
fn large_document_budget_address(ctx: &JoinAuthCtx) -> String {
    ctx.sender_did
        .as_deref()
        .map(|vid| format!("vid:{vid}"))
        .unwrap_or_else(|| "ip:unknown".to_string())
}

/// A transport's say in whether a document whose proof has verified may go on
/// to execute: the HTTPS door's per-signer rate limit
/// ([`crate::routing::trust_task_admission`]).
///
/// The spine's [`vti_trust_task_server::VerifiedAdmission`] (asked once, after
/// the proof has verified against the document's `issuer` and before the
/// duplicate-execution record is claimed), plus what this community's size gate
/// needs to know about the transport.
pub(crate) trait VerifiedAdmission: vti_trust_task_server::VerifiedAdmission {
    /// The transport has charged this document to a room budget sized for file
    /// transfer before anything in it was verified, and settles that charge
    /// itself — so the size check need not also charge an upload chunk to the
    /// large-document budget ([`size::check_for_known_issuer_with`]).
    fn room_precharged(&self) -> bool {
        false
    }
}

/// [`dispatch_trust_task_core`], with `admit` consulted once the proof has
/// verified (see [`VerifiedAdmission`]), and the raised-limit budget charged
/// against `client_ip` rather than the sender-VID fallback
/// [`large_document_budget_address`] uses — the real address a stranger
/// cannot choose over HTTPS, resolved by the caller from the connection peer
/// (or `X-Forwarded-For`, behind a configured trusted proxy).
pub(crate) async fn dispatch_trust_task_core_admitted(
    state: &AppState,
    ctx: &JoinAuthCtx,
    body: &[u8],
    admit: &dyn VerifiedAdmission,
    client_ip: std::net::IpAddr,
) -> TrustTaskOutcome {
    let address = format!("ip:{client_ip}");
    receive(state, ctx, body, Some(admit), &address).await
}

/// Run `body` through the spine (`vti_trust_task_server::Spine`) with this
/// community's pieces, and sign the answer.
///
/// The order and the rules are the crate's (size, parse, freshness, expiry and
/// recipient, the specification's own policy, the proof bound to `issuer`, the
/// messaging sender binding, admission, the duplicate-execution record,
/// dispatch, signing). What is this community's:
///
/// - **size**: the per-type limits, raised only for a claimed issuer with
///   standing here and charged to `budget_address`'s large-document budget
///   until the proof settles it ([`size::KnownIssuerSizeGate`]);
/// - **policy**: [`spec_policy_for`], read off the versions `vti-specs` pins;
/// - **recipient**: this VTC's DID, while one is configured;
/// - **before the proof** ([`VtcSpine`]): the `auth/oob` family's `did:key`
///   rule (T21), and a fresh resolution of an install claim's founder DID;
/// - **after the proof**: no delegated signing key is an approver, and a
///   `did:scid` signer's source is remembered (VTI-KEY-162);
/// - **the record**: the store-backed [`accepted_ids`], shared with every
///   other binding (VTI-OPS-027);
/// - **dispatch**: [`dispatch_typed`], inside the submission scope that lets an
///   operation be parked as exactly what its requester signed
///   (`crate::admin_actions`).
///
/// Every one of these checks is unconditional; nothing relaxes any of them
/// (`docs/05-design-notes/vtc-trust-task-proof-enforcement.md`).
async fn receive(
    state: &AppState,
    ctx: &JoinAuthCtx,
    body: &[u8],
    admit: Option<&dyn VerifiedAdmission>,
    budget_address: &str,
) -> TrustTaskOutcome {
    let size = size::KnownIssuerSizeGate {
        state,
        address: budget_address,
        room_precharged: admit.is_some_and(|a| a.room_precharged()),
    };
    let policy: fn(&str) -> Option<trust_tasks_rs::SpecPolicy> = spec_policy_for;
    let verifier = vti_trust_task_server::ResolverProofVerifier::new(
        state.trust_task_vm_resolver(),
        helpers::is_approval_type,
    );
    let vtc = VtcSpine { state };
    let accepted = state.accepted_ids();
    vti_trust_task_server::Spine::new(&policy, &verifier, &vtc, &accepted, &vtc)
        .with_size_gate(&size)
        .with_freshness(freshness_policy())
        .with_admission(admit.map(|a| a as &dyn vti_trust_task_server::VerifiedAdmission))
        .with_signer(response_signer(state))
        .receive(ctx, body)
        .await
}

/// This community's hooks and routing table for the spine.
struct VtcSpine<'a> {
    state: &'a AppState,
}

#[async_trait::async_trait]
impl vti_trust_task_server::SpineHooks for VtcSpine<'_> {
    /// The recipient binding (document `recipient` must equal this VTC's DID)
    /// is the replay defence that the bespoke `audience` field used to
    /// provide. Skipped while the VTC has no DID configured (setup).
    async fn recipient(&self) -> Option<String> {
        self.state.config.read().await.vtc_did.clone()
    }

    async fn before_proof(
        &self,
        doc: &TrustTask<Value>,
        type_uri: &str,
    ) -> Option<TrustTaskOutcome> {
        // The `auth/oob` family's signer must be an Ed25519 `did:key`, decided
        // from the identifier before any proof is read (T21) — a rule its
        // specifications state in prose, which `spec_policy_for` cannot carry.
        if let Some(refused) = oob_tasks::precheck(doc, type_uri) {
            return Some(refused);
        }
        // An install claim under an existing DID is verified against that
        // DID's *live* document (`vtc/install/claim/finish/0.3` item 3), so its
        // cached copy is dropped and the DID resolved afresh first.
        if type_uri == install_tasks::CLAIM_FINISH_V0_3_TYPE
            && let Some(refused) = install_tasks::refresh_founder_did(self.state, doc).await
        {
            return Some(refused);
        }
        None
    }

    async fn after_proof(
        &self,
        doc: &TrustTask<Value>,
        type_uri: &str,
        signer: &str,
    ) -> Option<TrustTaskOutcome> {
        let state = self.state;
        // A delegated signing key is an operational credential, never an
        // approver's attestation (auth/signing-key/enroll item 7): no approval
        // is accepted under its proof, whatever its state.
        if helpers::is_approval_type(type_uri) {
            match crate::acl::console_key::get_delegation(&state.console_keys_ks, signer).await {
                Ok(None) => {}
                // approve-response 0.7 names this case (consumer item 1a): a
                // delegated key's proof never establishes an approver —
                // `subjectMismatch`, whatever the evidence, before the pending
                // step-up is looked up. Same refusal, at the same point; only
                // the code is the task's own.
                Ok(Some(_)) if type_uri == STEP_UP_APPROVE_RESPONSE_TYPE => {
                    return Some(reject_with_code(
                        doc,
                        helpers::extended_code(
                            step_up_approve_response::error_codes::SUBJECT_MISMATCH.code,
                        ),
                        "a delegated signing key is never the approver's evidence; \
                         answer with the passkey assertion alone, or sign with the \
                         approver's own DID",
                        None,
                    ));
                }
                Ok(Some(_)) => {
                    return Some(reject_with(
                        doc,
                        RejectReason::PermissionDenied {
                            reason: "a delegated signing key is never accepted as an \
                                     approver's attestation; sign with the approver's \
                                     own key, or answer a passkey step-up unsigned"
                                .to_string(),
                        },
                    ));
                }
                Err(e) => return Some(app_error_to_reject(doc, &e)),
            }
        }
        // A did:scid signer verified through its `src`: remember where, so the
        // bare DID it is recorded by resolves after a restart (VTI-KEY-162).
        crate::scid_sources::record_best_effort(&state.members_ks, signer).await;
        None
    }
}

impl vti_trust_task_server::Dispatcher for VtcSpine<'_> {
    /// Dispatch by type URI. The document as received travels with the
    /// dispatch, so an operation that has to wait for other administrators'
    /// approval is parked as exactly what its requester signed
    /// (`crate::admin_actions`).
    fn dispatch<'b>(
        &'b self,
        ctx: &'b JoinAuthCtx,
        doc: TrustTask<Value>,
        type_uri: &'b str,
        received: std::sync::Arc<Value>,
    ) -> vti_trust_task_server::BoxFuture<'b, TrustTaskOutcome> {
        let submission = crate::admin_actions::Submission {
            received,
            signer: ctx.verified_signer.clone(),
            transport: ctx.transport,
            waiver: Default::default(),
            immediate: Default::default(),
        };
        Box::pin(crate::admin_actions::with_submission(
            submission,
            // Already boxed: `dispatch_typed` returns the chosen handler's
            // future.
            dispatch_typed(self.state, ctx, doc, type_uri),
        ))
    }

    /// See [`records_response`].
    fn records_response(&self, type_uri: &str) -> bool {
        records_response(type_uri)
    }
}

/// Whether a successful response to `type_uri` is kept in the
/// duplicate-execution record for a redelivery.
///
/// A response that carries a bearer secret (an invite's claim code, a
/// session's access and refresh tokens, a setup session token, a backup
/// transfer's transport token, a badge claim code, a forge device code) is recorded as
/// completed **without** its body, so the secret is not kept for the
/// acceptance window and is never handed to a redelivery; a redelivery is then
/// answered `204`. The census in `trust_tasks::response_record_census` holds every served
/// response schema with a token or secret member to this list.
pub(crate) fn records_response(type_uri: &str) -> bool {
    !(step_up_passkey_tasks::SECRET_RESPONSES.contains(&type_uri)
        || step_up_approver_tasks::SECRET_RESPONSES.contains(&type_uri)
        || admin_tasks::SECRET_RESPONSES.contains(&type_uri)
        || community_tasks::SECRET_RESPONSES.contains(&type_uri)
        || auth_tasks::SECRET_RESPONSES.contains(&type_uri)
        || install_tasks::SECRET_RESPONSES.contains(&type_uri)
        || recognise_tasks::SECRET_RESPONSES.contains(&type_uri)
        || backup_tasks::SECRET_RESPONSES.contains(&type_uri)
        || badge_tasks::SECRET_RESPONSES.contains(&type_uri)
        || crate::git_ns::tasks::SECRET_RESPONSES.contains(&type_uri)
        || event_tasks::UNRECORDED_RESPONSES.contains(&type_uri))
}

/// This community's response signer, while it has one.
fn response_signer(state: &AppState) -> Option<&dyn vti_trust_task_server::ResponseSigner> {
    state
        .credential_signer
        .as_deref()
        .map(|s| s as &dyn vti_trust_task_server::ResponseSigner)
}

#[async_trait::async_trait]
impl vti_trust_task_server::ResponseSigner for crate::credentials::LocalSigner {
    async fn sign_response_document(&self, doc: &mut Value) -> Result<(), AppError> {
        self.sign_operational_response(doc).await
    }
}

/// The document requirements (SPEC §7.2 items 5b, 7a, 8; §7.3 item 17) of
/// `type_uri`: its published specification's, read off the version VTI pins
/// (`vti-specs`, which answers the framework's own from `trust_tasks_rs`).
///
/// The deprecated prebuilt `trust_tasks_rs` index is the fallback only: a
/// version pinned after the last `trust-tasks-rs` release is in `vti-specs`
/// alone, and reading only the prebuilt index answered `None` for it — so the
/// spine enforced none of its specification's proof, `recipient` or
/// `issuedAt` requirements (fail-open; `vtc/admin/invites/create/0.2` was the
/// first such version).
pub(crate) fn spec_policy_for(type_uri: &str) -> Option<trust_tasks_rs::SpecPolicy> {
    vti_specs::schema_index::spec_policy_for(type_uri)
}

/// The acceptance window this VTC is willing to act inside — **VTI-OPS-024**,
/// SPEC §7.2 item 13, and the bound the accepted-id record's retention is
/// derived from.
///
/// # Acceptance and retention are one bound
///
/// This used to be a `retention_policy()` whose documentation said, in terms,
/// "**retention only** — this is not an acceptance policy and must not become
/// one", because many of this service's producers stamped no `issuedAt`. §7.2
/// (*Bounding the record*) makes that separation unavailable: a consumer
/// "**MUST NOT** accept for execution a document older than the window over
/// which it retains records", and one that "can establish neither an
/// `expiresAt` nor an age for a document has no window in which to place it,
/// and **MUST NOT** execute a *consequential Trust Task* on it". A record kept
/// for a window nothing is measured against is a record whose horizon is
/// capacity eviction, which makes the defence weakest exactly when the service
/// is busiest.
///
/// # Why ten minutes, and 60 seconds of skew
///
/// The library's `DEFAULT_MAX_AGE` is five minutes, "long enough to survive a
/// mediator queue, a retry with backoff, and a modest clock disagreement".
/// This service reaches members through a mediator that holds messages while a
/// recipient reconnects, so it takes double that — the same window
/// `vta-service` settled on, for the same reason, so a document that one
/// accepts is not stale at the other. The skew tolerance is the library's
/// `DEFAULT_SKEW`, 60 seconds, which is SPEC §4.2's own "typically ≤ 60s".
///
/// # Why `issuedAt` is required, and what that costs
///
/// Without it two shapes escape the window. A document carrying neither
/// timestamp is refused anyway — as `Stale { Unboundable }`, which renders as
/// the wire code `expired`, telling a producer to wait when what it must do is
/// reissue with the member it omitted. And a document carrying only
/// `expiresAt` is accepted for however long its *producer* chose: the thirty-day
/// horizon (VTI-OPS-028) is counted from `issuedAt`, so without one it bounds
/// nothing, and the producer would decide how long this consumer must remember
/// its `id`. Requiring `issuedAt` makes the last instant an accepted document
/// can return provable, which is what [`retain_until`] keeps the record to.
///
/// The cost is exact: the one shape that moves from accepted to refused is
/// **`expiresAt` present, `issuedAt` absent**. Every VTI producer stamps
/// `issuedAt` (`vta_sdk::trust_task_sign::build_unsigned`, and
/// `VtaClient::dispatch_trust_task` for every transport), and 52 of the 95
/// specifications this service binds declare the member REQUIRED in any case.
pub(super) fn freshness_policy() -> trust_tasks_rs::FreshnessPolicy {
    // The window this node also advertises in its `trust-task-discovery/0.4`
    // answer (VTI-TRN-047): one value, so the two cannot drift. It is the
    // spine's default, `VTI_ACCEPTANCE_WINDOW` requiring `issuedAt`.
    vti_trust_task_server::default_freshness_policy()
}

/// How long the duplicate-execution record for `doc` must be kept: its
/// acceptance end plus the skew (VTI-OPS-029), which SPEC §7.2 makes the end of
/// this consumer's willingness to execute it. See
/// [`vti_trust_task_server::retain_until`].
///
/// A stated `expiresAt` is honoured up to thirty days after `issuedAt`
/// (VTI-OPS-028), so this is up to thirty days and never the ten-minute window
/// alone: a record dropped while its document is still acceptable lets a
/// replay execute twice.
fn retain_until(
    doc: &TrustTask<Value>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    vti_trust_task_server::retain_until(&freshness_policy(), doc, now)
}

/// Attach this community's Data-Integrity proof to a success response.
///
/// # Why here and not at each `success_response`
///
/// Signing is the same decision taken once per handler, and there are twenty-one
/// of them. Forgetting once is a task whose response is unattributable, and
/// nothing downstream would notice — which is exactly how every response came to
/// be unsigned in the first place. The spine is where the framework's inbound
/// checks already live; the outbound one belongs beside them.
///
/// # Why this was missing, and what it cost
///
/// SPEC §7.3 item 7: where a specification declares no separate requirement for
/// the *response*, the request's applies to it — "an omission can never weaken a
/// variant". 265 published specifications declare a single
/// `proofRequirement: REQUIRED`, so their responses require a proof, and this
/// service attached none to any of them.
///
/// Nothing went red because no consumer verifies one either. Producers not
/// signing and consumers not checking is a mutually consistent silence, and the
/// cost is that **no answer this service has ever given is evidence of
/// anything**: a member cannot show a third party what the host told them, and
/// cannot be contradicted when they misreport it.
///
/// # Scope
///
/// Every response document — success **and** `trust-task-error` — is signed
/// with `proofPurpose: authentication` (VTI-KEY-106): a client that refuses
/// unsigned replies must be able to attribute a refusal as well as a result.
/// A document that already carries a proof, or an empty body, is left alone.
///
/// A community with no signer configured (setup, before provisioning) returns
/// the document unsigned rather than failing: it has nothing to sign with, and
/// refusing to answer would make an unprovisioned VTC unusable rather than
/// merely unattributable.
pub(crate) async fn sign_response(state: &AppState, outcome: TrustTaskOutcome) -> TrustTaskOutcome {
    vti_trust_task_server::sign_response(response_signer(state), outcome).await
}

/// Dispatch an approved action's stored document — the requester's own, parked
/// when it was submitted — through the handler it was sent to, and sign what
/// comes back (`crate::admin_actions`, VTI-APV-017).
///
/// Past the spine on purpose: freshness and the replay record held the
/// document once, when it arrived (VTI-OPS-024…027), and this service is
/// executing its own stored copy, not accepting the document again. Every
/// check the handler makes runs as it did on submission, against the community
/// as it is now.
async fn dispatch_parked(
    state: &AppState,
    ctx: JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let type_uri = doc.type_uri.for_routing().to_string();
    let outcome = dispatch_typed(state, &ctx, doc, &type_uri).await;
    sign_response(state, outcome).await
}

/// [`dispatch_parked`] as `exec`'s execution, boxed behind a plain `fn` with a
/// named return type. The executor is reached from a decision, which is one
/// arm of [`dispatch_typed`]; an `async fn` cycle cannot prove its own future
/// `Send`, and a concrete `dyn` return type is what breaks it.
pub(crate) fn dispatch_parked_boxed<'a>(
    state: &'a AppState,
    ctx: JoinAuthCtx,
    doc: TrustTask<Value>,
    exec: crate::admin_actions::Executing,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = TrustTaskOutcome> + Send + 'a>> {
    Box::pin(crate::admin_actions::executing_scope(
        exec,
        dispatch_parked(state, ctx, doc),
    ))
}

/// The routing table, as a plain `fn` returning the chosen handler's future,
/// boxed — never an `async fn` that awaits it.
///
/// An `async fn` holding this `match` is one poll function with every arm's
/// handler future and its temporaries in a single stack frame, live under
/// whichever handler runs: unoptimised, that frame was ~1.1 MiB, and with
/// `vetting-pcs` a `git-ns/*` document overflowed a 2 MiB test thread on Linux
/// (it already had once, after VTI-13 grew the join path, which boxing three
/// arms put off). Here each arm is boxed where it is chosen and this frame is
/// gone before any handler is polled, so the stack a document is dispatched on
/// is the deepest handler's alone, not that plus the sum of all the others.
fn dispatch_typed<'a>(
    state: &'a AppState,
    ctx: &'a JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = TrustTaskOutcome> + Send + 'a>> {
    // Every `rooms/*` operation is authorized against the DID that **signed the
    // request**, so an unsigned one has nothing to authorize and is refused.
    //
    // That refusal is not new: each of these handlers used to call
    // `verify_trust_task_proof` itself and return this same rejection. The
    // verification moved to the spine; the requirement did not move anywhere.
    // Since #1641 the spine refuses a proof-less `rooms/*` document before this
    // arm is reached, because every one of them declares `proof` REQUIRED and
    // `spec_policy_for` is now enforced — so this guard is belt to that brace.
    // It stays: `verified_signer` is `Option`, and defaulting to an empty
    // presenter would authorize a room operation against nobody.
    let rooms_presenter = ctx.verified_signer.as_deref();

    match type_uri {
        // The rooms family. Note what these still do not take: no `ctx`, and no auth
        // claims. A room operation is authorized by the authority chain the room itself
        // issued, never by this service's ACL, roster, or the caller's session —
        // invariant I5 of `docs/05-design-notes/data-rooms.md`, and what makes a room
        // portable.
        //
        // They do take the **verified signer**, which is not a weakening of that: it is
        // a cryptographic fact about the request, not an authority this service confers.
        // The handlers used to derive it themselves; they cannot once they hold a typed
        // payload, because re-deriving the signed bytes from a parsed payload is sound
        // only for a type that round-trips losslessly. See `JoinAuthCtx::
        // verified_signer`.
        uri if crate::rooms::handlers::serves(uri) => Box::pin(async move {
            // A room operation is authorized against the DID that signed the
            // request, so an unsigned one has nothing to authorize. The spine
            // verified any proof that was present; absent, there is no signer.
            let Some(presenter) = rooms_presenter else {
                return reject_with(&doc, trust_tasks_rs::RejectReason::ProofRequired);
            };
            crate::rooms::handlers::dispatch(state, doc, presenter).await
        }),
        // Every `git-ns/*` task, read off that family's own dispatcher as the
        // rooms arm is. Authority there is the signer's git rights, resolved
        // from the VTC's records at execution time — never a bearer token,
        // never a payload member. Every task in the family requires the proof,
        // which the spine has already enforced.
        uri if crate::git_ns::tasks::serves(uri) => Box::pin(async move {
            crate::git_ns::tasks::dispatch(
                state,
                doc,
                ctx.verified_signer.as_deref(),
                ctx.sender_did.as_deref(),
            )
            .await
        }),
        // Every other task this community serves, each registered by its
        // generated payload type in its family module ([`routing`], #2579).
        // Boxed as the arms above are: a decision that completes an action
        // re-enters this dispatcher with the parked document.
        uri if routing::serves(uri) => Box::pin(routing::dispatch(state, ctx, doc)),
        discovery::DISCOVERY_V0_4_TYPE | discovery::DISCOVERY_V0_3_TYPE => {
            Box::pin(async move { discovery::handle(ctx, doc) })
        }
        other => Box::pin(async move { unsupported_type_or_version(&doc, other) }),
    }
}

#[cfg(test)]
use vti_trust_task_server::reject::task_family;

/// Reject a type URI this dispatcher has no arm for, distinguishing the two
/// failures that used to wear one code.
///
/// "I have never heard of this task" and "I know this task, at a different
/// version" send the operator to completely different places — the first to
/// whether the verb exists at all, the second to which side is out of date —
/// and only the second is recoverable by upgrading something.
///
/// So a URI whose family this VTC *does* dispatch is rejected as
/// `unsupportedVersion` — SPEC's code for exactly this, "the consumer
/// recognizes the type but not at this MAJOR.MINOR" — naming the versions
/// actually served in `message` and in `details.servedVersions`. Anything else
/// stays `unsupportedType`.
///
/// This is the VTC half of #1220, which did the same on the VTA after an
/// operator spent an hour reading `unsupported type: …/provision/integration/0.3`
/// as "this agent cannot provision" when it meant "this agent is older than
/// your client". The VTC is more exposed to that reading, not less: its
/// `spec/vtc/*` families are mid-migration, so a member client and a community
/// can legitimately be at different versions of the same verb.
///
/// Both `details` members are bounded by construction — `servedVersions` comes
/// from a `const` of seven, and `requestedType` echoes a `TypeUri` the
/// framework already parsed and already puts in `message` — but they still go
/// through `reject_with_code`'s `bound_details`, because "bounded by
/// construction" is a property of today's callers rather than of the funnel.
fn unsupported_type_or_version(doc: &TrustTask<Value>, type_uri: &str) -> TrustTaskOutcome {
    // Both halves of what this service serves: the URIs still routed by the
    // match below, and the ones the rooms and git-ns dispatchers derive from
    // their registrations — the routing table itself, so a version hint cannot
    // name a task nobody serves, nor omit one that is served.
    let served = dispatched_uris()
        .into_iter()
        .chain(crate::rooms::handlers::served_uris())
        .chain(crate::git_ns::tasks::served_uris());
    vti_trust_task_server::reject::unsupported_type_or_version(doc, type_uri, served, "VTC")
}

/// The Trust Task URIs this dispatcher routes besides the `rooms/*` and
/// `git-ns/*` families: every family's registrations ([`routing`], #2579) and
/// the framework's discovery task. Read off the routing table itself, so it
/// cannot name a task nobody serves, nor omit one that is served.
///
/// This set is also exactly what is reachable **over TSP**, since the TSP
/// inbound path (#833) hands every frame to this dispatcher and has no
/// protocol-message surface behind it.
///
/// Read at runtime: [`unsupported_type_or_version`] answers an unrouted URI
/// from it, and discovery lists it.
pub(crate) fn dispatched_uris() -> Vec<&'static str> {
    let mut all = routing::served_uris();
    all.extend([
        discovery::DISCOVERY_V0_4_TYPE,
        discovery::DISCOVERY_V0_3_TYPE,
    ]);
    all
}

/// `vtc/members/admin-remove/0.1` — an administrator removes another member.
pub(crate) const MEMBER_ADMIN_REMOVE_TYPE: &str =
    <member_admin_remove::Payload as trust_tasks_rs::Payload>::TYPE_URI;

pub(crate) const DID_HOSTING_ERR_NO_KEY_HOLDER: &str =
    did_hosting_list::error_codes::NO_KEY_HOLDER.code;
pub(crate) const DID_HOSTING_ERR_KEY_HOLDER_UNAVAILABLE: &str =
    did_hosting_list::error_codes::KEY_HOLDER_UNAVAILABLE.code;
pub(crate) const DID_HOSTING_ERR_KEY_HOLDER_REFUSED: &str =
    did_hosting_list::error_codes::KEY_HOLDER_REFUSED.code;

/// `acl/revoke/0.2` — remove an entry, or narrow its act scope.
#[allow(deprecated)] // the community serves acl/* 0.2 (list 0.3): see `acl_tasks`
pub(crate) const ACL_REVOKE_TYPE: &str =
    <vti_specs::acl::revoke::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `auth/step-up/approve-response/0.7` — the answer to an operation-bound
/// step-up: a passkey assertion (`webauthn`) — unsigned from the admin
/// console, whose only key is a delegation, or beside the subject's own proof
/// — or a step-up approver's statement (`approverSigned`, VTI-APV-015), which
/// the subject's own DID signs. 0.4 and 0.6 are no longer served.
pub(crate) const STEP_UP_APPROVE_RESPONSE_TYPE: &str =
    <step_up_approve_response::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/join-requests/submit:presentationInvalid` — the presentation is not
/// the applicant's own.
pub(crate) const SUBMIT_ERR_PRESENTATION_INVALID: &str =
    jr::JOIN_REQUEST_SUBMIT_ERR_PRESENTATION_INVALID;

/// Resolve the proven holder DID for a holder-bound verb. DIDComm → the
/// authcrypt sender; REST → the document proof signer. When the document
/// carries an `issuer`, it must match the proven identity (anti-spoof).
async fn resolve_holder(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<String, TrustTaskOutcome> {
    // REST: the spine has already verified the document's proof over the JSON
    // as received and bound it to the issuer (`verified_signer`). Verifying it
    // again here, over the typed `doc`, would re-serialise it and refuse what
    // the producer actually signed (VTI-45). With no verified signer there is
    // no proof, and the typed call refuses that the same way it always has.
    let proven = match (&ctx.sender_did, &ctx.verified_signer) {
        (Some(did), _) => did.clone(),
        (None, Some(signer)) => signer.clone(),
        (None, None) => match verify_trust_task_proof(state, doc).await {
            Ok(did) => did,
            Err(e) => return Err(app_error_to_reject(doc, &e)),
        },
    };
    if let Some(issuer) = doc.issuer.as_deref() {
        // By identity, as the holder was authenticated (VTI-KEY-160).
        let issuer_base = vta_sdk::did_scid::identity(issuer);
        if issuer_base != vta_sdk::did_scid::identity(&proven) {
            return Err(reject_with(
                doc,
                RejectReason::PermissionDenied {
                    reason: format!(
                        "document issuer ({issuer_base}) does not match the authenticated holder ({proven})"
                    ),
                },
            ));
        }
    }
    Ok(proven)
}

// ─── the admin-facing member verbs (#1641 phase 2) ───────────────────────

/// The administrator a signed admin document is authorized as.
///
/// # Why this is not the bearer route's gate, and why it is not weaker
///
/// The REST routes these four verbs also sit on take `AdminAuth`: a live
/// session whose JWT says `role: admin`. That claim was itself written from the
/// caller's ACL row — `map_vtc_role_to_auth_role` admits only `VtcRole::Admin`
/// — at the moment the session was minted, and nothing re-reads it afterwards.
///
/// Here there is no session, because a signed document is not a session: the
/// proof says who authored *this document*, and **VTI-OPS-020** is satisfied by
/// that rather than by a transport. So authority is read from the ACL entry
/// [`crate::acl::resolve_auth_role`] finds for the verified signer, **at the
/// time the document is executed**. That is the same rule the bearer route
/// applies, evaluated later: a row removed, expired, or demoted since the
/// session began refuses here and would not have refused there.
///
/// What does change is the revocation lever. A bearer session is killed by
/// revoking the session; a signed document is refused by removing or expiring
/// the ACL row, which is the only authority it ever rested on. That is
/// deliberate — `docs/05-design-notes/vtc-trust-task-proof-enforcement.md` §1
/// — and it is why nothing here consults `sessions_ks`.
///
/// The signer is taken from [`JoinAuthCtx::verified_signer`], which the spine
/// filled in from the proof it verified against the document's own `issuer`
/// (SPEC §4.7) — never from the transport. All four of these specifications
/// declare `proof` REQUIRED, so the spine has already refused a document
/// carrying none; the `None` arm is belt to that brace, exactly as the
/// `rooms/*` arm keeps its own.
///
/// # Acting as, via a console-key delegation (#1684)
///
/// A signer with **no ACL row of its own** may still be a console signing key
/// — a `did:key` the admin SPA generated in the browser and enrolled as a
/// credential of the operator's admin DID, so the console can author a signed
/// document at all. Then the delegation names an admin DID and *that* DID's
/// ACL row is resolved, here, at execution time. Nothing in the paragraphs
/// above changes: a delegation carries no role, the row is still the whole
/// authority, and a row removed, demoted or expired since the key was enrolled
/// refuses exactly as it would for a direct signer. `sessions_ks` is still not
/// consulted.
///
/// **The fall-through is only for a signer with no row at all.** A signer that
/// *has* one is answered by it, including when it refuses. The design note
/// sketches falling through on `Forbidden` too; that would let a delegation
/// route around a row that has since been demoted or expired, which is the one
/// thing "authority is the ACL row" exists to prevent.
/// [`crate::acl::console_key`] carries the matching enrolment refusal, so the
/// two halves cannot drift.
///
/// # What a delegated key may *not* do, and why nothing here enforces it
///
/// Two escalations are worth naming, because both are closed structurally and
/// a later change could quietly open either.
///
/// - **It cannot enrol another delegation.** `POST /v1/admin/console-keys` is a
///   bearer route under `AdminAuth`, and a bearer session is minted only for a
///   DID that `resolve_auth_role` admits — which a console DID, holding no ACL
///   row, never is. A console key therefore cannot authenticate at all, let
///   alone reach the enrolment door. `tests/admin_console_keys.rs::
///   a_console_key_gains_no_bearer_authority` pins that.
/// - **It cannot spend a session's step-up, or make a gesture.** An
///   [`crate::acl::AdminActor`] carries no session at all, so there is no
///   session step-up to spend (#2580). A verb
///   on this door that confers administrative authority (`acl/grant`) asks
///   [`crate::acl::bound_step_up`] instead, for a gesture bound to that one
///   operation. A delegated key can *redeem* such a gesture — it acts as its
///   admin — but only the admin's own user-verified passkey can *record* one
///   (`vtc-operation-bound-step-up.md`).
async fn admin_signer(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<crate::acl::AdminActor, TrustTaskOutcome> {
    let Some(signer) = ctx.verified_signer.clone() else {
        return Err(reject_with(doc, RejectReason::ProofRequired));
    };

    // The signer's own row first — unchanged for the CLI, integrations and
    // wallets, which is every caller that is not a browser.
    let has_own_row = crate::acl::get_acl_entry(&state.acl_ks, &signer)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?
        .is_some();

    if !has_own_row
        && let Some(delegation) =
            crate::acl::console_key::resolve_delegated_admin(&state.console_keys_ks, &signer)
                .await
                .map_err(|e| app_error_to_reject(doc, &e))?
    {
        // Resolve the delegating admin's row *before* stamping last-used, so
        // the stamp records an authorized use rather than an attempt.
        let actor = resolve_admin_actor(state, doc, &delegation.admin_did)
            .await?
            .through_console_key(signer.as_str());
        crate::acl::console_key::touch_last_used(&state.console_keys_ks, &delegation).await;
        tracing::info!(
            console_did = %signer,
            admin_did = %delegation.admin_did,
            task = %doc.type_uri,
            "authorizing a signed document under a console-key delegation"
        );
        return Ok(actor);
    }

    // Not delegated, or delegated and revoked/expired. Falls through to the
    // ordinary resolve, so the refusal is the same `permissionDenied` an
    // unknown signer has always got — a distinct code here would tell a prober
    // which DIDs are, or once were, console keys.
    resolve_admin_actor(state, doc, &signer).await
}

/// [`admin_signer`], held to **the capability the operation needs**
/// (`vtc-admin-roles.md` §4 "Gates"; **VTI-ACL-030**, **-034**, **-036**).
///
/// The capability is read from the acting administrator's live entry — the
/// signer's own, or the delegating administrator's for a console key — at
/// execution time, through the one authorization question,
/// [`crate::acl::VtcAclEntry::can`] ([`crate::acl::AdminActor::can`]). The
/// entry [`admin_signer`] read is the one asked: it is not read a second time
/// (#2580). `resource` narrows the question to one resource (`None` =
/// community-wide).
pub(crate) async fn capable_signer(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
    cap: crate::acl::Capability,
    resource: Option<&crate::acl::ResourceQualifier>,
) -> Result<crate::acl::AdminActor, TrustTaskOutcome> {
    let actor = admin_signer(state, ctx, doc).await?;
    actor
        .require(cap, resource)
        .map_err(|e| app_error_to_reject(doc, &e))?;
    Ok(actor)
}

/// The administrative verbs a suspended subject may still send: reading the
/// action list, where it sees the reduction about itself (VTI-APV-019), and
/// withdrawing a request of its own — which reduces nothing, and is refused
/// for any action it did not ask for.
const SUSPENDED_MAY_SEND: &[&str] = &[
    action_tasks::LIST_TYPE,
    action_tasks::SHOW_TYPE,
    action_tasks::CANCEL_TYPE,
];

/// Read `did`'s ACL row and admit it as the [`crate::acl::AdminActor`] the
/// admin verbs take.
///
/// Split out of [`admin_signer`] because the delegated arm needs the identical
/// resolution, and "identical" has to be structural rather than remembered.
///
/// Not a synthetic `AuthClaims` any more (#2580): the VTC has no contexts, so
/// such a value read as unscoped — a super-admin — to every shared
/// `vti_common` helper. The actor carries the entry and answers `can`, and
/// nothing role-shaped.
async fn resolve_admin_actor(
    state: &AppState,
    doc: &TrustTask<Value>,
    did: &str,
) -> Result<crate::acl::AdminActor, TrustTaskOutcome> {
    let actor = crate::acl::AdminActor::resolve(&state.acl_ks, did)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    // A subject whose reduction is cooling off is suspended
    // (`vtc-action-list.md` §8.2): it may read the action list — to see the
    // action about itself (VTI-APV-019) — and nothing else, whatever the
    // operation. One refusal here, naming the action and when it lands, for
    // every administrative verb; the capability checks behind it refuse too.
    if !SUSPENDED_MAY_SEND.contains(&doc.type_uri.for_routing().to_string().as_str())
        && let Some(s) = crate::acl::storage::get_suspension(&state.acl_ks, did)
            .await
            .map_err(|e| app_error_to_reject(doc, &e))?
    {
        return Err(app_error_to_reject(doc, &s.refusal(did)));
    }
    Ok(actor)
}

// Validate a payload against its published schema and hand back the generated
// type (`deny_unknown_fields` and the required set from serde, `const`, `enum`,
// `pattern`, `minLength` from `validate_value`). The bearer routes got the
// first half from their hand-written bodies and the second from nothing at all,
// so this door is the stricter of the two.
use vti_trust_task_server::typed::parse_spec_payload;

/// `vtc/members/personhood/challenge/0.1` — mint the single-use nonce
/// the assert presentation must be bound to.
#[cfg(test)]
pub(crate) const PERSONHOOD_CHALLENGE_TYPE: &str =
    <pc::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/members/personhood/assert/0.2` — present the evidence, with the outcome evidence of
/// each witnessing session a VWC in it cites (`outcomeEvidence`). 0.1, which had no member for
/// that evidence, is not served.
#[cfg(test)]
pub(crate) const PERSONHOOD_ASSERT_TYPE: &str = <pa::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/members/update/0.1` — update a member's role or metadata.
#[cfg(test)]
pub(crate) const MEMBER_UPDATE_TYPE: &str =
    <member_update::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/members/purge/0.1` — irreversibly erase a member record.
#[cfg(test)]
pub(crate) const MEMBER_PURGE_TYPE: &str =
    <member_purge::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/members/credentials/0.1` — read one member's credential bodies.
#[cfg(test)]
pub(crate) const MEMBER_CREDENTIALS_TYPE: &str =
    <member_credentials::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/join-requests/decide/0.1` — admit or refuse a pending applicant.
#[cfg(test)]
pub(crate) const JOIN_DECIDE_TYPE: &str =
    <join_decide::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/endorsement-types/register/0.1` — register an endorsement type.
#[cfg(test)]
pub(crate) const ENDORSEMENT_TYPE_REGISTER_TYPE: &str =
    <endorsement_type_register::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/endorsement-types/delete/0.1` — delete an unreferenced endorsement type.
#[cfg(test)]
pub(crate) const ENDORSEMENT_TYPE_DELETE_TYPE: &str =
    <endorsement_type_delete::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/config/import/0.1` — preview or apply a portable configuration.
#[cfg(test)]
pub(crate) const CONFIG_IMPORT_TYPE: &str =
    <config_import::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/config/export/0.1` — the community's portable configuration.
#[cfg(test)]
pub(crate) const CONFIG_EXPORT_TYPE: &str =
    <config_export::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/community/profile/update/0.1` — edit the community's public profile.
#[cfg(test)]
pub(crate) const COMMUNITY_PROFILE_UPDATE_TYPE: &str =
    <community_profile_update::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/backup/export/0.1` — an encrypted full-state backup.
#[cfg(test)]
pub(crate) const BACKUP_EXPORT_TYPE: &str =
    <backup_export::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `acl/update/0.2` — amend act, capabilities, approve, label, expiry.
#[allow(deprecated)] // the community serves acl/* 0.2 (list 0.3): see `acl_tasks`
#[cfg(test)]
pub(crate) const ACL_UPDATE_TYPE: &str =
    <vti_specs::acl::update::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `acl/show/0.2` — one entry, every axis stated.
#[allow(deprecated)] // the community serves acl/* 0.2 (list 0.3): see `acl_tasks`
#[cfg(test)]
pub(crate) const ACL_SHOW_TYPE: &str =
    <vti_specs::acl::show::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `acl/list/0.3` — the entries, filterable by capability and resource, paged
/// by `limit` / `nextCursor`.
#[allow(deprecated)] // the community serves acl/* 0.2 (list 0.3): see `acl_tasks`
#[cfg(test)]
pub(crate) const ACL_LIST_TYPE: &str =
    <vti_specs::acl::list::v0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `acl/grant/0.2` — AclEntry 0.2: an administrative role, explicit act scope,
/// capabilities and approve scope. 0.1 is no longer served.
#[allow(deprecated)] // the community serves acl/* 0.2 (list 0.3): see `acl_tasks`
#[cfg(test)]
pub(crate) const ACL_GRANT_TYPE: &str =
    <vti_specs::acl::grant::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `acl/change-role/0.2` — move the administrative role, compare-and-swap.
#[allow(deprecated)] // the community serves acl/* 0.2 (list 0.3): see `acl_tasks`
#[cfg(test)]
pub(crate) const ACL_CHANGE_ROLE_TYPE: &str =
    <vti_specs::acl::change_role::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;

#[cfg(test)]
mod tests {
    use super::*;

    fn error_doc(outcome: TrustTaskOutcome) -> Value {
        serde_json::from_slice(&outcome.body).expect("rejection is a framework error document")
    }

    /// A request document to reject from. Its own type is irrelevant — the
    /// rejection is built from the URI passed in, not from this.
    fn request_doc() -> TrustTask<Value> {
        let uri: trust_tasks_rs::TypeUri = jr::JOIN_REQUEST_MANIFEST_TYPE
            .parse()
            .expect("manifest uri");
        TrustTask::new("urn:uuid:test", uri, serde_json::json!({}))
    }

    /// A family split on its trailing version segment, nothing else.
    ///
    /// Written against synthetic paths: a `trusttasks.org/spec/` literal
    /// anywhere under `vtc-service/src` is read by `trust_task_manifest`'s
    /// census as an assertion that the registry publishes that task, and a
    /// test fixture is not one.
    #[test]
    fn task_family_strips_only_the_version_segment() {
        assert_eq!(
            task_family("scheme://host/spec/vtc/a/b/0.2"),
            Some("scheme://host/spec/vtc/a/b")
        );
        assert_eq!(task_family("no-slashes-at-all"), None);
    }

    /// A verb this VTC has never heard of still gets `unsupportedType`.
    ///
    /// The version arm must not swallow the plain case: "I do not implement
    /// this" and "I implement this at another version" are different answers
    /// and only the second is fixed by upgrading something.
    #[test]
    fn an_unknown_family_is_still_unsupported_type() {
        let outcome =
            unsupported_type_or_version(&request_doc(), "scheme://host/spec/vtc/nope/1.0");
        let doc = error_doc(outcome);
        assert_eq!(doc["payload"]["code"], "unsupportedType");
        assert!(doc["payload"]["details"].get("servedVersions").is_none());
    }

    /// A known family at an unknown version names the versions served.
    ///
    /// The VTC half of #1220. Its `spec/vtc/*` families are mid-migration, so
    /// a member client and a community can legitimately sit at different
    /// versions of the same verb — which makes a bare `unsupported type` read
    /// as "this community cannot do this" when it means "one of us is older".
    ///
    /// Built from `dispatched_uris` rather than a literal, so the fixture
    /// cannot claim a version this VTC does not serve.
    #[test]
    fn a_known_family_at_an_unknown_version_names_what_is_served() {
        let served = dispatched_uris();
        let real = served
            .first()
            .expect("the dispatcher routes at least one URI");
        let family = task_family(real).expect("a task URI has a family");
        let bogus = format!("{family}/99.99");

        let doc = error_doc(unsupported_type_or_version(&request_doc(), &bogus));

        assert_eq!(doc["payload"]["code"], "unsupportedVersion");
        let message = doc["payload"]["message"].as_str().expect("a message");
        assert!(
            message.contains(real),
            "the message must name the served version; got {message}"
        );
        assert_eq!(doc["payload"]["details"]["servedVersions"][0], *real);
        assert_eq!(doc["payload"]["details"]["requestedType"], bogus);
    }

    /// The migration hint never names a *neighbouring* family.
    ///
    /// `join-requests/submit` and `join-requests/status` share a long prefix
    /// and are different verbs; offering one as the version to migrate onto
    /// would send a client at a task that cannot serve its request.
    #[test]
    fn a_neighbouring_family_is_not_offered_as_a_version() {
        let served = dispatched_uris();
        let real = served
            .first()
            .expect("the dispatcher routes at least one URI");
        let family = task_family(real).expect("a task URI has a family");
        let bogus = format!("{family}/99.99");

        let doc = error_doc(unsupported_type_or_version(&request_doc(), &bogus));
        let served = doc["payload"]["details"]["servedVersions"]
            .as_array()
            .expect("servedVersions is an array");

        for entry in served {
            let uri = entry.as_str().expect("a URI string");
            assert_eq!(
                task_family(uri),
                Some(family),
                "{uri} is a different family and must not be offered as a version of {family}"
            );
        }
    }

    /// Every URI the dispatcher declares as routed must be a known Trust Task
    /// request URI — one the spec registry can answer a policy for — so a
    /// typo or a URI nobody published can never silently reach `dispatch_typed`.
    ///
    /// This used to also assert `DISPATCHED_URIS` against a second,
    /// hand-retyped copy of itself (`declared`), which caught nothing a
    /// typo in one of the two copies couldn't equally cause to agree by
    /// accident. There is no registry API to enumerate every published URI
    /// (only to look one up), so the derivable half of the old check — ask
    /// the registry, don't retype it — is what is left, and it is the half
    /// that actually protects a member: an unrouted URI already fails in
    /// `dispatch_typed`, but a routed one the registry has never heard of
    /// would route a document none of the framework's SPEC §7.2 checks
    /// (`is_proof_required`, `recipient`, `issuedAt`, ...) are enforced for.
    /// (That no two families register one URI is `routing`'s own census.)

    #[test]
    fn dispatcher_routes_every_dispatched_uri() {
        for uri in dispatched_uris() {
            assert!(
                spec_policy_for(uri).is_some(),
                "`{uri}` is dispatched but the spec registry has no policy for it — either it \
                 is misspelled, or its specification is not published where \
                 `vti_specs::schema_index` can answer `spec_policy_for` for it (or, for a \
                 task bound ahead of its specification, a local policy stands in for it)"
            );
        }
    }

    /// The rooms dispatcher serves every URI `vti_rooms` puts on the wire.
    ///
    /// The one thing registration-by-type cannot check for itself: that no verb
    /// was *forgotten*. A missing `.on_async` is silent — the task simply is not
    /// served — so this compares the dispatcher's own list against the family's
    /// wire constants, which `vti-rooms/tests/schema_conformance.rs` in turn
    /// pins against the published `TYPE_URI`s.
    #[test]
    fn rooms_dispatcher_serves_every_wire_uri() {
        let served = crate::rooms::handlers::served_uris();
        for uri in vti_rooms::wire::ROOMS_DISPATCHED_URIS {
            assert!(
                served.contains(uri),
                "`{uri}` is on the wire but no handler is registered for it — a \
                 client would be told it is unsupported at every version"
            );
        }
        assert_eq!(
            served.len(),
            vti_rooms::wire::ROOMS_DISPATCHED_URIS.len(),
            "the dispatcher serves something the wire module does not name: {served:?}"
        );
    }

    /// The request URIs must parse as framework `TypeUri`s (the `/spec/`
    /// path shape), otherwise an inbound document would never deserialise.
    #[test]
    fn dispatched_uris_are_canonical_type_uris() {
        for u in dispatched_uris() {
            let parsed: Result<trust_tasks_rs::TypeUri, _> = u.parse();
            assert!(
                parsed.is_ok(),
                "dispatched URI is not a canonical TypeUri: {u}"
            );
        }
    }

    /// The two member verbs are what #185 needs over TSP, and the TSP inbound
    /// path reaches a verb only through this dispatcher — so their absence
    /// would be an `UnsupportedType` on the wire, not a compile error.
    #[test]
    fn member_verbs_are_dispatched() {
        for u in [
            jr::MEMBER_SELF_REMOVE_TYPE,
            vta_sdk::protocols::members::MEMBER_VMC_TYPE,
        ] {
            assert!(
                dispatched_uris().contains(&u),
                "member verb not reachable over TSP: {u}"
            );
        }
    }

    /// The whole point of routing personhood here: a member client that
    /// speaks Trust Tasks over messaging can run the ceremony. Before this,
    /// personhood was REST-only, so `openvtc` — which talks to the VTC over
    /// DIDComm/TSP and holds no bearer token — could not reach it at all.
    #[test]
    fn personhood_verbs_are_dispatched() {
        for u in [PERSONHOOD_CHALLENGE_TYPE, PERSONHOOD_ASSERT_TYPE] {
            assert!(
                dispatched_uris().contains(&u),
                "personhood verb not reachable over TSP: {u}"
            );
        }
    }

    mod personhood {
        use super::*;
        use crate::acl::{VtcAclEntry, VtcRole, store_acl_entry};
        use crate::test_support::TestVtc;
        use serde_json::json;
        use vti_rooms_dtg::test_support::Party;

        const MEMBER: &str = "did:key:zPersonhoodMember";

        /// A community with signers and [`MEMBER`] seeded as a member.
        async fn fixture() -> TestVtc {
            let vtc = TestVtc::builder().with_signers(true).build().await;
            seed_member(&vtc, MEMBER).await;
            vtc
        }

        /// Seed `did` as a member of `vtc`.
        async fn seed_member(vtc: &TestVtc, did: &str) {
            store_acl_entry(
                &vtc.state.acl_ks,
                &VtcAclEntry {
                    did: did.into(),
                    role: VtcRole::Member,
                    label: None,
                    admin: VtcRole::Member.implied_authority(),
                    delegated_by: None,
                    created_at: 0,
                    created_by: "did:key:vtc-install".into(),
                    updated_at: None,
                    updated_by: None,
                    expires_at: None,
                    resource_grants: Vec::new(),
                    group_grants: Vec::new(),
                    label_set_by_subject: false,
                    suspension: None,
                },
            )
            .await
            .expect("seed member ACL");
        }

        /// The fixture leaves `vtc_did` unset, so `validate_basic`'s
        /// recipient binding is skipped — these tests are about the per-verb
        /// auth the handlers add. Every document here is signed: over DIDComm
        /// the spine accepts a document only when its proof binds it to the
        /// sender, whatever the task's own proof requirement.
        ///
        /// A document issued by `from` and carrying `from`'s Data-Integrity
        /// proof — what a producer sends for a task that declares `proof`
        /// REQUIRED. Both `vtc/members/personhood/challenge/0.1` (since
        /// trust-tasks 0.23) and `assert/0.2` do.
        ///
        /// `from` is a real `did:key` with the secret behind it, because the
        /// spine verifies the proof against the document's own `issuer`
        /// (SPEC §4.7): a placeholder string like [`MEMBER`] can address a
        /// document but cannot sign one.
        async fn signed_document(
            from: &Party,
            type_uri: &str,
            payload: serde_json::Value,
        ) -> Vec<u8> {
            let mut doc = vta_sdk::trust_task_sign::build_unsigned(
                type_uri,
                payload,
                &from.did,
                crate::test_support::TEST_VTC_DID,
            )
            .expect("build the document");
            let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(
                &from.did,
                &from.secret_multibase,
            )
            .expect("a did:key names its own verification method");
            vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
                .await
                .expect("sign the document");
            serde_json::to_vec(&doc).expect("serialize document")
        }

        /// The reply body as text. `TrustTaskOutcome` keeps raw bytes so the
        /// wire output is byte-identical to direct serialisation.
        fn rendered(out: &TrustTaskOutcome) -> String {
            String::from_utf8_lossy(&out.body).into_owned()
        }

        /// Happy path over messaging: a member mints their own challenge and
        /// the reply carries the spoken match code, same as over REST.
        #[tokio::test]
        async fn a_member_can_mint_a_challenge_over_messaging() {
            let vtc = fixture().await;
            let member = Party::new();
            seed_member(&vtc, &member.did).await;
            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(member.did.clone()),
                &signed_document(
                    &member,
                    PERSONHOOD_CHALLENGE_TYPE,
                    json!({ "did": member.did }),
                )
                .await,
            )
            .await;

            let body = rendered(&out);
            assert!(
                body.contains("challengeId"),
                "expected a challenge in the reply, got: {body}"
            );
            assert!(
                body.contains(crate::members::match_code::MATCH_CODE_EXT_KEY),
                "the messaging reply must carry the match code the REST reply does, got: {body}"
            );
        }

        /// **Every success response carries this community's proof.**
        ///
        /// SPEC §7.3 item 7: a specification declaring a single
        /// `proofRequirement: REQUIRED` binds its *response* as well as its
        /// request — "an omission can never weaken a variant" — and 265
        /// published specifications declare exactly that. This service attached
        /// a proof to none of them until the spine started signing.
        ///
        /// Nothing caught it because no consumer verifies one either, which is
        /// why the guard is here rather than left to a client: a mutually
        /// consistent silence between producer and consumer stays silent.
        #[tokio::test]
        async fn a_success_response_is_signed() {
            let vtc = fixture().await;
            let member = Party::new();
            seed_member(&vtc, &member.did).await;
            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(member.did.clone()),
                &signed_document(
                    &member,
                    PERSONHOOD_CHALLENGE_TYPE,
                    json!({ "did": member.did }),
                )
                .await,
            )
            .await;

            let doc: serde_json::Value =
                serde_json::from_slice(&out.body).expect("the reply is a JSON document");
            let proof = doc.get("proof").unwrap_or_else(|| {
                panic!(
                    "a success response carries no proof, so nothing this community says is \
                     attributable: {}",
                    rendered(&out)
                )
            });
            assert_eq!(
                proof.get("cryptosuite").and_then(|v| v.as_str()),
                Some("eddsa-jcs-2022"),
                "unexpected cryptosuite: {proof}"
            );
            assert!(
                proof.get("proofValue").and_then(|v| v.as_str()).is_some(),
                "the proof carries no signature: {proof}"
            );
        }

        /// A community with no signer answers **unsigned rather than failing**.
        ///
        /// It has nothing to sign with, and refusing would make an
        /// unprovisioned VTC unusable rather than merely unattributable — the
        /// wrong direction to err in, since the operation itself succeeded.
        #[tokio::test]
        async fn a_community_with_no_signer_still_answers() {
            let vtc = TestVtc::builder().with_signers(false).build().await;
            let member = Party::new();
            seed_member(&vtc, &member.did).await;

            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(member.did.clone()),
                &signed_document(
                    &member,
                    PERSONHOOD_CHALLENGE_TYPE,
                    json!({ "did": member.did }),
                )
                .await,
            )
            .await;

            assert!(
                out.status.is_success(),
                "an unsigned answer is still an answer: {}",
                rendered(&out)
            );
            let doc: serde_json::Value =
                serde_json::from_slice(&out.body).expect("the reply is a JSON document");
            assert!(doc.get("proof").is_none(), "signed without a signer");
        }

        /// The membership check standing in for the REST route's session.
        /// Without it, anyone who can reach the mediator could mint
        /// challenges against this community's members.
        #[tokio::test]
        async fn a_stranger_cannot_mint_a_challenge() {
            let vtc = fixture().await;
            let stranger = Party::new();
            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(stranger.did.clone()),
                &signed_document(
                    &stranger,
                    PERSONHOOD_CHALLENGE_TYPE,
                    json!({ "did": MEMBER }),
                )
                .await,
            )
            .await;

            let body = rendered(&out);
            assert!(
                !body.contains("challengeId"),
                "a non-member minted a challenge: {body}"
            );
            assert!(
                body.contains("not a member"),
                "expected a permission refusal naming membership, got: {body}"
            );
        }

        /// A refusal is signed, for `authentication`, like a result.
        #[tokio::test]
        async fn a_refusal_is_signed() {
            let vtc = fixture().await;
            let stranger = Party::new();
            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(stranger.did.clone()),
                &signed_document(
                    &stranger,
                    PERSONHOOD_CHALLENGE_TYPE,
                    json!({ "did": stranger.did }),
                )
                .await,
            )
            .await;
            assert!(!out.status.is_success(), "{}", rendered(&out));
            let doc: serde_json::Value = serde_json::from_slice(&out.body).expect("JSON reply");
            assert_eq!(
                doc["proof"]["proofPurpose"], "authentication",
                "a refusal must carry this community's proof: {doc}"
            );

            // So is one refused before dispatch — here an unsigned document.
            let mut unsigned: serde_json::Value = serde_json::from_slice(
                &signed_document(
                    &stranger,
                    PERSONHOOD_CHALLENGE_TYPE,
                    json!({ "did": stranger.did }),
                )
                .await,
            )
            .unwrap();
            unsigned.as_object_mut().unwrap().remove("proof");
            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(stranger.did.clone()),
                &serde_json::to_vec(&unsigned).unwrap(),
            )
            .await;
            let doc: serde_json::Value = serde_json::from_slice(&out.body).expect("JSON reply");
            assert_eq!(doc["proof"]["proofPurpose"], "authentication", "{doc}");
        }

        /// `assert/0.2` declares `actsAsSubject: true`. On a transport that
        /// proves the sender, one member must not be able to assert
        /// personhood in another's name — even though the presentation gate
        /// would also stop them, because a caller should be refused before
        /// the daemon starts verifying someone else's credentials.
        ///
        /// The document is **signed**, and that is the point of the fixture
        /// change #1672 made here. `assert/0.2` declares `proof` REQUIRED; this
        /// test used to send an unsigned one over DIDComm, which reached the
        /// handler only through the transitional allowance the same change
        /// removes. Left alone it would now stop at `proofRequired` and go on
        /// passing for a reason that has nothing to do with subject binding —
        /// a green test asserting nothing. Signing it puts the caller's
        /// identity where the handler reads it from (`verified_signer`, bound
        /// to the document's own `issuer`), so the refusal under test is still
        /// the one being produced.
        #[tokio::test]
        async fn one_member_cannot_assert_personhood_for_another() {
            let vtc = fixture().await;
            let stranger = Party::new();
            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(stranger.did.clone()),
                &signed_document(
                    &stranger,
                    PERSONHOOD_ASSERT_TYPE,
                    json!({
                        "did": MEMBER,
                        "presentation": { "type": ["VerifiablePresentation"], "holder": MEMBER },
                    }),
                )
                .await,
            )
            .await;

            let body = rendered(&out);
            assert!(
                body.contains("asserted by its subject"),
                "expected the subject-binding refusal, got: {body}"
            );
        }
    }
}
