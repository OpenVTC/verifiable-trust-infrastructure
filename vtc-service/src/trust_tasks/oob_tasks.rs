//! Wallet sign-in started by a trigger link: `auth/oob/request/0.2`,
//! `claim/0.2`, `prove/0.3`, `respond/0.3` (carrying a `grant/0.3`),
//! `redeem/0.2` and `cancel/0.1` on the signed-document spine.
//!
//! The handlers — the check order of base design §7.3–7.6
//! (`design-docs/vtc-qr-login-design.md`), with the trigger link contract's
//! changes (C5), and the T7/T15/T19/T21 rules they cite — are the shared
//! [`vti_oob_server`] crate. This module is the VTC's [`OobHost`]: what the
//! handlers ask of a community.
//!
//! - **Rows.** The member session keyspace.
//! - **Identity.** The VTC DID, its `public_url`, and the community's name
//!   (its profile's, else the configured one).
//! - **Signer.** The VTC's `assertionMethod` key (`credential_signer`).
//! - **Carried proofs.** This community's DID resolver, and its accepted-id
//!   record for their replay (T7).
//! - **Gates.** For the member portal, an active member
//!   ([`crate::member_portal::active_member`]); for the operator console, an
//!   administrator in the ACL ([`crate::acl::resolve_auth_role`]), told so
//!   once the DID is proved (`details.reason: notAnAdmin`).
//! - **Signing scope.** [`PORTAL_SIGNING_SCOPE`] for the member portal; none
//!   for the console.
//! - **Audit.** `MemberWalletSignIn` or `AdminWalletSignIn`.
//! - **What `redeem` issues.** A member session and its cookies, arming
//!   `K_b`'s delegation when the grant carries a scope; or the console
//!   session every console sign-in issues. Never the other audience's (T19).
//!
//! # Which session: member portal or operator console
//!
//! A request is a member-portal sign-in unless the starter asks otherwise in
//! `ext["org.openvtc.session"].audience` (`"admin"`: the operator console's
//! login page) — [`SessionAudience`]. A member request's responses carry no
//! extension, exactly as before the extension existed.

use super::routing::{Routes, on};
use std::net::IpAddr;

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vtc_audit::{AuditEvent, MemberWalletSignInData};
use vti_common::auth::session::{
    Session, SessionState, now_epoch, store_refresh_index, store_session,
};
use vti_common::store::KeyspaceHandle;
use vti_oob_server::{
    AMR, Approved, Completion, Eligibility, Gate, OobHost, OobMessages, SignInEvent,
};
use vti_trust_task_server::AcceptedIdStore;

use super::JoinAuthCtx;
use super::helpers::TrustTaskOutcome;
use crate::member_portal::oob::{self, NOT_AN_ADMIN, SessionAudience};
use crate::member_portal::{MemberAuthBackend, active_member, cookies};
use crate::server::AppState;

/// The sign-in tasks, as `vti_oob_server` names them (the admission layer's
/// closed set). `identify` and `grant` are not here: they are only ever
/// carried inside `prove` and `respond`, and one sent by itself is refused as
/// an unsupported type.
pub(crate) use vti_oob_server::URIS;

/// The task families a member-portal sign-in offers to let `K_b` sign for as
/// the member (`auth/oob/prove/0.3` `signingScope`): the member directory, so
/// the portal can read it and edit the member's own card, and the community's
/// groups, so it can list, join and leave them, and the community's boards, so
/// a member can propose ideas and leave notes (VTI-BRD-050; deciding, selecting
/// and hiding refuse the key, VTI-BRD-051), without asking the wallet for
/// every document — and the member's own view of the community's repositories
/// (`git-ns/view`) with where a forge-account link they began stands
/// (`git-ns/account/link-status`), never another `git-ns` task: linking,
/// unlinking and every right change take the member's own signature, through
/// their wallet (`auth/oob/grant/0.3` consumer item 6). Fixed for the surface,
/// as the specification requires; the operator console offers none.
pub(crate) const PORTAL_SIGNING_SCOPE: &[&str] = &[
    "vtc/directory",
    "vtc/groups",
    "vtc/boards",
    "vtc/badges",
    "git-ns/view",
    "git-ns/account/link-status",
];

/// The message an identity that is not an administrator gets, on the
/// wallet's side (`prove`, `respond`) and the console's (`redeem`).
const NOT_AN_ADMIN_MESSAGE: &str = "This identity isn't an administrator of this community.";

/// Run before the spine verifies the proof of an `auth/oob` document: the
/// signer must be an Ed25519 `did:key` (T21, [`vti_oob_server::precheck`]).
pub(super) fn precheck(doc: &TrustTask<Value>, type_uri: &str) -> Option<TrustTaskOutcome> {
    vti_oob_server::precheck(doc, type_uri)
}

/// Register every sign-in task (#2579), each handed to `vti_oob_server`.
pub(super) fn register(routes: Routes) -> Routes {
    use vti_specs::auth::oob;
    let routes = on!(routes, oob::request::v0_2::Payload => run);
    let routes = on!(routes, oob::claim::v0_2::Payload => run);
    let routes = on!(routes, oob::prove::v0_3::Payload => run);
    let routes = on!(routes, oob::respond::v0_3::Payload => run);
    let routes = on!(routes, oob::redeem::v0_2::Payload => run);
    on!(routes, oob::cancel::v0_1::Payload => run)
}

async fn run(state: &AppState, ctx: &JoinAuthCtx, doc: TrustTask<Value>) -> TrustTaskOutcome {
    // The spine verified the proof against `issuer`; `precheck` required one.
    let signer = ctx.verified_signer.clone().unwrap_or_default();
    let type_uri = doc.type_uri.for_routing().to_string();
    vti_oob_server::dispatch(&VtcOobHost::new(state), doc, &type_uri, signer)
        .await
        .expect("registered only for the sign-in tasks vti_oob_server routes")
}

/// The community, as the `auth/oob` handlers see it.
struct VtcOobHost<'a> {
    state: &'a AppState,
    accepted_ids: super::accepted_ids::AcceptedIds,
}

impl<'a> VtcOobHost<'a> {
    fn new(state: &'a AppState) -> Self {
        Self {
            state,
            accepted_ids: state.accepted_ids(),
        }
    }

    fn refused_admin(reason: &str) -> Eligibility {
        Eligibility::RefusedTelling {
            reason: reason.into(),
            told: NOT_AN_ADMIN.into(),
            message: NOT_AN_ADMIN_MESSAGE.into(),
        }
    }
}

/// Whether `did` may open an operator-console session: the check every
/// console sign-in makes ([`crate::acl::resolve_auth_role`] — a live,
/// unexpired ACL entry with an administrative role). Read now, never from a
/// session.
async fn is_administrator(state: &AppState, did: &str) -> Result<bool, crate::error::AppError> {
    match crate::acl::resolve_auth_role(&state.acl_ks, did).await {
        Ok(_) => Ok(true),
        Err(crate::error::AppError::Forbidden(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

#[async_trait::async_trait]
impl OobHost for VtcOobHost<'_> {
    type Audience = SessionAudience;

    fn records(&self) -> &KeyspaceHandle {
        &self.state.member_sessions_ks
    }

    async fn service_did(&self) -> Option<String> {
        self.state.config.read().await.vtc_did.clone()
    }

    async fn public_url(&self) -> Option<String> {
        self.state.config.read().await.public_url.clone()
    }

    /// The profile's name, else the configured one.
    async fn service_name(&self) -> Option<String> {
        let vtc_name = self.state.config.read().await.vtc_name.clone();
        let profile = crate::community::load_profile(&self.state.community_ks)
            .await
            .ok()
            .flatten();
        profile
            .map(|p| p.name)
            .filter(|n| !n.is_empty())
            .or(vtc_name.filter(|n| !n.is_empty()))
    }

    /// From the local GeoIP database only (base design §12.6).
    fn locate(&self, address: IpAddr) -> Option<String> {
        self.state.geoip.locate(address)
    }

    async fn sign_step(&self, response: &mut Value) -> Result<(), String> {
        let Some(signer) = self.state.credential_signer.clone() else {
            return Err(
                "this community has no signing key, so it cannot sign the sign-in response".into(),
            );
        };
        signer
            .sign_attested_response(response)
            .await
            .map_err(|e| e.to_string())
    }

    async fn verify_authentication(
        &self,
        received: &Value,
    ) -> Result<String, crate::error::AppError> {
        super::helpers::verify_received_trust_task_proof(self.state, received).await
    }

    async fn verify_assertion(
        &self,
        received: &Value,
        type_uri: &str,
    ) -> Result<String, crate::error::AppError> {
        super::helpers::verify_received_approval_proof(self.state, received, type_uri).await
    }

    fn freshness_policy(&self) -> trust_tasks_rs::FreshnessPolicy {
        super::freshness_policy()
    }

    fn accepted_ids(&self) -> &dyn AcceptedIdStore {
        &self.accepted_ids
    }

    async fn gate(
        &self,
        gate: Gate,
        audience: SessionAudience,
        did: &str,
    ) -> Result<Eligibility, crate::error::AppError> {
        let state = self.state;
        let member = || async { active_member(state, did).await.map(|m| m.is_some()) };
        Ok(match (gate, audience) {
            // `prove` step 3, before any DID is resolved (T15). For the portal,
            // an active member. For the console, an active member or an
            // administrator: a member who is not an administrator is let
            // through to the signature check only so that, once they have
            // proved the DID is theirs, they can be told why they cannot sign
            // in (step 5a).
            (Gate::Known, SessionAudience::Member) => {
                if member().await? {
                    Eligibility::Eligible
                } else {
                    Eligibility::Refused {
                        reason: "not an active member".into(),
                    }
                }
            }
            (Gate::Known, SessionAudience::Admin) => {
                if is_administrator(state, did).await? || member().await? {
                    Eligibility::Eligible
                } else {
                    Eligibility::Refused {
                        reason: "not an active member".into(),
                    }
                }
            }
            // `prove` step 5a: the console's gate, by the same check every
            // console sign-in makes. The portal's was step 3.
            (Gate::Proved, SessionAudience::Member) => Eligibility::Eligible,
            (Gate::Proved, SessionAudience::Admin) => {
                if is_administrator(state, did).await? {
                    Eligibility::Eligible
                } else {
                    Self::refused_admin("not an administrator")
                }
            }
            // `respond` step 5: still a member — or, for the console, still an
            // administrator.
            (Gate::Decided, SessionAudience::Member) => {
                if member().await? {
                    Eligibility::Eligible
                } else {
                    Eligibility::Refused {
                        reason: "no longer an active member".into(),
                    }
                }
            }
            (Gate::Decided, SessionAudience::Admin) => {
                if is_administrator(state, did).await? {
                    Eligibility::Eligible
                } else {
                    Self::refused_admin("no longer an administrator")
                }
            }
        })
    }

    fn told_message(&self, told: &str) -> Option<String> {
        (told == NOT_AN_ADMIN).then(|| NOT_AN_ADMIN_MESSAGE.into())
    }

    /// A member sign-in offers the portal's signing scope. The console offers
    /// none.
    fn signing_scope(&self, audience: SessionAudience) -> Option<Vec<String>> {
        (audience == SessionAudience::Member)
            .then(|| PORTAL_SIGNING_SCOPE.iter().map(|s| s.to_string()).collect())
    }

    async fn audit(&self, event: SignInEvent<'_, SessionAudience>) {
        let Some(writer) = self.state.audit_writer.as_ref() else {
            tracing::warn!(
                stage = event.stage,
                "audit writer not configured; wallet sign-in step not audited"
            );
            return;
        };
        let rec = event.record;
        let data = MemberWalletSignInData {
            stage: event.stage.into(),
            request_id: rec.request_id.clone(),
            member: event.member.map(str::to_string),
            reason: event.reason.map(str::to_string),
            location: Some(rec.requester.location.clone()),
            grant: event.grant,
        };
        // An operator-console sign-in is its own event, so an audit reader
        // filtering for console access sees it beside the other console logins.
        let audit_event = match rec.audience {
            SessionAudience::Member => AuditEvent::MemberWalletSignIn(data),
            SessionAudience::Admin => AuditEvent::AdminWalletSignIn(data),
        };
        if let Err(e) = writer.write(event.actor, event.member, audit_event).await {
            tracing::warn!(stage = event.stage, error = %e, "could not audit a wallet sign-in step");
        }
    }

    /// The session the request asked for: subject the DID that signed the
    /// grant, session key `K_b`, `amr = ["did", "oob", "uv"]`.
    ///
    /// - **Member portal:** a member session, ending at the earlier of the
    ///   grant's `sessionEndsAt` and the member session limit.
    /// - **Operator console:** the console session every console sign-in
    ///   issues ([`crate::routes::auth::mint_admin_cookie_session`]), for a
    ///   DID the ACL holds as an administrator now, ending no later than the
    ///   grant's `sessionEndsAt`. Anyone else is `declined` with
    ///   `details.reason: notAnAdmin`, and the request stays spent.
    ///
    /// Either way the grant's `sessionEndsAt` is stored as the session's
    /// absolute end ([`vti_common::auth::session::Session::not_after`]):
    /// refresh rotates the tokens inside it and refuses once it has passed, so
    /// the member's approval bounds the whole session, not only its first
    /// window. The `sessionEndsAt` reported is the session's true end.
    async fn complete(
        &self,
        approved: Approved<'_, SessionAudience>,
    ) -> Result<Completion, crate::error::AppError> {
        match approved.record.audience {
            SessionAudience::Member => redeem_member(self, &approved).await,
            SessionAudience::Admin => redeem_admin(self, &approved).await,
        }
    }

    fn reject_app_error(
        &self,
        doc: &TrustTask<Value>,
        err: &crate::error::AppError,
    ) -> TrustTaskOutcome {
        super::helpers::app_error_to_reject(doc, err)
    }

    fn messages(&self) -> OobMessages {
        OobMessages {
            request_https_only: "auth/oob/request is accepted only over HTTPS from the member portal",
            request_wrong_origin: "auth/oob/request is accepted only from this community's own origin \
                 (the member portal and operator console)",
            redeem_https_only: "auth/oob/redeem is served only over HTTPS, where the session is set as cookies",
            not_set_up: "this community has not finished setting up",
        }
    }
}

async fn redeem_member(
    host: &VtcOobHost<'_>,
    approved: &Approved<'_, SessionAudience>,
) -> Result<Completion, crate::error::AppError> {
    let state = host.state;
    let consumed = approved.record;
    let member_did = approved.subject;
    // Membership again, now (T18).
    let Some(member) = active_member(state, member_did).await? else {
        return Ok(Completion::NotAuthorized);
    };
    let (session_id, session_end, set) =
        mint_session(state, member_did, &consumed.start_key, approved.not_after).await?;
    // A grant with `signingScope` arms `K_b` to sign those families as the
    // member, for this session (auth/oob/grant/0.3).
    if let Some(scope) = approved.signing_scope() {
        let delegation = crate::member_portal::delegation::Delegation {
            member_did: member_did.to_string(),
            session_id: session_id.clone(),
            scope,
            not_after: session_end,
            grant_id: approved.grant_id(),
        };
        crate::member_portal::delegation::record(
            &state.member_sessions_ks,
            &consumed.start_key,
            &delegation,
        )
        .await?;
    }
    approved.http.set_cookies(set);
    let display_name: String = member
        .entry
        .label
        .clone()
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| member_did.chars().take(128).collect());
    Ok(Completion::Issued {
        display_name,
        ends_at: session_end,
    })
}

async fn redeem_admin(
    host: &VtcOobHost<'_>,
    approved: &Approved<'_, SessionAudience>,
) -> Result<Completion, crate::error::AppError> {
    let state = host.state;
    let consumed = approved.record;
    let admin_did = approved.subject;
    // Administrator again, now: an entry removed or narrowed since the
    // approval opens no console. The request is already spent.
    if !is_administrator(state, admin_did).await? {
        host.audit(SignInEvent {
            actor: admin_did,
            stage: "declined",
            record: consumed,
            member: Some(admin_did),
            reason: Some(NOT_AN_ADMIN),
            grant: None,
        })
        .await;
        return Ok(Completion::Declined {
            told: NOT_AN_ADMIN.into(),
        });
    }
    let session_key = oob::did_key_multikey(&consumed.start_key).map(str::to_string);
    let minted = match crate::routes::auth::mint_admin_cookie_session(
        state,
        admin_did,
        AMR,
        session_key,
        Some(approved.not_after),
    )
    .await
    {
        Ok(m) => m,
        // Removed between the check above and the mint.
        Err(crate::error::AppError::Forbidden(_)) => {
            return Ok(Completion::Declined {
                told: NOT_AN_ADMIN.into(),
            });
        }
        Err(e) => return Err(e),
    };
    approved.http.set_cookies(minted.cookies);
    let label = crate::acl::get_acl_entry(&state.acl_ks, admin_did)
        .await
        .ok()
        .flatten()
        .and_then(|e| e.label)
        .filter(|l| !l.is_empty());
    let display_name = label.unwrap_or_else(|| admin_did.chars().take(128).collect());
    Ok(Completion::Issued {
        display_name,
        ends_at: minted.minted.refresh_expires_at,
    })
}

/// Create the member session and the cookies that carry it, through the same
/// backend, keyspace and cookie shapes as every portal sign-in
/// (`crate::member_portal`).
async fn mint_session(
    state: &AppState,
    did: &str,
    session_key: &str,
    not_after: u64,
) -> Result<(String, u64, Vec<String>), crate::error::AppError> {
    let backend = MemberAuthBackend::from_state(state).await?;
    let session_id = uuid::Uuid::new_v4().to_string();
    let amr: Vec<String> = AMR.iter().map(|s| s.to_string()).collect();
    let acr = "aal2".to_string();
    // The grant's `sessionEndsAt` bounds the session: both tokens are minted to
    // end by it, and it is stored as the session's absolute end, so refresh
    // rotation (`handle_refresh`) cannot extend it either.
    let minted = vti_common::auth::handlers::mint_session_tokens_until(
        &backend,
        did,
        &session_id,
        &crate::acl::Role::Reader,
        &[],
        &amr,
        &acr,
        false,
        Some(not_after),
    )
    .await?;
    let refresh_expires_at = minted.refresh_expires_at;
    let access_expires_at = minted.access_expires_at;
    store_session(
        &state.member_sessions_ks,
        &Session {
            session_id: session_id.clone(),
            did: did.to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: minted.issued_at,
            last_seen: minted.issued_at,
            refresh_token: Some(minted.refresh_token.clone()),
            refresh_expires_at: Some(refresh_expires_at),
            tee_attested: false,
            amr,
            acr,
            acr_expires_at: None,
            token_id: Some(minted.token_id.clone()),
            session_pubkey_b58btc: oob::did_key_multikey(session_key).map(str::to_string),
            not_after: Some(not_after),
        },
    )
    .await?;
    store_refresh_index(
        &state.member_sessions_ks,
        &minted.refresh_token,
        &session_id,
    )
    .await?;
    let now = now_epoch();
    let access_max_age = access_expires_at.saturating_sub(now).max(1);
    let refresh_max_age = refresh_expires_at.saturating_sub(now).max(1);
    Ok((
        session_id,
        refresh_expires_at,
        vec![
            cookies::session_cookie(&minted.access_token, access_max_age),
            cookies::refresh_cookie(&minted.refresh_token, refresh_max_age),
            cookies::csrf_cookie(&cookies::new_csrf(), refresh_max_age),
        ],
    ))
}
