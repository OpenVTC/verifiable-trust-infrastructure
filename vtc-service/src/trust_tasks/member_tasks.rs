//! The member-facing verbs on the signed-document spine: renewal, DID
//! rotation, personhood revocation, the relationship graph's member verbs, and
//! the endorsement verbs an Issuer-role member performs.
//!
//! | task | authority (the proof signer's, read now) |
//! |---|---|
//! | `vtc/members/renew/0.1` | the signer renews **their own** membership |
//! | `vtc/members/rotate-challenge/0.1` | the signer opens a rotation of **their own** DID |
//! | `vtc/members/rotate/0.1` | the signer is `oldDid`; both in-payload signatures authorize the swap |
//! | `vtc/members/personhood/revoke/0.1` | the subject, or an administrator |
//! | `vtc/relationships/list/0.2` | any current member or administrator |
//! | `vtc/relationships/publish/0.2` | the signer, exactly as the bearer-less REST route |
//! | `vtc/relationships/revoke/0.1` | the edge's issuer, or an administrator |
//! | `vtc/relationships/revoke/0.2` | the edge's issuer (directly, or via `pop`), or an administrator |
//! | `vtc/endorsements/{issue,list,show,revoke}/0.1` | an `Admin` or `Issuer` ACL row |
//!
//! Until these were bound here every one of them was HTTPS REST only, so a
//! member on TSP or DIDComm could join a community and then do nothing with
//! their membership. Each arm calls the same operation its (former, in most
//! cases) REST route called (`renew_inner`, `rotate_inner`, `revoke_inner`,
//! …). Once this spine covered a verb, its bearer-session REST route had no
//! remaining reason to exist and was removed for renew, rotate-challenge,
//! rotate, personhood/revoke, relationships/list, endorsements/{issue,list,
//! show,revoke} and relationships/revoke. The last two waited on
//! trustoverip/dtgwg-trust-tasks-tf#689: `revoke/0.1` alone authorized only
//! two of the three capacities the REST route did — the edge's own issuer, or
//! an administrator — and not a `VrcRevokeAuthorization` proving control of a
//! pairwise relationship DID; `0.2` adds that as a `pop` bound to the document
//! rather than a REST session (see `handle_relationships_revoke_v0_2`).
//!
//! # Where the authority comes from
//!
//! The bearer routes take `AuthClaims`, which says only "a session exists";
//! each handler then reads the caller's ACL row (the endorsement verbs) or
//! compares the session DID with the subject (renew, rotate, personhood). A
//! signed document has no session, so every arm here reads the **verified
//! signer's** ACL row at execution time instead — the same rule
//! [`super::admin_signer`] applies to the admin verbs, and for the same reason
//! (`docs/05-design-notes/vtc-trust-task-proof-enforcement.md` §1). An
//! **expired** row refuses, as it refuses a bearer session.
//!
//! One consequence is worth stating rather than leaving to be discovered. A
//! VTC bearer session is minted only for a DID whose row maps to
//! `Role::Admin` (`acl::map_vtc_role_to_auth_role`), so in a deployed
//! community the bearer routes above were reachable by administrators alone,
//! whatever their handlers' own checks said. These specifications name the
//! member (`renew`'s "the authenticated caller … acting on their own
//! membership", `endorsements/*`'s "community-admin **or** issuer capability
//! against the live ACL"), so this door admits the parties the specifications
//! and the handlers name — a member renewing their own credentials, an issuer
//! issuing — exactly as `members/personhood/challenge` already does here. No
//! arm admits a party its handler's own check would refuse.
//!
//! A console-key delegation ([`super::admin_signer`]) is honoured where the
//! verb is exercised in an **administrative** capacity (revoking another
//! member's personhood or edge, the endorsement verbs, reading the graph). It
//! is not honoured for the self verbs: a console key acts *as* its admin, and
//! renewing or rotating someone's own membership is not an administrative act.

use chrono::Utc;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use trust_tasks_rs::specs::vtc::endorsements::{
    issue::v0_1 as end_issue, list::v0_1 as end_list, revoke::v0_1 as end_revoke,
    show::v0_1 as end_show,
};
use trust_tasks_rs::specs::vtc::members::{
    personhood::revoke::v0_1 as personhood_revoke, renew::v0_1 as renew, rotate::v0_1 as rotate,
    rotate_challenge::v0_1 as rotate_challenge,
};
use trust_tasks_rs::specs::vtc::relationships::{
    list::v0_2 as rel_list, publish::v0_2 as rel_publish, revoke::v0_1 as rel_revoke,
    revoke::v0_2 as rel_revoke_v0_2,
};
use trust_tasks_rs::validate::ValidatedPayload;
use trust_tasks_rs::{RejectReason, StandardCode, TrustTask, TrustTaskCode};
use uuid::Uuid;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, parse_payload, reject_with, reject_with_code,
    success_response, task_error_to_reject,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::acl::get_acl_entry;
use crate::error::{AppError, TaskError};
use crate::server::AppState;

/// `vtc/members/renew/0.1`.
pub(crate) const RENEW_TYPE: &str = <renew::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/members/rotate-challenge/0.1`.
pub(crate) const ROTATE_CHALLENGE_TYPE: &str =
    <rotate_challenge::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/members/rotate/0.1`.
pub(crate) const ROTATE_TYPE: &str = <rotate::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/members/personhood/revoke/0.1`.
pub(crate) const PERSONHOOD_REVOKE_TYPE: &str =
    <personhood_revoke::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/relationships/list/0.2`.
pub(crate) const RELATIONSHIPS_LIST_TYPE: &str =
    <rel_list::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/relationships/publish/0.2`.
pub(crate) const RELATIONSHIPS_PUBLISH_TYPE: &str =
    <rel_publish::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/relationships/revoke/0.1`.
pub(crate) const RELATIONSHIPS_REVOKE_TYPE: &str =
    <rel_revoke::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/relationships/revoke/0.2` — adds the pairwise `pop` route.
pub(crate) const RELATIONSHIPS_REVOKE_0_2_TYPE: &str =
    <rel_revoke_v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/endorsements/issue/0.1`.
pub(crate) const ENDORSEMENTS_ISSUE_TYPE: &str =
    <end_issue::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/endorsements/list/0.1`.
pub(crate) const ENDORSEMENTS_LIST_TYPE: &str =
    <end_list::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/endorsements/show/0.1`.
pub(crate) const ENDORSEMENTS_SHOW_TYPE: &str =
    <end_show::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/endorsements/revoke/0.1`.
pub(crate) const ENDORSEMENTS_REVOKE_TYPE: &str =
    <end_revoke::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Every URI [`dispatch`] routes. `super::DISPATCHED_URIS` names each of these
/// and `dispatcher_routes_every_dispatched_uri` holds the two in step.
pub(crate) const URIS: &[&str] = &[
    RENEW_TYPE,
    ROTATE_CHALLENGE_TYPE,
    ROTATE_TYPE,
    PERSONHOOD_REVOKE_TYPE,
    RELATIONSHIPS_LIST_TYPE,
    RELATIONSHIPS_PUBLISH_TYPE,
    RELATIONSHIPS_REVOKE_TYPE,
    RELATIONSHIPS_REVOKE_0_2_TYPE,
    ENDORSEMENTS_ISSUE_TYPE,
    ENDORSEMENTS_LIST_TYPE,
    ENDORSEMENTS_SHOW_TYPE,
    ENDORSEMENTS_REVOKE_TYPE,
];

/// Route one of [`URIS`]; `None` for any other URI.
pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        RENEW_TYPE => handle_renew(state, ctx, doc).await,
        ROTATE_CHALLENGE_TYPE => handle_rotate_challenge(state, ctx, doc).await,
        ROTATE_TYPE => handle_rotate(state, ctx, doc).await,
        PERSONHOOD_REVOKE_TYPE => handle_personhood_revoke(state, ctx, doc).await,
        RELATIONSHIPS_LIST_TYPE => handle_relationships_list(state, ctx, doc).await,
        RELATIONSHIPS_PUBLISH_TYPE => handle_relationships_publish(state, ctx, doc).await,
        RELATIONSHIPS_REVOKE_TYPE => handle_relationships_revoke(state, ctx, doc).await,
        RELATIONSHIPS_REVOKE_0_2_TYPE => handle_relationships_revoke_v0_2(state, ctx, doc).await,
        ENDORSEMENTS_ISSUE_TYPE => handle_endorsements_issue(state, ctx, doc).await,
        ENDORSEMENTS_LIST_TYPE => handle_endorsements_list(state, ctx, doc).await,
        ENDORSEMENTS_SHOW_TYPE => handle_endorsements_show(state, ctx, doc).await,
        ENDORSEMENTS_REVOKE_TYPE => handle_endorsements_revoke(state, ctx, doc).await,
        _ => return None,
    })
}

// ─── who is asking ───────────────────────────────────────────────────────

/// The DID that signed this document, verified by the spine against its
/// `issuer`. Every task here authorizes against it; a document without one
/// has nothing to authorize and is refused.
///
/// The spine has already refused a proof-less document for every task whose
/// specification declares `proof` REQUIRED, and for every document arriving
/// over DIDComm or TSP. `relationships/list` and `endorsements/{list,show}`
/// declare it optional, which leaves only an unsigned REST document reaching
/// here — an anonymous request for a gated read, refused as `proofRequired`
/// because a proof is the only thing that could make it answerable.
fn proven_signer(ctx: &JoinAuthCtx, doc: &TrustTask<Value>) -> Result<String, TrustTaskOutcome> {
    ctx.verified_signer
        .clone()
        .ok_or_else(|| reject_with(doc, RejectReason::ProofRequired))
}

/// The signer, for a verb a member performs on **their own** membership.
///
/// An expired ACL row is refused here, as it is refused a bearer session. An
/// absent row is *not*: the operation's own member check answers that, with
/// the task's declared `notMember` rather than a bare `permissionDenied`.
async fn self_signer(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<String, TrustTaskOutcome> {
    let signer = proven_signer(ctx, doc)?;
    match get_acl_entry(&state.acl_ks, &signer).await {
        Ok(Some(entry)) if entry.is_expired(now_unix()) => Err(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!("ACL entry expired: {signer}"),
            },
        )),
        Ok(_) => Ok(signer),
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

/// Who is acting, and in what role: the signer's own current ACL row, or — for
/// a signer with no row — the administrator a console-key delegation names
/// ([`admin_signer`]). Refused when neither applies, or when the row expired.
struct Actor {
    did: String,
    /// The live entry the actor acts under — its own, or the delegating
    /// administrator's for a console key.
    entry: crate::acl::VtcAclEntry,
}

impl Actor {
    /// The one authorization question, asked of the actor's live entry
    /// (VTI-ACL-030).
    fn can(&self, cap: crate::acl::Capability) -> bool {
        self.entry.can(cap, None)
    }
}

async fn acting_party(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<Actor, TrustTaskOutcome> {
    let signer = proven_signer(ctx, doc)?;
    match get_acl_entry(&state.acl_ks, &signer).await {
        Ok(Some(entry)) if entry.is_expired(now_unix()) => Err(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!("ACL entry expired: {signer}"),
            },
        )),
        Ok(Some(entry)) => Ok(Actor { did: signer, entry }),
        // No row of its own: a console key acting for its admin, or nobody.
        // `admin_signer` answers both, refusing the second with the same
        // `permissionDenied` an unknown signer always gets.
        Ok(None) => {
            let claims = admin_signer(state, ctx, doc).await?;
            match get_acl_entry(&state.acl_ks, &claims.did).await {
                Ok(Some(entry)) => Ok(Actor {
                    did: claims.did,
                    entry,
                }),
                Ok(None) => Err(reject_with(
                    doc,
                    RejectReason::PermissionDenied {
                        reason: "the delegating administrator holds no entry".into(),
                    },
                )),
                Err(e) => Err(app_error_to_reject(doc, &e)),
            }
        }
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

/// [`acting_party`], held to the credential capability an endorsement verb
/// rests on — `vtc.credentials.issue` to mint and read, `vtc.credentials.revoke`
/// to revoke (vtc-admin-roles.md §4). `verb` completes the refusal message.
async fn endorsement_actor(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
    cap: crate::acl::Capability,
    verb: &str,
) -> Result<String, TrustTaskOutcome> {
    let actor = acting_party(state, ctx, doc).await?;
    if !actor.can(cap) {
        return Err(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!("only a holder of {cap} can {verb}"),
            },
        ));
    }
    Ok(actor.did)
}

fn now_unix() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

// ─── the reply ───────────────────────────────────────────────────────────

/// Answer with the operation's result **as the generated `#response` type**.
///
/// The operations return the bearer routes' own response structs. Reading one
/// back through the generated type — whose `deny_unknown_fields` and required
/// set are the specification's — and then its schema is what holds this
/// door's reply to the published shape; the router-level `response_conformance`
/// layer keys on the `Trust-Task` header and never sees these replies. A
/// mismatch is this service's fault, so it is an `internalError`, never a
/// reply that claims a schema it does not satisfy.
fn respond_as<R>(doc: &TrustTask<Value>, result: impl Serialize) -> TrustTaskOutcome
where
    R: DeserializeOwned + Serialize + ValidatedPayload,
{
    let checked = serde_json::to_value(&result)
        .map_err(|e| e.to_string())
        .and_then(|v| {
            R::validate_value(&v).map_err(|e| e.to_string())?;
            serde_json::from_value::<R>(v).map_err(|e| e.to_string())
        });
    match checked {
        Ok(response) => success_response(doc, response),
        Err(e) => {
            tracing::error!(task = %doc.type_uri, error = %e, "response does not match its published schema");
            reject_with(
                doc,
                RejectReason::InternalError {
                    reason: format!("response does not match its published schema: {e}"),
                },
            )
        }
    }
}

/// A payload member that names a row by UUID. Anything else names no row, so
/// it is answered with the task's declared `notFound` — the same answer as a
/// well-formed id nobody holds.
fn row_id(
    doc: &TrustTask<Value>,
    raw: &str,
    not_found: &'static str,
) -> Result<Uuid, TrustTaskOutcome> {
    Uuid::parse_str(raw).map_err(|_| {
        task_error_to_reject(
            doc,
            &TaskError::declared(not_found, AppError::NotFound(format!("{raw} not found"))),
        )
    })
}

// ─── members ─────────────────────────────────────────────────────────────

/// `vtc/members/renew/0.1` — re-mint the signer's VMC and role VAC.
async fn handle_renew(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let caller = match self_signer(state, ctx, &doc).await {
        Ok(d) => d,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<renew::Payload>(&doc) {
        return reject;
    }
    match crate::routes::members::renew::renew_inner(state, &caller).await {
        Ok(res) => respond_as::<renew::Response>(&doc, res),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/members/rotate-challenge/0.1` — open a rotation of the signer's DID.
///
/// `reason` is bound to the challenge row here: the rotation signatures do
/// not cover it, so it is taken from the party that opened the ceremony and
/// never from the finish.
async fn handle_rotate_challenge(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let caller = match self_signer(state, ctx, &doc).await {
        Ok(d) => d,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<rotate_challenge::Payload>(&doc) {
        return reject;
    }
    // The route's own body carries `reason` as the audit enum the challenge
    // row stores; the generated parse above has already held it to the
    // specification's `enum`.
    let body: crate::routes::members::rotate::ChallengeBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::routes::members::rotate::challenge_inner(state, &caller, body.reason).await {
        Ok(res) => respond_as::<rotate_challenge::Response>(&doc, res),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/members/rotate/0.1` — complete the rotation.
///
/// The signer must be `oldDid`. That is attribution; the swap itself is
/// authorized by the two in-payload signatures, which the operation verifies
/// whoever relayed them.
async fn handle_rotate(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let caller = match self_signer(state, ctx, &doc).await {
        Ok(d) => d,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<rotate::Payload>(&doc) {
        return reject;
    }
    let body: crate::routes::members::rotate::FinishBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::routes::members::rotate::rotate_inner(state, &caller, body).await {
        // `rotate_inner` answers `vmc: null` when the swap succeeded and
        // re-issuing the credentials did not; the published response requires
        // both, so `respond_as` refuses that reply rather than send it. The
        // rotation has still happened — `renew` under the new DID recovers.
        Ok(res) => respond_as::<rotate::Response>(&doc, res),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/members/personhood/revoke/0.1` — clear a member's personhood flag.
///
/// Admits the subject or an administrator. A signer revoking their own
/// personhood acts as the subject, and needs a
/// current ACL row of their own — a console key is not anyone's self.
async fn handle_personhood_revoke(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::routes::members::personhood::{RevokeCapacity, revoke_inner};

    let signer = match proven_signer(ctx, &doc) {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    let body: personhood_revoke::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let subject = body.did.as_str();
    if let Err(e) = vti_common::identifier::validate_did("did", subject) {
        return app_error_to_reject(&doc, &e);
    }

    let (actor, capacity) = if signer == subject {
        match get_acl_entry(&state.acl_ks, &signer).await {
            Ok(Some(entry)) if !entry.is_expired(now_unix()) => (signer, RevokeCapacity::Subject),
            Ok(_) => return not_permitted(&doc),
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    } else {
        match acting_party(state, ctx, &doc).await {
            Ok(actor) if actor.can(crate::acl::Capability::CredentialsRevoke) => {
                (actor.did, RevokeCapacity::Admin)
            }
            _ => return not_permitted(&doc),
        }
    };

    match revoke_inner(state, &actor, subject, capacity).await {
        Ok(res) => respond_as::<personhood_revoke::Response>(&doc, res),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

fn not_permitted(doc: &TrustTask<Value>) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: "only an admin or the subject member can revoke personhood".into(),
        },
    )
}

// ─── relationships ───────────────────────────────────────────────────────

/// `vtc/relationships/list/0.2` — one member's edges, paged.
///
/// Readable by any current member or administrator, the parties the
/// specification's *Consent/purpose* names ("members and administrators can
/// see the attestations the community holds"). A signer with no current row
/// is refused before the subject is resolved, so this cannot be used to learn
/// who is a member.
async fn handle_relationships_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = acting_party(state, ctx, &doc).await {
        return reject;
    }
    let body: rel_list::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let limit = body.limit.map(|n| n.get() as usize);
    let page = match crate::routes::members::relationships::list_inner(
        state,
        body.did.as_str(),
        body.cursor.as_deref(),
        limit,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return task_error_to_reject(&doc, &e),
    };
    // A stored edge also carries its persona annotation and lifecycle log,
    // which the published entry does not; the entry is exactly these six.
    let items: Vec<Value> = page
        .items
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "issuerDid": r.issuer_did,
                "subjectDid": r.subject_did,
                "vrcJsonld": r.vrc_jsonld,
                "vrcDigestMultibase": r.vrc_digest_multibase,
                "createdAt": r.created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            })
        })
        .collect();
    respond_as::<rel_list::Response>(
        &doc,
        vti_common::pagination::Paginated {
            items,
            next_cursor: page.next_cursor,
            total_estimate: page.total_estimate,
        },
    )
}

/// `vtc/relationships/publish/0.2` — lodge a VRC in the community graph.
///
/// The bearer-less REST route verifies this document's proof itself and then
/// runs [`publish_inner`](crate::routes::relationships::publish_inner); the
/// spine has verified it already, so this runs the same function on the same
/// signer — rate limit, VRC proof, publish authorization, policy and all.
async fn handle_relationships_publish(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::routes::relationships::{PublishError, publish_inner};

    let signer = match proven_signer(ctx, &doc) {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<rel_publish::Payload>(&doc) {
        return reject;
    }
    match publish_inner(state, &doc, &signer, Utc::now()).await {
        Ok((_status, res)) => respond_as::<rel_publish::Response>(&doc, res),
        Err(PublishError::App(e)) => task_error_to_reject(&doc, &e),
        // A limiter refusal is `unavailable` — retryable, which is the truth —
        // carrying the same `limiter` and `retryAfterSecs` the REST 429 body
        // does, so a client backs off identically on either door.
        Err(PublishError::RateLimited(r)) => reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::Unavailable),
            format!(
                "rate limited by `{}`; retry after {}s",
                r.limiter(),
                r.retry_after_secs()
            ),
            Some(serde_json::json!({
                "limiter": r.limiter(),
                "retryAfterSecs": r.retry_after_secs(),
            })),
        ),
    }
}

/// `vtc/relationships/revoke/0.1` — retract an edge.
///
/// Two capacities: the edge's **issuer**, or an **administrator**
/// (moderation). A current member who is neither gets the task's `notFound`,
/// as the specification requires — "the same code as for a relationship that
/// does not exist … an anti-probing measure". A signer who is not a current
/// member at all is refused before any lookup.
///
/// `0.1`'s payload is `{id}` alone, so an edge issued under a pairwise
/// relationship DID cannot be retracted through this door — the signer is the
/// member's own DID, never the R-DID, and there is no authorization member to
/// carry a proof of control. [`handle_relationships_revoke_v0_2`] adds it.
async fn handle_relationships_revoke(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::routes::relationships::{REVOKE_ERR_NOT_FOUND, revoke_authorized};

    let actor = match acting_party(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let body: rel_revoke::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let not_found = |doc: &TrustTask<Value>| {
        task_error_to_reject(
            doc,
            &TaskError::declared(
                REVOKE_ERR_NOT_FOUND,
                AppError::NotFound(format!("VRC {} not found", body.id.as_str())),
            ),
        )
    };
    let id = match row_id(&doc, body.id.as_str(), REVOKE_ERR_NOT_FOUND) {
        Ok(id) => id,
        Err(reject) => return reject,
    };
    let rel = match crate::relationships::get_relationship(&state.relationships_ks, id).await {
        Ok(Some(rel)) => rel,
        Ok(None) => return not_found(&doc),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let revoked_by = if actor.did == rel.issuer_did {
        "issuer"
    } else if actor.can(crate::acl::Capability::MembersManage) {
        "admin"
    } else {
        return not_found(&doc);
    };
    match revoke_authorized(state, &actor.did, &rel, revoked_by).await {
        Ok(res) => respond_as::<rel_revoke::Response>(&doc, res),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/relationships/revoke/0.2` — retract an edge, adding the pairwise route
/// `0.1` cannot reach: an edge published under a relationship DID, authorized
/// by a `pop` (`VrcRevokeAuthorization`) proving control of it, bound to this
/// document and to the edge.
///
/// Checked in the order the specification requires — issuer, administrator,
/// pairwise — so a caller who is none of the three, or whose `pop` fails to
/// verify, gets the same `notFound` an unknown id would (Security & Privacy
/// §Correlation: "not an oracle over others' relationships, nor over which
/// pairwise DIDs a member controls").
async fn handle_relationships_revoke_v0_2(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::routes::relationships::{
        REVOKE_ERR_NOT_FOUND, revoke_authorized, verify_revoke_authorization,
    };

    let actor = match acting_party(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let body: rel_revoke_v0_2::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let not_found = |doc: &TrustTask<Value>| {
        task_error_to_reject(
            doc,
            &TaskError::declared(
                REVOKE_ERR_NOT_FOUND,
                AppError::NotFound(format!("VRC {} not found", body.id.as_str())),
            ),
        )
    };
    let id = match row_id(&doc, body.id.as_str(), REVOKE_ERR_NOT_FOUND) {
        Ok(id) => id,
        Err(reject) => return reject,
    };
    let rel = match crate::relationships::get_relationship(&state.relationships_ks, id).await {
        Ok(Some(rel)) => rel,
        Ok(None) => return not_found(&doc),
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    let revoked_by = if actor.did == rel.issuer_did {
        "issuer"
    } else if actor.can(crate::acl::Capability::MembersManage) {
        "admin"
    } else if let Some(pop) = doc.payload.get("pop") {
        // `pop`'s own shape (its `type`, `documentId`, `relationship` and
        // `proof` members) was already checked by `parse_spec_payload`'s
        // schema validation above; read here as raw JSON rather than through
        // the typed `body.pop`, because `verify_revoke_authorization` — like
        // `verify_publish_authorization` beside it — verifies the
        // data-integrity proof over the object *as signed*, and the typed
        // `PayloadPop` splits `proof` out from the members it covers.
        let resolver = match state.did_resolver.as_ref().cloned() {
            Some(r) => r,
            None => {
                return app_error_to_reject(
                    &doc,
                    &AppError::Internal(
                        "DID resolver not configured — a VRC revoke authorization requires it"
                            .into(),
                    ),
                );
            }
        };
        match verify_revoke_authorization(pop, &rel.issuer_did, &doc.id, &id.to_string(), &resolver)
            .await
        {
            Ok(()) => "issuer",
            Err(_) => return not_found(&doc),
        }
    } else {
        return not_found(&doc);
    };

    match revoke_authorized(state, &actor.did, &rel, revoked_by).await {
        Ok(res) => respond_as::<rel_revoke_v0_2::Response>(&doc, res),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── endorsements ────────────────────────────────────────────────────────

/// `vtc/endorsements/issue/0.1` — mint a custom endorsement.
async fn handle_endorsements_issue(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match endorsement_actor(
        state,
        ctx,
        &doc,
        crate::acl::Capability::CredentialsIssue,
        "mint custom endorsements",
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_spec_payload::<end_issue::Payload>(&doc) {
        return reject;
    }
    let body: crate::routes::endorsements::IssueBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    // The document as received — a community `vetted/1` statement cites it by
    // `taskContext` and `taskDigestMultibase`. The spine verified the proof
    // over this same serialisation.
    let request = match serde_json::to_value(&doc) {
        Ok(v) => v,
        Err(e) => {
            return app_error_to_reject(
                &doc,
                &AppError::Internal(format!("serialise the issue request: {e}")),
            );
        }
    };
    match crate::routes::endorsements::issue_inner(state, &actor, body, &request).await {
        Ok(res) => respond_as::<end_issue::Response>(&doc, res),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/endorsements/list/0.1` — endorsements, filtered and paged.
///
/// The filters are applied, as the specification's Conformance requires; the
/// bearer route takes none, so it lists everything.
async fn handle_endorsements_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = endorsement_actor(
        state,
        ctx,
        &doc,
        crate::acl::Capability::CredentialsIssue,
        "list custom endorsements",
    )
    .await
    {
        return reject;
    }
    let body: end_list::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let filter = crate::routes::endorsements::ListFilter {
        subject_did: body.subject_did.map(|d| d.to_string()),
        type_uri: body.type_uri.map(|t| t.to_string()),
        include_revoked: body.include_revoked,
    };
    match crate::routes::endorsements::list_inner(
        state,
        &filter,
        body.cursor.as_deref(),
        body.limit.map(|n| n.get() as usize),
    )
    .await
    {
        Ok(page) => respond_as::<end_list::Response>(&doc, page),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/endorsements/show/0.1` — one endorsement.
async fn handle_endorsements_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::routes::endorsements::{SHOW_ERR_NOT_FOUND, show_inner};

    if let Err(reject) = endorsement_actor(
        state,
        ctx,
        &doc,
        crate::acl::Capability::CredentialsIssue,
        "read custom endorsements",
    )
    .await
    {
        return reject;
    }
    let body: end_show::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let id = match row_id(&doc, body.endorsement_id.as_str(), SHOW_ERR_NOT_FOUND) {
        Ok(id) => id,
        Err(reject) => return reject,
    };
    match show_inner(state, id).await {
        Ok(res) => respond_as::<end_show::Response>(&doc, res),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/endorsements/revoke/0.1` — flip an endorsement's status bit.
///
/// The capability check precedes the lookup (Conformance 1 before 2), so a
/// caller who may not revoke cannot learn which endorsement ids exist.
///
/// `reason` is accepted — the schema admits it — and not persisted: the
/// audit event this revocation writes (`CustomEndorsementRevoked`) has no
/// member for it, and the bearer route has never carried one either.
async fn handle_endorsements_revoke(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::routes::endorsements::{REVOKE_ERR_NOT_FOUND, revoke_inner};

    let actor = match endorsement_actor(
        state,
        ctx,
        &doc,
        crate::acl::Capability::CredentialsRevoke,
        "revoke endorsements",
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let body: end_revoke::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let id = match row_id(&doc, body.endorsement_id.as_str(), REVOKE_ERR_NOT_FOUND) {
        Ok(id) => id,
        Err(reject) => return reject,
    };
    match revoke_inner(state, &actor, id).await {
        Ok(res) => respond_as::<end_revoke::Response>(&doc, res),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// Each task driven through [`super::dispatch_trust_task_core`] — the one
/// place REST (`/trust-tasks`), DIDComm and TSP meet — with the context each
/// transport builds. Every task has a success case on every transport and the
/// refusal its authorization rule makes; the reply is held to the task's
/// published `#response` schema.
#[cfg(test)]
mod tests {
    use crate::acl::VtcRole;
    use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
    use affinidi_status_list::StatusPurpose;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};
    use vti_rooms_dtg::test_support::Party;

    use super::super::members_admin_tests::{
        assert_conforms, error_code, payload_of, seed_acl, signed, unsigned,
    };
    use super::super::{JoinAuthCtx, TrustTaskOutcome, dispatch_trust_task_core};
    use super::*;
    use crate::acl::{VtcAclEntry, store_acl_entry};
    use crate::join::JoinTransport;
    use crate::members::{Member, get_member, store_member};
    use crate::test_support::TestVtc;

    /// Every transport the spine is reached from.
    const TRANSPORTS: [JoinTransport; 3] = [
        JoinTransport::Rest,
        JoinTransport::DIDComm,
        JoinTransport::Tsp,
    ];

    const PUBLIC_URL: &str = "https://vtc.example.com";
    const ENDORSEMENT_TYPE: &str = "https://example.com/endorsements/skill/v1";
    const DIGEST: &str = "zQmbGXRT3v1RmfWkQ7Y3Z5Uj9pKq2NcXhLd8sVtA4eB6nMw";

    struct Fixture {
        vtc: TestVtc,
        admin: Party,
        issuer: Party,
        member: Party,
        /// A second member, the other end of the member's edges.
        peer: Party,
        /// A DID with no ACL row at all.
        stranger: Party,
    }

    async fn fixture() -> Fixture {
        let vtc = TestVtc::builder()
            .with_audit(true)
            .with_signers(true)
            .with_did_resolver(true)
            .with_public_url(PUBLIC_URL)
            .build()
            .await;
        crate::policy::default::install_defaults(
            &vtc.state.policies_ks,
            &vtc.state.active_policies_ks,
        )
        .await
        .expect("install default policies");
        for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
            crate::status_list::ensure_initial(
                &vtc.state.status_lists_ks,
                purpose,
                format!("{PUBLIC_URL}/v1/status-lists/{purpose}"),
            )
            .await
            .expect("provision status list");
        }
        let f = Fixture {
            vtc,
            admin: Party::new(),
            issuer: Party::new(),
            member: Party::new(),
            peer: Party::new(),
            stranger: Party::new(),
        };
        seed_acl(&f.vtc, &f.admin.did, VtcRole::Admin, vec![]).await;
        seed_acl(&f.vtc, &f.issuer.did, VtcRole::Issuer, vec![]).await;
        for p in [&f.member, &f.peer] {
            seed_member(&f.vtc, &p.did).await;
        }
        crate::endorsement_types::store_type(
            &f.vtc.state.endorsement_types_ks,
            &crate::endorsement_types::EndorsementType {
                type_uri: ENDORSEMENT_TYPE.into(),
                claim_schema: None,
                description: None,
                created_at: Utc::now(),
                created_by_did: f.admin.did.clone(),
            },
        )
        .await
        .expect("register endorsement type");
        f
    }

    /// An ACL row and a member row holding a status-list slot, which is what
    /// renewal, rotation and personhood revocation re-mint against.
    async fn seed_member(vtc: &TestVtc, did: &str) {
        seed_acl(vtc, did, VtcRole::Member, vec![]).await;
        let mut m = Member::fresh(did);
        m.status_list_index = Some((Uuid::new_v4().as_u128() % 1000) as u32);
        store_member(&vtc.state.members_ks, &m)
            .await
            .expect("seed member row");
    }

    fn ctx(transport: JoinTransport, from: &Party) -> JoinAuthCtx {
        match transport {
            JoinTransport::Rest => JoinAuthCtx::rest(),
            _ => JoinAuthCtx {
                transport,
                sender_did: Some(from.did.clone()),
                verified_signer: None,
            },
        }
    }

    async fn send(
        vtc: &TestVtc,
        transport: JoinTransport,
        from: &Party,
        uri: &str,
        payload: Value,
    ) -> TrustTaskOutcome {
        let doc = signed(from, uri, payload).await;
        let body = serde_json::to_vec(&doc).expect("a document serialises");
        dispatch_trust_task_core(&vtc.state, &ctx(transport, from), &body).await
    }

    fn ok(out: &TrustTaskOutcome, what: &str) {
        assert!(
            out.status.is_success(),
            "{what}: {}",
            String::from_utf8_lossy(&out.body)
        );
    }

    fn code(out: &TrustTaskOutcome) -> String {
        error_code(out).unwrap_or_else(|| {
            panic!(
                "expected an error document: {}",
                String::from_utf8_lossy(&out.body)
            )
        })
    }

    // ── the premise ──────────────────────────────────────────────────────

    /// The refusals below lean on which tasks declare a proof: the spine
    /// refuses an unsigned document for those, and these handlers refuse one
    /// for the three reads that do not.
    #[test]
    fn member_verbs_declare_the_proofs_these_tests_assume() {
        let reads = [
            RELATIONSHIPS_LIST_TYPE,
            ENDORSEMENTS_LIST_TYPE,
            ENDORSEMENTS_SHOW_TYPE,
        ];
        for uri in URIS {
            let required = trust_tasks_rs::schema_index::spec_policy_for(uri)
                .unwrap_or_else(|| panic!("{uri} has no published policy"))
                .is_proof_required;
            assert_eq!(required, !reads.contains(uri), "{uri}");
        }
    }

    /// The three proof-optional reads still authorize from a signer, so an
    /// unsigned document — which only REST can deliver — is refused.
    #[tokio::test]
    async fn proof_optional_member_reads_refuse_an_unsigned_document() {
        let f = fixture().await;
        for (uri, payload) in [
            (RELATIONSHIPS_LIST_TYPE, json!({ "did": f.member.did })),
            (ENDORSEMENTS_LIST_TYPE, json!({})),
            (
                ENDORSEMENTS_SHOW_TYPE,
                json!({ "endorsementId": Uuid::new_v4().to_string() }),
            ),
        ] {
            let body = serde_json::to_vec(&unsigned(&f.issuer, uri, payload)).unwrap();
            let out = dispatch_trust_task_core(&f.vtc.state, &JoinAuthCtx::rest(), &body).await;
            assert_eq!(code(&out), "proofRequired", "{uri}");
        }
    }

    // ── members/renew ────────────────────────────────────────────────────

    #[tokio::test]
    async fn members_renew_reissues_the_signers_own_credentials_on_every_transport() {
        let f = fixture().await;
        for t in TRANSPORTS {
            let out = send(&f.vtc, t, &f.member, RENEW_TYPE, json!({})).await;
            ok(&out, "renew");
            assert_conforms::<renew::Response>(&out);
            assert_eq!(payload_of(&out)["did"], json!(f.member.did));
        }
    }

    #[tokio::test]
    async fn members_renew_refuses_a_signer_who_is_not_a_member() {
        let f = fixture().await;
        let out = send(
            &f.vtc,
            JoinTransport::DIDComm,
            &f.stranger,
            RENEW_TYPE,
            json!({}),
        )
        .await;
        assert_eq!(
            code(&out),
            crate::routes::members::renew::RENEW_ERR_NOT_MEMBER
        );
    }

    #[tokio::test]
    async fn members_renew_refuses_an_expired_acl_row() {
        let f = fixture().await;
        let mut entry: VtcAclEntry = get_acl_entry(&f.vtc.state.acl_ks, &f.member.did)
            .await
            .unwrap()
            .unwrap();
        entry.expires_at = Some(1);
        store_acl_entry(&f.vtc.state.acl_ks, &entry).await.unwrap();
        let out = send(&f.vtc, JoinTransport::Tsp, &f.member, RENEW_TYPE, json!({})).await;
        assert_eq!(code(&out), "permissionDenied");
    }

    // ── members/rotate-challenge + members/rotate ────────────────────────

    #[tokio::test]
    async fn members_rotate_challenge_opens_a_rotation_on_every_transport() {
        let f = fixture().await;
        for t in TRANSPORTS {
            let out = send(
                &f.vtc,
                t,
                &f.member,
                ROTATE_CHALLENGE_TYPE,
                json!({ "reason": "deviceLoss" }),
            )
            .await;
            ok(&out, "rotate-challenge");
            assert_conforms::<rotate_challenge::Response>(&out);
            assert_eq!(
                payload_of(&out)["canonicalTemplate"]["oldDid"],
                json!(f.member.did)
            );
        }
    }

    #[tokio::test]
    async fn members_rotate_challenge_refuses_a_signer_who_is_not_a_member() {
        let f = fixture().await;
        let out = send(
            &f.vtc,
            JoinTransport::Rest,
            &f.stranger,
            ROTATE_CHALLENGE_TYPE,
            json!({}),
        )
        .await;
        assert_eq!(
            code(&out),
            crate::routes::members::rotate::ROTATE_CHALLENGE_ERR_NOT_MEMBER
        );
    }

    fn signing_key(p: &Party) -> SigningKey {
        let (_, seed) = multibase::decode(&p.secret_multibase).expect("multibase seed");
        SigningKey::from_bytes(&seed.try_into().expect("32-byte seed"))
    }

    /// Open a rotation as `old` and return the finish payload moving it to
    /// `new`, co-signed by both keys.
    async fn rotation_payload(vtc: &TestVtc, t: JoinTransport, old: &Party, new: &Party) -> Value {
        let out = send(vtc, t, old, ROTATE_CHALLENGE_TYPE, json!({})).await;
        ok(&out, "rotate-challenge");
        let challenge = payload_of(&out);
        let rotation_id = challenge["rotationId"].as_str().unwrap().to_string();
        let expires_at =
            chrono::DateTime::parse_from_rfc3339(challenge["expiresAt"].as_str().unwrap())
                .unwrap()
                .timestamp();
        let bytes = crate::routes::members::rotate::canonical_signing_bytes(
            Uuid::parse_str(&rotation_id).unwrap(),
            &old.did,
            &new.did,
            expires_at,
        )
        .unwrap();
        json!({
            "rotationId": rotation_id,
            "oldDid": old.did,
            "newDid": new.did,
            "oldSignature": hex::encode(signing_key(old).sign(&bytes).to_bytes()),
            "newSignature": hex::encode(signing_key(new).sign(&bytes).to_bytes()),
        })
    }

    #[tokio::test]
    async fn members_rotate_moves_the_membership_to_the_new_did_on_every_transport() {
        let f = fixture().await;
        for t in TRANSPORTS {
            let (old, new) = (Party::new(), Party::new());
            seed_member(&f.vtc, &old.did).await;
            let payload = rotation_payload(&f.vtc, t, &old, &new).await;
            let out = send(&f.vtc, t, &old, ROTATE_TYPE, payload).await;
            ok(&out, "rotate");
            assert_conforms::<rotate::Response>(&out);
            assert_eq!(payload_of(&out)["newDid"], json!(new.did));
            let acl = |did: String| {
                let ks = f.vtc.state.acl_ks.clone();
                async move { get_acl_entry(&ks, &did).await.unwrap() }
            };
            assert!(acl(old.did.clone()).await.is_none(), "the old row moved");
            assert!(acl(new.did.clone()).await.is_some(), "to the new DID");
        }
    }

    /// The signer must be `oldDid`: a member cannot finish somebody else's
    /// rotation, even holding both of that rotation's signatures.
    #[tokio::test]
    async fn members_rotate_refuses_a_signer_other_than_the_old_did() {
        let f = fixture().await;
        let (old, new) = (Party::new(), Party::new());
        seed_member(&f.vtc, &old.did).await;
        let payload = rotation_payload(&f.vtc, JoinTransport::Rest, &old, &new).await;
        let out = send(
            &f.vtc,
            JoinTransport::DIDComm,
            &f.member,
            ROTATE_TYPE,
            payload,
        )
        .await;
        assert_eq!(code(&out), "permissionDenied");
        assert!(
            get_acl_entry(&f.vtc.state.acl_ks, &old.did)
                .await
                .unwrap()
                .is_some(),
            "nothing moved"
        );
    }

    // ── members/personhood/revoke ────────────────────────────────────────

    async fn assert_personhood(vtc: &TestVtc, did: &str) {
        crate::members::storage::edit_member(&vtc.state.members_ks, did, |m| {
            m.personhood = true;
            m.personhood_asserted_at = Some(Utc::now());
            true
        })
        .await
        .unwrap()
        .unwrap();
    }

    async fn has_personhood(vtc: &TestVtc, did: &str) -> bool {
        get_member(&vtc.state.members_ks, did)
            .await
            .unwrap()
            .unwrap()
            .personhood
    }

    #[tokio::test]
    async fn members_personhood_revoke_by_the_subject_on_every_transport() {
        let f = fixture().await;
        for t in TRANSPORTS {
            assert_personhood(&f.vtc, &f.member.did).await;
            let out = send(
                &f.vtc,
                t,
                &f.member,
                PERSONHOOD_REVOKE_TYPE,
                json!({ "did": f.member.did }),
            )
            .await;
            ok(&out, "personhood/revoke by the subject");
            assert_conforms::<personhood_revoke::Response>(&out);
            assert!(payload_of(&out)["vmc"].is_object(), "a fresh VMC is minted");
            assert!(!has_personhood(&f.vtc, &f.member.did).await);
        }
    }

    #[tokio::test]
    async fn members_personhood_revoke_by_an_admin_for_another_member() {
        let f = fixture().await;
        assert_personhood(&f.vtc, &f.member.did).await;
        let out = send(
            &f.vtc,
            JoinTransport::Tsp,
            &f.admin,
            PERSONHOOD_REVOKE_TYPE,
            json!({ "did": f.member.did }),
        )
        .await;
        ok(&out, "personhood/revoke by an admin");
        assert_conforms::<personhood_revoke::Response>(&out);
        assert!(!has_personhood(&f.vtc, &f.member.did).await);
    }

    /// Neither the subject nor a holder of `vtc.credentials.revoke` — another
    /// member, a stranger — is refused, and the flag stands. (An issuer is a
    /// credential officer and holds it.)
    #[tokio::test]
    async fn members_personhood_revoke_refuses_a_party_who_is_neither_subject_nor_admin() {
        let f = fixture().await;
        assert_personhood(&f.vtc, &f.member.did).await;
        for from in [&f.peer, &f.stranger] {
            let out = send(
                &f.vtc,
                JoinTransport::DIDComm,
                from,
                PERSONHOOD_REVOKE_TYPE,
                json!({ "did": f.member.did }),
            )
            .await;
            assert_eq!(code(&out), "permissionDenied");
        }
        assert!(
            has_personhood(&f.vtc, &f.member.did).await,
            "the refused revocations changed nothing"
        );
    }

    // ── relationships/list ───────────────────────────────────────────────

    async fn seed_edge(vtc: &TestVtc, issuer: &str, subject: &str) -> Uuid {
        let id = Uuid::new_v4();
        crate::relationships::store_relationship(
            &vtc.state.relationships_ks,
            &vtc.state.relationships_by_did_ks,
            &crate::relationships::Relationship {
                id,
                issuer_did: issuer.into(),
                subject_did: subject.into(),
                vrc_jsonld: json!({ "type": ["VerifiableCredential"] }),
                vrc_digest_multibase: DIGEST.into(),
                created_at: Utc::now(),
                persona: None,
                lifecycle: Default::default(),
            },
        )
        .await
        .expect("seed edge");
        id
    }

    async fn edge_exists(vtc: &TestVtc, id: Uuid) -> bool {
        crate::relationships::get_relationship(&vtc.state.relationships_ks, id)
            .await
            .unwrap()
            .is_some()
    }

    #[tokio::test]
    async fn relationships_list_answers_a_member_on_every_transport() {
        let f = fixture().await;
        let id = seed_edge(&f.vtc, &f.member.did, &f.peer.did).await;
        for t in TRANSPORTS {
            let out = send(
                &f.vtc,
                t,
                &f.peer,
                RELATIONSHIPS_LIST_TYPE,
                json!({ "did": f.member.did, "limit": 10 }),
            )
            .await;
            ok(&out, "relationships/list");
            assert_conforms::<rel_list::Response>(&out);
            assert_eq!(payload_of(&out)["items"][0]["id"], json!(id.to_string()));
        }
    }

    #[tokio::test]
    async fn relationships_list_refuses_a_signer_who_is_not_a_member() {
        let f = fixture().await;
        seed_edge(&f.vtc, &f.member.did, &f.peer.did).await;
        let out = send(
            &f.vtc,
            JoinTransport::Tsp,
            &f.stranger,
            RELATIONSHIPS_LIST_TYPE,
            json!({ "did": f.member.did }),
        )
        .await;
        assert_eq!(code(&out), "permissionDenied");
    }

    #[tokio::test]
    async fn relationships_list_names_an_unknown_subject_not_found() {
        let f = fixture().await;
        let out = send(
            &f.vtc,
            JoinTransport::Rest,
            &f.member,
            RELATIONSHIPS_LIST_TYPE,
            json!({ "did": "did:key:zNobodyHere" }),
        )
        .await;
        assert_eq!(
            code(&out),
            crate::routes::members::relationships::LIST_ERR_NOT_FOUND
        );
    }

    // ── relationships/publish ────────────────────────────────────────────

    /// An attributed VRC: issued under the member's own DID, so the document's
    /// proof establishes control of the issuing key and no `pop` is needed.
    async fn vrc(issuer: &Party, subject: &Party) -> Value {
        let mut vc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://registry.trustoverip.org/dtg/context/v1"
            ],
            "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "issuer": issuer.did,
            // Issued under the member's own DID, which the community
            // recognises: an attributed edge.
            "issuerScope": "public",
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": { "id": subject.did },
        });
        let proof = DataIntegrityProof::sign(
            &vc,
            &issuer.secret,
            SignOptions::new()
                .with_proof_purpose("assertionMethod")
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .expect("sign the VRC");
        vc["proof"] = serde_json::to_value(&proof).unwrap();
        vc
    }

    #[tokio::test]
    async fn relationships_publish_lodges_a_members_vrc_on_every_transport() {
        let f = fixture().await;
        for t in TRANSPORTS {
            let v = vrc(&f.member, &f.peer).await;
            let out = send(
                &f.vtc,
                t,
                &f.member,
                RELATIONSHIPS_PUBLISH_TYPE,
                json!({ "vrc": v }),
            )
            .await;
            ok(&out, "relationships/publish");
            assert_conforms::<rel_publish::Response>(&out);
            let p = payload_of(&out);
            assert_eq!(p["issuerDid"], json!(f.member.did));
            assert_eq!(p["subjectDid"], json!(f.peer.did));
        }
    }

    /// A VRC someone else issued, published without an authorization proving
    /// control of its key, is the declared `vrcInvalid` — the bearer-less REST
    /// route's own answer, from the same function.
    #[tokio::test]
    async fn relationships_publish_refuses_another_partys_vrc() {
        let f = fixture().await;
        let v = vrc(&f.member, &f.peer).await;
        let out = send(
            &f.vtc,
            JoinTransport::DIDComm,
            &f.peer,
            RELATIONSHIPS_PUBLISH_TYPE,
            json!({ "vrc": v }),
        )
        .await;
        assert_eq!(
            code(&out),
            crate::routes::relationships::PUBLISH_ERR_VRC_INVALID
        );
    }

    // ── relationships/revoke ─────────────────────────────────────────────

    #[tokio::test]
    async fn relationships_revoke_by_the_issuer_on_every_transport() {
        let f = fixture().await;
        for t in TRANSPORTS {
            let id = seed_edge(&f.vtc, &f.member.did, &f.peer.did).await;
            let out = send(
                &f.vtc,
                t,
                &f.member,
                RELATIONSHIPS_REVOKE_TYPE,
                json!({ "id": id.to_string() }),
            )
            .await;
            ok(&out, "relationships/revoke by the issuer");
            assert_conforms::<rel_revoke::Response>(&out);
            assert!(!edge_exists(&f.vtc, id).await);
        }
    }

    #[tokio::test]
    async fn relationships_revoke_by_an_admin_for_moderation() {
        let f = fixture().await;
        let id = seed_edge(&f.vtc, &f.member.did, &f.peer.did).await;
        let out = send(
            &f.vtc,
            JoinTransport::Tsp,
            &f.admin,
            RELATIONSHIPS_REVOKE_TYPE,
            json!({ "id": id.to_string() }),
        )
        .await;
        ok(&out, "relationships/revoke by an admin");
        assert!(!edge_exists(&f.vtc, id).await);
    }

    /// A member who is not the issuer is told `notFound`, as the specification
    /// requires, and a non-member is refused before any lookup. The edge
    /// stands either way.
    #[tokio::test]
    async fn relationships_revoke_refuses_a_party_who_is_not_the_issuer() {
        let f = fixture().await;
        let id = seed_edge(&f.vtc, &f.member.did, &f.peer.did).await;
        let payload = json!({ "id": id.to_string() });
        let out = send(
            &f.vtc,
            JoinTransport::DIDComm,
            &f.peer,
            RELATIONSHIPS_REVOKE_TYPE,
            payload.clone(),
        )
        .await;
        assert_eq!(
            code(&out),
            crate::routes::relationships::REVOKE_ERR_NOT_FOUND
        );
        let out = send(
            &f.vtc,
            JoinTransport::DIDComm,
            &f.stranger,
            RELATIONSHIPS_REVOKE_TYPE,
            payload,
        )
        .await;
        assert_eq!(code(&out), "permissionDenied");
        assert!(edge_exists(&f.vtc, id).await, "the edge stands");
    }

    // ── endorsements/* ───────────────────────────────────────────────────

    async fn issue(f: &Fixture, t: JoinTransport, from: &Party, subject: &str) -> TrustTaskOutcome {
        send(
            &f.vtc,
            t,
            from,
            ENDORSEMENTS_ISSUE_TYPE,
            json!({
                "subjectDid": subject,
                "typeUri": ENDORSEMENT_TYPE,
                "claim": { "level": "expert" },
            }),
        )
        .await
    }

    fn endorsement_id(out: &TrustTaskOutcome) -> String {
        payload_of(out)["endorsement"]["endorsementId"]
            .as_str()
            .unwrap_or_else(|| panic!("no endorsement: {}", String::from_utf8_lossy(&out.body)))
            .to_string()
    }

    #[tokio::test]
    async fn endorsements_issue_by_an_issuer_on_every_transport() {
        let f = fixture().await;
        for t in TRANSPORTS {
            let out = issue(&f, t, &f.issuer, &f.member.did).await;
            ok(&out, "endorsements/issue");
            assert_conforms::<end_issue::Response>(&out);
        }
    }

    #[tokio::test]
    async fn endorsements_issue_refuses_a_member_without_the_issuer_role() {
        let f = fixture().await;
        for from in [&f.member, &f.stranger] {
            let out = issue(&f, JoinTransport::Tsp, from, &f.peer.did).await;
            assert_eq!(code(&out), "permissionDenied");
        }
    }

    #[tokio::test]
    async fn endorsements_list_applies_its_filters_on_every_transport() {
        let f = fixture().await;
        ok(
            &issue(&f, JoinTransport::Rest, &f.issuer, &f.member.did).await,
            "issue",
        );
        ok(
            &issue(&f, JoinTransport::Rest, &f.admin, &f.peer.did).await,
            "issue",
        );
        for t in TRANSPORTS {
            let out = send(
                &f.vtc,
                t,
                &f.issuer,
                ENDORSEMENTS_LIST_TYPE,
                json!({ "subjectDid": f.member.did }),
            )
            .await;
            ok(&out, "endorsements/list");
            assert_conforms::<end_list::Response>(&out);
            let items = payload_of(&out)["items"].as_array().cloned().unwrap();
            assert_eq!(items.len(), 1, "{items:?}");
            assert_eq!(items[0]["subjectDid"], json!(f.member.did));
        }
    }

    #[tokio::test]
    async fn endorsements_list_refuses_a_member_without_the_issuer_role() {
        let f = fixture().await;
        let out = send(
            &f.vtc,
            JoinTransport::DIDComm,
            &f.member,
            ENDORSEMENTS_LIST_TYPE,
            json!({}),
        )
        .await;
        assert_eq!(code(&out), "permissionDenied");
    }

    #[tokio::test]
    async fn endorsements_show_answers_an_admin_or_issuer_on_every_transport() {
        let f = fixture().await;
        let issued = issue(&f, JoinTransport::Rest, &f.issuer, &f.member.did).await;
        let id = endorsement_id(&issued);
        for t in TRANSPORTS {
            for from in [&f.admin, &f.issuer] {
                let out = send(
                    &f.vtc,
                    t,
                    from,
                    ENDORSEMENTS_SHOW_TYPE,
                    json!({ "endorsementId": id }),
                )
                .await;
                ok(&out, "endorsements/show");
                assert_conforms::<end_show::Response>(&out);
            }
        }
        let out = send(
            &f.vtc,
            JoinTransport::Rest,
            &f.issuer,
            ENDORSEMENTS_SHOW_TYPE,
            json!({ "endorsementId": Uuid::new_v4().to_string() }),
        )
        .await;
        assert_eq!(code(&out), crate::routes::endorsements::SHOW_ERR_NOT_FOUND);
    }

    /// The endorsement's own subject is not thereby entitled to the row.
    #[tokio::test]
    async fn endorsements_show_refuses_a_member_without_the_issuer_role() {
        let f = fixture().await;
        let issued = issue(&f, JoinTransport::Rest, &f.issuer, &f.member.did).await;
        let id = endorsement_id(&issued);
        let out = send(
            &f.vtc,
            JoinTransport::Tsp,
            &f.member,
            ENDORSEMENTS_SHOW_TYPE,
            json!({ "endorsementId": id }),
        )
        .await;
        assert_eq!(code(&out), "permissionDenied");
    }

    #[tokio::test]
    async fn endorsements_revoke_by_an_issuer_on_every_transport() {
        let f = fixture().await;
        for t in TRANSPORTS {
            let issued = issue(&f, JoinTransport::Rest, &f.issuer, &f.member.did).await;
            let id = endorsement_id(&issued);
            let out = send(
                &f.vtc,
                t,
                &f.issuer,
                ENDORSEMENTS_REVOKE_TYPE,
                json!({ "endorsementId": id, "reason": "superseded" }),
            )
            .await;
            ok(&out, "endorsements/revoke");
            assert_conforms::<end_revoke::Response>(&out);
            // A second revocation is the declared `alreadyRevoked`, not a
            // second receipt.
            let again = send(
                &f.vtc,
                t,
                &f.issuer,
                ENDORSEMENTS_REVOKE_TYPE,
                json!({ "endorsementId": id }),
            )
            .await;
            assert_eq!(
                code(&again),
                crate::routes::endorsements::REVOKE_ERR_ALREADY_REVOKED
            );
        }
    }

    #[tokio::test]
    async fn endorsements_revoke_refuses_a_member_without_the_issuer_role() {
        let f = fixture().await;
        let issued = issue(&f, JoinTransport::Rest, &f.issuer, &f.member.did).await;
        let id = endorsement_id(&issued);
        let out = send(
            &f.vtc,
            JoinTransport::DIDComm,
            &f.member,
            ENDORSEMENTS_REVOKE_TYPE,
            json!({ "endorsementId": id }),
        )
        .await;
        assert_eq!(code(&out), "permissionDenied");
        let row = crate::endorsements::get_endorsement(
            &f.vtc.state.endorsements_ks,
            Uuid::parse_str(&id).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!row.is_revoked(), "the refused revocation changed nothing");
    }
}
