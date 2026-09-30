//! `POST /v1/invitations` — issue an **Invitation Credential** (VIC) to a
//! prospective member (the operator side of the VIC auto-join ceremony).
//!
//! The community admin enters an invitee DID; the VTC mints a short-lived,
//! revocable VIC bound to that DID and signed by the community key, and returns
//! the signed credential for **out-of-band delivery** (copy / QR) to the
//! invitee. The invitee later presents it inside a join VP and is auto-admitted
//! (`credentials::invitation_verify` + the default `join.rego`).
//!
//! Auth: Admin / Moderator / Issuer — the roles that grow + vouch for
//! membership. The issuance itself (slot allocation, signing, schema check)
//! lives in [`crate::credentials::invitation`]; this is the thin authenticated
//! REST surface over it.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::info;

use vti_common::audit::{
    AuditEvent, InvitationDeliveredData, InvitationIssuedData, InvitationRevokedData,
};
use vti_common::error::AppError;

use crate::acl::{VtcRole, get_acl_entry};
use crate::credentials::invitation::{DEFAULT_INVITATION_VALIDITY, issue_invitation};
use crate::credentials::invitation_registry::{
    InvitationRecord, get_invitation, list_invitations, store_invitation,
};
use crate::server::AppState;
use crate::status_list;

/// Upper bound on a caller-requested validity — an invite is a short-lived
/// onboarding artifact, not a standing credential.
const MAX_VALIDITY_DAYS: i64 = 90;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssueInvitationBody {
    /// The DID to invite (a prospective, non-member holder).
    pub subject_did: String,
    /// Optional validity in days (1..=90); defaults to the 7-day VIC default.
    #[serde(default)]
    pub validity_days: Option<u32>,
    /// Optional role to grant the invitee on join (e.g. `member`, `moderator`,
    /// `issuer`). Carried in the VIC's `credentialSubject.scopes` as
    /// `role:<name>` and honored by the join policy. `admin` is refused — the
    /// no-admin-via-join privilege ceiling would deny it anyway. Defaults to
    /// `member` (absent scope).
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssueInvitationResponse {
    /// Echo of the invited DID.
    pub subject_did: String,
    /// The VIC's `validUntil` (RFC3339), for the operator UI to display.
    pub valid_until: Option<String>,
    /// The signed Invitation Credential — handed to the invitee out-of-band
    /// (copy / QR). The invitee presents it back in a join request.
    pub vic: JsonValue,
}

/// `vtc/invitations/issue/0.1`, by `actor`. A signed document served by the
/// spine (`trust_tasks::community_tasks`).
pub(crate) async fn issue(
    state: &AppState,
    actor: &str,
    body: IssueInvitationBody,
) -> Result<IssueInvitationResponse, AppError> {
    let signer = state
        .credential_signer
        .as_ref()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;

    // Auth: Admin / Moderator / Issuer can invite (read the ACL row — the JWT
    // degrades non-Admin VTC roles to Reader, so it can't distinguish them).
    let acl = get_acl_entry(&state.acl_ks, actor)
        .await?
        .ok_or_else(|| AppError::Forbidden("caller has no ACL row".into()))?;
    if !matches!(
        acl.role,
        VtcRole::Admin | VtcRole::Moderator | VtcRole::Issuer
    ) {
        return Err(AppError::Forbidden(
            "only Admin, Moderator, or Issuer members can issue invitations".into(),
        ));
    }

    // An invite is for a *prospective* member.
    if !body.subject_did.starts_with("did:") {
        return Err(AppError::Validation("subjectDid must be a DID".into()));
    }
    // "Already a member" means a *current* (ACL-present) member — not a departed
    // one whose tombstone Member row lingers after a Tombstone/Historical
    // removal. A departed member can be re-invited (re-join overwrites the
    // tombstone with a fresh membership), so gate on the ACL, not the Member row.
    if get_acl_entry(&state.acl_ks, &body.subject_did)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "{} is already a current member — no invitation needed",
            body.subject_did
        )));
    }

    let validity = match body.validity_days {
        Some(d) if d == 0 || (d as i64) > MAX_VALIDITY_DAYS => {
            return Err(AppError::Validation(format!(
                "validityDays must be between 1 and {MAX_VALIDITY_DAYS}"
            )));
        }
        Some(d) => Duration::days(d as i64),
        None => DEFAULT_INVITATION_VALIDITY,
    };

    // A role grant on the invite must parse to a known role and may never be
    // `admin` — a join can't grant admin (host privilege ceiling), so we refuse
    // it at issuance rather than mint an invite that would be denied on redeem.
    if let Some(role) = body.role.as_deref() {
        let parsed = role
            .parse::<VtcRole>()
            .map_err(|_| AppError::Validation(format!("unknown role `{role}`")))?;
        if matches!(parsed, VtcRole::Admin) {
            return Err(AppError::Validation(
                "an invitation may not grant `admin` (no admin via join)".into(),
            ));
        }
        // Conferring a role is an administrator's authority. A `Moderator` or
        // `Issuer` invites members; it cannot mint an invitation that seats
        // someone as a moderator or issuer, or as any custom role.
        if !matches!(parsed, VtcRole::Member) && !matches!(acl.role, VtcRole::Admin) {
            return Err(AppError::Forbidden(format!(
                "only an administrator can invite with the role `{role}`"
            )));
        }
    }

    let vic = issue_invitation(
        signer,
        &state.status_lists_ks,
        &state.schemas_ks,
        &body.subject_did,
        validity,
        body.role.as_deref(),
    )
    .await?;
    let valid_until = vic
        .get("validUntil")
        .and_then(JsonValue::as_str)
        .map(str::to_string);

    // Record the issued VIC so it can be listed + revoked. The id + revocation
    // slot are read back from the freshly-signed credential.
    let id = vic
        .get("id")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| AppError::Internal("issued VIC has no `id`".into()))?
        .to_string();
    let slot = vic
        .pointer("/credentialStatus/statusListIndex")
        .and_then(JsonValue::as_str)
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| AppError::Internal("issued VIC has no usable statusListIndex".into()))?;
    store_invitation(
        &state.invitations_ks,
        &InvitationRecord {
            id: id.clone(),
            subject_did: body.subject_did.clone(),
            slot,
            role: body.role.clone(),
            issued_by: actor.to_string(),
            issued_at: Utc::now(),
            valid_until: valid_until.clone(),
            revoked_at: None,
            // Kept for `deliver`, which offers it to the invitee later.
            credential: Some(vic.clone()),
            offer_code: None,
        },
    )
    .await?;

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor,
                Some(&body.subject_did),
                AuditEvent::InvitationIssued(InvitationIssuedData {
                    invitation_id: id.clone(),
                    subject_did: body.subject_did.clone(),
                    role: body.role.clone(),
                    valid_until: valid_until.clone().unwrap_or_default(),
                    status_list_index: Some(slot),
                }),
            )
            .await?;
    }

    info!(
        actor = %actor,
        subject = %body.subject_did,
        vic_id = %id,
        "issued an invitation credential (VIC)"
    );

    Ok(IssueInvitationResponse {
        subject_did: body.subject_did,
        valid_until,
        vic,
    })
}

// ── List + revoke ─────────────────────────────────────────────────────────

/// One row of the invitation list (the registry record, body-free).
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InvitationListItem {
    pub id: String,
    pub subject_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub issued_by: String,
    pub issued_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

impl From<InvitationRecord> for InvitationListItem {
    fn from(r: InvitationRecord) -> Self {
        // One timestamp form per row: `validUntil` is echoed from the signed
        // credential (`…Z`, whole seconds), so the record's own instants are
        // written the same way rather than chrono's default `+00:00` with
        // microseconds (OBS-04).
        let instant =
            |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        Self {
            id: r.id,
            subject_did: r.subject_did,
            role: r.role,
            issued_by: r.issued_by,
            issued_at: instant(r.issued_at),
            valid_until: r.valid_until,
            revoked_at: r.revoked_at.map(instant),
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InvitationListResponse {
    pub invitations: Vec<InvitationListItem>,
}

/// What an inviter may manage: every invitation (an `Admin`), or only the
/// ones it issued itself (a `Moderator` or `Issuer`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InviterScope {
    All,
    OwnOnly,
}

impl InviterScope {
    fn covers(self, record: &InvitationRecord, actor: &str) -> bool {
        self == Self::All || record.issued_by == actor
    }
}

/// Auth gate shared by the invitation ops: Admin / Moderator / Issuer, and
/// how far the caller's authority over issued invitations reaches.
///
/// A `Moderator` or `Issuer` grows the community by inviting; it does not
/// manage the invitations other inviters (an administrator included) issued.
/// Their invitees, revocations and offers are not its to see or act on, so
/// an invitation outside its scope answers exactly as one that does not
/// exist.
async fn require_inviter(state: &AppState, did: &str) -> Result<InviterScope, AppError> {
    let acl = get_acl_entry(&state.acl_ks, did)
        .await?
        .ok_or_else(|| AppError::Forbidden("caller has no ACL row".into()))?;
    match acl.role {
        VtcRole::Admin => Ok(InviterScope::All),
        VtcRole::Moderator | VtcRole::Issuer => Ok(InviterScope::OwnOnly),
        _ => Err(AppError::Forbidden(
            "only Admin, Moderator, or Issuer members can manage invitations".into(),
        )),
    }
}

pub(crate) async fn list(
    state: &AppState,
    actor: &str,
) -> Result<InvitationListResponse, AppError> {
    let scope = require_inviter(state, actor).await?;
    let invitations = list_invitations(&state.invitations_ks)
        .await?
        .into_iter()
        .filter(|r| scope.covers(r, actor))
        .map(InvitationListItem::from)
        .collect();
    Ok(InvitationListResponse { invitations })
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[schema(as = InvitationRevokeResponse)]
#[serde(rename_all = "camelCase")]
pub struct RevokeResponse {
    pub id: String,
    pub revoked_at: String,
    /// True if this call performed the revocation; false if it was already
    /// revoked (idempotent).
    pub newly_revoked: bool,
}

pub(crate) async fn revoke(
    state: &AppState,
    actor: &str,
    id: String,
) -> Result<RevokeResponse, AppError> {
    let scope = require_inviter(state, actor).await?;

    let mut record = get_invitation(&state.invitations_ks, &id)
        .await?
        .filter(|r| scope.covers(r, actor))
        .ok_or_else(|| AppError::NotFound(format!("no invitation with id {id}")))?;

    // Idempotent: an already-revoked invite reports its prior revocation.
    if let Some(revoked_at) = record.revoked_at {
        return Ok(RevokeResponse {
            id,
            revoked_at: revoked_at.to_rfc3339(),
            newly_revoked: false,
        });
    }

    // Flip the revocation status-list bit at the VIC's slot — locked RMW so a
    // concurrent allocate/flip can't clobber it (P0.1).
    let slot = record.slot;
    status_list::with_locked(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        |sl| {
            status_list::flip(sl, slot, true)
                .map_err(|e| AppError::Internal(format!("flip revocation bit {slot}: {e}")))
        },
    )
    .await?;

    let now = Utc::now();
    record.revoked_at = Some(now);
    store_invitation(&state.invitations_ks, &record).await?;

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor,
                Some(&record.subject_did),
                AuditEvent::InvitationRevoked(InvitationRevokedData {
                    invitation_id: id.clone(),
                    subject_did: Some(record.subject_did.clone()),
                    newly_revoked: true,
                }),
            )
            .await?;
    }

    info!(actor = %actor, vic_id = %id, slot, "revoked an invitation credential (VIC)");

    Ok(RevokeResponse {
        id,
        revoked_at: now.to_rfc3339(),
        newly_revoked: true,
    })
}

use trust_tasks_rs::specs::vtc::invitations::deliver::v0_1::error_codes as deliver_codes;

/// `vtc/invitations/deliver:notFound`, read from the generated bindings.
pub const INVITATION_DELIVER_ERR_NOT_FOUND: &str = deliver_codes::NOT_FOUND.code;
/// `vtc/invitations/deliver:revoked`, read from the generated bindings.
pub const INVITATION_DELIVER_ERR_REVOKED: &str = deliver_codes::REVOKED.code;
/// `vtc/invitations/deliver:noRoute`, read from the generated bindings.
pub const INVITATION_DELIVER_ERR_NO_ROUTE: &str = deliver_codes::NO_ROUTE.code;

/// A `deliver` refusal. The three the specification declares carry their code
/// beside the usual `error` member; anything else renders as every other VTC
/// error does. `expired` is the framework's standard code, reported as a 410.
pub enum DeliverError {
    NotFound(String),
    Revoked(String),
    NoRoute(String),
    Other(AppError),
}

impl From<AppError> for DeliverError {
    fn from(e: AppError) -> Self {
        Self::Other(e)
    }
}

impl From<DeliverError> for crate::error::TaskError {
    fn from(e: DeliverError) -> Self {
        use crate::error::TaskError;
        match e {
            DeliverError::NotFound(m) => {
                TaskError::declared(INVITATION_DELIVER_ERR_NOT_FOUND, AppError::NotFound(m))
            }
            DeliverError::Revoked(m) => {
                TaskError::declared(INVITATION_DELIVER_ERR_REVOKED, AppError::Conflict(m))
            }
            DeliverError::NoRoute(m) => {
                TaskError::declared(INVITATION_DELIVER_ERR_NO_ROUTE, AppError::Validation(m))
            }
            // A lapsed invitation is the framework's standard `expired`.
            DeliverError::Other(AppError::Gone(m)) => {
                TaskError::declared("expired", AppError::Gone(m))
            }
            DeliverError::Other(e) => TaskError::App(e),
        }
    }
}

/// The delivery channels this build implements.
#[derive(Clone, Copy)]
enum Channel {
    Message,
    Offer,
}

/// How long a delivery offer lives, at most: long enough for an invitee to
/// act on a pushed offer or a printed QR code, and never longer than the
/// invitation itself.
const DELIVERY_OFFER_TTL: Duration = Duration::days(7);

/// The OID4VCI credential configuration an invitation is offered under.
const VIC_CONFIGURATION: &str = "VIC";

/// Deliver an issued invitation to the DID it admits
/// (`vtc/invitations/deliver/0.1`, Keyring VTI-21 / VTI-32).
///
/// Records a single-use offer bound to the invited DID — withdrawing any
/// earlier one — and either pushes it to that DID as a
/// `credential-exchange/offer` (`message`) or returns it for a QR code
/// (`offer`). The invitation credential is released only by
/// `credential-exchange/request` with a key-binding proof by the invited
/// DID's key, so the offer itself admits no one else; it is never in this
/// response.
pub(crate) async fn deliver(
    state: &AppState,
    actor: &str,
    body: trust_tasks_rs::specs::vtc::invitations::deliver::v0_1::Payload,
) -> Result<trust_tasks_rs::specs::vtc::invitations::deliver::v0_1::Response, DeliverError> {
    use trust_tasks_rs::specs::vtc::invitations::deliver::v0_1 as spec;

    let scope = require_inviter(state, actor).await?;
    let payload = body;
    let id = payload.id.to_string();
    // The generated channel is `#[non_exhaustive]`: a channel a later
    // specification adds is refused here, not guessed at.
    let channel = match payload.channel {
        spec::PayloadChannel::Message => Channel::Message,
        spec::PayloadChannel::Offer => Channel::Offer,
        other => {
            return Err(AppError::Validation(format!(
                "this community does not deliver over channel {other:?}"
            ))
            .into());
        }
    };

    let mut record = get_invitation(&state.invitations_ks, &id)
        .await?
        .filter(|r| scope.covers(r, actor))
        .ok_or_else(|| DeliverError::NotFound(format!("no invitation with id {id}")))?;
    if record.is_revoked() {
        return Err(DeliverError::Revoked(format!(
            "invitation {id} has been revoked"
        )));
    }
    let now = Utc::now();
    let lapses = record
        .valid_until
        .as_deref()
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        .map(|t| t.with_timezone(&Utc));
    if lapses.is_some_and(|t| t <= now) {
        return Err(AppError::Gone(format!("expired: invitation {id} has lapsed")).into());
    }
    let credential = record.credential.clone().ok_or_else(|| {
        DeliverError::Other(AppError::Conflict(format!(
            "invitation {id} was issued before delivery existed, and its credential was \
             returned once and not kept. Issue a new invitation to {} and deliver that.",
            record.subject_did
        )))
    })?;
    let vtc_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;

    // `message` needs a route to the invitee before anything is recorded, so a
    // refusal leaves the live offer (if any) as it was.
    if matches!(channel, Channel::Message)
        && !can_authcrypt_to(state.did_resolver.as_ref(), &record.subject_did).await
    {
        return Err(DeliverError::NoRoute(format!(
            "{} does not resolve to a key this community can encrypt the offer to. \
             Deliver with channel `offer` and hand it over as a QR code.",
            record.subject_did
        )));
    }

    let ttl = match lapses {
        Some(t) => (t - now).min(DELIVERY_OFFER_TTL),
        None => DELIVERY_OFFER_TTL,
    };
    // At most one live offer per invitation: withdraw the last one first.
    if let Some(old) = record.offer_code.take() {
        crate::credentials::exchange::withdraw_offer(&state.join_requests_ks, &old).await?;
    }
    let (offer, code) = crate::credentials::exchange::make_offer(
        &state.join_requests_ks,
        &vtc_did,
        vec![VIC_CONFIGURATION.to_string()],
        credential,
        &record.subject_did,
        ttl,
        now,
    )
    .await?;
    record.offer_code = Some(code);
    store_invitation(&state.invitations_ks, &record).await?;
    let expires_at = now + ttl;

    let offer_json = serde_json::to_value(&offer)
        .map_err(|e| AppError::Internal(format!("serialise offer: {e}")))?;
    let returned_offer = match channel {
        Channel::Message => {
            // A signed `credential-exchange/offer`, over whichever transport
            // the invitee speaks. Its `request` answer threads on this id.
            if let Err(e) = crate::credentials::delivery::push_document(
                state,
                &record.subject_did,
                vta_sdk::protocols::credential_exchange::OFFER,
                serde_json::json!({ "credential_offer": offer_json }),
                crate::credentials::delivery::Thread::New,
            )
            .await
            {
                // Nothing went out, so no offer should be live for it.
                if let Some(code) = record.offer_code.take() {
                    crate::credentials::exchange::withdraw_offer(&state.join_requests_ks, &code)
                        .await?;
                    store_invitation(&state.invitations_ks, &record).await?;
                }
                return Err(e.into());
            }
            None
        }
        Channel::Offer => match offer_json {
            JsonValue::Object(map) => Some(map),
            _ => {
                return Err(
                    AppError::Internal("offer did not serialise to an object".into()).into(),
                );
            }
        },
    };

    let channel_name = match channel {
        Channel::Message => "message",
        Channel::Offer => "offer",
    };
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor,
                Some(&record.subject_did),
                AuditEvent::InvitationDelivered(InvitationDeliveredData {
                    invitation_id: id.clone(),
                    subject_did: record.subject_did.clone(),
                    channel: channel_name.to_string(),
                    expires_at: expires_at.to_rfc3339(),
                }),
            )
            .await?;
    }
    info!(actor = %actor, vic_id = %id, channel = channel_name, "delivered an invitation");

    let response: spec::Response = spec::Response::builder()
        .id(id)
        .channel(match channel {
            Channel::Message => spec::ResponseChannel::Message,
            Channel::Offer => spec::ResponseChannel::Offer,
        })
        // An absent offer is an empty map: the generated type omits it then.
        .offer(returned_offer.unwrap_or_default())
        .expires_at(expires_at)
        .try_into()
        .map_err(|e| AppError::Internal(format!("build deliver response: {e}")))?;
    Ok(response)
}

/// Whether an offer can be sent to `did` over DIDComm: it resolves, and names
/// a key-agreement key to encrypt to. An advertised service is not required —
/// a DID with none (a `did:peer:2` holding only keys) is reached through the
/// community's mediator, as members already are for credential delivery.
async fn can_authcrypt_to(
    resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    did: &str,
) -> bool {
    let Some(resolver) = resolver else {
        return false;
    };
    let Ok(resolved) = resolver.resolve(did).await else {
        return false;
    };
    serde_json::to_value(&resolved.doc)
        .ok()
        .and_then(|doc| {
            doc.get("keyAgreement")
                .and_then(JsonValue::as_array)
                .map(|a| !a.is_empty())
        })
        .unwrap_or(false)
}
