//! Naming vetters (`vtc/vetting/vetters/grant/0.1`) and delivering a grant
//! again (`vtc/vetting/vetters/resend/0.1`).
//!
//! OpenVTC vetting design §10. A vetter is a member the community has issued a
//! **vetter role credential**: a DTG `EndorsementCredential` with endorsement
//! `{ type: "CommunityRole", role: "vetter", communityDid }`, a revocation slot
//! on the shared `Revocation` status list, and a bounded validity. The grant is
//! recorded as an [`Endorsement`] row — the record the join path counts
//! statements against — with the signed credential kept on it, and the
//! credential is delivered to the member, who presents it to applicants
//! (`vta_sdk::vetting::eligibility`).
//!
//! A grant is withdrawn through `vtc/endorsements/revoke/0.1` like any other
//! endorsement, and every grant a member holds is revoked when they depart
//! ([`revoke_on_departure`]). Either way the vetter's profile goes with it
//! ([`super::profiles`]).
//!
//! ## Who grants
//!
//! An admin ([`grant`]), or the automatic-grant sweep when the community's
//! `vetter_eligibility` policy allows it ([`super::auto_grant`]). A row the
//! sweep issued carries `auto_granted`; the sweep revokes only those
//! ([`revoke_auto_grants`]), and an admin granting a member the sweep already
//! named adopts the grant, which the sweep then leaves alone.
//!
//! ## Granting converges
//!
//! While a member holds a live, unexpired vetter grant, granting again returns
//! that grant rather than minting a second credential on a second slot. The
//! check and the issuance run under one lock ([`GRANT_LOCK`]), so two
//! concurrent grants for the same member cannot both pass it.

use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value as JsonValue, json};
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

use vta_sdk::protocols::members::ENDORSEMENT_CREDENTIAL_TYPE;
use vta_sdk::protocols::vetting::{
    COMMUNITY_ROLE_ENDORSEMENT_TYPE, DEFAULT_VETTER_GRANT_VALIDITY_SECONDS, GrantOrigin,
    VETTER_ROLE, VetterGrantBody, VetterGrantResponseBody, VetterGrantRow,
    VetterResendResponseBody, role_matches,
};
use vti_common::audit::{
    AuditEvent, AuditWriter, CredentialIssuedData, CustomEndorsementRevokedData,
    StatusListFlippedData, VetterGrantResentData, VetterGrantedData,
};
use vti_common::error::AppError;

use super::profiles;
use crate::acl::{VtcRole, get_acl_entry};
use crate::credentials::CredentialStatusRef;
use crate::credentials::delivery::deliver_credentials;
use crate::credentials::dtg::{into_typed, issue_endorsement};
use crate::endorsements::{
    Endorsement, endorsements_by_type, endorsements_for_subject, mark_revoked, store_endorsement,
};
use crate::members::Member;
use crate::members::storage::get_member;
use crate::server::AppState;
use crate::status_list;

/// Serialises every check-then-act on a member's vetter standing: granting,
/// revoking on departure or by the sweep, and publishing or deleting a profile.
pub(crate) static GRANT_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// The outcome of a grant.
#[derive(Debug)]
pub struct VetterGrant {
    /// The wire answer.
    pub response: VetterGrantResponseBody,
    /// The credential this call minted, or `None` when an existing live grant
    /// was returned instead.
    pub credential: Option<JsonValue>,
}

impl VetterGrant {
    /// `true` when this call issued a new grant.
    pub fn created(&self) -> bool {
        self.credential.is_some()
    }
}

/// Does `grant` name its subject in `role`, unrevoked, and valid at `at`?
///
/// `at` is when the grant is relied on — for a vetting statement, its
/// `validFrom`: a grant recorded after the statement was signed does not make
/// its issuer retroactively a vetter.
pub fn grant_covers(grant: &Endorsement, role: &str, at: DateTime<Utc>) -> bool {
    grant.endorsement_type == COMMUNITY_ROLE_ENDORSEMENT_TYPE
        && grant.revoked_at.is_none()
        && grant.created_at <= at
        && grant.valid_until.is_none_or(|until| until >= at)
        && grant
            .claim
            .get("role")
            .and_then(JsonValue::as_str)
            .is_some_and(|held| role_matches(held, role))
}

/// Who issued `row`.
pub fn origin_of(row: &Endorsement) -> GrantOrigin {
    if row.auto_granted {
        GrantOrigin::Auto
    } else {
        GrantOrigin::Manual
    }
}

/// A live vetter grant for `member`, now: recorded during this membership and
/// covering `now`.
fn is_live_for(grant: &Endorsement, member: &Member, now: DateTime<Utc>) -> bool {
    grant.created_at >= member.joined_at && grant_covers(grant, VETTER_ROLE, now)
}

/// The live vetter grant `did` holds, if they are a current member holding
/// one — the most recent when there are several.
pub async fn live_grant(
    state: &AppState,
    did: &str,
    now: DateTime<Utc>,
) -> Result<Option<Endorsement>, AppError> {
    let Some(member) = get_member(&state.members_ks, did)
        .await?
        .filter(|m| m.removed_at.is_none())
    else {
        return Ok(None);
    };
    live_grant_of(state, &member, now).await
}

async fn live_grant_of(
    state: &AppState,
    member: &Member,
    now: DateTime<Utc>,
) -> Result<Option<Endorsement>, AppError> {
    Ok(endorsements_for_subject(
        &state.endorsements_ks,
        &member.did,
        COMMUNITY_ROLE_ENDORSEMENT_TYPE,
    )
    .await?
    .into_iter()
    .rev()
    .find(|g| is_live_for(g, member, now)))
}

/// Every live vetter grant, by member DID: one scan of the grants and one
/// member read per grantee, instead of a scan per vetter.
pub async fn live_grants(
    state: &AppState,
    now: DateTime<Utc>,
) -> Result<HashMap<String, Endorsement>, AppError> {
    let mut by_subject: HashMap<String, Vec<Endorsement>> = HashMap::new();
    for row in endorsements_by_type(&state.endorsements_ks, COMMUNITY_ROLE_ENDORSEMENT_TYPE).await?
    {
        by_subject
            .entry(row.subject_did.clone())
            .or_default()
            .push(row);
    }
    let mut live = HashMap::new();
    for (did, grants) in by_subject {
        let Some(member) = get_member(&state.members_ks, &did)
            .await?
            .filter(|m| m.removed_at.is_none())
        else {
            continue;
        };
        if let Some(grant) = grants
            .into_iter()
            .rev()
            .find(|g| is_live_for(g, &member, now))
        {
            live.insert(did, grant);
        }
    }
    Ok(live)
}

/// Every vetter grant, newest first, as `GET /v1/vetting/vetters` reports it.
pub async fn grant_rows(state: &AppState) -> Result<Vec<VetterGrantRow>, AppError> {
    let now = Utc::now();
    let live = live_grants(state, now).await?;
    let profiles: HashMap<String, profiles::StoredProfile> =
        profiles::list_profiles(&state.vetter_profiles_ks)
            .await?
            .into_iter()
            .map(|p| (p.vetter_did.clone(), p))
            .collect();
    let mut rows: Vec<VetterGrantRow> =
        endorsements_by_type(&state.endorsements_ks, COMMUNITY_ROLE_ENDORSEMENT_TYPE)
            .await?
            .into_iter()
            .filter(|row| {
                row.claim
                    .get("role")
                    .and_then(JsonValue::as_str)
                    .is_some_and(|held| role_matches(held, VETTER_ROLE))
            })
            .map(|row| VetterGrantRow {
                endorsement_id: row.id.to_string(),
                live: live.get(&row.subject_did).is_some_and(|g| g.id == row.id),
                origin: origin_of(&row),
                profile: profiles.get(&row.subject_did).map(|p| p.summary()),
                member_did: row.subject_did,
                credential_id: row.vec_id,
                valid_from: row.created_at,
                valid_until: row.valid_until,
                revoked: row.revoked_at.is_some(),
                revoked_at: row.revoked_at,
            })
            .collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.valid_from));
    Ok(rows)
}

/// Refuse anyone but a community `Admin` — read from the ACL row, since a
/// session token degrades custom roles.
async fn require_admin(state: &AppState, actor_did: &str) -> Result<(), AppError> {
    let acl = get_acl_entry(&state.acl_ks, actor_did)
        .await?
        .ok_or_else(|| AppError::Forbidden("caller has no ACL row".into()))?;
    if !matches!(acl.role, VtcRole::Admin) {
        return Err(AppError::Forbidden(
            "only a community admin can manage vetters".into(),
        ));
    }
    Ok(())
}

/// Name `body.member_did` a vetter on behalf of `actor_did`, an admin.
///
/// # Errors
///
/// [`AppError::Validation`] for a malformed body or a subject who is not a
/// current member, [`AppError::Forbidden`] for a non-admin actor, and
/// [`AppError::Internal`] when signing or the status list is unavailable.
pub async fn grant(
    state: &AppState,
    actor_did: &str,
    body: &VetterGrantBody,
) -> Result<VetterGrant, AppError> {
    body.check_shape()
        .map_err(|e| AppError::Validation(e.to_string()))?;
    require_admin(state, actor_did).await?;
    let grant = {
        let _guard = GRANT_LOCK.lock().await;
        grant_locked(
            state,
            actor_did,
            &body.member_did,
            body.validity_seconds,
            GrantOrigin::Manual,
        )
        .await?
    };
    if let Some(credential) = &grant.credential {
        deliver_grant(state, &body.member_did, credential).await;
    }
    Ok(grant)
}

/// Hand a newly issued grant credential to the messaging layer for its member.
///
/// Best effort, after the grant is durable, and never under [`GRANT_LOCK`]: a
/// slow or unreachable mediator must not hold up every other grant, revocation
/// and profile write. The record is what counts statements, so a member whose
/// wallet missed the credential is still a vetter, and can ask for it again
/// (`vtc/vetting/vetters/resend/0.1`).
pub(crate) async fn deliver_grant(state: &AppState, member_did: &str, credential: &JsonValue) {
    match into_typed(credential.clone(), "vetter role VEC") {
        Ok(typed) => {
            if let Err(e) = deliver_credentials(state, member_did, &[&typed]).await {
                warn!(member = %member_did, error = %e, "vetter role credential not delivered");
            }
        }
        Err(e) => {
            warn!(member = %member_did, error = %e, "vetter role credential not deliverable");
        }
    }
}

/// Issue (or return) `member_did`'s vetter grant. The caller holds
/// [`GRANT_LOCK`] and has decided the actor may grant, and delivers a newly
/// issued credential ([`deliver_grant`]) once it has released the lock.
pub(crate) async fn grant_locked(
    state: &AppState,
    actor_did: &str,
    member_did: &str,
    validity_seconds: Option<u64>,
    origin: GrantOrigin,
) -> Result<VetterGrant, AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let signer = state
        .credential_signer
        .as_ref()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;

    let Some(member) = get_member(&state.members_ks, member_did)
        .await?
        .filter(|m| m.removed_at.is_none())
    else {
        return Err(AppError::Validation(format!(
            "{member_did} is not a current member of this community"
        )));
    };

    let now = Utc::now();
    if let Some(mut row) = live_grant_of(state, &member, now).await? {
        // An admin granting a member the sweep named adopts the grant: the
        // sweep revokes only its own, so from here it stays.
        if origin == GrantOrigin::Manual && row.auto_granted {
            row.auto_granted = false;
            store_endorsement(&state.endorsements_ks, &row).await?;
            info!(
                endorsement_id = %row.id,
                member = %member_did,
                "an admin adopted an automatic vetter grant"
            );
        }
        return Ok(VetterGrant {
            response: response_for(&row)?,
            credential: None,
        });
    }

    let (slot, list_credential_id) = status_list::with_locked(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        |row| {
            let slot = status_list::allocate(row).ok_or_else(|| {
                AppError::Internal(
                    "revocation status list is full — cannot allocate a slot for a vetter grant"
                        .into(),
                )
            })?;
            Ok((slot, row.list_credential_id.clone()))
        },
    )
    .await?;
    let status_ref = CredentialStatusRef::revocation(list_credential_id, slot);

    let id = Uuid::new_v4();
    let vec_id = format!("urn:uuid:{id}");
    let seconds = validity_seconds.unwrap_or(DEFAULT_VETTER_GRANT_VALIDITY_SECONDS);
    let validity = Duration::seconds(
        i64::try_from(seconds)
            .map_err(|_| AppError::Validation("validitySeconds is out of range".into()))?,
    );
    let credential = issue_endorsement(
        signer,
        member_did,
        json!({
            "type": COMMUNITY_ROLE_ENDORSEMENT_TYPE,
            "role": VETTER_ROLE,
            "communityDid": signer.issuer_did(),
        }),
        Some(&vec_id),
        Some(&status_ref),
        validity,
    )
    .await?;
    // The row carries the credential's own window, so what the community
    // counts against and what the member presents cannot disagree.
    let valid_from = timestamp(&credential, "validFrom")?;
    let valid_until = timestamp(&credential, "validUntil")?;

    let row = Endorsement {
        id,
        endorsement_type: COMMUNITY_ROLE_ENDORSEMENT_TYPE.into(),
        issuer_did: signer.issuer_did().to_string(),
        subject_did: member_did.to_string(),
        claim: json!({ "role": VETTER_ROLE }),
        status_list_index: slot,
        vec_id: vec_id.clone(),
        created_at: valid_from,
        revoked_at: None,
        valid_until: Some(valid_until),
        auto_granted: origin == GrantOrigin::Auto,
        credential: Some(credential.clone()),
    };
    store_endorsement(&state.endorsements_ks, &row).await?;

    let granted = VetterGrantedData {
        endorsement_id: id.to_string(),
        status_list_index: slot,
    };
    audit_writer
        .write(
            actor_did,
            Some(member_did),
            match origin {
                GrantOrigin::Manual => AuditEvent::VetterGranted(granted),
                GrantOrigin::Auto => AuditEvent::VetterAutoGranted(granted),
            },
        )
        .await?;
    audit_writer
        .write(
            actor_did,
            Some(member_did),
            AuditEvent::VecIssued(CredentialIssuedData {
                credential_id: vec_id.clone(),
                credential_type: ENDORSEMENT_CREDENTIAL_TYPE.into(),
                valid_from: rfc3339(valid_from),
                valid_until: rfc3339(valid_until),
                status_list_index: Some(slot),
            }),
        )
        .await?;
    info!(
        endorsement_id = %id,
        member = %member_did,
        slot,
        origin = ?origin,
        "vetter role granted"
    );

    Ok(VetterGrant {
        response: response_for(&row)?,
        credential: Some(credential),
    })
}

/// Deliver `member_did`'s live vetter grant credential again, on behalf of
/// `actor_did` — the member themselves over `vtc/vetting/vetters/resend/0.1`,
/// or an admin.
///
/// "Delivered" means the credential was handed to the messaging layer for the
/// member, as on the grant path; it is not an acknowledgement from their wallet.
///
/// # Errors
///
/// [`AppError::NotFound`] when the member holds no live grant, or holds one
/// recorded before grant credentials were kept — the Trust Task dispatcher
/// answers either with `vtc/vetting/vetters/resend:notGranted`. A 503
/// [`AppError::ServiceError`] when the delivery could not be handed to the
/// transport — answered with the framework's `unavailable`.
pub async fn resend(
    state: &AppState,
    actor_did: &str,
    member_did: &str,
) -> Result<VetterResendResponseBody, AppError> {
    let row = live_grant(state, member_did, Utc::now())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("{member_did} holds no live vetter grant")))?;
    let credential = row.credential.clone().ok_or_else(|| {
        AppError::NotFound(format!(
            "{member_did}'s vetter grant was recorded before grant credentials were kept; \
             revoke it and grant again to re-issue the credential"
        ))
    })?;
    let valid_until = row
        .valid_until
        .ok_or_else(|| AppError::Internal("vetter grant row has no validUntil".into()))?;
    let typed = into_typed(credential, "vetter role VEC")?;
    if let Err(e) = deliver_credentials(state, member_did, &[&typed]).await {
        warn!(member = %member_did, error = %e, "vetter grant credential could not be delivered again");
        return Err(AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "the credential could not be handed to the transport for delivery".into(),
        });
    }

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor_did,
                Some(member_did),
                AuditEvent::VetterGrantResent(VetterGrantResentData {
                    endorsement_id: row.id.to_string(),
                    credential_id: row.vec_id.clone(),
                }),
            )
            .await?;
    }
    info!(member = %member_did, endorsement_id = %row.id, "vetter grant credential delivered again");
    Ok(VetterResendResponseBody {
        credential_id: row.vec_id,
        valid_until,
    })
}

/// [`resend`] for `POST /v1/vetting/vetters/{memberDid}/resend`: admins only.
pub async fn resend_as_admin(
    state: &AppState,
    actor_did: &str,
    member_did: &str,
) -> Result<VetterResendResponseBody, AppError> {
    require_admin(state, actor_did).await?;
    resend(state, actor_did, member_did).await
}

/// Revoke the live grants the sweep issued `member_did`, and their profile when
/// no live grant is left. Returns how many grants were revoked.
pub(crate) async fn revoke_auto_grants(
    state: &AppState,
    actor_did: &str,
    member_did: &str,
) -> Result<u32, AppError> {
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let _guard = GRANT_LOCK.lock().await;
    let now = Utc::now();
    let own: Vec<Endorsement> = endorsements_for_subject(
        &state.endorsements_ks,
        member_did,
        COMMUNITY_ROLE_ENDORSEMENT_TYPE,
    )
    .await?
    .into_iter()
    .filter(|g| g.auto_granted && grant_covers(g, VETTER_ROLE, now))
    .collect();
    let mut revoked = 0u32;
    for grant in own {
        let slot = grant.status_list_index;
        status_list::with_locked(
            &state.status_lists_ks,
            affinidi_status_list::StatusPurpose::Revocation,
            move |sl| {
                status_list::flip(sl, slot, true)
                    .map_err(|e| AppError::Internal(format!("flip status-list bit {slot}: {e}")))
            },
        )
        .await?;
        if let Some(row) = mark_revoked(&state.endorsements_ks, grant.id).await? {
            audit_revoked_grant(writer, actor_did, member_did, &row).await?;
            revoked += 1;
            info!(endorsement_id = %row.id, member = %member_did, "automatic vetter grant revoked");
        }
    }
    if revoked > 0 {
        profiles::delete_unless_granted_locked(
            state,
            actor_did,
            member_did,
            profiles::DELETED_GRANT_REVOKED,
        )
        .await?;
    }
    Ok(revoked)
}

/// Revoke every live community role grant `subject_did` holds: flip each
/// slot, then mark the row. Deletes their vetter profile. Returns the rows
/// revoked, for the caller to audit.
///
/// Best effort per grant, like the membership credential's flip on departure:
/// the member is already gone, so a grant whose flip fails is logged and left
/// for an operator rather than unwinding the departure. It stops counting
/// statements regardless, because eligibility requires a current member.
pub(crate) async fn revoke_on_departure(
    state: &AppState,
    actor_did: &str,
    subject_did: &str,
) -> Vec<Endorsement> {
    // Under the grant lock: a grant that passed its member check just before
    // the departure has stored its row by now, and one that has not yet run
    // will find no current member.
    let _guard = GRANT_LOCK.lock().await;
    let grants = match endorsements_for_subject(
        &state.endorsements_ks,
        subject_did,
        COMMUNITY_ROLE_ENDORSEMENT_TYPE,
    )
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!(subject = %subject_did, error = %e, "could not read role grants on departure");
            return Vec::new();
        }
    };
    let mut revoked = Vec::new();
    for grant in grants.into_iter().filter(|g| !g.is_revoked()) {
        let slot = grant.status_list_index;
        let flipped = status_list::with_locked(
            &state.status_lists_ks,
            affinidi_status_list::StatusPurpose::Revocation,
            move |sl| {
                status_list::flip(sl, slot, true)
                    .map_err(|e| AppError::Internal(format!("flip status-list bit {slot}: {e}")))
            },
        )
        .await;
        if let Err(e) = flipped {
            warn!(
                subject = %subject_did,
                endorsement_id = %grant.id,
                slot,
                error = %e,
                "could not revoke a role grant on departure — operator must revoke it"
            );
            continue;
        }
        match mark_revoked(&state.endorsements_ks, grant.id).await {
            Ok(Some(row)) => revoked.push(row),
            Ok(None) => {}
            Err(e) => warn!(
                subject = %subject_did,
                endorsement_id = %grant.id,
                error = %e,
                "role grant's bit flipped but its row was not marked revoked"
            ),
        }
    }
    // A departed member is listed nowhere, so their profile has nothing left
    // to say — and would say it again were the DID readmitted.
    if let Err(e) = profiles::delete_unless_granted_locked(
        state,
        actor_did,
        subject_did,
        profiles::DELETED_DEPARTED,
    )
    .await
    {
        warn!(subject = %subject_did, error = %e, "could not delete a departed vetter's profile");
    }
    revoked
}

/// The two envelopes a revoked grant is accounted with, as for any revoked
/// endorsement: `CustomEndorsementRevoked` + `StatusListFlipped`.
pub(crate) async fn audit_revoked_grant(
    writer: &AuditWriter,
    actor_did: &str,
    subject_did: &str,
    grant: &Endorsement,
) -> Result<(), AppError> {
    writer
        .write(
            actor_did,
            Some(subject_did),
            AuditEvent::CustomEndorsementRevoked(CustomEndorsementRevokedData {
                endorsement_id: grant.id.to_string(),
                endorsement_type: grant.endorsement_type.clone(),
            }),
        )
        .await?;
    writer
        .write(
            actor_did,
            Some(subject_did),
            AuditEvent::StatusListFlipped(StatusListFlippedData {
                purpose: affinidi_status_list::StatusPurpose::Revocation.to_string(),
                index: grant.status_list_index,
                revoked: true,
            }),
        )
        .await?;
    Ok(())
}

fn response_for(row: &Endorsement) -> Result<VetterGrantResponseBody, AppError> {
    Ok(VetterGrantResponseBody {
        endorsement_id: row.id.to_string(),
        credential_id: row.vec_id.clone(),
        valid_from: row.created_at,
        valid_until: row
            .valid_until
            .ok_or_else(|| AppError::Internal("vetter grant row has no validUntil".into()))?,
        ext: None,
    })
}

fn timestamp(credential: &JsonValue, member: &str) -> Result<DateTime<Utc>, AppError> {
    credential
        .get(member)
        .and_then(JsonValue::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
        .ok_or_else(|| AppError::Internal(format!("issued vetter grant has no {member}")))
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant_row(role: &str, created: DateTime<Utc>, until: Option<DateTime<Utc>>) -> Endorsement {
        let id = Uuid::new_v4();
        Endorsement {
            id,
            endorsement_type: COMMUNITY_ROLE_ENDORSEMENT_TYPE.into(),
            issuer_did: "did:webvh:vtc".into(),
            subject_did: "did:key:zCarol".into(),
            claim: json!({ "role": role }),
            status_list_index: 1,
            vec_id: format!("urn:uuid:{id}"),
            created_at: created,
            revoked_at: None,
            valid_until: until,
            auto_granted: false,
            credential: None,
        }
    }

    #[test]
    fn a_grant_covers_a_statement_signed_while_it_stood() {
        let now = Utc::now();
        let g = grant_row(
            "vetter",
            now - Duration::days(10),
            Some(now + Duration::days(10)),
        );
        assert!(grant_covers(&g, "vetter", now));
        assert!(grant_covers(&g, "custom:vetter", now));
        assert!(!grant_covers(&g, "moderator", now));
    }

    #[test]
    fn a_grant_does_not_reach_back_before_it_was_recorded() {
        let now = Utc::now();
        let g = grant_row("vetter", now, Some(now + Duration::days(10)));
        assert!(!grant_covers(&g, "vetter", now - Duration::minutes(1)));
    }

    #[test]
    fn an_expired_or_revoked_grant_covers_nothing() {
        let now = Utc::now();
        let g = grant_row(
            "vetter",
            now - Duration::days(10),
            Some(now - Duration::days(1)),
        );
        assert!(!grant_covers(&g, "vetter", now));
        assert!(grant_covers(&g, "vetter", now - Duration::days(2)));

        let mut g = grant_row("vetter", now - Duration::days(10), None);
        assert!(grant_covers(&g, "vetter", now));
        g.revoked_at = Some(now);
        assert!(
            !grant_covers(&g, "vetter", now - Duration::days(5)),
            "revocation withdraws a grant for statements signed before it too"
        );
    }

    #[test]
    fn only_community_role_rows_are_grants() {
        let now = Utc::now();
        let mut g = grant_row("vetter", now - Duration::days(1), None);
        g.endorsement_type = "https://example.com/v1/skills/rust".into();
        assert!(!grant_covers(&g, "vetter", now));
    }

    #[test]
    fn a_grant_from_before_this_membership_is_not_live() {
        let now = Utc::now();
        let mut member = Member::fresh("did:key:zCarol");
        member.joined_at = now - Duration::days(5);
        let old = grant_row("vetter", now - Duration::days(30), None);
        assert!(!is_live_for(&old, &member, now));
        let current = grant_row("vetter", now - Duration::days(1), None);
        assert!(is_live_for(&current, &member, now));
    }

    #[test]
    fn the_origin_follows_the_row() {
        let now = Utc::now();
        let mut g = grant_row("vetter", now, None);
        assert_eq!(origin_of(&g), GrantOrigin::Manual);
        g.auto_granted = true;
        assert_eq!(origin_of(&g), GrantOrigin::Auto);
        let wire = serde_json::to_value(&g).unwrap();
        assert_eq!(wire["autoGranted"], true);
        g.auto_granted = false;
        let wire = serde_json::to_value(&g).unwrap();
        assert!(wire.get("autoGranted").is_none());
        assert!(wire.get("credential").is_none());
    }
}
