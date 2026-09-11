//! Naming vetters (`vtc/vetting/vetters/grant/0.1`).
//!
//! OpenVTC vetting design §10. A vetter is a member the community has issued a
//! **vetter role credential**: a DTG `EndorsementCredential` with endorsement
//! `{ type: "CommunityRole", role: "vetter", communityDid }`, a revocation slot
//! on the shared `Revocation` status list, and a bounded validity. The grant is
//! recorded as an [`Endorsement`] row — the record the join path counts
//! statements against — and the credential is delivered to the member, who
//! presents it to applicants (`vta_sdk::vetting::eligibility`).
//!
//! A grant is withdrawn through `vtc/endorsements/revoke/0.1` like any other
//! endorsement, and every grant a member holds is revoked when they depart
//! ([`revoke_on_departure`]).
//!
//! ## Granting converges
//!
//! While a member holds a live, unexpired vetter grant, granting again returns
//! that grant rather than minting a second credential on a second slot. The
//! check and the issuance run under one lock, so two concurrent grants for the
//! same member cannot both pass it.

use std::sync::LazyLock;

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value as JsonValue, json};
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

use vta_sdk::protocols::members::ENDORSEMENT_CREDENTIAL_TYPE;
use vta_sdk::protocols::vetting::{
    COMMUNITY_ROLE_ENDORSEMENT_TYPE, DEFAULT_VETTER_GRANT_VALIDITY_SECONDS, VETTER_ROLE,
    VetterGrantBody, VetterGrantResponseBody, role_matches,
};
use vti_common::audit::{
    AuditEvent, AuditWriter, CredentialIssuedData, CustomEndorsementRevokedData,
    StatusListFlippedData, VetterGrantedData,
};
use vti_common::error::AppError;

use crate::acl::{VtcRole, get_acl_entry};
use crate::credentials::CredentialStatusRef;
use crate::credentials::delivery::deliver_credentials;
use crate::credentials::dtg::{into_typed, issue_endorsement};
use crate::endorsements::{Endorsement, endorsements_for_subject, mark_revoked, store_endorsement};
use crate::members::storage::get_member;
use crate::server::AppState;
use crate::status_list;

/// Serialises the live-grant check with the issuance it guards.
static GRANT_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

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

/// Name `body.member_did` a vetter on behalf of `actor_did`.
///
/// The actor must hold the VTC `Admin` role — read from the ACL row, since a
/// session token degrades custom roles. The subject must be a current member.
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
    let acl = get_acl_entry(&state.acl_ks, actor_did)
        .await?
        .ok_or_else(|| AppError::Forbidden("caller has no ACL row".into()))?;
    if !matches!(acl.role, VtcRole::Admin) {
        return Err(AppError::Forbidden(
            "only a community admin can name a vetter".into(),
        ));
    }
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let signer = state
        .credential_signer
        .as_ref()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;

    let _guard = GRANT_LOCK.lock().await;

    let member_did = body.member_did.as_str();
    let is_current = get_member(&state.members_ks, member_did)
        .await?
        .is_some_and(|m| m.removed_at.is_none());
    if !is_current {
        return Err(AppError::Validation(format!(
            "{member_did} is not a current member of this community"
        )));
    }

    let now = Utc::now();
    let existing = endorsements_for_subject(
        &state.endorsements_ks,
        member_did,
        COMMUNITY_ROLE_ENDORSEMENT_TYPE,
    )
    .await?
    .into_iter()
    .rev()
    .find(|row| grant_covers(row, VETTER_ROLE, now));
    if let Some(row) = existing {
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
    let seconds = body
        .validity_seconds
        .unwrap_or(DEFAULT_VETTER_GRANT_VALIDITY_SECONDS);
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
    };
    store_endorsement(&state.endorsements_ks, &row).await?;

    audit_writer
        .write(
            actor_did,
            Some(member_did),
            AuditEvent::VetterGranted(VetterGrantedData {
                endorsement_id: id.to_string(),
                status_list_index: slot,
            }),
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
        "vetter role granted"
    );

    // Best effort, after the grant is durable: the record is what counts
    // statements, so a member whose wallet missed the credential is still a
    // vetter, and an operator can re-issue it by revoking and granting again.
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

    Ok(VetterGrant {
        response: response_for(&row)?,
        credential: Some(credential),
    })
}

/// Revoke every live community role grant `subject_did` holds: flip each
/// slot, then mark the row. Returns the rows revoked, for the caller to audit.
///
/// Best effort per grant, like the membership credential's flip on departure:
/// the member is already gone, so a grant whose flip fails is logged and left
/// for an operator rather than unwinding the departure. It stops counting
/// statements regardless, because eligibility requires a current member.
pub(crate) async fn revoke_on_departure(state: &AppState, subject_did: &str) -> Vec<Endorsement> {
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
}
