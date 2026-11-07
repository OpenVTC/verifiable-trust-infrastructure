//! The badge credential (VTI-BDG-060 – 063): what a badge group issues each holder in
//! place of a group membership credential.
//!
//! An **Open Badges 3.0** `OpenBadgeCredential` — a profile of the W3C Verifiable
//! Credentials Data Model v2.0 — whose `issuer` is the badge group's DID, whose subject is
//! the holder's membership DID, whose `achievement` is the badge (name, description,
//! criteria, picture) with the community as its `creator`, and with one `evidence` entry
//! per accepted award. The community has its VTA sign it **as the group**, through
//! `keys/sign-document`, exactly as a group membership credential (VTI-DIR-080), and
//! offers it on the credential-exchange path every credential it issues travels.
//!
//! Two regimes, chosen per badge by `shareableOutside`:
//!
//! - **Inside only** (VTI-BDG-061): short-lived and renewed, no `credentialStatus`, on the
//!   terms a group membership credential has.
//! - **May be shown outside** (VTI-BDG-062): long-lived (`BadgeSettings.credentialValidDays`,
//!   [`OUTSIDE_DEFAULT_DAYS`]) with a `credentialStatus` slot in the **community's** own
//!   revocation list — the one every community credential uses, allocated at random — one
//!   slot per badge and holder, reused by every re-issue and renewal, flipped when the badge
//!   is taken back, retired or the holder departs (VTI-BDG-063). The list's credential is the
//!   community's while the badge credential's issuer is the group: the W3C Bitstring Status
//!   List validate algorithm compares no issuers, and says the two "might differ".
//!
//! Every credential embeds the community's Open Badges `EndorsementCredential` of the
//! Achievement, signed by the VTA as the community and kept on the badge (VTI-BDG-060), so
//! an outside verifier sees who stands behind the issuer without a registry.

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use vti_common::error::AppError;

use super::{Award, Badge};
use crate::credentials::vmc::CredentialStatusRef;
use crate::groups::Group;
use crate::groups::identity::{self, Failure};
use crate::rooms::community::{HolderError, SIGN_TIMEOUT};
use crate::server::AppState;
use crate::status_list;

/// The Open Badges 3.0 context the credential carries beside the VC 2.0 one.
pub const OB_CONTEXT: &str = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json";

/// How long a credential its holders may show outside stands when the community sets no
/// `credentialValidDays`: two years.
pub const OUTSIDE_DEFAULT_DAYS: u32 = 730;

/// What this community keeps of an issued credential, and the credential itself.
#[derive(Debug, Clone)]
pub struct Issued {
    pub credential_id: String,
    pub valid_until: DateTime<Utc>,
    pub credential: Value,
}

/// The Achievement's stable identifier: the badge's public location where the community
/// has one (VTI-BDG-051), else a URN.
pub fn achievement_id(badge: &Badge, public_url: Option<&str>) -> String {
    match public_url {
        Some(u) => format!("{}/badges/{}", u.trim_end_matches('/'), badge.badge_id),
        None => format!("urn:vtc:badge:{}", badge.badge_id),
    }
}

/// The badge's Achievement, as the credential names it (VTI-BDG-060), with the
/// community's endorsement of it where one is held.
fn achievement(
    state_did: &str,
    badge: &Badge,
    public_url: Option<&str>,
    endorsement: Option<&Value>,
) -> Value {
    let mut a = json!({
        "id": achievement_id(badge, public_url),
        "type": ["Achievement"],
        "name": badge.name,
        "description": badge.description,
        "creator": { "id": state_did, "type": ["Profile"] },
        "achievementType": "Badge",
    });
    if let Some(c) = &badge.criteria {
        a["criteria"] = json!({ "narrative": c });
    }
    if let Some(e) = endorsement {
        a["endorsement"] = json!([e]);
    }
    if let Some(sha) = crate::directory::images::sha_of(&badge.image) {
        let media = badge
            .image
            .get("mediaType")
            .and_then(Value::as_str)
            .unwrap_or("image/png");
        a["image"] = json!({
            "id": format!("urn:sha256:{sha}"),
            "type": "Image",
            "caption": badge.name,
            "mediaType": media,
        });
    }
    a
}

/// The community's endorsement of the badge's Achievement, unsigned: an Open Badges 3.0
/// `EndorsementCredential` whose subject is the Achievement (VTI-BDG-060).
pub fn endorsement_document(
    community_did: &str,
    badge: &Badge,
    public_url: Option<&str>,
    now: DateTime<Utc>,
) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2", OB_CONTEXT],
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": ["VerifiableCredential", "EndorsementCredential"],
        "name": format!("Endorsement of {}", badge.name),
        "issuer": { "id": community_did, "type": ["Profile"] },
        "validFrom": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "credentialSubject": {
            "id": achievement_id(badge, public_url),
            "type": ["EndorsementSubject"],
            "endorsementComment": format!(
                "The community stands behind this badge: its badge group is appointed by the \
                 community to issue “{}”.",
                badge.name
            ),
        },
    })
}

/// The unsigned credential for `member_did` holding `badge` with `awards` as its evidence.
/// `status` is the holder's slot in the community's revocation list, for a badge its
/// holders may show outside; `endorsement` the community's, where one is held.
#[allow(clippy::too_many_arguments)]
pub fn document(
    community_did: &str,
    public_url: Option<&str>,
    group: &Group,
    badge: &Badge,
    member_did: &str,
    awards: &[Award],
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    status: Option<Value>,
    endorsement: Option<&Value>,
) -> Value {
    let evidence: Vec<Value> = awards
        .iter()
        .map(|a| {
            let mut e = json!({
                "id": format!("urn:vtc:award:{}", a.award_id),
                "type": ["Evidence"],
                "name": "Award",
            });
            if let Some(n) = &a.note {
                e["narrative"] = json!(n);
            }
            if let Some(at) = a.decided_at {
                e["description"] = json!(format!("Accepted {}", at.to_rfc3339()));
            }
            e
        })
        .collect();
    let mut doc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2", OB_CONTEXT],
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "name": badge.name,
        "issuer": { "id": group.group_did, "type": ["Profile"] },
        "validFrom": valid_from.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "validUntil": valid_until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "credentialSubject": {
            "type": ["AchievementSubject"],
            "id": member_did,
            "achievement": achievement(community_did, badge, public_url, endorsement),
        },
    });
    if let Some(s) = status {
        doc["credentialStatus"] = s;
    }
    if !evidence.is_empty() {
        doc["evidence"] = Value::Array(evidence);
    }
    doc
}

/// Sign a document as the community through its VTA.
async fn sign_as_community(setup: &identity::Setup, document: Value) -> Result<Value, Failure> {
    let answer = setup
        .holder
        .ask(
            vta_sdk::trust_tasks::TASK_KEYS_SIGN_DOCUMENT_0_1,
            json!({ "keyId": setup.community_key_id, "document": document }),
            SIGN_TIMEOUT,
        )
        .await
        .map_err(|e| Failure::Holder(e, None))?;
    let signed: vta_sdk::protocols::key_management::sign_document::SignDocumentResponse =
        serde_json::from_value(answer).map_err(|e| {
            Failure::Holder(
                HolderError::Unavailable(format!(
                    "keys/sign-document answered a shape not its own: {e}"
                )),
                None,
            )
        })?;
    Ok(Value::Object(signed.document))
}

/// The community's endorsement of `badge`'s Achievement: the one the badge holds, else
/// one signed now as the community and kept on the badge (VTI-BDG-060).
pub async fn ensure_endorsement(
    state: &AppState,
    setup: &identity::Setup,
    badge: &Badge,
    public_url: Option<&str>,
) -> Result<Value, Failure> {
    if let Some(e) = &badge.endorsement {
        return Ok(e.clone());
    }
    let unsigned = endorsement_document(&setup.community_did, badge, public_url, Utc::now());
    let signed = sign_as_community(setup, unsigned).await?;
    // Kept on the badge as it is now, so a change made meanwhile is not undone.
    let mut fresh = super::get_badge(&state.badges_ks, &badge.badge_id)
        .await
        .map_err(Failure::Local)?
        .unwrap_or_else(|| badge.clone());
    if fresh.endorsement.is_none() {
        fresh.endorsement = Some(signed.clone());
        super::put_badge(&state.badges_ks, &fresh)
            .await
            .map_err(Failure::Local)?;
    }
    Ok(signed)
}

/// The holder's slot in the community's revocation list for a badge they may show
/// outside: the one they hold, else one allocated now and kept. Answers the
/// `credentialStatus` to write.
async fn outside_status(
    state: &AppState,
    badge_id: &str,
    entry_id: &str,
) -> Result<Value, AppError> {
    let held = super::holder_slot(&state.badges_ks, badge_id, entry_id).await?;
    let slot = status_list::with_locked(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        move |row| {
            let slot = match held {
                Some(s) => Some(s),
                None => status_list::allocate(row),
            };
            Ok(slot.map(|s| (s, row.list_credential_id.clone())))
        },
    )
    .await?;
    let Some((slot, list_credential_id)) = slot else {
        return Err(AppError::Internal(
            "revocation status list is full — cannot allocate a slot for a badge credential".into(),
        ));
    };
    if held.is_none() {
        super::put_holder_slot(&state.badges_ks, badge_id, entry_id, slot).await?;
    }
    serde_json::to_value(CredentialStatusRef::revocation(list_credential_id, slot))
        .map_err(|e| AppError::Internal(format!("credentialStatus: {e}")))
}

async fn flip(state: &AppState, slot: u32) -> Result<(), AppError> {
    status_list::with_locked(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        move |row| {
            status_list::flip(row, slot, true)
                .map_err(|e| AppError::Internal(format!("flip status-list bit {slot}: {e}")))
        },
    )
    .await
}

/// Revoke `entry_id`'s credential of `badge_id` where it carries a status (VTI-BDG-063):
/// the badge was taken back, or the holder left. Nothing to do for an inside-only badge.
pub async fn revoke_holder(
    state: &AppState,
    badge_id: &str,
    entry_id: &str,
) -> Result<(), AppError> {
    if let Some(slot) = super::holder_slot(&state.badges_ks, badge_id, entry_id).await? {
        flip(state, slot).await?;
    }
    Ok(())
}

/// Revoke every holder's credential of `badge_id` that carries a status: the badge is
/// retired (VTI-BDG-063).
pub async fn revoke_all_holders(state: &AppState, badge_id: &str) -> Result<(), AppError> {
    for (_, slot) in super::holder_slots_of_badge(&state.badges_ks, badge_id).await? {
        flip(state, slot).await?;
    }
    Ok(())
}

/// Revoke every badge credential `entry_id` holds that carries a status: they departed
/// (VTI-BDG-063). Their inside-only credentials lapse with their renewal.
pub async fn revoke_departed(state: &AppState, entry_id: &str) -> Result<(), AppError> {
    for (_, slot) in super::holder_slots_of_entry(&state.badges_ks, entry_id).await? {
        flip(state, slot).await?;
    }
    Ok(())
}

/// Issue `member_did` the badge credential of `badge`, signed by the VTA as the group.
/// `entry_id` is the holder's directory entry, which keys their status slot for a badge
/// they may show outside; resolved from `member_did` when the caller has none.
pub async fn issue(
    state: &AppState,
    group: &Group,
    badge: &Badge,
    member_did: &str,
    entry_id: Option<&str>,
    awards: &[Award],
) -> Result<Issued, Failure> {
    let setup = identity::setup(state)
        .await
        .map_err(|why| Failure::Holder(HolderError::Unavailable(why), None))?;
    let (group_days, public_url) = {
        let config = state.config.read().await;
        (
            config
                .groups
                .as_ref()
                .map(|g| g.credential_valid_days())
                .unwrap_or(30),
            config.public_url.clone(),
        )
    };
    let endorsement = ensure_endorsement(state, &setup, badge, public_url.as_deref()).await?;
    let (days, status) = if badge.shareable_outside {
        let entry = match entry_id {
            Some(e) => e.to_string(),
            None => crate::directory::cards::entry_of(state.directory.ks(), member_did)
                .await
                .map_err(Failure::Local)?
                .ok_or_else(|| {
                    Failure::Local(AppError::Internal(
                        "a badge holder without a directory entry".into(),
                    ))
                })?,
        };
        let settings = super::settings(&state.badges_ks)
            .await
            .map_err(Failure::Local)?;
        let status = outside_status(state, &badge.badge_id, &entry)
            .await
            .map_err(Failure::Local)?;
        (
            settings
                .credential_valid_days
                .unwrap_or(OUTSIDE_DEFAULT_DAYS),
            Some(status),
        )
    } else {
        (group_days, None)
    };
    let valid_from = Utc::now();
    let valid_until = valid_from + Duration::days(i64::from(days));
    let mut document = document(
        &setup.community_did,
        public_url.as_deref(),
        group,
        badge,
        member_did,
        awards,
        valid_from,
        valid_until,
        status,
        Some(&endorsement),
    );
    let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    document["id"] = json!(credential_id);
    let answer = setup
        .holder
        .ask(
            vta_sdk::trust_tasks::TASK_KEYS_SIGN_DOCUMENT_0_1,
            json!({ "keyId": group.signing_key_id, "document": document }),
            SIGN_TIMEOUT,
        )
        .await
        .map_err(|e| Failure::Holder(e, None))?;
    let signed: vta_sdk::protocols::key_management::sign_document::SignDocumentResponse =
        serde_json::from_value(answer).map_err(|e| {
            Failure::Holder(
                HolderError::Unavailable(format!(
                    "keys/sign-document answered a shape not its own: {e}"
                )),
                None,
            )
        })?;
    Ok(Issued {
        credential_id,
        valid_until,
        credential: Value::Object(signed.document),
    })
}

/// Offer `issued` to `member_did`, with the group's authority credential it chains to.
/// Best effort, as every delivery is: a holder offline now receives it from the outbox.
pub async fn offer(state: &AppState, group: &Group, member_did: &str, issued: &Issued) {
    let mut credentials = Vec::with_capacity(2);
    match crate::credentials::dtg::into_typed(issued.credential.clone(), "badge credential") {
        Ok(vc) => credentials.push(vc),
        Err(e) => {
            tracing::warn!(group = %group.group_id, error = %e, "could not offer a badge credential");
            return;
        }
    }
    if let Some(vac) = &group.authority_credential
        && let Ok(vc) = crate::credentials::dtg::into_typed(vac.clone(), "group VAC")
    {
        credentials.push(vc);
    }
    let refs: Vec<&affinidi_vc::VerifiableCredential> = credentials.iter().collect();
    if let Err(e) =
        crate::credentials::delivery::deliver_credentials(state, member_did, &refs).await
    {
        tracing::warn!(
            group = %group.group_id,
            error = %e,
            "a badge credential was issued but could not be offered yet"
        );
    }
}

/// The badge `group` backs, read for the groups' own issuance paths (admission by a
/// request, a dynamic rule, renewal): a badge group issues the badge credential, never a
/// membership credential.
pub async fn for_group(state: &AppState, group: &Group) -> Result<Option<Badge>, AppError> {
    let Some(badge_id) = &group.badge_id else {
        return Ok(None);
    };
    super::get_badge(&state.badges_ks, badge_id).await
}

/// Issue the credential of `group` to `member_did` as the groups subsystem does for any
/// group: the badge credential where `group` backs a badge, with the holder's accepted
/// awards as evidence. `None` where the group backs no badge.
pub async fn issue_for_group(
    state: &AppState,
    group: &Group,
    member_did: &str,
    entry_id: Option<&str>,
) -> Result<Option<crate::groups::credential::Issued>, Failure> {
    let Some(badge) = for_group(state, group).await.map_err(Failure::Local)? else {
        return Ok(None);
    };
    let entry = match entry_id {
        Some(e) => Some(e.to_string()),
        None => crate::directory::cards::entry_of(state.directory.ks(), member_did)
            .await
            .map_err(Failure::Local)?,
    };
    let awards = match &entry {
        Some(e) => super::accepted_of(&state.badges_ks, &badge.badge_id, e)
            .await
            .map_err(Failure::Local)?,
        None => Vec::new(),
    };
    let issued = issue(state, group, &badge, member_did, entry.as_deref(), &awards).await?;
    Ok(Some(crate::groups::credential::Issued {
        credential_id: issued.credential_id,
        valid_until: issued.valid_until,
        credential: issued.credential,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::badges::{AwardState, BadgeKind, BadgeState};

    fn badge() -> Badge {
        Badge {
            badge_id: "bdg_W5k2N8xRb3Qz7TpLAAAAAA".into(),
            kind: BadgeKind::Community,
            name: "Workshop host".into(),
            description: "Ran a workshop.".into(),
            criteria: Some("Hosted any workshop.".into()),
            image: json!({ "sha256": "ab".repeat(32), "mediaType": "image/png", "size": 10 }),
            repeatable: true,
            requestable: true,
            listed: true,
            shareable_outside: false,
            group_id: Some("grp_x".into()),
            state: BadgeState::Active,
            created_at: Utc::now(),
            created_by: None,
            updated_at: Utc::now(),
            retired_at: None,
            endorsement: None,
        }
    }

    fn group() -> Group {
        Group {
            group_id: "grp_x".into(),
            group_did: "did:example:badge-group".into(),
            signing_key_id: "did:example:badge-group#key-1".into(),
            name: "Workshop host".into(),
            description: None,
            kind: crate::groups::GroupKind::Static,
            rule: None,
            join_policy: crate::groups::JoinPolicy::Request,
            visibility: crate::groups::Audience::Members,
            show_members: crate::groups::Audience::Members,
            issues_credentials: true,
            authority: None,
            authority_credential: None,
            did_log_path: None,
            badge_id: Some("bdg_W5k2N8xRb3Qz7TpLAAAAAA".into()),
            created_at: Utc::now(),
            created_by: None,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn the_document_is_an_open_badge_issued_by_the_group_and_created_by_the_community() {
        let now = Utc::now();
        let award = Award {
            award_id: "awd_1".into(),
            badge_id: "bdg_W5k2N8xRb3Qz7TpLAAAAAA".into(),
            entry_id: "dir_a".into(),
            given_by: Some("dir_b".into()),
            note: Some("Resin pour".into()),
            state: AwardState::Accepted,
            offered_at: now,
            decided_at: Some(now),
            expires_at: None,
            credential_id: None,
            revoke_reason: None,
        };
        let endorsement = endorsement_document(
            "did:example:community",
            &badge(),
            Some("https://vtc.example.com/"),
            now,
        );
        let doc = document(
            "did:example:community",
            Some("https://vtc.example.com/"),
            &group(),
            &badge(),
            "did:example:member",
            std::slice::from_ref(&award),
            now,
            now + Duration::days(30),
            None,
            Some(&endorsement),
        );
        assert_eq!(
            doc["type"],
            json!(["VerifiableCredential", "OpenBadgeCredential"])
        );
        assert_eq!(doc["@context"][1], OB_CONTEXT);
        assert_eq!(doc["issuer"]["id"], "did:example:badge-group");
        assert_eq!(doc["credentialSubject"]["id"], "did:example:member");
        let a = &doc["credentialSubject"]["achievement"];
        assert_eq!(a["creator"]["id"], "did:example:community");
        assert_eq!(
            a["id"],
            "https://vtc.example.com/badges/bdg_W5k2N8xRb3Qz7TpLAAAAAA"
        );
        assert_eq!(a["criteria"]["narrative"], "Hosted any workshop.");
        assert_eq!(doc["evidence"].as_array().unwrap().len(), 1);
        assert_eq!(doc["evidence"][0]["narrative"], "Resin pour");
        assert!(
            doc.get("credentialStatus").is_none(),
            "inside regime: no status"
        );
        // The community's endorsement rides on the Achievement (VTI-BDG-060).
        let e = &a["endorsement"][0];
        assert_eq!(
            e["type"],
            json!(["VerifiableCredential", "EndorsementCredential"])
        );
        assert_eq!(e["issuer"]["id"], "did:example:community");
        assert_eq!(e["credentialSubject"]["id"], a["id"]);
        assert_eq!(
            e["credentialSubject"]["type"],
            json!(["EndorsementSubject"])
        );

        // The outside regime carries the status it was given, verbatim.
        let status = json!({
            "id": "https://vtc.example.com/v1/status-lists/revocation#7",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "7",
            "statusListCredential": "https://vtc.example.com/v1/status-lists/revocation",
        });
        let outside = document(
            "did:example:community",
            Some("https://vtc.example.com/"),
            &group(),
            &badge(),
            "did:example:member",
            &[award],
            now,
            now + Duration::days(730),
            Some(status.clone()),
            None,
        );
        assert_eq!(outside["credentialStatus"], status);
        assert!(
            outside["credentialSubject"]["achievement"]
                .get("endorsement")
                .is_none()
        );
    }
}
