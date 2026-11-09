//! The badge credential (VTI-BDG-060 – 063): what the community issues each holder of a
//! community badge in place of a group membership credential.
//!
//! An **Open Badges 3.0** `OpenBadgeCredential` — a profile of the W3C Verifiable
//! Credentials Data Model v2.0 — whose `issuer` is the community, named as it names itself
//! (VTI-BDG-060), whose subject is the holder's membership DID, whose `achievement` is the
//! badge (name, description, criteria, picture) with the same community as its `creator`,
//! and with one `evidence` entry per accepted award. It names the Open Badges JSON Schema in
//! `credentialSchema`, so the standard validators check it. The community has its VTA sign
//! it **as the community**, through `keys/sign-document`, and offers it on the
//! credential-exchange path every credential it issues travels.
//!
//! The issuer is the community, not the badge group, because a verifier outside the
//! community knows the community and nothing of a group's DID (VTI-BDG-064). The badge
//! group keeps the badge's owners, holders, requests and rules, and issues nothing.
//!
//! Two regimes, chosen per badge by `shareableOutside`:
//!
//! - **Inside only** (VTI-BDG-061): short-lived and renewed, no `credentialStatus`, on the
//!   terms a group membership credential has.
//! - **May be shown outside** (VTI-BDG-062): long-lived (`BadgeSettings.credentialValidDays`,
//!   [`OUTSIDE_DEFAULT_DAYS`]) with a `credentialStatus` slot in the **community's** own
//!   revocation list — the one every community credential uses, allocated at random — one
//!   slot per badge and holder, reused by every re-issue and renewal, flipped when the badge
//!   is taken back, retired or the holder departs (VTI-BDG-063).

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

/// The Open Badges 3.0 JSON Schema an `OpenBadgeCredential` names, and the validator type
/// 1EdTech defines for it.
pub const OB_SCHEMA: &str =
    "https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json";
pub const OB_SCHEMA_TYPE: &str = "1EdTechJsonSchemaValidator2019";

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

/// The public location of a shareable badge's picture (VTI-BDG-051), where the community
/// has a public origin.
pub fn public_image_url(badge: &Badge, public_url: Option<&str>) -> Option<String> {
    match public_url {
        Some(u) if badge.shareable_outside => Some(format!(
            "{}/{}/{}/image",
            u.trim_end_matches('/'),
            super::public::BADGE_PATH,
            badge.badge_id
        )),
        _ => None,
    }
}

/// The community as an Open Badges `Profile`: its DID, the name it gives itself, and its
/// public origin where it has one. The credential's `issuer` and the Achievement's
/// `creator` alike (VTI-BDG-060), so a wallet shows a name rather than a DID.
pub fn community_profile(
    community_did: &str,
    name: Option<&str>,
    public_url: Option<&str>,
) -> Value {
    let mut p = json!({ "id": community_did, "type": ["Profile"] });
    if let Some(n) = name.map(str::trim).filter(|n| !n.is_empty()) {
        p["name"] = json!(n);
    }
    if let Some(u) = public_url {
        p["url"] = json!(u.trim_end_matches('/'));
    }
    p
}

/// The community's [`community_profile`], read now.
pub async fn load_community_profile(state: &AppState) -> Result<Value, AppError> {
    let (did, public_url) = {
        let config = state.config.read().await;
        (
            config.vtc_did.clone().unwrap_or_default(),
            config.public_url.clone(),
        )
    };
    let name = crate::community::profile::load_profile(&state.community_ks)
        .await?
        .map(|p| p.name);
    Ok(community_profile(
        &did,
        name.as_deref(),
        public_url.as_deref(),
    ))
}

/// The badge's Achievement, as the credential names it (VTI-BDG-060), `creator` the
/// community's profile. Its picture is named by its public location for a badge its holders
/// may show outside, else by digest.
pub fn achievement(creator: &Value, badge: &Badge, public_url: Option<&str>) -> Value {
    let mut a = json!({
        "id": achievement_id(badge, public_url),
        "type": ["Achievement"],
        "name": badge.name,
        "description": badge.description,
        "creator": creator,
        "achievementType": "Badge",
    });
    if let Some(c) = &badge.criteria {
        a["criteria"] = json!({ "narrative": c });
    }
    if let Some(sha) = crate::directory::images::sha_of(&badge.image) {
        let media = badge
            .image
            .get("mediaType")
            .and_then(Value::as_str)
            .unwrap_or("image/png");
        a["image"] = json!({
            "id": public_image_url(badge, public_url).unwrap_or_else(|| format!("urn:sha256:{sha}")),
            "type": "Image",
            "caption": badge.name,
            "mediaType": media,
        });
    }
    a
}

/// The unsigned credential for `member_did` holding `badge` with `awards` as its evidence,
/// issued by `issuer`, the community's [`community_profile`]. `status` is the holder's slot
/// in the community's revocation list, for a badge its holders may show outside.
#[allow(clippy::too_many_arguments)]
pub fn document(
    issuer: &Value,
    public_url: Option<&str>,
    badge: &Badge,
    member_did: &str,
    awards: &[Award],
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    status: Option<Value>,
) -> Value {
    let evidence: Vec<Value> = awards
        .iter()
        .map(|a| {
            let mut e = json!({ "type": ["Evidence"], "name": "Award" });
            if let Some(n) = &a.note {
                e["narrative"] = json!(n);
            }
            if let Some(at) = a.decided_at {
                e["description"] = json!(format!(
                    "Accepted {}",
                    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                ));
            }
            e
        })
        .collect();
    let mut doc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2", OB_CONTEXT],
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "name": badge.name,
        "issuer": issuer,
        "validFrom": valid_from.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "validUntil": valid_until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "credentialSchema": [{ "id": OB_SCHEMA, "type": OB_SCHEMA_TYPE }],
        "credentialSubject": {
            "type": ["AchievementSubject"],
            "id": member_did,
            "achievement": achievement(issuer, badge, public_url),
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
    // The group backs this badge: the credential is its holders' (VTI-BDG-060).
    if group.badge_id.as_deref() != Some(badge.badge_id.as_str()) {
        return Err(Failure::Local(AppError::Internal(format!(
            "group {} does not back badge {}",
            group.group_id, badge.badge_id
        ))));
    }
    let issuer = load_community_profile(state)
        .await
        .map_err(Failure::Local)?;
    let (days, status, outside_entry) = if badge.shareable_outside {
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
            Some(entry),
        )
    } else {
        (group_days, None, None)
    };
    let valid_from = Utc::now();
    let valid_until = valid_from + Duration::days(i64::from(days));
    let mut document = document(
        &issuer,
        public_url.as_deref(),
        badge,
        member_did,
        awards,
        valid_from,
        valid_until,
        status,
    );
    let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    document["id"] = json!(credential_id);
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
    let credential = Value::Object(signed.document);
    // The one its holder's shares serve from now on, at the same locations
    // (`vtc/badges/awards/share` item 10).
    if let Some(entry) = &outside_entry {
        super::share::keep_credential(&state.badges_ks, &badge.badge_id, entry, &credential)
            .await
            .map_err(Failure::Local)?;
    }
    Ok(Issued {
        credential_id,
        valid_until,
        credential,
    })
}

/// Offer `issued` to `member_did`. The community is its issuer, so nothing rides with it.
/// Best effort, as every delivery is: a holder offline now receives it from the outbox.
pub async fn offer(state: &AppState, group: &Group, member_did: &str, issued: &Issued) {
    let vc = match crate::credentials::dtg::into_typed(
        issued.credential.clone(),
        "badge credential",
    ) {
        Ok(vc) => vc,
        Err(e) => {
            tracing::warn!(group = %group.group_id, error = %e, "could not offer a badge credential");
            return;
        }
    };
    if let Err(e) =
        crate::credentials::delivery::deliver_credentials(state, member_did, &[&vc]).await
    {
        tracing::warn!(
            group = %group.group_id,
            error = %e,
            "a badge credential was issued but could not be offered yet"
        );
    }
}

/// Admit `member_did` (at `entry_id`) to a badge group outside an offer: an approved
/// request, which is the requester's consent (VTI-BDG-024), or the group's rule
/// (VTI-BDG-013). Where they hold no accepted award of the badge, one is recorded —
/// `given_by` the owner who approved, absent for a rule — and is the new credential's
/// evidence: credential first, the award recorded after it is issued (VTI-BDG-021).
/// `None` for a group that backs no badge.
pub async fn issue_admitting(
    state: &AppState,
    group: &Group,
    member_did: &str,
    entry_id: &str,
    given_by: Option<&str>,
) -> Result<Option<crate::groups::credential::Issued>, Failure> {
    let Some(badge) = for_group(state, group).await.map_err(Failure::Local)? else {
        return Ok(None);
    };
    let held = super::accepted_of(&state.badges_ks, &badge.badge_id, entry_id)
        .await
        .map_err(Failure::Local)?;
    let issued = if held.is_empty() {
        let change = if given_by.is_some() {
            "requestApproved"
        } else {
            "givenByRule"
        };
        issue_with_new_award(state, group, &badge, member_did, entry_id, given_by, change)
            .await?
            .0
    } else {
        issue(state, group, &badge, member_did, Some(entry_id), &held).await?
    };
    Ok(Some(crate::groups::credential::Issued {
        credential_id: issued.credential_id,
        valid_until: issued.valid_until,
        credential: issued.credential,
    }))
}

/// Record one new accepted award of `badge` to `entry_id` and issue the credential with it
/// among the holder's evidence: credential first, the award recorded after it is issued,
/// audited as `change`. For an admission outside an offer (VTI-BDG-024, 013) and a claim
/// code's redemption (VTI-BDG-026), whose consent is the request, the rule's admission or
/// the redemption itself.
pub async fn issue_with_new_award(
    state: &AppState,
    group: &Group,
    badge: &Badge,
    member_did: &str,
    entry_id: &str,
    given_by: Option<&str>,
    change: &str,
) -> Result<(Issued, Award), Failure> {
    let mut evidence = super::accepted_of(&state.badges_ks, &badge.badge_id, entry_id)
        .await
        .map_err(Failure::Local)?;
    let now = Utc::now();
    let mut award = Award {
        award_id: super::new_award_id(),
        badge_id: badge.badge_id.clone(),
        entry_id: entry_id.to_string(),
        given_by: given_by.map(str::to_string),
        note: None,
        state: super::AwardState::Accepted,
        offered_at: now,
        decided_at: Some(now),
        expires_at: None,
        credential_id: None,
        revoke_reason: None,
        shared: None,
    };
    evidence.push(award.clone());
    let issued = issue(state, group, badge, member_did, Some(entry_id), &evidence).await?;
    award.credential_id = Some(issued.credential_id.clone());
    {
        let _guard = super::WRITE_LOCK.lock().await;
        super::put_award(&state.badges_ks, &award)
            .await
            .map_err(Failure::Local)?;
    }
    super::audit(
        state,
        given_by.unwrap_or(member_did),
        vti_common::audit::BadgeChangedData {
            badge_id: award.badge_id.clone(),
            award_id: Some(award.award_id.clone()),
            entry_id: Some(award.entry_id.clone()),
            change: change.to_string(),
            fields: Vec::new(),
            group_id: Some(group.group_id.clone()),
        },
    )
    .await
    .map_err(Failure::Local)?;
    Ok((issued, award))
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
        }
    }

    #[test]
    fn the_document_is_an_open_badge_issued_and_created_by_the_named_community() {
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
            shared: None,
        };
        let issuer = community_profile(
            "did:example:community",
            Some(" First VTC "),
            Some("https://vtc.example.com/"),
        );
        let doc = document(
            &issuer,
            Some("https://vtc.example.com/"),
            &badge(),
            "did:example:member",
            std::slice::from_ref(&award),
            now,
            now + Duration::days(30),
            None,
        );
        assert_eq!(
            doc["type"],
            json!(["VerifiableCredential", "OpenBadgeCredential"])
        );
        assert_eq!(doc["@context"][1], OB_CONTEXT);
        // The community issues, named, with its origin (VTI-BDG-060).
        assert_eq!(
            doc["issuer"],
            json!({
                "id": "did:example:community",
                "type": ["Profile"],
                "name": "First VTC",
                "url": "https://vtc.example.com",
            })
        );
        assert_eq!(
            doc["credentialSchema"],
            json!([{ "id": OB_SCHEMA, "type": OB_SCHEMA_TYPE }])
        );
        assert_eq!(doc["credentialSubject"]["id"], "did:example:member");
        let a = &doc["credentialSubject"]["achievement"];
        assert_eq!(a["creator"], doc["issuer"]);
        assert_eq!(
            a["id"],
            "https://vtc.example.com/badges/bdg_W5k2N8xRb3Qz7TpLAAAAAA"
        );
        assert_eq!(a["criteria"]["narrative"], "Hosted any workshop.");
        assert_eq!(doc["evidence"].as_array().unwrap().len(), 1);
        assert_eq!(doc["evidence"][0]["narrative"], "Resin pour");
        // Accepted to the second, in UTC; no identifier of our own invention.
        let accepted = doc["evidence"][0]["description"].as_str().unwrap();
        assert!(
            accepted.starts_with("Accepted ") && accepted.ends_with('Z'),
            "{accepted}"
        );
        assert!(!accepted.contains('.'), "{accepted}");
        assert!(doc["evidence"][0].get("id").is_none());
        assert!(
            doc.get("credentialStatus").is_none(),
            "inside regime: no status"
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
            &issuer,
            Some("https://vtc.example.com/"),
            &badge(),
            "did:example:member",
            &[award],
            now,
            now + Duration::days(730),
            Some(status.clone()),
        );
        assert_eq!(outside["credentialStatus"], status);
        assert!(
            outside["credentialSubject"]["achievement"]
                .get("endorsement")
                .is_none()
        );

        // A community without a name or a public origin is still a Profile.
        assert_eq!(
            community_profile("did:example:community", Some("  "), None),
            json!({ "id": "did:example:community", "type": ["Profile"] })
        );
    }
}
