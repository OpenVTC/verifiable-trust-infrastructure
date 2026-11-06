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
//! This build serves the **inside-only regime** (VTI-BDG-061): short-lived and renewed,
//! no `credentialStatus`, on the terms a group membership credential has. A badge whose
//! holders may show it outside (VTI-BDG-062, a long-lived credential in the community's
//! own status set) is not served yet, and `create` refuses `shareableOutside` until it is.

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use vti_common::error::AppError;

use super::{Award, Badge};
use crate::groups::Group;
use crate::groups::identity::{self, Failure};
use crate::rooms::community::{HolderError, SIGN_TIMEOUT};
use crate::server::AppState;

/// The Open Badges 3.0 context the credential carries beside the VC 2.0 one.
pub const OB_CONTEXT: &str = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json";

/// What this community keeps of an issued credential, and the credential itself.
#[derive(Debug, Clone)]
pub struct Issued {
    pub credential_id: String,
    pub valid_until: DateTime<Utc>,
    pub credential: Value,
}

/// The badge's Achievement, as the credential names it (VTI-BDG-060).
fn achievement(state_did: &str, badge: &Badge, public_url: Option<&str>) -> Value {
    let id = match public_url {
        Some(u) => format!("{}/badges/{}", u.trim_end_matches('/'), badge.badge_id),
        None => format!("urn:vtc:badge:{}", badge.badge_id),
    };
    let mut a = json!({
        "id": id,
        "type": ["Achievement"],
        "name": badge.name,
        "description": badge.description,
        "creator": { "id": state_did, "type": ["Profile"] },
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
            "id": format!("urn:sha256:{sha}"),
            "type": "Image",
            "caption": badge.name,
            "mediaType": media,
        });
    }
    a
}

/// The unsigned credential for `member_did` holding `badge` with `awards` as its evidence.
pub fn document(
    community_did: &str,
    public_url: Option<&str>,
    group: &Group,
    badge: &Badge,
    member_did: &str,
    awards: &[Award],
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
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
            "achievement": achievement(community_did, badge, public_url),
        },
    });
    if !evidence.is_empty() {
        doc["evidence"] = Value::Array(evidence);
    }
    doc
}

/// Issue `member_did` the badge credential of `badge`, signed by the VTA as the group.
pub async fn issue(
    state: &AppState,
    group: &Group,
    badge: &Badge,
    member_did: &str,
    awards: &[Award],
) -> Result<Issued, Failure> {
    let setup = identity::setup(state)
        .await
        .map_err(|why| Failure::Holder(HolderError::Unavailable(why), None))?;
    let (days, public_url) = {
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
    let awards = match entry_id {
        Some(e) => super::accepted_of(&state.badges_ks, &badge.badge_id, e)
            .await
            .map_err(Failure::Local)?,
        None => Vec::new(),
    };
    let issued = issue(state, group, &badge, member_did, &awards).await?;
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
        let doc = document(
            "did:example:community",
            Some("https://vtc.example.com/"),
            &group(),
            &badge(),
            "did:example:member",
            &[award],
            now,
            now + Duration::days(30),
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
    }
}
