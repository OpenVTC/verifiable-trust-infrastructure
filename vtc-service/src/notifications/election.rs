//! The `election` notification to a member party (VTI-NTF-060, VTI-NTF-061).
//!
//! A community's list never shows an election put to the members of a party that is itself a
//! member of the community (VTI-VOT-015), and the community holds no record of those members,
//! so it tells the party — and only the party — and leaves the rest to it.
//!
//! # Remote first, one retry owner
//!
//! The notice is a row of its own beside the election (`party-notice:<electionId>` in the
//! elections keyspace, so it is backed up with it): the `notificationId`, the revision the
//! community means the party to hold, and the revision last queued. [`settle`], run by the
//! election sweeper once a minute, is its only writer and the only sender:
//!
//! 1. an election that is registered (the ballot box said so) and whose voting has not closed
//!    gets a notice at revision 1, `available`;
//! 2. an election cancelled, or closed early, before voting closes has its notice raised to a
//!    higher revision, `withdrawn` (VTI-NTF-024, VTI-NTF-061);
//! 3. the row is written **before** anything is sent, and a revision not yet queued is queued on
//!    the durable member push, which owns delivery and escalation (VTI-NTF-020). A crash between
//!    the push and recording it queues the same revision again — the same `notificationId` and
//!    `revision`, which the party holds as one notification (VTI-NTF-021, VTI-NTF-022).
//!
//! Nothing is sent once voting has closed: the notification has lapsed (Appendix G). A revision
//! that still offers the election is sent only while the party is an active member, checked at
//! every document issued (VTI-NTF-005); a withdrawal is sent whatever the party's standing, and
//! keeps the voting period of the revision it replaces (VTI-NTF-025).

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vta_sdk::notifications::{ELECTION_OPEN_WITH, KIND_ELECTION};
use vta_sdk::trust_tasks::TASK_NOTIFICATIONS_NOTIFY_0_1;

use crate::elections::store::{ElectionRecord, Standing};
use crate::error::AppError;
use crate::server::AppState;

const NOTICE_PREFIX: &str = "party-notice:";

/// The community's record of what it told a member party about one election.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyNotice {
    pub election_id: String,
    /// The member party: the DID the credential roll names.
    pub party: String,
    /// Unguessable and not descriptive: it travels as far as the notification is relayed.
    pub notification_id: String,
    /// The revision the party should hold.
    pub revision: u64,
    pub withdrawn: bool,
    /// The highest revision queued for delivery; 0 for none.
    pub queued_revision: u64,
}

fn notice_key(election_id: &str) -> String {
    format!("{NOTICE_PREFIX}{election_id}")
}

/// The notice for `election_id`, if one was made.
///
/// # Errors
/// A store failure.
pub async fn get(state: &AppState, election_id: &str) -> Result<Option<PartyNotice>, AppError> {
    state.elections.ks().get(notice_key(election_id)).await
}

/// The `notifications/notify/0.1` payload for `notice` (VTI-NTF-060): the community as holder,
/// the election's identifier, `vtc/elections/show/0.6` to open it, the party as audience, the
/// voting period — and nothing else of the election.
#[must_use]
pub fn payload(community: &str, rec: &ElectionRecord, notice: &PartyNotice) -> Value {
    let at = |t: DateTime<Utc>| t.to_rfc3339_opts(SecondsFormat::Secs, true);
    json!({
        "notification": {
            "notificationId": notice.notification_id,
            "revision": notice.revision,
            "kind": KIND_ELECTION,
            "subject": {
                "heldBy": community,
                "id": rec.election_id,
                "openWith": ELECTION_OPEN_WITH,
            },
            "audience": notice.party,
            "status": if notice.withdrawn { "withdrawn" } else { "available" },
            "relayable": true,
            "validFrom": at(rec.voting_opens),
            "validUntil": at(rec.voting_closes),
        }
    })
}

/// Bring the notice for `rec` up to date and queue what has not been. See the module docs.
///
/// # Errors
/// A store failure, or a push that could not be queued (the next pass tries again).
pub async fn settle(
    state: &AppState,
    rec: &ElectionRecord,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    if !rec.is_member_party_election() || now >= rec.voting_closes {
        return Ok(());
    }
    let Some(party) = rec.roll_member_of().map(str::to_string) else {
        return Ok(());
    };
    let ks = state.elections.ks();
    let ended_early = matches!(rec.standing, Standing::Cancelled | Standing::Closed);
    let mut notice = match get(state, &rec.election_id).await? {
        None if rec.standing == Standing::Registered => {
            let notice = PartyNotice {
                election_id: rec.election_id.clone(),
                party,
                notification_id: format!("ntf-{}", uuid::Uuid::new_v4().simple()),
                revision: 1,
                withdrawn: false,
                queued_revision: 0,
            };
            ks.insert(notice_key(&rec.election_id), &notice).await?;
            notice
        }
        // Not registered yet, or ended before it was: nothing to tell, or to withdraw.
        None => return Ok(()),
        Some(mut notice) => {
            if ended_early && !notice.withdrawn {
                notice.revision += 1;
                notice.withdrawn = true;
                ks.insert(notice_key(&rec.election_id), &notice).await?;
            }
            notice
        }
    };
    if notice.queued_revision >= notice.revision {
        return Ok(());
    }
    // VTI-NTF-005, at every document issued: a revision that still offers the election goes
    // only to a party the community's records still show as concerned — an active member. A
    // withdrawal is exempt: it goes to every party an earlier revision went to (VTI-NTF-024).
    if !notice.withdrawn && !still_concerned(state, &notice.party).await? {
        tracing::info!(
            election = %rec.election_id,
            revision = notice.revision,
            "election notification not sent: the member party is no longer an active member"
        );
        return Ok(());
    }
    let community = super::own_did(state)
        .await
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;
    super::push_signed(
        state,
        &notice.party,
        TASK_NOTIFICATIONS_NOTIFY_0_1,
        payload(&community, rec, &notice),
        super::deliver_by(
            Some(rec.voting_closes),
            now,
            std::time::Duration::from_secs(3600),
        ),
    )
    .await?;
    notice.queued_revision = notice.revision;
    ks.insert(notice_key(&rec.election_id), &notice).await?;
    tracing::info!(
        election = %rec.election_id,
        revision = notice.revision,
        withdrawn = notice.withdrawn,
        "election notification queued for the member party the roll names"
    );
    Ok(())
}

/// Whether the community's records still show `party` as concerned by a member-party election:
/// an active member (VTI-NTF-005). The roll that names it is the election's, recorded at create
/// and never re-derived.
async fn still_concerned(state: &AppState, party: &str) -> Result<bool, AppError> {
    Ok(crate::member_portal::active::active_member(state, party)
        .await?
        .is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// VTI-NTF-060: the notification names the community, the election and the task that opens
    /// it, the roll's party as audience and the voting period — and carries nothing else of the
    /// election (VTI-NTF-003).
    #[test]
    fn vti_ntf_060_the_payload_carries_only_the_reference() {
        let now = Utc::now();
        let mut rec = crate::elections::store::test_record(now);
        rec.manifest["title"] = json!("Board 2027");
        let notice = PartyNotice {
            election_id: rec.election_id.clone(),
            party: "did:web:partner.example".into(),
            notification_id: "ntf-abc".into(),
            revision: 1,
            withdrawn: false,
            queued_revision: 0,
        };
        let p = payload("did:web:community.example", &rec, &notice);
        let n = &p["notification"];
        assert_eq!(n["kind"], "election");
        assert_eq!(n["subject"]["heldBy"], "did:web:community.example");
        assert_eq!(n["subject"]["id"], json!(rec.election_id));
        assert_eq!(n["subject"]["openWith"], ELECTION_OPEN_WITH);
        assert_eq!(n["audience"], "did:web:partner.example");
        assert_eq!(n["status"], "available");
        assert!(!p.to_string().contains("Board 2027"));
        let schema = vti_specs::schema_index::schema_for(TASK_NOTIFICATIONS_NOTIFY_0_1).unwrap();
        trust_tasks_rs::validate::against_schema(schema, &p).expect("valid notify payload");
    }

    /// VTI-NTF-025: a withdrawal states the same period as the revision it replaces.
    #[test]
    fn vti_ntf_025_a_withdrawal_keeps_the_period_it_replaces() {
        let now = Utc::now();
        let rec = crate::elections::store::test_record(now);
        let mut notice = PartyNotice {
            election_id: rec.election_id.clone(),
            party: "did:web:partner.example".into(),
            notification_id: "ntf-abc".into(),
            revision: 1,
            withdrawn: false,
            queued_revision: 0,
        };
        let first = payload("did:web:community.example", &rec, &notice);
        notice.revision = 2;
        notice.withdrawn = true;
        let withdrawal = payload("did:web:community.example", &rec, &notice);
        assert_eq!(withdrawal["notification"]["status"], "withdrawn");
        for member in ["validFrom", "validUntil"] {
            assert_eq!(
                withdrawal["notification"][member], first["notification"][member],
                "{member}"
            );
        }
    }

    /// VTI-NTF-005: a revision that offers the election is issued only to a party the
    /// community's records still show as concerned — an active member — checked at every
    /// document issued; a withdrawal is issued whatever the party's standing (VTI-NTF-024).
    #[tokio::test]
    async fn vti_ntf_005_an_offer_goes_only_to_a_party_still_concerned() {
        use crate::acl::{AdminAuthority, VtcAclEntry, VtcRole};
        let community = vta_sdk::provision_client::EphemeralSetupKey::generate().unwrap();
        let party = vta_sdk::provision_client::EphemeralSetupKey::generate()
            .unwrap()
            .did;
        let tv = crate::test_support::TestVtc::builder()
            .vtc_did(community.did.clone())
            .build()
            .await;
        let state = &tv.state;
        let now = Utc::now();
        let mut rec = crate::elections::store::test_record(now);
        rec.manifest = json!({ "roll": { "rule": "credential", "memberOf": party } });
        rec.roll_party = Some(crate::elections::store::RollParty::MemberParty);

        // Not (or no longer) a member: the offer is recorded but never sent.
        settle(state, &rec, now).await.unwrap();
        let notice = get(state, &rec.election_id).await.unwrap().unwrap();
        assert_eq!((notice.revision, notice.queued_revision), (1, 0));

        // An active member: issued. The party's DID advertises no transport here, so the
        // attempt to queue it is what shows it was issued (the next pass tries again).
        let entry = VtcAclEntry::new(&party, VtcRole::Member, AdminAuthority::none(), "test");
        crate::acl::storage::store_acl_entry(&state.acl_ks, &entry)
            .await
            .unwrap();
        let m: crate::members::Member =
            serde_json::from_value(json!({ "did": party, "joinedAt": now.to_rfc3339() })).unwrap();
        crate::members::storage::store_member(&state.members_ks, &m)
            .await
            .unwrap();
        assert!(
            settle(state, &rec, now).await.is_err(),
            "an active member is sent the offer"
        );

        // The party leaves: the offer is no longer issued to it.
        crate::acl::storage::delete_acl_entry(&state.acl_ks, &party)
            .await
            .unwrap();
        settle(state, &rec, now).await.unwrap();

        // Then the election is cancelled: the withdrawal is issued whatever its standing.
        rec.standing = Standing::Cancelled;
        assert!(
            settle(state, &rec, now).await.is_err(),
            "the withdrawal is sent to a party that has left"
        );
        let notice = get(state, &rec.election_id).await.unwrap().unwrap();
        assert!(notice.withdrawn);
        assert_eq!(notice.revision, 2);
    }
}
