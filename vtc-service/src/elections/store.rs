//! The registrar's records: one per election, one per ticket issued.
//!
//! Plain data, compiled whatever the build's features, because the action list pins a parked
//! binding election to whether a record exists under its identifier
//! (`acl::admin_consent::pin_for`), and that pin must be readable by every build that can hold
//! the action.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Where an election stands with its ballot box, as the community records it. The clock turns
/// [`Standing::Registered`] into the state a reader sees ([`ElectionRecord::state`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Standing {
    /// Recorded, and the registration is still being delivered (create item 8).
    PendingRegistration,
    /// The ballot box refused the registration on a later delivery. Only a cancellation clears it.
    RegistrationRefused,
    /// The ballot box registered it.
    Registered,
    /// The ballot box closed it early, on this community's request.
    Closed,
    /// The community certified its result.
    Tallied,
    /// Cancelled.
    Cancelled,
}

/// A registration still being delivered: the community is the only retry owner (create item 8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Delivery {
    pub attempts: u32,
    pub next_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// What the ballot box said when it refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoxRefusal {
    pub code: String,
    pub message: String,
}

/// One election.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElectionRecord {
    pub election_id: String,
    /// The manifest exactly as registered: every ticket, cast and certification is bound to it.
    pub manifest: Value,
    /// Its digest, multibase multihash.
    pub manifest_digest: String,
    pub standing: Standing,
    pub binding: bool,
    pub ballot_box: String,
    pub registration_opens: DateTime<Utc>,
    pub voting_opens: DateTime<Utc>,
    pub voting_closes: DateTime<Utc>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    /// The parked action a binding creation executed from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    /// Set durably before anything else on a cancellation, and never cleared (VTI-VOT-024).
    #[serde(default)]
    pub issuance_stopped: bool,
    /// A close sent and not yet answered: no ticket is issued meanwhile (close item 4).
    #[serde(default)]
    pub close_in_flight: bool,
    #[serde(default)]
    pub tickets_issued: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<Delivery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<BoxRefusal>,
    /// Board heads kept, oldest first: `{head, document}`, the document exactly as the ballot
    /// box signed it.
    #[serde(default)]
    pub checkpoints: Vec<Value>,
    /// Whether the head as it stood at close is among them.
    #[serde(default)]
    pub final_checkpoint: bool,
    /// The certification, once recorded: `{result, certifiedAt, auditAttestations}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certified: Option<Value>,
    /// A sealed or tallied-encrypted election's key, once its trustees formed it, as the ballot
    /// box reported it and checked against the dealings it reported with it (show item 6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub election_key: Option<Value>,
}

impl ElectionRecord {
    /// The state a reader is shown (`RegistrarState`): the record's standing, with the clock
    /// read for a registered election as the ballot box would.
    #[must_use]
    pub fn state(&self, now: DateTime<Utc>) -> &'static str {
        match self.standing {
            Standing::PendingRegistration => "pendingRegistration",
            Standing::RegistrationRefused => "registrationRefused",
            Standing::Cancelled => "cancelled",
            Standing::Tallied => "tallied",
            Standing::Closed => "closed",
            Standing::Registered if now < self.registration_opens => "registered",
            Standing::Registered if now < self.voting_opens => "registration",
            Standing::Registered if now < self.voting_closes => "voting",
            Standing::Registered => "closed",
        }
    }

    /// Whether the ballot box has registered it (whatever has happened since).
    #[must_use]
    pub fn is_registered(&self) -> bool {
        matches!(
            self.standing,
            Standing::Registered | Standing::Closed | Standing::Tallied
        )
    }
}

/// A ticket issued: the record that spends the signer's one ticket (VTI-VOT-022), and what a
/// resend of the same request is answered from (tickets/issue item 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TicketIssued {
    pub election_id: String,
    pub signer: String,
    pub issued_at: DateTime<Utc>,
    /// The request document's `id`, and a digest of its bytes as received.
    pub doc_id: String,
    pub doc_digest: String,
    /// The pre-credential answered, kept until voting closes and then discarded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_credential: Option<String>,
}

const ELECTION_PREFIX: &str = "election:";
const TICKET_PREFIX: &str = "ticket:";

fn election_key(election_id: &str) -> String {
    format!("{ELECTION_PREFIX}{election_id}")
}

/// Hashed, so a DID's length or characters never shape the key.
fn ticket_key(election_id: &str, signer: &str) -> String {
    let mut h = Sha256::new();
    for part in [election_id, signer] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    format!("{TICKET_PREFIX}{election_id}:{}", hex::encode(h.finalize()))
}

/// The election under `election_id`.
///
/// # Errors
/// A store failure.
pub async fn get(
    ks: &KeyspaceHandle,
    election_id: &str,
) -> Result<Option<ElectionRecord>, AppError> {
    ks.get(election_key(election_id)).await
}

/// Write `record`.
///
/// # Errors
/// A store failure.
pub async fn put(ks: &KeyspaceHandle, record: &ElectionRecord) -> Result<(), AppError> {
    ks.insert(election_key(&record.election_id), record).await
}

/// Write `record` only when no election holds its identifier: `false` when one does.
///
/// # Errors
/// A store failure.
pub async fn put_new(ks: &KeyspaceHandle, record: &ElectionRecord) -> Result<bool, AppError> {
    ks.insert_if_absent(election_key(&record.election_id), record)
        .await
}

/// Remove the election (a registration the ballot box refused at once records nothing).
///
/// # Errors
/// A store failure.
pub async fn remove(ks: &KeyspaceHandle, election_id: &str) -> Result<(), AppError> {
    ks.remove(election_key(election_id)).await
}

/// Every election.
///
/// # Errors
/// A store failure, or a record that does not parse.
pub async fn all(ks: &KeyspaceHandle) -> Result<Vec<ElectionRecord>, AppError> {
    ks.prefix_iter_raw(ELECTION_PREFIX)
        .await?
        .into_iter()
        .map(|(_, v)| {
            serde_json::from_slice(&v)
                .map_err(|e| AppError::Internal(format!("an election record does not parse: {e}")))
        })
        .collect()
}

/// The ticket `signer` took for `election_id`.
///
/// # Errors
/// A store failure.
pub async fn ticket(
    ks: &KeyspaceHandle,
    election_id: &str,
    signer: &str,
) -> Result<Option<TicketIssued>, AppError> {
    ks.get(ticket_key(election_id, signer)).await
}

/// Record a ticket. `false` when `signer` already holds one for the election.
///
/// # Errors
/// A store failure.
pub async fn put_ticket(ks: &KeyspaceHandle, t: &TicketIssued) -> Result<bool, AppError> {
    ks.insert_if_absent(ticket_key(&t.election_id, &t.signer), t)
        .await
}

/// Every ticket of one election (to discard stored pre-credentials after voting closes).
///
/// # Errors
/// A store failure, or a record that does not parse.
pub async fn tickets(
    ks: &KeyspaceHandle,
    election_id: &str,
) -> Result<Vec<TicketIssued>, AppError> {
    ks.prefix_iter_raw(format!("{TICKET_PREFIX}{election_id}:"))
        .await?
        .into_iter()
        .map(|(_, v)| {
            serde_json::from_slice(&v)
                .map_err(|e| AppError::Internal(format!("a ticket record does not parse: {e}")))
        })
        .collect()
}

/// Overwrite a ticket record (to discard its pre-credential).
///
/// # Errors
/// A store failure.
pub async fn replace_ticket(ks: &KeyspaceHandle, t: &TicketIssued) -> Result<(), AppError> {
    ks.insert(ticket_key(&t.election_id, &t.signer), t).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn record(now: DateTime<Utc>) -> ElectionRecord {
        ElectionRecord {
            election_id: "agm".into(),
            manifest: Value::Null,
            manifest_digest: "z".into(),
            standing: Standing::Registered,
            binding: false,
            ballot_box: "did:key:z6MkBox".into(),
            registration_opens: now + Duration::days(1),
            voting_opens: now + Duration::days(2),
            voting_closes: now + Duration::days(3),
            created_by: "did:key:z6MkAdmin".into(),
            created_at: now,
            action_id: None,
            issuance_stopped: false,
            close_in_flight: false,
            tickets_issued: 0,
            delivery: None,
            refusal: None,
            checkpoints: Vec::new(),
            final_checkpoint: false,
            certified: None,
            election_key: None,
        }
    }

    #[test]
    fn a_registered_election_reads_its_state_off_the_clock() {
        let now = Utc::now();
        let r = record(now);
        assert_eq!(r.state(now), "registered");
        assert_eq!(r.state(now + Duration::hours(25)), "registration");
        assert_eq!(r.state(now + Duration::hours(49)), "voting");
        assert_eq!(r.state(now + Duration::hours(73)), "closed");
        let cancelled = ElectionRecord {
            standing: Standing::Cancelled,
            ..r
        };
        assert_eq!(cancelled.state(now + Duration::hours(49)), "cancelled");
    }

    #[test]
    fn ticket_keys_separate_elections_and_signers() {
        assert_ne!(ticket_key("a", "did:x"), ticket_key("a", "did:y"));
        assert_ne!(ticket_key("a", "did:x"), ticket_key("b", "did:x"));
        assert!(ticket_key("a", "did:x").starts_with("ticket:a:"));
    }
}
