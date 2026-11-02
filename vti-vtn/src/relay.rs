//! Broadcast envelopes and their relay hops.
//!
//! A broadcast is a **message** signed by the network that sends it, plus one signed
//! **hop** per delivery step:
//!
//! ```text
//! envelope = { message: <signed by origin>, hops: [<hop 1 signed by origin>, <hop 2 signed by the
//!              network that owns hop 1's group>, …] }
//! ```
//!
//! Each hop names the group it delivers to. The next hop must be signed by the network that
//! owns that group, so the chain shows exactly who relayed what to whom, and the message
//! keeps its origin's signature end to end. This is the messaging form of "nesting must
//! not flatten" (VTI-VTN-032/033): a recipient sees
//! *WHN → Health-AU → Health-NSW → St Vincent's admins*, not one global claim.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{Result, VtnError};
use crate::groups::network_of_group;
use crate::identity::Identity;
use crate::verify::{ASSERTION_METHOD, KeyResolver, verify_document};

pub const MESSAGE_TYPE: &str = "VtnBroadcast";
pub const HOP_TYPE: &str = "VtnRelayHop";
/// Default limit on hops, matching the DTG attenuation depth.
pub const DEFAULT_MAX_HOPS: usize = 8;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Envelope {
    pub message: Value,
    pub hops: Vec<Value>,
}

/// What the sender wants to say.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub role: String,
    /// e.g. `notice`, `request-for-action`, `room-invite`.
    #[serde(default = "default_class")]
    pub class: String,
    pub subject: String,
    pub body: String,
    /// Where replies go (e.g. a network data room), so a broadcast never becomes reply-all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

fn default_class() -> String {
    "notice".into()
}

/// A verified envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub id: String,
    pub origin: String,
    /// The network that delivered it here (the last hop's signer).
    pub from: String,
    /// The group the last hop delivered to.
    pub to: String,
    pub hops: usize,
}

/// The origin network signs a new message.
pub async fn new_message(
    origin: &Identity,
    outgoing: &Outgoing,
    ttl: Duration,
    sent_at: DateTime<Utc>,
) -> Result<Value> {
    let mut message = json!({
        "type": MESSAGE_TYPE,
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "origin": origin.did(),
        "role": outgoing.role,
        "class": outgoing.class,
        "subject": outgoing.subject,
        "body": outgoing.body,
        "sentAt": sent_at,
        "expiresAt": sent_at + ttl,
    });
    if let Some(reply_to) = &outgoing.reply_to {
        message["replyTo"] = json!(reply_to);
    }
    origin.sign_document(message).await
}

/// `relayer` signs the hop that delivers `message_id` to `group`.
pub async fn new_hop(
    relayer: &Identity,
    message_id: &str,
    group: &str,
    role: &str,
    index: usize,
) -> Result<Value> {
    relayer
        .sign_document(json!({
            "type": HOP_TYPE,
            "message": message_id,
            "index": index,
            "from": relayer.did(),
            "to": group,
            "role": role,
            "at": Utc::now(),
        }))
        .await
}

fn field<'a>(doc: &'a Value, name: &str) -> Result<&'a str> {
    doc.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| VtnError::Rejected(format!("relay document has no `{name}`")))
}

/// Verify an envelope: the origin's signature, expiry, the hop limit, and an unbroken,
/// signed chain of hops from the origin to the last group.
pub async fn verify(
    envelope: &Envelope,
    resolver: &dyn KeyResolver,
    now: DateTime<Utc>,
    max_hops: usize,
) -> Result<Verified> {
    let message = &envelope.message;
    if field(message, "type")? != MESSAGE_TYPE {
        return Err(VtnError::Rejected(format!("expected a {MESSAGE_TYPE}")));
    }
    let id = field(message, "id")?.to_string();
    let origin = field(message, "origin")?.to_string();
    verify_document(message, &origin, ASSERTION_METHOD, resolver).await?;
    let expires: DateTime<Utc> = field(message, "expiresAt")?
        .parse()
        .map_err(|_| VtnError::Rejected("unreadable expiresAt".into()))?;
    if expires <= now {
        return Err(VtnError::Rejected("the message has expired".into()));
    }
    if envelope.hops.is_empty() {
        return Err(VtnError::Rejected("the envelope has no hops".into()));
    }
    if envelope.hops.len() > max_hops {
        return Err(VtnError::Rejected(format!(
            "the envelope has {} hops, over the limit of {max_hops}",
            envelope.hops.len()
        )));
    }

    let mut expected_from = origin.clone();
    let mut to = String::new();
    for (i, hop) in envelope.hops.iter().enumerate() {
        if field(hop, "type")? != HOP_TYPE || field(hop, "message")? != id {
            return Err(VtnError::Rejected(format!(
                "hop {i} is not for this message"
            )));
        }
        if hop.get("index").and_then(Value::as_u64) != Some(i as u64) {
            return Err(VtnError::Rejected(format!("hop {i} is out of order")));
        }
        let from = field(hop, "from")?;
        if from != expected_from {
            return Err(VtnError::Rejected(format!(
                "hop {i} is signed by {from}, but the previous hop delivered to {expected_from}"
            )));
        }
        verify_document(hop, from, ASSERTION_METHOD, resolver).await?;
        to = field(hop, "to")?.to_string();
        // The next hop, if any, must come from the network owning this group.
        expected_from = network_of_group(&to).unwrap_or(&to).to_string();
    }
    let from = field(envelope.hops.last().expect("checked non-empty"), "from")?.to_string();
    Ok(Verified {
        id,
        origin,
        from,
        to,
        hops: envelope.hops.len(),
    })
}

/// What happened to one delivery, reported back up the chain.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub group: String,
    pub member: String,
    pub status: DeliveryStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The group is a network group: the network relayed it on, and `relayed` holds the
    /// receipts of its own deliveries.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub network: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relayed: Vec<Receipt>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    /// Accepted by the group's endpoint.
    Delivered,
    /// Already seen there (another path got there first).
    Duplicate,
    /// The receiving network or group declined it.
    Refused,
    /// Could not be delivered yet; queued for retry.
    Queued,
    /// Could not be delivered, and retries are exhausted (or it was not retryable).
    Failed,
}

impl Receipt {
    /// Groups reached, counting through relays: a network group counts the groups it
    /// reached, not itself.
    pub fn reached(&self) -> usize {
        match self.status {
            DeliveryStatus::Delivered if self.network => {
                self.relayed.iter().map(Receipt::reached).sum()
            }
            DeliveryStatus::Delivered => 1,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::network_group_id;
    use crate::verify::LocalDidKeyResolver;

    fn outgoing() -> Outgoing {
        Outgoing {
            role: "admins".into(),
            class: "notice".into(),
            subject: "Drill".into(),
            body: "Exercise at 09:00".into(),
            reply_to: None,
        }
    }

    #[tokio::test]
    async fn a_three_level_chain_verifies() {
        let whn = Identity::generate();
        let au = Identity::generate();
        let message = new_message(&whn, &outgoing(), Duration::hours(1), Utc::now())
            .await
            .unwrap();
        let id = message["id"].as_str().unwrap().to_string();
        let au_group = network_group_id(au.did(), "admins");
        let mut env = Envelope {
            message,
            hops: vec![new_hop(&whn, &id, &au_group, "admins", 0).await.unwrap()],
        };
        let v = verify(&env, &LocalDidKeyResolver, Utc::now(), 8)
            .await
            .unwrap();
        assert_eq!(
            (v.from.as_str(), v.to.as_str()),
            (whn.did(), au_group.as_str())
        );

        env.hops.push(
            new_hop(&au, &id, "did:web:stv.example:admins", "admins", 1)
                .await
                .unwrap(),
        );
        let v = verify(&env, &LocalDidKeyResolver, Utc::now(), 8)
            .await
            .unwrap();
        assert_eq!(v.origin, whn.did());
        assert_eq!(v.from, au.did());
        assert_eq!(v.hops, 2);
        assert!(
            verify(&env, &LocalDidKeyResolver, Utc::now(), 1)
                .await
                .is_err(),
            "hop limit"
        );
    }

    #[tokio::test]
    async fn a_hop_by_a_network_that_was_not_delivered_to_is_refused() {
        let whn = Identity::generate();
        let au = Identity::generate();
        let interloper = Identity::generate();
        let message = new_message(&whn, &outgoing(), Duration::hours(1), Utc::now())
            .await
            .unwrap();
        let id = message["id"].as_str().unwrap().to_string();
        let env = Envelope {
            message,
            hops: vec![
                new_hop(
                    &whn,
                    &id,
                    &network_group_id(au.did(), "admins"),
                    "admins",
                    0,
                )
                .await
                .unwrap(),
                new_hop(&interloper, &id, "did:web:x", "admins", 1)
                    .await
                    .unwrap(),
            ],
        };
        assert!(
            verify(&env, &LocalDidKeyResolver, Utc::now(), 8)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn tampering_and_expiry_are_refused() {
        let whn = Identity::generate();
        let message = new_message(&whn, &outgoing(), Duration::hours(1), Utc::now())
            .await
            .unwrap();
        let id = message["id"].as_str().unwrap().to_string();
        let hop = new_hop(&whn, &id, "did:web:g", "admins", 0).await.unwrap();
        let mut tampered = Envelope {
            message: message.clone(),
            hops: vec![hop.clone()],
        };
        tampered.message["body"] = json!("Evacuate now");
        assert!(
            verify(&tampered, &LocalDidKeyResolver, Utc::now(), 8)
                .await
                .is_err()
        );
        let env = Envelope {
            message,
            hops: vec![hop],
        };
        assert!(
            verify(
                &env,
                &LocalDidKeyResolver,
                Utc::now() + Duration::hours(2),
                8
            )
            .await
            .is_err()
        );
    }
}
