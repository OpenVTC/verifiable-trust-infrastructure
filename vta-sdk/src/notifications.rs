//! Notifications (`notifications/notify/0.1`, `notifications/relay/0.1`, VTI-NTF-001 – 063):
//! verifying a delivered notification layer by layer, and building one.
//!
//! A notification is a signed statement by an **originator**, addressed to one DID, that a
//! thing exists which the addressee — or the parties it stands for — may take part in. A party
//! that stands for others passes it on with a **relay** that carries the document it received
//! exactly as received, proof included. A final recipient therefore holds the originator's own
//! signature and every relayer's, and checks them all ([`verify_delivery`]).
//!
//! # The typestate
//!
//! [`verify_delivery`] is the only way to a [`VerifiedDelivery`]: a call site that reads a
//! notification's members without verifying the chain does not compile. It checks what
//! `notifications/relay` consumer item 2 lists (VTI-NTF-042) — every layer's `type`, its payload
//! against the pinned schema, that its proof verifies as its own `issuer` over the JSON as
//! received, that each forwarded document is addressed to the relay carrying it, at most
//! [`MAX_RELAYS`] relays in all, and that a relayed notification says it may be relayed.
//!
//! What it does **not** check is the outermost layer's acceptance window, `expiresAt` and
//! `recipient`: those are the receiving node's own §7.2 checks on the document it was sent, and
//! a service's dispatch spine has applied them before a handler runs. The forwarded documents'
//! windows are deliberately never re-applied: they bound when each could be delivered to its own
//! recipient, not how long it remains evidence of what was said.
//!
//! A notification confers no authority and is no evidence of eligibility (VTI-NTF-004). A
//! verified delivery proves who said a thing exists and who passed the message on — nothing
//! about whether anyone may take part in it.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_specs::notifications::notify::v0_1 as notify;

use crate::trust_task_proof::{TrustTaskVmResolver, verify_trust_task_proof_value};
use crate::trust_tasks::{TASK_NOTIFICATIONS_NOTIFY_0_1, TASK_NOTIFICATIONS_RELAY_0_1};

/// The most relays one delivery may carry, counting its own outermost layer (VTI-NTF-042):
/// a network, a community it lists, a group of that community, the group's member — with one
/// to spare.
pub const MAX_RELAYS: usize = 4;

/// The registered notification kind for an election (Appendix G, VTI-NTF-060).
pub const KIND_ELECTION: &str = "election";

/// The task that opens a notified election (VTI-NTF-060).
pub const ELECTION_OPEN_WITH: &str = "https://trusttasks.org/spec/vtc/elections/show/0.6";

/// Whether this build recognises `kind` (VTI-NTF-012): a recipient does nothing with an
/// unrecognised kind beyond holding, listing and discarding it.
#[must_use]
pub fn is_recognised_kind(kind: &str) -> bool {
    kind == KIND_ELECTION
}

/// Whether a registered kind's definition lets it be relayed (Appendix G). An unregistered
/// kind (`<domain>:<name>`) is relayable as far as this registry knows: the notification's own
/// `relayable` decides.
#[must_use]
pub fn kind_may_be_relayed(kind: &str) -> bool {
    // Every kind registered in Appendix G today may be relayed (`election` among them); a
    // kind registered as not relayable is refused here.
    let _ = kind;
    true
}

/// What relaying a notification of `kind` discloses about the relayer, for whoever decides
/// the relay to be shown first (VTI-NTF-046). `None` when its definition says a relay
/// discloses nothing about the relayer, or the kind is not registered here.
#[must_use]
pub fn relay_disclosure(kind: &str) -> Option<&'static str> {
    match kind {
        KIND_ELECTION => Some(
            "Relaying this notification shows each party it is relayed to that you are a \
             member of the community holding the election — which your own listing in that \
             community's directory may otherwise keep from them (VTI-NTF-046, VTI-DIR-040).",
        ),
        _ => None,
    }
}

/// Why a delivered document is not a notification this recipient may hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// The outermost document is neither a notify nor a relay, or is not a Trust Task document.
    #[error("not a notification: {0}")]
    NotANotification(String),
    /// A layer fails its type's pinned schema.
    #[error("layer {layer} does not validate as a document of its type: {reason}")]
    Invalid { layer: usize, reason: String },
    /// A layer's proof does not verify, or verifies as a DID other than its `issuer`.
    #[error("layer {layer}'s proof does not hold: {reason}")]
    Proof { layer: usize, reason: String },
    /// A forwarded document is not addressed to the issuer of the relay carrying it.
    #[error("layer {layer} is not addressed to the relayer that forwarded it")]
    Misaddressed { layer: usize },
    /// More than [`MAX_RELAYS`] relays in all.
    #[error("the relay carries more than {MAX_RELAYS} relays")]
    TooDeep,
    /// A relayed notification says it may not be relayed, or its kind may not be.
    #[error("the notification may not be relayed")]
    NotRelayable,
}

impl ChainError {
    /// Whether the refusal is `notifications/relay:chainInvalid` — a layer inside a relay
    /// failed — rather than the outermost document itself failing its own checks.
    #[must_use]
    pub fn is_chain_invalid(&self) -> bool {
        match self {
            ChainError::Invalid { layer, .. } | ChainError::Proof { layer, .. } => *layer > 0,
            ChainError::Misaddressed { .. } | ChainError::TooDeep | ChainError::NotRelayable => {
                true
            }
            ChainError::NotANotification(_) => false,
        }
    }
}

/// A delivered notification whose every layer verified. Constructed only by
/// [`verify_delivery`].
#[derive(Debug, Clone)]
pub struct VerifiedDelivery {
    originator: String,
    addressee: String,
    relayed_by: Vec<String>,
    notification: notify::Notification,
    notification_json: Value,
    document: Value,
}

impl VerifiedDelivery {
    /// The originator: the innermost `notifications/notify` document's `issuer`, whose proof
    /// verified.
    #[must_use]
    pub fn originator(&self) -> &str {
        &self.originator
    }

    /// The outermost document's `recipient`: the party this delivery was addressed to.
    #[must_use]
    pub fn addressee(&self) -> &str {
        &self.addressee
    }

    /// The relayers, in the order they relayed: the first is the notification's own addressee,
    /// the last the party that delivered it. Empty for a notification sent directly.
    #[must_use]
    pub fn relayed_by(&self) -> &[String] {
        &self.relayed_by
    }

    /// The party whose standing an acceptance policy counts (VTI-NTF-031): the last relayer,
    /// or the originator for a notification sent directly.
    #[must_use]
    pub fn delivered_by(&self) -> &str {
        self.relayed_by.last().unwrap_or(&self.originator)
    }

    /// The notification's members, typed.
    #[must_use]
    pub fn notification(&self) -> &notify::Notification {
        &self.notification
    }

    /// The notification's members exactly as the originator signed them.
    #[must_use]
    pub fn notification_json(&self) -> &Value {
        &self.notification_json
    }

    /// The delivering document, whole, as received.
    #[must_use]
    pub fn document(&self) -> &Value {
        &self.document
    }

    /// The innermost `notifications/notify` document, as received.
    #[must_use]
    pub fn innermost(&self) -> &Value {
        let mut layer = &self.document;
        while layer["type"].as_str() == Some(TASK_NOTIFICATIONS_RELAY_0_1) {
            layer = &layer["payload"]["forwarded"];
        }
        layer
    }

    /// Whether it was relayed to its recipient.
    #[must_use]
    pub fn is_relayed(&self) -> bool {
        !self.relayed_by.is_empty()
    }
}

/// The identity a DID reference names, for comparing originators, relayers and addressees
/// (VTI-KEY-160 – 169): no fragment, and a `did:scid` without its `src`.
#[must_use]
pub fn identity(did: &str) -> String {
    crate::did_scid::identity(did)
}

/// Verify a delivered `notifications/notify/0.1` or `notifications/relay/0.1` document, every
/// layer of it (VTI-NTF-042). See the module docs for what is, and is not, checked.
pub async fn verify_delivery(
    document: &Value,
    resolver: &TrustTaskVmResolver,
) -> Result<VerifiedDelivery, ChainError> {
    let outer_type = document["type"].as_str().unwrap_or_default();
    if outer_type != TASK_NOTIFICATIONS_NOTIFY_0_1 && outer_type != TASK_NOTIFICATIONS_RELAY_0_1 {
        return Err(ChainError::NotANotification(format!(
            "`{outer_type}` is neither notifications/notify/0.1 nor notifications/relay/0.1"
        )));
    }
    let addressee = document["recipient"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| ChainError::Invalid {
            layer: 0,
            reason: "the document names no recipient".into(),
        })?;

    // Outermost first: layer 0 is the document received.
    let mut relayers_outer_first: Vec<String> = Vec::new();
    let mut layer = document;
    let mut depth = 0usize;
    loop {
        let doc = check_layer(layer, depth, resolver).await?;
        let issuer = doc.issuer.clone().unwrap_or_default();
        if doc.type_uri.to_string() == TASK_NOTIFICATIONS_NOTIFY_0_1 {
            let notification_json = layer["payload"]["notification"].clone();
            let notification: notify::Notification =
                serde_json::from_value(notification_json.clone()).map_err(|e| {
                    ChainError::Invalid {
                        layer: depth,
                        reason: e.to_string(),
                    }
                })?;
            if depth > 0 && (!notification.relayable || !kind_may_be_relayed(&notification.kind)) {
                return Err(ChainError::NotRelayable);
            }
            relayers_outer_first.reverse();
            return Ok(VerifiedDelivery {
                originator: issuer,
                addressee,
                relayed_by: relayers_outer_first,
                notification,
                notification_json,
                document: document.clone(),
            });
        }
        // A relay.
        relayers_outer_first.push(issuer.clone());
        if relayers_outer_first.len() > MAX_RELAYS {
            return Err(ChainError::TooDeep);
        }
        let forwarded = &layer["payload"]["forwarded"];
        let inner_type = forwarded["type"].as_str().unwrap_or_default();
        if inner_type != TASK_NOTIFICATIONS_NOTIFY_0_1 && inner_type != TASK_NOTIFICATIONS_RELAY_0_1
        {
            return Err(ChainError::Invalid {
                layer: depth + 1,
                reason: format!("a relay may forward only a notify or a relay, not `{inner_type}`"),
            });
        }
        let inner_recipient = forwarded["recipient"].as_str().unwrap_or_default();
        if identity(inner_recipient) != identity(&issuer) {
            return Err(ChainError::Misaddressed { layer: depth + 1 });
        }
        layer = forwarded;
        depth += 1;
    }
}

/// One layer: a Trust Task document of its type, valid against the pinned schema, whose proof
/// verifies as its own `issuer` over the JSON as received.
async fn check_layer(
    layer: &Value,
    depth: usize,
    resolver: &TrustTaskVmResolver,
) -> Result<TrustTask<Value>, ChainError> {
    let invalid = |reason: String| ChainError::Invalid {
        layer: depth,
        reason,
    };
    let doc: TrustTask<Value> =
        serde_json::from_value(layer.clone()).map_err(|e| invalid(e.to_string()))?;
    let type_uri = doc.type_uri.to_string();
    let schema = vti_specs::schema_index::schema_for(&type_uri)
        .ok_or_else(|| invalid(format!("`{type_uri}` is not pinned by this build")))?;
    trust_tasks_rs::validate::against_schema(schema, &doc.payload)
        .map_err(|e| invalid(e.to_string()))?;
    let issuer = doc
        .issuer
        .as_deref()
        .ok_or_else(|| invalid("the document names no issuer".into()))?;
    if doc.proof.is_none() {
        return Err(ChainError::Proof {
            layer: depth,
            reason: "the document carries no proof".into(),
        });
    }
    let signer = verify_trust_task_proof_value(layer, resolver)
        .await
        .map_err(|e| ChainError::Proof {
            layer: depth,
            reason: e.to_string(),
        })?;
    if identity(&signer) != identity(issuer) {
        return Err(ChainError::Proof {
            layer: depth,
            reason: "the proof verifies as a DID other than the document's issuer".into(),
        });
    }
    Ok(doc)
}
