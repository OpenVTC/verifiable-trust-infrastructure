//! Consent store — records + KV helpers for VTA-gated inbound messaging.
//!
//! Generic across platforms / agents / interaction kinds (see the `consent/*`
//! Trust Task family). A messaging bridge asks the VTA to gate a conversation
//! (**default-deny**); an approver's decision is recorded as a [`ConsentGrant`]
//! the bridge then enforces. The pending-request store mirrors the step-up
//! pattern in [`crate::auth::step_up`] (challenge-keyed, single-use, TTL'd).

use serde::{Deserialize, Serialize};

use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Interaction kind — a 1:1 DM, a multi-party group, or a broadcast channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConsentKind {
    Dm,
    Group,
    Channel,
}

/// What the agent may do on a conversation: read inbound, or read and reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConsentScope {
    Receive,
    Converse,
}

/// Allow or deny. The ABSENCE of a grant is treated as deny (default-deny).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConsentEffect {
    Allow,
    Deny,
}

/// Platform-agnostic identifier of WHAT consent is about: one conversation, for
/// one agent. `conversation_ref` is the bridge's OPAQUE handle — never a raw
/// platform address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentSubject {
    pub platform: String,
    pub conversation_ref: String,
    pub kind: ConsentKind,
    pub agent: String,
}

impl ConsentSubject {
    /// Storage key for a grant over this subject. Unit-separator (`\x1f`) joined
    /// so the colons in `agent` (a DID) can't collide with the field delimiter.
    fn grant_key(&self) -> String {
        format!(
            "grant:{}\u{1f}{}\u{1f}{}",
            self.platform, self.conversation_ref, self.agent
        )
    }
}

/// A recorded consent decision over a [`ConsentSubject`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentGrant {
    pub subject: ConsentSubject,
    pub effect: ConsentEffect,
    /// Granted scope; present when `effect == Allow`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scope: Option<ConsentScope>,
    /// VID of the approver who made the decision.
    pub granted_by: String,
    pub granted_at: u64,
    /// Optional TTL; after this the grant lapses and the subject re-consents.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<u64>,
    /// How the decision was authorized, e.g. `"did-signed"` | `"bridge-attested"`.
    pub evidence: String,
}

impl ConsentGrant {
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|e| now >= e)
    }

    /// Effective allow: an `allow` grant that has not expired.
    pub fn allows(&self, now: u64) -> bool {
        self.effect == ConsentEffect::Allow && !self.is_expired(now)
    }
}

/// A pending consent request awaiting an approver decision. Keyed by challenge,
/// single-use, TTL'd — mirrors [`crate::auth::step_up::PendingStepUp`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingConsent {
    pub subject: ConsentSubject,
    pub scope: ConsentScope,
    pub challenge: String,
    /// The bridge DID that raised the request.
    pub requested_by: String,
    /// The VTA context the subject was scoped to (drives approver resolution).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub context: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
}

fn pending_key(challenge: &str) -> String {
    format!("consent_pending:{challenge}")
}

/// Outcome of consuming a pending consent by challenge.
#[derive(Debug, PartialEq)]
pub enum ConsumeConsent {
    NotFound,
    Expired,
    Found(Box<PendingConsent>),
}

// ── Grants ───────────────────────────────────────────────────────────────────

/// Store (upsert) a consent grant keyed by its subject.
pub async fn store_consent_grant(
    ks: &KeyspaceHandle,
    grant: &ConsentGrant,
) -> Result<(), AppError> {
    ks.insert(grant.subject.grant_key(), grant).await
}

/// Read the grant for a subject, if any.
pub async fn get_consent_grant(
    ks: &KeyspaceHandle,
    subject: &ConsentSubject,
) -> Result<Option<ConsentGrant>, AppError> {
    ks.get(subject.grant_key()).await
}

/// Delete the grant for a subject (revert to default-deny).
pub async fn delete_consent_grant(
    ks: &KeyspaceHandle,
    subject: &ConsentSubject,
) -> Result<(), AppError> {
    ks.remove(subject.grant_key()).await
}

/// All grants. Callers filter by agent / platform / subject in memory.
pub async fn list_consent_grants(ks: &KeyspaceHandle) -> Result<Vec<ConsentGrant>, AppError> {
    let rows = ks.prefix_iter_raw("grant:").await?;
    let mut out = Vec::with_capacity(rows.len());
    for (_key, value) in rows {
        match serde_json::from_slice::<ConsentGrant>(&value) {
            Ok(g) => out.push(g),
            Err(e) => tracing::warn!(error = %e, "skipping undeserializable consent grant"),
        }
    }
    Ok(out)
}

// ── Pending ──────────────────────────────────────────────────────────────────

/// Store a pending consent keyed by its challenge.
pub async fn store_pending_consent(
    ks: &KeyspaceHandle,
    pending: &PendingConsent,
) -> Result<(), AppError> {
    ks.insert(pending_key(&pending.challenge), pending).await
}

/// Locate and **consume** the pending consent matching `challenge` (single-use).
pub async fn consume_pending_consent(
    ks: &KeyspaceHandle,
    challenge: &str,
    now: u64,
) -> Result<ConsumeConsent, AppError> {
    let key = pending_key(challenge);
    let Some(pending): Option<PendingConsent> = ks.get(key.clone()).await? else {
        return Ok(ConsumeConsent::NotFound);
    };
    ks.remove(key).await?; // single-use, live or expired
    if now >= pending.expires_at {
        return Ok(ConsumeConsent::Expired);
    }
    Ok(ConsumeConsent::Found(Box::new(pending)))
}

/// Build a pending consent expiring `ttl_secs` from now.
pub fn new_pending_consent(
    subject: ConsentSubject,
    scope: ConsentScope,
    challenge: impl Into<String>,
    requested_by: impl Into<String>,
    context: Option<String>,
    ttl_secs: u64,
) -> PendingConsent {
    let created_at = now_epoch();
    PendingConsent {
        subject,
        scope,
        challenge: challenge.into(),
        requested_by: requested_by.into(),
        context,
        created_at,
        expires_at: created_at + ttl_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    fn subject() -> ConsentSubject {
        ConsentSubject {
            platform: "signal".into(),
            conversation_ref: "sig-1a2b3c4d".into(),
            kind: ConsentKind::Group,
            agent: "did:key:z6MkAgent".into(),
        }
    }

    async fn ks() -> KeyspaceHandle {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir = Box::leak(Box::new(dir)); // outlive the test
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        store.keyspace("consent").expect("keyspace")
    }

    fn grant(effect: ConsentEffect) -> ConsentGrant {
        ConsentGrant {
            subject: subject(),
            effect,
            scope: matches!(effect, ConsentEffect::Allow).then_some(ConsentScope::Converse),
            granted_by: "did:web:operator".into(),
            granted_at: 1_000,
            expires_at: None,
            evidence: "bridge-attested".into(),
        }
    }

    #[tokio::test]
    async fn grant_store_get_delete_round_trip() {
        let ks = ks().await;
        // Default-deny: nothing stored yet.
        assert!(get_consent_grant(&ks, &subject()).await.unwrap().is_none());

        let g = grant(ConsentEffect::Allow);
        store_consent_grant(&ks, &g).await.unwrap();
        assert_eq!(get_consent_grant(&ks, &subject()).await.unwrap(), Some(g));

        delete_consent_grant(&ks, &subject()).await.unwrap();
        assert!(get_consent_grant(&ks, &subject()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_returns_all_grants() {
        let ks = ks().await;
        store_consent_grant(&ks, &grant(ConsentEffect::Allow))
            .await
            .unwrap();
        let mut other = grant(ConsentEffect::Deny);
        other.subject.conversation_ref = "sig-99999999".into();
        store_consent_grant(&ks, &other).await.unwrap();
        assert_eq!(list_consent_grants(&ks).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn pending_consume_is_single_use_and_ttl_aware() {
        let ks = ks().await;
        let p = new_pending_consent(
            subject(),
            ConsentScope::Converse,
            "chal-1",
            "did:webvh:bridge",
            None,
            300,
        );
        store_pending_consent(&ks, &p).await.unwrap();

        // Live match → Found, and consumed (single-use).
        match consume_pending_consent(&ks, "chal-1", p.created_at + 1)
            .await
            .unwrap()
        {
            ConsumeConsent::Found(found) => assert_eq!(found.subject, subject()),
            other => panic!("expected Found, got {other:?}"),
        }
        assert_eq!(
            consume_pending_consent(&ks, "chal-1", p.created_at + 1)
                .await
                .unwrap(),
            ConsumeConsent::NotFound,
        );

        // Expired match → Expired (and still removed).
        let p2 = new_pending_consent(subject(), ConsentScope::Receive, "chal-2", "b", None, 10);
        store_pending_consent(&ks, &p2).await.unwrap();
        assert_eq!(
            consume_pending_consent(&ks, "chal-2", p2.expires_at + 1)
                .await
                .unwrap(),
            ConsumeConsent::Expired,
        );
        assert_eq!(
            consume_pending_consent(&ks, "chal-2", p2.expires_at + 1)
                .await
                .unwrap(),
            ConsumeConsent::NotFound,
        );
    }

    #[test]
    fn allow_grant_is_effective_until_expiry() {
        let g = ConsentGrant {
            subject: subject(),
            effect: ConsentEffect::Allow,
            scope: Some(ConsentScope::Converse),
            granted_by: "did:web:operator".into(),
            granted_at: 1_000,
            expires_at: Some(2_000),
            evidence: "bridge-attested".into(),
        };
        assert!(g.allows(1_500));
        assert!(!g.allows(2_000)); // expired
        let deny = ConsentGrant {
            effect: ConsentEffect::Deny,
            scope: None,
            ..g.clone()
        };
        assert!(!deny.allows(1_500));
    }

    #[test]
    fn pending_ttl_is_set_from_now() {
        let p = new_pending_consent(
            subject(),
            ConsentScope::Converse,
            "chal",
            "did:webvh:bridge",
            Some("ctx".into()),
            300,
        );
        assert_eq!(p.expires_at, p.created_at + 300);
    }

    #[test]
    fn grant_round_trips_through_json() {
        let g = ConsentGrant {
            subject: subject(),
            effect: ConsentEffect::Allow,
            scope: Some(ConsentScope::Receive),
            granted_by: "did:web:operator".into(),
            granted_at: 42,
            expires_at: None,
            evidence: "did-signed".into(),
        };
        let s = serde_json::to_string(&g).unwrap();
        assert_eq!(serde_json::from_str::<ConsentGrant>(&s).unwrap(), g);
    }
}
