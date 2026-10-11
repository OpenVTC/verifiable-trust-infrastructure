//! The stored account, and its projection onto the wire.
//!
//! [`AccountRecord`] is a **storage record**, not a wire type. The wire shape is
//! `ExternalAccount` from `trust_tasks_rs::specs::external::*` (one copy per
//! task module, as the code generator emits them); [`AccountRecord::to_wire`]
//! renders the JSON every one of those copies parses, and the handlers
//! deserialize it into the generated type of the task they answer. Keeping the
//! record separate is what lets it carry what the wire never shows — which seed
//! generation wrapped the secret — without a wire type growing a member.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// `active`, `suspended` or `archived` — `AccountState` in the shared schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountState {
    Active,
    Suspended,
    Archived,
}

impl AccountState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Archived => "archived",
        }
    }
}

/// The widest scope a binding's consumer may request (`CredentialScopeCeiling`).
/// Absent members confer nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeCeiling {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

/// Who may use an account, and how far (`AccountBinding`). One per consumer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Binding {
    pub consumer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_ceiling: Option<ScopeCeiling>,
    pub max_ttl_seconds: u32,
    pub rate_per_minute: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_at: Option<DateTime<Utc>>,
}

/// What the record says about a stored secret. The value itself lives in the
/// `external_secrets` keyspace, wrapped; it is never in this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretInfo {
    pub fingerprint: String,
    pub set_at: DateTime<Utc>,
    /// The seed generation whose KEK wrapped it. Internal: a seed rotation
    /// keeps every generation, so the secret opens under the generation that
    /// sealed it.
    pub seed_id: u32,
}

/// One external account as the custodian stores it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRecord {
    pub id: String,
    pub label: String,
    pub context: String,
    /// The validated wire `AccountSettings` (it carries `model`). Never a
    /// secret: the schema has nowhere to put one.
    pub settings: Value,
    pub state: AccountState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_material: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretInfo>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    pub provider_setup_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_probe: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AccountRecord {
    /// The account's auth model, from its settings.
    pub fn model(&self) -> &str {
        model_of(&self.settings)
    }

    /// The binding naming `consumer`, if any.
    pub fn binding_for(&self, consumer: &str) -> Option<&Binding> {
        self.bindings.iter().find(|b| b.consumer == consumer)
    }

    /// The account as the wire's `ExternalAccount` JSON. Never a secret, a
    /// private key or a seed generation.
    pub fn to_wire(&self, egress_hosts: &[String]) -> Value {
        let mut out = json!({
            "id": self.id,
            "label": self.label,
            "context": self.context,
            "settings": self.settings,
            "state": self.state.as_str(),
            "bindings": self.bindings,
            "egressHosts": egress_hosts,
            "providerSetupRequired": self.provider_setup_required,
            "createdAt": rfc3339(self.created_at),
            "updatedAt": rfc3339(self.updated_at),
        });
        if let Some(pm) = &self.public_material {
            out["publicMaterial"] = pm.clone();
        }
        if let Some(secret) = &self.secret {
            out["secret"] = json!({
                "fingerprint": secret.fingerprint,
                "setAt": rfc3339(secret.set_at),
            });
        }
        if let Some(probe) = &self.last_probe {
            out["lastProbe"] = probe.clone();
        }
        // `grantedAt` is a date-time in the schema; chrono's default form is
        // RFC 3339 already, but render it the same way as every other instant.
        if let Some(bindings) = out["bindings"].as_array_mut() {
            for (wire, b) in bindings.iter_mut().zip(&self.bindings) {
                if let Some(at) = b.granted_at {
                    wire["grantedAt"] = Value::String(rfc3339(at));
                }
            }
        }
        out
    }
}

/// The `model` member of a settings object; empty if absent.
pub fn model_of(settings: &Value) -> &str {
    settings.get("model").and_then(Value::as_str).unwrap_or("")
}

/// RFC 3339 with whole seconds and a `Z`, the form every instant in the family
/// is written in.
pub fn rfc3339(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> AccountRecord {
        let now = DateTime::parse_from_rfc3339("2026-10-10T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        AccountRecord {
            id: "r2-main".into(),
            label: "R2".into(),
            context: "community".into(),
            settings: json!({"model": "s3-static-presign", "endpoint": "https://x.r2.cloudflarestorage.com",
                "region": "auto", "bucket": "rooms", "accessKeyId": "AKID"}),
            state: AccountState::Active,
            public_material: None,
            secret: Some(SecretInfo {
                fingerprint: "zQmFingerprint".into(),
                set_at: now,
                seed_id: 3,
            }),
            bindings: vec![Binding {
                consumer: "did:key:z6Mkconsumer".into(),
                scope_ceiling: Some(ScopeCeiling {
                    prefixes: vec!["rooms/".into()],
                    actions: vec!["get".into()],
                    scopes: vec![],
                }),
                max_ttl_seconds: 900,
                rate_per_minute: 60,
                source_cidrs: vec![],
                granted_at: Some(now),
            }],
            provider_setup_required: false,
            last_probe: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// The seed generation stays in the record and never reaches the wire.
    #[test]
    fn the_wire_form_carries_no_seed_generation_and_no_secret() {
        let wire = record().to_wire(&[]);
        assert_eq!(wire["secret"]["fingerprint"], "zQmFingerprint");
        assert!(wire["secret"].get("seedId").is_none(), "{wire}");
        assert_eq!(wire["bindings"][0]["grantedAt"], "2026-10-10T09:00:00Z");
        assert_eq!(wire["state"], "active");
        assert_eq!(record().model(), "s3-static-presign");
    }

    #[test]
    fn a_record_round_trips_through_storage() {
        let r = record();
        let back: AccountRecord =
            serde_json::from_value(serde_json::to_value(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }
}
