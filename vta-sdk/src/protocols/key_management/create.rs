use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::keys::{KeyOrigin, KeyStatus, KeyType};

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateKeyBody {
    #[serde(alias = "key_type")]
    pub key_type: KeyType,
    /// Durable identifier to give the new key.
    ///
    /// Optional: for a derived key the maintainer defaults it to
    /// `derivation_path`, which is what this workspace does. It is **not**
    /// optional in practice for `internal: true` — such a key has no
    /// derivation path to be named after — which is the gap that put it in
    /// `keys/create/0.1` (dtgwg-trust-tasks-tf#275, `trust-tasks-rs` 0.12.1).
    #[serde(default, alias = "key_id", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Optional, as `keys/create/0.1` says: "omitting it leaves the choice to
    /// the custodian".
    ///
    /// It was a required `String` here, so a conforming client that omitted it
    /// got `malformedRequest` — and `VtaClient::create_key` papered over that
    /// by sending `""`, which the operation layer then treats as absent. The
    /// operation layer was always right: `CreateKeyParams::derivation_path` is
    /// an `Option` and auto-derives from the context when unset. Only this wire
    /// type disagreed, and it is also incoherent with `internal`, which derives
    /// from no seed and records no path at all.
    #[serde(
        default,
        alias = "derivation_path",
        skip_serializing_if = "Option::is_none"
    )]
    pub derivation_path: Option<String>,
    /// An unset member must be **absent**, never `null` — `keys/create/0.1`
    /// types each of these as `"string"`, and none of them accepts null. See
    /// the `an_unset_member_is_absent_from_the_wire_not_null` test below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, alias = "context_id", skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Mint a **non-extractable internal key** rather than a derived one.
    ///
    /// Absent or `false` keeps today's behaviour exactly. `true` mints a key
    /// from the system CSPRNG that is never exported, never backed up, and
    /// **cannot be recovered** — see `vta_keys::internal`.
    ///
    /// Published in `keys/create/0.1` as of `trust-tasks-rs` 0.11.17
    /// (dtgwg-trust-tasks-tf#269). Before that the request schema was
    /// `additionalProperties: false` with no such member, so the dispatch
    /// spine rejected any document carrying it — the capability existed at
    /// both ends and was unreachable over the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,
}

// Manual Debug — `mnemonic` is the BIP-39 phrase that recovers the
// key being imported. Redact via `{:?}` so any tracing call site or
// panic-with-debug can't leak it. Serialize is unchanged.
impl std::fmt::Debug for CreateKeyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateKeyBody")
            .field("key_type", &self.key_type)
            .field("derivation_path", &self.derivation_path)
            .field("mnemonic", &self.mnemonic.as_ref().map(|_| "<redacted>"))
            .field("label", &self.label)
            .field("context_id", &self.context_id)
            .finish()
    }
}

/// The realized key record, in the canonical camelCase shape. A strict subset
/// of `keys/_shared/0.1/key-record#KeyRecord`'s members, so it validates as one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateKeyResultBody {
    #[serde(alias = "key_id")]
    pub key_id: String,
    #[serde(alias = "key_type")]
    pub key_type: KeyType,
    #[serde(alias = "derivation_path")]
    pub derivation_path: String,
    #[serde(alias = "public_key")]
    pub public_key: String,
    pub status: KeyStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default = "default_derived")]
    pub origin: KeyOrigin,
    #[serde(alias = "created_at")]
    pub created_at: DateTime<Utc>,
}

/// `keys/create/0.1` response — the realized record under `key`.
///
/// Nested rather than flattened because the canonical `keys/*` family carries
/// one record shape across create, show and import, so a consumer comparing
/// records between them cannot end up looking at two spellings of the same
/// thing. Mirrors `acl/*`'s `{ entry }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateKeyResponseBody {
    pub key: CreateKeyResultBody,
}

fn default_derived() -> KeyOrigin {
    KeyOrigin::Derived
}

#[cfg(test)]
mod null_member_tests {
    use super::*;

    /// The bug this skip fixes, pinned.
    ///
    /// `keys/create/0.1` types every optional member — `mnemonic`, `label`,
    /// `contextId`, `derivationPath` — as `"string"`. None of them accepts
    /// null, so serialising `None` as `null` failed schema validation the
    /// moment the payload reached a maintainer:
    ///
    /// ```text
    /// malformed request: payload does not conform to
    /// https://trusttasks.org/spec/keys/create/0.1: payload failed schema
    /// validation: null is not of type "string"
    /// ```
    ///
    /// Every caller that mints a key without a BIP-39 phrase — which is every
    /// caller that is not importing external seed material — sent
    /// `"mnemonic": null` and was refused. That is the whole of `keys/create`
    /// over the trust-task transports, so an OpenVTC persona mint could not
    /// get past its first key. The REST leg was unaffected: it serialises
    /// [`CreateKeyRequest`](crate::client::CreateKeyRequest), which already
    /// skipped its `None`s.
    ///
    /// Same defect, same shape, as `did_management::update`'s
    /// `an_unset_field_is_absent_from_the_wire_not_null` — the canonical-body
    /// fold reintroduced it on a different task.
    #[test]
    fn an_unset_member_is_absent_from_the_wire_not_null() {
        // What `create_key` builds for a plain, unlabelled, uncontexted key.
        let minimal = CreateKeyBody {
            internal: None,
            key_type: KeyType::Ed25519,
            key_id: None,
            derivation_path: None,
            mnemonic: None,
            label: None,
            context_id: None,
        };

        assert_eq!(
            serde_json::to_value(&minimal).expect("serialises"),
            serde_json::json!({"keyType": "ed25519"}),
            "an unset member must be absent — not null, and not an empty \
             string. This assertion used to require `derivationPath: \"\"`, \
             which contradicted the test's own name: the empty string is a \
             value the caller never chose, and it reached the wire only \
             because the member was a required `String` here while the \
             specification and the operation layer both make it optional."
        );
    }

    /// A set member still reaches the wire under its canonical camelCase name
    /// — the skip must not be reachable for `Some`.
    #[test]
    fn a_set_member_still_serialises() {
        let labelled = CreateKeyBody {
            internal: None,
            key_type: KeyType::Ed25519,
            key_id: None,
            derivation_path: Some("m/26'/2'/0'/1'".into()),
            mnemonic: None,
            label: Some("persona-signing".into()),
            context_id: Some("openvtc".into()),
        };

        assert_eq!(
            serde_json::to_value(&labelled).expect("serialises"),
            serde_json::json!({
                "keyType": "ed25519",
                "derivationPath": "m/26'/2'/0'/1'",
                "label": "persona-signing",
                "contextId": "openvtc",
            })
        );
    }
}
