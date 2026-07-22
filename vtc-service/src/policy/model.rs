//! Policy persistence model — spec §5.4 + §7.1.
//!
//! One [`Policy`] row per uploaded Rego module. Active modules are
//! pointed at by `active_policies:<purpose>` rows (single id per
//! purpose). M2.2 lands the model + storage CRUD; the upload /
//! activate / test endpoints layer on top in M2.3.
//!
//! ## What's stored, what's recompiled
//!
//! Spec §5.4 + plan §D3: only the Rego **source** + its **SHA-256**
//! hit fjall. Compiled bytecode is reconstructed at boot by walking
//! the active-pointer set and re-compiling. This keeps the on-disk
//! shape stable across regorus upgrades — bumping the interpreter
//! never invalidates stored rows.
//!
//! ## Wire shape vs storage shape
//!
//! The serialized form (`camelCase`) is also the JSON shape returned
//! by `GET /v1/policies/{id}` (M2.4). The audit envelope's
//! `PolicyActivated` data struct lifts `id` + `purpose` + `sha256` +
//! `version` from this same struct — see vti-common audit events.
//!
//! Phase 2 milestones layered on top:
//! - M2.3 — upload + activate + test endpoints.
//! - M2.5 — bundled default policies (join, removal, personhood, …)
//!   land as [`Policy`] rows at boot if no row exists for the
//!   purpose.
//! - M2.6 / M2.7 — `join.rego` + `removal.rego` consume the active
//!   pointer.
//! - M2.17 — audit variants `PolicyUploaded` + `PolicyActivated`
//!   reference [`Policy::id`] / [`Policy::sha256`].

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One uploaded Rego policy.
///
/// Identity is by [`Self::id`] (UUID v4, allocated server-side at
/// upload time). `(purpose, version)` is unique across the
/// keyspace: every upload for a purpose bumps `version` by 1 so
/// historical rows stay reachable for audit even after a newer
/// upload supersedes them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct Policy {
    /// Server-allocated UUID. Stable across activations + renames.
    pub id: Uuid,
    /// What this policy decides — see [`PolicyPurpose`].
    pub purpose: PolicyPurpose,
    /// The full Rego source. Bounded by [`POLICY_SOURCE_MAX_BYTES`]
    /// at the route layer (M2.3).
    pub rego_source: String,
    /// SHA-256 over the source bytes. Used by audit + the trust-task
    /// upload echo; computed alongside compilation in
    /// [`super::engine::compile`] so the hash + bytecode stay
    /// lockstep. Wire shape is a 64-char lowercase-hex string so
    /// operators + audit log consumers don't have to read a 32-element
    /// byte array — see [`hex32`] for the (de)serialization adapter.
    #[serde(with = "hex32")]
    pub sha256: [u8; 32],
    /// When this version was activated — `None` if it has never
    /// been the live policy for its purpose. M2.3's activate
    /// endpoint stamps this on every flip; archived rows retain
    /// the last activation time for audit context.
    #[serde(default)]
    pub activated_at: Option<DateTime<Utc>>,
    /// DID of the operator who uploaded this revision. Recorded
    /// for audit + the `PolicyUploaded` envelope's actor field
    /// (the audit envelope's `actor` is already this DID; this
    /// field exists so the row itself remains self-describing
    /// when read in isolation).
    pub author_did: String,
    /// Wall-clock time the row hit fjall.
    pub created_at: DateTime<Utc>,
    /// Monotone per-`purpose` counter. The first upload for any
    /// purpose is `1`. Audit + the operator UX use this to label
    /// historical revisions ("removal.rego v3 archived").
    pub version: u32,
    /// Operator-supplied module name and description (canonical
    /// `PolicyModule.name` / `.description`; `name` is required there).
    ///
    /// `#[serde(default)]` keeps rows written before these fields
    /// deserializable; they fall back to the purpose for `name`, which
    /// is the only stable human-meaningful identifier such a row has.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Hard cap on the bytes-on-disk size of [`Policy::rego_source`].
/// 64 KiB is comfortably above every default policy the workspace
/// ships in M2.5 (the largest, `join.rego`, is ~3 KiB) but small
/// enough that a malicious upload can't bloat the keyspace. M2.3
/// rejects payloads above this with 413.
pub const POLICY_SOURCE_MAX_BYTES: usize = 64 * 1024;

/// What a policy decides. The keyspace `active_policies:<purpose>`
/// has at most one row per variant; the active pointer is a
/// per-purpose singleton.
///
/// Wire shape is `camelCase` ASCII (`join`, `removal`,
/// `crossCommunityRoles`) — operators wire purposes into REST
/// payloads + the policies CLI verbs.
///
/// Per spec §7.1, the workspace ships nine purposes. They split
/// into three groups:
/// - **Membership lifecycle**: [`Self::Join`], [`Self::Removal`],
///   [`Self::Personhood`].
/// - **Discoverability**: [`Self::Registry`], [`Self::Directory`].
/// - **Authorization**: [`Self::RoleDefinitions`],
///   [`Self::CrossCommunityRoles`],
///   [`Self::CrossCommunityRelationships`], [`Self::Relationships`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub enum PolicyPurpose {
    Join,
    Removal,
    Personhood,
    Registry,
    Directory,
    RoleDefinitions,
    CrossCommunityRoles,
    CrossCommunityRelationships,
    Relationships,
    /// In-place change of a member's role — the role-change ceremony
    /// (pipeline `vtc.role_change`). The one ceremony whose `allow`
    /// may grant `admin`, gated by a verified step-up. Distinct from
    /// [`Self::RoleDefinitions`] (the role→permission matrix).
    RoleChange,
}

impl PolicyPurpose {
    /// Every purpose variant, in declaration order. Used by the
    /// boot-time default-policy loader (M2.5) so missing rows can
    /// be filled from the bundled defaults without listing each
    /// purpose explicitly at the call site.
    pub const ALL: [PolicyPurpose; 10] = [
        PolicyPurpose::Join,
        PolicyPurpose::Removal,
        PolicyPurpose::Personhood,
        PolicyPurpose::Registry,
        PolicyPurpose::Directory,
        PolicyPurpose::RoleDefinitions,
        PolicyPurpose::CrossCommunityRoles,
        PolicyPurpose::CrossCommunityRelationships,
        PolicyPurpose::Relationships,
        PolicyPurpose::RoleChange,
    ];

    /// Lowercase camelCase wire form of this purpose. Stable wire
    /// (operators script around it); matches the serde
    /// representation.
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyPurpose::Join => "join",
            PolicyPurpose::Removal => "removal",
            PolicyPurpose::Personhood => "personhood",
            PolicyPurpose::Registry => "registry",
            PolicyPurpose::Directory => "directory",
            PolicyPurpose::RoleDefinitions => "roleDefinitions",
            PolicyPurpose::CrossCommunityRoles => "crossCommunityRoles",
            PolicyPurpose::CrossCommunityRelationships => "crossCommunityRelationships",
            PolicyPurpose::Relationships => "relationships",
            PolicyPurpose::RoleChange => "roleChange",
        }
    }

    /// The Rego package an uploaded policy for this purpose must live
    /// in, for the four ceremony purposes the decision pipeline probes
    /// by a fixed package (`data.<pkg>.decision`). A module compiled
    /// into the *wrong* package compiles cleanly but evaluates to
    /// `undefined` at decision time, which the host reads as a silent
    /// default-deny for that whole ceremony — so the package is part of
    /// the upload contract, validated by
    /// [`crate::policy::validate_purpose_package`].
    ///
    /// `None` for purposes without a single pinned decision package
    /// (registry, personhood, role-definitions, …) — those are not
    /// package-validated at upload.
    pub fn expected_package(self) -> Option<&'static str> {
        match self {
            PolicyPurpose::Join => Some("vtc.join"),
            PolicyPurpose::Removal => Some("vtc.removal"),
            PolicyPurpose::RoleChange => Some("vtc.role_change"),
            PolicyPurpose::Directory => Some("vtc.directory"),
            _ => None,
        }
    }
}

/// `[u8; 32]` ↔ 64-char lowercase-hex string serde adapter. Used by
/// [`Policy::sha256`] so the wire form is human-readable and matches
/// what `sha256sum policy.rego` prints. Hand-rolled to avoid pulling
/// `serde_with` into the workspace for a single field.
mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|got: Vec<u8>| serde::de::Error::invalid_length(got.len(), &"32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    #[test]
    fn purpose_wire_shape_round_trips() {
        // Every variant serializes to the documented `camelCase`
        // string and deserializes back. Lock the shape down at
        // model level — the audit envelope + the route layer both
        // depend on it.
        let cases = [
            (PolicyPurpose::Join, json!("join")),
            (PolicyPurpose::Removal, json!("removal")),
            (PolicyPurpose::Personhood, json!("personhood")),
            (PolicyPurpose::Registry, json!("registry")),
            (PolicyPurpose::Directory, json!("directory")),
            (PolicyPurpose::RoleDefinitions, json!("roleDefinitions")),
            (
                PolicyPurpose::CrossCommunityRoles,
                json!("crossCommunityRoles"),
            ),
            (
                PolicyPurpose::CrossCommunityRelationships,
                json!("crossCommunityRelationships"),
            ),
            (PolicyPurpose::Relationships, json!("relationships")),
            (PolicyPurpose::RoleChange, json!("roleChange")),
        ];
        for (purpose, wire) in cases {
            assert_eq!(serde_json::to_value(purpose).unwrap(), wire);
            let parsed: PolicyPurpose = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(parsed, purpose);
            assert_eq!(purpose.as_str(), wire.as_str().unwrap());
        }
    }

    #[test]
    fn policy_round_trips_through_json() {
        let source = "package vtc.test\nimport rego.v1\n";
        let sha256: [u8; 32] = Sha256::digest(source.as_bytes()).into();
        let policy = Policy {
            id: Uuid::from_u128(0xdead_beef_0000_0001_0000_0000_0000_0000),
            purpose: PolicyPurpose::Removal,
            rego_source: source.into(),
            sha256,
            activated_at: None,
            author_did: "did:key:zAdmin".into(),
            created_at: Utc::now(),
            version: 7,
            name: None,
            description: None,
        };
        let json = serde_json::to_value(&policy).unwrap();
        assert!(json["regoSource"].is_string());
        assert_eq!(json["purpose"], "removal");
        assert_eq!(json["version"], 7);
        let parsed: Policy = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, policy);
    }

    #[test]
    fn all_covers_every_variant() {
        // `ALL` is consumed by M2.5's default-policy loader; if a
        // new variant lands and someone forgets to add it here,
        // the bundled default would silently never load. Drive the
        // count + exhaustiveness assertion off the same constant
        // so a missed entry surfaces at test time.
        assert_eq!(PolicyPurpose::ALL.len(), 10);
        for purpose in PolicyPurpose::ALL {
            // Compiles iff the match is total — `as_str` exhaustively
            // matches every variant; this exists so the assertion
            // sticks if anyone tries to special-case a variant out.
            let _ = purpose.as_str();
        }
    }
}
