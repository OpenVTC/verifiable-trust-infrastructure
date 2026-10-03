//! What an approver is shown — **VTI-APV-011 / VTI-APV-013**, as data.
//!
//! Every action `kind` ships a **summary template**: a title and an effect in
//! prose, and named fields, each a JSON Pointer into the digested payload with
//! a format from a closed set (`docs/05-design-notes/vtc-action-list.md`
//! §7a.2). The community renders the summary by resolving each pointer against
//! the action's `payload`; a renderer (the console, `cnm`) re-derives every
//! field from that same payload and refuses the action on any mismatch, so
//! nothing an approver reads is something only the community asserted.
//!
//! One template per `(kind, typeUri)`, because one kind arrives through several
//! tasks whose payloads differ in shape: making someone an unrestricted
//! administrator is an `acl/grant` (`/entry/subject`) or an `acl/change-role`
//! (`/subject`). Each template's digest — SHA-256 over its RFC 8785
//! canonicalisation, as a multibase multihash — is **pinned in the build**
//! ([`PINNED`], checked by `every_template_matches_its_pin`), and the console
//! holds the same table, so the community cannot change what approvers are
//! shown for a kind without that change being visible.
//!
//! The title and effect carry `{field}` placeholders — prose, which a renderer
//! fills from the fields it re-derived, never from anything else.

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// One displayed value: where it is in the payload, and how to show it.
#[derive(Debug, Clone, Copy)]
pub struct FieldDef {
    pub name: &'static str,
    /// RFC 6901 pointer into the action's `payload`.
    pub pointer: &'static str,
    /// One of the closed set: `did`, `capabilityList`, `duration`,
    /// `datetime`, `text`.
    pub format: &'static str,
}

/// A summary template.
#[derive(Debug, Clone, Copy)]
pub struct Template {
    pub kind: &'static str,
    pub type_uri: &'static str,
    pub title: &'static str,
    pub effect: &'static str,
    pub fields: &'static [FieldDef],
}

/// The action kinds this build raises.
pub const KIND_GRANT_AUTHORITY: &str = "acl.grant.authority";
pub const KIND_REDUCE_AUTHORITY: &str = "acl.reduce.authority";
pub const KIND_THRESHOLD_LOWER: &str = "config.threshold.lower";
pub const KIND_POLICY_AUTHORITY: &str = "policy.authority.change";
pub const KIND_INVITE_CREATE: &str = "admin.invite.create";
/// An operator's offline write, raised for acknowledgement (VTI-VTC-023).
pub const KIND_OPERATOR_WRITE: &str = "operator.offlineWrite";
/// Defining or replacing a custom administrative role (`vtc-admin-roles.md`
/// §6.2).
pub const KIND_ROLE_DEFINE: &str = "acl.role.define";
/// Deleting a custom administrative role.
pub const KIND_ROLE_DELETE: &str = "acl.role.delete";
/// Restoring a backup, which replaces the ACL (`vtc-admin-roles.md` §7).
pub const KIND_BACKUP_RESTORE: &str = "backup.restore";
/// A departed granter's grants, for re-affirmation (`vtc-admin-roles.md` §6.3).
pub const KIND_GRANTS_REVIEW: &str = "acl.grants.review";

/// The record type a grants review is raised under. Not a Trust Task: the
/// community raises it itself, as it does the boot migration's item, and it is
/// never sent or dispatched.
pub const GRANTS_REVIEW_URI: &str = "urn:openvtc:vtc:acl:grants-review";

const ACL_GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const ACL_UPDATE: &str = "https://trusttasks.org/spec/acl/update/0.1";
const ACL_CHANGE_ROLE: &str = "https://trusttasks.org/spec/acl/change-role/0.1";
pub(crate) const ACL_REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";
const ACL_GRANT_V0_2: &str = "https://trusttasks.org/spec/acl/grant/0.2";
const ACL_UPDATE_V0_2: &str = "https://trusttasks.org/spec/acl/update/0.2";
const ACL_CHANGE_ROLE_V0_2: &str = "https://trusttasks.org/spec/acl/change-role/0.2";
const ACL_REVOKE_V0_2: &str = "https://trusttasks.org/spec/acl/revoke/0.2";
/// `vtc/operator/offline-write/0.1` — the record type an operator's offline
/// write is named by (VTI-VTC-023). Never sent; see
/// [`super::OPERATOR_OFFLINE_WRITE_URI`].
const OFFLINE_WRITE: &str = super::OPERATOR_OFFLINE_WRITE_URI;
const ACL_MIGRATION: &str = super::OPERATOR_ACL_MIGRATION_URI;
const INVITES_CREATE: &str = "https://trusttasks.org/spec/vtc/admin/invites/create/0.1";
const ADMIN_REMOVE: &str = "https://trusttasks.org/spec/vtc/members/admin-remove/0.1";
const CONFIG_PATCH: &str = "https://trusttasks.org/spec/config/patch/0.1";
const CONFIG_IMPORT: &str = "https://trusttasks.org/spec/vtc/config/import/0.1";
const POLICY_UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const POLICY_ACTIVATE: &str = "https://trusttasks.org/spec/policy/activate/0.1";
const ROLES_DEFINE: &str = "https://trusttasks.org/spec/vtc/roles/define/0.1";
const ROLES_DELETE: &str = "https://trusttasks.org/spec/vtc/roles/delete/0.1";
const BACKUP_FINALIZE_IMPORT: &str = "https://trusttasks.org/spec/backup/finalize-import/0.1";

const fn f(name: &'static str, pointer: &'static str, format: &'static str) -> FieldDef {
    FieldDef {
        name,
        pointer,
        format,
    }
}

const GRANT_EFFECT: &str = "{subject} will be able to grant and remove any authority in this \
                            community, including yours.";
const REDUCE_EFFECT: &str = "{subject} loses unrestricted authority in this community. They are \
                             not asked: a party to a removal never decides it.";
// Role-based administration (`vtc-admin-roles.md` §7): what the capabilities
// at stake let their holder do.
const GRANT_CAPABILITY_EFFECT: &str = "{subject} will hold capabilities that create authority in \
                                       this community: they can grant, change or approve what \
                                       others hold.";
const REDUCE_CAPABILITY_EFFECT: &str = "{subject} loses capabilities that create authority in this \
                                        community. They are not asked: a party to a removal never \
                                        decides it.";
const THRESHOLD_EFFECT: &str = "Fewer administrators will be needed to make an unrestricted \
                                administrator — including the next one this requester asks for.";
const POLICY_EFFECT: &str = "The rules that decide who holds authority in this community change.";
const ACL_MIGRATION_EFFECT: &str = "This VTC ran {command} when it started on {host} at {at}. It \
                                    is already in effect: acknowledging records that you have \
                                    seen it, and changes nothing. Re-grant anyone who should keep \
                                    authority with acl/update.";
const OPERATOR_EFFECT: &str = "Written at {at}, while the service was stopped. It is already in \
                               effect: acknowledging records that you have seen it, and changes \
                               nothing.";
const ROLE_DEFINE_EFFECT: &str = "Anyone holding {name} may then hold at most {ceiling} and \
                                  approve at most {approveScope}. Replacing a role changes what \
                                  every holder may do at once.";
const ROLE_DELETE_EFFECT: &str = "The role {name} leaves this community's vocabulary. Nobody holds \
                                  it, so nobody's authority changes.";
const BACKUP_RESTORE_EFFECT: &str = "Every record in the backup replaces this community's — its \
                                     access control included, so who administers it afterwards \
                                     is whoever the backup says.";
const GRANTS_REVIEW_EFFECT: &str = "{granter} granted authority to {subjects} and no longer holds \
                                    it. Approving re-affirms those grants under your own \
                                    authority; declining, or letting this lapse, withdraws them.";

/// Every template this build renders.
pub const TEMPLATES: &[Template] = &[
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: ACL_GRANT_V0_2,
        title: "Make {subject} a {role}",
        effect: GRANT_CAPABILITY_EFFECT,
        fields: &[
            f("subject", "/entry/subject", "did"),
            f("role", "/entry/role", "text"),
            f("capabilities", "/entry/capabilities", "text"),
            f("expiresAt", "/entry/expiresAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: ACL_UPDATE_V0_2,
        title: "Widen what {subject} holds",
        effect: GRANT_CAPABILITY_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("capabilities", "/capabilities", "text"),
            f("expiresAt", "/expiresAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: ACL_CHANGE_ROLE_V0_2,
        title: "Move {subject} from {fromRole} to {toRole}",
        effect: GRANT_CAPABILITY_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("fromRole", "/fromRole", "text"),
            f("toRole", "/toRole", "text"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_REVOKE_V0_2,
        title: "Revoke {subject}",
        effect: REDUCE_CAPABILITY_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("revocation", "/revocation", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_UPDATE_V0_2,
        title: "Narrow what {subject} holds",
        effect: REDUCE_CAPABILITY_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("capabilities", "/capabilities", "text"),
            f("expiresAt", "/expiresAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_CHANGE_ROLE_V0_2,
        title: "Move {subject} from {fromRole} to {toRole}",
        effect: REDUCE_CAPABILITY_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("fromRole", "/fromRole", "text"),
            f("toRole", "/toRole", "text"),
        ],
    },
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: ACL_GRANT,
        title: "Make {subject} an unrestricted administrator",
        effect: GRANT_EFFECT,
        fields: &[
            f("subject", "/entry/subject", "did"),
            f("role", "/entry/role", "text"),
            f("scopes", "/entry/scopes", "capabilityList"),
            f("expiresAt", "/entry/expiresAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: ACL_UPDATE,
        title: "Widen {subject} to an unrestricted administrator",
        effect: GRANT_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("scopes", "/scopes", "capabilityList"),
            f("expiresAt", "/expiresAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: ACL_CHANGE_ROLE,
        title: "Promote {subject} from {fromRole} to unrestricted administrator",
        effect: GRANT_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("fromRole", "/fromRole", "text"),
            f("toRole", "/toRole", "text"),
        ],
    },
    Template {
        kind: KIND_INVITE_CREATE,
        type_uri: INVITES_CREATE,
        title: "Invite {subject} to become an unrestricted administrator",
        effect: GRANT_EFFECT,
        fields: &[f("subject", "/did", "did"), f("label", "/label", "text")],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_REVOKE,
        title: "Remove unrestricted administrator {subject}",
        effect: REDUCE_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("scopes", "/scopes", "capabilityList"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_CHANGE_ROLE,
        title: "Demote unrestricted administrator {subject} to {toRole}",
        effect: REDUCE_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("toRole", "/toRole", "text"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_UPDATE,
        title: "Narrow unrestricted administrator {subject}",
        effect: REDUCE_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("scopes", "/scopes", "capabilityList"),
            f("expiresAt", "/expiresAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_GRANT,
        title: "Rewrite unrestricted administrator {subject} as {role}",
        effect: REDUCE_EFFECT,
        fields: &[
            f("subject", "/entry/subject", "did"),
            f("role", "/entry/role", "text"),
            f("scopes", "/entry/scopes", "capabilityList"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ADMIN_REMOVE,
        title: "Remove unrestricted administrator {subject} from the community",
        effect: REDUCE_EFFECT,
        fields: &[
            f("subject", "/did", "did"),
            f("disposition", "/disposition", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_THRESHOLD_LOWER,
        type_uri: CONFIG_PATCH,
        title: "Lower the unrestricted-administrator consent threshold to {threshold}",
        effect: THRESHOLD_EFFECT,
        fields: &[f(
            "threshold",
            "/overrides/acl.unrestricted_admin_consent_threshold",
            "text",
        )],
    },
    Template {
        kind: KIND_THRESHOLD_LOWER,
        type_uri: CONFIG_IMPORT,
        title: "Import a configuration that lowers the consent threshold to {threshold}",
        effect: THRESHOLD_EFFECT,
        fields: &[f(
            "threshold",
            "/document/configOverrides/acl.unrestricted_admin_consent_threshold",
            "text",
        )],
    },
    Template {
        kind: KIND_POLICY_AUTHORITY,
        type_uri: POLICY_UPSERT,
        title: "Replace the policy {name}",
        effect: POLICY_EFFECT,
        fields: &[
            f("name", "/name", "text"),
            f("id", "/id", "text"),
            f("module", "/module", "text"),
        ],
    },
    Template {
        kind: KIND_POLICY_AUTHORITY,
        type_uri: POLICY_ACTIVATE,
        title: "Activate policy {id} for {purpose}",
        effect: POLICY_EFFECT,
        fields: &[f("id", "/id", "text"), f("purpose", "/purpose", "text")],
    },
    Template {
        kind: KIND_OPERATOR_WRITE,
        type_uri: OFFLINE_WRITE,
        title: "The operator ran {command} on {host}, changing access for {dids}",
        effect: OPERATOR_EFFECT,
        fields: &[
            f("command", "/command", "text"),
            f("dids", "/dids", "capabilityList"),
            f("host", "/host", "text"),
            f("at", "/at", "datetime"),
        ],
    },
    Template {
        kind: KIND_OPERATOR_WRITE,
        type_uri: ACL_MIGRATION,
        title: "Context-scoped administrators lost administrative authority when this VTC moved \
                to role-based administration",
        effect: ACL_MIGRATION_EFFECT,
        fields: &[
            f("command", "/command", "text"),
            f("host", "/operatorHost", "text"),
            f("at", "/invokedAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_ROLE_DEFINE,
        type_uri: ROLES_DEFINE,
        title: "Define the administrative role {name}",
        effect: ROLE_DEFINE_EFFECT,
        fields: &[
            f("name", "/name", "text"),
            f("ceiling", "/ceiling", "text"),
            f("approveScope", "/approveScope", "text"),
            f("replaces", "/replaces", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_ROLE_DELETE,
        type_uri: ROLES_DELETE,
        title: "Delete the administrative role {name}",
        effect: ROLE_DELETE_EFFECT,
        fields: &[f("name", "/name", "text"), f("reason", "/reason", "text")],
    },
    Template {
        kind: KIND_BACKUP_RESTORE,
        type_uri: BACKUP_FINALIZE_IMPORT,
        title: "Restore this community from backup {bundleId}",
        effect: BACKUP_RESTORE_EFFECT,
        fields: &[f("bundleId", "/bundleId", "text")],
    },
    Template {
        kind: KIND_GRANTS_REVIEW,
        type_uri: GRANTS_REVIEW_URI,
        title: "Re-affirm or withdraw the grants {granter} made",
        effect: GRANTS_REVIEW_EFFECT,
        fields: &[
            f("granter", "/granter", "did"),
            f("subjects", "/subjects", "capabilityList"),
            f("deadline", "/deadline", "datetime"),
        ],
    },
];

/// The digest of every template, pinned. A change to a template's prose,
/// pointers or formats changes its digest and fails
/// `every_template_matches_its_pin` until this table — and the console's copy
/// (`admin-ui/src/lib/action-summary.ts`) — is updated with it: what approvers
/// are shown cannot move silently.
pub const PINNED: &[(&str, &str, &str)] = &[
    (
        KIND_GRANT_AUTHORITY,
        ACL_GRANT_V0_2,
        "zQmNiciJtH7xnKdQUxEwp44mpbCrVt8tfBrt1XKg7VfAc71",
    ),
    (
        KIND_GRANT_AUTHORITY,
        ACL_UPDATE_V0_2,
        "zQmQBA6WoTVVo2wBJrmkJwTnefj6q1Hgwc2BWFTCCPpWnQT",
    ),
    (
        KIND_GRANT_AUTHORITY,
        ACL_CHANGE_ROLE_V0_2,
        "zQmVAPMeYXgX9bUi5HruaPFxBLsW1ZJNkbRss6VixMz48vt",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_REVOKE_V0_2,
        "zQmfJss7J6uNUdyZPUC64BoJ971CdnTfgd6BVEQd7aFjYwD",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_UPDATE_V0_2,
        "zQmNWjHGRwDCfUsvVFxx6o6eXczqjQTepMEKwkS3qqNo1N6",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_CHANGE_ROLE_V0_2,
        "zQmaAjJC1L9w3pbUTEbWfhzfBdUpv8pofDZvL6mWSpU2eWk",
    ),
    (
        KIND_GRANT_AUTHORITY,
        ACL_GRANT,
        "zQmPrXgyRpZ57y4AekuZPspEkunnEbEhxvZuqrfoxrgsvr4",
    ),
    (
        KIND_GRANT_AUTHORITY,
        ACL_UPDATE,
        "zQmbvgey1akTyTq74Vhe4fuXGvpTKKTVw34mo3y4hVEKSEQ",
    ),
    (
        KIND_GRANT_AUTHORITY,
        ACL_CHANGE_ROLE,
        "zQmQX9Dx7cDqLtcoTNuDSWWo5nJTGecB9CqRLKgpd4es1c9",
    ),
    (
        KIND_INVITE_CREATE,
        INVITES_CREATE,
        "zQmSXC2GaMpizs4kKRhz4nBchZikWjqHAoeDfA5D7fVizgp",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_REVOKE,
        "zQmbvSkPZnzCqq5idfR5DKfFyiHFRCeimT48C4c6jtZfG1Z",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_CHANGE_ROLE,
        "zQmfHspRZaXfEPkeAyqcFkpgqYT2RCqXjjnXVZmFhsaJQcu",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_UPDATE,
        "zQmXcYLQhsgDQEgDZuf2mvmkxDDKEd1c9C47tmRAGLofPgM",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_GRANT,
        "zQmVrvxot9bAts7S22CfXQgqR8vC5aZHWQz97UjfMWveT7o",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ADMIN_REMOVE,
        "zQmc2FGMz27Bqiu3CPpy5BrVBWyst3RkfWhfk322QWzu6mR",
    ),
    (
        KIND_THRESHOLD_LOWER,
        CONFIG_PATCH,
        "zQmeGT7ztnicC5RScp86U5Yjq1s3vhtzZof8yYy6sWi9cYP",
    ),
    (
        KIND_THRESHOLD_LOWER,
        CONFIG_IMPORT,
        "zQmQ6yxgM1HYuJkY4RvQDYiB7NyfsFeAeYzcPnh6d5rrrPc",
    ),
    (
        KIND_POLICY_AUTHORITY,
        POLICY_UPSERT,
        "zQma1zFb7cvRpSH7erp14W83wYZW5vP7cke1yLwcwQZdEie",
    ),
    (
        KIND_POLICY_AUTHORITY,
        POLICY_ACTIVATE,
        "zQmTqKd5UoQZfTy7giJU9KFWFyhUbqxAtr5XWoUB9BLncBL",
    ),
    (
        KIND_OPERATOR_WRITE,
        OFFLINE_WRITE,
        "zQmQZTPg2MeWt1C8oAvoLMGJNY9DpxvB6bRjvQwJT7ns9Ah",
    ),
    (
        KIND_OPERATOR_WRITE,
        ACL_MIGRATION,
        "zQmcx336K693LHuAKosCP9avuLZWauw1vome6VBxWBFDiqK",
    ),
    (
        KIND_ROLE_DEFINE,
        ROLES_DEFINE,
        "zQmf6erEaANYgarV9c8frmZSZ8R5XuomNdXxGNQ8FAZ2QUh",
    ),
    (
        KIND_ROLE_DELETE,
        ROLES_DELETE,
        "zQmNmqjjmZmPfvapiR91YcFDgXtg1xdAw3QNwaQemrEHL8U",
    ),
    (
        KIND_BACKUP_RESTORE,
        BACKUP_FINALIZE_IMPORT,
        "zQmY89pWbScF2Mj1B1tWXJrtKPyhqcWDJDiV8eKCTchKscE",
    ),
    (
        KIND_GRANTS_REVIEW,
        GRANTS_REVIEW_URI,
        "zQmes3QBrvXfxcwu7tyU7gk58b8RrLfrQiteFRJGCwDYS4S",
    ),
];

/// The template for `(kind, type_uri)`, if this build has one.
#[must_use]
pub fn template_for(kind: &str, type_uri: &str) -> Option<&'static Template> {
    TEMPLATES
        .iter()
        .find(|t| t.kind == kind && t.type_uri == type_uri)
}

/// A template as the JSON its digest is taken over.
#[must_use]
pub fn template_json(t: &Template) -> Value {
    let fields: Map<String, Value> = t
        .fields
        .iter()
        .map(|d| {
            (
                d.name.to_string(),
                json!({ "pointer": d.pointer, "format": d.format }),
            )
        })
        .collect();
    json!({
        "kind": t.kind,
        "typeUri": t.type_uri,
        "title": t.title,
        "effect": t.effect,
        "fields": fields,
    })
}

/// SHA-256 over the template's RFC 8785 canonical form, as a base58btc
/// multibase multihash — the `templateDigest` a renderer checks.
#[must_use]
pub fn template_digest(t: &Template) -> String {
    let canonical =
        serde_json_canonicalizer::to_string(&template_json(t)).expect("a template canonicalises");
    multihash(canonical.as_bytes())
}

/// SHA-256 of `bytes` as a base58btc multibase multihash (`0x12 0x20 …`).
#[must_use]
pub fn multihash(bytes: &[u8]) -> String {
    let mut mh = vec![0x12, 0x20];
    mh.extend_from_slice(&Sha256::digest(bytes));
    multibase::encode(multibase::Base::Base58Btc, mh)
}

/// `payloadDigest` on the wire: SHA-256 over the payload's RFC 8785
/// canonicalisation, as a multibase multihash — what an approver recomputes to
/// check that `payload` is what was parked.
pub fn payload_digest(payload: &Value) -> Result<String, vti_common::error::AppError> {
    let canonical = serde_json_canonicalizer::to_string(payload).map_err(|e| {
        vti_common::error::AppError::Internal(format!("payload JCS canonicalization failed: {e}"))
    })?;
    Ok(multihash(canonical.as_bytes()))
}

/// Render the `summary` member of an action for `(kind, type_uri)` over
/// `payload`: the template's prose, and each field's value read by its
/// pointer. A pointer into a member the payload does not carry reads `null`.
///
/// A pair this build has no template for — none is raised today — falls back
/// to one field holding the whole payload, so a renderer still shows exactly
/// what would run.
#[must_use]
pub fn render(kind: &str, type_uri: &str, payload: &Value) -> Value {
    let fallback;
    let t = match template_for(kind, type_uri) {
        Some(t) => t,
        None => {
            fallback = Template {
                kind: "unknown",
                type_uri: "unknown",
                title: "Run a parked operation",
                effect: "",
                fields: &[FieldDef {
                    name: "payload",
                    pointer: "",
                    format: "text",
                }],
            };
            &fallback
        }
    };
    let fields: Map<String, Value> = t
        .fields
        .iter()
        .map(|d| {
            (
                d.name.to_string(),
                json!({
                    "pointer": d.pointer,
                    "format": d.format,
                    "value": payload.pointer(d.pointer).cloned().unwrap_or(Value::Null),
                }),
            )
        })
        .collect();
    let mut summary = json!({
        "title": t.title,
        "fields": fields,
        "templateDigest": template_digest(t),
    });
    if !t.effect.is_empty() {
        summary["effect"] = json!(t.effect);
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pin: what approvers are shown for a kind cannot change without
    /// this table — and the console's copy — changing with it.
    #[test]
    fn every_template_matches_its_pin() {
        assert_eq!(TEMPLATES.len(), PINNED.len(), "one pin per template");
        let mut mismatched = Vec::new();
        for t in TEMPLATES {
            let pin = PINNED
                .iter()
                .find(|(k, u, _)| *k == t.kind && *u == t.type_uri)
                .unwrap_or_else(|| panic!("no pin for ({}, {})", t.kind, t.type_uri));
            let digest = template_digest(t);
            if digest != pin.2 {
                mismatched.push(format!("({}, {}) => {digest}", t.kind, t.type_uri));
            }
        }
        assert!(
            mismatched.is_empty(),
            "template digests changed — update PINNED and the console's copy:\n{}",
            mismatched.join("\n")
        );
    }

    /// The closed format set, and pointers a renderer can parse.
    #[test]
    fn every_field_uses_a_closed_format_and_a_valid_pointer() {
        const FORMATS: &[&str] = &["did", "capabilityList", "duration", "datetime", "text"];
        for t in TEMPLATES {
            for d in t.fields {
                assert!(FORMATS.contains(&d.format), "{}: {}", t.kind, d.format);
                assert!(
                    d.pointer.is_empty() || d.pointer.starts_with('/'),
                    "{}: {}",
                    t.kind,
                    d.pointer
                );
            }
            // Every placeholder names a field.
            for prose in [t.title, t.effect] {
                for part in prose.split('{').skip(1) {
                    let name = part.split('}').next().unwrap_or_default();
                    assert!(
                        t.fields.iter().any(|d| d.name == name),
                        "{}: placeholder {{{name}}} names no field",
                        t.kind
                    );
                }
            }
        }
    }

    /// The shared test vectors (`admin-ui/src/lib/action-summary.vectors.json`):
    /// the console runs the same file, so the two renderers agree on every one.
    #[test]
    fn the_shared_vectors_render_identically() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../admin-ui/src/lib/action-summary.vectors.json"
        ))
        .expect("vectors parse");
        for v in vectors.as_array().expect("an array") {
            let rendered = render(
                v["kind"].as_str().unwrap(),
                v["typeUri"].as_str().unwrap(),
                &v["payload"],
            );
            assert_eq!(rendered, v["summary"], "vector {}", v["name"]);
        }
    }
}
