//! `GET /v1/ceremonies` — the ceremony registry.
//!
//! The daemon is the source of truth for *which* ceremonies exist and
//! how their decision surface is shaped. Each manifest carries the
//! ceremony's metadata (purpose, package, nature, copy), the
//! simulator's input **fields** (a declarative UI schema), and a
//! **facts template** — a JSON skeleton of the verified-Facts `input`
//! document with `$field:<key>` / `$now` / `$if` directives the
//! admin-UI materializes from the field values.
//!
//! This is what makes a ceremony *over an existing effect* data, not
//! code: adding one is a manifest entry here, and the admin-UI renders
//! its whole flow + simulator from this endpoint — no per-ceremony
//! frontend. The effect a ceremony triggers (admit / depart / remint /
//! project) stays reviewed Rust; this registry only describes the
//! decision surface.

use axum::Json;
use serde::Serialize;
use serde_json::{Value as JsonValue, json};

use crate::auth::AuthClaims;

#[derive(Serialize, utoipa::ToSchema)]
pub struct FieldOption {
    pub value: &'static str,
    pub label: &'static str,
}

/// A `showWhen` predicate, declarative so it crosses the wire: render
/// the field only when `field`'s value equals `eq` (or its truthiness
/// matches `truthy`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct ShowWhen {
    pub field: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eq: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truthy: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct FieldDef {
    pub key: &'static str,
    pub label: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<&'static str>,
    #[serde(rename = "type")]
    pub field_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<FieldOption>>,
    pub default: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_when: Option<ShowWhen>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct CeremonyManifest {
    pub purpose: &'static str,
    pub pkg: &'static str,
    pub nature: &'static str,
    pub label: &'static str,
    pub wired: &'static str,
    pub blurb: &'static str,
    pub fields: Vec<FieldDef>,
    /// JSON skeleton of the verified-Facts `input`, with `$field:<key>`
    /// / `$now` / `$if` directives the admin-UI materializes.
    pub facts_template: JsonValue,
}

fn role_options() -> Vec<FieldOption> {
    vec![
        FieldOption {
            value: "member",
            label: "member",
        },
        FieldOption {
            value: "moderator",
            label: "moderator",
        },
        FieldOption {
            value: "admin",
            label: "admin",
        },
    ]
}

fn base_context() -> JsonValue {
    json!({
        "community_did": "did:webvh:demo.example",
        "channel": "rest",
        "member_count": 42,
    })
}

fn manifests() -> Vec<CeremonyManifest> {
    vec![
        CeremonyManifest {
            purpose: "directory",
            pkg: "vtc.directory",
            nature: "read-only",
            label: "Directory",
            wired: "live",
            blurb: "A member views another member's record. Read-only — the verdict's allow carries a field projection, capped by the PII boundary.",
            fields: vec![
                FieldDef {
                    key: "viewerRole",
                    label: "Viewer's community role",
                    hint: Some("actor.role — admin sees the fuller record"),
                    field_type: "select",
                    options: Some(vec![
                        FieldOption {
                            value: "admin",
                            label: "admin",
                        },
                        FieldOption {
                            value: "member",
                            label: "member",
                        },
                        FieldOption {
                            value: "",
                            label: "none (authenticated)",
                        },
                    ]),
                    default: json!("member"),
                    show_when: None,
                },
                FieldDef {
                    key: "subjectIsMember",
                    label: "Subject is a member",
                    hint: Some("state.subject_member present"),
                    field_type: "toggle",
                    options: None,
                    default: json!(true),
                    show_when: None,
                },
                FieldDef {
                    key: "subjectRole",
                    label: "Subject's role",
                    hint: Some("state.subject_member.role"),
                    field_type: "select",
                    options: Some(role_options()),
                    default: json!("member"),
                    show_when: Some(ShowWhen {
                        field: "subjectIsMember",
                        eq: None,
                        truthy: Some(true),
                    }),
                },
            ],
            facts_template: json!({
                "purpose": "directory",
                "now": "$now",
                "actor": { "did": "did:key:zViewer", "role": "$field:viewerRole", "authenticated": true },
                "subject": { "did": "did:key:zTarget" },
                "context": base_context(),
                "evidence": { "request": { "fields_requested": ["did", "role", "joined_at", "status"] } },
                "state": {
                    "subject_member": {
                        "$if": "subjectIsMember",
                        "then": { "role": "$field:subjectRole", "status": "active", "joined_at": "2026-01-02T00:00:00Z" },
                        "else": null
                    }
                }
            }),
        },
        CeremonyManifest {
            purpose: "join",
            pkg: "vtc.join",
            nature: "constructive",
            label: "Join",
            wired: "live",
            blurb: "A DID joins the community. A trusted presented credential auto-admits (allow → issue the membership credential); everything else is referred to the moderator queue for review.",
            fields: vec![FieldDef {
                key: "joinTrusted",
                label: "Presented credential is trusted",
                hint: Some("evidence.presentation.credentials[].issuer_trusted"),
                field_type: "toggle",
                options: None,
                default: json!(false),
                show_when: None,
            }],
            facts_template: json!({
                "purpose": "join",
                "now": "$now",
                "actor": { "did": "did:key:zApplicant", "authenticated": true },
                "subject": { "did": "did:key:zApplicant" },
                "context": base_context(),
                "evidence": {
                    "presentation": {
                        "verified": true,
                        "holder": "did:key:zApplicant",
                        "credentials": [{
                            "type": "WitnessCredential",
                            "issuer": "did:webvh:notary.example",
                            "issuer_trusted": "$field:joinTrusted",
                            "status": "valid",
                            "claims": {}
                        }]
                    }
                },
                "state": { "subject_member": null }
            }),
        },
        CeremonyManifest {
            purpose: "removal",
            pkg: "vtc.removal",
            nature: "destructive",
            label: "Leave",
            wired: "live",
            blurb: "A member departs or is removed. Self-leave is unconditional; an admin may remove a non-admin. The no-last-admin invariant + revocation are host-enforced in the effect.",
            fields: vec![
                FieldDef {
                    key: "selfLeave",
                    label: "Self-leave",
                    hint: Some("actor.did == subject.did — always allowed"),
                    field_type: "toggle",
                    options: None,
                    default: json!(false),
                    show_when: None,
                },
                FieldDef {
                    key: "subjectRole",
                    label: "Subject's role",
                    hint: Some("an admin may remove a non-admin only"),
                    field_type: "select",
                    options: Some(role_options()),
                    default: json!("member"),
                    show_when: Some(ShowWhen {
                        field: "selfLeave",
                        eq: None,
                        truthy: Some(false),
                    }),
                },
            ],
            facts_template: json!({
                "purpose": "leave",
                "now": "$now",
                "actor": { "did": "did:key:zActor", "role": "admin", "authenticated": true },
                "subject": { "did": { "$if": "selfLeave", "then": "did:key:zActor", "else": "did:key:zTarget" } },
                "context": base_context(),
                "evidence": { "request": { "disposition": "tombstone" } },
                "state": { "subject_member": { "role": "$field:subjectRole", "status": "active", "joined_at": "2026-01-02T00:00:00Z" } }
            }),
        },
        CeremonyManifest {
            purpose: "roleChange",
            pkg: "vtc.role_change",
            nature: "mutating",
            label: "Role change",
            wired: "live",
            blurb: "A member's role changes in place (the DID + VMC are unchanged; the role VEC is re-minted). The one ceremony whose allow may grant admin — gated by a verified step-up; demotions are guarded by no-last-admin.",
            fields: vec![
                FieldDef {
                    key: "targetRole",
                    label: "Target role",
                    hint: Some("evidence.request.target_role"),
                    field_type: "select",
                    options: Some(vec![
                        FieldOption {
                            value: "member",
                            label: "member",
                        },
                        FieldOption {
                            value: "moderator",
                            label: "moderator",
                        },
                        FieldOption {
                            value: "admin",
                            label: "admin (promotion)",
                        },
                    ]),
                    default: json!("moderator"),
                    show_when: None,
                },
                FieldDef {
                    key: "stepUp",
                    label: "Step-up verified",
                    hint: Some("admin needs step-up — else the verdict refers"),
                    field_type: "toggle",
                    options: None,
                    default: json!(false),
                    show_when: Some(ShowWhen {
                        field: "targetRole",
                        eq: Some(json!("admin")),
                        truthy: None,
                    }),
                },
            ],
            facts_template: json!({
                "purpose": "role-change",
                "now": "$now",
                "actor": { "did": "did:key:zAdmin", "role": "admin", "authenticated": true },
                "subject": { "did": "did:key:zTarget" },
                "context": base_context(),
                "evidence": { "request": { "target_role": "$field:targetRole", "step_up": "$field:stepUp" } },
                "state": { "subject_member": { "role": "member", "status": "active", "joined_at": "2026-01-02T00:00:00Z" } }
            }),
        },
    ]
}

/// `GET /v1/ceremonies` — list the ceremony manifests. Authenticated
/// (any session); the payload is admin-UI metadata, not secret, but
/// the surface lives behind the same gate as the rest of the API.
#[utoipa::path(
    get, path = "/ceremonies", tag = "ceremonies",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Ceremony manifests", body = [CeremonyManifest]),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn list(_claims: AuthClaims) -> Json<Vec<CeremonyManifest>> {
    Json(manifests())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_ceremonies_with_stable_purposes() {
        let m = manifests();
        let purposes: Vec<_> = m.iter().map(|c| c.purpose).collect();
        assert_eq!(purposes, vec!["directory", "join", "removal", "roleChange"]);
    }

    #[test]
    fn every_field_default_is_present_and_typed() {
        for c in manifests() {
            for f in &c.fields {
                assert!(!f.default.is_null(), "{}::{} default", c.purpose, f.key);
                if f.field_type == "select" {
                    assert!(
                        f.options.is_some(),
                        "{}::{} needs options",
                        c.purpose,
                        f.key
                    );
                }
            }
        }
    }

    #[test]
    fn facts_template_carries_the_purpose() {
        for c in manifests() {
            let p = c.facts_template.get("purpose").and_then(|v| v.as_str());
            assert!(p.is_some(), "{} facts_template purpose", c.purpose);
        }
    }
}
