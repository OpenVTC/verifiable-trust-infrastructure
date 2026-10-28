//! The `vault/*` wire-casing edge transform.
//!
//! The vault handlers model their wire bodies with the `vti_common::vault`
//! types, which serialise their enum *values* kebab-case — the form entries are
//! stored in. The versions the VTA serves (`vault/list/0.4`, `get/0.3`,
//! `upsert/0.4`, `release/0.2`, `proxy-login/0.2`, `sign-trust-task/0.2`) spell
//! a fixed set of those values in camelCase (`oauth-tokens` → `oauthTokens`,
//! `web-origin` → `webOrigin`, `didcomm-authcrypt` → `didcommAuthcrypt`).
//!
//! So the spine rewrites the values at each spec's declared enum paths on the
//! way in ([`kebabize`]) and on the way out ([`camelize`]). The Type URI is
//! never rewritten: the dispatch table registers the served version itself, so
//! a superseded version is simply not dispatched.
//!
//! Why path-targeted and not a blanket value rewrite: a free-text field
//! (a display name, a label) could coincidentally equal an enum token. By
//! transforming only at the declared enum paths we never touch opaque or
//! free-text values (JWEs, DIDs, labels).
//!
//! `kebabize`/`camelize` are deterministic inverses and each is idempotent on
//! its own target form, so a path that happens to carry an unchanged
//! single-word value (`password`, `did`) is a safe no-op.
//!
//! **Not** used for specs whose payload carries a signature over the document
//! (e.g. `auth/step-up/approve-response`, where the approver signs the
//! payload) — mutating those bytes would void the proof. A signed spec is
//! parsed at its own version, whose generated type reads the camelCase values.

use serde_json::Value;

use super::TrustTaskOutcome;

/// One served spec's casing map. Paths are `.`-separated and relative to the
/// document `payload`; a `*` segment fans out over every array element or
/// object value.
pub(super) struct WireSpecV02 {
    /// The served Type URI — the one its `dispatch_table!` entry registers.
    pub uri: &'static str,
    /// Enum field paths in the **request** payload (down-converted camel→kebab).
    pub request_paths: &'static [&'static str],
    /// Enum field paths in the **response** payload (up-converted kebab→camel).
    pub response_paths: &'static [&'static str],
    /// Paths to the `VaultEntry` objects in the **response** payload, whose
    /// archival-lifecycle members move into `ext` ([`LIFECYCLE_EXT`]).
    pub entry_paths: &'static [&'static str],
}

/// The `ext` member carrying a vault entry's archival lifecycle
/// (`status`, `archivedAt`, `deletedAt`, `graceUntil`).
///
/// `vault/_shared/0.1`'s `VaultEntry` declared those members; 0.2 and 0.3, the
/// component the served versions pin, do not, and the component is
/// `additionalProperties: false`. The lifecycle is this VTA's extension (the
/// `vault/{archive,unarchive,restore,purge}` tasks are openvtc's own), so it
/// travels where SPEC §4.5.1 puts an ecosystem's members: a namespaced `ext`
/// entry. An `active` entry carries none, exactly as it carried no lifecycle
/// members before.
pub(super) const LIFECYCLE_EXT: &str = "org.openvtc.vault-lifecycle";

const LIFECYCLE_MEMBERS: &[&str] = &["status", "archivedAt", "deletedAt", "graceUntil"];

/// Move a `VaultEntry`'s lifecycle members into `ext[LIFECYCLE_EXT]`.
fn relocate_lifecycle(entry: &mut Value) {
    let Value::Object(map) = entry else {
        return;
    };
    let mut lifecycle = serde_json::Map::new();
    for member in LIFECYCLE_MEMBERS {
        if let Some(v) = map.remove(*member) {
            lifecycle.insert((*member).to_string(), v);
        }
    }
    if lifecycle.is_empty() {
        return;
    }
    let ext = map
        .entry("ext")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Value::Object(ext) = ext {
        ext.insert(LIFECYCLE_EXT.to_string(), Value::Object(lifecycle));
    }
}

fn apply_at_path_mut(v: &mut Value, segments: &[&str], f: fn(&mut Value)) {
    match segments.split_first() {
        None => f(v),
        Some((&"*", rest)) => match v {
            Value::Array(items) => {
                for it in items.iter_mut() {
                    apply_at_path_mut(it, rest, f);
                }
            }
            Value::Object(map) => {
                for val in map.values_mut() {
                    apply_at_path_mut(val, rest, f);
                }
            }
            _ => {}
        },
        Some((seg, rest)) => {
            if let Value::Object(map) = v
                && let Some(child) = map.get_mut(*seg)
            {
                apply_at_path_mut(child, rest, f);
            }
        }
    }
}

/// Registry of edge-transformed specs. Signed-payload specs (step-up) are
/// intentionally absent.
///
/// SecretKind (`oauth-tokens`, `did-self-issued`, …) and the SiteTarget `kind`
/// discriminator (`web-origin`, `ios-app`, `android-app`) carry the renamed
/// values, as does the `sealedSecret`/`sealedSessionBlob` envelope tag
/// (`didcommAuthcrypt`/`hpkeArmored`/`tspMessage`) — it sits next to the opaque
/// JWE as a plaintext object key, so it is reachable on an enum path. What the
/// transform CANNOT reach are the values sealed *inside* the JWE ciphertext
/// (the released `VaultSecret.kind`, the `SessionBlob.refreshHint`,
/// `PasswordLoginConfig.format`); those are camelCased at seal time (see
/// `operations::vault::{release,proxy_login}`). The step-up proof / signed-
/// envelope payloads are opaque and on no enum path, so they pass through
/// byte-exact.
pub(super) const WIRE_SPECS_V0_2: &[WireSpecV02] = &[
    WireSpecV02 {
        uri: "https://trusttasks.org/spec/vault/list/0.4",
        request_paths: &["secretKind"],
        response_paths: &["entries.*.secretKind", "entries.*.targets.*.kind"],
        entry_paths: &["entries.*"],
    },
    WireSpecV02 {
        uri: "https://trusttasks.org/spec/vault/get/0.3",
        request_paths: &[],
        response_paths: &["entry.secretKind", "entry.targets.*.kind"],
        entry_paths: &["entry"],
    },
    WireSpecV02 {
        uri: "https://trusttasks.org/spec/vault/upsert/0.4",
        request_paths: &["secretKind", "targets.*.kind", "sealedSecret.envelope"],
        response_paths: &["entry.secretKind", "entry.targets.*.kind"],
        entry_paths: &["entry"],
    },
    WireSpecV02 {
        uri: "https://trusttasks.org/spec/vault/release/0.2",
        request_paths: &["target.kind"],
        // `secretKind` is the outer echo; `sealedSecret.envelope` is the
        // pluggable-cipher tag wrapping the JWE. The `VaultSecret.kind` *inside*
        // the JWE is camelCased at seal time, not here (it's ciphertext).
        response_paths: &["secretKind", "sealedSecret.envelope"],
        entry_paths: &[],
    },
    WireSpecV02 {
        uri: "https://trusttasks.org/spec/vault/proxy-login/0.2",
        request_paths: &["target.kind"],
        // The `sealedSessionBlob.envelope` tag wraps the JWE; the
        // `SessionBlob.refreshHint` inside it is camelCased at seal time.
        response_paths: &["sealedSessionBlob.envelope"],
        entry_paths: &[],
    },
];

/// Look up the edge-transform spec for an inbound type URI.
pub(super) fn lookup_0_2(type_uri: &str) -> Option<&'static WireSpecV02> {
    WIRE_SPECS_V0_2.iter().find(|s| s.uri == type_uri)
}

/// kebab-case → camelCase (`apple-app-attest` → `appleAppAttest`). Idempotent
/// on already-camel input; a no-op on hyphen-free single words.
fn camelize(s: &str) -> String {
    let mut parts = s.split('-');
    let mut out = String::new();
    if let Some(first) = parts.next() {
        out.push_str(first);
    }
    for p in parts {
        let mut chars = p.chars();
        if let Some(f) = chars.next() {
            out.extend(f.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
}

/// camelCase → kebab-case (`appleAppAttest` → `apple-app-attest`). Idempotent
/// on already-kebab input; a no-op on hyphen-free single words.
fn kebabize(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_ascii_uppercase() {
            out.push('-');
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Apply `f` to every string value reached by the `.`-separated `path`
/// (with `*` fanning out over arrays / object values).
fn apply_at_path(v: &mut Value, segments: &[&str], f: fn(&str) -> String) {
    match segments.split_first() {
        None => {
            if let Value::String(s) = v {
                *s = f(s);
            }
        }
        Some((&"*", rest)) => match v {
            Value::Array(items) => {
                for it in items.iter_mut() {
                    apply_at_path(it, rest, f);
                }
            }
            Value::Object(map) => {
                for val in map.values_mut() {
                    apply_at_path(val, rest, f);
                }
            }
            _ => {}
        },
        Some((seg, rest)) => {
            if let Value::Object(map) = v
                && let Some(child) = map.get_mut(*seg)
            {
                apply_at_path(child, rest, f);
            }
        }
    }
}

fn apply_paths(payload: &mut Value, paths: &[&str], f: fn(&str) -> String) {
    for path in paths {
        let segments: Vec<&str> = path.split('.').collect();
        apply_at_path(payload, &segments, f);
    }
}

/// Down-convert a request `payload` in place — rewrite the enum values at
/// `spec.request_paths` to kebab so the handler's storage-form types parse it.
pub(super) fn downconvert_request(payload: &mut Value, spec: &WireSpecV02) {
    apply_paths(payload, spec.request_paths, kebabize);
}

/// Up-convert (kebab→camel) the enum values at `paths` in `payload`.
///
/// Exposed for the JWE-sealing operations (`vault/release`, `vault/proxy-login`):
/// the released `VaultSecret` / `SessionBlob` cleartext rides inside ciphertext
/// the edge transform can't reach, so the seal step camelizes the relevant
/// enum paths itself. Reuses the same path-targeted [`camelize`] the response
/// up-converter uses.
pub(crate) fn camelize_paths(payload: &mut Value, paths: &[&str]) {
    apply_paths(payload, paths, camelize);
}

/// Up-convert a dispatch outcome: rewrite a success response's payload enum
/// values to camel. Error/reject documents (a different `type`) are passed
/// through untouched, since their payload carries no spec enums.
///
/// Operates on the typed [`TrustTaskOutcome`] body directly — the status is
/// preserved untouched and there is no round-trip through an `axum::Response`.
pub(super) fn upconvert_response(
    outcome: TrustTaskOutcome,
    spec: &WireSpecV02,
) -> TrustTaskOutcome {
    let TrustTaskOutcome {
        status,
        body,
        restart,
    } = outcome;
    let mut doc: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        // Not JSON (shouldn't happen) — pass the original bytes through.
        Err(_) => {
            return TrustTaskOutcome {
                status,
                body,
                restart,
            };
        }
    };

    let is_success_response = doc
        .get("type")
        .and_then(Value::as_str)
        .and_then(|t| t.strip_prefix(spec.uri))
        == Some("#response");
    if !is_success_response {
        return TrustTaskOutcome {
            status,
            body,
            restart,
        };
    }
    if let Some(payload) = doc.get_mut("payload") {
        apply_paths(payload, spec.response_paths, camelize);
        for path in spec.entry_paths {
            let segments: Vec<&str> = path.split('.').collect();
            apply_at_path_mut(payload, &segments, relocate_lifecycle);
        }
    }

    let new_body = serde_json::to_vec(&doc).unwrap_or(body);
    TrustTaskOutcome {
        status,
        body: new_body,
        restart,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn casing_transforms_are_inverse_and_idempotent() {
        for (kebab, camel) in [
            ("vault-read", "vaultRead"),
            ("apple-app-attest", "appleAppAttest"),
            ("did-self-issued", "didSelfIssued"),
            ("full-resync-required", "fullResyncRequired"),
            ("webauthn-uv", "webauthnUv"),
        ] {
            assert_eq!(camelize(kebab), camel, "camelize({kebab})");
            assert_eq!(kebabize(camel), kebab, "kebabize({camel})");
            // Idempotent on the target form.
            assert_eq!(camelize(camel), camel);
            assert_eq!(kebabize(kebab), kebab);
        }
        // Single words are no-ops in both directions.
        for w in ["mediator", "companion", "sign", "browser"] {
            assert_eq!(camelize(w), w);
            assert_eq!(kebabize(w), w);
        }
    }

    #[test]
    fn apply_at_path_fans_out_over_arrays_and_objects() {
        let mut v = serde_json::json!({
            "devices": [
                { "consumerKind": { "serviceKind": "ai-agent" }, "capabilities": ["vault-read", "sign"] },
                { "consumerKind": { "serviceKind": "mediator" }, "capabilities": ["proxy-login"] }
            ]
        });
        apply_paths(
            &mut v,
            &[
                "devices.*.consumerKind.serviceKind",
                "devices.*.capabilities.*",
            ],
            camelize,
        );
        assert_eq!(v["devices"][0]["consumerKind"]["serviceKind"], "aiAgent");
        assert_eq!(v["devices"][0]["capabilities"][0], "vaultRead");
        assert_eq!(v["devices"][0]["capabilities"][1], "sign");
        assert_eq!(v["devices"][1]["consumerKind"]["serviceKind"], "mediator");
        assert_eq!(v["devices"][1]["capabilities"][0], "proxyLogin");
    }

    #[test]
    fn free_text_at_non_enum_path_is_untouched() {
        // A display name that coincidentally looks like a token must not be
        // rewritten — it isn't on an enum path.
        let mut v = serde_json::json!({
            "binding": { "displayName": "vault-read", "capabilities": ["vault-read"] }
        });
        apply_paths(&mut v, &["binding.capabilities.*"], camelize);
        assert_eq!(
            v["binding"]["displayName"], "vault-read",
            "free text untouched"
        );
        assert_eq!(
            v["binding"]["capabilities"][0], "vaultRead",
            "enum value upcased"
        );
    }

    #[tokio::test]
    async fn upconvert_passes_through_reject_documents() {
        // A reject carries a different `type`; up-convert must not camelCase
        // its payload, only (harmlessly) leave it intact.
        let spec = lookup_0_2("https://trusttasks.org/spec/vault/get/0.3").unwrap();
        let doc = serde_json::json!({
            "id": "urn:uuid:2",
            "type": "https://trusttasks.org/spec/trust-task-error/0.3",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "code": "permission_denied", "reason": "nope" }
        });
        let outcome = TrustTaskOutcome {
            status: axum::http::StatusCode::FORBIDDEN,
            body: serde_json::to_vec(&doc).unwrap(),
            restart: false,
        };
        let out = upconvert_response(outcome, spec);
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["type"],
            "https://trusttasks.org/spec/trust-task-error/0.3"
        );
        assert_eq!(v["payload"]["code"], "permission_denied");
    }

    #[test]
    fn vault_upsert_request_downconverts_secretkind_and_target() {
        let spec = lookup_0_2("https://trusttasks.org/spec/vault/upsert/0.4").unwrap();
        let mut payload = serde_json::json!({
            "contextId": "personal",
            "label": "did-self-issued", // free-text label that LOOKS like a token
            "secretKind": "didSelfIssued",
            "targets": [
                { "kind": "webOrigin", "origin": "https://example.com" },
                { "kind": "iosApp", "bundleId": "com.example.app" },
                { "kind": "did", "did": "did:web:rp.example" }
            ]
        });
        downconvert_request(&mut payload, spec);
        assert_eq!(payload["secretKind"], "did-self-issued");
        assert_eq!(payload["targets"][0]["kind"], "web-origin");
        assert_eq!(payload["targets"][1]["kind"], "ios-app");
        assert_eq!(payload["targets"][2]["kind"], "did"); // single word, no-op
        // SiteTarget variant fields stay camelCase (not on enum paths).
        assert_eq!(payload["targets"][1]["bundleId"], "com.example.app");
        // Free-text label is NOT an enum path — untouched.
        assert_eq!(payload["label"], "did-self-issued");
    }

    #[tokio::test]
    async fn vault_list_response_upconverts_nested_enums() {
        let spec = lookup_0_2("https://trusttasks.org/spec/vault/list/0.4").unwrap();
        let doc = serde_json::json!({
            "id": "urn:uuid:9",
            "type": "https://trusttasks.org/spec/vault/list/0.4#response",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {
                "entries": [
                    { "id": "v1", "label": "oauth-tokens", "secretKind": "oauth-tokens",
                      "targets": [ { "kind": "ios-app", "bundleId": "x" } ] }
                ]
            }
        });
        let outcome = TrustTaskOutcome {
            status: axum::http::StatusCode::OK,
            body: serde_json::to_vec(&doc).unwrap(),
            restart: false,
        };
        let out = upconvert_response(outcome, spec);
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["type"],
            "https://trusttasks.org/spec/vault/list/0.4#response"
        );
        assert_eq!(v["payload"]["entries"][0]["secretKind"], "oauthTokens");
        assert_eq!(v["payload"]["entries"][0]["targets"][0]["kind"], "iosApp");
        // Free-text label coinciding with a token stays put.
        assert_eq!(v["payload"]["entries"][0]["label"], "oauth-tokens");
    }

    #[tokio::test]
    async fn vault_release_response_camelizes_sealed_secret_envelope_tag() {
        // The `sealedSecret.envelope` tag sits next to the JWE as a plaintext
        // key, so the edge transform must up-convert it to the canonical 0.2
        // `didcommAuthcrypt`. (The `VaultSecret.kind` inside the JWE is opaque
        // here — it's camelCased at seal time, exercised in the ops tests.)
        let spec = lookup_0_2("https://trusttasks.org/spec/vault/release/0.2").unwrap();
        let doc = serde_json::json!({
            "id": "urn:uuid:7",
            "type": "https://trusttasks.org/spec/vault/release/0.2#response",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {
                "sealedSecret": { "envelope": "didcomm-authcrypt", "jwe": "opaque.jwe.bytes" },
                "secretKind": "oauth-tokens",
                "ttlSeconds": 60
            }
        });
        let outcome = TrustTaskOutcome {
            status: axum::http::StatusCode::OK,
            body: serde_json::to_vec(&doc).unwrap(),
            restart: false,
        };
        let out = upconvert_response(outcome, spec);
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["type"],
            "https://trusttasks.org/spec/vault/release/0.2#response"
        );
        assert_eq!(
            v["payload"]["sealedSecret"]["envelope"], "didcommAuthcrypt",
            "envelope tag up-converted"
        );
        assert_eq!(v["payload"]["secretKind"], "oauthTokens");
        // The opaque JWE bytes are NOT a string on any enum path beyond the
        // `envelope` key, so they pass through verbatim.
        assert_eq!(v["payload"]["sealedSecret"]["jwe"], "opaque.jwe.bytes");
    }

    #[tokio::test]
    async fn vault_proxy_login_response_camelizes_sealed_session_blob_envelope_tag() {
        let spec = lookup_0_2("https://trusttasks.org/spec/vault/proxy-login/0.2").unwrap();
        let doc = serde_json::json!({
            "id": "urn:uuid:8",
            "type": "https://trusttasks.org/spec/vault/proxy-login/0.2#response",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {
                "sealedSessionBlob": { "envelope": "didcomm-authcrypt", "jwe": "opaque" },
                "sessionId": "s1",
                "expiresAt": "2026-06-17T00:00:00Z"
            }
        });
        let outcome = TrustTaskOutcome {
            status: axum::http::StatusCode::OK,
            body: serde_json::to_vec(&doc).unwrap(),
            restart: false,
        };
        let out = upconvert_response(outcome, spec);
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["payload"]["sealedSessionBlob"]["envelope"],
            "didcommAuthcrypt"
        );
    }

    #[test]
    fn vault_upsert_request_downconverts_sealed_secret_envelope_tag() {
        // A producer sends `sealedSecret.envelope: "didcommAuthcrypt"`;
        // down-convert hands the handler the kebab tag it parses.
        let spec = lookup_0_2("https://trusttasks.org/spec/vault/upsert/0.4").unwrap();
        let mut payload = serde_json::json!({
            "contextId": "personal",
            "secretKind": "oauthTokens",
            "targets": [],
            "label": "x",
            "sealedSecret": { "envelope": "didcommAuthcrypt", "jwe": "opaque" }
        });
        downconvert_request(&mut payload, spec);
        assert_eq!(payload["sealedSecret"]["envelope"], "didcomm-authcrypt");
        assert_eq!(payload["secretKind"], "oauth-tokens");
    }

    #[test]
    fn camelize_paths_camelizes_a_sealed_secret_body() {
        // The seal path camelizes the storage-form (kebab) secret body.
        let mut secret = serde_json::json!({
            "kind": "oauth-tokens",
            "loginConfig": { "format": "form-urlencoded" }
        });
        camelize_paths(&mut secret, &["kind", "loginConfig.format"]);
        assert_eq!(secret["kind"], "oauthTokens");
        assert_eq!(secret["loginConfig"]["format"], "formUrlencoded");
    }

    /// Every edge-transformed URI is a served one: the transform no longer
    /// rewrites the Type URI, so a row the dispatch table does not register
    /// would rewrite a payload nothing then handles.
    #[test]
    fn every_transformed_uri_is_dispatched() {
        let dispatched = super::super::dispatched_uris();
        for spec in WIRE_SPECS_V0_2 {
            assert!(
                dispatched.contains(&spec.uri),
                "{} is not dispatched",
                spec.uri
            );
            assert!(lookup_0_2(spec.uri).is_some());
        }
    }

    /// An archived or deleted entry's lifecycle members travel in `ext`, which
    /// the served `VaultEntry` component allows; an active entry has none.
    #[tokio::test]
    async fn lifecycle_members_move_into_ext() {
        let spec = lookup_0_2("https://trusttasks.org/spec/vault/list/0.4").unwrap();
        let doc = serde_json::json!({
            "id": "urn:uuid:10",
            "type": "https://trusttasks.org/spec/vault/list/0.4#response",
            "payload": {
                "entries": [
                    { "id": "v1", "secretKind": "password", "targets": [],
                      "status": "deleted", "deletedAt": "2026-01-01T00:00:00Z",
                      "graceUntil": "2026-02-01T00:00:00Z" },
                    { "id": "v2", "secretKind": "password", "targets": [] }
                ]
            }
        });
        let outcome = TrustTaskOutcome {
            status: axum::http::StatusCode::OK,
            body: serde_json::to_vec(&doc).unwrap(),
            restart: false,
        };
        let v: Value = serde_json::from_slice(&upconvert_response(outcome, spec).body).unwrap();
        let deleted = &v["payload"]["entries"][0];
        assert!(deleted.get("status").is_none(), "{deleted}");
        assert_eq!(deleted["ext"][LIFECYCLE_EXT]["status"], "deleted");
        assert_eq!(
            deleted["ext"][LIFECYCLE_EXT]["graceUntil"],
            "2026-02-01T00:00:00Z"
        );
        assert!(v["payload"]["entries"][1].get("ext").is_none());
    }
}
