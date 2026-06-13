//! Trust-Task **0.2 dual-accept** edge transform.
//!
//! The 0.2 wire form of a spec differs from 0.1 in exactly two ways: the
//! `TYPE_URI` minor bumps to `/0.2`, and a fixed set of enum *values* switch
//! from kebab-case to camelCase (`vault-read` → `vaultRead`,
//! `apple-app-attest` → `appleAppAttest`, …). The Rust struct shapes are
//! otherwise identical.
//!
//! For specs whose payload is **not** signed (bearer-authenticated:
//! device/*, vault/*, passkey login) we exploit that by reusing the existing
//! 0.1 handlers unchanged:
//!
//! 1. **Down-convert** an inbound 0.2 request — rewrite the enum values at the
//!    spec's known enum field paths back to kebab ([`kebabize`]), and retype
//!    the envelope to the 0.1 URI — then dispatch it through the ordinary 0.1
//!    machinery.
//! 2. **Up-convert** the handler's (kebab) response — rewrite the enum values
//!    at the response's known enum field paths to camel ([`camelize`]) and
//!    retype the response document to `…/0.2#response`.
//!
//! Why path-targeted and not a blanket value rewrite: a free-text field
//! (a display name, a label) could coincidentally equal an enum token. By
//! transforming only at the declared enum paths we never touch opaque or
//! free-text values (JWEs, DIDs, labels).
//!
//! `kebabize`/`camelize` are deterministic inverses and each is idempotent on
//! its own target form, so a path that happens to carry an unchanged
//! single-word value (`mediator`, `companion`) is a safe no-op.
//!
//! **Not** used for specs whose payload carries a signature over the document
//! (e.g. `auth/step-up/approve-response`, where the approver signs the
//! payload) — mutating those bytes would void the proof, so they get genuine
//! version-matched typed handlers instead.

use serde_json::Value;

use super::TrustTaskOutcome;

/// One spec's 0.1 ⇄ 0.2 mapping. Paths are `.`-separated and relative to the
/// document `payload`; a `*` segment fans out over every array element or
/// object value.
pub(super) struct WireSpecV02 {
    /// Canonical 0.1 type URI the 0.2 request is down-converted to.
    pub uri_0_1: &'static str,
    /// 0.2 type URI this entry matches on the wire.
    pub uri_0_2: &'static str,
    /// Enum field paths in the **request** payload (down-converted camel→kebab).
    pub request_paths: &'static [&'static str],
    /// Enum field paths in the **response** payload (up-converted kebab→camel).
    pub response_paths: &'static [&'static str],
}

/// Registry of dual-accepted, edge-transformed specs. Signed-payload specs
/// (step-up) are intentionally absent — they get typed handlers.
pub(super) const WIRE_SPECS_V0_2: &[WireSpecV02] = &[
    // ── device slice ────────────────────────────────────────────────
    WireSpecV02 {
        uri_0_1: "https://trusttasks.org/spec/device/register/0.1",
        uri_0_2: "https://trusttasks.org/spec/device/register/0.2",
        request_paths: &["consumerKind.serviceKind", "attestation.kind"],
        response_paths: &["binding.consumerKind.serviceKind", "binding.capabilities.*"],
    },
    WireSpecV02 {
        uri_0_1: "https://trusttasks.org/spec/device/heartbeat/0.1",
        uri_0_2: "https://trusttasks.org/spec/device/heartbeat/0.2",
        request_paths: &[],
        response_paths: &["queuedOperations.*.kind", "syncHint"],
    },
    WireSpecV02 {
        uri_0_1: "https://trusttasks.org/spec/device/list/0.1",
        uri_0_2: "https://trusttasks.org/spec/device/list/0.2",
        request_paths: &[
            "capabilityFilter",
            "consumerKindFilter",
            "formFactorFilter",
            "serviceKindFilter",
        ],
        response_paths: &[
            "devices.*.consumerKind.serviceKind",
            "devices.*.capabilities.*",
        ],
    },
    WireSpecV02 {
        // No enum fields in either direction — pure minor-version bump.
        uri_0_1: "https://trusttasks.org/spec/device/set-wake/0.1",
        uri_0_2: "https://trusttasks.org/spec/device/set-wake/0.2",
        request_paths: &[],
        response_paths: &[],
    },
    // ── vault slice ─────────────────────────────────────────────────
    // SecretKind (`oauth-tokens`, `did-self-issued`, …) and the SiteTarget
    // `kind` discriminator (`web-origin`, `ios-app`, `android-app`) carry the
    // renamed values. `sealedSecret`/`sealedSessionBlob` envelope tags
    // (`didcomm-authcrypt`, …) are NOT renamed in 0.2, and the JWE / step-up
    // proof / signed-envelope payloads are opaque — none are on enum paths, so
    // they pass through byte-exact.
    WireSpecV02 {
        uri_0_1: "https://trusttasks.org/spec/vault/list/0.1",
        uri_0_2: "https://trusttasks.org/spec/vault/list/0.2",
        request_paths: &["secretKind"],
        response_paths: &["entries.*.secretKind", "entries.*.targets.*.kind"],
    },
    WireSpecV02 {
        uri_0_1: "https://trusttasks.org/spec/vault/get/0.1",
        uri_0_2: "https://trusttasks.org/spec/vault/get/0.2",
        request_paths: &[],
        response_paths: &["entry.secretKind", "entry.targets.*.kind"],
    },
    WireSpecV02 {
        uri_0_1: "https://trusttasks.org/spec/vault/upsert/0.1",
        uri_0_2: "https://trusttasks.org/spec/vault/upsert/0.2",
        request_paths: &["secretKind", "targets.*.kind"],
        response_paths: &["entry.secretKind", "entry.targets.*.kind"],
    },
    WireSpecV02 {
        uri_0_1: "https://trusttasks.org/spec/vault/release/0.1",
        uri_0_2: "https://trusttasks.org/spec/vault/release/0.2",
        request_paths: &["target.kind"],
        response_paths: &["secretKind"],
    },
    WireSpecV02 {
        uri_0_1: "https://trusttasks.org/spec/vault/proxy-login/0.1",
        uri_0_2: "https://trusttasks.org/spec/vault/proxy-login/0.2",
        request_paths: &["target.kind"],
        response_paths: &[],
    },
    WireSpecV02 {
        // Request/response carry the unsigned/signed Trust-Task envelope verbatim
        // (signed bytes — must not be mutated); no SecretKind/SiteTarget fields.
        uri_0_1: "https://trusttasks.org/spec/vault/sign-trust-task/0.1",
        uri_0_2: "https://trusttasks.org/spec/vault/sign-trust-task/0.2",
        request_paths: &[],
        response_paths: &[],
    },
];

/// Every 0.2 URI handled by the edge transform — consumed by the dispatcher's
/// parity harness (these are "tracked" without a `dispatch_typed` arm).
#[allow(dead_code)] // consumed by the test-only parity harness
pub(super) const WIRE_V0_2_URIS: &[&str] = &[
    "https://trusttasks.org/spec/device/register/0.2",
    "https://trusttasks.org/spec/device/heartbeat/0.2",
    "https://trusttasks.org/spec/device/list/0.2",
    "https://trusttasks.org/spec/device/set-wake/0.2",
    "https://trusttasks.org/spec/vault/list/0.2",
    "https://trusttasks.org/spec/vault/get/0.2",
    "https://trusttasks.org/spec/vault/upsert/0.2",
    "https://trusttasks.org/spec/vault/release/0.2",
    "https://trusttasks.org/spec/vault/proxy-login/0.2",
    "https://trusttasks.org/spec/vault/sign-trust-task/0.2",
];

/// Look up the edge-transform spec for an inbound type URI, if it's a
/// dual-accepted 0.2 URI.
pub(super) fn lookup_0_2(type_uri: &str) -> Option<&'static WireSpecV02> {
    WIRE_SPECS_V0_2.iter().find(|s| s.uri_0_2 == type_uri)
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

/// Down-convert a 0.2 request `payload` in place — rewrite the enum values at
/// `spec.request_paths` to kebab so the existing 0.1 handler parses it.
pub(super) fn downconvert_request(payload: &mut Value, spec: &WireSpecV02) {
    apply_paths(payload, spec.request_paths, kebabize);
}

/// Down-convert (camel→kebab) the enum values at `paths` in `payload`.
///
/// Exposed for the **typed** slices (e.g. step-up) whose payload is signed:
/// they can't mutate the document itself (it would void the proof), so they
/// down-convert a *copy* of the payload purely to parse it with the v0_1
/// types, while proof verification and the echoed response still use the
/// original 0.2 document.
pub(super) fn kebabize_paths(payload: &mut Value, paths: &[&str]) {
    apply_paths(payload, paths, kebabize);
}

/// Up-convert a dispatch outcome: retype `…/0.1#response` → `…/0.2#response`
/// and rewrite the response payload's enum values to camel. Error/reject
/// documents (a different `type`) are passed through with only the type
/// prefix swapped, since their payload carries no spec enums.
///
/// Operates on the typed [`TrustTaskOutcome`] body directly — the status is
/// preserved untouched and there is no round-trip through an `axum::Response`.
pub(super) fn upconvert_response(
    outcome: TrustTaskOutcome,
    spec: &WireSpecV02,
) -> TrustTaskOutcome {
    let TrustTaskOutcome { status, body } = outcome;
    let mut doc: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        // Not JSON (shouldn't happen) — pass the original bytes through.
        Err(_) => return TrustTaskOutcome { status, body },
    };

    // Retype the response document. A success response echoes the (now 0.1)
    // request type with a `#response` fragment; rejects carry their own error
    // type and are left as-is apart from a 0.1→0.2 prefix swap if present.
    let mut is_success_response = false;
    if let Some(Value::String(t)) = doc.get_mut("type")
        && let Some(fragment) = t.strip_prefix(spec.uri_0_1)
    {
        is_success_response = fragment == "#response";
        *t = format!("{}{}", spec.uri_0_2, fragment);
    }

    if is_success_response && let Some(payload) = doc.get_mut("payload") {
        apply_paths(payload, spec.response_paths, camelize);
    }

    let new_body = serde_json::to_vec(&doc).unwrap_or(body);
    TrustTaskOutcome {
        status,
        body: new_body,
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

    #[test]
    fn device_list_request_downconverts_enums() {
        // A 0.2 device/list request carries camelCase enum values; after
        // down-convert the existing v0_1 handler must see kebab.
        let spec = lookup_0_2("https://trusttasks.org/spec/device/list/0.2").unwrap();
        let mut payload = serde_json::json!({
            "capabilityFilter": "vaultRead",
            "serviceKindFilter": "aiAgent",
            "consumerKindFilter": "service",
            "includeDisabled": false
        });
        downconvert_request(&mut payload, spec);
        assert_eq!(payload["capabilityFilter"], "vault-read");
        assert_eq!(payload["serviceKindFilter"], "ai-agent");
        assert_eq!(payload["consumerKindFilter"], "service"); // unchanged single word
        assert_eq!(payload["includeDisabled"], false); // non-enum untouched
    }

    #[tokio::test]
    async fn device_list_response_upconverts_and_retypes() {
        // The v0_1 handler echoes a `…/device/list/0.1#response` doc with
        // kebab enum values; up-convert must retype to 0.2 and camelCase the
        // enum values at the declared response paths.
        let spec = lookup_0_2("https://trusttasks.org/spec/device/list/0.2").unwrap();
        let doc = serde_json::json!({
            "id": "urn:uuid:1",
            "type": "https://trusttasks.org/spec/device/list/0.1#response",
            "issuer": "did:web:vta",
            "recipient": "did:key:zClient",
            "payload": {
                "devices": [
                    { "deviceId": "d1", "displayName": "vault-read",
                      "consumerKind": { "kind": "service", "serviceKind": "ai-agent" },
                      "capabilities": ["vault-read", "sign"] }
                ],
                "truncated": false
            }
        });
        let outcome = TrustTaskOutcome {
            status: axum::http::StatusCode::OK,
            body: serde_json::to_vec(&doc).unwrap(),
        };

        let out = upconvert_response(outcome, spec);
        let v: Value = serde_json::from_slice(&out.body).unwrap();

        assert_eq!(
            v["type"],
            "https://trusttasks.org/spec/device/list/0.2#response"
        );
        assert_eq!(
            v["payload"]["devices"][0]["consumerKind"]["serviceKind"],
            "aiAgent"
        );
        assert_eq!(v["payload"]["devices"][0]["capabilities"][0], "vaultRead");
        assert_eq!(v["payload"]["devices"][0]["capabilities"][1], "sign");
        // A free-text field that coincidentally equals an enum token must NOT
        // be rewritten — it isn't on a declared response path.
        assert_eq!(v["payload"]["devices"][0]["displayName"], "vault-read");
    }

    #[tokio::test]
    async fn upconvert_passes_through_reject_documents() {
        // A reject carries a different `type`; up-convert must not camelCase
        // its payload, only (harmlessly) leave it intact.
        let spec = lookup_0_2("https://trusttasks.org/spec/device/list/0.2").unwrap();
        let doc = serde_json::json!({
            "id": "urn:uuid:2",
            "type": "https://trusttasks.org/spec/trust-task-error/0.1",
            "payload": { "code": "permission_denied", "reason": "nope" }
        });
        let outcome = TrustTaskOutcome {
            status: axum::http::StatusCode::FORBIDDEN,
            body: serde_json::to_vec(&doc).unwrap(),
        };
        let out = upconvert_response(outcome, spec);
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["type"],
            "https://trusttasks.org/spec/trust-task-error/0.1"
        );
        assert_eq!(v["payload"]["code"], "permission_denied");
    }

    #[test]
    fn vault_upsert_request_downconverts_secretkind_and_target() {
        let spec = lookup_0_2("https://trusttasks.org/spec/vault/upsert/0.2").unwrap();
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
        let spec = lookup_0_2("https://trusttasks.org/spec/vault/list/0.2").unwrap();
        let doc = serde_json::json!({
            "id": "urn:uuid:9",
            "type": "https://trusttasks.org/spec/vault/list/0.1#response",
            "payload": {
                "entries": [
                    { "id": "v1", "label": "oauth-tokens", "secretKind": "oauth-tokens",
                      "targets": [ { "kind": "ios-app", "bundleId": "x" } ] }
                ],
                "truncated": false
            }
        });
        let outcome = TrustTaskOutcome {
            status: axum::http::StatusCode::OK,
            body: serde_json::to_vec(&doc).unwrap(),
        };
        let out = upconvert_response(outcome, spec);
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["type"],
            "https://trusttasks.org/spec/vault/list/0.2#response"
        );
        assert_eq!(v["payload"]["entries"][0]["secretKind"], "oauthTokens");
        assert_eq!(v["payload"]["entries"][0]["targets"][0]["kind"], "iosApp");
        // Free-text label coinciding with a token stays put.
        assert_eq!(v["payload"]["entries"][0]["label"], "oauth-tokens");
    }

    #[test]
    fn registry_uris_are_consistent() {
        // Every spec's 0.2 URI is in the parity list, and 0.1/0.2 differ only
        // by the minor version.
        for spec in WIRE_SPECS_V0_2 {
            assert!(WIRE_V0_2_URIS.contains(&spec.uri_0_2), "{}", spec.uri_0_2);
            assert_eq!(spec.uri_0_1.replace("/0.1", "/0.2"), spec.uri_0_2);
            assert!(lookup_0_2(spec.uri_0_2).is_some());
        }
    }
}
