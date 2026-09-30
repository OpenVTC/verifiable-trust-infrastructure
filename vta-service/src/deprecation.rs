//! How this service retires things.
//!
//! **Superseded Trust Task URIs** — [`SUPERSEDED_TASKS`] below. A Trust Task
//! URI a client still sends after a successor exists gets
//! `deprecated_trust_task_requests_total` (labelled by URI) incremented and a
//! successor named in the response, so a client can act rather than guess;
//! removal is gated on the counter reaching an observed zero. Added in #1045,
//! because until then a task could be retired only by deleting it and the
//! only evidence available was a source audit — grep the repos we can see and
//! reason about the rest.
//!
//! The table is pinned to what it describes by a test, because a row that
//! outlives its handler reads zero forever and **that is the same reading as
//! "safe to delete"**. See `superseded_tasks_are_dispatched`
//! (`crate::trust_tasks`).
//!
//! One consequence worth naming: a URI can now leave
//! `UNSPECCED_DISPATCHED_URIS` (or `vtc-service`'s `UNPUBLISHED_CANONICAL_OK`)
//! by *ceasing to exist* rather than by gaining a spec. Both censuses shrink
//! monotonically by test, so that departure looks identical to progress in the
//! count alone. A row here, and its removal, is the explicit record of which
//! one happened.
//!
//! **REST exceptions** — [`REST_EXCEPTIONS`] further down: the routes that
//! stay REST on purpose, because the protocol they serve is not one a Trust
//! Task can carry, tabulated with the reason beside each one.
//!
//! This module used to carry a third thing: a `SUPERSEDED` table of ~56
//! legacy REST *routes* a canonical Trust Task had superseded (advisory
//! `Deprecation`/`Link` headers plus a `deprecated_route_requests_total` hit
//! counter, gating removal on an observed zero the same way the task table
//! above does), covering acl, audit, config, contexts, did_templates, keys,
//! did_webvh servers/dids, `/vta/restart` and the `/api/trust-tasks`
//! spelling. This is a test deployment with no migration window and no
//! compat shims to keep working while a counter drains, so all of it was
//! deleted outright in one pass rather than marked and waited out — the
//! REST routes themselves are gone (see `routes::mod` and the deleted
//! `routes::{acl,audit,config,contexts,did_templates,keys}`), and the
//! machinery that would have tracked their usage went with them.

use metrics::counter;
use vta_sdk::trust_tasks;

// ─── REST routes kept on purpose ───────────────────────────────────────────

/// A REST route that stays REST because the protocol it serves is not one a
/// Trust Task can carry, and so has no successor to be superseded by.
///
/// The standing rule is that every remote operation is a Trust Task, carried
/// over TSP, DIDComm or HTTPS. The only transport restriction it permits is a
/// foreign-protocol interface: OAuth / WebAuthn ceremonies and DID resolution
/// files. A row here is that exception made explicit, with the reason beside
/// it, so a route that looks like an unconverted legacy route can be told
/// apart from one that is REST by design.
#[derive(Debug, Clone, Copy)]
pub struct RestException {
    /// HTTP method, upper-case.
    pub method: &'static str,
    /// The route's axum `MatchedPath` pattern.
    pub path: &'static str,
    /// The foreign protocol that makes the route REST.
    pub protocol: &'static str,
    /// The Trust Task a DID-holding client uses for the same operation, when
    /// one exists. The route is kept for the caller that cannot sign one.
    pub twin: Option<&'static str>,
    /// Why this route cannot be a Trust Task, in one line.
    pub reason: &'static str,
}

/// Why the passkey-VM routes stay REST.
const PASSKEY_VM_REASON: &str = "passkey enrolment is a WebAuthn ceremony driven from a browser \
     (the VTA auth portal, examples/vta-auth-demo) that holds only the bearer token \
     passkey-login issued, and no DID key with which to sign a Trust Task";

/// The REST exceptions.
///
/// Pinned by `every_rest_exception_names_a_live_route` (`tests/
/// api_integration.rs`), which fails when a row outlives its route.
const REST_EXCEPTIONS: &[RestException] = &[
    RestException {
        method: "POST",
        path: "/did/verification-methods/passkey/challenge",
        protocol: "WebAuthn",
        twin: Some(trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_0_1),
        reason: PASSKEY_VM_REASON,
    },
    RestException {
        method: "POST",
        path: "/did/verification-methods/passkey",
        protocol: "WebAuthn",
        twin: Some(trust_tasks::TASK_PASSKEY_VMS_ENROLL_SUBMIT_0_1),
        reason: PASSKEY_VM_REASON,
    },
    RestException {
        method: "GET",
        path: "/did/verification-methods/passkey",
        protocol: "WebAuthn",
        twin: Some(trust_tasks::TASK_PASSKEY_VMS_LIST_0_1),
        reason: PASSKEY_VM_REASON,
    },
    RestException {
        method: "DELETE",
        path: "/did/verification-methods/passkey/{fragment}",
        protocol: "WebAuthn",
        twin: Some(trust_tasks::TASK_PASSKEY_VMS_REVOKE_0_1),
        reason: PASSKEY_VM_REASON,
    },
    RestException {
        method: "POST",
        path: "/bootstrap/request",
        protocol: "pre-identity bootstrap",
        twin: None,
        reason: "the TEE's first boot, before any identity exists yet for it to sign a Trust \
                 Task with",
    },
    RestException {
        method: "GET",
        path: "/backup/blob/{bundle_id}",
        protocol: "bulk byte transfer",
        twin: None,
        reason: "a one-shot bearer-token-gated blob fetch; the control step (authorizing the \
                 backup/restore) is itself a Trust Task, this is just the bytes",
    },
    RestException {
        method: "POST",
        path: "/backup/blob/{bundle_id}",
        protocol: "bulk byte transfer",
        twin: None,
        reason: "a one-shot bearer-token-gated blob upload; the control step (authorizing the \
                 backup/restore) is itself a Trust Task, this is just the bytes",
    },
    RestException {
        method: "GET",
        path: "/openapi.json",
        protocol: "tooling/discovery",
        twin: None,
        reason: "describes the API shape, not a secret; unauthenticated by design so black-box \
                 conformance/fuzz tooling can fetch it before it holds a token",
    },
];

/// The REST-exception table, for tests that assert on its contents.
pub fn rest_exceptions_table() -> &'static [RestException] {
    REST_EXCEPTIONS
}

// ─── The superseded-task table ─────────────────────────────────────────────
//
// The Trust-Task half of everything above. A REST route gets `Deprecation:
// true`, a `Link: rel="successor-version"`, and a per-route hit counter, so it
// can be removed on evidence. A Trust Task URI had none of that: it could be
// retired only by deleting it, and the only available evidence was a source
// audit — grep this repo and the ones we can see, and reason about the rest.
// That was defensible for `vta/discovery/capabilities/1.0` (#1044: zero
// consumers anywhere, plus a member whose vocabulary corresponded to nothing)
// and it does not generalise. The next retirement may be one somebody is
// calling, and we would find out from a support ticket.
//
// ## Invention, not adoption — the framework has no signal to adopt
//
// Checked first, per #1045. The *registry* has the concept: a spec's front
// matter can say `status: retired` with `supersededBy`, which is how twelve
// `messaging/*` tasks were retired upstream. `trust-tasks-rs` (0.11) exposes
// none of it — `schema_index` maps URI → payload schema and nothing else,
// `Payload` carries `IS_BEARER` / `IS_PROOF_REQUIRED` and no lifecycle
// constant, and `trust-task-discovery/0.1`'s expanded `supportedTypes` entry is
// `additionalProperties: false` over `{type, requiredExt}`. So a consumer
// cannot read a task's retirement status at runtime and a producer has nowhere
// framework-defined to announce one. This stays local machinery until that
// changes; the vocabulary deliberately matches the registry's (`supersededBy`)
// so adopting a published signal later is a rename, not a redesign.

/// One Trust Task the VTA still dispatches and intends to stop dispatching.
///
/// Rows are added when a task is superseded and removed when the task itself
/// is — retirement is gated on `deprecated_trust_task_requests_total` reaching
/// zero for the URI, exactly as route removal is gated on
/// `deprecated_route_requests_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupersededTask {
    /// The Type URI clients still send. MUST be one the dispatch spine
    /// actually routes — pinned by `superseded_tasks_are_dispatched` in
    /// `crate::trust_tasks`. A row for a URI nothing dispatches reads zero
    /// forever, which is the "safe to delete" signal produced about something
    /// already deleted.
    pub uri: &'static str,
    /// The Type URI to send instead. Named on the wire so a client can act
    /// rather than guess.
    pub successor: &'static str,
    /// Why, in one line, rendered to the caller alongside the successor.
    pub reason: &'static str,
}

/// The table.
///
/// Seeded from what this workspace had already declared deprecated in prose:
/// the eleven dispatched URIs carrying `#[deprecated]` in
/// `vta_sdk::trust_tasks`, each naming its 0.2 successor. Those attributes
/// told a Rust caller to migrate and told a wire caller nothing at all, and no
/// instrument anywhere said whether anyone was still sending them.
///
/// `auth/passkey/login/{start,finish}/0.1` are deprecated too and are
/// deliberately **absent**: they are `REST_ROUTED_URIS`, served by dedicated
/// unauthenticated routes the dispatcher never sees, so a row here would count
/// nothing and read a permanent zero.
///
/// Naming the gap rather than hiding it: those two are covered by *neither*
/// instrument. The route table above excludes `/auth/*` on purpose (genuinely
/// REST, and the pre-login bootstrap that has to work before a Trust Task can
/// be authenticated at all), and a per-route counter could not separate 0.1
/// from 0.2 anyway — one path serves both and the only difference is the
/// casing of a `purpose` value inside the body. Distinguishing them needs a
/// counter inside those two handlers, which is its own change.
#[allow(deprecated)] // names the deprecated 0.1 URIs on purpose — that is the point
const SUPERSEDED_TASKS: &[SupersededTask] = &[
    // ── did-templates ───────────────────────────────────────────────────
    //
    // 3.0 exists because 2.0's template schema pins `schemaVersion` to
    // `const: 1` and so cannot express a `keys` block at all. 2.0 has no
    // defect and stays dispatched: it remains a correct way to manage a v1
    // template, and the service holds a 2.0 caller to exactly that (see
    // `did_templates::max_template_schema_version`). These rows are what tell
    // such a caller where to go, and let removal wait on the usage counter
    // reaching zero rather than a guessed date.
    //
    // `delete` and `render` are absent deliberately — neither carries a
    // template shape, so neither gained a 3.0.
    SupersededTask {
        uri: trust_tasks::TASK_DID_TEMPLATES_LIST_2_0,
        successor: trust_tasks::TASK_DID_TEMPLATES_LIST_3_0,
        reason: "3.0 returns records that may carry a `keys` block; 2.0's schema cannot \
                 express one, so a post-quantum template is unreadable through it",
    },
    SupersededTask {
        uri: trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
        successor: trust_tasks::TASK_DID_TEMPLATES_CREATE_3_0,
        reason: "3.0 accepts a template declaring `schemaVersion` 2 and a `keys` block, \
                 which names each key slot's algorithms",
    },
    SupersededTask {
        uri: trust_tasks::TASK_DID_TEMPLATES_GET_2_0,
        successor: trust_tasks::TASK_DID_TEMPLATES_GET_3_0,
        reason: "3.0 returns a record that may carry a `keys` block; 2.0's schema cannot \
                 express one, so a post-quantum template is unreadable through it",
    },
    SupersededTask {
        uri: trust_tasks::TASK_DID_TEMPLATES_UPDATE_2_0,
        successor: trust_tasks::TASK_DID_TEMPLATES_UPDATE_3_0,
        reason: "3.0 accepts a template declaring `schemaVersion` 2 and a `keys` block, \
                 which names each key slot's algorithms",
    },
    // ── contexts ────────────────────────────────────────────────────────
    //
    // 1.0 has no defect for what it expresses and stays dispatched through the
    // same handler; it simply cannot say "no DID".
    SupersededTask {
        uri: trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0,
        successor: trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_1,
        reason: "1.1 accepts `did: null`, which clears the context's DID, and requires a \
                 string `did` to be a DID; 1.0 can only replace one",
    },
    // ── auth ────────────────────────────────────────────────────────────
    SupersededTask {
        uri: trust_tasks::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_1,
        successor: trust_tasks::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_2,
        reason: "0.2 spells the evidence enum `didSigned` in camelCase; the payload is \
                 signed, so the two versions have separate typed handlers rather than \
                 an edge transform",
    },
    // ── device ──────────────────────────────────────────────────────────
    SupersededTask {
        uri: trust_tasks::TASK_DEVICE_REGISTER_0_1,
        successor: trust_tasks::TASK_DEVICE_REGISTER_0_2,
        reason: "0.2 spells the enum values in camelCase",
    },
    SupersededTask {
        uri: trust_tasks::TASK_DEVICE_HEARTBEAT_0_1,
        successor: trust_tasks::TASK_DEVICE_HEARTBEAT_0_2,
        reason: "0.2 spells the enum values in camelCase",
    },
    SupersededTask {
        uri: trust_tasks::TASK_DEVICE_LIST_0_1,
        successor: trust_tasks::TASK_DEVICE_LIST_0_2,
        reason: "0.2 spells the enum values in camelCase",
    },
    SupersededTask {
        uri: trust_tasks::TASK_DEVICE_SET_WAKE_0_1,
        successor: trust_tasks::TASK_DEVICE_SET_WAKE_0_2,
        reason: "no enum values changed; the bump is canonical-version alignment, so \
                 the whole device slice sits on one version",
    },
    SupersededTask {
        uri: trust_tasks::TASK_DEVICE_WIPE_0_1,
        successor: trust_tasks::TASK_DEVICE_WIPE_0_2,
        reason: "0.2 spells the `scope` enum value `cacheAndKeys` in camelCase",
    },
    // ── vault ───────────────────────────────────────────────────────────
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_LIST_0_1,
        successor: trust_tasks::TASK_VAULT_LIST_0_2,
        reason: "0.2 spells secretKind and the related enums in camelCase",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_LIST_0_2,
        successor: trust_tasks::TASK_VAULT_LIST_0_3,
        reason: "0.3 replaces AttachmentRef's bare-hex `sha256` with a multibase \
                 `digestMultibase`, which names its own hash algorithm",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_GET_0_1,
        successor: trust_tasks::TASK_VAULT_GET_0_2,
        reason: "0.2 spells the response enums in camelCase",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_GET_0_2,
        successor: trust_tasks::TASK_VAULT_GET_0_3,
        reason: "0.3 replaces AttachmentRef's bare-hex `sha256` with a multibase \
                 `digestMultibase`, which names its own hash algorithm",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_UPSERT_0_1,
        successor: trust_tasks::TASK_VAULT_UPSERT_0_2,
        reason: "0.2 spells the secretKind / sealed-envelope / target enums in camelCase",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_UPSERT_0_2,
        successor: trust_tasks::TASK_VAULT_UPSERT_0_3,
        reason: "0.3 replaces AttachmentRef's bare-hex `sha256` with a multibase \
                 `digestMultibase`, which names its own hash algorithm",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_RELEASE_0_1,
        successor: trust_tasks::TASK_VAULT_RELEASE_0_2,
        reason: "0.2 spells the secretKind / sealed-envelope / step-up-proof enums in \
                 camelCase, inside the sealed cleartext as well as around it",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_PROXY_LOGIN_0_1,
        successor: trust_tasks::TASK_VAULT_PROXY_LOGIN_0_2,
        reason: "0.2 spells the site-target / step-up-proof enums in camelCase, inside \
                 the sealed cleartext as well as around it",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_SIGN_TRUST_TASK_0_1,
        successor: trust_tasks::TASK_VAULT_SIGN_TRUST_TASK_0_2,
        reason: "0.2 spells the step-up-proof enums in camelCase",
    },
];

/// The table, for the dispatch spine and for tests that assert on its contents.
pub fn superseded_tasks_table() -> &'static [SupersededTask] {
    SUPERSEDED_TASKS
}

/// The row for `type_uri`, or `None` when the task is not superseded.
pub fn superseded_task(type_uri: &str) -> Option<&'static SupersededTask> {
    SUPERSEDED_TASKS.iter().find(|t| t.uri == type_uri)
}

/// Top-level document member carrying the deprecation notice.
///
/// A reverse-DNS name, matching SPEC §4.5.1's `ext` namespace convention and
/// the `org.openvtc.*` names this workspace already uses (`vault-session`,
/// `authorization-context`, `purpose`).
///
/// **Document level, not `payload.ext`.** The framework's envelope keeps
/// unrecognized top-level members in `TrustTask::extra`, and SPEC §7.1/§7.2
/// tells consumers to preserve rather than reject them, so a member here
/// cannot break a client that has never heard of it. `payload` can make no
/// such promise: every published payload schema is `additionalProperties:
/// false`, the generated `Response` types are `deny_unknown_fields`, and the
/// conformance sweep validates response payloads against those schemas — so a
/// member there would have to go in per-spec, and only for specs whose schema
/// happens to define `ext`. This is the Trust-Task analogue of putting the
/// REST signal in a header: beside the answer rather than inside it.
pub const DEPRECATION_MEMBER: &str = "org.openvtc.deprecation";

/// Record a dispatch of a superseded task.
///
/// Unlike [`mark_superseded`], this counts the request whatever the outcome.
/// The route middleware filters non-success responses because an unauthorised
/// request there says nothing about a client depending on the route — those
/// routes are reachable without credentials. The dispatch spine is behind
/// authentication on all three transports (bearer on REST, authcrypt sender on
/// DIDComm, VID on TSP), so there is no unauthenticated-prober class to filter
/// out: an authenticated party emitting this URI *is* the usage being
/// measured, whether or not its payload turned out to be well-formed.
pub fn note_superseded_task(task: &SupersededTask) {
    counter!("deprecated_trust_task_requests_total", "task" => task.uri).increment(1);
}

/// Stamp the deprecation notice onto a serialized response document.
///
/// Refuses to touch a document carrying a `proof`: adding a member after
/// signing voids the signature, and a silently-invalid proof is worse than an
/// absent notice. Also a no-op on a body that is not a JSON object, or that
/// already carries the member.
pub fn annotate_superseded(body: &mut Vec<u8>, task: &SupersededTask) {
    let Ok(mut doc) = serde_json::from_slice::<serde_json::Value>(body) else {
        return;
    };
    let Some(obj) = doc.as_object_mut() else {
        return;
    };
    if obj.contains_key("proof") || obj.contains_key(DEPRECATION_MEMBER) {
        return;
    }
    obj.insert(
        DEPRECATION_MEMBER.to_string(),
        serde_json::json!({
            "supersededBy": task.successor,
            "reason": task.reason,
        }),
    );
    if let Ok(bytes) = serde_json::to_vec(&doc) {
        *body = bytes;
    }
}

#[cfg(test)]
mod superseded_task_tests {
    use super::*;

    #[test]
    fn a_notice_rides_the_document_top_level_not_the_payload() {
        let task = &SUPERSEDED_TASKS[0];
        let mut body = serde_json::to_vec(&serde_json::json!({
            "id": "urn:uuid:1",
            "type": "https://trusttasks.org/spec/device/list/0.1#response",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "devices": [] },
        }))
        .unwrap();

        annotate_superseded(&mut body, task);

        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(doc[DEPRECATION_MEMBER]["supersededBy"], task.successor);
        assert_eq!(doc[DEPRECATION_MEMBER]["reason"], task.reason);
        // The payload is what a published schema validates and what a generated
        // `Response` type deserialises with `deny_unknown_fields`. It must come
        // back unchanged.
        assert_eq!(doc["payload"], serde_json::json!({ "devices": [] }));
    }

    #[test]
    fn a_signed_document_is_left_alone() {
        // Stamping a member into a signed document voids the proof over it. A
        // notice is worth less than a verifiable signature, so the notice loses.
        let task = &SUPERSEDED_TASKS[0];
        let original = serde_json::json!({
            "id": "urn:uuid:1",
            "type": "https://trusttasks.org/spec/device/list/0.1#response",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {},
            "proof": { "type": "DataIntegrityProof" },
        });
        let mut body = serde_json::to_vec(&original).unwrap();

        annotate_superseded(&mut body, task);

        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            doc, original,
            "a proofed document must be returned untouched"
        );
    }

    #[test]
    fn annotating_twice_does_not_nest_or_duplicate() {
        // The spine annotates exactly once today — the idempotency store
        // records the un-annotated outcome and the replay is annotated on its
        // way out like any other. This pins the helper against a future caller
        // that does not preserve that ordering: a second stamp must be a no-op,
        // not a nested or duplicated notice.
        let task = &SUPERSEDED_TASKS[0];
        let mut body = serde_json::to_vec(&serde_json::json!({
            "id": "urn:uuid:1",
            "type": "x",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {},
        }))
        .unwrap();

        annotate_superseded(&mut body, task);
        let once = body.clone();
        annotate_superseded(&mut body, task);

        assert_eq!(body, once);
    }

    #[test]
    fn a_body_that_is_not_a_document_is_left_alone() {
        // `error_response` falls back to an empty body when serialisation
        // fails. Annotation must not turn that into a panic or a fake document.
        let task = &SUPERSEDED_TASKS[0];
        let mut empty: Vec<u8> = Vec::new();
        annotate_superseded(&mut empty, task);
        assert!(empty.is_empty());

        let mut array = b"[1,2,3]".to_vec();
        annotate_superseded(&mut array, task);
        assert_eq!(array, b"[1,2,3]");
    }

    #[test]
    fn every_row_names_a_different_successor() {
        // A row whose successor is itself would advertise "migrate to where you
        // already are" and could never be retired.
        for t in SUPERSEDED_TASKS {
            assert_ne!(
                t.uri, t.successor,
                "{} is listed as its own successor",
                t.uri
            );
            assert!(!t.reason.is_empty(), "{} has no reason", t.uri);
        }
    }

    #[test]
    fn no_uri_is_listed_twice() {
        // `superseded_task` returns the first match, so a duplicate would make
        // one of the two rows unreachable — and unreachable is exactly what a
        // zero reading means.
        let mut seen: Vec<&str> = SUPERSEDED_TASKS.iter().map(|t| t.uri).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "a URI is listed more than once");
    }
}

#[cfg(test)]
mod rest_exception_tests {
    use super::*;

    #[test]
    fn every_exception_says_why() {
        for e in REST_EXCEPTIONS {
            assert!(
                !e.protocol.is_empty(),
                "`{} {}` names no protocol",
                e.method,
                e.path
            );
            assert!(
                !e.reason.is_empty(),
                "`{} {}` gives no reason",
                e.method,
                e.path
            );
        }
    }
}
