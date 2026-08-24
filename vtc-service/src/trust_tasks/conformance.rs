//! The VTC's schema-conformance sweep (#1059): every Trust Task this service
//! binds to a **published** `spec/vtc/*` URI must carry that URI's wire shape.
//!
//! ## Why this exists
//!
//! `vtc-service/tests/trust_task_manifest.rs` already runs two parity checks,
//! and both are about *identity*, not *shape*:
//! `every_bound_task_is_published_or_excepted` (coverage) and
//! `every_bound_canonical_task_exists_in_the_registry` (the URI resolves in
//! `trust_tasks_rs::schema_index`). Neither looks at a payload, and there is
//! no runtime validation on this side either — the document dispatcher's
//! `parse_payload` (`trust_tasks/helpers.rs:59`) is a bare
//! `serde_json::from_value`, and the REST layer's Trust-Task gate checks the
//! header URI, not the body. So a VTC response could diverge arbitrarily from
//! the schema its URI names and every gate in the repo stayed green.
//!
//! This is the check `vta-service` got in #857
//! (`vta-service/src/trust_tasks/conformance.rs`), whose module docs name the
//! defect class: *"Nothing checked correctness: that a task bound to a
//! published URI actually speaks that URI's schema."* The VTC never got the
//! equivalent. This file is it, and it deliberately follows that file's shape
//! — witness table, derived census, mechanical non-vacuity — rather than
//! inventing a second idiom for the same job.
//!
//! ## How it works
//!
//! The URI census is **derived, not hand-maintained**, from the two places
//! this service binds a task:
//!
//! - the REST tower layers (`tt` / `ttl` in `routes/mod.rs`), which cannot be
//!   enumerated from a built `Router`, so they are read as source text — the
//!   same blunt-but-confined technique `tests/trust_task_manifest.rs` uses;
//! - [`super::DISPATCHED_URIS`], the document dispatcher's own list, which is
//!   what REST-as-document, DIDComm and TSP all route through.
//!
//! That union, filtered to what `schema_index::schema_for` resolves, is the
//! scope. Every URI in it MUST have an entry in [`table`]: a [`Witness`]
//! carrying a representative request and response, or an annotated
//! [`Conformance::KnownDrift`] debt entry.
//!
//! ## Scope: `spec/vtc/*` only
//!
//! The VTC also binds 36 URIs in the shared `spec/{acl,audit,auth,config,
//! policy}/*` families. Those are **not** covered here, and that is a stated
//! limit rather than an oversight: #1059 scopes to the VTC's own family, and
//! the shared families are served by both daemons, so witnessing them belongs
//! with a decision about which service's response shape is canonical. The
//! mechanism below is prefix-parameterised at exactly one place
//! ([`VTC_PREFIX`]), so widening it later is a one-line change plus the
//! witnesses.
//!
//! ## Both sides are schema-validated, not just parsed
//!
//! Each witness's request must parse as the generated `specs::…::Payload` and
//! its response as `specs::…::Response` — the generated types carry
//! `deny_unknown_fields` plus the spec's required set, so parsing them is
//! itself an assertion. But parsing alone is strictly weaker than the schema:
//! serde reads `null` into an `Option<T>` where JSON Schema types the member
//! `"string"` and refuses it, and serde ignores `const` / `enum` / `pattern`
//! entirely. `submit/0.1`'s response `status` is `const: "pending"`; nothing
//! in the generated struct enforces that.
//!
//! So both sides are also validated against their embedded schema. This is
//! where the VTC harness can be stricter than the VTA's, which validates the
//! request only and says so: the VTA's note ("the codegen emits
//! `ValidatedPayload` for `Payload` but not for `Response`") was true of the
//! 0.4/0.5 codegen and is **stale** at the 0.11 series this workspace pins —
//! `trust-tasks-rs` now emits `impl Payload for Response` with the response
//! schema inlined, and `validate::ValidatedPayload` is a blanket impl over
//! `Payload`. Since a response schema is the thing #1059 is about, this file
//! uses it.
//!
//! ## The table is keyed by type, not by URI literal
//!
//! [`checked!`] takes the generated `Payload` / `Response` types and reads the
//! URI off the first one, `<P as Payload>::TYPE_URI`. Two reasons, both about
//! the check keeping its teeth:
//!
//! 1. A hand-written URI literal can be paired with the wrong generated type,
//!    and the sweep would then cheerfully validate `members/list`'s response
//!    against `members/show`'s schema and report conformance.
//! 2. The census scans this crate's source for `spec/vtc/` literals. If this
//!    file contained any, it would find its own table and the stale-witness
//!    direction of the coverage assertion would be vacuous — a witness would
//!    prove itself in scope.
//!
//! ## Non-vacuity is enforced mechanically
//!
//! Every witness is drifted (an unknown member injected) after the good case
//! passes, and the drifted form MUST be rejected on both sides — a schema
//! that accepts anything cannot produce a green row. The VTA learned this the
//! expensive way: its `acl/update` defect survived three PRs because "adding a
//! forbidden member makes this fail" passed while the body was *already*
//! failing for an unrelated reason.
//!
//! [`Conformance::KnownDrift`] carries the same treatment in reverse. A debt
//! entry states which side diverges and carries the real fixtures, and the
//! sweep asserts that the named side **fails** and the other side **passes**.
//! A prose-only debt note would be unfalsifiable: it could not tell you when
//! the drift was fixed, and it could not tell you it had been mis-diagnosed.
//! This is the one place this file's shape differs from the VTA's
//! `KnownDrift(&'static str)`, and the reason is that the VTA's arm is empty
//! — it has never had to describe a real divergence, and the VTC's has 33 on
//! day one.
//!
//! ## When this fails
//!
//! A newly bound published URI with no witness fails the coverage assertion
//! **by design** — add a witness, or a `KnownDrift` entry with a stated
//! reason. A witness for a URI nothing binds any more fails the same
//! assertion from the other direction, and that direction is what tells you a
//! fold landed.

use std::collections::BTreeSet;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use trust_tasks_rs::Payload;
use trust_tasks_rs::validate::ValidatedPayload;

use super::DISPATCHED_URIS;

/// The one place the sweep's family scope is written down. See the module
/// docs' "Scope" section for why it is `vtc/` and not `spec/`.
const VTC_PREFIX: &str = "https://trusttasks.org/spec/vtc/";

// ─── The census ──────────────────────────────────────────────────────────

/// Every `spec/vtc/*` URI this service binds, from both binding mechanisms.
///
/// REST bindings are attached as tower layers, so a built `Router` cannot be
/// enumerated for them and this reads the wiring sites as source text —
/// exactly as `tests/trust_task_manifest.rs` does, and for the same reason.
/// It is blunt, but the wiring is confined to `src/routes/` and a false
/// positive here is a compile-visible string, not a silent pass.
fn bound_uris() -> BTreeSet<String> {
    let mut found: BTreeSet<String> = DISPATCHED_URIS
        .iter()
        .filter(|u| u.starts_with(VTC_PREFIX))
        .map(|u| (*u).to_owned())
        .collect();
    collect_from_dir(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut found,
    );
    found
}

/// Recursively harvest `"https://trusttasks.org/spec/vtc/…"` string literals.
///
/// Only literals count: doc comments carry `{verb}`-style URI templates that
/// are documentation, not bindings. The `#response` fragment is trimmed —
/// a response variant publishes under its request's URI.
fn collect_from_dir(dir: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_from_dir(&path, out);
            continue;
        }
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source file");
        for (idx, _) in text.match_indices(VTC_PREFIX) {
            if idx == 0 || !text[..idx].ends_with('"') {
                continue;
            }
            let rest = &text[idx..];
            let Some(end) = rest.find('"') else { continue };
            let uri = rest[..end].split('#').next().expect("split yields a head");
            out.insert(uri.to_owned());
        }
    }
}

/// The sweep's scope: bound ∩ published. Derived, never hand-listed.
fn resolved_uris() -> BTreeSet<String> {
    bound_uris()
        .into_iter()
        .filter(|u| trust_tasks_rs::schema_index::schema_for(u).is_some())
        .collect()
}

// ─── Witnesses ───────────────────────────────────────────────────────────

type ParseFn = fn(Value) -> Result<(), String>;
type ValidateFn = fn(&Value) -> Result<(), String>;

fn parses<T: DeserializeOwned>(v: Value) -> Result<(), String> {
    serde_json::from_value::<T>(v)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Validate against the spec's own embedded schema.
///
/// Not the same check as [`parses`], and the gap is the point: serde accepts
/// `null` into an `Option<T>` the schema types `"string"`, and it ignores
/// `const`, `enum`, `pattern` and `minLength` outright. `submit/0.1`'s
/// response `status` is `const: "pending"` — no generated struct enforces
/// that, only this does.
fn validates<T: ValidatedPayload>(v: &Value) -> Result<(), String> {
    T::validate_value(v).map_err(|e| e.to_string())
}

/// A representative request/response pair for one bound, published URI.
///
/// Built from the VTC's own wire types wherever one exists, so the assertion
/// is about **our emission** rather than a hand-typed fixture. A transcription
/// only proves that someone can type JSON the schema accepts: it stops
/// tracking the producer the moment the producer changes, and stays green
/// while live traffic fails. Where a fixture is transcribed, the entry says
/// why.
struct Witness {
    uri: &'static str,
    request: Value,
    parse_request: ParseFn,
    validate_request: ValidateFn,
    response: Value,
    parse_response: ParseFn,
    validate_response: ValidateFn,
}

/// Which side of a [`Conformance::KnownDrift`] entry is expected to fail.
///
/// Named per side rather than "something fails" so a debt entry cannot pass
/// on the wrong evidence — the failure mode the VTA's module docs record for
/// `acl/update`, where an assertion held for an unrelated reason.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Request,
    Response,
    Both,
}

impl Side {
    fn request_diverges(self) -> bool {
        matches!(self, Side::Request | Side::Both)
    }
    fn response_diverges(self) -> bool {
        matches!(self, Side::Response | Side::Both)
    }
}

enum Conformance {
    Checked(Witness),
    /// Known non-conformance, kept visible, falsifiable and counted instead of
    /// silently tolerated. Every entry names the drift precisely enough that
    /// the fix needs no re-diagnosis, and carries real fixtures so the sweep
    /// can assert the drift is still there.
    KnownDrift {
        reason: &'static str,
        side: Side,
        witness: Witness,
    },
}

impl Conformance {
    fn witness(&self) -> &Witness {
        match self {
            Conformance::Checked(w) => w,
            Conformance::KnownDrift { witness, .. } => witness,
        }
    }
}

/// A conforming witness. `$p` / `$r` are the generated `Payload` /
/// `Response` types — the URI is read off `$p`, never written as a literal
/// (see the module docs).
macro_rules! checked {
    ($p:ty, $r:ty, $req:expr, $resp:expr) => {
        Conformance::Checked(Witness {
            uri: <$p as Payload>::TYPE_URI,
            request: $req,
            parse_request: parses::<$p>,
            validate_request: validates::<$p>,
            response: $resp,
            parse_response: parses::<$r>,
            validate_response: validates::<$r>,
        })
    };
}

/// An annotated divergence. Same fixtures as [`checked!`], plus the side that
/// is expected to fail and why.
macro_rules! drift {
    ($p:ty, $r:ty, $side:expr, $req:expr, $resp:expr, $reason:expr) => {
        Conformance::KnownDrift {
            reason: $reason,
            side: $side,
            witness: Witness {
                uri: <$p as Payload>::TYPE_URI,
                request: $req,
                parse_request: parses::<$p>,
                validate_request: validates::<$p>,
                response: $resp,
                parse_response: parses::<$r>,
                validate_response: validates::<$r>,
            },
        }
    };
}

fn to_v<T: serde::Serialize>(t: T) -> Value {
    serde_json::to_value(t).expect("serialize fixture")
}

// ─── Shared fixture values ───────────────────────────────────────────────

const DID: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
const OTHER_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const COMMUNITY_DID: &str = "did:web:community.example";
const REQUEST_ID: &str = "5b8f1d4e-9c2a-4f6b-8e31-7a0c5d9e2f14";
const TS: &str = "2026-08-23T00:00:00Z";

/// A signed VC as this service emits one. Opaque to every schema below
/// (`vmc` / `roleVec` / `vec` / `vic` are all `type: object`), so one shape
/// serves them all rather than eight near-copies.
fn credential() -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:2f9c1d4e-7a3b-4c5d-8e6f-1a2b3c4d5e6f",
        "type": ["VerifiableCredential", "MembershipCredential"],
        "issuer": COMMUNITY_DID,
        "credentialSubject": { "id": DID },
        "validFrom": TS,
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": TS,
            "verificationMethod": "did:web:community.example#key-0",
            "proofPurpose": "assertionMethod",
            "proofValue": "z3FXQdBGauhBXNZeYPvKjDkxU8vJmYKq1LrGe4tHnGZk9",
        },
    })
}

/// A `MemberResponse` as `routes/members/read.rs:29` serialises one, with
/// every optional populated. Shared by list / show / update, which all
/// return this type.
fn member_response() -> Value {
    json!({
        "did": DID,
        "role": "member",
        "label": "Ada",
        "joinedAt": TS,
        "publishConsent": true,
        "departurePreference": "tombstone",
        "statusListIndex": 4211,
        "currentVmcId": "urn:uuid:2f9c1d4e-7a3b-4c5d-8e6f-1a2b3c4d5e6f",
        "currentRoleVecId": "urn:uuid:8ab13f70-2c4d-4e5f-9a0b-1c2d3e4f5a6b",
        "extensions": { "org": "acme" },
        "personhood": true,
        "personhoodAssertedAt": TS,
        "joinedViaInvitation": true,
        "memberVmcId": "urn:uuid:c0de1234-5678-4abc-9def-0123456789ab",
        "memberVmcReceivedAt": TS,
    })
}

/// The `CommunityProfile` this service serialises
/// (`community/profile.rs:73`). Carried by profile show/update and by the
/// config export document.
fn community_profile() -> Value {
    json!({
        "communityDid": COMMUNITY_DID,
        "name": "Example Community",
        "description": "A demo community.",
        "logoUrl": "https://community.example/logo.png",
        "publicUrl": "https://community.example",
        "contactEmail": "ops@community.example",
        "language": "en",
        "relationshipIdentifierDefault": "pairwise",
        "createdAt": TS,
        "extensions": { "tier": "gold" },
    })
}

/// The `BackupEnvelope` (`backup.rs:63`) — canonical, and the same object on
/// both the export response and the import request.
fn backup_envelope() -> Value {
    json!({
        "version": 1,
        "format": "vtc-backup-v1",
        "createdAt": TS,
        "sourceDid": COMMUNITY_DID,
        "sourceVersion": "0.9.0",
        "kdf": {
            "algorithm": "argon2id",
            "salt": "c2FsdC1iYXNlNjR1cmwtMzJieXRlcw",
            "mCost": 65536,
            "tCost": 3,
            "pCost": 1,
        },
        "encryption": { "algorithm": "aes-256-gcm", "nonce": "bm9uY2UtMTJieXRl" },
        "includesAudit": true,
        "ciphertext": "3q2-7wAAAAAAAAAAAAAAAA",
    })
}

/// The `Paginated<T>` wrapper as `vti-common/src/pagination/mod.rs` serialises
/// it — camelCase throughout, wrapper and items alike.
///
/// The wrapper carried no `rename_all` until this witness caught it, so it sent
/// `next_cursor` / `total_estimate` against schemas that have always said
/// `nextCursor` / `totalEstimate`. One missing attribute, five drifting list
/// tasks, and a direct R3.1 violation of the same class as #656/#658.
fn paginated(items: Value) -> Value {
    json!({ "items": items, "nextCursor": "eyJsYXN0S2V5Ijoi", "totalEstimate": 12 })
}

/// A `JoinRequest` as `join/mod.rs:81` serialises one. No member carries
/// `skip_serializing_if`, so all ten are always on the wire.
fn join_request() -> Value {
    json!({
        "id": REQUEST_ID,
        "applicantDid": DID,
        "vp": { "type": ["VerifiablePresentation"] },
        "vpClaims": { "email": "ada@example.com" },
        "submittedAt": TS,
        "status": "pending",
        "policyDecision": null,
        "registryConsent": true,
        "extensions": { "org": "acme" },
        "decision": null,
    })
}

/// An `Endorsement` row as `endorsements/mod.rs:41` serialises one.
fn endorsement() -> Value {
    json!({
        "id": "11111111-1111-4111-8111-111111111111",
        "endorsementType": "https://skills.example.com/v1/rust",
        "issuerDid": COMMUNITY_DID,
        "subjectDid": DID,
        "claim": { "level": "expert" },
        "statusListIndex": 42,
        "vecId": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "createdAt": TS,
        "revokedAt": null,
    })
}

/// An `EndorsementType` row as `endorsement_types/mod.rs:42` serialises one.
fn endorsement_type() -> Value {
    json!({
        "typeUri": "https://skills.example.com/v1/rust",
        "claimSchema": { "type": "object" },
        "description": "Rust proficiency",
        "createdAt": TS,
        "createdByDid": OTHER_DID,
    })
}

fn uuid() -> uuid::Uuid {
    uuid::Uuid::parse_str(REQUEST_ID).expect("fixture uuid parses")
}

// ─── The witness table ───────────────────────────────────────────────────

/// The number of annotated divergences. Asserted, so the debt can shrink but
/// not grow unnoticed — the same discipline `UNPUBLISHED_CANONICAL_OK` in
/// `tests/trust_task_manifest.rs` applies to unpublished URIs.
///
/// **33 of 58.** #1059 named two and said it had not audited the rest; the
/// sweep says the rest are worse than the two. Nothing here was fixed in the
/// change that added this file, and that is deliberate: the issue's own plan
/// is to land the ledger first and "decide, separately and with the list in
/// hand, which drifts get fixed by correcting the service and which by taking
/// the shape upstream". Most of these are one of three recurring shapes, and
/// the disposition differs per shape:
///
/// 1. **No response envelope.** The spec wraps the payload
///    (`{ "member": … }`, `{ "removed": [ … ] }`, `{ "envelope": … }`) and the
///    handler returns the bare object or a bare array. 12 entries.
/// 2. ~~**`Paginated<T>` is snake_case**~~ — **fixed.** The wrapper had no
///    `rename_all`, so every list task sent `next_cursor` where the spec says
///    `nextCursor`: a direct R3.1 violation of the same casing-drift class as
///    #656/#658. One attribute in `vti-common` closed it for all five.
///
///    Only `relationships/list` became *fully* conforming, because it was the
///    only one whose drift was the wrapper alone — the spec types its `items`
///    as free objects. The other four still diverge at row level and keep
///    their entries, now describing only what is left. Worth noting when
///    reading a drift count: closing a shared root cause moves four entries
///    without closing them.
/// 3. **Unspecced members on an `additionalProperties: false` response.**
///    Usually the service is ahead of the spec (the ceremony verdict
///    envelope, `decidedAt`), occasionally behind it (`didBindingChallenge`).
const KNOWN_DRIFT_COUNT: usize = 32;

/// Every bound, published `spec/vtc/*` URI, with the request and response the
/// VTC actually speaks.
///
/// **Fixtures are transcribed, not typed, and that is a debt.** The VTA's
/// sweep records why: a transcription "only proves someone can type valid
/// JSON: it stops tracking the producer the moment the producer changes, and
/// stays green while live traffic fails". Typed fixtures are not reachable
/// from here today — most of `routes/` is `mod x;`, private to `routes`, so
/// naming `MemberResponse` would mean widening a dozen modules to
/// `pub(crate)` in production code to satisfy a test. That is a real change
/// with its own argument, and mixing it into the change that first adds the
/// sweep would make both harder to review. Every fixture below therefore
/// cites the `file:line` of the type it transcribes, so the next reader can
/// check it in one hop.
///
/// The exception is the join / member ceremony family, whose wire types live
/// in `vta-sdk` and are reachable: those are built from the real type, which
/// is the stronger form and is also where #1059's two named divergences are.
///
/// **The difference between the two forms was measured, not assumed.** Adding
/// `#[serde(rename = "state")]` to `MemberVmcReceiptBody.status`
/// (`vta-sdk/src/protocols/members.rs:170`) fails this sweep — the typed
/// witness re-serialises and the rename shows up. Adding
/// `#[serde(rename = "wasRemoved")]` to `RemoveResponse.removed`
/// (`routes/members/remove.rs:56`) does **not** — the transcribed witness
/// keeps asserting the old spelling and the sweep stays green while the
/// service breaks. That is the exact cost of the transcription, and it is why
/// converting the table to typed fixtures is worth its own change rather than
/// being a nicety.
#[allow(clippy::too_many_lines)]
fn table() -> Vec<Conformance> {
    use trust_tasks_rs::specs::vtc as s;
    use vta_sdk::protocols::join_requests as jr;
    use vta_sdk::protocols::members as mem;

    vec![
        // ─── admin ───────────────────────────────────────────────────
        drift!(
            s::admin::bootstrap::v0_1::Payload,
            s::admin::bootstrap::v0_1::Response,
            Side::Request,
            // `BootstrapRequest` (routes/admin/bootstrap.rs:38) has no
            // `rename_all`, so the single member is snake_case.
            json!({ "setup_session_token": "eyJhbGciOiJFZERTQSJ9.e30.sig" }),
            json!({ "adminDid": OTHER_DID, "eventId": REQUEST_ID }),
            "request member is `setup_session_token`; the spec names \
             `setupSessionToken` and forbids extras. A conforming client's \
             body deserialises as a missing required field. R3.1 casing \
             drift — fix here (add `rename_all = \"camelCase\"`), not \
             upstream; it also breaks the admin SPA's post and needs that \
             changed in the same commit"
        ),
        checked!(
            s::admin::invites::create::v0_1::Payload,
            s::admin::invites::create::v0_1::Response,
            // `CreateInviteRequest` — routes/admin/invites.rs:51.
            json!({ "did": OTHER_DID, "ttlSeconds": 3600, "label": "ops laptop invite" }),
            // `CreateInviteResponse` — routes/admin/invites.rs:69.
            json!({
                "jti": REQUEST_ID,
                "installUrl": "https://vtc.example.org/admin/install?token=eyJ0.e30.s",
                "claimCode": "K7QW-3M2X-9PLD",
                "expiresAt": TS,
                "aclEntryCreated": true,
            })
        ),
        checked!(
            s::admin::invites::list::v0_1::Payload,
            s::admin::invites::list::v0_1::Response,
            // GET: the payload has no required member and the body is empty.
            json!({}),
            // `ListInvitesResponse` / `InviteSummary` —
            // routes/admin/invites.rs:122 / :92.
            json!({
                "invites": [
                    { "jti": REQUEST_ID, "status": "issued", "targetDid": OTHER_DID,
                      "expiresAt": TS },
                    { "jti": "8b7a6c5d-1e2f-4a3b-9c8d-7e6f5a4b3c2d", "status": "consumed",
                      "targetDid": DID, "consumedAt": TS },
                ]
            })
        ),
        checked!(
            s::admin::invites::revoke::v0_1::Payload,
            s::admin::invites::revoke::v0_1::Response,
            // The REST route carries `jti` in the path and ignores the body,
            // so the canonical payload is consumable as-is.
            json!({ "jti": REQUEST_ID }),
            // `RevokeInviteResponse` — routes/admin/invites.rs:129.
            json!({ "jti": REQUEST_ID })
        ),
        // ─── auth ────────────────────────────────────────────────────
        drift!(
            s::auth::admin_session::v0_1::Payload,
            s::auth::admin_session::v0_1::Response,
            Side::Response,
            // `AdminSessionRequest` — routes/auth.rs:364.
            json!({ "accessToken": "eyJhbGciOiJFZERTQSJ9.e30.sig" }),
            // There is no response type: the handler (routes/auth.rs:401)
            // returns 204 with an EMPTY body. `{}` is the closest JSON there
            // is, and it already flatters the real wire form.
            json!({}),
            "no response body at all — the handler returns 204 and puts its \
             result in two Set-Cookie headers, where the spec requires \
             `{sessionId, expiresAt}`. A cookie is not a Trust Task response \
             and no non-browser transport can read one, so this is a real \
             hole rather than a naming mismatch: fix here by returning the \
             body as well as the cookies"
        ),
        checked!(
            s::auth::recognise::challenge::v0_1::Payload,
            s::auth::recognise::challenge::v0_1::Response,
            json!({}),
            // `RecogniseChallengeResponse` — routes/recognise.rs:92.
            // `expiresAt` is unix seconds, which is what the spec types.
            json!({ "nonce": "b7c1e0a94f2d4e8ab5c36f01d9e27a3c", "expiresAt": 1_787_654_400_u64 })
        ),
        drift!(
            s::auth::recognise::v0_1::Payload,
            s::auth::recognise::v0_1::Response,
            Side::Request,
            // `RecogniseRequest` — routes/recognise.rs:82.
            json!({ "presentation": { "type": ["VerifiablePresentation"], "nonce": "b7c1e0" } }),
            // `RecogniseResponse` — routes/recognise.rs:102.
            json!({
                "sessionId": "xc-6f2b1a7c-9d3e-4c58-b0a1-2e7d4f6a8b9c",
                "data": {
                    "accessToken": "eyJhbGciOiJFZERTQSJ9.e30.sig",
                    "accessExpiresAt": 1_787_655_300_u64,
                    "foreignIssuerDid": "did:web:peer.example",
                    "mappedRole": "member",
                },
            }),
            "the spec's payload is two credentials (`vec` + `vmc`, both \
             required); this service takes one `presentation` VP and pulls \
             both out of it. Neither shape is obviously wrong — the VP form \
             carries the holder-binding proof the recognition gate needs, \
             which two loose credentials do not — so this one is a candidate \
             for taking upstream rather than changing here"
        ),
        // ─── backup ──────────────────────────────────────────────────
        drift!(
            s::backup::export::v0_1::Payload,
            s::backup::export::v0_1::Response,
            Side::Response,
            // `ExportRequest` — routes/backup.rs:24.
            json!({ "password": "correct-horse-battery-staple", "includeAudit": true }),
            // The handler returns the envelope bare (routes/backup.rs:58).
            backup_envelope(),
            "response is the bare `BackupEnvelope`; the spec wraps it as \
             `{envelope: …}`. Envelope-only mismatch — the inner object \
             conforms member for member — so fix here"
        ),
        checked!(
            s::backup::import::v0_1::Payload,
            s::backup::import::v0_1::Response,
            // `ImportRequest` — routes/backup.rs:36.
            json!({ "backup": backup_envelope(), "password": "correct-horse-battery-staple",
                    "confirm": true }),
            // `ImportResult` — backup.rs:136.
            json!({
                "status": "imported",
                "sourceDid": COMMUNITY_DID,
                "counts": { "acl": 3, "members": 12 },
                "message": "Import complete. Restart the daemon to serve the restored identity.",
            })
        ),
        // ─── ceremonies ──────────────────────────────────────────────
        drift!(
            s::ceremonies::list::v0_1::Payload,
            s::ceremonies::list::v0_1::Response,
            Side::Response,
            json!({}),
            // `list` returns `Json<Vec<CeremonyManifest>>` — a top-level
            // array (routes/ceremonies.rs:320).
            json!([{
                "purpose": "directory",
                "pkg": "vtc.directory",
                "nature": "read-only",
                "label": "Directory",
                "wired": "live",
                "blurb": "A member views another member's record.",
                "fields": [],
                "factsTemplate": { "purpose": "directory" },
            }]),
            "response is a top-level array where the spec says \
             `{ceremonies: [...]}`, and each manifest carries an unspecced \
             `factsTemplate`. Two fixes, both here: wrap the array, and take \
             `factsTemplate` upstream (the admin UI renders the simulator \
             from it, so dropping it is not an option)"
        ),
        // ─── community ───────────────────────────────────────────────
        drift!(
            s::community::profile::show::v0_1::Payload,
            s::community::profile::show::v0_1::Response,
            Side::Response,
            json!({}),
            // `CommunityProfileResponse` flattens the profile and appends
            // `registryStatus` (routes/community/profile.rs:39).
            {
                let mut v = community_profile();
                v.as_object_mut()
                    .expect("object")
                    .insert("registryStatus".into(), json!("active"));
                v
            },
            "response flattens the profile to the top level; the spec nests \
             it under `profile`. The flattened object then also carries \
             `communityDid`, `createdAt` and `relationshipIdentifierDefault`, \
             which the canonical `CommunityProfile` component does not \
             define. Nesting is a fix here; the three extra members need to \
             go upstream — `communityDid` in particular is the one member a \
             consumer most needs"
        ),
        drift!(
            s::community::profile::update::v0_1::Payload,
            s::community::profile::update::v0_1::Response,
            Side::Both,
            // `CommunityProfileUpdate` — community/profile.rs:144.
            json!({
                "name": "Example Community",
                "description": "A demo community.",
                "logoUrl": "https://community.example/logo.png",
                "publicUrl": "https://community.example",
                "contactEmail": "ops@community.example",
                "language": "en",
                "relationshipIdentifierDefault": "pairwise",
                "extensions": { "tier": "gold" },
            }),
            // `UpdateProfileResponse` — routes/community/profile.rs:196.
            json!({ "profile": community_profile(), "fieldsChanged": ["name", "logoUrl"] }),
            "both sides carry `relationshipIdentifierDefault`, which the \
             spec's payload and `CommunityProfile` component both omit, and \
             the response adds `fieldsChanged`. The response DOES nest under \
             `profile` — unlike its sibling `show` — so the two verbs of one \
             family disagree with each other as well as with the spec. All \
             three members are real and worth having: take them upstream"
        ),
        // ─── config ──────────────────────────────────────────────────
        drift!(
            s::config::export::v0_1::Payload,
            s::config::export::v0_1::Response,
            Side::Response,
            json!({}),
            // `ExportResponse` / `ConfigExportDocument` —
            // routes/admin/config.rs:476 / :460.
            json!({
                "document": {
                    "schemaVersion": 1,
                    "exportedAt": TS,
                    "communityProfile": community_profile(),
                    "configOverrides": { "log.level": "debug", "server.port": 8200 },
                }
            }),
            "the embedded profile carries `relationshipIdentifierDefault`, \
             which `CommunityProfileSnapshot` does not define \
             (`additionalProperties: false`). Same root cause as \
             `community/profile/*`: one member missing from the canonical \
             component. Take it upstream once, and three tasks stop drifting"
        ),
        drift!(
            s::config::import::v0_1::Payload,
            s::config::import::v0_1::Response,
            Side::Request,
            // `ImportRequest` — routes/admin/config.rs:524. The document is
            // whatever `export` handed back, so it carries the same extra
            // member.
            json!({
                "document": {
                    "schemaVersion": 1,
                    "exportedAt": TS,
                    "communityProfile": community_profile(),
                    "configOverrides": { "log.level": "warn" },
                },
                "confirm": true,
            }),
            // `ImportResponse` — routes/admin/config.rs:560.
            json!({
                "status": "imported",
                "profileChanges": [{ "key": "name", "oldValue": "Old", "newValue": "New" }],
                "overrideChanges": [{ "key": "log.level", "newValue": "warn" }],
                "pendingRestart": ["server.port"],
                "rejected": [{ "key": "bogus.key", "reason": "unknown config key" }],
            }),
            "request-side half of the `config/export` drift: an import \
             replays the document an export produced, so it carries the same \
             unspecced `relationshipIdentifierDefault`. The response \
             conforms. One upstream fix clears both"
        ),
        // ─── directory ───────────────────────────────────────────────
        checked!(
            s::directory::query::v0_1::Payload,
            s::directory::query::v0_1::Response,
            // `subject` is the path segment and `fields` the query string
            // (routes/directory.rs:65,93); both are consumable in the body.
            json!({ "subject": DID, "fields": "did,role,joined_at,status" }),
            // `DirectoryResponse` — routes/directory.rs:74. The projection's
            // keys are policy output, and the spec types `fields` as a free
            // object, so their snake_case is in scope here.
            json!({
                "subject": DID,
                "fields": { "did": DID, "role": "member", "joined_at": TS, "status": "active" },
            })
        ),
        // ─── endorsement-types ───────────────────────────────────────
        drift!(
            s::endorsement_types::register::v0_1::Payload,
            s::endorsement_types::register::v0_1::Response,
            Side::Response,
            // `RegisterBody` — routes/endorsement_types.rs:51.
            json!({
                "typeUri": "https://skills.example.com/v1/rust",
                "claimSchema": { "type": "object" },
                "description": "Rust proficiency",
            }),
            // The handler returns the row bare (routes/endorsement_types.rs:69).
            endorsement_type(),
            "response is the bare `EndorsementType`; the spec wraps it as \
             `{endorsementType: …}`. The row also carries `createdByDid`, \
             which the canonical component omits — that one is worth taking \
             upstream (who registered a type is audit-relevant), the wrapper \
             is a fix here"
        ),
        drift!(
            s::endorsement_types::list::v0_1::Payload,
            s::endorsement_types::list::v0_1::Response,
            Side::Response,
            json!({ "cursor": "eyJsYXN0S2V5Ijoi", "limit": 50 }),
            paginated(json!([endorsement_type()])),
            "the items carry the unspecced `createdByDid` against an \
             `additionalProperties: false` response. The wrapper's snake_case \
             casing was the other half of this entry and is now fixed in \
             `vti-common`; what remains is a row-level decision — publish \
             `createdByDid` upstream, or stop sending it"
        ),
        checked!(
            s::endorsement_types::delete::v0_1::Payload,
            s::endorsement_types::delete::v0_1::Response,
            json!({ "typeUri": "https://skills.example.com/v1/rust" }),
            // `DeleteResponse` — routes/endorsement_types.rs:178.
            json!({ "typeUri": "https://skills.example.com/v1/rust" })
        ),
        // ─── endorsements ────────────────────────────────────────────
        drift!(
            s::endorsements::issue::v0_1::Payload,
            s::endorsements::issue::v0_1::Response,
            Side::Both,
            // `IssueBody` — routes/endorsements.rs:57. `endorsement_type` is
            // renamed to `type`, and the rename beats `rename_all`.
            json!({
                "subjectDid": DID,
                "type": "https://skills.example.com/v1/rust",
                "claim": { "level": "expert" },
                "validitySeconds": 2_592_000_u64,
            }),
            // `IssueResponse` — routes/endorsements.rs:70.
            json!({
                "id": "11111111-1111-4111-8111-111111111111",
                "vecId": "urn:uuid:11111111-1111-4111-8111-111111111111",
                "vec": credential(),
            }),
            "the request names the endorsement type `type`; the spec names it \
             `typeUri`. The response is `{id, vecId, vec}` against a spec \
             that says `{endorsement: {endorsementId, typeUri, subjectDid, \
             issued, statusListIndex}}` — a different model, not a naming \
             slip: the spec returns the stored row with the credential \
             nested under `issued`, this returns the credential and two ids. \
             Needs a decision on which model wins before either side moves"
        ),
        drift!(
            s::endorsements::list::v0_1::Payload,
            s::endorsements::list::v0_1::Response,
            Side::Response,
            json!({ "subjectDid": DID, "typeUri": "https://skills.example.com/v1/rust",
                    "includeRevoked": true, "cursor": "eyJsYXN0S2V5Ijoi", "limit": 50 }),
            paginated(json!([endorsement()])),
            "the wrapper's casing is fixed; what remains is that the rows are this service's \
             `Endorsement` (endorsements/mod.rs:41) — `id` / \
             `endorsementType` / `issuerDid` / `vecId` / `createdAt` — not \
             the spec's (`endorsementId` / `typeUri` / `issued`). Same model \
             disagreement as `issue`"
        ),
        drift!(
            s::endorsements::show::v0_1::Payload,
            s::endorsements::show::v0_1::Response,
            Side::Response,
            json!({ "endorsementId": "11111111-1111-4111-8111-111111111111" }),
            endorsement(),
            "bare row where the spec says `{endorsement: …}`, and the row's \
             members are this service's spelling. Same model disagreement as \
             `issue`; fix the family together"
        ),
        drift!(
            s::endorsements::revoke::v0_1::Payload,
            s::endorsements::revoke::v0_1::Response,
            Side::Response,
            json!({ "endorsementId": "11111111-1111-4111-8111-111111111111",
                    "reason": "issued in error" }),
            // `RevokeResponse` — routes/endorsements.rs:344.
            json!({ "id": "11111111-1111-4111-8111-111111111111" }),
            "response is `{id}`; the spec requires `{endorsementId, \
             revocation: {credentialId, revokedAt}, statusListIndex}`. The \
             service holds all four values at the point it replies — it \
             flipped the status-list bit to get there — so this is a fix \
             here, and a caller currently cannot tell a fresh revocation \
             from an idempotent repeat"
        ),
        // ─── install ─────────────────────────────────────────────────
        drift!(
            s::install::claim::start::v0_1::Payload,
            s::install::claim::start::v0_1::Response,
            Side::Both,
            // `ClaimStartRequest` — routes/install.rs:65. No `rename_all`.
            json!({ "install_token": "eyJhbGciOiJFZERTQSJ9.e30.sig",
                    "claim_secret": "K7QW-3M2X-9PLD" }),
            // `ClaimStartResponse` — routes/install.rs:81.
            json!({ "registrationId": REQUEST_ID, "options": { "publicKey": {} } }),
            "request members are snake_case (`install_token`) and it carries \
             `claim_secret`, which the spec does not define at all — the \
             claim secret is the second factor on the install URL, so the \
             spec is missing a real member. The response omits \
             `didBindingChallenge`, which the spec REQUIRES: this service \
             binds the admin DID at `claim/finish` instead, so the member has \
             nowhere to come from. Casing is a fix here; the two structural \
             halves need the spec and the flow reconciled"
        ),
        drift!(
            s::install::claim::finish::v0_1::Payload,
            s::install::claim::finish::v0_1::Response,
            Side::Request,
            // `ClaimFinishRequest` — routes/install.rs:93. No `rename_all`.
            json!({
                "install_token": "eyJhbGciOiJFZERTQSJ9.e30.sig",
                "registration_id": REQUEST_ID,
                "webauthn_response": { "id": "AX6nVQ8s", "type": "public-key" },
            }),
            // `ClaimFinishResponse` — routes/install.rs:103.
            json!({ "adminDid": OTHER_DID, "setupSessionToken": "eyJhbGciOiJFZERTQSJ9.e30.sig" }),
            "request members are snake_case, and the spec's fourth required \
             member `didBindingSignature` is absent — the passkey attestation \
             is the only binding this service checks. Same reconciliation as \
             `claim/start`: R3.1 casing is a fix here, the missing signature \
             is a design question. Note the response's `setupSessionToken` is \
             camelCase and feeds `admin/bootstrap`, which then reads it back \
             as `setup_session_token`"
        ),
        // ─── invitations ─────────────────────────────────────────────
        checked!(
            s::invitations::issue::v0_1::Payload,
            s::invitations::issue::v0_1::Response,
            // `IssueInvitationBody` — routes/invitations.rs:42.
            json!({ "subjectDid": DID, "validityDays": 14, "role": "moderator" }),
            // `IssueInvitationResponse` — routes/invitations.rs:59.
            json!({ "subjectDid": DID, "validUntil": TS, "vic": credential() })
        ),
        checked!(
            s::invitations::list::v0_1::Payload,
            s::invitations::list::v0_1::Response,
            json!({}),
            // `InvitationListResponse` / `InvitationListItem` —
            // routes/invitations.rs:254 / :225.
            json!({
                "invitations": [{
                    "id": "urn:uuid:22222222-2222-4222-8222-222222222222",
                    "subjectDid": DID,
                    "role": "moderator",
                    "issuedBy": OTHER_DID,
                    "issuedAt": TS,
                    "validUntil": TS,
                    "revokedAt": TS,
                }]
            })
        ),
        checked!(
            s::invitations::revoke::v0_1::Payload,
            s::invitations::revoke::v0_1::Response,
            json!({ "id": "urn:uuid:22222222-2222-4222-8222-222222222222" }),
            // `RevokeResponse` — routes/invitations.rs:297.
            json!({ "id": "urn:uuid:22222222-2222-4222-8222-222222222222",
                    "revokedAt": TS, "newlyRevoked": true })
        ),
        // ─── join-requests ───────────────────────────────────────────
        drift!(
            s::join_requests::list::v0_1::Payload,
            s::join_requests::list::v0_1::Response,
            Side::Response,
            json!({ "status": "pending", "cursor": "eyJsYXN0S2V5Ijoi", "limit": 25 }),
            paginated(json!([join_request()])),
            "the wrapper's casing is fixed; what remains is that each row carries `vpClaims` \
             and `decision`, which the canonical `JoinRequest` component does \
             not define. `decision` is the admin-reject detail #1058 added — \
             the same members that drifted on `status/0.1`, in a second \
             place. Take the component upstream once and both stop"
        ),
        drift!(
            s::join_requests::show::v0_1::Payload,
            s::join_requests::show::v0_1::Response,
            Side::Response,
            json!({ "id": REQUEST_ID }),
            join_request(),
            "bare `JoinRequest` where the spec says `{request: …}`, plus the \
             same unspecced `vpClaims` / `decision` as `list`"
        ),
        drift!(
            s::join_requests::decide::v0_1::Payload,
            s::join_requests::decide::v0_1::Response,
            Side::Response,
            // `DecideBody` — routes/join_requests/decide.rs:54; `id` is the
            // path segment and is consumable in the body.
            json!({ "id": REQUEST_ID, "decision": "approved", "reason": "verified out of band" }),
            // `DecideResponse` — routes/join_requests/decide.rs:65. The
            // approve arm populates both credentials; the reject arm omits
            // them and DOES conform, which is exactly why the witness has to
            // carry the approve arm.
            json!({ "requestId": REQUEST_ID, "status": "approved",
                    "vmc": credential(), "roleVec": credential() }),
            "the approve arm returns the issued `vmc` and `roleVec`, which \
             the spec's response does not define. The reject arm conforms, so \
             a witness built from a rejection would have passed green over \
             this — worth knowing when reading the rest of the table. \
             Delivering the credentials inline on the admin's approve saves \
             the applicant a round trip: take it upstream"
        ),
        checked!(
            s::join_requests::manifest::v0_1::Payload,
            s::join_requests::manifest::v0_1::Response,
            json!({}),
            // Built from the SDK type, not transcribed.
            to_v(jr::JoinRequestManifestResponseBody {
                community_did: COMMUNITY_DID.into(),
                criteria: vec![jr::ManifestCriterion {
                    id: "email-verified".into(),
                    description: Some("A verified email credential".into()),
                    presentation_definition: json!({ "credentials": [] }),
                }],
            })
        ),
        drift!(
            s::join_requests::submit::v0_1::Payload,
            s::join_requests::submit::v0_1::Response,
            Side::Both,
            // From the SDK producer type, with `extensions` left at its
            // `Default` — the shape a minimal client actually sends.
            to_v(jr::JoinRequestSubmitBody {
                vp: json!({ "type": ["VerifiablePresentation"] }),
                registry_consent: true,
                extensions: Value::Null,
            }),
            // The ceremony verdict envelope
            // (docs/05-design-notes/vtc-ceremony-protocol.md §3), from the
            // SDK type the dispatcher returns (trust_tasks/mod.rs:218).
            to_v(jr::VerdictResponse::refer(
                uuid(),
                "admin-review",
                "queued for an admin decision (approve/reject)",
            )),
            "#1059's first named divergence, CONFIRMED, and the request side \
             diverges too. Response: the dispatcher returns `VerdictResponse` \
             — `{requestId, verdict}` — where the spec requires \
             `{requestId, status}` with `status` a `const: \"pending\"`. The \
             required `status` is absent and `verdict` is unspecced. The \
             verdict envelope superseded the published shape and was never \
             taken upstream, and it is the better design (a submit can \
             allow / deny / refer / request_more, and `pending` can express \
             only one of those), so the fix belongs upstream. Request: \
             `JoinRequestSubmitBody.extensions` is `#[serde(default)]` with \
             no `skip_serializing_if`, so an unset `extensions` serialises as \
             `null` and the schema types it `object` — the same null-into-\
             Option class that shipped `keys/create/0.1` broken. That half is \
             a one-line fix in vta-sdk"
        ),
        drift!(
            s::join_requests::status::v0_1::Payload,
            s::join_requests::status::v0_1::Response,
            Side::Both,
            // The id-less poll: `requestId` is `Option` and omitted
            // (vta-sdk/src/protocols/join_requests.rs:164).
            to_v(jr::JoinRequestStatusBody { request_id: None }),
            // The rejected projection — the only one that carries the three
            // members #1058 added (routes/join_requests/status.rs:140).
            to_v(jr::JoinRequestStatusResponseBody {
                request_id: uuid(),
                status: "rejected".into(),
                needs: vec![],
                presentation_definition: None,
                code: Some(jr::ADMIN_REJECT_CODE.into()),
                reason: Some("insufficient evidence".into()),
                decided_at: Some(
                    chrono::DateTime::parse_from_rfc3339(TS)
                        .expect("fixture ts")
                        .with_timezone(&chrono::Utc),
                ),
            }),
            "#1059's second named divergence, CONFIRMED, with one correction \
             and one addition. Response: `code`, `reason` and `decidedAt` \
             (#1058) are not in the spec's response, which is \
             `additionalProperties: false` — but only a REJECTED request \
             carries them; a pending poll conforms. So the drift is \
             conditional, and a witness built from a pending response would \
             have passed green over it. Request: the spec's payload requires \
             `requestId`, and this service deliberately makes it optional — \
             an applicant whose first reply was lost holds no id and the \
             id-less poll is the only form it can use. Both belong upstream: \
             the refusal detail and the id-less poll are the right \
             behaviours and the published schema is behind them"
        ),
        // ─── members ─────────────────────────────────────────────────
        checked!(
            s::members::admin_remove::v0_1::Payload,
            s::members::admin_remove::v0_1::Response,
            // `RemoveBody` — routes/members/remove.rs:37; `did` is the path
            // segment and is consumable in the body.
            json!({ "did": DID, "disposition": "purge", "reason": "ToS violation" }),
            // `RemoveResponse` — routes/members/remove.rs:53.
            json!({ "did": DID, "disposition": "purge", "removed": true })
        ),
        drift!(
            s::members::list::v0_1::Payload,
            s::members::list::v0_1::Response,
            Side::Response,
            json!({ "role": "member", "cursor": "eyJsYXN0S2V5Ijoi", "limit": 50 }),
            paginated(json!([member_response()])),
            "the wrapper's casing is fixed; what remains is that `MemberResponse` \
             (routes/members/read.rs:29) carries five members the canonical \
             component does not define: `personhood`, \
             `personhoodAssertedAt`, `joinedViaInvitation`, `memberVmcId`, \
             `memberVmcReceivedAt`. All five are real state a consumer needs \
             — personhood in particular gates recognition — so the component \
             is behind: take them upstream. The wrapper is the R3.1 fix here"
        ),
        drift!(
            s::members::show::v0_1::Payload,
            s::members::show::v0_1::Response,
            Side::Response,
            json!({ "did": DID }),
            member_response(),
            "bare `MemberResponse` where the spec says `{member: …}`, plus \
             the same five unspecced members as `list`"
        ),
        drift!(
            s::members::update::v0_1::Payload,
            s::members::update::v0_1::Response,
            Side::Both,
            // `UpdateMemberRequest` — routes/members/update.rs:61.
            json!({ "did": DID, "role": "moderator", "label": "Ada Lovelace",
                    "publishConsent": true, "departurePreference": "historical",
                    "extensions": { "org": "acme" } }),
            member_response(),
            "request carries `label`, which the spec's payload does not \
             define — a member's display label is editable here and \
             unspecified upstream. Response is the bare `MemberResponse` \
             (spec: `{member: …}`) with the same five unspecced members as \
             `list`"
        ),
        checked!(
            s::members::purge::v0_1::Payload,
            s::members::purge::v0_1::Response,
            json!({ "did": DID }),
            json!({ "did": DID, "disposition": "purge", "removed": true })
        ),
        drift!(
            s::members::removed::v0_1::Payload,
            s::members::removed::v0_1::Response,
            Side::Response,
            json!({}),
            // `list_removed` returns `Json<Vec<RemovedMember>>` — a
            // top-level array (routes/members/read.rs:227).
            json!([{ "did": DID, "removedAt": TS, "statusListIndex": 77, "status": "removed" }]),
            "response is a top-level array where the spec says \
             `{removed: [...]}`. The rows themselves conform. Envelope-only, \
             so this is a fix here"
        ),
        checked!(
            s::members::renew::v0_1::Payload,
            s::members::renew::v0_1::Response,
            json!({}),
            // `RenewResponse` — routes/members/renew.rs:56.
            json!({ "did": DID, "vmc": credential(), "roleVec": credential(),
                    "personhood": true, "personhoodChanged": false })
        ),
        checked!(
            s::members::rotate_challenge::v0_1::Payload,
            s::members::rotate_challenge::v0_1::Response,
            // `ChallengeBody` — routes/members/rotate.rs:193.
            json!({ "reason": "deviceLoss" }),
            // `ChallengeResponse` — routes/members/rotate.rs:169.
            json!({
                "rotationId": REQUEST_ID,
                "expiresAt": TS,
                "signingPayloadHex": "7674632d6469642d726f746174696f6e2f763100",
                "canonicalTemplate": { "rotationId": REQUEST_ID, "oldDid": DID },
            })
        ),
        checked!(
            s::members::rotate::v0_1::Payload,
            s::members::rotate::v0_1::Response,
            // `FinishBody` — routes/members/rotate.rs:269.
            json!({ "rotationId": REQUEST_ID, "oldDid": DID, "newDid": OTHER_DID,
                    "oldSignature": "9a3f", "newSignature": "1c7b" }),
            // `FinishResponse` — routes/members/rotate.rs:282.
            json!({ "newDid": OTHER_DID, "method": "did:key",
                    "vmc": credential(), "roleVec": credential() })
        ),
        checked!(
            s::members::self_remove::v0_1::Payload,
            s::members::self_remove::v0_1::Response,
            // The document form's body (vta-sdk). The REST route's
            // `RemoveBody` also accepts a `reason`, which it then ignores on
            // self-remove (routes/members/remove.rs:86) — unspecced, but
            // unreachable in any body a conforming client sends.
            to_v(jr::SelfRemoveBody {
                disposition: Some("tombstone".into())
            }),
            to_v(jr::SelfRemoveReceiptBody {
                did: DID.into(),
                disposition: "tombstone".into(),
                removed: true,
            })
        ),
        checked!(
            s::members::solicit_vmc::v0_1::Payload,
            s::members::solicit_vmc::v0_1::Response,
            // `RequestVmcBody` — routes/members/request_vmc.rs:26; the DID is
            // the path segment.
            json!({ "memberDid": DID, "reason": "annual audit" }),
            // `RequestVmcResponse` — routes/members/request_vmc.rs:35.
            json!({ "memberDid": DID, "requested": true, "threadId": REQUEST_ID })
        ),
        checked!(
            s::members::personhood::challenge::v0_1::Payload,
            s::members::personhood::challenge::v0_1::Response,
            json!({ "did": DID }),
            // `ChallengeResponse` — routes/members/personhood.rs:138.
            json!({ "challengeId": REQUEST_ID, "expiresAt": TS })
        ),
        checked!(
            s::members::personhood::assert::v0_1::Payload,
            s::members::personhood::assert::v0_1::Response,
            // `AssertBody` — routes/members/personhood.rs:196.
            json!({ "did": DID, "presentation": { "type": ["VerifiablePresentation"] } }),
            // `AssertResponse` — routes/members/personhood.rs:206. NOTE the
            // DELETE on the same mount answers with `personhood: false`,
            // which is `members/personhood/revoke/0.1`'s shape, not this
            // one's — the two verbs share a Trust Task because the router
            // has no per-method selector here. That collapse is #710's
            // shared-mount workaround, not a conformance defect of this URI,
            // so the witness carries the POST.
            json!({ "did": DID, "personhood": true,
                    "vmc": credential(), "roleVec": credential() })
        ),
        checked!(
            s::members::vmc::v0_1::Payload,
            s::members::vmc::v0_1::Response,
            to_v(mem::MemberVmcBody {
                vc: credential(),
                request_id: Some(REQUEST_ID.into()),
            }),
            to_v(mem::MemberVmcReceiptBody {
                member_did: DID.into(),
                vmc_id: "urn:uuid:2f9c1d4e-7a3b-4c5d-8e6f-1a2b3c4d5e6f".into(),
                status: "stored".into(),
                request_id: Some(REQUEST_ID.into()),
            })
        ),
        // ─── policies ────────────────────────────────────────────────
        checked!(
            s::policies::test::v0_1::Payload,
            s::policies::test::v0_1::Response,
            // `TestBody` — routes/policies/admin.rs:176; `id` is the path
            // segment and is consumable in the body.
            json!({ "id": REQUEST_ID, "query": "data.vtc.directory.decision",
                    "input": { "purpose": "directory" } }),
            // `TestResponse` — routes/policies/admin.rs:190.
            json!({ "id": REQUEST_ID, "purpose": "directory", "sha256": "3b9f0a1c8d2e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f809a1b2c3",
                    "result": { "result": [] } })
        ),
        // ─── recognition ─────────────────────────────────────────────
        checked!(
            s::recognition::check::v0_1::Payload,
            s::recognition::check::v0_1::Response,
            json!({ "did": "did:web:other.example" }),
            // `RecognitionCheck` — routes/recognition_admin.rs:31.
            json!({ "did": "did:web:other.example", "recognised": false,
                    "registryConfigured": true, "error": "registry unreachable" })
        ),
        // ─── registry ────────────────────────────────────────────────
        drift!(
            s::registry::diagnostics::v0_1::Payload,
            s::registry::diagnostics::v0_1::Response,
            Side::Response,
            json!({}),
            // `DiagnosticsResponse` — routes/health.rs:73. No `rename_all`.
            json!({
                "registry_status": "active",
                "queue_depth": 3,
                "rtbf_batched_count": 1,
                "failed_count": 0,
                "oldest_pending_age_seconds": 42,
                "last_success_at": TS,
                "syncer_enabled": true,
                "syncer_running": true,
                "syncer_restarts": 0,
                "messaging_status": "connected",
                "transports": [{ "protocol": "rest", "advertised": true, "serviceable": true }],
            }),
            "every member is snake_case (`registry_status` for \
             `registryStatus`), so not one of the four required members is \
             present under the name the spec gives it — the worst single row \
             in this table. Nine further members (`syncer_*`, \
             `messaging_status`, `transports`, `registry_transport`, \
             `vta_did`, `mediator_*`) have no counterpart in the spec at \
             all. R3.1 casing is a fix here; the transport/messaging half is \
             genuinely useful diagnostics and should go upstream"
        ),
        // ─── relationships ───────────────────────────────────────────
        checked!(
            s::relationships::list::v0_1::Payload,
            s::relationships::list::v0_1::Response,
            json!({ "did": DID, "cursor": "eyJsYXN0S2V5Ijoi", "limit": 50 }),
            // `Relationship` — relationships/mod.rs:59. The spec types the
            // items as free objects, so only the wrapper diverges.
            paginated(json!([{
                "id": REQUEST_ID,
                "issuerDid": DID,
                "subjectDid": OTHER_DID,
                "vrcJsonld": credential(),
                "vrcSha256": "3b9f0a1c8d2e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f809a1b2c3",
                "createdAt": TS,
            }]))
        ),
        checked!(
            s::relationships::graph::v0_1::Payload,
            s::relationships::graph::v0_1::Response,
            json!({}),
            // `RelationshipsGraph` — routes/relationships.rs:773.
            json!({
                "nodes": [{ "did": DID }, { "did": OTHER_DID }],
                "edges": [{ "id": REQUEST_ID, "issuerDid": DID,
                            "subjectDid": OTHER_DID, "createdAt": TS }],
            })
        ),
        drift!(
            s::relationships::publish::v0_1::Payload,
            s::relationships::publish::v0_1::Response,
            Side::Request,
            // `PublishBody` — routes/relationships.rs:92.
            json!({ "vrc": credential(), "pop": { "type": "DataIntegrityProof" } }),
            // `PublishResponse` — routes/relationships.rs:113.
            json!({ "id": REQUEST_ID, "issuerDid": DID, "subjectDid": OTHER_DID,
                    "vrcSha256": "3b9f0a1c8d2e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f809a1b2c3" }),
            "request carries `pop`, the proof-of-possession an admin supplies \
             when publishing an edge they did not issue (#1061); the spec's \
             payload is `{vrc}` and forbids extras. Nothing here is wrong — \
             the spec predates the third-party publish path — so take `pop` \
             upstream. Note the registry also publishes \
             `relationships/publish/0.2`, which swaps `vrcSha256` for \
             `vrcDigestMultibase`; this service still binds 0.1"
        ),
        checked!(
            s::relationships::revoke::v0_1::Payload,
            s::relationships::revoke::v0_1::Response,
            json!({ "id": REQUEST_ID }),
            // `RevokeResponse` — routes/relationships.rs:423.
            json!({ "id": REQUEST_ID })
        ),
        // ─── website ─────────────────────────────────────────────────
        drift!(
            s::website::files::list::v0_1::Payload,
            s::website::files::list::v0_1::Response,
            Side::Response,
            json!({ "cursor": "assets/logo.png", "limit": 50 }),
            // `ListResponse` / `FileEntry` — routes/website/files.rs:47 / :38.
            // The wrapper is the one list response in this service that is
            // NOT a `Paginated<T>`, so it does say `nextCursor`; the rows are
            // where it goes wrong.
            json!({
                "items": [{
                    "path": "index.html",
                    "sizeBytes": 2048,
                    "etag": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "modifiedAt": 1_755_946_800_u64,
                }],
                "nextCursor": "styles/main.css",
            }),
            "each row sends `sizeBytes` where the item schema requires \
             `size`, and adds an unspecced `etag`; the item is \
             `additionalProperties: false`, so a conforming consumer sees a \
             missing required member and an unknown one. `modifiedAt` also \
             differs in kind — unix seconds here, `format: date-time` in the \
             spec — which no serde check would catch and this one does not \
             either, since format assertion is off by default. This entry is \
             the sweep finding a task I had first written as `checked!`: the \
             wrapper conforms and I stopped reading there"
        ),
        drift!(
            s::website::files::delete::v0_1::Payload,
            s::website::files::delete::v0_1::Response,
            Side::Response,
            json!({ "path": "assets/old-logo.png" }),
            // The handler returns a bare `StatusCode::OK` — zero bytes
            // (routes/website/files.rs:341). `{}` flatters it.
            json!({}),
            "no response body: the handler returns 200 with zero bytes where \
             the spec requires `{path, deleted}`. Fix here — both values are \
             in hand at the point it replies"
        ),
        drift!(
            s::website::generations::list::v0_1::Payload,
            s::website::generations::list::v0_1::Response,
            Side::Response,
            json!({}),
            // `list` returns `Json<Vec<GenerationEntry>>` — a top-level
            // array (routes/website/generations.rs:20).
            json!([{ "generation": 1, "isCurrent": false,
                     "deployedAt": 1_755_860_400_u64, "sizeBytes": 1_048_576_u64 }]),
            "response is a top-level array where the spec says \
             `{generations: [...]}`. Envelope-only; fix here"
        ),
        drift!(
            s::website::rollback::v0_1::Payload,
            s::website::rollback::v0_1::Response,
            Side::Response,
            // The generation is a path segment, typed `u32` there and
            // `string` in the spec (routes/website/generations.rs:43).
            json!({ "generation": "1" }),
            json!({}),
            "no response body: the handler returns 200 with zero bytes where \
             the spec requires `{generation, current, noop}`. It even \
             computes `noop` (the `from != gen_num` guard that decides \
             whether to write an audit event) and then discards it. Fix here"
        ),
    ]
}

// ─── The sweep ───────────────────────────────────────────────────────────

/// Coverage: the witness table and the derived census agree exactly, in both
/// directions. A stream that binds a new published `spec/vtc/*` URI lands
/// here first — that is the point.
#[test]
fn every_bound_published_uri_has_a_witness() {
    let expected = resolved_uris();
    assert!(
        !expected.is_empty(),
        "the census found no bound, published spec/vtc/ URIs at all — the \
         scan is broken, not the code"
    );

    let mut covered: BTreeSet<String> = BTreeSet::new();
    for c in table() {
        assert!(
            covered.insert(c.witness().uri.to_owned()),
            "duplicate witness entry for {} — one entry per URI",
            c.witness().uri
        );
    }

    let missing: Vec<_> = expected.difference(&covered).cloned().collect();
    assert!(
        missing.is_empty(),
        "these bound URIs are published in the registry but have no \
         conformance witness:\n  {}\n\nAdd a `checked!` entry (request + \
         response built from the wire types the handler actually emits), or \
         — only for a real, understood non-conformance — a `drift!` entry \
         with a reason.",
        missing.join("\n  ")
    );

    let stale: Vec<_> = covered.difference(&expected).cloned().collect();
    assert!(
        stale.is_empty(),
        "these witnesses cover URIs that are no longer both bound and \
         published:\n  {}\n\nRemove them, or fix the spec module they name.",
        stale.join("\n  ")
    );
}

/// Correctness: every conforming witness's request parses as the generated
/// `Payload` and validates against its schema, and its response likewise
/// against `Response` — and the check has teeth: a drifted (unknown-member)
/// form of each MUST be rejected, so a witness cannot pass vacuously against
/// a schema that accepts anything.
#[test]
fn every_witnessed_task_speaks_its_published_schema() {
    for c in table() {
        let Conformance::Checked(w) = &c else {
            continue;
        };
        let uri = w.uri;

        (w.parse_request)(w.request.clone())
            .unwrap_or_else(|e| panic!("{uri}: request is not canonical: {e}\n{:#}", w.request));
        (w.validate_request)(&w.request).unwrap_or_else(|e| {
            panic!(
                "{uri}: request fails its own payload schema: {e}\n{:#}",
                w.request
            )
        });
        (w.parse_response)(w.response.clone())
            .unwrap_or_else(|e| panic!("{uri}: response is not canonical: {e}\n{:#}", w.response));
        (w.validate_response)(&w.response).unwrap_or_else(|e| {
            panic!(
                "{uri}: response fails its own response schema: {e}\n{:#}",
                w.response
            )
        });

        assert_drifted_form_is_rejected(w);
    }
}

/// The teeth: an unknown member must be rejected on both sides.
///
/// The generated types carry `deny_unknown_fields` wherever the spec is
/// `additionalProperties: false`, which is every published `vtc/*` task
/// today. A URI for which this stops holding needs review, not a silent pass.
fn assert_drifted_form_is_rejected(w: &Witness) {
    let uri = w.uri;
    for (side, value, parse, validate) in [
        ("request", &w.request, w.parse_request, w.validate_request),
        (
            "response",
            &w.response,
            w.parse_response,
            w.validate_response,
        ),
    ] {
        let mut drifted = value.clone();
        drifted
            .as_object_mut()
            .unwrap_or_else(|| panic!("{uri}: {side} witness must be a JSON object"))
            .insert("__conformance_sweep_drift".into(), json!(true));
        assert!(
            parse(drifted.clone()).is_err() || validate(&drifted).is_err(),
            "{uri}: the generated {side} type AND its schema both accepted an \
             unknown member — this witness can pass vacuously and proves \
             nothing"
        );
    }
}

/// Debt: every `KnownDrift` entry must still diverge, on the side it names,
/// and must still conform on the side it does not.
///
/// A prose-only debt note is unfalsifiable — it cannot tell you the drift was
/// fixed upstream, and it cannot tell you it was mis-diagnosed. This makes
/// both visible: fix the divergence and this test fails asking you to promote
/// the entry to `checked!`.
#[test]
fn known_drift_entries_still_diverge_where_they_say_they_do() {
    let mut recorded: Vec<String> = Vec::new();

    for c in table() {
        let Conformance::KnownDrift {
            reason,
            side,
            witness: w,
        } = &c
        else {
            continue;
        };
        let uri = w.uri;
        assert!(
            !reason.trim().is_empty(),
            "{uri}: KnownDrift entries must state the drift"
        );

        let request_ok = (w.parse_request)(w.request.clone()).is_ok()
            && (w.validate_request)(&w.request).is_ok();
        let response_ok = (w.parse_response)(w.response.clone()).is_ok()
            && (w.validate_response)(&w.response).is_ok();

        assert_eq!(
            request_ok,
            !side.request_diverges(),
            "{uri}: the recorded drift says the request {}, but it actually \
             {}. Re-diagnose the entry — a debt note that describes the wrong \
             half is worse than none.\n{:#}",
            if side.request_diverges() {
                "diverges"
            } else {
                "conforms"
            },
            if request_ok { "conforms" } else { "diverges" },
            w.request
        );
        assert_eq!(
            response_ok,
            !side.response_diverges(),
            "{uri}: the recorded drift says the response {}, but it actually \
             {}. If it was fixed (here or upstream), promote this entry to \
             `checked!` and drop the KNOWN_DRIFT count by one.\n{:#}",
            if side.response_diverges() {
                "diverges"
            } else {
                "conforms"
            },
            if response_ok { "conforms" } else { "diverges" },
            w.response
        );

        recorded.push(format!("{uri}: {reason}"));
    }

    // Debt is visible in the test output every run, not buried in a table.
    for line in &recorded {
        eprintln!("KNOWN DRIFT (follow-up issue required): {line}");
    }

    assert_eq!(
        recorded.len(),
        KNOWN_DRIFT_COUNT,
        "the known-drift count changed. If it went DOWN, a divergence was \
         closed — lower KNOWN_DRIFT_COUNT. If it went UP, a task was bound \
         that does not speak its published schema; that is the thing this \
         sweep exists to stop, and raising the number is the wrong fix unless \
         the divergence is understood and written down."
    );
}
