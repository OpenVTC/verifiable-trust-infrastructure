# VTA Mobile Agent — Architecture & Re-implementation Spec

**Audience:** an engineer porting the VTA mobile agent (the **Authenticator** +
**PNM** apps) to another language/runtime — e.g. **Dart/Flutter**, Kotlin
Multiplatform, React Native, or a fully-native rewrite.

**Status:** descriptive snapshot of `vta-mobile-core` v0.3.0 (the shared engine)
and the design decisions behind it, as of 2026-06. The engine is built
incrementally; "Build-out slices" below maps what exists today. This doc is the
**contract + standards** a second implementation must honour to be wire- and
custody-compatible. It is not a line-by-line transliteration guide.

> Nothing here is platform-secret. Every wire format is a published standard
> (Trust Tasks, DIDComm v2, W3C Data Integrity, WebAuthn, Aries push). The value
> of this document is that it tells you *exactly which* standards, *which*
> parameters, and *which* invariants, so you don't have to reverse-engineer them.

---

## 1. What the apps are

Two iPhone-first (then Android) apps, both built on the **same engine**:

| App | Role |
|---|---|
| **Authenticator** | A holder's pocket approver. Receives VTA/RP-pushed **AAL step-up** "approve-request" prompts ("Confirm transfer of $1,000…"), shows the reason, and returns a passkey- or DID-signed **approve-response**. Think "Okta Verify / Google Authenticator", but the second factor is a DID-bound key in the Secure Enclave and the transport is DIDComm, not TOTP. |
| **PNM** (Personal Network Manager) | The mobile counterpart of the `pnm` CLI: an operator's single-VTA admin console. Authenticates to its VTA and drives the management surface (ACL, contexts, services, DID lifecycle, …) over the same Trust-Task wire the CLI uses. |

Both apps are **thin native shells** over a shared Rust core. The native side
owns everything platform-bound; the core owns everything cryptographic and
wire-shaped. That split is the single most important architectural decision and
the rest of this document elaborates it.

---

## 2. The core architectural principle: shared engine, native edges

```
┌──────────────────────────── Native app (Swift / Kotlin / Dart) ────────────────────────────┐
│                                                                                              │
│  • UI (consent screens, login, admin surfaces)                                               │
│  • Key custody:  Secure Enclave (iOS) / StrongBox+Keystore (Android)  ── biometric-gated     │
│  • Transports:   mediator WebSocket, REST/HTTPS, APNs/FCM push receipt                        │
│  • Platform WebAuthn / passkeys:  ASAuthorization (iOS) / Credential Manager (Android)        │
│  • Identifiers + clock:  UUIDs, RFC-3339 timestamps                                           │
│                                                                                              │
│        ▲   builds bytes to sign / parses responses        │ calls back to sign (Signer)      │
│        │                                                   ▼                                  │
│  ┌──────────────────────────── vta-mobile-core (Rust, via UniFFI) ──────────────────────┐    │
│  │  PURE FUNCTIONS OVER BYTES + a few stateful Objects                                   │    │
│  │  Trust-Task build/parse · Data-Integrity proof assembly · DIDComm pack/unpack ·       │    │
│  │  DID resolution · push-registration message build · mediator session                  │    │
│  └──────────────────────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Rule:** the FFI surface is *deliberately* "pure functions over bytes."
Everything stateful or platform-bound stays **native** and is handed to the
engine as inputs. The engine writes the wire crypto **once** and shares it
across both platforms, so it is never reimplemented per-platform and can never
drift between them.

The two things that are genuinely stateful in the engine (`DidcommSession`,
`MediatorSession`) are still fed all their inputs natively (key material,
sockets-as-bytes).

### 2.1 Why this matters to a Dart/Flutter port

You have two viable strategies. **Decide this first** — it changes everything
downstream:

**Strategy A — reuse the Rust core (recommended).**
`vta-mobile-core` is a `cdylib`/`staticlib`. You can bind it from Dart with
[`flutter_rust_bridge`](https://github.com/fzyzcjy/flutter_rust_bridge) or raw
`dart:ffi` instead of UniFFI. You get the *exact* same crypto, byte-for-byte,
for free; you only re-write the native edges (custody, transport, UI) in
Dart/Kotlin/Swift platform channels. This is the lowest-risk path and the one
the existing iOS/Android apps take (they just use UniFFI's generated Swift/Kotlin
instead of FRB's Dart).

**Strategy B — reimplement the engine in Dart.**
Only do this if you cannot ship a Rust artifact. You then must re-derive every
standard in §4 against Dart libraries, and you take on the burden of staying
wire-compatible with the VTA forever. This document is the spec you'd implement
against. Expect to need Dart equivalents of: a JCS canonicaliser, Ed25519 +
X25519 (ed25519→x25519 conversion!), multibase/multicodec, a DIDComm v2 stack,
a DID resolver, and JOSE. Several of these (a correct DIDComm v2 authcrypt impl,
ed25519→x25519 birational map) are non-trivial and are exactly why the engine
exists.

Either way, §3 (the FFI contract) and §4 (the standards) are what you must
match.

---

## 3. The engine's capability surface (the FFI contract)

This is the complete public surface of `vta-mobile-core` v0.3.0. Group =
source module. Types are described in Rust-ish form; map them to your host
types. `Result<T, FfiError>` means "throws/returns the `FfiError` union" (§3.9).

The engine namespace is `vta_mobile_core`; bindings ship as Kotlin package
`org.openvtc.vta.mobilecore` and Swift module `VtaMobileCore`.

### 3.1 Engine metadata (`api`)

| Function | Signature | Purpose |
|---|---|---|
| `library_version` | `() -> String` | Engine semver. First call to confirm linkage. |
| `engine_info` | `() -> EngineInfo { version, namespace }` | Structured metadata (exercises record codegen). |
| `challenge_len_bytes` | `(challenge_b64url: String) -> Result<u32>` | Decode a base64url challenge, return its byte length, **enforce ≥16 bytes (128-bit) minimum**. The canonical example of a pure validating call. |

### 3.2 Key custody seam (`keys`) — **the most important interface**

```rust
// Implemented on the NATIVE side; the engine calls back into it.
callback interface Signer {
    did() -> String;                          // the signer's did:key (Ed25519)
    sign(payload: Vec<u8>) -> Result<Vec<u8>>; // EdDSA over payload, done in the enclave
}
```

- `did()` returns the **`did:key`** whose private half this signer controls.
  The engine uses it as the proof `verificationMethod`.
- `sign(payload)` signs the **exact bytes the engine computed** (e.g. the
  canonicalised Data-Integrity signing input). The biometric prompt and the
  Secure Enclave / StrongBox operation happen entirely natively. **Private key
  material never crosses the FFI boundary and never exists in engine memory.**
- A user cancel / biometric failure surfaces as `FfiError` *through* the
  callback — your host binding must propagate host exceptions back into the
  engine as the error type.

| Function | Signature | Purpose |
|---|---|---|
| `sign_challenge` | `(signer, challenge_b64url) -> Result<Vec<u8>>` | Decodes a challenge and round-trips it through the native signer. Mostly a seam-proving primitive; real flows call the signer internally (auth, step-up). |

This callback is the seam **every** signing flow is built on. Port it first.

### 3.3 DID resolution (`resolver`)

| Function | Signature | Notes |
|---|---|---|
| `resolve_did` | `async (did: String) -> Result<String /*DID Document JSON*/>` | First async export. Default config is **local**: `did:key` / `did:peer` resolve fully offline (covers holder/RP key lookup for step-up verification). `did:web` / `did:webvh` need network-mode resolver config (follow-up). One process-wide cached resolver. |

### 3.4 Trust-Task: step-up request parsing (`task`)

| Function | Signature | Returns |
|---|---|---|
| `parse_step_up_request` | `(json: String) -> Result<StepUpRequest>` | Deserialises & structurally validates an inbound `auth/step-up/approve-request/0.1` and surfaces the consent-UI fields. |

```
StepUpRequest {
  relying_party: Option<String>,   // document `issuer`
  subject: String,                 // VID whose session is being elevated
  session_id: String,              // echo verbatim in the response
  challenge: String,               // base64url; the response binds over it
  reason: String,                  // MUST be shown to the user VERBATIM for consent
  target_acr: Option<String>,      // e.g. "aal2"
  acceptable_evidence: Vec<String>,// ["did-signed"] / ["webauthn"]; empty = any supported
  webauthn_requested: bool,        // RP supplied WebAuthn ceremony options
}
```

### 3.5 Trust-Task: step-up response building (`stepup`)

```
ApproveResponseDraft {
  id, issuer_did, recipient_did, issued_at /*RFC3339*/,
  subject, session_id, challenge, granted_acr: Option<String>,
}
WebAuthnAssertion {              // base64url fields, mirrors AuthenticatorAssertionResponse
  credential_id, client_data_json, authenticator_data, signature,
  user_handle: Option<String>,
}
```

| Function | Signature | Gate |
|---|---|---|
| `build_approve_response_webauthn` | `(draft, assertion) -> Result<String>` | Passkey assertion **is** the gate. No framework proof attached. `evidence.kind = "webauthn"`, `decision = "approved"`. |
| `build_approve_response_did_signed` | `(draft, signer) -> Result<String>` | A `eddsa-jcs-2022` Data-Integrity proof over the document **is** the gate, produced via the native `Signer`. `evidence.kind = "did-signed"`. |

### 3.6 Trust-Task: VTA authentication (`session`)

All of these only **build/parse JSON**; transport is the caller's job
(DIDComm or REST). `auth/*` Trust Tasks; see §4.5 for the flow and the
`IS_PROOF_REQUIRED` semantics that decide whether a `Signer` is needed.

```
AuthEnvelope { id, holder_did /*issuer*/, vta_did /*recipient*/, issued_at /*RFC3339*/ }
AuthChallenge { challenge, session_id, expires_at }
AuthTokens   { access_token, token_type, expires_in, refresh_token?, refresh_expires_in?, acr?, amr[] }
SessionInfo  { session_id, subject, issued_at, expires_at, acr?, amr[], roles[], scopes[] }
```

| Function | Proof? | Purpose |
|---|---|---|
| `build_auth_challenge(env, subject?, purpose?) -> String` | no | Start auth: request a nonce (`auth/challenge`). |
| `parse_auth_challenge_response(json) -> AuthChallenge` | — | Read the challenge + session id. |
| `build_authenticate(env, challenge, session_id, scope[], signer) -> String` | **yes** | Present the challenge; the holder-signed framework proof **is** the authentication. |
| `parse_authenticate_response(json) -> AuthTokens` | — | The issued access/refresh tokens + session snapshot. |
| `build_refresh(env, refresh_token, scope[]) -> String` | **no** | Exchange refresh token (`auth/refresh`). The opaque token is the credential. `scope` may narrow, never widen; empty = keep current. |
| `parse_refresh_response(json) -> AuthTokens` | — | Rotated tokens; session snapshot is **optional** (absent → keep prior acr/amr). |
| `build_whoami(env, signer) -> String` | **yes** | Empty-payload introspection; the proof authenticates the asker (`auth/whoami`). |
| `parse_whoami_response(json) -> SessionInfo` | — | Auth service's view: session + roles + scopes. Reconcile local AAL/authz after a step-up or policy edit without re-issuing tokens. |
| `build_revoke_session(env, session_id, reason?, signer) -> String` | **yes** | Invalidate one named session. |
| `build_revoke_all_sessions(env, reason?, signer) -> String` | **yes** | "Log out everywhere." (Named-vs-all is the spec payload's mutually-exclusive `oneOf`; two builders make misuse impossible.) |
| `parse_revoke_session_response(json) -> u64` | — | Count of sessions invalidated (0 is valid). |

### 3.7 DIDComm v2 session (`didcomm`) — stateful `Object`

A `DidcommSession` is bound to one holder identity and holds the library agent
(holder identity + resolved peers). Thread-safe (internal lock).

```
HolderKeys {                       // Tier-2 software-held (see §5); native loads & zeroizes
  did, key_agreement_kid, key_agreement_private_x25519 /*32B*/,
  signing_kid, signing_private_ed25519 /*32B*/,
}
Peer { did, key_agreement_kid, key_agreement_public_x25519 /*32B*/ }
UnpackedMessage { message_json, sender_authenticated: bool, sender_kid: Option<String> }
```

| Method | Signature | Purpose |
|---|---|---|
| `DidcommSession::new` | `(holder: HolderKeys) -> Session` | Open a session from holder key material. |
| `add_peer` | `(peer: Peer)` | Register a resolved peer so the session can authcrypt to it / verify its authcrypt. |
| `unpack` | `(packed, sender_did?) -> UnpackedMessage` | Decrypt/verify inbound (authcrypt / anoncrypt / signed / plaintext). **`sender_authenticated == false` for anoncrypt & plaintext — do not trust `from` in that case.** |
| `pack_authcrypt` | `(message_json, recipient_did) -> String /*JWE*/` | Sender-authenticated encrypt. Recipient must be added via `add_peer`. |
| `pack_anoncrypt` | `(message_json, recipient_did) -> String /*JWE*/` | Anonymous encrypt (sender hidden). |
| `add_route` | `(recipient_did, mediator: Peer)` | After this, packs to `recipient_did` are auto-wrapped in `routing/2.0/forward` anoncrypt'd to the mediator. How you deliver to a peer reachable only via its mediator. |

| Free function | Signature | Purpose |
|---|---|---|
| `didcomm_holder_keys` | `(did, signing_private_ed25519 /*32B Ed25519 seed*/) -> HolderKeys` | Derive the DIDComm key material for an Ed25519 `did:key` holder. The X25519 key-agreement key is the **standard ed25519→x25519 conversion** of the signing key, so its public half equals the `keyAgreement` a resolver derives from the `did:key` — anyone resolving the holder did:key can authcrypt to a key this session can open. **Re-derive this exactly or DIDComm interop breaks** (see §4.4). |

### 3.8 Mediator-connected session (`mediator`) — stateful async `Object`

Wraps `vta-sdk`'s `DIDCommSession` (the Affinidi ATM client): mediator
challenge-auth + message-pickup 3.0 + WebSocket live delivery. The mobile
approver uses it to pull VTA-pushed step-up requests off its mediator.

| Method | Signature | Purpose |
|---|---|---|
| `MediatorSession::connect` | `async (holder_did, holder_signing_private_ed25519 /*32B*/, vta_did, mediator_did) -> Session` | Authenticate to the mediator as the holder and open live delivery. The 32-byte Ed25519 seed stays in the engine; only derived DIDComm secrets reach the ATM secrets resolver. |
| `receive_next` | `async (timeout_secs) -> Option<String /*unpacked message JSON*/>` | Wait up to `timeout_secs` for the next inbound message (the application Trust Task rides in `body`); `None` on timeout. Poll again to continue. |
| `shutdown` | `async ()` | Close the live-delivery WebSocket. |

### 3.9 Push registration (`push`)

Builds the DIDComm message **core** (`{type, body}`) the agent sends to its
**mediator** to register/clear its push channel. Native adds envelope headers
(`id`/`from`/`to`) and authcrypt-packs it.

```
enum PushRegistration {
  Apns { token, topic, environment: {Sandbox|Production} },
  Fcm  { token },
  WebPush { endpoint, p256dh, auth },   // -> Unimplemented (RFC 8030 is out-of-band, not DIDComm)
}
enum PushPlatform { Apns, Fcm, WebPush }
```

| Function | Signature |
|---|---|
| `build_set_device_info(registration) -> Result<String>` |
| `build_delete_device_info(platform) -> Result<String>` |

### 3.10 Error union (`FfiError`)

Coarse and stable; switch on the **variant** for control flow, treat the string
as logs-only. New variants are additive; never reshape one.

```
FfiError = InvalidInput{reason} | Decode{reason} | Unimplemented{what} | Transport{reason}
```

---

## 4. The standards you must honour

This is the heart of the spec. Every item is a published standard with the
exact parameters this ecosystem pins.

### 4.1 Identifiers are DIDs, always `did:key` (Ed25519)

- Every operator/wire-facing public key is a **`did:key`**, Ed25519, multicodec
  prefix `0xed 0x01`, multibase base58btc (`did:key:z6Mk…`). Never a raw
  base64url pubkey.
- The verification-method id is `did:key:<mb>#<mb>` (the method-specific-id
  repeated as the fragment).
- The HPKE/DIDComm layers operate on **X25519** internally, derived on demand
  from the Ed25519 key — never surfaced as a separate identity. (See §4.4.)

### 4.2 Trust Tasks — the envelope (`trusttasks.org`)

Every application message is a **Trust Task** document. This is the single most
important wire format in the system; the VTA routes on it and the CLI/SDK speak
it end-to-end.

Envelope shape (JSON):

```jsonc
{
  "id": "<caller-chosen id, e.g. UUID>",
  "type": "https://trusttasks.org/spec/<namespace>/<op-path>/<maj>.<min>",
  "issuer": "<sender DID>",
  "recipient": "<receiver DID>",
  "issuedAt": "<RFC 3339>",
  "payload": { /* op-specific */ },
  "proof": { /* optional DataIntegrityProof; present iff IS_PROOF_REQUIRED */ }
}
```

Type-URI grammar (**must** match or the framework rejects the document at the
wire boundary):

```
https://trusttasks.org/spec/{namespace}/{op-path}/{major}.{minor}
```

- Scheme+host always `https://trusttasks.org/`; **identifier only, not
  resolvable**.
- The `spec/` segment is **mandatory**.
- `namespace` ∈ {`vta`, `did-hosting`, `webvh`, …}; `op-path` is one or more
  lowercase-kebab path segments (`auth/challenge`, `auth/step-up/approve-request`).
- Version is `{major}.{minor}` **only — no patch**. `1.0` and `1.1` are entirely
  separate identifiers; the router does **no** version-family matching.
- A `#response` document echoes the request: type gets a `#response` suffix,
  issuer/recipient swap, `threadId` = request id.

The full VTA URI catalogue (~79 ops: auth, keys, seeds, contexts, acl, audit,
attestation, services, webvh, did-templates, backup, …) is in
[`trust-task-uri-registry.md`](./trust-task-uri-registry.md). The PNM app drives
those; the Authenticator mostly needs the `auth/*` and `auth/step-up/*` subset.

Engine binding: it composes generated payload types from **`trust-tasks-rs`**
(`specs::auth::{challenge,authenticate,refresh,whoami,revoke_session}` and
`specs::auth::step_up::{approve_request,approve_response}`). A Dart reimpl needs
those payload schemas — derive them from the `trust-tasks-rs` types / the
trusttasks.org specs, not by guessing.

### 4.3 Data Integrity proofs — `eddsa-jcs-2022`

When a Trust Task carries a holder-signed proof, it's a **W3C Data Integrity**
`DataIntegrityProof` with cryptosuite **`eddsa-jcs-2022`**:

```jsonc
"proof": {
  "type": "DataIntegrityProof",
  "cryptosuite": "eddsa-jcs-2022",
  "created": "<RFC 3339, == issuedAt>",
  "verificationMethod": "did:key:<mb>#<mb>",
  "proofPurpose": "assertionMethod",
  "proofValue": "z<base58btc(signature)>"
}
```

Signing algorithm (engine does this in `proof.rs`; you must reproduce it
**byte-for-byte** or proofs won't verify):

1. Build the proof config **without** `proofValue`.
2. `prepare_sign_input(document_without_proof, proof_config, EddsaJcs2022)` —
   this is **JCS canonicalisation + hashing** of (document, proof config) per
   the eddsa-jcs-2022 suite. This is the only correctness-critical step; use a
   spec-correct JCS (RFC 8785) implementation.
3. The **native `Signer` signs the resulting bytes** (EdDSA / Ed25519).
4. `proofValue = multibase(base58btc, signature)`.
5. Attach the completed proof to the document.

The mobile holder key is always a `did:key`, so the VM is `did:key:<id>#<id>`.
A non-`did:key` signer is rejected before signing.

> **Sealed-transfer note (PNM, secret-bearing bundles):** any private-key/credential
> bundle that moves between tools uses `vta_sdk::sealed_transfer` — HPKE
> (X25519-HKDF-SHA256 / HKDF-SHA256 / ChaCha20-Poly1305), domain-info string
> `vta-sealed-transfer/v1`, ASCII-armor + out-of-band SHA-256 digest, and a
> producer assertion that is itself an Ed25519 signature over
> `DID_SIGNED_DOMAIN_TAG ("vta-sealed-transfer/v1\0") || client_x25519_pub ||
> bundle_id`. The mobile engine doesn't implement this yet (it's a PNM
> provisioning/bootstrap concern), but a full PNM port will need it. It is a
> hard-pinned suite — do not negotiate or version-parameterise it.

### 4.4 DIDComm v2 — authcrypt / anoncrypt / mediator forward

- Library: `affinidi-messaging-didcomm` (pinned **0.15**), key-agreement types
  from `affinidi-crypto`.
- **authcrypt** = sender-authenticated + encrypted. Unpacking yields a
  cryptographically-authenticated sender DID — **sender auth is intrinsic**, no
  hand-rolled signature check. This is *the* reason DIDComm is preferred over a
  REST-plus-bespoke-signature scheme for every inter-component flow.
- **anoncrypt** = encrypted, sender hidden — `sender_authenticated == false`.
- **Mediator delivery** wraps the inner authcrypt JWE in a
  `https://didcomm.org/routing/2.0/forward` message, anoncrypt'd to the mediator
  (`add_route`).
- Mediator protocol itself: Affinidi ATM = challenge-auth + `messagepickup/3.0`
  + `coordinate-mediation/2.0` over WebSocket. Reuse a library; don't
  reimplement.

**The ed25519→x25519 derivation (interop-critical).** The holder's X25519
key-agreement key is the **birational map** of its Ed25519 signing key
(`affinidi_crypto::ed25519::{ed25519_private_to_x25519, ed25519_public_to_x25519}`).
This guarantees the public X25519 equals the `keyAgreement` any resolver derives
from the holder's `did:key`, so a VTA that only knows the holder `did:key` can
authcrypt to a key the session holds. If your Dart impl derives X25519
differently, **inbound authcrypt will silently fail to decrypt.** kid shapes:
key-agreement `=> <did>#<x25519-multikey>`, signing `=> <did>#<ed25519-multikey>`.

### 4.5 VTA authentication — the `auth/*` flow

```
build_auth_challenge ──▶ POST/DIDComm ──▶ parse_auth_challenge_response
        (no proof)                              │ {challenge, session_id, expires_at}
                                                ▼
build_authenticate (HOLDER-SIGNED proof) ──▶ … ──▶ parse_authenticate_response
        challenge + session_id echoed                 │ {access, refresh, acr, amr, …}
                                                       ▼
   …time passes; access token nears expiry…
build_refresh (NO proof; refresh token IS the credential) ──▶ parse_refresh_response
```

Semantics that must hold:

- **`IS_PROOF_REQUIRED`** per op: `challenge` = no, `authenticate` = yes,
  `refresh` = no, `whoami` = yes, `revoke-session` = yes. The engine attaches /
  omits the proof accordingly; a reimpl must too.
- **Refresh is `IS_PROOF_REQUIRED == false`** because the opaque refresh token is
  itself the bearer credential (OAuth2 §10.4 rotation), verified server-side.
- **Dual transport.** `auth/*` works over both DIDComm (via mediator) **and**
  plain REST. The DI-signed Trust Task's holder proof *is* the auth, so a
  REST-only VTA (no mediator) can authenticate. The server content-negotiates
  on the body shape: Trust-Task in → Trust-Task `#response` out; flat-JSON in →
  flat-JSON out. (Server side: `vti_common::auth::handlers`.)
- **Freshness/replay:** anchored by the single-use, TTL'd challenge bound to the
  session at `/auth/challenge`. The DIDComm path additionally enforces a 60s
  window on the envelope `created_time`; the DI/REST path passes
  `created_time: None`.
- **JWT claims** the VTA mints: `{ aud, sub, session_id, role, contexts, exp }`.
  Audience separates VTA from VTC — cross-audience tokens are rejected.

### 4.6 AAL step-up — `auth/step-up/*`

The Authenticator's core job. The VTA/RP pushes an **approve-request**; the app
shows `reason` and returns an **approve-response** satisfying one **evidence
gate**:

| Gate | `evidence.kind` | What proves it |
|---|---|---|
| **WebAuthn / passkey** | `"webauthn"` | A platform passkey assertion over the challenge, carried as payload. **No** framework proof. |
| **DID-signed** | `"did-signed"` | An `eddsa-jcs-2022` proof over the response document, from the subject's enclave key. |

Pinned details:

- Challenge **MUST be ≥16 bytes (128-bit)** (`challenge_len_bytes` enforces it;
  the newtype enforces ≥16 chars too).
- `decision`: `"approved"` (the engine builds the approved path;
  denied/`denied_reason` is modelled).
- `granted_acr` is the AAL the approver believes it demonstrated, e.g.
  **`"aal2"`**.
- `subject`, `session_id`, `challenge` are echoed verbatim from the request.
- The request's `acceptableEvidence` constrains which gate(s) the RP accepts;
  empty = any supported. `reason` is shown to the user **verbatim** (consent
  integrity).

### 4.7 WebAuthn / passkeys

- **Authentication model (decided 2026-05-20):** the WebAuthn assertion bytes
  are carried as **Trust-Task payload data**, *not* as a Data-Integrity proof on
  the Trust Task. Verified server-side by a standard WebAuthn library
  (webauthn-rs) against the **DID-resolved verification method**. (The earlier
  `webauthn-vti-v1` Data-Integrity cryptosuite was **superseded** — do not
  implement it.)
- **Document-binding rule (carry this forward):** for any task that carries a
  WebAuthn assertion, `clientData.challenge` MUST equal
  `base64url(SHA-256(canonical Trust-Task body))`. That binds the passkey
  ceremony to the exact document.
- `WebAuthnAssertion` fields are base64url and mirror the WebAuthn
  `AuthenticatorAssertionResponse` (`clientDataJSON`, `authenticatorData`,
  `signature`, `credential_id`, optional `userHandle`).
- Native APIs: **`ASAuthorization`** (iOS) / **Credential Manager** (Android).
  Flutter: `webauthn`/passkey plugins or platform channels to those APIs.
- Passkeys are also enrollable as DID verification methods
  (`spec/vta/passkey-vms/*`) — a PNM concern, see the URI registry.

### 4.8 Push wake-up (APNs / FCM)

- Binding: `https://trusttasks.org/binding/push/0.1`, adopting **Aries RFC 0699
  (APNs)** and **RFC 0734 (FCM)** as DIDComm v2 messages.
- Protocols: `https://didcomm.org/push-notifications-apns/1.0` and
  `…-fcm/1.0`, verbs `set-device-info` / `delete-device-info`.
- APNs body: `{ device_token, service: "apns"|"apns_sandbox", topic }`.
  FCM body: `{ device_token, service: "fcm" }`.
- **The push itself is contentless** — it only wakes the app. The app then opens
  its `MediatorSession` and pulls the actual (encrypted) Trust Task via message
  pickup. Push never carries Trust-Task content. Honour this — it's a privacy
  and security property, not an optimisation.
- Web Push (RFC 8030) is **not** done via DIDComm `set-device-info`
  (`Unimplemented`).

---

## 5. Key custody model

The defining security property: **private keys live in platform secure hardware,
gated by biometrics, and never enter the engine.**

| Tier | Keys in secure hardware | Status |
|---|---|---|
| **Tier-1 (target)** | Signing **and** key-agreement behind an enclave callback. | Future. The DIDComm FFI surface is shaped so the X25519 key can move behind an enclave key-agreement callback **without changing the FFI**. |
| **Tier-2 (interim, today)** | **Signing** key (Ed25519) in Secure Enclave / StrongBox via the `Signer` callback. **Key-agreement** (X25519) is **software-held**: DIDComm ECDH needs the raw X25519 scalar, which mobile secure hardware can't hold, so native loads it from the keystore (biometric-gated), passes it into `DidcommSession::new`, and it lives in app memory only while the session is open. Native **SHOULD zeroize** on session end. |

Implications for a port:

- The `Signer` callback (§3.2) is mandatory and platform-specific: iOS
  `SecKeyCreateSignature` over a Secure-Enclave key with `LAContext`
  biometric policy; Android `KeyStore` + `BiometricPrompt` + `Signature`.
  Flutter: a platform channel to those, or a vetted plugin.
- For Tier-2 DIDComm you must securely store and load the 32-byte Ed25519 seed
  (from which both the signing key and, via §4.4, the X25519 key derive). Treat
  it as the crown jewel: keystore-backed, biometric-gated, zeroized after use.
- Never log key material; never serialise it into a plaintext bundle (use
  sealed-transfer, §4.3).

---

## 6. Session / AAL state the native app must hold

The engine is stateless about sessions; the app owns this state:

- **Tokens:** access token (use as `Authorization: <token_type> <access_token>`,
  typically `Bearer`), `expires_in`; refresh token + `refresh_expires_in`.
- **AAL state:** `acr` (e.g. `aal1`/`aal2`) and `amr` (e.g. `["did"]`,
  `["did","passkey"]`). **A step-up bumps `acr`; the bump is surfaced on the
  next `refresh` response's session snapshot, or by `whoami`.** Refresh
  **preserves** AAL — a stepped-up `aal2` session stays `aal2` across rotation,
  it does not drop to `aal1`. Access-token TTL is shorter for `aal2`.
- **Reconciliation:** after a step-up or a server-side policy/role edit, call
  `whoami` to refresh local `acr`/`amr`/`roles`/`scopes` without re-issuing
  tokens.
- **Refresh quietly:** when the access token nears expiry, `build_refresh`
  without re-prompting the user.

---

## 7. Build, packaging & distribution

How the Rust engine becomes platform artifacts (relevant if you take Strategy A).

- **UniFFI 0.28**, with `tokio` async support
  (`#[uniffi::export(async_runtime = "tokio")]`). `setup_scaffolding!()` in
  `lib.rs`; bindings config in `uniffi.toml` (Kotlin package
  `org.openvtc.vta.mobilecore`, Swift module `VtaMobileCore`). Bindgen via the
  in-crate `uniffi-bindgen` bin.
- **Crate types:** `cdylib` (Android `.so` + the lib bindgen introspects),
  `staticlib` (iOS xcframework), `lib` (host tests).
- **iOS:** `aarch64-apple-ios` (device) + `aarch64-apple-ios-sim` +
  `x86_64-apple-ios` (simulator, fused with `lipo`) → `VtaMobileCore.xcframework`
  + generated `VtaMobileCore.swift` + C header/modulemap. Zipped, SHA-256
  checksummed, consumed from a SwiftPM `.binaryTarget(url:checksum:)` against a
  GitHub Release. **`IPHONEOS_DEPLOYMENT_TARGET=16.0` is load-bearing** —
  `aws-lc-sys` assembly references `___chkstk_darwin`, absent below 16.0, so the
  device link fails. Don't lower it without re-checking the link.
- **Android:** `cargo-ndk`, ABIs `arm64-v8a` / `armeabi-v7a` / `x86_64`, **min
  API 24**, output as `jniLibs`, published as an AAR
  (`org.openvtc.vta:mobile-core-android`).
- The crate is **excluded from `default-members`** so a server `cargo build`
  doesn't pull `uniffi`/the mobile graph; a dedicated CI `mobile-artifacts` job
  cross-compiles and packages it. `publish = false` (artifacts are AAR/xcframework,
  not crates.io).
- Build gate script: `scripts/build-mobile.sh [ios|android|all]` proves the
  cross-compile links and the bindings still generate. `scripts/package-ios.sh`
  produces the xcframework + checksum.

For **Strategy A in Flutter:** point `flutter_rust_bridge` at this crate (or
hand-write `dart:ffi` over the same `cdylib`/`staticlib`), reuse the same
cross-compile + deployment floors, and ship the `.so`/xcframework inside your
Flutter plugin. You replace UniFFI's generated glue with FRB's, nothing else.

---

## 8. Re-implementation checklist (Dart/Flutter)

Port in this order — each slice is independently testable, matching how the
engine was built:

1. **Custody seam.** Platform-channel `Signer` (Secure Enclave / StrongBox +
   biometric). Round-trip `sign_challenge`. *Nothing else works until this does.*
2. **Identifiers.** `did:key` Ed25519 encode/decode (multicodec `0xed01`,
   base58btc); VM id shape `did#id`.
3. **Trust-Task envelope.** Build/parse the `{id,type,issuer,recipient,issuedAt,
   payload,proof}` shape; enforce the canonical type-URI grammar; implement
   `#response` echoing.
4. **Data Integrity / `eddsa-jcs-2022`.** RFC-8785 JCS canonicaliser + the
   prepare-sign-input hashing; assemble `proofValue = multibase(base58btc, sig)`.
   **Verify against a known-good engine output before trusting it.**
5. **Step-up.** `parse_step_up_request` + both `build_approve_response_*`. Wire
   the WebAuthn gate to `ASAuthorization`/Credential Manager; the document-binding
   rule (§4.7).
6. **Auth flow.** `auth/challenge|authenticate|refresh|whoami|revoke-session`
   build/parse with correct `IS_PROOF_REQUIRED`; AAL preservation in your session
   store.
7. **DID resolution.** Local `did:key`/`did:peer` first; network methods later.
8. **DIDComm v2.** ed25519→x25519 derivation (§4.4 — get this exactly right),
   authcrypt/anoncrypt pack+unpack, mediator `routing/2.0/forward`. Hardest
   slice; strongly prefer reusing the Rust core here.
9. **Mediator session.** Challenge-auth + message-pickup 3.0 over WebSocket; the
   `receive_next` poll loop.
10. **Push.** `set-device-info`/`delete-device-info` message cores; native APNs/FCM
    receipt → open mediator session → pull the real (encrypted) Trust Task.

---

## 9. Invariants to preserve (don't relax these)

- Private signing key **never** crosses the FFI / leaves secure hardware.
  Tier-2 X25519 is software-held but keystore-loaded, biometric-gated, zeroized.
- Step-up challenge **≥16 bytes**; `reason` shown **verbatim**; `subject` /
  `session_id` / `challenge` **echoed verbatim**.
- `eddsa-jcs-2022` signing input is JCS-canonical and **byte-identical** to the
  engine's, or proofs don't verify.
- ed25519→x25519 uses the **standard birational map**, or DIDComm authcrypt to
  the holder `did:key` silently fails.
- `sender_authenticated == false` (anoncrypt/plaintext) ⇒ **do not trust
  `from`**.
- Trust-Task type URIs are **canonical** (`/spec/<ns>/<op>/<maj>.<min>`); no
  patch version; no version-family matching.
- Auth `IS_PROOF_REQUIRED` matrix: challenge=no, authenticate=yes, refresh=no,
  whoami=yes, revoke=yes.
- Refresh **preserves AAL**; `aal2` access tokens get the shorter TTL.
- Push wake-ups are **contentless**; Trust-Task content only ever travels
  encrypted via mediator pickup.
- DIDComm is the **preferred** transport for every inter-component flow; REST is
  the fallback for parties that can't speak it (and `auth/*` supports both).
- Sealed-transfer (PNM bundles) uses the hard-pinned HPKE suite + info string +
  domain tag; never negotiated.

---

## 10. Source map (for cross-referencing the reference impl)

| Concern | Engine file |
|---|---|
| FFI façade / metadata | `vta-mobile-core/src/api.rs` |
| Custody seam (`Signer`) | `src/keys.rs` |
| DI proof assembly (`eddsa-jcs-2022`) | `src/proof.rs` |
| Step-up parse / build | `src/task.rs`, `src/stepup.rs` |
| VTA `auth/*` build/parse | `src/session.rs` |
| DIDComm pack/unpack + key derivation | `src/didcomm.rs` |
| DID resolution | `src/resolver.rs` |
| Mediator session | `src/mediator.rs` |
| Push registration | `src/push.rs` |
| Error union | `src/error.rs` |
| Build / packaging | `src/lib.rs`, `uniffi.toml`, `scripts/build-mobile.sh`, `scripts/package-ios.sh` |

| Standard / context | Doc |
|---|---|
| Trust-Task URI catalogue (all VTA ops the PNM app drives) | [`trust-task-uri-registry.md`](./trust-task-uri-registry.md) |
| Canonical auth backend (server side of `auth/*`) | [`auth-architecture.md`](./auth-architecture.md) |
| WebAuthn-as-payload + document binding (superseded cryptosuite, useful rules) | [`webauthn-vti-v1-cryptosuite.md`](./webauthn-vti-v1-cryptosuite.md) |
| Workspace design principles (DIDs, DIDComm-first, templates, sealed-transfer) | root `CLAUDE.md` |

---

### Scope notes / open edges (so you don't mistake "not done" for "not needed")

- The engine today covers the **Authenticator** core (step-up, auth, DIDComm,
  push, mediator) end-to-end. The **PNM** management surface (driving the ~79
  `spec/vta/*` ops, sealed-transfer bundle open, provision-integration) is
  largely *not yet* in `vta-mobile-core` — it's specced in the URI registry and
  implemented in the CLIs (`vta-sdk`, `vta-cli-common`). A full PNM port pulls
  from those.
- `resolve_did` is local-methods-only today; `did:web`/`did:webvh` need
  network-mode resolver config.
- Tier-1 (key-agreement in the enclave) is a future hardening; the FFI is
  pre-shaped for it.
