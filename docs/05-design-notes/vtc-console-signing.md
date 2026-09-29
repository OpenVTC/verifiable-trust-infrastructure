# Signing from the admin console

*Design note for the successor to [#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/issues/1641).
[#1681](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1681) moved
the first four admin member verbs onto the VTC's signed-document dispatcher and
could not retire their bearer routes, because the admin console cannot author a
signed document. `vtc-trust-task-proof-enforcement.md` §6b states that as the
removal point for every bearer route in the migration. This note is how the
console gets there.*

---

## 1. The premise, verified

`vtc-service/admin-ui/src` contains no signing primitive. Grepping the whole
source tree for `eddsa-jcs-2022`, `DataIntegrityProof`, `ed25519`, `nacl`,
`tweetnacl`, `crypto.subtle`, `jcs`, `canonicali[sz]`, `@noble`, `@scure`,
`indexeddb` returns **nothing outside `src/lib/wire.ts`**, and those are
generated OpenAPI doc comments, not code. `package.json` carries no crypto
dependency: React, react-router, TanStack Query, zustand, lucide, qrcode,
three `@fontsource` packages. The only cryptographic thing the console does is
call `navigator.credentials.{create,get}` through `src/lib/webauthn.ts`, and
WebAuthn cannot produce a Data-Integrity proof.

That second half is not a gap waiting to be filled. A cryptosuite that would
have let a WebAuthn assertion *be* a Data-Integrity proof was drafted here —
`docs/05-design-notes/webauthn-vti-v1-cryptosuite.md` — and **superseded on
2026-05-20**. The direction taken instead is that a WebAuthn assertion travels
as trust-task *payload data*, verified by a WebAuthn library, and that embedded
Data-Integrity proofs use the standard cryptosuites. So "make the passkey sign
the document" is not an open option; it is a closed one, and reopening it is a
larger decision than this note.

The console therefore needs a key. The rest of this note is which key, whose,
where it lives, and what authorises it.

---

## 2. What a signed Trust Task requires here

Exactly reproducible, and small. The Rust reference is
`vta-sdk/src/trust_task_sign.rs::sign_in_place_with`; the verifier is
`vta-sdk/src/trust_task_proof/verify.rs::verify_trust_task_proof_with`, reached
from the VTC at `vtc-service/src/trust_tasks/helpers.rs:453`.

**The document.** A `TrustTask` with `id` (`urn:uuid:…`), `type` (the task's
Type URI), `payload`, `issuer`, `recipient`, `issuedAt`. `recipient` is not
optional in practice — SPEC §4.8.2 audience binding rejects a *signed* document
with no in-band recipient unless its specification is a bearer spec, which is
why `build_unsigned` always sets it. `issuedAt` is checked against a 10-minute
acceptance window with 60 s skew (`freshness_policy()`, VTI-OPS-024).

**The proof config**, with `proofValue` absent:

```json
{
  "type": "DataIntegrityProof",
  "cryptosuite": "eddsa-jcs-2022",
  "created": "<RFC-3339 UTC>",
  "verificationMethod": "<did>#<fragment>",
  "proofPurpose": "assertionMethod"
}
```

**The bytes signed** (`affinidi-data-integrity` 0.7.7, `hashing_jcs`):

```
hashData  = SHA-256( JCS(proofConfig) ) || SHA-256( JCS(document minus "proof") )
signature = Ed25519( hashData )                       // 64 bytes, over the 64-byte hashData
proofValue = "z" + base58btc(signature)               // multibase
```

Three details that each yield a signature which verifies nowhere if missed:

- **The proof-config hash comes first.** Concatenation order is not symmetric.
- **`proof` is removed from the document before canonicalising**, not set to
  `null` and not left as an empty object. JCS is presence-sensitive.
- **`created` must not be in the verifier's future.** `verify_proof_internal`
  rejects a future `created` outright, with *no* skew tolerance. Both existing
  browser implementations back-date it — the plugin by 60 s, did-hosting-ui by
  5 s — and the plugin's comment records that this was found the hard way.

**Who may sign.** Any DID that can name a key.
`TrustTaskVmResolver` resolves `did:key` and `did:peer` locally with no I/O and
everything else through the configured `DIDCacheClient`. A `did:key` console key
therefore costs the VTC no network resolution at all.

**What verification establishes, and what it does not.** It returns the proven
signer DID. It does not say that party was entitled to anything. On the VTC's
dispatch spine the proven signer is additionally bound to the document's own
`issuer` (SPEC §4.7) — so `issuer` and the proof's `verificationMethod` DID must
be the same DID. **This is the constraint that shapes everything below.**
Authorization is then a separate read: for the tasks #1681 moved, `admin_signer`
(`vtc-service/src/trust_tasks/mod.rs:2107`) resolves the signer's own ACL row
via `crate::acl::resolve_auth_role` at execution time, and deliberately does not
consult `sessions_ks`.

---

## 3. What the console is, and who the operator is

**Build.** React 19 + TypeScript + Vite 8, `base: "/admin/"`, `target: ES2022`,
built by `build.rs` into `$OUT_DIR` and baked into the binary with
`include_dir!`. No browserslist and no downlevelling beyond ES2022: whatever
the project's real browser floor is, it is not written down anywhere in the
repo. `npm run lint` is `wire:check` + `tsc -b --noEmit`; tests are vitest +
jsdom.

**Content-Security-Policy** (`vtc-service/src/routing/security_headers.rs`) is
`default-src 'self'; script-src 'self'; …` — no CDN, no inline script, and no
`wasm-unsafe-eval`. A pure-JS + WebCrypto signer needs no change to it. A
WASM-compiled signer would need the CSP widened, which is a reason not to reach
for one.

**Authentication today.** A passkey login (`POST /v1/auth/passkey-login/{start,
finish}`) sets `vtc_admin_session` — an **HttpOnly** cookie carrying a
short-lived access JWT (300 s at `acr=aal2`), plus a refresh cookie and a CSRF
cookie. `src/lib/session.ts` renews ahead of expiry. Because the cookie is
HttpOnly, **no bearer material is reachable from JavaScript today**; that is a
property worth not losing. Per-user state in the browser is: nothing
cryptographic. There is no IndexedDB use at all.

**Step-up** (`src/lib/step-up.ts`, added by #1658) is a second passkey
user-verification gesture with `purpose: "stepUp"`, run *before* any operation
that confers the `admin` role. It stamps a bounded elevation window on the
session row.

### 3a. The operator already is a DID — and already has a key they never use

This is the fact that makes the rest of the design tractable, and it is not
obvious from the console.

A VTC console operator **is** a DID string with an `acl:<did>` row at
`role = admin`, plus a passkey bound to that same DID. The JWT `sub`, the audit
actor, the ACL key and the session `did` are all that string.
`map_vtc_role_to_auth_role` admits only `VtcRole::Admin`, so "console operator"
and "DID with an admin ACL row" are the same set.

That DID is real and has real key material. `vtc setup` takes it from the
provisioning VTA (`vtc-service/src/setup/wizard.rs:277`), and the wizard
**prints the admin private key as JSON for the operator to save by hand** — the
comment there says a keyring write is not yet implemented. The install ceremony
then attaches a passkey to that DID for browser access.

So the console operator has a signing identity. The browser has never held it.

### 3b. Three constraints that close off the obvious answers

**(i) The operator's DID is a `did:key`, which cannot grow a second
verification method.** A `did:key` *is* its key. If the operator's admin
identity were a `did:webvh`, a console key could simply be published as
`did:webvh:…:alice#console-1` in their own DID document and the whole problem
would evaporate: `issuer` = the admin DID, the proof names a VM that DID
controls, `verify_trust_task_proof_with` resolves it, `admin_signer` finds the
ACL row, and **not one line of VTC code changes**. That is the standards-clean
shape and §7 says what it would take. It is not available today.

**(ii) Self-promotion is structurally refused.** #1658 added
`Invariant::SelfPromotion` (**VTI-OPS-050**) — nobody promotes themselves,
however well authenticated — and `create_acl` refuses a self-targeted grant that
creates a new admin entry (`vtc-service/src/routes/acl.rs:332`). So "the console
mints a key and enrols its DID as an admin" is self-promotion reached by a
longer path, and it will hit the invariant. Any design that gives the console
key **its own admin ACL row** is therefore either blocked or requires a second
human, per device, per browser profile.

**(iii) Nothing in the VTC models one human holding several DIDs.**
`acl:<did>`, `admin:<did>` and `members:<did>` are each 1:1 with one DID string.
There is no `controller`, no `alsoKnownAs`, no owner field. What *is* modelled,
and modelled well, is **one DID holding several credentials**: `AdminEntry`
(`vtc-service/src/acl/admin.rs`) carries `passkeys: Vec<RegisteredPasskey>`, and
`POST /v1/admin/passkeys/{register,revoke}/{start,finish}` is a self-service
ceremony under `AdminAuth` for adding and removing devices from your own
identity. It also carries a free 16 KiB `extensions` JSON slot that no gate
reads.

Those three facts together point at one answer, and §5 takes it: **a console
signing key should be a credential of the operator's existing admin DID, the way
a passkey is — not an identity of its own.**

---

## 4. Prior art

Three implementations of this exact signature exist in the ecosystem. Two are
in a browser.

### 4a. `pnm-browser-plugin` — `packages/core/src/trust-tasks/`

`sign.ts` (97 lines) + `canonical.ts` (115 lines). `@noble/curves`'s
`ed25519.sign(toSign, privateKey)` for the signature, `crypto.subtle.digest`
for SHA-256, hand-rolled RFC-8785 JCS and base58btc with no dependency. Signing
is owned by the **channel**, not the call site: every outbound envelope passes
`signOutboundTask(envelope, signer)` on its way out, because ~93 of 141 task
types declare a proof REQUIRED and signing at ~116 call sites was not a design.
`created` is back-dated 60 s by default. The package (`@openvtc/pnm-core`) is
published on npm and has a `./trust-tasks` subpath export; the repo already ships
a plain Vite + React 19 SPA (`packages/pwa`) consuming it, so "lift it into a
Vite SPA" is a walked path. Signing-only cost is roughly **15 KB gzip**,
almost all of it `@noble/curves/ed25519`.

**Its key custody is the part not to copy.** `SigningIdentity.privateKey` is a
raw extractable `Uint8Array` in JS memory, persisted to IndexedDB, and
`installVtaMintedHolder` is called with `secretEncrypted: false`
**unconditionally** at onboarding — the shipped default is a plaintext Ed25519
seed in origin storage. A WebAuthn-PRF/AES-GCM wrap exists
(`packages/extension/src/webauthn-prf-wrap.ts`) but is labelled "foundation
only" and is an opt-in the user must find. The module's own header says an
attacker with origin-scoped storage access "walks away with the wallet". An
extension has an isolated world and a locked CSP; a web origin does not, so this
posture does not transfer.

Its enrolment is also not transferable: the plugin mints a throwaway
`did:key`, the operator pastes a `pnm acl create --did <ephemeral> --role admin
--expires 1h` into a terminal out of band, and the VTA then ships the long-term
admin key back inside an HPKE-sealed bundle. The browser does not generate the
key it keeps.

### 4b. `affinidi-webvh-service/did-hosting-ui/lib/session-key.ts` — the closest precedent

476 lines, **zero dependencies**, and it is a browser SPA rather than an
extension. This is the one to read first.

- `generateSessionKeypair()` on login — `crypto.subtle.generateKey({name:
  "Ed25519"}, …)`, public key multikey-encoded to `did:key:z6Mk…`, keypair
  mirrored into **IndexedDB** so it survives a page reload.
- The `did:key` is sent to the server at `passkey/login/finish` as
  `session_pubkey_b58btc` and stored on the session row.
- `signEnvelope()` implements exactly §2's construction, signing with
  `crypto.subtle.sign({name: "Ed25519"}, privateKey, toSign)`.
- `clearSessionKeypair()` on logout wipes the IDB entry.

Server side (`did-hosting-control/src/routes/trust_tasks.rs:100-160`), two
cases, and the comment is worth quoting because it is the whole security
argument:

> (a) JWT carries an ephemeral session pubkey (passkey Web UI flow). The
> proof's `verificationMethod` MUST be the matching `did:key:{pk}#{pk}` URL.
> Otherwise the proof was signed by a key the server hasn't bound to this JWT —
> even if the signature verifies, accepting it would let any key holder forge
> requests as the JWT subject.
> (b) JWT carries no session pubkey … the proof's `verificationMethod` MUST
> resolve to a DID that matches `auth.did`.

**A bug in it, found while reading, which the VTC must not copy.** It calls
`generateKey(…, true, ["sign","verify"])` with the comment *"extractable=true is
needed to export the raw public key bytes; the private key stays inside the
CryptoKey wrapper"*. That is wrong. Per WebCrypto, `generateKey` sets
`publicKey.[[extractable]]` to **true unconditionally** and
`privateKey.[[extractable]]` from the argument. Measured on Node 26:

| call | `pub.extractable` | `priv.extractable` | `exportKey("raw", pub)` | `exportKey("pkcs8", priv)` |
|---|---|---|---|---|
| `generateKey(…, true, …)` | true | **true** | 32 bytes | **succeeds** |
| `generateKey(…, false, …)` | true | false | 32 bytes | `InvalidAccessError` |

So `extractable: false` costs nothing — the raw public key still exports — and
`true` hands any script in the origin the private key. **The VTC must pass
`false`, and assert `keypair.privateKey.extractable === false` after
generating.** (Worth reporting upstream; it is a one-character fix there.)

### 4c. The dormant half of this, already in `vti-common`

`vti_common::auth::session::Session` already carries
`session_pubkey_b58btc: Option<String>`, with this doc comment:

> Ephemeral session pubkey for Data Integrity proof binding (`eddsa-jcs-2022`).
> Ed25519 multikey, base58btc with the `z` prefix. The corresponding
> `did:key:<this>` is the verificationMethod the holder uses when signing
> trust-task envelopes for this session.

It is threaded through `challenge` → `authenticate` → `refresh`, validated in
`vtc-service/src/routes/auth.rs:193` (must start `z6Mk`), and set to **`None` on
every passkey-login path** (`routes/auth.rs:846`). Half the mechanism is built
and the console never populates it.

---

## 5. The options

### Option A — a durable per-device console key, delegated from the operator's admin DID ✅ **recommended**

The console generates a non-extractable Ed25519 `CryptoKey` pair, keeps it in
IndexedDB, and derives `did:key:z6Mk…`. That DID gets **no ACL row**. Instead
the VTC stores a **delegation**: "console key K may act as admin DID D",
created by D's own authenticated session behind a step-up, revocable, expiring —
the same lifecycle, the same ceremony and the same place in the model as a
registered passkey.

Documents are issued *by the console key's own DID* (`issuer = did:key:zK`), so
SPEC §4.7's issuer↔signer binding holds unchanged. Authorization resolution
gains one step: the signer's own ACL row, and failing that, the delegation →
the delegating admin DID's ACL row, read at execution time.

- **For:** does not need an ACL row per device, so VTI-OPS-050 self-promotion is
  never engaged — a delegation confers *no role*, it names a credential of an
  identity that already has one. Mirrors the passkey model the VTC already has,
  including per-device revocation. Authority is still an ACL row read at
  execution time, so #1681's stated property survives. Survives page reload;
  survives token refresh; survives sign-out if you want it to.
- **Against:** the largest build of the options (§6). Introduces a VTC-side
  concept — a delegated signing key — that is *not* published anywhere a third
  party can read, so an outside auditor holding a signed document can verify it
  and identify the key, but needs the VTC's delegation record to say which human
  that was. §7 is the fix for that, and it is a `did:webvh` fix, not a code one.

### Option B — an ephemeral per-session key bound via `session_pubkey_b58btc`

The did-hosting-ui pattern verbatim: fresh keypair per login, `did:key` sent up
at `passkey-login/finish`, stored on the session row, and the dispatcher
requires `proof.verificationMethod` to equal the session-bound key.

- **For:** by far the least to build — the session field, its validation and
  its plumbing already exist in `vti-common`; the client side is a file that
  already exists in a sibling repo; and there is **no enrolment at all**, so
  nothing to design, document, or explain to an operator. No key outlives a
  session, so a stolen key expires on its own.
- **Against:** authority comes back through the session. `admin_signer` would
  have to consult `sessions_ks`, which `vtc-service/src/trust_tasks/mod.rs`
  documents at length as the thing it deliberately does not do, and which the
  proof-enforcement note gives a reason for in §1: a bearer session is killed by
  revoking the session, a signed document by removing the ACL row, "which is the
  only authority it ever rested on". Option B reinstates the session as the
  authority chain for signed documents. It also makes every document's `issuer`
  a per-login pseudonym, so the evidentiary value VTI-OPS-021's rationale is
  about — "survives the message being stored, forwarded, replayed on another
  transport, or produced in evidence afterwards" — is recoverable only from a
  session row that is swept. It satisfies the letter of VTI-OPS-020 (the
  producer signs) while giving up much of what -021 wants from it.
- **Verdict:** a legitimate cheaper answer, and the right one if the build in §6
  is judged too large. It is not the better one. Note it is also *forward*
  compatible: the client-side module is identical, and moving B→A later changes
  only where the delegation is recorded.

### Option C — a passkey-PRF-derived key

WebAuthn's `prf` extension yields a stable 32-byte secret per credential per
salt; HKDF it into an Ed25519 seed and sign with `@noble`. No key at rest, and
signing requires a user-verification gesture.

- **For:** strongest custody — the signing key exists only for the duration of a
  ceremony, and script execution in the origin cannot produce a signature
  without a human touching the authenticator.
- **Against:** PRF support is uneven across authenticators (it needs a resident
  key and UV, and not every platform authenticator or browser exposes it); the
  plugin's own PRF wrap is labelled "foundation only" and its fallback is
  plaintext. It binds signing to one authenticator, so losing it loses the
  ability to sign as well as the ability to log in. **And a UV gesture per
  signed document is not viable for a console** where a single screen issues
  several admin verbs. The key must also be extractable into JS to reach
  `@noble` (WebCrypto cannot import raw bytes as an Ed25519 key and keep the
  same derivation), so the "no key at rest" benefit is partly given back at use
  time.
- **Verdict:** keep as an *optional hardening* on top of A — PRF-wrap the
  IndexedDB entry rather than derive the signing key — not as the mechanism.

### Option D — the operator imports the admin key `vtc setup` printed

Simplest possible: paste the admin private key JSON into the console, import it
as a non-extractable `CryptoKey`, sign as the admin DID. `issuer` = signer =
the DID with the ACL row, so **zero server-side change** and `admin_signer`
works today.

- **Against:** it puts the community's super-admin private key into a browser
  origin, in cleartext at the moment of import, on every device the operator
  uses. There is no per-device revocation — revoking means rotating the admin
  identity and re-enrolling every passkey. It makes a manual key-handling step
  (already flagged as MVP-grade in `wizard.rs`) load-bearing for daily console
  use. And it spreads one key rather than distributing several.
- **Verdict:** rejected. Worth stating because it is what someone will propose
  first, and it is genuinely the smallest diff.

### Option E — the VTC signs on the operator's behalf ❌ **rejected, explicitly**

The VTC holds a key and produces the proof for a console request authenticated
by its session cookie.

This defeats the requirement the migration exists to satisfy, and the
specification says so in one sentence. **VTI-OPS-021**: *"A transport that
authenticates its sender MUST NOT be treated as relieving a producer of
addressing or signing the document it sends."* Server-side signing is that
sentence with an extra hop: the session still authenticates the caller, and the
signature attests to the *VTC's* action rather than the operator's. The proof
would say "the VTC asserts that someone with a valid cookie asked for this",
which is precisely the transport-attribution claim §1a of the proof-enforcement
note establishes a proof may *not* substitute for. Every bearer route it
"unblocked" would be the same divergence wearing a signature.

It also fails **VTI-OPS-093** (a binding must not weaken the document
requirements on the strength of a transport property) and, because the VTC would
hold a key that can author admin documents in any operator's name, it manufactures
a single compromise that forges the entire operator population. It is not a
fallback, a stopgap, or a transitional path. It should not appear in the issue
as an option.

### Option F — enrol each console key as its own admin ACL row

Mentioned to close it off. Blocked by VTI-OPS-050 as described in §3b(ii): a
self-targeted new admin entry is refused, so every new browser profile would
need a *second human* to grant it. It also produces one full admin credential
per device in `acl list`, and — the part that matters most — it converts an XSS
in the console origin from session-bounded into *persistent*: script that wins
the race on a legitimate step-up window could leave behind a durable admin row.
Option A cannot do this, because a delegation grants no role and is visible and
revocable beside the operator's passkeys.

---

## 6. The recommended design in detail

**A console signing key is to the operator's admin DID what a passkey is: a
credential of that identity, enrolled by its holder, listed beside the others,
individually revocable, and conferring nothing on its own.** Everything below
follows from taking that sentence literally.

### 6a. How the key is created and where it lives

```ts
const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
if (kp.privateKey.extractable) throw new Error("refusing an extractable console key");
const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)); // 32 bytes
const did = `did:key:${multibase(0xed01, raw)}`;                                 // z6Mk…
```

`extractable: false` — §4b measured that this still exports the raw public key
and that `true` exposes the private key to any script in the origin. The
`CryptoKey` objects are structured-cloneable, so the pair is stored in
IndexedDB **as `CryptoKey` objects**, never as bytes; the browser's serialiser
preserves the non-extractable invariant across the round trip. There is no code
path anywhere in the console that can turn that key into bytes.

The `verificationMethod` is `${did}#${did.slice("did:key:".length)}`, matching
`vta_sdk::trust_task_sign::did_key_to_vm`.

### 6b. The client module

Lift `did-hosting-ui/lib/session-key.ts` — it is zero-dependency, browser-generic
and already implements §2 — with three changes: `extractable: false` and the
assertion above; the IndexedDB record keyed per VTC origin rather than a
singleton; and `created` back-dated by 60 s rather than 5 s, matching the
plugin, since `verify_proof_internal` allows no future skew and the console's
clock is the operator's laptop.

Take the JCS canonicaliser as-is from either source (they are the same code).
Note the honest caveat the plugin's author records: it is a "good enough for our
documents" JCS, not a conformance-tested one — number serialisation leans on
`String(v)` rather than RFC 8785's ES6 `Number::toString`, and there is no
Unicode normalisation. Trust Task documents are strings, integers and nested
objects, so this has not bitten; a test that round-trips each dispatched
payload's canonical form against the Rust `serde_jcs` output would close it, and
is cheap.

Signing belongs in **one place**, the way the plugin puts it in the channel.
`src/lib/api.ts` already funnels every request and already threads a
`trustTask` option through `postJson`/`patchJson`; the signed path is a variant
of that seam, not 60 call sites.

### 6c. Enrolment

A self-service pair mirroring `auth/passkey/{enroll,revoke}` exactly:

- `POST /v1/admin/console-keys` — `AdminAuth` **plus a live step-up**
  (`StepUpAuth`). Body `{ consoleDid, label }`. Writes a delegation record
  against `claims.did`. The console already calls `stepUpSession()` before
  admin-conferring operations, so the gesture and its UI exist.
- `GET /v1/admin/console-keys` — the caller's own keys, for a "this browser" /
  "other browsers" list beside `myPasskeys.tsx`.
- `DELETE /v1/admin/console-keys/{consoleDid}` — `AdminAuth`, self or another
  admin. Immediate.

**Why this is not self-promotion.** VTI-OPS-050 is about *conferring a role*. A
delegation confers none: it names a key that may act as an identity which
already holds whatever role it holds, and it can never reach further than that
identity's own ACL row, read fresh on every document. Enrolling a console key is
the same class of act as registering a second passkey — which the VTC already
permits under `AdminAuth` with no second human — and it is strictly weaker,
because a passkey can pass the step-up gate that confers admin and a console key
must not (§6f).

**Storage.** Either a new `console_keys` keyspace (`console_key:<consoleDid>` →
`{ admin_did, label, created_at, created_by, expires_at, last_used_at }`) or the
existing `AdminEntry.extensions` slot. Prefer the keyspace: the lookup is
by *console* DID on the hot path, `extensions` would need a scan, and a new
keyspace must be classified in the backup partition census anyway, which is a
decision better made explicitly. It should sit in `EXCLUDED_FROM_BACKUP` — a
restored VTC should not resurrect signing authority for a browser that no longer
exists — and it needs a sweeper tick for `expires_at`, alongside the ACL sweeper.

**Default expiry** should be finite. 30 days, refreshed on use, is the obvious
starting point and is a decision for the issue, not this note.

### 6d. Verification and authorization

`admin_signer` gains one step, and loses none:

```
verified_signer (bound to doc.issuer by the spine, SPEC §4.7)
  → resolve_auth_role(acl_ks, signer)            // unchanged: CLI, integrations, wallets
  → on Forbidden/absent:
      console_keys.get(signer)                   // the delegation
      → check not expired
      → resolve_auth_role(acl_ks, delegation.admin_did)   // still an ACL row, still at execution time
```

Authority is still an ACL row read at execution time; a row removed, demoted or
expired since enrolment refuses here. The delegation adds a second revocation
lever (drop the key) without removing the first (drop the row).

The audit row must carry **both** — `actor` = the admin DID, and the console DID
as the acting credential — or the record says a human did something when a
specific browser did. `AuditLogEntry.detail` is the existing place for it.

### 6e. Lifecycle facts, stated plainly

| Question | Answer |
|---|---|
| Survives page reload? | Yes — IndexedDB, lazily restored before the first signature. |
| Survives sign-out? | Design choice. Recommend **keeping** it (it is a device credential, not a session artefact) and offering "forget this browser" beside it. |
| Survives a browser-profile change, a new machine, a private window? | **No.** Each is a fresh origin store, so each enrols its own key — exactly as each gets its own passkey. |
| Second device? | Supported and expected: N delegations per admin DID, listed and individually revocable. This needs no one-human-↔-many-DIDs model, which the VTC does not have. |
| Operator with no key yet? | Detected on load. The console offers "enable signing for this browser", which runs the step-up and enrols. Until then it keeps using the bearer routes — which is exactly why they stay mounted during the migration and are removed per §7. |
| Revocation | `DELETE` the delegation, or let it expire, or remove the operator's ACL row (which kills every key delegated from it at once). |
| Browser with no WebCrypto Ed25519 | Detected at generate time; the console says so and stays on the bearer path rather than failing a click. |

### 6f. Interaction with the passkey — two factors, still

The console key is **not** a second factor and must not become one. It is
possession of a browser profile; the passkey is possession of an authenticator
plus user verification. Keep `stepUpSession()` exactly where #1658 put it: every
admin-conferring operation still requires a live passkey gesture, whether the
request arrives as a bearer call or a signed document. A signed document
carrying a delegated console key satisfies VTI-OPS-020; it says nothing about
who is at the keyboard, which is what the step-up is for.

Concretely: `acl/grant` and `acl/change-role` moved onto the signed door must
still consult `elevation::verified` on the delegating admin's live session. That
is the one place a signed document legitimately reads a session — not for
authority, but for the freshness of a human gesture.

> **Superseded (2026-09-24)** by
> [`vtc-operation-bound-step-up.md`](vtc-operation-bound-step-up.md). Reading
> the admin's live session cannot say *which* session, and it hands §6g's script
> a 15-minute window to spend. The signed door instead takes a step-up bound to
> the one operation by payload digest, which elevates nothing. The rule above —
> the console key is not a second factor — stands unchanged.

### 6g. What an attacker with script execution in the console origin gets

Honestly: **they can sign anything the operator could, for as long as they run.**
A non-extractable `CryptoKey` prevents exfiltration, not use. This is the same
bound as today — script in the origin can already ride the HttpOnly cookie — so
the change is roughly neutral, with two differences worth being precise about:

- **Worse:** a signature is a durable artefact. A captured signed document
  remains replayable until its `issuedAt` window closes (10 min) or its id is
  spent in `accepted_ids`, whereas a cookie-borne request had to be made live.
  The acceptance window and the replay record are what bound this, and they are
  already enforced.
- **Better than Option F:** the attacker cannot leave anything behind. They
  cannot exfiltrate the key, and enrolling a *new* key requires a live passkey
  UV gesture they cannot forge. When the tab closes, they are gone. Under
  Option F they could have planted a durable admin ACL row.

The residual risk is a script that sits quietly and waits for the operator's own
step-up gesture to open a window it can spend. That risk exists today, unchanged,
and the mitigations are the ones already in place: `script-src 'self'`, no
third-party script, no inline script, and the plugin loader's own contract
(`docs/03-vtc/admin-ui-plugins.md`) — which is the one place third-party code
legitimately enters this origin and should be re-read before shipping this.

---

## 7. Retiring the bearer routes, and what it unblocks

### What it takes for the four #1681 kept

For `vtc/members/{credentials,update,admin-remove,purge}` — which already have
signed doors — the removal is:

1. §6's client module and enrolment, shipped and reachable.
2. `admin_signer`'s delegation step (§6d).
3. `admin-ui/src/plugins/members.tsx` moved from the four REST calls to
   `POST /v1/trust-tasks` with signed documents. Note the door difference #1681
   records: the signed endpoint is on the **governed unauth chain** — per-IP
   rate limit and a **64 KiB** body cap rather than 1 MB. `members/update`'s
   `extensions` bag is the one in this batch that can exceed it; check before
   moving, not after.
4. `vtc-client` given the same path — it reaches three of the four over bearer
   REST, and it has `vta_sdk::trust_task_sign` available, so this is small.
   `cnm-cli` reaches none of them.
5. Delete the routes, their OpenAPI entries and the transitional descriptions;
   regenerate `admin-ui/openapi.json` + `src/lib/wire.ts`.

### How many of #1641's routes this unblocks

#1641 records 48 (30 community + 17 canonical + `vtc/auth/admin-session/0.1`);
the proof-enforcement note re-derives **49**, the extra being
`vtc/invitations/deliver/0.1` (#1648), and warns the count is a floor that grows
with each new admin route.

Grepping `admin-ui/src` for Type URIs gives 66 tasks the console calls.
Intersected with the 49:

| bucket | in #1641 | console-reachable |
|---|---|---|
| Admin | 18 | **12** |
| Member session | 12 | **4** |
| Canonical (shared) | 17 | **16** |
| `vtc/auth/admin-session/0.1` | 1 | 1 |
| `vtc/invitations/deliver/0.1` | 1 | 1 |
| **total** | **49** | **34** |

The console does not reach `config/{export,import}`, `backup/{export,import}`,
`website/{files/delete,rollback}` (no screen) or `config/restart`; the remaining
member-session verbs belong to `openvtc-core` and the plugin, both of which
already sign.

So **this change is the blocker on 34 of the 49**, including all four #1681
kept. It is not sufficient for them — each still needs its signed-door binding
in a #1641 batch, and `cnm`/`vtc-client` need the same treatment for the ones
they reach — but of the three client surfaces named as blocking, the console is
the one with no path at all, and it is the largest share.

### Where this should end up

§3b(i): if the operator's admin identity were a `did:webvh` rather than a
`did:key`, a console key would be enrolled by **publishing it as a verification
method in the operator's own DID document**. Then `issuer` is the admin DID, the
proof names `did:webvh:…:alice#console-1`, `TrustTaskVmResolver` resolves it
through the DID cache, `admin_signer` finds the ACL row directly, and the
delegation record in §6c disappears — along with the objection in §5A that the
delegation is not publicly readable. A third party holding a signed document
could then attribute it with nothing but the DID document.

That is where this should end up. It needs the operator's admin DID to be a
`did:webvh` they can update — which the provisioning VTA can mint (`vta-admin`
is an existing DID template) but `vtc setup` does not today — and it needs a
console-key enrolment verb that reaches the VTA. It is a larger change than §6
and should not gate it: §6's delegation record is the same wire shape minus one
lookup, so the migration later is a server-side change with no client churn.

---

## 8. Decisions this note does not make

1. **A or B** — durable per-device delegation (§5A) or ephemeral session-bound
   (§5B). A is recommended; B is materially cheaper and forward-compatible.
2. **The browser-support floor.** WebCrypto Ed25519 needs Chrome 137+,
   Firefox 130+, Safari 17+. Accepting it buys non-extractable keys. Rejecting
   it means `@noble/curves` (~15 KB gzip) and a key that is extractable by
   definition — which is the plugin's posture, and not one to adopt in a web
   origin without saying so out loud.
3. **Whether an operator may sign from two devices.** §6e assumes yes, N
   delegations per admin DID, mirroring passkeys. Saying no means one key, and
   an operator locked out of their own console from a second machine.
4. **Default delegation lifetime**, and whether a key survives sign-out.
5. Whether to PRF-wrap the IndexedDB entry (§5C) as later hardening.
