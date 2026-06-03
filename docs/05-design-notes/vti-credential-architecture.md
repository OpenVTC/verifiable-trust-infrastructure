# VTI Credential Architecture — invite, hold, present, join

**Status:** SPECIFY (spec-driven). Awaiting review before PLAN → TASKS →
IMPLEMENT. Greenfield: breaking changes are in scope where they make the
architecture better. Security and privacy are the gating constraints.

This is the shared source of truth for turning VTI into a
credential-centric system: the VTA becomes a holder's credential agent
(store + wallet + signer), the VTC becomes an issuer + verifier + schema
authority, and trust between nodes moves as Verifiable Credentials over a
privacy-preserving exchange protocol. The motivating user journey is
**invite → hold → present → join**.

---

## 0. Locked decisions (design-review forks)

| # | Decision | Choice |
|---|---|---|
| D1 | Exchange wire protocol | **Trust Tasks wrap OID4VCI (issuance) + OID4VP (query/presentation)**; DCQL is the query language. The same OID4VP shapes are exposable to the browser via the W3C Digital Credentials API. |
| D2 | Role / session auth model | **Hybrid**: the VC is the source of truth; a fast local *verified-assertion record* (TTL + invalidation) backs every hot-path authorization check. Re-prove only on invalidation. |
| D3 | Credential type layer | **Adopt `dtg-credentials` (DTC)** as the canonical type catalog; the bespoke VMC/VEC become thin wrappers (or are retired) onto DTC types. |
| D4 | Selective disclosure | **BOTH, claim-level — and ALREADY BUILT in the TDK** (`affinidi-sd-jwt`/`-vc`, `affinidi-bbs`, the `bbs_2023` DI cryptosuite — validated, tests green). So this is **adopt, not build**. BBS curve = **`bls12_381_plus`** (the existing `affinidi-bbs`; supersedes the earlier `arkworks` call). One net-new TDK gap: **DCQL** (add to `affinidi-openid4vp`, which uses DIF PE today). |

---

## 1. Objective

Build the credential plane that lets a community **invite** a prospective
member, lets that member **hold** the invitation in their own agent, and
lets them **present** it to **join** — with the community then **issuing**
a membership credential, and all subsequent authority (membership, roles,
admin) **proven by held credentials** rather than asserted by a name in a
server-side list.

### Users

- **Alice** — a prospective then actual member. Holds credentials in her
  VTA; drives consent through the browser plugin (or mobile).
- **Community operator** — runs the VTC; defines which credentials the
  community issues and accepts (schemas), and the join ceremony.
- **Integrations / other VTI nodes** — exchange credentials VTA↔VTC and
  VTA↔VTA.

### Success criteria (testable)

1. A VTC can issue an **InvitationCredential** to an arbitrary DID that is
   **not yet a member** (the holder is unknown to the community), and the
   holder can store it in their VTA.
2. A holder's VTA can **store, index, search (by type/criteria), and
   present** credentials, and **mint** its own.
3. A verifier can request a credential by **DCQL** and receive **only**
   what the holder consents to — there is **no API that enumerates a
   holder's wallet** across a trust boundary ("no fishing").
4. Presentation supports **claim-level selective disclosure** — Alice can
   prove "holds a valid InvitationCredential for community X" without
   revealing unrelated claims or unrelated credentials.
5. **Authorization is credential-derived**: `admin` (and every role) is
   proven by a held **Role credential**, not by an ACL naming the DID.
6. **Session auth** is established by presenting a VP once; subsequent
   requests hit a **fast local verified-assertion record**; proof is
   re-requested only when that record is invalidated (revocation, role
   change, expiry).
7. The end-to-end **invite → join** flow works through the existing
   ceremony decision pipeline, including a legible **deny reason** on
   failure.

---

## 2. Principles

- **A credential is the unit of trust.** Membership, roles, invitations,
  endorsements, personhood — all are VCs. Everything server-side is a
  *projection* of credentials, never the source of truth.
- **The VTA is the holder's agent — always.** It stores the holder's VCs
  (the `vault`), holds the holder's keys, signs/presents on the holder's
  behalf, and mints VCs the holder issues. **There is no browser-only
  holder:** the browser plugin / mobile-core is the UX + consent surface
  and is *always backed by a VTA*. Consent originates on the device; the
  VTA never presents without it.
- **The VTC is issuer + verifier + schema authority.** It is *not* a
  wallet. It declares what it issues and accepts, issues credentials, and
  verifies presented ones.
- **The ACL becomes a cache.** The authoritative statement "Alice is an
  admin of context X" is a Role credential Alice holds. The VTC keeps a
  derived, fast, local *verified-assertion record* for the hot path, with
  a TTL and explicit invalidation.
- **Privacy is default-deny on disclosure.** A verifier asks for a
  *specific* credential/claims; the holder matches locally and consents
  per request. Unlinkability where the crypto allows it.
- **Reuse the rails.** Trust Tasks (envelope/auth/choreography),
  `sealed_transfer` (secret-bearing parts), the ceremony decision
  pipeline (Facts→Verdict→Effect), status lists (revocation), and the
  `affinidi-*` issue/verify stack are kept; the credential *data plane*
  and the *proof format* are the new work.

---

## 3. The credential catalog (DTC)

Adopt `dtg-credentials` (DTC) as the canonical type layer. The community
catalog (a superset of `docs/05-design-notes/vtc-mvp.md` §6.1):

| Credential | Issuer | Subject | Purpose | Selective disclosure |
|---|---|---|---|---|
| **InvitationCredential (VIC)** | community (or member with `can_invite`) | a (possibly unknown) DID | authorizes a join | yes — prove validity without revealing inviter graph |
| **MembershipCredential (VMC)** | community | member | "is a member of X" | yes — prove membership without other claims |
| **RoleCredential (Role VEC)** | community | member | proves a role (admin/moderator/issuer/member/custom) | yes |
| **EndorsementCredential (VEC)** | community or issuer-role member | member | community-defined claims | yes |
| **RecognitionCredential (VRC)** | member (self-issued) | another member | peer trust edge | n/a (Phase 3) |
| **PersonhoodCredential** | personhood oracle / community | member | Sybil resistance | yes |

`vtc-service/src/credentials/{vmc,vec}.rs` become thin adapters over DTC
types (or are retired). The JSON-LD `@context` documents live under
`https://openvtc.org/contexts/` and are `include_str!`-baked for offline
verification.

**Capabilities as credentials.** `can_invite` (delegated invitation) and
issuer authority are themselves credentials/claims, not ACL flags — this
is what lets invitation trees and delegated issuance work without a
central list.

---

## 4. Proof format — selective disclosure

The workspace today issues W3C VCDM 2.0 credentials with Data Integrity
proofs (`eddsa-jcs-2022`). To get claim-level selective disclosure
(D4) **from the start**, we implement **both** SD-JWT-VC and BBS+ as
first-class formats — the credential layer abstracts over *format*, not
just over DI cryptosuite. They are complementary, not redundant:

- **SD-JWT-VC** (IETF) — selective disclosure via **salted-hash
  disclosures over a JWT**, with a key-binding JWT (`kb-jwt`) for holder
  binding. *Needs no new curve* — it runs on the **Ed25519/JOSE** we
  already have, so it can ship first and unblock the VTA/VTC layers
  (Phases 1–6). Broadest **OID4VP / wallet ecosystem interop** (the
  `dc+sd-jwt` format). A distinct serialization from W3C-DI VCs (not a DI
  cryptosuite), so the credential-handling layer must span both shapes.
- **BBS+** via the **`bbs-2023` Data Integrity cryptosuite** — keeps the
  W3C VCDM + Data Integrity + JSON-LD model; the holder derives a *proof*
  disclosing a chosen subset of claims, and BBS+ adds **unlinkable**
  presentations (two presentations of the same credential can't be
  correlated). This is the stronger-privacy format and the reason for the
  BLS curve work below.

The two share one contract: disclose **only** the DCQL-requested claims,
mandatory holder binding, status-list revocability. The verifier accepts
both; DCQL `format` selectors say which a given query wants.
- **DID keys: we ADD a key, we do not change one.** BBS runs over
  BLS12-381 (a pairing-friendly curve, ≠ Ed25519), but the impact is
  asymmetric:
  - **Holders (Alice): no change at all.** Proof derivation (selective
    disclosure) is a *public* operation on the issuer's signature — the
    holder needs **no BLS key** to receive a credential or derive a
    disclosure proof. Holder binding stays an **Ed25519** signature over
    the verifier nonce (her existing `did:key`/`did:webvh`). Her DID +
    keys are untouched.
  - **Issuers (VTC, and a VTA that mints BBS credentials): add one
    verification method.** A **BLS12-381 G2** assertion key
    (`#bbs-key-0`, `Bls12381G2Key2020` / multicodec `0xeb`) **alongside**
    the existing Ed25519 `#key-0`. Because issuers are **`did:webvh`**
    (multi-key DID documents), this is purely additive — the DID
    identifier is unchanged and Ed25519 is not rotated.
  - **Caveat:** `did:key` is single-key, so an *ephemeral `did:key`
    issuer* can't carry a BLS key; only durable `did:webvh` issuers mint
    BBS credentials. `eddsa-jcs-2022` stays for anything a `did:key`
    signs. The workspace's "default to Ed25519 `did:key`" principle thus
    *expands* (issuer DID docs also carry a BLS G2 key) — it doesn't break.
  - **Optional later:** cryptographically *unlinkable* holder binding
    (inside the ZKP) uses the BBS **pseudonym/commitment** extension with
    a wallet-managed BLS **link secret** — still **not** the holder's DID
    key, just a blinding scalar the wallet holds. Start without it.
- **Implementation: ADOPT — the TDK already has it (validated).** The
  earlier "build from scratch" framing was wrong: the `Cargo.lock` grep
  came back empty only because *this workspace doesn't depend on the
  credential crates yet*. They exist and pass their suites (validated
  `cargo test`, exit 0):
  | TDK crate | LOC | tests | what it is |
  |---|---|---|---|
  | `affinidi-sd-jwt` | ~2.3k | 90 | SD-JWT core (issuer/holder/verifier, key binding) |
  | `affinidi-sd-jwt-vc` | ~0.5k | 11 | the SD-JWT-VC profile (`SdJwtVc`, `issue`, `verify_temporal`) |
  | `affinidi-bbs` | ~2.1k | 52 | BBS over **BLS12-381 (`bls12_381_plus`)**, IETF `draft-irtf-cfrg-bbs-signatures` |
  | `affinidi-data-integrity` | ~3k | ✓ | includes **`bbs_2023.rs`** — the DI cryptosuite, parallel to `eddsa-jcs-2022` |
  | `affinidi-openid4vp` / `-vci` | ~0.8k ea | 13 | OID4VP/VCI (**DIF Presentation Exchange today, not DCQL**) |

  So the BBS curve is **`bls12_381_plus`** (D-revised — the original
  `arkworks` call predated finding `affinidi-bbs`; we keep the existing,
  tested crate rather than rewrite it). The crates are
  `publish.workspace = true` (crates.io-publishable, like the
  `affinidi-vc = "0.1"` deps VTI already uses), so VTI **adopts them as
  dependencies** — no new TDK crate, no `arkworks`.
  - **The one net-new TDK gap is DCQL** (D-locked). `affinidi-openid4vp`
    uses the older DIF Presentation Exchange (`PresentationDefinition` /
    `InputDescriptor`); DCQL is absent across the whole TDK. We add a DCQL
    query + match module to `affinidi-openid4vp`.
  - **Still to confirm during adoption:** SD-JWT-VC profile completeness
    (`vct` / `cnf` / `status`); a BLS12-381 G2 verification-method
    representation for `#bbs-key-0` in the did:key/did:webvh layer.
  - **BBS audit** remains a gate before BBS signs anything real (the crate
    is implemented + unit-tested, not yet independently audited).
- **Holder binding** is mandatory on presentation (both formats): bound to
  a fresh holder-key signature over the verifier nonce — `kb-jwt` for
  SD-JWT-VC, an Ed25519 binding (or the BBS pseudonym extension later) for
  BBS+. Prevents replay / credential lifting.
- **`eddsa-jcs-2022` is retained** for credentials where selective
  disclosure adds nothing (status-list credentials, internal authorization
  VCs) and for the holder key-binding signature.

> **Sequencing (de-risked — the foundation is already built):** both
> formats exist + pass tests in the TDK, so Phase 0 is *validate + adopt*,
> not *build*. Integrate **SD-JWT-VC first** (simplest to wire — JOSE over
> Ed25519); **BBS+ is additive** (register a second format + the
> `bbs_2023` cryptosuite) and gated only by its independent **security
> audit** before real signing. The one net-new TDK build is **DCQL**.
> Neither blocks the VTA/VTC integration (Phases 1–6).

---

## 5. The VTA credential store (`vault` promotion)

The VTA already has a `vault` keyspace (M1 read-only stub). Promote it to
a first-class credential store. Each stored credential carries an indexed
envelope so the holder's agent can search **by type/criteria** without
parsing every credential:

```
StoredCredential {
  id,                       // local handle
  format,                   // "bbs-2023" | "eddsa-jcs-2022" | "sd-jwt-vc"
  types: [..],              // VC type tags (InvitationCredential, ...)
  schema_id,                // → VTC schema store / catalog entry
  community_did,            // which community / context this is for
  subject_did,              // the holder DID this VC is about
  issuer_did,
  purpose,                  // invite | membership | role | endorsement | personhood
  status,                   // valid | expired | revoked | unknown
  valid_from, valid_until,
  received_at, source,      // provenance
  tags: {..},               // holder-applied labels
  body,                     // the VC itself (encrypted at rest)
}
```

VTA capabilities (the missing data plane):

- **Receive** a VC → verify minimally (issuer signature, not-expired),
  index, store (encrypted).
- **Search** locally by `{type, community, issuer, purpose, schema,
  status, claims}` — this is the DCQL match engine, **local only**.
- **Present** → build a VP / derived proof (BBS+ selective disclosure)
  on demand, signed with the holder key (device callback / signing
  oracle), **gated by consent**.
- **Mint** → the VTA issues its own VCs (generalize the existing
  `DataIntegrityProof` issuer surface; add BBS+).
- **Track validity** → poll/refresh status-list state; mark
  revoked/expired so search can exclude them.

Encryption at rest reuses the existing per-keyspace AES-256-GCM.

---

## 6. Exchange protocols — Trust Tasks wrapping OID4VCI / OID4VP

A `credential-exchange/*` Trust Task family. The **Trust Task is the
transport + auth + choreography envelope**; the **body is OID4VCI/OID4VP**.

### Issuance (OID4VCI inside a Trust Task)

```
issuer → holder:  credential-exchange/offer/1.0      { credential_offer }   (OID4VCI)
holder → issuer:  credential-exchange/request/1.0    { credential_request } (OID4VCI, key-binding proof)
issuer → holder:  credential-exchange/issue/1.0      { credential }         (the VC, sealed if secret-bearing)
```

### Presentation (OID4VP + DCQL inside a Trust Task)

```
verifier → holder: credential-exchange/query/1.0     { dcql_query, nonce, purpose }  (OID4VP)
holder   → verifier: credential-exchange/present/1.0 { vp_token }                    (OID4VP, derived proof + holder binding)
```

Why wrap rather than adopt OID4VP raw:

- Trust Tasks already give **sender authentication** (authcrypt /
  DI-signed), **threading**, **relayer≠holder** (the air-gap onboarding
  pattern from provision-integration), and a uniform audit envelope.
- OID4VP/VCI give **standard, wallet-interoperable** request/response
  shapes and let the **browser plugin** speak the same bytes via the
  **W3C Digital Credentials API** (`navigator.credentials.get({digital})`
  with a DCQL request) — no bespoke plugin protocol.
- New protocol → new Trust Task type + handler, exactly the existing
  extension pattern (`vta-sdk/src/protocols/*`, `messaging/handlers.rs`).

`purpose` on every query is mandatory and **shown to the holder** (purpose
binding); the verifier cannot ask for a credential without stating why.

---

## 7. Privacy-first discovery (DCQL)

- The verifier sends a **DCQL query** — "a credential of type
  `InvitationCredential` for community `X` issued by a trusted issuer,
  disclosing claims `{a, b}`." It never receives, and there is no endpoint
  that returns, the holder's credential list.
- The holder's VTA runs the DCQL match **locally** over its `vault`
  index, producing candidate credentials.
- The **browser plugin** renders the request in plain English (reuse the
  ceremony's English-rendering approach) — *what* is being asked, *which*
  of Alice's credentials would satisfy it, *what claims* would be
  disclosed, and *why* (purpose) — and Alice **consents per credential**.
- Only on consent does the VTA build the **selectively-disclosed** VP and
  send it. Unmatched / unconsented credentials never leave the agent and
  are never even acknowledged to the verifier.

This is the "no fishing" guarantee at two layers: **no enumeration**
(DCQL targets specific credentials) and **claim minimisation** (BBS+
discloses only the requested claims).

---

## 8. VTC schema store

A `schemas` keyspace + registry. The community declares:

- **Issues** — the credential types this VTC mints (Invitation,
  Membership, Role, plus operator-defined endorsement types), each with a
  JSON Schema (`credentialSchema`) and a DTC type binding.
- **Accepts** — the credential types/criteria the community recognises as
  evidence, expressed so a ceremony's required evidence is a **DCQL query
  over the schema store** (this is the "manifest" / Presentation
  Definition from the join-ceremony design, now concrete).

The schema store is the single source for: what a join requires, what the
admin UI offers operators to issue, and what the DCQL queries reference.
Validation of an incoming VC against its `credentialSchema` happens at
verify time (a new step alongside signature + status + issuer-trust).

---

## 9. Issuing to a DID — unknown (invite) vs member-only

- **Invite (unknown holder).** The community issues an
  InvitationCredential to a DID that is **not a member**. This is the
  relayer≠holder / air-gap pattern already used by provision-integration:
  the credential is sealed to the holder's key and delivered out-of-band
  (link, QR, DIDComm), and the holder need not have an account first.
  Delegated invites (`can_invite`) let an authorised member issue.
- **Member-only.** Membership, Role, and Endorsement credentials are
  issued only to an established member DID (gated by the
  verified-assertion record, §10).

Issuance always goes through the **schema store** (the type must be
registered as "issues") and the **status-list allocator** (so every
issued credential is revocable).

---

## 10. Role-by-VC + the verified-assertion cache (hybrid auth)

This replaces the ACL-name-as-truth model.

- **Source of truth:** a held **Role credential** ("Alice holds a
  `RoleCredential{role: admin, community: X}` issued by X"). There is no
  ACL row that *names* Alice an admin.
- **Hot-path cache — the verified-assertion record:**

  ```
  VerifiedAssertion {
    did,
    community_did,
    roles: [admin, ...],          // proven by presented Role VCs
    contexts: [..],
    membership: { vmc_id, status },
    proof_refs: [credential ids + presentation nonce],
    verified_at,
    expires_at,                   // TTL — short for high-assurance roles
    invalidated: bool,            // flipped on revocation / role change
  }
  ```

  Built when the holder presents a VP (at login or step-up). Every gated
  route reads this record **synchronously** — no per-request credential
  verification, no async I/O on the hot path.

- **Invalidation:** a status-list revocation event, a role-change
  ceremony, or TTL expiry flips `invalidated` / drops the record. The
  next request gets a `re-present required` and the holder re-proves. This
  is requirement #8 verbatim: *simple fast local lookup; only when
  invalidated do you request proof again.*

- **What changes in code:** the `VtcAclEntry.role` field stops being
  authoritative; the auth extractors (`AdminAuth`, `ManageAuth`,
  `StepUpAuth`) read the verified-assertion record instead of a JWT role
  burned from the ACL. The ceremony `Admit`/`Remint`/`Depart` effects
  issue/revoke Role VCs and update the cache rather than writing an ACL
  role.

---

## 11. Session authentication via VP

Generalise the existing challenge-response so the credential **is** the
authentication:

```
POST /auth/challenge   → { nonce, dcql_query }     // "present membership (+ role) for X"
POST /auth/            → { vp_token }               // selectively-disclosed VP, holder-bound
   → verify: signature + holder binding + status + issuer trust + schema
   → write VerifiedAssertion (roles/contexts/membership)
   → mint session JWT whose role/contexts are DERIVED from the assertion
POST /auth/refresh     → rotates the bearer; re-checks the assertion isn't invalidated
```

The JWT stays as the session bearer (fast stateless transport of "who +
what"), but it is now a **cache of a cache** — derived from the
verified-assertion record, which is derived from credentials. Token TTLs
stay short for high-assurance roles (existing aal2 pattern).

---

## 12. The end-to-end flow (invite → join)

```
1. Operator (VTC) issues InvitationCredential to did:alice
   └ credential-exchange/offer → issue ; sealed to alice's key ; alice unknown to community
2. Alice stores it in her VTA
   └ browser plugin → VTA vault.store ; indexed { type: Invitation, community: X, purpose: invite }
3. Alice opens community, clicks "Join"
   └ VTC starts the join ceremony
4. VTC → Alice: credential-exchange/query (DCQL)  "InvitationCredential for X (+ schema-required evidence)"
   └ Alice's VTA matches locally ; plugin shows request + purpose + claims to disclose
5. Alice consents per credential
   └ VTA builds selectively-disclosed, holder-bound VP → credential-exchange/present
6. VTC verifies → assembles ceremony Facts → decide() → execute()
   ├ Allow  → issue MembershipCredential (+ Role VC) back to Alice ; write VerifiedAssertion
   ├ Deny   → return the decision-trace reason (the "why this verdict" UX)
   ├ Refer  → moderator queue (existing) ; refer→queue link
   └ RequestMore → DCQL for the missing evidence (the request_more loop)
7. Alice is a member: her authority is now the held Membership + Role VCs.
```

Every wire step is a `credential-exchange/*` Trust Task; every decision is
the ceremony pipeline already built; every failure is a legible verdict.

---

## 13. Browser plugin UX

The plugin is the consent + key + legibility surface:

- Speaks **OID4VP via the W3C Digital Credentials API** to the same query
  shapes the Trust Tasks carry.
- Renders the DCQL request in **plain English** (reuse the ceremony
  English renderer): what, which credential, which claims, why.
- Drives **per-credential, per-claim consent** and the **holder-binding**
  signature (device key).
- Shows held credentials, their validity/revocation status, and the
  invite→join progress (mirrors the ceremony pipeline visual).

---

## 14. Security & privacy invariants (do not relax)

1. **No wallet enumeration across a trust boundary.** No endpoint returns
   a holder's credential list. Discovery is DCQL-targeted only.
2. **Consent before disclosure.** The VTA never presents a credential
   without explicit, purpose-bound holder consent.
3. **Claim minimisation.** Presentations disclose only the DCQL-requested
   claims (BBS+ selective disclosure); unlinkable where the suite allows.
4. **Holder binding mandatory.** Every presentation is bound to a fresh
   holder signature over the verifier nonce — no replay, no lifting.
5. **Every issued credential is revocable** (status-list entry) and
   re-verified for status at presentation time.
6. **Issuer trust is explicit.** A verifier accepts a credential only
   from an issuer its policy/trust-registry trusts (reuse Phase-3
   recognition).
7. **Secret-bearing transfers stay sealed.** Any credential carrying key
   material moves via `sealed_transfer` (HPKE), never plaintext.
8. **The verified-assertion cache is authoritative only as a cache.** It
   must be invalidatable within one revocation propagation cycle; it
   never outlives the credential it projects.

---

## 15. Data model (keyspaces)

| Keyspace | Node | New/changed | Holds |
|---|---|---|---|
| `vault` | VTA | **promote** (was M1 stub) | StoredCredential envelopes + index |
| `schemas` | VTC | **new** | issued + accepted credential schemas (DTC + JSON Schema) |
| `verified_assertions` | VTC (+VTA) | **new** | the hot-path auth cache (§10) |
| `acl` | VTC | **repurpose** | from "role source of truth" → derived index / legacy gate |
| `status_lists` | VTC | reuse | revocation/suspension |
| `sealed_nonces` | VTA | reuse | anti-replay for sealed transfers |
| credential-exchange threads | both | **new** (or reuse join_requests) | in-flight exchange state |

---

## 16. Boundaries

- **Always:** issue through the schema store + status-list allocator;
  require purpose on every DCQL query; require holder binding on every
  presentation; verify signature + status + issuer-trust + schema before
  trusting any VC; gate every disclosure on consent.
- **Ask first:** introducing a second proof format (SD-JWT-VC); changing
  the BLS/BBS key management on issuers; widening what the
  verified-assertion cache trusts; any endpoint that returns more than one
  credential at a time.
- **Never:** an endpoint that enumerates a holder's wallet; presenting a
  credential without consent; disclosing claims beyond the DCQL request;
  treating the ACL/JWT role as authoritative over a revoked credential;
  emitting plaintext secret-bearing credentials.

---

## 17. Open questions

1. ~~BBS+ library maturity (highest risk)~~ **RESOLVED: it exists +
   passes tests.** `affinidi-bbs` (BBS over `bls12_381_plus`, 52 tests) +
   `affinidi-data-integrity::bbs_2023` are implemented and validated
   (`cargo test` exit 0). Remaining real risk is the **independent
   security audit** before BBS signs anything real — not existence.
2. **Issuer BLS key lifecycle.** How are BLS12-381 issuer keys minted,
   stored (the VTC `LocalSigner`), and rotated alongside the Ed25519 key?
3. **Trust-registry binding for issuer trust** — reuse Phase-3
   recognition, or a dedicated trusted-issuer policy per credential type?
4. **Verified-assertion invalidation propagation** — push (revocation
   event → cache flip) vs pull (TTL + status re-check). Likely both;
   what's the max staleness window?
5. ~~Where does the VTA wallet run for a browser-only Alice?~~
   **RESOLVED:** there is no browser-only holder — the plugin is always
   backed by a VTA, which holds the wallet + keys. (Open sub-question:
   does the plugin also hold a device-side key for holder binding, or
   does the VTA hold it? Lean device-side for the binding signature, VTA
   for the credential store.)
6. **OID4VP profile** — which DCQL/credential-format profile to target for
   external-wallet interop (and is that a near-term goal or future)?
7. ~~Pairing-library choice~~ **RESOLVED: `bls12_381_plus`** — keep the
   existing, tested `affinidi-bbs` (the earlier `arkworks` + new-crate
   plan predated finding it). ~~Proof format~~ **RESOLVED: BOTH, and both
   already built.** ~~BBS home~~ **RESOLVED: existing `affinidi-bbs`.**
   Remaining: **who audits** BBS before real signing.
8. **DCQL shape** — confirm the DCQL profile/version to implement in
   `affinidi-openid4vp`, and how it maps onto both SD-JWT-VC and BBS
   credential formats.

---

## 18. Phased plan (PLAN preview — not yet TASKS)

- **Phase 0 — Validate + adopt the TDK formats (mostly DONE).** The
  credential foundation already exists and passes its tests (`affinidi-sd-jwt`,
  `affinidi-sd-jwt-vc`, `affinidi-bbs` on `bls12_381_plus`, the `bbs_2023`
  DI cryptosuite). *Verify: ✅ `cargo test` exit 0 across the crates.*
  Remaining adoption tasks: wire them as VTI deps; confirm the SD-JWT-VC
  profile (`vct`/`cnf`/`status`) + a BLS12-381 G2 verification method for
  `#bbs-key-0`; schedule the **BBS security audit** before real signing.
- **Phase 0c — DCQL (the one net-new TDK build):** add a DCQL query +
  match module to `affinidi-openid4vp` (it uses DIF Presentation Exchange
  today). *Verify: a DCQL query matches/selects credentials against the
  SD-JWT-VC + BBS formats.* Unblocks the privacy-first discovery (§7).
- **Phase 1 — Credential store:** promote the VTA `vault` to a real
  store (receive/store/index/search/present/mint). *Verify: store + DCQL
  local search + present round-trip.*
- **Phase 2 — DTC catalog + schema store:** adopt `dtg-credentials`;
  build the VTC `schemas` registry; port VMC/VEC; add InvitationCredential.
  *Verify: issue each catalog type against its schema.*
- **Phase 3 — Exchange protocol:** the `credential-exchange/*` Trust Task
  family wrapping OID4VCI/OID4VP + DCQL. *Verify: VTC↔VTA issue + query +
  present.*
- **Phase 4 — Role-by-VC + verified-assertion cache:** rebuild auth so
  roles are credential-derived; ACL → cache; VP-based `/auth`. *Verify:
  admin proven by a held Role VC; revocation invalidates within the
  window.*
- **Phase 5 — Join ceremony integration:** wire the exchange + cache into
  the existing ceremony pipeline (invite → DCQL → present → decide →
  issue membership). *Verify: the §12 flow end-to-end, allow + deny.*
- **Phase 6 — Browser plugin UX:** Digital Credentials API, plain-English
  consent, per-claim disclosure, progress UI. *Verify: Alice completes
  invite→join in the plugin.*

Each phase is its own PR(s) and its own review gate. PLAN → TASKS expand
each into discrete, verifiable tasks before implementation.
