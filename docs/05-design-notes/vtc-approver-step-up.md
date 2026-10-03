# Step-up for wallet administrators — an approver device as the step-up factor

Status: **accepted** (2026-10-02; open questions settled in §11). The wire
changes in §9 landed in dtgwg-trust-tasks-tf (trust-tasks-rs 0.26.3) and
dtgwg-vti-spec (VTI-APV-015 as amended, VTI-APV-016). The VTC side — §10 steps
2–5 and step 7 (factor store, gate, enrolment R1–R4, revocation, install claim
0.3, console) — is implemented: `vtc-service/src/acl/approver.rs`,
`acl/bound_step_up.rs`, `step_up_approver.rs`,
`trust_tasks/step_up_approver_tasks.rs`. The browser plugin (step 6), the
console's 0.3 install page, and mobile approvers (phase 2) are not.

Builds on `vtc-operation-bound-step-up.md` (the bound step-up this extends),
`vtc-console-signing.md` (§6f, two factors), and the step-up passkey invite
flow (`vtc-service/src/step_up_passkey.rs`). The approver identity it relies on
is the browser plugin's (`vta-browser-plugin`,
`packages/core/src/store/approver-identity.ts`).

---

## 1. The problem

An administrator who signs in to the VTC console with their **VTA wallet**
acts as a DID the VTA holds (typically `did:webvh:…`), and the VTC knows no
passkey for it. Every operation behind the operation-bound step-up — a grant
or promotion to `admin`, an admin invite, a widening `acl/update`, git
break-glass — asks that DID for a WebAuthn gesture and refuses:

> step-up required: this operation needs a passkey gesture from did:webvh:…,
> who has no passkey registered with this community

The routes that message suggests are closed to that person:

- **A self-invite** for a step-up passkey is refused on purpose
  (`step_up_passkey.rs`, "an administrator does not invite themselves"):
  otherwise one stolen key could mint a second factor for itself.
- **Settings → Passkeys** adds a passkey only behind an existing one
  (`routes/admin/passkeys.rs::register_start` answers 404 "no passkey user for
  caller").

So a wallet-only administrator can administer nothing that confers authority,
and a community whose administrators are all wallet-only can only grow through
the offline break-glass. The wallet is the sign-in the VTI stack is built
around; it must work as a first-class administrator path.

The VTA and the browser plugin already have the missing piece: the plugin holds
a second, distinct **approver identity** — an Ed25519 `did:key` whose seed is
PRF-wrapped behind a WebAuthn gesture, cryptographically separated from the
worker key — used today to sign DTTE decisions. This note makes that identity,
or any device identity with the same properties, acceptable to the VTC as the
administrator's step-up factor.

## 2. What the specification requires

The step-up is a **re-authentication**, not a consent. That decides the shape.

- **VTI-APV-003** — a re-authentication is satisfied only by the caller, and is
  never evidence that another party agreed. The definition of *step-up*:
  "involves no third party. Where the requirement is that a different party
  agrees, the mechanism is consent."
- **VTI-APV-015** — bound to one operation's digest (computed as VTI-APV-004),
  redeemable once, by the caller, expiring, raising no session; and "the
  gesture MUST be the caller's own additional factor, verified against the
  challenge the node issued for that operation — a proof the caller could
  produce without the factor, such as a signature by a key the caller already
  holds, does not satisfy it."
- **VTI-SES-001–004** — the challenge is CSPRNG, subject-bound, expiring,
  single use.
- **VTI-ACL-005 / VTI-OPS-110** — the factor travels as defined payload data,
  never in `ext`.
- **VTI-APV-011 / -013** apply to consent, not re-authentication, but the
  approver device in §5 can meet them for free, and does.

Consequences:

1. The approver device is **the caller's own factor**. It must not be modelled
   as a `task-consent` approver: a decision from the requester's own device is
   not "another party", and wiring it through the consent machinery would blur
   exactly the line APV-003 draws. The ceremony is the step-up's, with a new
   kind of evidence.
2. A signature counts under APV-015 only because the key is **not one the
   caller already holds for signing**. The approver key must be distinct from
   the administrator's DID keys and from every console key, held where using it
   takes user verification, and bound to the administrator as a step-up factor
   by an enrolment that did not rest on the administrator's signing key alone
   (§6). That is the property the passkey has by construction and the approver
   key has only by enrolment discipline — hence §6 is most of this note.
3. APV-015's wording reads, on its face, as excluding *any* signature. §9b
   proposes the clarification the specification needs before this is
   implemented, rather than reading it permissively.

## 3. Alternatives considered

**(a) Accept `didSigned` evidence from the administrator's own DID.** The
approve-response schema already defines it (`amr: "vta"`): the persona signs via
the wallet, and the VTA's own approval rules gate that signature behind the
user's approver device. Rejected as the end state because the VTC cannot see
that the VTA enforced anything — it sees one signature, by a key the caller
already holds, which is the case APV-015 names as not satisfying the step-up.
It would also need the VTA's rules to match on the type of the document being
signed rather than on `vault/sign-trust-task/0.1`, or every console signature
would need approval.

**(c) Route the step-up through `task-consent/*` with the requester's devices
as the approver set.** Rejected: APV-003 (above). It also inherits consent's
approver-authority rule (APV-006), which makes no sense for the caller's own
factor.

**(d) Only fix enrolment of an ordinary passkey for wallet administrators.**
Possible, and §6's anchors would serve it unchanged. Not chosen as the primary
path because a VTC passkey is per-origin and per-community, while the approver
identity is the one factor the user already carries across their VTA, its
communities and (later) their phone — and because the approver device, unlike a
bare WebAuthn assertion, can show the human *what* is being approved (§5d). It
stays available: nothing here removes the passkey path.

## 4. The factor: a step-up approver

A **step-up approver** is a DID bound at this VTC to exactly one administrator
(or member) DID as their step-up factor.

| Property | Rule |
|---|---|
| DID method | `did:key`, Ed25519 (`z6Mk…`). Resolution is local, so verification never depends on a network fetch. |
| Distinctness | MUST differ from the subject DID and from every console key enrolled for the subject; MUST NOT appear as a verification method in the subject's DID document. Checked at enrolment and again at use. |
| Uniqueness | One approver DID is bound to at most one subject at this VTC. |
| Confers | Nothing. No role, no scope, no session, no login. It is read only by the bound step-up gate, from its own keyspace, which login and session step-up never read — the same construction as `STEP_UP_PASSKEYS`. |
| Supersedes | Once a subject holds any dedicated step-up factor (approver or step-up passkey), their ordinary session passkeys stop counting for the bound step-up — the rule `bound_step_up.rs` already applies to step-up passkeys, widened to the union. |
| Limit | At most 5 per subject (same as console keys). |
| Backup | **Backed up** — unlike `STEP_UP_PASSKEYS`, an approver DID is not bound to a WebAuthn relying party, so it is as valid on the restored host as on the original. A restore into a different community is already refused by the VTC-DID compatibility check. Open question §11.3. |

Storage: a new keyspace `step_up_approvers` — `approver:<did>` → `{ subject,
label, enrolled_at, enrolled_via, last_used_at }`, `subject:<did>` → list.

## 5. The ceremony

### 5a. Flow

```
console ──(1) signed acl/grant (console key)──────────────▶ VTC gate
        ◀─(2) stepUpRequired: approve-request 0.4
              {subject, challenge, wireDigest,
               accepts: [approverSigned, webauthn?],
               approvers: [did:key:…]}───────────────────── parks a pending mark
console ──(3) approveStepUp(request, operation)──▶ plugin
                 plugin recomputes wireDigest from the operation it is shown,
                 renders the operation, user gesture unwraps the approver key,
                 approver signs the step-up statement
        ◀────────── evidence {kind: approverSigned, statement} ──
console ──(4) approve-response 0.6 {subject, challenge, decision: approved,
              evidence}, signed by the SUBJECT DID
              (wallet signTrustTask {asDid: subject})──────▶ VTC verifies both,
        ◀─(5) {status: recorded, boundTo}─────────────────── records the mark
console ──(6) the same acl/grant, re-sent─────────────────▶ gate spends it
```

Steps 1, 2, 5 and 6 are the existing bound step-up unchanged
(`vtc-operation-bound-step-up.md` §3a). Only the evidence differs.

### 5b. The statement

```json
{
  "kind": "approverSigned",
  "statement": {
    "subject":   "did:webvh:…",
    "audience":  "did:webvh:…vtc…",
    "challenge": "<step-up challenge>",
    "boundTo":   "<wireDigest>",
    "issuedAt":  "2026-10-02T09:00:00Z",
    "proof": {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "proofPurpose": "authentication",
      "verificationMethod": "did:key:z6Mk…#z6Mk…",
      "proofValue": "z…"
    }
  }
}
```

`audience` is the VTC's DID, so a statement made for one relying party is
refused at another even if a challenge ever collided. The proof is over the
statement exactly as received (no re-serialisation).

### 5c. Verification (VTC)

The approve-response is accepted only if **all** hold, checked in this order so
a cheap refusal comes first:

1. The outer document's proof is by the **subject DID's own** verification
   method — never a console key's delegation. This is the rule the step-up
   passkey path already has ("the passkey is beside the proof, never instead of
   it"), and is what stops a console key, which signs as its own `did:key`,
   from answering.
2. A pending mark exists for `challenge`, is unexpired, and names `subject`.
3. `statement.subject`, `challenge` and `boundTo` equal the pending mark's;
   `audience` equals this VTC's DID; `issuedAt` is within the mark's lifetime.
4. `statement.proof.verificationMethod`'s DID is a live step-up approver bound
   to `subject` (§4), and still distinct from the subject's DID and console
   keys.
5. The statement's proof verifies.

Then the mark is recorded exactly as for a passkey (`credential_id` becomes the
approver DID in `StepUpEvidence`), and the audit row names the evidence kind
and the approver DID.

### 5d. What the approver shows (and checks)

The plugin is handed the operation the console is about to re-send, not just
the challenge. It:

- recomputes `wireDigest` = the VTC step-up digest
  (`vtc/step-up/v1\0 ‖ len(uri) ‖ uri ‖ len(JCS(payload)) ‖ JCS(payload)`,
  salted with the challenge) from that operation, and refuses if it differs
  from the request's — so the human approves the bytes the VTC will execute;
- renders the operation, the subject and the community from those same bytes
  (APV-011 / -013 discipline, though not required for re-authentication);
- signs only after the user gesture that unwraps the approver key.

The digest construction is shared code (`vti_common::task_consent::domain_digest`);
the plugin's copy must be tested against the same pinned vectors
(`digest_matches_its_pinned_vectors`), not reimplemented from prose.

### 5e. Mobile approvers (phase 2)

A phone approver cannot be reached through the console. Phase 2 has the VTC
push the approve-request, VTC-signed, to the approver DID over the subject's
transport (TSP > DIDComm), and the device answer with the statement. Two
constraints carry over from DTTE: `vta-mobile-core` refuses a request whose
issuer is not an enrolled executor, so enrolment (§6) must also register the
VTC DID on the device; and a `did:key` approver is routable only through a
mediator, so the VTC needs the device's mediator from enrolment. Phase 1 ships
the plugin path only.

## 6. Enrolment — the first-factor problem

### 6a. The rule

A second factor cannot be bound on the strength of the first. Every enrolment
of a step-up approver MUST rest on an **anchor independent of the subject's DID
signing key**, and there are exactly four:

| Anchor | Held by | Route |
|---|---|---|
| A one-shot out-of-band token (install or enrolment URL + claim code) | whoever received it | R1, R2, R4 |
| Another administrator's authority, behind *their* step-up | a second administrator with a factor | R2 |
| A step-up factor the subject already holds | the subject | R3 |
| Host access, daemon stopped | the operator | R4 |

Every enrolment also requires **proof of possession** of the approver key: the
approver signs an enrolment statement (`{subject, audience, challenge, purpose:
"enrol"}`) over a fresh VTC challenge. And every enrolment requires the
**subject's own signature** over the request, so no holder of an invite can
bind their own device to someone else's DID (the rule `redeem/start` already
enforces for step-up passkeys).

### 6b. R1 — at install, for the founding administrator

Today `vtc/install/claim/{start,finish}/0.2` registers a passkey and derives the
first administrator's `did:key` from it. A wallet founder needs a claim *under
a DID they already control* — which the install route's own documentation
names as "a future version rather than approximated". This is that version:

- `vtc/install/claim/start/0.3` takes the install token (anchor) and returns a
  challenge;
- `vtc/install/claim/finish/0.3` carries the persona's signature (wallet
  `signTrustTask {asDid}`) proving control of a verification method in the
  persona's **live** DID document, and the approver's enrolment statement.

The VTC writes the persona as administrator and the approver as their step-up
factor in one step. `co_admin_did` at install is unchanged and gets the same
choice when they claim.

### 6c. R2 — invited by another administrator

The step-up passkey invite (`auth/passkey/enroll/invite/0.2`, `purpose:
stepUp`) already has every property needed: issued only by a community
administrator behind their own bound step-up, never to themselves, single use,
TTL-capped, token in the URL and claim code delivered separately, hashes only,
five wrong codes void it, redeemed by a `redeem/start` signed by the invited
member. R2 is that invite with an approver redeemed instead of a passkey
registered. §9a asks whether that is a new `factor` member on the invite or a
sibling family; the mechanism is the same either way.

Issuing an invite for a new administrator should be the default when the
administrator is created: the creation already passed the creator's step-up and,
for unrestricted scope, another administrator's consent (APV-014), so the
invite costs nothing extra and closes the gap before it is felt.

### 6d. R3 — self-service, from a factor already held

Adding or rotating an approver is itself a bound step-up operation
(`auth/step-up/approver/enroll/0.1`), satisfied by any factor the subject
already holds — another approver or a passkey. Same for revoking one's own.
This is how a user moves to a new browser or phone without anyone's help.

### 6e. R4 — offline break-glass

`vtc admin enrol-approver --did <subject>` (daemon stopped) mints an R2-shaped
invite — token + claim code — instead of writing a factor directly, so proof of
possession and the subject's signature still apply. Like every offline ACL
writer, it queues an `install:break_glass:*` marker and the daemon emits an
audit row at its next start. This is the route for the community whose
administrators are all wallet-only today.

### 6f. Revocation and loss

- The subject revokes their own approver behind a bound step-up (R3).
- A community administrator revokes another member's, as `auth/passkey/revoke/
  {start,finish}/0.2` does for step-up passkeys, behind their own step-up.
- Revoking the last factor is allowed: it removes the subject's ability to step
  up, not their authority, and is recoverable through R2/R4. It is audited.
- Removing a subject from the ACL removes their approvers.
- Losing every factor is recovered through R2 (another administrator) or R4
  (the operator). That is the same position as losing every passkey today.

## 7. Console and plugin

- The console reads the refusal's `accepts`. If `approverSigned` is listed and
  the wallet plugin is present, it calls the plugin's new
  `approveStepUp({ request, operation })`; otherwise it runs the WebAuthn path
  as now.
- The plugin today keys its approver identity by **VTA DID** (one approver per
  onboarded VTA). Using the same approver DID at several communities makes the
  user correlatable across them by that DID. §11.1.
- The console's error for a subject with no factor at all must name the routes
  that actually exist for *that* caller: R2 (ask another administrator, naming
  the console page) and R4 (the offline command), never a self-invite.

## 8. Residual risks

1. **User verification is not provable.** A WebAuthn assertion carries the UV
   flag; an approver signature does not. The VTC trusts, from enrolment, that
   the approver key is held behind a gesture. For the plugin this is true by
   construction (PRF-wrapped seed); for other approver implementations it is a
   claim. Mitigation options in §11.2.
2. **Browser compromise.** The console key and the plugin's approver key can
   live in one browser. They are separated — the console key in the console
   origin's IndexedDB, the approver seed PRF-wrapped in the extension's storage
   and released only by a WebAuthn gesture — so neither origin's storage alone
   yields both. A compromise of the extension itself defeats both factors; so
   does a compromised OS for a passkey on the same machine.
3. **Enrolment is the attack surface.** Everything above rests on §6a. Every
   enrolment route is audited with its anchor (`enrolled_via`).

## 9. Specification changes (upstream first)

### 9a. dtgwg-trust-tasks-tf

1. `auth/step-up/approve-response/0.6` — Evidence gains `approverSigned`
   (§5b). The existing `didSigned` and `webauthn` are unchanged.
2. `auth/step-up/approve-request/0.4` — `accepts` (evidence kinds the relying
   party will take) and `approvers` (the subject's bound approver DIDs);
   WebAuthn options become optional, present only when `webauthn` is accepted.
3. Approver enrolment — either `auth/passkey/enroll/invite/0.3` with a
   `factor: passkey | approver` member (redeem gaining an approver variant), or
   a sibling `auth/step-up/approver/{invite,redeem/start,redeem/finish,enroll,
   list,revoke}` family. Recommendation: the sibling family — a passkey invite
   that sometimes carries no passkey is a misleading name.
4. `vtc/install/claim/{start,finish}/0.3` — claim under an existing DID with an
   approver (§6b).

### 9b. dtgwg-vti-spec

1. **Clarify VTI-APV-015.** Proposed text to append: "A signature by a key
   bound to the caller as a re-authentication factor satisfies it only where
   that key is distinct from every key that can sign the caller's operations,
   is held where its use requires user verification, and was bound under
   VTI-APV-0xx."
2. **New requirement — factor binding.** Proposed: "A node MUST bind a
   re-authentication factor to a subject only on evidence independent of the
   subject's signing keys: a single-use out-of-band token, a factor the subject
   already holds, the authority of another administrator exercised under their
   own re-authentication, or administrative access to the host. The binding
   MUST prove possession of the factor and MUST be audited, naming the evidence
   it rested on."

Until 9b lands, implementing §5 would read APV-015 permissively, so it waits
for it — or, if implemented first, goes in the divergence register (Appendix F)
with this note as the intended resolution.

## 10. Implementation plan

Each step after the specs is its own PR.

1. Specs (§9a, §9b); `trust-tasks-rs` bump carrying the generated types.
2. **VTC factor store + gate.** `step_up_approvers` keyspace and its
   backup classification; `bound_step_up` accepts `approverSigned` (§5c) and
   advertises `accepts`/`approvers`; the factor union rule (§4). Tests for every
   refusal in §5c, including a console key answering and an approver bound to a
   different subject.
3. **Enrolment routes** R2, R3, R4 (§6c–e) and revocation (§6f), served on the
   signed-document spine.
4. **Install claim 0.3** (§6b) and `vtc setup` support for a wallet founder.
5. **Console**: the `accepts` branch, `approveStepUp`, enrolment UI under
   Settings and under Members → member, the corrected no-factor error.
6. **Browser plugin**: `approveStepUp` (digest recompute, rendering, gesture,
   statement), enrolment statement signing; digest pinned-vector tests.
7. **Docs**: `docs/03-vtc/bootstrap-runbook.md` (wallet founder path), the
   CLAUDE.md integration-flow entry.
8. Phase 2: mobile approvers (§5e).

## 11. Settled defaults (2026-10-02)

1. **One approver DID per community.** The plugin derives the approver identity
   per audience (VTC DID), so communities can't correlate a user by it. One
   enrolment per community is already required by §6.
2. **User verification is trusted from enrolment** for phase 1, and recorded
   in the threat model (§8.1). The plugin's approver key is PRF-wrapped, so
   unlocking it takes a gesture.
3. **Approvers are backed up** (§4). A restore into a different community is
   already refused by the VTC-DID check.
4. **Every newly created administrator gets an enrolment invite
   automatically** (§6c). The creator delivers the claim code separately.
