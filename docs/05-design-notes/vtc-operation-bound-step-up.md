# Step-up on a signed document, bound to the operation — and second-party consent for unrestricted admin

Status: **accepted; §3 implemented for `acl/grant` and `acl/change-role`** (§6 and §8 say what is done and what differs from this design) — §7 lists the decisions. Decided with the maintainer on 2026-09-24: the step-up a
signed document needs is bound to **the one operation** it authorizes, not to a
session; and this note also designs the second-party consent VTI-APV-014
requires for unrestricted-scope admin grants, which the VTC does not implement
on either door today.

Tracks #1641 (the first of the two blockers `vtc-trust-task-proof-enforcement.md`
§6b names). Builds on `vtc-console-signing.md` (§1, §6c, §6f, §6g) and follows
the VTA's direction in `approvals-convergence.md` and `docs/02-vta/task-consent.md`.

---

## 1. The problem

Three VTC verbs are gated on a live passkey gesture:

| verb | gate today | where |
|---|---|---|
| `acl/change-role` to `admin` | `Invariant::StepUpForAdmin` in the role-change ceremony; `step_up` resolved from the caller's live session | `ceremony/invariant.rs`, `ceremony/orchestrate.rs` |
| `acl/grant` of `admin` that widens authority | `elevation::verified` in the handler | `routes/acl.rs`, `acl/elevation.rs` |
| console-key enrolment (`POST /v1/admin/console-keys`) | `AdminAuth` + `elevation::verified` | `routes/admin/console_keys.rs` |

Every one reads the **session**: a passkey step-up stamps `acr = aal2` and
`acr_expires_at = now + 900` on the session row (`routes/auth.rs::step_up_finish`),
and `elevation::verified` checks it. A signed document has no session —
`admin_signer` builds claims with `session_id: ""` — so on the signed door the
check fails closed. That is correct, and it is why these verbs cannot leave
their bearer routes.

`vtc-console-signing.md` §6f proposed the smallest bridge: let the signed arm
read the signing admin's live session for the freshness of a gesture. It is
**not** taken, for three reasons:

- **Which session?** A document names no session. Accepting an elevation on
  *any* of the admin's sessions widens the gate beyond what the bearer route
  checks.
- **§6g's residual risk is exactly this path.** A script holding a console key
  waits for the operator's own step-up and spends the 15-minute window on acts
  the operator never saw.
- **It is the shape the VTA deleted.** "Delegated step-up" produced a session
  elevation, so approving one act admitted every other act for 15 minutes —
  "consent with strictly worse binding" (`approvals-convergence.md`). A session
  elevation reached from a signed door has the same defect.

## 2. Constraints the design must meet

From the specification and the code as merged:

1. **The gate sits before dispatch**, identical on REST, DIDComm and TSP and on
   both doors (VTI-OPS-050, -051). Not a handler flag.
2. **The fact is the host's.** `step_up` is resolved from verifiable state by
   the host, never supplied by a caller or handler (`invariant.rs`,
   `orchestrate.rs`).
3. **The factor is the acting admin's own passkey, with user verification.** A
   console key or any DI proof is possession only and must not become a second
   factor (`vtc-console-signing.md` §6f). A passkey cannot *be* the document's
   proof (§1); its assertion travels as defined payload data, verified by a
   WebAuthn library — never in `ext` (VTI-ACL-005, VTI-OPS-110).
4. **Fresh, subject-bound, single use.** ≥128-bit challenge, bound to its
   subject, expiring, redeemable once (VTI-SES-001–004, -010). The document stays
   under the `issuedAt` window and the shared accepted-id record (VTI-OPS-024–027).
5. **Bound to the exact operation** — type URI and payload, by a
   domain-separated, length-prefixed digest; salted before it leaves the
   process; single-use; state re-asserted at execution. Otherwise one gesture
   admits another act (VTI-APV-004, -005).
6. **Freshness, not authority.** Authority stays the ACL entry read at
   execution; the step-up adds a human gesture to it. Self-promotion refusal,
   the promotion lock and the role-change policy all still apply.

## 3. Operation-bound step-up

### 3a. The flow

```
signer ──(1) signed acl/grant document──────────────▶ VTC gate
       ◀─(2) stepUpRequired {challenge, wireDigest,
                             webauthn options}──────── parks a pending mark
admin passkey
       ──(3) auth/step-up/approve-response
             {challenge, decision: approve,
              boundTo: wireDigest,
              evidence: {kind: webauthn, assertion}}──▶ verifies UV assertion,
       ◀─(4) {status: recorded, boundTo}──────────────  records a one-shot mark
signer ──(5) the same document, re-sent──────────────▶ gate redeems the mark,
                                                        step_up = true, dispatch
```

1. **A signed document arrives** for a gated verb. `admin_signer` resolves the
   acting admin (the signer, or for a console key the delegating admin). The
   gate computes the operation's **payload digest** — the DTTE construction with
   its own domain tag, `vtc/step-up/v1\0 ‖ len(uri) ‖ uri ‖ len(JCS(payload)) ‖
   JCS(payload)`, SHA-256, multibase multihash — and finds no mark for
   `(acting admin, digest)`.
2. **It refuses with `stepUpRequired`** and parks a pending mark: a 256-bit
   challenge, the internal digest, the acting admin's DID, the type URI and an
   expiry — **300 s**, decided: shorter than a session elevation's 900 s, because a mark authorizes one known act and has no reason to wait. The refusal's `details.stepUpRequest` — an inline `approve-request/0.3` payload — carries the challenge, the **wire
   digest** (the payload digest salted with the challenge — all a client ever
   sees, since an unsalted digest over a low-entropy `acl/grant` payload is a
   confirmation oracle) and WebAuthn request options restricted to the acting
   admin's own credentials. The refused document's `id` is released, so the
   identical document can be re-sent.
3. **The admin answers** with `auth/step-up/approve-response` carrying
   `evidence.kind = webauthn` — an unmodified `AuthenticatorAssertionResponse`
   whose `clientDataJSON` challenge equals the step-up challenge — and
   `boundTo = wireDigest`. The VTC verifies it the way `auth/passkey/login/finish`
   does, and additionally requires:
   - the credential is a passkey **registered to the acting admin's DID**;
   - `user_verified()` holds (a silent assertion is refused — the check
     `step_up_finish` makes and `admin/passkeys` does not);
   - the pending mark exists, is unexpired, and its challenge matches.
4. **It answers `status: recorded, boundTo`** and elevates **nothing**: the
   pending mark becomes a redeemable mark, TTL 300 s.
5. **The same document is re-sent.** The gate recomputes the digest, finds the
   mark for `(acting admin, digest)`, **removes it before dispatch** (as
   `consume_grant` does), sets the host fact `step_up = true` for that one
   execution, and re-runs every other check — authority from the ACL row,
   self-promotion, the role-change policy, the promotion lock. A different
   payload has a different digest and finds nothing; the same payload twice
   finds the mark gone.

### 3b. Why this satisfies the constraints

- One gesture authorizes one act, bound by digest (5), and nothing is elevated,
  so §6g's window does not exist.
- The gate is the spine's, before dispatch, so every transport and the bearer
  route converge on one fact (1, 2). The bearer route keeps its session check
  **or** accepts a mark — see 3d.
- The factor is the admin's own UV passkey, carried as defined payload data in a
  published task (3). A console key can **sign** the document and **redeem**
  the mark, but cannot **create** one: that takes the gesture.
- Challenges and marks are single-use, subject-bound and short-lived (4).

### 3c. Console-key enrolment

Enrolment has no Trust Task URI yet (`auth/signing-key/{enroll,list,revoke}` is
proposed upstream), so it has no signed door and keeps its session gate until
that family exists. When it does, it takes the same mark. The rule that a
console key cannot enrol another key survives on its own: the mark is bound to
the enrol payload, and creating it takes the admin's passkey, never the key.

### 3d. The bearer route

Unchanged at first: `elevation::verified` on the session. Once marks exist, the
bearer arm can accept a mark as well, which lets one client flow serve both
doors; the session path is then retired with the route.

## 4. Second-party consent for unrestricted admin (VTI-APV-014)

### 4a. The gap

VTI-APV-014: creating or widening an entry to **unrestricted act scope** MUST
require consent from a party other than the requester. The VTC requires only
the requester's own step-up (and refuses self-promotion). That is a divergence
on both doors, independent of #1641, and VTI-VTC-020/021 say the VTC uses the
approvals model rather than a parallel one.

### 4b. The design

Reuse the VTA's task-consent model rather than invent a VTC one:

- **Trigger:** `acl/grant` or `acl/change-role` whose resulting entry is an
  admin with `ActScope::All` where the prior entry was not — the same
  `widens_admin_authority` predicate, narrowed to the unrestricted case. Scoped
  admin grants keep needing only the step-up.
- **Approvers:** the community's other unrestricted admins, **requester
  excluded** (VTI-APV-007). The threshold is **configurable per community**,
  default 1, minimum 1 — a runtime config key beside the others in
  `config_store`. A threshold the community cannot meet (greater than the
  number of unrestricted admins other than any one requester) is refused when
  it is **written**, not discovered at grant time (VTI-APV-009); and a
  revocation or demotion that would leave the configured threshold unmeetable
  is refused the same way, so the rule cannot become unsatisfiable by
  attrition.
- **Ceremony:** `task-consent/{request,decision,granted}/0.1`, as the VTA runs
  it — payload digest internal, challenge-salted wire digest shown, VTC-signed
  request, DI-signed decision, a grant keyed on `(digest, requester)` removed
  before execution, state re-asserted at consume.
- **Both are required, and they compose:** the requester's operation-bound
  step-up (their gesture) and another admin's consent (their agreement) are
  keyed on the **same payload digest**. The gate dispatches only when both are
  present and consumes both.

### 4c. The bootstrap edge

A community with one unrestricted admin — every community right after install,
since `routes/admin/bootstrap.rs` mints exactly one — has nobody to consent, so
it could never create a second unrestricted admin. Options, for the maintainer:

1. **Scoped first — does not work.** The sole admin can grant a *scoped* admin
   (step-up only), but a scoped admin cannot consent to an unrestricted grant:
   approving an unrestricted entry takes unrestricted approve authority
   (VTI-APV-006). Listed so it is not rediscovered.
2. **Install carries a second admin.** Bootstrap accepts an optional co-admin
   DID, so a community starts with two unrestricted admins.
3. **Offline break-glass.** As the VTA does: an offline `vtc acl …` command,
   daemon stopped, can write the entry. It is not a remote path and cannot be
   reached by a stolen session or key.
4. **Consent is required only once two unrestricted admins exist**, and the
   node records that it ran below the threshold. This is a divergence to
   register, not a design to prefer.

**Decided: 2 + 3** — `vtc setup` and the install bootstrap accept an optional
co-admin DID, so a community can start with two unrestricted admins and
administer remotely from day one; and an offline `vtc acl …` break-glass, daemon
stopped, can write an unrestricted entry for a community that did not. Neither
is reachable by a stolen session or key. Both are audited, and the break-glass
row records that it bypassed consent.

## 5. What has to change upstream first

Nothing here can be dispatched before its wire exists (a new family needs its
upstream spec and a `trust-tasks-rs` bump first).

1. **dtgwg-vti-spec, VTI-APV-003.** Re-authentication is defined as raising the
   *session's* assurance. Amend it so that re-authentication **MAY instead be
   bound to exactly one operation by payload digest**, in which case it elevates
   nothing and is consumed by that operation. That is strictly stronger than the
   session form, and the VTA already runs it for persona disclosures
   (`PendingStepUp.bound_to`, `approve-response/0.3`).
   **Proposed:** trustoverip/dtgwg-vti-spec#40 amends APV-003 to admit the
   operation-bound form and adds VTI-APV-015 with its rules.
2. **dtgwg-trust-tasks-tf, `auth/step-up/approve-response`.** `sessionId` is
   required. Make it optional when `boundTo` is present (a 0.4 if that is not
   additive under the versioning rules), and state that a `boundTo` response
   elevates no session.
   **Done:** trustoverip/dtgwg-trust-tasks-tf#631 — `approve-request/0.3`
   (`sessionId` optional for a bound step-up, a new `boundTo`) and
   `approve-response/0.4` (`sessionId` echoed exactly when the request carried
   one). Reaches this workspace with the next `trust-tasks-rs` release.
3. **A `stepUpRequired` refusal carrying the challenge.** The framework's
   `details` on a `permissionDenied`/`stepUpRequired` refusal needs a published
   shape — `{challenge, wireDigest, webauthn}` — so a client can answer without a
   side channel. Proposed alongside (2).
   **Done, in #631:** `approve-request/0.3` defines *inline delivery* — the
   refusal carries an `approve-request` payload, bound and session-less, in
   `details.stepUpRequest`. The digest travels as its `boundTo`; the WebAuthn
   options are its own `webauthn` member. A producer surfaces an inline request
   only when it is the relying party's own reply to the producer's request.
4. **VTC task-consent.** The three `task-consent/*` tasks are already published;
   the VTC needs only to dispatch them. No spec change.

## 6. Order of work

1. Upstream: (1)–(3) above. **Done** — dtgwg-vti-spec#40,
   dtgwg-trust-tasks-tf#631, released in `trust-tasks-rs` 0.22.7.
2. **Done.** VTC: the digest, the pending and redeemable marks (their own keyspace,
   excluded from backup, swept on TTL), the gate in front of dispatch, and
   `approve-response` dispatched with `webauthn` evidence. Tests: one gesture
   redeems one act; a second, different payload is refused; the same payload
   twice is refused; a console key cannot create a mark; a silent (non-UV)
   assertion is refused; a passkey of another admin is refused.
3. Bind `acl/grant` and `acl/change-role` on the signed door behind that gate.
   **Done.**
4. VTC task-consent for unrestricted admin (§4): the threshold config key with
   its write-time and attrition checks, the co-admin at install, and the
   offline break-glass (§4c). **In progress** (§9):
   1. The shared core moved to `vti_common::task_consent` (#1730). **Done.**
   2. The gate on `acl/grant` and `acl/change-role`, both doors;
      `task-consent/decision/0.1` dispatched; the threshold key with its
      write-time check. **Done.**
   3. Attrition checks, and the paths that confer unrestricted admin without
      reaching the gate: `vtc/admin/invites/create`, and an `acl/grant` rewrite
      that narrows an unrestricted admin (the attrition case). **Done** (§10).
   4. The co-admin at install, and audit rows for the offline writers.
5. Console-key enrolment once `auth/signing-key/*` is published.
6. Retire the bearer routes of the three verbs; close the #1641 entries.

## 7. Decisions (2026-09-24, with the maintainer)

- **Binding:** step-up on a signed document is bound to the one operation by
  payload digest and elevates nothing (§3), not read from a live session.
- **Scope:** this note also carries VTI-APV-014's second-party consent (§4).
- **Bootstrap:** co-admin at install plus offline break-glass (§4c).
- **Mark TTL:** 300 s for both the pending and the redeemable mark (§3a).
- **Consent threshold:** configurable per community, default and minimum 1,
  refused at write time when unmeetable (§4b).

## 8. As built (steps 2 and 3)

- **Code:** `vtc-service/src/acl/bound_step_up.rs` (digest, marks,
  `redeem_or_request`, `approve`, sweep); `trust_tasks::handle_acl_grant` and
  `handle_step_up_approve_response`; `routes::acl::{plan_grant, commit_grant}`,
  which the bearer route and the signed door now share. Keyspace
  `step_up_marks`, excluded from backup, swept by the retention sweeper.
  Audit: `OperationStepUpRecorded` names the task, the salted `boundTo` and
  the credential.
- **Tests:** `vtc-service/tests/signed_step_up.rs` drives the loop with the
  soft authenticator and holds every refusal §6 step 2 lists.
- **Where the gate sits — one difference from §2 item 1.** The gate is not a
  spine step in front of `dispatch_typed`. Whether an `acl/grant` needs a
  gesture depends on the entry it would replace (`widens_admin_authority`),
  and the gesture must not be asked for a grant that another check would
  refuse, so the verb asks the gate after `plan_grant` and before
  `commit_grant`. What §2 item 1 protects still holds: the handler is
  transport-neutral, so REST, DIDComm and TSP reach the same call; the fact
  is the host's (a mark only a verified assertion writes); and the gate is one
  function every gated verb will call.
- **Evidence:** only `webauthn` is accepted. A `didSigned` or absent
  `evidence` is refused `noGate` — a proof is possession of a key, which a
  console key already has.
- **`approve-response/0.4` declares no proof**, so the dispatcher does not
  require one; its gate is the assertion. A console may sign it anyway.
- **WebAuthn challenge = step-up challenge.** webauthn-rs mints the challenge
  when the ceremony starts, and the pending mark is keyed by it, so the
  assertion binds the same nonce the mark does.
- **`acl/change-role`.** A promotion runs the role-change ceremony, whose host
  invariant `StepUpForAdmin` reads a `step_up` fact. The pipeline takes a
  `StepUpSource` — the bearer route's live session, or a gesture bound to the
  operation — and never a boolean from its caller (#1645). On the bound
  source it decides *as if* the gesture were present, and acts on that verdict
  only after spending the mark: the verdict answers "would anything but the
  missing gesture refuse this?", so a promotion the policy or another
  invariant refuses is refused for that reason and asks nobody for a
  passkey. Spend and write both happen under `PROMOTE_LOCK`. `decide` is pure,
  so deciding before the spend has no effect of its own.
- **`AdminPromoted.authorising_session_id`** is empty for a promotion made on
  the signed door, which has no session; the gesture is the
  `OperationStepUpRecorded` row under the same actor.

## 9. As built (step 4.2: the consent gate)

- **Code:** `vtc-service/src/acl/admin_consent.rs` — the trigger
  (`confers_unrestricted`), the approver set, the threshold, `require` (find a
  live consent or raise the request), `gesture_then_consent` (the signed door's
  combined gate), `decide` (a `task-consent/decision/0.1`) and
  `ReadyGrant::spend`. Storage is `vti_common::task_consent`, the same code the
  VTA's gate runs, in its own `task_consent` keyspace: excluded from backup and
  swept by the retention sweeper.
- **Trigger:** the resulting entry is an admin with `ActScope::All`, and the
  entry before it was not a live unrestricted admin. So a new unrestricted
  admin, a scoped admin widened to community-wide, a scopeless member promoted
  by `acl/change-role`, and an expired unrestricted admin granted again all need
  consent. A label edit on a live unrestricted admin, and any scoped admin
  grant, do not.
- **Approvers:** every other live unrestricted admin, requester always
  excluded. The approver set is named `unrestricted-admins` on the wire; there
  is no rule to look it up in, because VTI-APV-014 fixes it.
- **Threshold:** `acl.unrestricted_admin_consent_threshold`
  (`[acl] unrestricted_admin_consent_threshold` in TOML,
  `VTC_ACL_UNRESTRICTED_ADMIN_CONSENT_THRESHOLD`), 1–16, default 1. The gate
  reads it through the config layers on every request, so a runtime patch binds
  the next grant without a `config/reload`. `config/patch` and the config import
  both refuse a value above the number of unrestricted admins less one;
  1 is always accepted, since there is no lower value to choose.
- **Order on the signed door:** satisfiable → gesture → consent → spend both.
  A community with too few possible approvers is refused before any gesture, with
  the break-glass command in the message. The gesture comes before any other
  admin is asked, so a party holding only the requester's signing key cannot
  make their devices ring. A gesture made while the consent is outstanding is
  kept (`bound_step_up::has_mark`); if it lapses before the approvals land it is
  asked for again.
- **Bearer route:** the session's step-up, then the consent. The digest is taken
  over the canonical task payload the body describes; for `acl/change-role` that
  includes the subject from the path.
- **Re-checked when spent:** the approvers must still be unrestricted admins,
  the threshold in force must still be met, and the subject's ACL entry must
  hash to the version the approvers were shown (a `StatePin` over the whole
  entry, label included). A consent that fails any of these is discarded and
  asked for again.
- **Refusal:** `auth:consent_required`, in the VTA gate's shape — `taskFailed`
  with the reason in `details` on the signed door, `403` with the details merged
  into the body on REST — carrying `payloadDigest` (salted), `challenge`,
  `correlator`, `approverSet`, `minApprovals`, `excludeRequester` and the
  VTC-signed `consentRequests` to relay. When the requests would push `details`
  over the framework's 4 KiB bound they are left out and counted
  (`consentRequestsOmitted`), because an oversized `details` is dropped whole.
- **Requests** are VTC-signed, one per approver, each addressed to that
  approver, and pushed over DIDComm when first raised; re-asking returns the
  same challenge and pushes nothing. An approver's device must list the VTC DID
  as a trusted issuer to show them.
- **Audit:** `TaskConsentRecorded` with a `stage` of `requested`, `approved`,
  `declined`, `granted` or `consumed`, under whoever took the step.
- **Not yet:** the granted notice to the requester (`task-consent/granted/0.1`)
  is not sent; a requester re-sends the operation to learn the outcome, as the
  VTA's CLI loop does.
- **Tests:** `vtc-service/tests/unrestricted_admin_consent.rs`.

## 10. As built (step 4.3: attrition and invites)

- **Attrition** (`admin_consent::check_attrition`): a change that ends a live
  unrestricted admin is refused when no other unrestricted admin would remain,
  or when the threshold is above 1 and could no longer be met. It runs on every
  door that can end one: `acl/revoke` (which had no last-admin check at all), a
  demotion (`execute::remint`), a removal from the community (`execute::depart`)
  and an `acl/grant` rewrite that narrows the entry to scoped. Each checks and
  writes under the executor's `LAST_ADMIN_LOCK` (`ceremony::lock_admin_set`), so
  two such changes cannot each pass the check and together strand the community.
- **Why threshold 1 is exempt from the second rule:** the write-time check
  accepts 1 however few admins there are, and attrition matches it. At the
  default a two-admin community can still remove one of them, which is the
  compromised-admin case, and must never be a lockout. Above 1 the threshold has
  to be lowered first, and the refusal names the `config/patch` that does it.
- **The old last-admin guard** counted any admin, so the last unrestricted admin
  could step down behind a scoped one. That left nobody who could ever consent to
  an unrestricted grant. The attrition check refuses it; the old guard is kept for
  what it still protects (no admin of any kind).
- **Invites** (`vtc/admin/invites/create`): an invite that writes a new admin
  entry writes an unrestricted one, so it now costs what that grant costs — an
  unrestricted caller, a live step-up, and another admin's consent bound to the
  invite request. Before this, `AdminAuth` was enough, so a **scoped** admin
  could mint a community-wide one here with no gesture and nobody else asked.
  An invite for a DID that already holds an admin entry writes nothing and is
  unchanged.
- **Console:** the invite form steps up first and, like an unrestricted
  `acl/grant`, turns `auth:consent_required` into an instruction to wait for
  another admin and try again.
