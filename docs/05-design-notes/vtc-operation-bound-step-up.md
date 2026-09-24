# Step-up on a signed document, bound to the operation — and second-party consent for unrestricted admin

Status: **accepted, not yet implemented** (§7 lists the decisions). Decided with the maintainer on 2026-09-24: the step-up a
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
   expiry — **300 s**, decided: shorter than a session elevation's 900 s, because a mark authorizes one known act and has no reason to wait. The refusal's `details` carry the challenge, the **wire
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
2. **dtgwg-trust-tasks-tf, `auth/step-up/approve-response`.** `sessionId` is
   required. Make it optional when `boundTo` is present (a 0.4 if that is not
   additive under the versioning rules), and state that a `boundTo` response
   elevates no session.
3. **A `stepUpRequired` refusal carrying the challenge.** The framework's
   `details` on a `permissionDenied`/`stepUpRequired` refusal needs a published
   shape — `{challenge, wireDigest, webauthn}` — so a client can answer without a
   side channel. Proposed alongside (2).
4. **VTC task-consent.** The three `task-consent/*` tasks are already published;
   the VTC needs only to dispatch them. No spec change.

## 6. Order of work

1. Upstream: (1)–(3) above.
2. VTC: the digest, the pending and redeemable marks (their own keyspace,
   excluded from backup, swept on TTL), the gate in front of dispatch, and
   `approve-response` dispatched with `webauthn` evidence. Tests: one gesture
   redeems one act; a second, different payload is refused; the same payload
   twice is refused; a console key cannot create a mark; a silent (non-UV)
   assertion is refused; a passkey of another admin is refused.
3. Bind `acl/grant` and `acl/change-role` on the signed door behind that gate.
4. VTC task-consent for unrestricted admin (§4): the threshold config key with
   its write-time and attrition checks, the co-admin at install, and the
   offline break-glass (§4c).
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
