# The administrator action list — N-of-M approvals that complete themselves

Status: **accepted** (2026-10-02; §7a, §7b, §8a decided with the maintainer).
**Phase A1 is implemented**: §4–§7 for every consent-gated VTC operation
(VTI-APV-014, VTI-APV-019, VTI-APV-020, VTI-VTC-022), and `task-consent/decision/0.2`
with `webauthn` evidence. **Phase A2 is implemented** (§10): acknowledge items
for operator writes (§8.3b, VTI-VTC-023), the authority-reduced notice and the
two-admin cooling-off (§8.2, VTI-APV-019), `approverSigned` decision evidence
(§6), crash-safe execution, and device pushes off by default. What is still
deferred is listed at the end of §10. It changes how consent is collected and
finished at the VTC, adds wire tasks that need a specification first (§9), and
depends on `vtc-approver-step-up.md` for the approver-signed evidence (§6).

Two deviations from the text below, as built:

- **Execution is serialised by the action's own status transition**, taken
  under a dedicated per-action lock, not by holding `lock_admin_set` across the
  execution (§4.2). The handlers the action re-runs take `lock_admin_set` (and
  the promotion lock) themselves for their write; holding it across them would
  invert the lock order and deadlock. Status leaves `open` before execution
  starts, so the operation still runs at most once.
- **Summary templates are keyed by `(kind, typeUri)`**, not by `kind` alone
  (§7a.2): one kind spans several operations whose payloads differ.

Builds on `vtc-operation-bound-step-up.md` §4 (the APV-014 consent as built,
`vtc-service/src/acl/admin_consent.rs`) and the shared consent store
(`vti_common::task_consent`).

---

## 1. The problem

As built, APV-014 consent is a short synchronous exchange:

1. Admin A sends an operation. The VTC refuses it with `consent_required`,
   keeps a pending request for **15 minutes** (`PENDING_TTL_SECS = 900`), and
   pushes a VTC-signed `task-consent/request` to every other unrestricted
   admin. The push is best-effort, and a copy rides in A's refusal for A to
   relay by hand.
2. An approver answers `task-consent/decision`, signed with their own DID key.
   Today only `cnm consent approve` can do that, and only for a `did:key`.
3. Once the threshold is met, the approval lives **10 minutes**
   (`GRANT_TTL_SECS = 600`), and A must **send the operation again** to have
   it run.

This fails a team that is not online at the same moment:

- **Nothing lists what is waiting.** An approver who signs in later sees
  nothing. The console has no approvals surface, and there is no query for
  "requests addressed to me".
- **The lifetimes assume everyone is online.** If B is away for an afternoon,
  the request lapses and A starts over, coordinating by chat.
- **The requester has to come back.** Approval doesn't finish anything; A must
  be present again within 10 minutes.
- **The console cannot approve.** A decision must be signed by the approver's
  own DID key, and the console holds only a delegated console key, which is
  refused as an approver on purpose.

## 2. What we want

- An **action list**: each admin sees, inside the VTC, the actions waiting for
  them, and the console shows that something is waiting.
- **N-of-M**: an action names who may approve it (M) and how many must (N).
- **It completes itself**: when the N-th approval lands, the VTC runs the
  operation, and the action disappears from everyone else's list.
- **A stated lifetime** for every action, long enough for people who are not
  online together.

## 3. What the specification requires

| Requirement | Effect here |
|---|---|
| VTI-APV-004 | Each approval binds the exact payload digest, is redeemable for that payload only and only once. The executed payload must be the approved one. |
| VTI-APV-005 | Approval never elevates a session; it authorizes this one action. |
| VTI-APV-006 | Every approver holds approve authority over the operation's scope. For APV-014 that means unrestricted admins only. |
| VTI-APV-007 | The requester is excluded where the rule says so (always for APV-014), and one subject counts once. |
| VTI-APV-008 | A request **MUST expire**, and an expired approval is never redeemable. The specification fixes no length, so the VTC chooses one (§5). |
| VTI-APV-009 | A threshold the approver set can't meet is refused when written, and again when an action is raised. |
| VTI-APV-011 / -013 | The approver is shown the operation, the requester, the scope and the effect, rendered from the same bytes that are digested. |
| VTI-APV-015 | The requester's own step-up is bound to the operation and expires (§4.3). |
| VTI-OPS-024–027 | The requester's document is checked for freshness and replay **once, when it is submitted**. Later, the VTC executes its own stored copy, so the document is never accepted twice. |
| `task-consent/decision/0.1` | "`deny` aborts the pending request." The proof on the decision "is the authorization", and the challenge is consumed **at execution**, not on receipt. |

## 4. The model

### 4.1 An action

An **action** is a parked operation waiting for approval:

```
Action {
  id,                       // opaque, 128-bit
  kind,                     // "unrestrictedAdmin" (APV-014); §8 lists others
  type_uri, payload,        // the exact operation, as submitted
  submitted_doc,            // the requester's signed document, verbatim
  requester,                // the acting admin's DID (console keys resolved)
  requester_step_up,        // evidence of the requester's gesture (§4.3)
  approver_set,             // the DIDs eligible when it was raised
  threshold,                // N
  approvals: [{did, at, evidence}],
  per_approver: {did -> challenge},   // salted wire digest per approver
  state_pin,                // version of every entry the operation touches
  status,                   // open | completed | declined | expired | cancelled | failed
  created_at, expires_at,
  closed_at, closed_reason
}
```

Actions live in a new keyspace, `admin_actions`, excluded from backup like
`TASK_CONSENT`: they bind the ACL as it stood on this host. Closed actions are
kept for 30 days for the action-list history, then pruned. The audit trail
keeps every transition regardless.

### 4.2 Lifecycle

```
            submit (step-up ✓, checks ✓)
                     │
                     ▼
   ┌──────────────── open ─────────────────┐
   │   approve (k < N): stays open         │
   │                                       │
   │ deny by any approver  ──▶ declined    │
   │ requester cancels     ──▶ cancelled   │
   │ expires_at passes     ──▶ expired     │
   │ invalidated (§4.4)    ──▶ cancelled   │
   │ N-th approve ──▶ execute ──┬─ ok ───▶ completed
   └────────────────────────────┴─ refused ▶ failed
```

- **Submit.** A sends the operation as today. Every check that does not need
  the approval runs: authority, separation of duties, the role-change policy,
  attrition, a meetable threshold, and A's step-up. Then the VTC **parks** the
  operation as an action and answers `202 accepted, actionId`, not an error.
  It does not ask A to re-send.
- **Approve.** Each approval is recorded against that approver's own challenge.
  A subject counts once. An approval from a DID not in the approver set, or no
  longer an unrestricted admin, is refused.
- **Complete.** The approval that reaches N runs the operation inside the same
  lock that serialises admin-set changes (`lock_admin_set`). The VTC re-runs
  **every** check against the community as it is now: authority, the
  approvers' current standing, the threshold, and the state pin. Only then does
  it write, consume each challenge (as `decision` requires), and close the
  action `completed`. A failed check closes it `failed`, with the reason, and
  nothing is written. The operation runs exactly once. Two approvals arriving
  together cannot both complete it, because the status moves out of `open`
  under the lock.
- **Deny.** One deny closes the action `declined` for everyone. That is the
  specification's rule ("`deny` aborts the pending request"), and it is the
  safe default: any one admin can stop an unrestricted grant.
- **Cancel.** The requester can withdraw their own open action.

### 4.3 The requester's step-up

The step-up proves A was present **when A asked**. The gesture is checked at
submission and recorded on the action as `requester_step_up`. It is not a mark
waiting to be redeemed, so it does not need to outlive the 300-second mark
window. That fits VTI-APV-015 (bound to this operation's digest, used once,
raising no session), but it means the VTC executes on a gesture made hours
earlier. §9.2 asks the specification to say this explicitly, rather than
leaving it to be read permissively.

An organisation that wants A present at completion as well can set the policy
`requireRequesterAtCompletion`. Reaching N then moves the action to `ready` on
A's list, and A finishes it with a fresh step-up. This is off by default.

### 4.4 Invalidation

An open action is cancelled (`closed_reason` saying why) when:

- the requester stops being an admin of the authority the operation needs;
- the state pin changes: someone else edits the subject's entry, so the
  approvers would no longer be approving what they saw;
- the approver set can no longer reach N (admins removed). VTI-APV-009, applied
  to a live action.

An approver who loses unrestricted standing has their approval dropped from the
count, and the action stays open.

## 5. Lifetimes

| Value | Default | Bounds | Set by |
|---|---|---|---|
| `acl.action_lifetime` (open → expired) | **72 h** | 15 min – 14 days | community config (`config/patch`), live |
| per action, at submit | the community value | ≤ the community value | requester, optionally |
| closed history kept | 30 days | — | fixed |
| step-up mark (unchanged) | 300 s | — | fixed |

72 hours covers a weekend for a small team. The cap stops an approval
collected days ago being spent on a community that has since moved on. The
re-checks at completion (§4.2) are what make a long wait safe: a stale action
doesn't run, it fails closed. Changing the community value affects only actions
raised afterwards; an open action keeps the `expires_at` it was raised with.

The 10-minute `GRANT_TTL_SECS` goes away, because there is no longer a gap
between the N-th approval and execution.

## 6. Signing an approval from the console

A `task-consent/decision` is **always signed by the approver's own DID**: its
`assertionMethod` proof is the authorization. A decision signed by a delegated
console key is refused, by design. There is no decision whose proof is anything
else.

| Approver works from | Signs the decision with |
|---|---|
| the console, with the browser wallet | the approver's admin DID, through the wallet's `signTrustTask({asDid})`. The VTA holds that key: the admin `did:key` it minted, or the wallet persona |
| `cnm` (a `did:key`), for an admin without a wallet | the profile's own key (`cnm consent approve --action <actionId>`) |

Evidence is an **additional** factor carried in `decision/0.2`'s `evidence`
member, never a substitute for the proof:

- `webauthn` (built in A1): when the console session has a passkey, the console
  attaches a WebAuthn assertion whose challenge is the UTF-8 bytes of the
  decision's challenge. The VTC verifies it against that approver's registered
  passkeys, with user verification required, as for a step-up.
- `approverSigned` (built in A2): the approver device's statement from
  `vtc-approver-step-up.md` — an `auth/step-up/approver/attest/0.1` with
  purpose `decision`, subject the decision's signer, audience the VTC,
  challenge the decision's challenge, `boundTo` its `payloadDigest`, by a
  step-up approver bound to the signer. (A1 refused it as
  `approverSignedUnsupported`.) The console does not send it yet: the plugin's
  `attestApprover` signs enrolment statements only (§10). `cnm` and other
  clients can.

Without a wallet, the console shows the `cnm consent approve --action
<actionId>` command instead of the buttons.

## 7. The console

### 7.1 Seeing that something is waiting

- **Badge.** A nav item **Actions** with a count of open actions waiting for
  *you*, meaning those where you are an eligible approver and haven't decided.
  It is fetched at sign-in and on every focus of the tab, and polled every 60 s
  while the console is open, using a signed read
  (`vtc/admin/actions/list`). A console key may sign reads.
- **Banner.** After sign-in, if your count is non-zero: "*2 actions are waiting
  for your approval*", with a link to Actions. The banner can be dismissed for
  the session; the badge can't.
- **Tab title.** `(2) VTC console`, so a background tab shows it too.

Delivery outside the console is optional. The existing pushes to approver
devices stay best-effort (and off by default). The action list is the source of
truth, so nothing is lost when a push is.

### 7.2 The Actions page

Three tabs:

- **Waiting for me.** Each card shows what the action does, rendered from the
  same bytes that are digested (APV-013), for example "*Make
  did:webvh:…:carol an unrestricted administrator*". It also shows who asked,
  when, approvals so far (*1 of 2*, with names), and time left (*expires in
  2 d 4 h*). Buttons **Approve** and **Decline** (decline asks for a reason).
  Approve runs the approver's factor (§6) and the card leaves the list.
- **Requested by me.** Your open actions with progress, plus **Cancel**. When
  `requireRequesterAtCompletion` is set, also **Complete**.
- **History.** Closed actions, with outcome, who decided, and why it closed.
  Kept 30 days.

When the N-th approval lands, the action leaves every approver's **Waiting for
me** on their next fetch, and appears as *completed* in History and in the
requester's list.

### 7.3 What the requester sees at submit

Instead of today's red error toast, a success-styled notice: "*Sent for
approval. 2 of 3 unrestricted admins must approve within 72 hours.*" It links to
the action. This also fixes the most confusing part of the current flow, where
a request that worked reads as a failure.

## 7a. Abuse limits and what approvers see

Decided 2026-10-02: reasonable defaults, all community-configurable within
bounds.

### 7a.1 Approval fatigue

A compromised administrator can raise requests until a tired approver clicks
Approve: the MFA-fatigue attack. Every requester already pays a step-up per
action, which bounds the rate to their own gestures. On top of that:

| Limit | Default | Bounds |
|---|---|---|
| open actions per requester | 5 | 1–20 |
| open actions per community | 50 | 10–500 |
| after a decline, the same requester raising the same `kind` against the same subject | refused for 1 h | 0–24 h |
| burst alert: more than 3 actions by one requester in 10 min | `Critical` audit row + banner to every other approver | fixed |
| an approver's own decisions | at most 10 approvals per minute (anti-scripting) | fixed |

Each card in **Waiting for me** shows how many open actions the requester has,
and flags "*raised 4 actions in the last 10 minutes*" when that applies.

### 7a.2 What approvers see: renderers as data

VTI-APV-011/-013: the approver is shown the operation, the requester, its scope
and its effect, derived from the bytes that are digested. Today that would be
rendering code in the console, and again in the plugin, and again in `cnm`.
Three renderers that disagree make the plugin's "check what you approve" step
worthless.

Each action `kind` therefore ships a **summary template** as data, with every
field a JSON Pointer into the digested payload:

```json
{
  "kind": "acl.grant.authority",
  "title": "Give {subject} the {role} role",
  "fields": {
    "subject": {"pointer": "/did", "format": "did"},
    "role":    {"pointer": "/adminRole"},
    "caps":    {"pointer": "/capabilities", "format": "capabilityList"}
  },
  "effect": "They will be able to: {caps}"
}
```

- Templates are published in the action's `list` response, and pinned per
  `kind` by a hash in the VTC build. A list response whose template doesn't
  match its pin is refused by every client.
- Formats are a closed set (`did`, `capabilityList`, `duration`, `datetime`,
  `text`). A `did` format shows both ends of a long DID. A `text` field is
  rendered as text, never as markup.
- Shared test vectors (payload → expected rendered text) run in the VTC, the
  console, the plugin and `cnm`.

## 7b. Stop-gaps that ship before the action list

Decided 2026-10-02 (`vtc-admin-roles.md` §1). These close holes 1–3 using the
consent machinery that exists today. Each is replaced by its action-list rule
once that lands.

1. **Removals and demotions take the requester's step-up.** `acl/revoke`,
   downward `acl/change-role`, narrowing `acl/update` and
   `vtc/members/admin-remove` of an admin go through the bound step-up
   (`bound_step_up::redeem_or_request`). Removing an **unrestricted** admin
   also needs APV-014-style consent from the other unrestricted admins,
   excluding the subject. The two-admin rule applies: with no one else left,
   the requester's step-up is enough, and a `Critical` audit row plus a notice
   to the subject records it. The cooling-off arrives with the action list.
2. **Lowering the consent threshold needs consent, online.** `config/patch`
   and `config/import` lowering `acl.unrestricted_admin_consent_threshold` go
   through `admin_consent::require` with N = the current threshold. Raising
   stays immediate.
3. **Policy is role-gated.** Until roles land, `policy/upsert` and
   `policy/activate` require an unrestricted admin. The authority purposes
   (`role_change`, `removal`, `join`, `cross_community_roles`, `git_ns`) also
   take the step-up and APV-014-style consent. `vtc/members/admin-remove` gains
   the scope-cover check `acl/revoke` already has.

## 8. Every mechanism that could use it

The action list is a general mechanism, and APV-014 is its first producer. A
survey of the VTC's operations (2026-10-02, at `1bb00e1c`) found two kinds of
candidate:

- **Queues.** Something already waits on a human today, but in a queue of its
  own, or in none.
- **Single-admin acts.** One admin can do them alone today, and a second
  approval would be a real protection.

### 8.1 Three holes in today's protections

The survey found three places where one admin can undo the controls in the
admin-access guide. They are the strongest reason to generalise beyond APV-014,
and they hold whether or not the action list is built:

1. **Stripping the other admins.** `acl/revoke`, a downward `acl/change-role`
   and `vtc/members/admin-remove` carry no second gate. The code calls removal
   ungated because "removing authority confers none". One unrestricted admin
   can remove every other admin one at a time; the attrition guard only
   protects the last one. After that, APV-014 has no approvers left.
2. **Lowering the consent threshold.** `config/patch` and `vtc/config/import`
   can set `acl.unrestricted_admin_consent_threshold` back to 1 with no
   consent. The check only refuses a value that can't be met, never one that is
   lower. N-of-M then becomes 1-of-M, and APV-014 is weakened by a single admin.
3. **Policy is open to scoped admins.** `policy/upsert` and `policy/activate`
   accept any admin, scoped ones included. They replace the Rego for role
   change, removal, join, registry, recognition, git-ns, rooms and vetter
   eligibility. The default removal policy refuses removing an admin, but any
   admin can replace it. `vtc/members/admin-remove` also has no scope-cover
   check, so it relies entirely on that editable policy.

Holes 1 and 2 are how a single compromised unrestricted admin defeats
APV-014: remove the others, lower the threshold, and then promote at will.
Hole 3 lets a *scoped* admin start down the same road. The fix is the same
shape for all three: the act needs other admins' agreement, as an action.

### 8.2 The catalogue

**Default** means what ships when this is built. **Policy** means an approvals
rule a community can turn on (§8.3). **Queue** means an existing human decision
that moves into the action list, usually with N = 1.

#### Protecting the admin set (default N-of-M)

| Operation | Today | As an action |
|---|---|---|
| Make or widen an unrestricted admin: `acl/grant`, `acl/update`, `acl/change-role`, `vtc/admin/invites/create` | APV-014, re-send model | **Default.** The first producer (§4) |
| Remove, demote or narrow an unrestricted admin: `acl/revoke`, `acl/change-role` down, `acl/update` narrowing, `vtc/members/admin-remove` | one admin alone; only the last admin protected | **Default.** Approvers are the *other* unrestricted admins, never the subject. Hole 1 |
| Lower `acl.unrestricted_admin_consent_threshold`, by `config/patch` or `vtc/config/import` | one unrestricted admin | **Default.** Raising stays immediate; lowering needs the *current* threshold. Hole 2 |
| `policy/upsert` and `policy/activate` for the purposes that guard authority (`role_change`, `removal`, `join`, `cross_community_roles`, `git_ns`) | any admin, scoped included | **Default** for those purposes. Separately, policy should become unrestricted-admin only. Hole 3 |
| `backup/initiate-import` → `finalize-import` (replaces all state, ACL included) | one unrestricted admin | **Default.** A restore can bring back removed admins or remove current ones |

**Removal when nobody else is left to approve.** With two unrestricted admins,
removing one leaves no approver: the requester is excluded and so is the
subject. The VTC can't tell whether the requester is removing a compromised
co-admin or is the compromised one, and must not make the first impossible.
The code already makes the same call for attrition (threshold 1 is exempt from
the unmeetable rule, so a two-admin community can remove a compromised admin).
So when the approver set excluding requester and subject is empty, a removal
**proceeds** without approval, but it does all of the following:

- it takes the requester's step-up;
- it is delayed by a **cooling-off** period (default 24 h, an action of its own,
  visible to both);
- it notifies the subject;
- it is audited at `Critical`.

During the cooling-off the requester can cancel. The subject cannot block it,
because if the subject is the attacker a veto would protect them; the subject
can only see it coming. If the subject answers by asking to remove the
requester, the earlier request completes first, and the removed admin's own
pending actions are then cancelled (§4.4). So the first to act wins, and that
is stated plainly in both admins' action lists. In every other case the normal
rule applies. A
community that wants to remove that window runs with three or more unrestricted
admins.

#### Irreversible or high-impact (policy)

| Operation | Why it matters |
|---|---|
| `vtc/backup/export` and the chunked export | the whole community's state leaves the host |
| `vtc/members/purge` | erases a member record for good |
| `did-management/did/register` | extends the VTC's own DID log, which only grows |
| `vtc/schemas/accepts/register` / `delete` (join criteria) | switching `admission: review` to `automatic` removes the human join decision |
| `vtc/vetting/vetters/grant`, `vtc/vetting/auto-grant/update` | who may vouch for applicants |
| `vtc/endorsements/revoke`, `vtc/members/personhood/revoke` | a status-list revocation can't be undone |
| `vtc/registry/sync-jobs/discard` | dropping a revoke job can leave a removed member recognised upstream |
| `policy/upsert` / `activate`, all other purposes | community rules |
| `config/restart` | availability |
| git-ns `namespace/unbind`, `namespace/reseat`, `repo/transfer`, `right/grant` of `ns.admin` or `own` | repository control. Its `consent_gate` classes would map onto action rules |

#### Existing queues (move into the action list)

| Queue | Today | As an action |
|---|---|---|
| **git-ns break-glass ratification** (`git-ns/right/ratify`) | takes effect at once; waits for another namespace or community admin to ratify or revoke; announced by notice | Queue item for the other admins: **Ratify** or **Revoke**. It does not expire into acceptance; it stays until someone decides |
| **Join review** (`admission: review` → `vtc/join-requests/decide`) | any one admin, from the join queue, with no step-up | Queue item, N = 1 by default. A community can ask for N > 1 for some criteria |
| **Vetting withdrawal review** (`vtc/vetting/revocations/list`, `NeedsReview`) | an informational list with no decide verb; follow-up is a manual removal | Queue item with **Keep member** or **Start removal** (removal then follows its own rule) |

#### Not candidates

- **Waits on a machine, not a person:** git-ns `namespace/bind` and
  `account/link` pending states, waiting on the forge or member.
- **Not reachable by admins:** rooms. Authority is the room's own owner chain,
  never the VTC ACL.
- **Must stay fast:** incident response. Revoking another admin's console key
  (`auth/signing-key/revoke`), signing someone out (`auth/revoke-session`) and
  revoking an admin invite all *remove* access and must never wait on a quorum.
  They are audited instead. That is the line between these and hole 1: those
  remove a credential, while hole 1 removes a person's *authority*, which is
  what the quorum protects.
- **Day-to-day surface:** profile, branding, website, schemas, endorsement
  types, invitations. Approvals could be offered as policy, but the default is
  no.

### 8.3 One rule list, keyed on Trust Task URI

Rather than each producer hard-coding its approver set, the VTC takes the
VTA's approvals model (VTI-VTC-020: one model, not a parallel one). It keeps
one rule list keyed on the Trust Task type URI (VTI-APV-001), and each rule
says:

```toml
[[approvals]]
task      = "https://trusttasks.org/spec/vtc/backup/export/0.1"
approvers = "unrestricted-admins"   # or a named set
threshold = 1
exclude_requester = true
lifetime  = "24h"                   # ≤ acl.action_lifetime
```

- The **default** rows in §8.2 are built in and can be tightened but never
  removed or loosened below the requirement. APV-014's row is fixed by
  VTI-APV-014.
- Every rule is checked when written: VTI-APV-009 (meetable) and VTI-APV-010
  (report what applies). A rule that has made itself unsatisfiable has a
  removal route that is audited (VTI-APV-012): the offline break-glass, as at
  the VTA.
- **Changing the rule list is itself a default N-of-M action.** Otherwise hole 2
  reappears one level up.

Each producer still declares its `kind`, its renderer (what the approver is
shown, from the digested bytes) and any extra re-checks at completion. The
lifecycle, lifetimes, list and console are shared.

### 8.3a Approver sets come from roles

`vtc-admin-roles.md` §7 restates every default rule in role terms. An approver
set is "the holders of capability C at a qualifier covering the action's
resource, requester excluded". Examples:

- vetting leads approve vetter grants;
- repo managers for a namespace approve repo transfers in it;
- community admins approve what confers authority.

The rule list (§8.3) names capabilities rather than DIDs, so the set follows the
ACL as it changes.

### 8.3b Operator writes are actions too

Built in A2 (§10). Every `AclBreakGlassWritten` and `emergency-bootstrap` raises an
**acknowledge** item in each remaining administrator's list, with a `Critical`
banner until it is acknowledged (`vtc-admin-roles.md` §2). It has no approve or
decline, only acknowledge, and acknowledging is audited.

### 8.4 Order

1. APV-014 (this note §4–7).
2. Holes 1–3 as default rules (§8.2, first table), plus policy upsert and
   activate becoming unrestricted-only. These close real attacks and should
   follow straight after.
3. The existing queues: break-glass ratification, join review, vetting
   withdrawal review.
4. The policy-optional rules, and the rule-list surface (`pnm`-style `vtc
   approvals require …` and a console page).

## 8a. Rollout

Decided 2026-10-02: net-new. Existing VTCs are reinstalled and restored from
backup, with basic migration only (`vtc-admin-roles.md` §9). Pending consents
and step-up marks are not carried. Clients that expect the re-send model (older
consoles and `cnm`) are not supported against a new VTC. No compatibility shim
answers `consent_required` for them.

## 9. Specification changes (upstream first)

### 9.1 dtgwg-trust-tasks-tf

1. **`vtc/admin/actions/list/0.1`** — signed read: the caller's open actions
   (`waitingForMe`, `requestedByMe`), plus `history` with a `since` filter. Each
   item carries the rendered summary, the digest and that approver's challenge,
   so the approver can verify what they are shown.
2. **`vtc/admin/actions/cancel/0.1`** — the requester withdraws an open action.
3. **`task-consent/decision/0.2`** — an optional `actionId` and an optional
   `evidence` member: `webauthn` (an assertion over the approver's challenge)
   and `approverSigned`
   (from `vtc-approver-step-up.md`). Without it the document's proof is the
   authorization, as in 0.1.
4. **The submit response.** A parked operation answers with an `accepted`
   status and `actionId` instead of `consent_required`. This is either a
   framework-level response status or a VTC response shape; the trust-tasks
   maintainers decide which.

### 9.2 dtgwg-vti-spec

1. **VTI-APV-015 clarification:** a gesture made at submission may stand for a
   consent-gated operation executed when its consent completes, provided the
   operation's checks are re-run at execution, and the action expires.
2. **Recommended lifetimes:** the specification leaves VTI-APV-008's lifetime
   open. Note the trade-off (§5) and recommend the re-check at execution
   whenever the lifetime is longer than the original step-up window.

## 10. What changes in code

**Landed in A1.** `vtc-service/src/admin_actions/` (the `admin_actions`
keyspace, lifecycle, invalidation, limits, burst alert, summary templates) and
`vtc-service/src/trust_tasks/action_tasks.rs` (`vtc/admin/actions/{list,show,cancel}/0.1`).
`admin_consent` parks instead of refusing, for every operation in §8.2's first
table except backup restore; the submit answers `trust-task-next-step/0.1`
(HTTP 202, continuation `proceed`, expecting `vtc/admin/actions/show/0.1` with
`{actionId}`). `task-consent/decision/0.2` adds `actionId` and `webauthn`
evidence. The lifetimes and limits of §5 and §7a.1 are community config
(`acl.action_lifetime`, `acl.action_max_open_per_requester`,
`acl.action_max_open`, `acl.action_decline_cooldown`), patchable at runtime.
The console's Actions page, badge, banner and submit notice, and `cnm actions
{list,show}` / `cnm consent {approve,deny} --action`, ship with it.

**Landed in A2.**

1. **Operator writes are acknowledged** (§8.3b, VTI-VTC-023,
   `vtc-admin-roles.md` §2). Every offline access-control write (`vtc acl
   add` / `remove`, `vtc admin invite`, `vtc create-did-key --admin`, `vtc
   admin enrol-approver`, `vtc admin emergency-bootstrap`) is, at the daemon's
   next start, audited as before (`AclBreakGlassWritten` /
   `EmergencyBootstrapInvoked`) **and** raised as an `acknowledge`-category
   action of kind `operator.offlineWrite`, its summary naming the command, the
   DIDs, the host and the time. No approve or decline, no expiry, no threshold.
   Expected acknowledgers: the administrators (any admin role) who held one
   when the write was made, less anyone who has since lost every admin role;
   if none remain — and always for an emergency bootstrap — every
   administrator now. Each acknowledges with the signed
   `vtc/admin/actions/acknowledge/0.1` (audited); when all have, it closes
   `completed` / `acknowledged`. A repeat answers `alreadyAcknowledged`, a
   non-expected caller `notAcknowledgeable`. Markers are cleared only after the
   item is raised, so a crash raises it again, once, under a stable id. The
   console shows a non-dismissable `Critical` banner while the viewer has one
   unacknowledged.
2. **Authority-reduced notice** (VTI-APV-019). After any reduction of an
   admin entry lands — `acl/revoke` (full or scope), downward
   `acl/change-role`, narrowing `acl/update` / `acl/grant` — by consent, after
   a cooling-off, or on a scoped-admin requester's step-up alone, the subject
   gets a VTC-signed `vtc/members/authority-reduced-notice/0.1` (durable push,
   TSP > DIDComm > REST): `code` (`revoked` | `demoted` | `narrowed`),
   `previousRole`, `resultingRole` (absent for `revoked`), `agreement`
   (`consented` | `unopposed`; `unopposed` whenever no third party agreed),
   `reason` when given, `decidedAt`, `decidedBy`. Not sent for
   `vtc/members/admin-remove`, whose removal notice covers it; never both. (An
   ACL-only admin revoked unopposed used to get a removal notice.)
3. **Two-admin cooling-off** (§8.2). With no approver but requester and
   subject, the reduction of an unrestricted admin is parked, after the
   requester's step-up, with no approvers and a cooling-off
   (`acl.removal_cooling_off`, default 86400 s, bounds 0–604800, live; `0`
   restores immediate landing). On the wire it is category `approval` with no
   `threshold` and no `expiresAt`, and `ext["org.openvtc"].coolingOff =
   {landsAt, subject, agreement, againstYou}`. The requester can cancel; the
   subject sees it and a `Critical` banner but cannot block it. The sweeper
   (every minute) lands it when the window ends: audited
   `AuthorityReducedUnopposed` at `Critical`, notice `unopposed`, closed
   `completed` / `thresholdMet` with a closed message saying it landed
   unopposed. A third unrestricted admin appearing invalidates it. First to act
   wins: a counter-request from the subject lands the earlier one immediately,
   is refused saying so, and the subject's own open actions are invalidated.
4. **Pushes off by default.** `task-consent/request/0.1` pushes to approvers'
   devices run only when `acl.consent_request_push` (boolean, default `false`,
   live) is set.
5. **`approverSigned` decision evidence** (§6) is verified and accepted.
6. **Crash-safe execution** (CLAUDE.md R2.1, Remote-First). An approved action is persisted
   `executing`, with an execution id, before its operation runs; the operation
   records its effect at its write (a marker plus an `AdminActionEffect` audit
   row naming action and execution). An action found executing with no live
   execution — at startup or by the sweeper — is reconciled from that
   evidence: `completed` if the effect landed, `failed` if it never wrote. This
   replaces the blind `failed` after 10 minutes.
7. **Approver-step-up leftovers.** `vtc/install/claim/start/0.3` voids the
   install token after five wrong claim codes, answering `invalidToken` each
   time. Every administrator made by a completed action (`acl/grant`,
   `acl/update`, `acl/change-role` to unrestricted admin) is issued a step-up
   approver enrolment invite (`vtc-approver-step-up.md` §6c, §11.4), shown once
   to the requester on the completed action as
   `ext["org.openvtc"].approverInvite` (URL and claim code). An approve-response
   0.6 signed by a console key is refused
   `auth/step-up/approve-response:subjectMismatch` (was `permissionDenied`).
   The console's install page offers claim 0.3 beside the 0.2 passkey claim.

**Still deferred.**

- `requireRequesterAtCompletion` (§4.3, §7.2's **Complete**): not built.
- A "pending" notice to the subject of a cooling-off, outside the console. No
  such notice is specified; it needs an upstream task first. Until then the
  console banner and the action list are how the subject learns.
- Approving from the console with an approver device. The VTC accepts
  `approverSigned`, but the browser plugin has no method that signs a
  `decision`-purpose statement; the console approves with `webauthn` evidence
  only.
- **Upstream schema note.** The published Action schema cannot express a
  threshold of zero. A cooling-off therefore omits `threshold` and `expiresAt`
  and carries `ext["org.openvtc"].coolingOff`; the schema should say how an
  action with no approvers is represented.

The plan as written:

1. `vti_common::task_consent`: the pending record gains the parked operation,
   `status` and the per-approver challenges. The VTA's DTTE keeps its re-send
   model; the VTC's executor completes on approval. (The VTA could adopt this
   later; no change there now.)
2. `vtc-service/src/acl/admin_consent.rs`: `require` parks rather than refuses.
   `decide` executes on the N-th approval through the same paths `acl/grant`,
   `acl/change-role` and admin invites already use, under `lock_admin_set`.
3. A sweeper for `expired`, and invalidation hooks in ACL writes (§4.4).
4. `vtc/admin/actions/{list,cancel}` on the signed-document spine.
5. Console: the Actions page, badge, banner and submit notice, and the approval
   paths in §6 (`cnm` is unchanged).
6. Tests:
   - N-of-M completion with N = 1, 2 and 3;
   - concurrent N-th approvals execute exactly once;
   - deny closes for everyone;
   - expiry;
   - each invalidation in §4.4;
   - a stale action fails closed at completion;
   - a console-key-signed decision is refused.

## 11. Settled defaults (2026-10-02)

1. **One deny ends the action**, as `task-consent/decision` says. "Deny counts
   as abstain" is not offered.
2. **72 hours** default action lifetime, configurable 15 minutes to 14 days.
3. **`requireRequesterAtCompletion` is off**: actions complete themselves.
4. **Two-admin removal:** 24 h cooling-off, and first to act wins (§8.2).
5. **Holes 1–3 close first**, as stop-gaps on today's consent machinery
   (§7b), before the action list ships.
6. **No notifications outside the console** by default. Pushes to approver
   devices stay best-effort and off. E-mail and webhook adapters are later
   work.
