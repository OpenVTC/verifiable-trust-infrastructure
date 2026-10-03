# Role-based administration at the VTC

Status: **implemented** (accepted 2026-10-02, §1 decided with the maintainer;
phases C1–C3 built by 2026-10-03 — see *As built* below). Companion to
`vtc-action-list.md` (approvals) and `vtc-approver-step-up.md` (factors). The
operator guide is `docs/03-vtc/admin-access.md`.

**Phase C1 is implemented**: the capability registry (§4), resource qualifiers
(§5), the built-in roles and the granting bounds (§6.1, §6.3), the generalised
APV-014 trigger (§7, VTI-APV-018), explicit act scope (§8), the §9 migration
(on backup import, and in place at boot for a VTC upgraded over its own
store), and `acl/*/0.2` beside 0.1 (`vtc-service/src/acl/capability.rs`,
`acl/granting.rs`, `acl/delegation.rs`, `acl/migrate.rs`).

**Phase C2 is implemented**: custom roles (§6.2) as records in the `acl`
keyspace, served as `vtc/roles/{define,list,show,delete}/0.1`
(`acl/roles.rs`, `trust_tasks/role_tasks.rs`) — define and delete through the
action list under `vtc.roles.assign` + `vtc.approvals.admin`, the ceiling
bounded by the requester's and every approver's own holdings, an entry naming
an undefined role conferring nothing; approver sets read off approve authority
alone (VTI-ACL-040), so the least-privilege `approver` counts for every act
(`admin_consent::may_approve`); the departed-granter review as an action-list
item (`acl.grants.review`, §6.3), with the sweeper kept as the backstop and an
expired granter now noticed by it; a backup restore's commit parked for the
holders of `vtc.backup.restore` (§7); a subject rolling its own entry to a new
key with `acl/swap-key/0.1` (VTI-CLT-025 – 032), delegations following it; and
`auth/whoami` naming the caller's live capabilities, which the console
navigates by. The operator-write acknowledge items (§2) shipped with the action
list (A2).

**Phase C3 is implemented**: git-ns rights are capabilities on the ACL entry
(VTI-VTC-020, VTI-ACL-035 – 037). Each right is a **resource grant** in the
entry's `resourceGrants` (`acl/resource_grant.rs`) — `git.ns.admin`,
`git.repo.manage` graded `create` / `own` / `maintain`, or `git.commit.sign`,
qualified by `git-ns:<forge>/<owner>` or `git-repo:<forge>/<owner>/<repo-id>`,
each with its own `delegatedBy`, expiry, reason and break-glass mark — and the
separate rights store is gone, migrated at boot and on backup import
(`git_ns/migrate.rs`). Three decisions refine §5 and §9 as written:

- **Resource grants sit beside the administrative role, not in its
  ceiling.** §9 mapped `own` / `maintain` to `repo-manager`, but an entry has
  one administrative role (§11.1) and a git right is held by members with no
  administrative role, external signers and the bridge; and each git grant is
  separately a delegation. So a grant is bounded at write time by the
  granter's own holding at a covering qualifier (VTI-ACL-037, -071), and by the
  fixed rules of `git-ns/right/grant/0.3`, not by a role ceiling. The
  `repo-manager` role is unchanged: a qualified administrative ceiling for
  someone who administers repositories through `acl/*`.
- **Grades narrow `git.repo.manage`.** `own` is the capability in full on one
  repository; `maintain` confers no management (it is what the forge projection
  makes a maintainer); `create` at a namespace confers creation and nothing over
  the repositories already in it. VTI-ACL-035 bounds what a qualified
  capability confers from above, so a grade that confers less is within it —
  and it is what keeps "an implied `repo.create` carries no creator ownership"
  and the owner/maintainer forge roles intact.
- **The bridge and external signers hold an entry of community role
  `application`** (Appendix F's question), created with the first grant and
  removed with the last; never a membership, never signs in, never an elevated
  right. A departed granter's git grants go to review grant by grant
  (`acl.grants.review` with `gitGrants`), and are withdrawn at the deadline —
  the default that kept them in force is gone.

### As built

| PR | What it built |
|---|---|
| #1914 | this note, with `vtc-action-list.md` and `vtc-approver-step-up.md` |
| #1917 | the three stop-gaps of §1 item 3 (removals take a step-up and a third party, threshold lowering is consented, policy is role-gated) |
| #1924 | C1: capabilities, qualifiers, built-in roles, explicit act scope, granting bounds, `acl/*/0.2`, the §9 migration at boot and on import |
| #1925 | single-administrator mode (VTI-APV-022), the §7 exception |
| #1927 | C2: custom roles, approver sets read off approve scope, the departed-granter review as an action, restore consent, `acl/swap-key/0.1`, a capability-driven console |
| #1923 | `cnm`'s per-community identity, rotated with `acl/swap-key` by `cnm community continue` / `rotate` |
| #1929 | console tiles and badges gated per capability |
| #1930 | C3: git-ns rights as resource grants on the entry, the `application` role, the rights-store migration |

Deviations recorded during implementation, beside the three C3 decisions
above:

- **Repository rights sit beside the administrative role.** §9's mapping of
  git rights onto `repo-manager` was not built; every git right is a resource
  grant on its holder's entry, bounded by the granter (VTI-ACL-037, -071) and
  the git rights model's fixed rules, whatever the entry's role (C3, above).
- **Departed-granter review, by kind.** An ACL entry's grants go to review
  when their granter is removed, narrowed so that it no longer covers them, or
  expires (`acl/delegation.rs`). Git grants go to review on the granter's
  **departure only** — when it is no longer a member — never on a narrowing
  (`git_ns/lifecycle.rs::sweep_departures`); `cascade_on_departure` revokes
  them instead. The review item is for the holders who may approve
  `vtc.roles.assign` (not "every `community-admin`", §6.3), and the sweeper
  stays the backstop that withdraws at the deadline.
- **Consent is a SHOULD, waived only by single-administrator mode.**
  VTI-APV-014 and -018 – -020 are SHOULD; the one way this VTC does not apply
  them is VTI-APV-022's host-configured single-administrator mode, judged per
  act from the same approver set (§7). Without the mode, an empty approver set
  refuses before any gesture, as §7 says.
- **Removals keep their cooling-off in single-administrator mode**
  (`vtc-action-list.md` §8.5): the mode waives a consent nobody could give; it
  never lands a reduction of another administrator at once.
- **`vtc.approvals.admin` gates custom roles only.** The approvals rule list
  it is named for (`vtc-action-list.md` §8.3) is not built, and with it none of
  §7's rule-driven rows (vetter grants, repo transfer, `ns.admin` grants as
  N-of-M); those keep the gates they had.
- **Approvals are signed in the console with the wallet** — by the approver's
  own DID, never a console key — with an approver device or passkey as extra
  evidence (`vtc-action-list.md` §6).

Not built: hand-off marker rollover (VTI-ACL-054 – 058; `acl/swap-key` is
VTI-CLT-025 – 032 self-rotation), and a key rotation that moves a VTA-bound
`cnm` identity's VTC and VTA entries together.

---

## 1. Decisions this note records

Agreed on 2026-10-02:

1. **Trust roots.** The host operator and the owner of the VTA that provisioned
   the VTC are **the same party**. `vtc admin emergency-bootstrap` stays. The
   controls below protect a community against its administrators, **not**
   against that party (§2).
2. **Administration is role-based.** Examples: community administrators, repo
   managers, vetting leads who approve other vetters. It is not "admin, plus a
   context label".
3. **The stop-gaps** (`vtc-action-list.md` §8.1):
   - removals and demotions take the requester's step-up;
   - lowering the consent threshold is done **online, as an approval**, like
     every other N-of-M act, not offline;
   - policy changes are gated by role.
4. **Abuse limits and what approvers see:** reasonable defaults, set in
   `vtc-action-list.md` §7a.
5. **Rollout:** net-new. Existing VTCs are reinstalled; only basic migration
   (§9).

## 2. Who sits above the administrators

| Party | Can | Why it is accepted |
|---|---|---|
| **Operator** (host + VTA owner, one party) | run any offline command (`vtc acl add`, `vtc admin invite`, `vtc admin emergency-bootstrap`); read or replace the store; act as the VTC, since its VTA mints and holds the VTC's keys | Somebody has to be able to recover a community whose administrators are all lost. Giving that power to one party, who already holds the keys, adds no new root of trust |
| **Administrators** | what their roles allow, subject to approvals | — |

Since the operator can't be constrained, what they do is made **visible**
instead:

- **Every offline write is surfaced as an action** (VTI-VTC-023; implemented
  in action-list phase A2, `vtc-action-list.md` §8.3b). `AclBreakGlassWritten`
  and `emergency-bootstrap` leave a marker that the daemon audits at its next
  start. It also raises an **acknowledge** item (kind `operator.offlineWrite`)
  for the administrators who held an admin role when the write was made and
  still hold one, and a `Critical` console banner, naming the command, the
  DIDs, the host and the time. The banner can't be dismissed; acknowledging
  (`vtc/admin/actions/acknowledge/0.1`) is audited. Administrators can't undo
  the operator's act, but they can't fail to learn of it.
- `emergency-bootstrap` wipes every admin, so it has nobody to tell at that
  moment. Its item is raised for the new administrators (as is any item whose
  original administrators have all gone) and stays in History.
- Guides and the console say plainly that approvals protect against
  administrators, not the operator.

## 3. Why roles, and what the specification asks for

- **VTI-VTC-020** — "A VTC MUST express its own roles, capabilities, approve
  scope and approval rules using the model defined in the Access Control and
  Authority and the Approvals … chapters, and MUST NOT define a parallel
  model."
- **VTI-ACL-010 / -030 / -031 / -032** — a role is a **ceiling**, never a
  grant. An entry's effective capabilities are the role's ceiling intersected
  with the entry's own set. A grant outside the ceiling is refused when
  written, and an unknown capability is never granted.
- **VTI-ACL-033** — an additive capability, one no role implies, needs
  unrestricted authority to grant.
- **VTI-ACL-040–042** — approve scope is independent of act scope, defaults to
  none, and can't be conferred wider than the granter holds. A least-privilege
  approver (no act, some approve) must be expressible.
- **VTI-ACL-071 / -073** — delegated authority never exceeds the delegator's.
- **VTI-VTC-010** — a VTC creates no contexts. Contexts belong to the VTA's
  tree, so they aren't the tool for limiting a VTC administrator to one area.
- **Appendix F** already records git-ns rights as a second authority model
  (VTI-VTC-020, observed). It proposes resource rights "held beside the entry,
  conferring nothing without a live entry for the same subject, and bounded as
  delegated authority is". §5 is that proposal.

So:

- **Roles are named bundles of capabilities.**
- **Capabilities are the unit of administrative power, optionally qualified by
  a resource.**
- **Approve scope says which capabilities a subject may approve.**

All of it lives on the ACL entry and is enforced in host code, never in Rego.
Policy can only refuse, as it does today.

## 4. Capabilities

A capability is one administrative power. The registry is fixed in code and
grows only by release (VTI-ACL-032).

| Capability | Gates | Authority-conferring? |
|---|---|---|
| `vtc.roles.assign` | granting, changing and removing roles and capabilities on others' entries, bounded by §6 | **yes** |
| `vtc.approvals.admin` | the approvals rule list | **yes** |
| `vtc.policy.admin` | uploading and activating policy, qualified by purpose (§5) | **yes** for `role_change`, `removal`, `join`, `cross_community_roles`, `git_ns` |
| `vtc.config.admin` | `config/patch` / `import` / `reload` / `restart` | yes (the threshold) |
| `vtc.backup.export` | backup export | no |
| `vtc.backup.restore` | backup import | **yes** (it replaces the ACL) |
| `vtc.audit.read` | audit list and verify | no |
| `vtc.did.admin` | `did-management/did/register` | yes |
| `vtc.members.manage` | suspend, remove, purge, change non-administrative role | no |
| `vtc.join.decide` | join review decisions | no |
| `vtc.invitations.manage` | issue and revoke invitations | no |
| `vtc.credentials.issue` / `vtc.credentials.revoke` | endorsements, personhood, status-list flips | no |
| `vtc.vetting.manage` | granting and revoking vetters, auto-grant, vetting-withdrawal review | no |
| `vtc.surface.admin` | profile, branding, website, schemas, endorsement types, join criteria | no |
| `vtc.registry.admin` | registry sync jobs, recognition | no |
| `vtc.sessions.revoke` | revoking others' sessions and console keys (incident response) | no |
| `git.ns.admin` | a git namespace (qualified by namespace) | yes, within the namespace |
| `git.repo.manage` | repository create, adopt, archive, transfer (qualified by namespace or repository) | no |
| `git.commit.sign` | the CI-accepted commit right (qualified) | no |

A capability is **authority-conferring** when holding it lets you create
authority, your own or someone else's. Granting one, or widening one, is an
N-of-M action in every case (§7). This generalises VTI-APV-014: the old trigger
"unrestricted act scope" becomes "the resulting entry holds an
authority-conferring capability it did not hold before".

## 5. Resource qualifiers

Some capabilities apply to a part of the community rather than all of it:

```
git.repo.manage @ git-ns:github.com/acme          # one namespace
git.repo.manage @ git-repo:github.com/acme/r#4211 # one repository, by id
vtc.policy.admin @ policy:join                     # one policy purpose
vtc.vetting.manage @ criterion:age-over-18         # one join criterion
```

- A qualifier names a VTC-owned resource (VTI-VTC-012: admission, membership,
  recognition, publication, and the repositories it governs). It never names a
  VTA context (VTI-VTC-010).
- An unqualified capability covers every resource of its kind.
- A qualified capability covers its resource and the resources inside it: a
  namespace covers its repositories.
- Repository qualifiers name the repository **id**, not its name. That is the
  rule git-ns already follows: a rename moves the right, and a new repository
  with an old name inherits nothing.

## 6. Roles

A role is a ceiling: the capabilities an entry with that role *may* hold. The
entry carries what it *does* hold, and that may be narrower (VTI-ACL-030). An
entry has exactly one administrative role, beside the community role
(`member`, `issuer` …) that its membership already carries. Holding both is
normal: a member can be a repo manager.

### 6.1 Built-in roles

| Role | Ceiling | Approve scope (default) |
|---|---|---|
| `community-admin` | every `vtc.*` capability, `git.ns.admin` (unqualified) | every capability |
| `moderator` | `vtc.members.manage`, `vtc.join.decide`, `vtc.invitations.manage` | the same |
| `vetting-lead` | `vtc.vetting.manage` (optionally qualified by criterion) | `vtc.vetting.manage` at the same qualifier: vetting leads approve other vetting leads and vetter grants |
| `repo-manager` | `git.repo.manage`, `git.ns.admin` (qualified) | the same, at the same qualifier |
| `credential-officer` | `vtc.credentials.issue`, `vtc.credentials.revoke` | the same |
| `auditor` | `vtc.audit.read` | none |
| `approver` | none (act none) | as granted: the least-privilege approver of VTI-ACL-041 |

`community-admin` with its full ceiling is what this document has called an
"unrestricted administrator". APV-014's approver set becomes "every other
`community-admin` holding `vtc.roles.assign`".

### 6.2 Custom roles

A community can define more roles, for example `events-team` =
`vtc.surface.admin` + `vtc.invitations.manage`.

- A custom role is a **record in the ACL model** with a name, a ceiling and an
  approve scope. It is created, changed and deleted only through an N-of-M
  action under `vtc.roles.assign` + `vtc.approvals.admin`. It is not Rego: if
  policy could define authority, hole 3 would return.
- Its ceiling can't name a capability the creating approvers don't hold
  themselves (VTI-ACL-042, -071).
- The `role_definitions.rego` default (today read only by a test) is removed.

### 6.3 Granting

Who may grant what is bounded by the granter's own entry:

- You can grant a capability only if you hold it **and** hold
  `vtc.roles.assign`, at a qualifier at least as wide (VTI-ACL-071). A repo
  manager for `acme` who also holds `vtc.roles.assign @ git-ns:acme` can make
  another repo manager for `acme`, and for nowhere else.
- You can grant approve scope only within your own approve scope (VTI-ACL-042).
- No grant outlives its granter's entry (VTI-ACL-053), and no one grants
  themselves anything (VTI-OPS-050).
- **A grant is a delegation.** When the granter leaves, their grants are listed
  for review in every `community-admin`'s action list, and are withdrawn if
  nobody re-affirms them within the action lifetime. This settles the git-ns
  question Appendix F raises: today's default keeps a departed granter's
  grants in force.

## 7. Approvals that follow from roles

The default approval rules of `vtc-action-list.md` §8.2, restated in role terms:

| Act | Approvers | N |
|---|---|---|
| grant or widen an authority-conferring capability | holders of the same capability at a covering qualifier, requester excluded | `acl.unrestricted_admin_consent_threshold` (≥ 1) |
| remove or narrow an authority-conferring capability, or remove an entry holding one | same, requester **and subject** excluded; two-admin rule as in `vtc-action-list.md` §8.2 | same |
| lower the consent threshold | `community-admin`s, requester excluded | the **current** threshold |
| raise the consent threshold | none: immediate, audited | — |
| change the approvals rule list | `community-admin`s with `vtc.approvals.admin` | the current threshold |
| create, change or delete a custom role | as above | the current threshold |
| activate an authority-purpose policy | holders of `vtc.policy.admin @ policy:<purpose>`, requester excluded | 1, or the rule's value |
| restore a backup | `community-admin`s | the current threshold |
| grant a vetter (`vtc.vetting.manage`) | `vetting-lead`s at a covering qualifier | 1 (rule may raise it) |
| repo transfer / archive, `git.ns.admin` grant | `repo-manager`s at a covering qualifier | 1 (rule may raise it) |

A qualifier-bound approver can only approve actions inside their qualifier.

When nobody else holds an authority-conferring capability at a covering
qualifier, the act is refused before any gesture. A single `repo-manager @ acme`
can't create a second one alone; a `community-admin` can, because their ceiling
covers it. That is VTI-APV-009 applied at raise time, as APV-014 already does.

**Single-administrator mode** (VTI-APV-022, `vtc-action-list.md` §8.5) is the
one exception: on a node configured for it on the host, an empty approver set
— nobody but the requester holds and may approve the stake — waives the
consent instead of refusing, and the requester's operation-bound step-up
authorizes the act, audited at `Critical`. It is judged per act, from the same
approver set: a non-empty set always parks, so a `repo-manager @ acme` beside a
`community-admin` still needs the `community-admin`'s approval for anything the
`community-admin` may approve. Rows 2 (reductions) are unaffected — they
already proceed without a third party where none exists (VTI-APV-019) and keep
their cooling-off.

## 8. Act scope and contexts

VTC entries state act scope explicitly as `all` or `none` (VTI-ACL-020, -021).
They no longer carry context lists, because a VTC creates no contexts
(VTI-VTC-010), and qualifiers (§5) are the VTC's way to narrow. This retires the
empty-list trap for the VTC, and with it the Appendix F divergence on the act
scope encoding, at least for the VTC.

The VTA keeps contexts. They are the right tool there.

## 9. Rollout

Net-new; existing VTCs are reinstalled. Basic migration is limited to what a
backup brings across. The same mapping also runs **in place at boot**, so a VTC
upgraded over its own store locks nobody out: before anything is authorized,
every ACL row in the old shape is mapped (all of them before any is written,
each written as one put), the migration is audited once (`AclMigrated`,
Critical, naming the counts and the context-scoped administrators it left
with no administrative role), and those losses are raised as an `acknowledge`
item for the remaining community administrators (VTI-VTC-023). A second boot
is a no-op. A row that cannot be mapped refuses the boot, naming the DID and
the fix (`vtc acl remove` then `vtc acl add` with the daemon stopped); it is
never dropped. The mapping:

- An unrestricted admin entry becomes `community-admin` with the full ceiling.
- A context-scoped admin entry becomes **no administrative role**. The import
  report lists it for re-grant, and the community role is kept. A label never
  meant anything, so silently mapping it to a role would invent authority.
- `member`, `moderator`, `issuer` keep their community role. `moderator` and
  `issuer` also get the matching administrative role (§6.1), because today's
  matrix gives them exactly those powers.
- Custom roles (`custom:*`) keep their community role and get no administrative
  role.
- git-ns rights become qualified capabilities on the holder's entry:
  `git.ns.admin` and `repo.own` / `maintain` → `repo-manager` at that
  qualifier; `repo.create` → `git.repo.manage` at the namespace. A right held
  by a subject with **no** entry (the bridge) becomes an entry of role
  `application` with `git.commit.sign` qualified. Appendix F's other open
  question is answered: the bridge must have an entry.
- Pending consents, step-up marks and actions are not carried.
- Old consoles and old `cnm` builds are not supported against a new VTC.

## 10. Specification work

**dtgwg-vti-spec:**

1. Appendix C gains the VTC capability registry (§4) and the VTC roles (§6.1).
2. The resource-rights extension Appendix F proposes, as normative text: a
   qualifier on a capability, conferring nothing without a live entry,
   delegation-bounded.
3. Close the git-ns divergence (VTI-VTC-020) once the VTC implements this.
4. "Authority-conferring capability" as the generalised APV-014 trigger.

**dtgwg-trust-tasks-tf:**

- `acl/_shared` and `acl/grant` / `update` / `list` carry `adminRole`,
  `capabilities` (with qualifiers), `approveScope` and explicit `act`.
- Custom roles: `vtc/roles/{define,list,delete}`.

## 11. Settled defaults (2026-10-02)

1. **One administrative role per entry**, plus narrowing. A combination, such
   as repo manager and vetting lead, is a custom role.
2. **A departed granter's grants go to review, then are withdrawn** (§6.3), if
   nobody re-affirms them within the action lifetime.
