# Role-based administration at the VTC

Status: **accepted direction** (2026-10-02, §1 decided with the maintainer); the details below are proposed. Companion to
`vtc-action-list.md` (approvals) and `vtc-approver-step-up.md` (factors).
Nothing here is implemented. The wire shapes it needs go upstream first (§10).

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

## 8. Act scope and contexts

VTC entries state act scope explicitly as `all` or `none` (VTI-ACL-020, -021).
They no longer carry context lists, because a VTC creates no contexts
(VTI-VTC-010), and qualifiers (§5) are the VTC's way to narrow. This retires the
empty-list trap for the VTC, and with it the Appendix F divergence on the act
scope encoding, at least for the VTC.

The VTA keeps contexts. They are the right tool there.

## 9. Rollout

Net-new; existing VTCs are reinstalled. Basic migration is limited to what a
backup brings across:

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
