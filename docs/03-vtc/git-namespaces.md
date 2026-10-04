# Git namespaces

A VTC can govern repositories on the forges its community uses — GitHub, a
Forgejo instance such as Codeberg — and publish who may do what there to its
Trust Registry, where CI checks such as `did-git-sign verify-trust` read it.

- **Normative:** the `git-ns/*` Trust Tasks in dtgwg-trust-tasks-tf
  (`specs/git-ns/**`). The rights model is in `git-ns/right/grant/0.3`.
- **Design:** `design-docs/vtc-git-namespaces-design.md`.
- **Code:** `vtc-service/src/git_ns/`.

## The model in one screen

A **namespace** binds the VTC to one owner on one forge: `github.com/acme`.
Inside it, **rights** are held by DIDs on forge-qualified, lowercase resources:

| Right | On | Holder may |
|---|---|---|
| `git.ns.admin` | `github.com/acme` | everything below, on every repository; adopt; unbind |
| `git.repo.create` | `github.com/acme` | create a repository, becoming its owner |
| `git.repo.own` | `github.com/acme/widgets` | grant/revoke `own`, `maintain`, `commit.sign` there; transfer; archive |
| `git.repo.maintain` | `github.com/acme/widgets` | merge and triage on the forge |
| `git.commit.sign` | a repository or a namespace | author commits the CI check accepts |

`own` implies `maintain` implies `commit.sign`; `ns.admin` implies
`repo.create` and `own` everywhere in its namespace. Implication is evaluated
by the VTC and is never a record — except that, because verifiers ask only
about `git.commit.sign`, the implied commit right of every `own`,
`maintain` and `ns.admin` is published explicitly.

A namespace admin gets **no role on the forge** — not organisation owner, no
repository role. `ns.admin` is exercised through the VTC and the bridge (bind,
adopt, reseat, grants); making someone an organisation owner is left to the
community, outside the VTC. The bridge projects only rights held in a
person's own name: each repository's `desiredRoles` carries, per linked
account and once per account, the highest `own`, `maintain` or `commit.sign`
recorded for them on that repository (or `commit.sign` on its namespace). An
admin with none of those there is sent as `git.ns.admin`, which the bridge
maps to no role — so it takes off a stale role it manages rather than leave
it — and an admin who is also an explicit owner is sent as the owner. There
is no namespace-level `projectRoles` job.

The **fixed rules** are code, not policy: containment by whole segment (a
right never crosses forges, and `acme` does not contain `acme-labs`), no
escalation, `repo.create` not re-delegable, a repository keeps an owner, a
namespace keeps an admin, and namespace rights go to current members only. The
community's `gitNamespace` policy is evaluated after them and can only refuse.

### Rights are capabilities on the ACL entry

There is one authority model (VTI-VTC-020). Every right is a **resource
grant** on its holder's own ACL entry — a capability qualified by the
namespace or by the repository's **id** (VTI-ACL-035), with its own granter
(`delegatedBy`), time, expiry, reason and any break-glass mark
(`vtc-service/src/acl/resource_grant.rs`). There is no separate rights store:
the `git-ns/*` tasks read and write the entries, and `VtcAclEntry::can`
answers the same question for the console, `acl/list`'s capability filter and
the approver sets.

| Right | Capability | Qualifier | Grade |
|---|---|---|---|
| `git.ns.admin` | `git.ns.admin` | `git-ns:github.com/acme` | — |
| `git.repo.create` | `git.repo.manage` | `git-ns:github.com/acme` | `create` |
| `git.repo.own` | `git.repo.manage` | `git-repo:github.com/acme/<repo-id>` | `own` |
| `git.repo.maintain` | `git.repo.manage` | `git-repo:github.com/acme/<repo-id>` | `maintain` |
| `git.commit.sign` | `git.commit.sign` | either | — |

A **grade** narrows `git.repo.manage`: `own` is the capability in full on one
repository (a repository manager for it), `maintain` is the maintainer's
share — what the forge projection makes a maintainer, conferring no
management — and `create` is creation in the namespace, conferring nothing
over the repositories already in it. That is what keeps owner and maintainer
apart for the forge roles and the fixed rules, and keeps the invariant that an
implied `repo.create` carries no creator ownership. Implication is the rights
model's: `git.ns.admin` at a namespace holds `git.repo.manage` and
`git.commit.sign` throughout it. `acl/show` and `acl/list` (0.2) render an
entry's grants in `ext["org.openvtc"].resourceGrants` — never their reasons —
and `whoami` lists them as `git.repo.manage@git-repo:…` (a maintainer's or
creator's as `git.repo.manage/maintain@…`, so a display never reads one as the
capability in full).

- **A grant is bounded by the granter's own entry** (VTI-ACL-037,
  VTI-ACL-071): after the fixed rules pass, the granter's live entry must hold
  the capability at a covering qualifier, or the grant is refused as an
  `escalation`. The rules decide which holdings carry grant authority; this is
  the floor under them.
- **No grant without a live entry.** A grant on an expired entry confers
  nothing, and removing an entry removes its grants. The lifecycle sweep then
  records each as revoked and orphans what the subject owned alone.
- **A subject that is no member** — the bridge's service grant, an external
  signer a community's policy admits — holds its (never elevated) grants on an
  entry of the community role **`application`**, created with the first grant
  and removed with the last. It is never a membership: it cannot sign in, never
  counts as a member, and never receives an elevated right. A subject with an
  `application` entry who joins becomes a member on the same entry, keeping
  its grants. No caller can assign the role.
- **The community-administrator capability is `git.ns.admin` held
  community-wide** — a `community-admin`'s. It binds, reseats a headless
  namespace and ratifies; it is not a namespace administrator's grant
  authority, which is a qualified `git.ns.admin` grant.
- **An ACL write keeps the grants.** `acl/*` writes a role, act scope and
  capabilities; it never adds or drops a resource grant, which only `git-ns/*`
  writes. A key rotation (`acl/swap-key`, `vtc/members/rotate`) moves the grants
  with the entry, and the grants its subject delegated name the new key.

**Upgrading.** A store from before this change keeps its rights in
`rights:*` rows of the `git_ns` keyspace. At boot, after the ACL's own
migration, and right after a backup import, each is moved onto its holder's
entry (`git_ns::migrate`), audited once (`gitNs.rights.migrated`), and the
row removed — the store is removed, not kept read-only, so nothing can read a
second model. A right that maps onto nothing that would confer it — an
elevated right held by a DID with no member entry, a right on a namespace or
repository with no record — is kept inert under `rights-unmapped:*` and raised
as an acknowledge item for the community administrators, never dropped or
granted. A second run does nothing.

## Configuration

```toml
[git_ns]
# Which bridge serves which forge. A bridge-mode bind on a forge with no entry
# is refused with `git-ns/namespace/bind:noBridge`.
bridges = { "github.com" = "did:webvh:…:bridge.acme-vtc.example" }

# The consent-class fallback (below). Default true.
elevated_requires_admin = true

# Projector cadence in seconds. Default 5.
tick_seconds = 5
```

With no `[git_ns]` section a VTC serves manual-mode namespaces only.

### Consent classes, and why elevated actions need an administrator

The design classes grants of `own` and `repo.create`, transfer, archive and
adopt as **elevated** (step-up), and bind, unbind and grants of `ns.admin` as
**destructive** (step-up and confirmation). This VTC has no step-up a member
can perform on a signed Trust Task — its step-up is a passkey elevation on an
administrator's session, and a signed document has no session. Until a member
step-up exists, `elevated_requires_admin = true` accepts an elevated or
destructive git-namespace action only from a community administrator (an
entry holding `git.ns.admin` community-wide, as a `community-admin` does), *in
addition to* the rights model's own entitlement. It narrows; it never lets an
administrator do something their git rights do not allow.

What that means in practice, under the default: an owner **cannot** transfer
ownership, give up their own ownership, archive, or name a co-owner without a
community administrator doing it; nor can a namespace admin who is not one
grant `repo.create`, `own` or `ns.admin`. Creating a repository, finishing
one's own manual reservation with `adopt`, and granting or revoking
`maintain` and `commit.sign` are normal-class and need no administrator.

## Policy

`PolicyPurpose::GitNamespace`, wire name `gitNamespace`, package
`vtc.git_namespace`, managed with the usual policy upload / test / activate
flow. The shipped default (`policies/default/git_ns.rego`) is members-only
with no external signers.

The policy's `input` carries the action, the actor and subject (DID, whether a
member, community role, git rights on the resource), the right, the resource,
the forge, the visibility and expiry where relevant, and what the namespace
can do (`capabilities`). It answers `decision` (`allow`, or `deny` with a
`code` and `reason`) and may answer `settings`:

| Setting | Default | Effect |
|---|---|---|
| `maintainer_grants_commit` | `false` | a maintainer may grant `git.commit.sign` on their repository |
| `cascade_on_departure` | `false` | grants a departed member issued are revoked with them, instead of going to review (re-affirmed, or withdrawn at the deadline) |
| `role_drift` | `"report"` | `"enforce"` re-projects forge roles changed outside the VTC |
| `pr_open`, `pr_open_overrides`, `pr_exempt`, `pr_close_message`, `pr_join_hint` | `"anyone"`, `{}`, `["dependabot[bot]"]`, built in, derived | the pull-request gate — see [The pull-request gate](#the-pull-request-gate) |

## What is published

For every live right in a bound namespace, on an active, orphaned or archived
repository, one TRQP authorization record, written with
`registry/record/put` under the VTC's own authority:

```json
{
  "entity_id": "did:…:bob", "authority_id": "did:…:vtc",
  "action": "git.commit.sign", "resource": "github.com/acme/widgets",
  "record_type": "authorization", "authorized": true,
  "context": {
    "framework": "https://trusttasks.org/spec/git-ns/right/grant/0.1",
    "activeFrom": "…", "activeTo": "…",
    "impliedBy": "git.repo.own"
  }
}
```

Who granted a right and why stay inside the VTC: neither `grantedBy` nor a
grant's `reason` is ever published. The projector deletes what should no
longer be published before it publishes anything new, and after a rename it
publishes nothing for the new name until the old name's records are gone; a
repository cannot be created or adopted at a name whose previous records are
still being withdrawn. The mirror of what is published is `git_ns_projection`
(not backed up). At start and every 15 minutes the projector reads back what
the registry holds under this authority for the five git actions, rebuilds
the mirror from it for every resource inside a bound namespace, and
reconciles — so a restore, a registry reset or a lost write converges.

The v0.1 `[hooks.git-trust] grant_on_role` grants keep working through the
hook relay, except where the configured resource lies inside a bound
namespace: those are published by this projection as a second source (origin
`roleDerived`), the relay leaves them alone, and the boot log warns of each
such overlap. A key is withdrawn only when no source wants it. The admin
surface lists them as `roleDerived`; they are managed only through
configuration. When the namespace is unbound they go back to the relay at
once: the unbind queues a relay grant for each, and the projector drops them
from its mirror without withdrawing them, so no member loses a v0.1 right
while waiting for their next membership event.

### While its holder is suspended

An administrator whose removal is cooling off is **suspended** until it lands
or is cancelled (`docs/05-design-notes/vtc-action-list.md` §8.2): the entry
authorizes nothing, and every git-ns operation it signs is refused. The
projection treats it the same way — a suspended holder is projected as
holding **nothing**:

- its records are withdrawn from the Trust Registry, the implied
  `git.commit.sign` of every `own`, `maintain` and `ns.admin` among them, and
  any role-derived grant this projection publishes for it — so the
  community's commit check stops passing its commits;
- its linked accounts leave every repository's `desiredRoles`, so the bridge
  takes off the forge roles it gave them, as for an unlinked account;
- a repository created meanwhile gives it no role, and a drift revert never
  re-sends one.

Nothing is deleted: every right stays recorded on its entry, and the rows the
grant, revoke and sweep paths read and write still hold it. The projection
reads the records through its own view (`projection::ProjectionView`), which
leaves a suspended holder's rows out and cannot be written back. Cancelling
the cooling-off lifts the suspension, and the next pass publishes again —
from the stored rights — exactly what they still give; a removal that lands
takes the rights with the entry, and nothing already withdrawn is withdrawn
twice.

The view is a function of the stored rights and the suspension markers alone,
recomputed by every projector pass (the first one at start included), so a
crash between the marker and the withdrawal — or between lifting it and
republishing — converges on the next pass. Role jobs go through the job queue
and are retried until the bridge answers. Each change is audited as a
`GitNsOperation` naming the subject and the action:
`gitNs.projection.withheld` when a holder of git rights is suspended, then
`gitNs.projection.restored` (cancelled, rights republished) or
`gitNs.projection.released` (landed, nothing left to publish).
`git-ns/projection/show` counts a suspended holder's outstanding withdrawals
among its `pendingChanges`.

Rights published by the v0.1 hook relay outside every bound namespace are not
the projection's, and are not withheld.

## Membership

A member who leaves loses every git right. A repository they owned alone
becomes `orphaned` — governed by the namespace admins — until one of them
names an owner. Their linked forge accounts are removed.

A grant is a delegation (`vtc-admin-roles.md` §6.3, VTI-ACL-071), so the
grants a departed member **issued** go to review: each stays in force, marked
with a review (`{granter, deadline}`), and one `acl.grants.review` item in the
action list — its payload's `gitGrants` naming each subject, right and
resource — asks the community administrators to decide. Approving re-affirms
each grant under an approver whose own entry covers it, who becomes its
granter; declining withdraws them at once; a grant nobody re-affirms by the
deadline (the action lifetime, `acl.action_lifetime`) is withdrawn by the
lifecycle sweep, audited `gitNs.right.revoked` with detail `granterDeparted`.
Grants with no granter to depart are never reviewed: a binding's first admin,
a creator's own ownership, a break-glass (each granted by its own subject) and
the bridge's service grant (granted by the community). A policy setting
`cascade_on_departure` still revokes them at once instead. They are also listed
under *issued by departed members* (`git-ns/right/issued-by-departed/0.1`).
Only the granter's **departure** raises a review: narrowing a granter's entry
leaves the git grants they issued in force (an ACL entry's own grants, by
contrast, also go to review when their granter is narrowed or expires —
[`admin-access.md`](admin-access.md) §1.2).

## The bridge

In bridge mode the VTC never talks to the forge. It sends
`git-ns/bridge/job` documents to the bridge over TSP or DIDComm (whichever
both DID documents advertise), signed with the community's key, and accepts
`git-ns/bridge/result` and `git-ns/bridge/event` only from the bridge the
namespace records. When a bridge-mode namespace becomes bound, the community
grants that bridge `git.commit.sign` on the namespace — a *service grant*,
`grantedBy` the VTC's own DID — because the bridge re-signs Dependabot pull
requests with its own DID. The shipped policy admits exactly this grant
(`bridge.serviceGrant`) and nothing else for a non-member; unbinding revokes
it with everything else. The grant sits on the bridge's own ACL entry, of the
community role `application` — a bridge holds a capability like anyone else,
on an entry (VTI-ACL-070) — but the bridge is still authenticated exactly as
before: its results and events are accepted because the namespace records its
DID, not because of the entry.

A bridge speaks only for the namespace it serves: every resource an event
names must be a repository inside that namespace, and repositories are
matched by forge id before name. A repository renamed within the namespace
keeps its rights. A repository **transferred** out of it — to another owner,
another forge, or even another namespace this VTC has bound — is detached and
its rights withdrawn; rights never move with it, because the destination's
admins granted none of them. A new repository reported at a name the VTC
records under another forge id detaches the old one first. An event any of
whose resources — its drift items' included — lies outside the namespace is
refused whole, before anything is applied; a transfer's `to` alone is exempt,
recorded as where the repository went. This is `git-ns/bridge/event/0.2`
([trust-tasks #627](https://github.com/trustoverip/dtgwg-trust-tasks-tf/pull/627)).
The VTC serves 0.1, 0.2, 0.3 and 0.4 — 0.3 only adds `roleMapReported`
(below), 0.4 only `pullRequestOpened` ([The pull-request
gate](#the-pull-request-gate)) — and applies 0.2's rules to all four. Serving
0.4 is what lists it in the VTC's `trust-task-discovery` answer, which is how a
bridge learns it may report pull requests here.

### The bridge's role map, and re-projecting roles

Which forge role `own`, `maintain` and `commit.sign` get is the bridge's
**role map**, configurable per bridge, forge, namespace and repository; a
namespace admin gets no forge role under any map. The bridge reports the map
it applies — as the forge applies it, rounded onto the forge's ladder — with
`git-ns/bridge/event/0.3` `roleMapReported`, whenever it starts serving a
namespace, whenever it (re)establishes its link to the VTC, and whenever the
map changes: the namespace's map, each repository
whose own map differs, and each repository whose roles it last projected
under a different map (`stale`), with the forge's `ladder` for the namespace.
The VTC refuses an unordered map (`own ≥ maintain ≥ commit`,
`commit ≤ write`), a map with a role that is not on the ladder, a ladder
that is not the one it knows for the namespace (a GitHub organisation, a
GitHub personal account — `write` only — or Codeberg's Forgejo), and any
resource outside the namespace. Reports are ordered by `issuedAt`: one issued
before the report held from the same bridge is acknowledged and ignored. The
VTC keeps the report on the namespace, only while the same bridge serves it,
drops from `stale` any repository it does not record active or orphaned,
and uses the map for the console's effective forge role of each right, for
the right a drift adoption records, for the weight of a drift revert, and
for whether a right is elevated (a right the map projects to `admin` is).

**No map is assumed.** Until the bridge serving the namespace reports —
after binding, after another bridge DID comes to serve it, or for good with a
bridge older than event 0.3 — the map is *unknown*, shown as such on the
namespace card (`roleMapSource: "unknown"`, no `roleMap`). Meanwhile drift
adoption is refused with `git-ns:roleMapUnknown`, every role revert weighs as
revoking `own`, and `git.repo.maintain` counts as elevated. The default map
(`admin` / `maintain` / none; `write` / `write` / none on a personal account)
holds only when the bridge reports it.

A role map change reaches a repository only when its roles are next
projected. The VTC therefore **re-projects every stale repository by itself**
on receiving the report — it forgets the digest of what it last sent, so the
projector sends the complete `desiredRoles` again — and a repository leaves
`stale` when a `projectRoles` job queued after the report succeeds.
Re-projecting changes no right: the bridge would apply the map at the next
projection anyway. To re-project on demand — a bridge too old to report, a
forge suspected of drifting — a community administrator or a namespace admin
(by explicit record) sends `git-ns/roles/reproject/0.1` for a namespace or
one repository, and a repository's owner (`git.repo.own`, explicit or
implied) for that repository:

```sh
cnm git reproject github.com/acme --reason "maintainers now get admin"
cnm git reproject github.com/acme/widgets
```

It is normal-class, audited as `gitNs.roles.reprojected`, and refused in
manual mode (`manualMode`) and while the bridge has lost its access
(`noForgeAccess`). The shipped policy evaluates it as `roles.reproject`.

Every job goes out as `git-ns/bridge/job/0.5` to a bridge that lists 0.5
when asked with `trust-task-discovery`, and as `git-ns/bridge/job/0.4`
([trust-tasks #635](https://github.com/trustoverip/dtgwg-trust-tasks-tf/pull/635))
to one that lists only 0.4 (asked again hourly, so an upgrade is noticed). 0.5
is 0.4 plus `closePullRequest`, with the same meaning for every other kind, so
a 0.4-only bridge is unaffected; `closePullRequest` goes to no bridge without
0.5. A bridge that lists neither is sent nothing: in-line jobs (binding,
account links, a `roleAdded` revert) are refused with "upgrade the bridge",
and queued jobs wait with that as their last error. A bridge before 0.4 would
read a `git.ns.admin` entry as ownership, which is why there is no downgrade.

Jobs are queued in `git_ns_jobs`; role projection retries
forever, everything else within a budget. `GET /v1/git-ns/jobs` shows them.

## The pull-request gate

On GitHub and Forgejo anyone who can read a public repository can open a pull
request against it, and the forge offers no way to restrict that. A community
can: its bridge reports every pull request opened, or closed-and-reopened, on
a governed repository (`git-ns/bridge/event/0.4` `pullRequestOpened`), the VTC
decides whether its author may open one there, and when not, sends the bridge a
`closePullRequest` job (`git-ns/bridge/job/0.5`), which posts the community's
message on the pull request and closes it — reported as the steps `comment`
then `close`. The specification is
[trust-tasks #723](https://github.com/trustoverip/dtgwg-trust-tasks-tf/pull/723).

**This is hygiene, not the merge gate.** The required commit-trust check that
bootstrapping installs (`requiredCheck`) is still what keeps untrusted commits
out of a governed repository, and nothing here weakens it. The gate fails
open: if the VTC or the bridge is down, if the bridge does not take job 0.5,
or if a setting cannot be read, the pull request stays open — and nothing the
required check refuses can be merged through it. A pull request the gate left
open is not "approved" by anything.

### Settings

Read from the active `gitNamespace` policy's `settings`, like the other
settings above (community-wide, with per-namespace and per-repository levels
through `pr_open_overrides`):

| Setting | Default | Effect |
|---|---|---|
| `pr_open` | `"anyone"` | who may open a pull request: `"anyone"` (no gate), `"members"`, `"committers"`, `"maintainers"`, or `{"roles": ["moderator", "custom:reviewer"]}` |
| `pr_open_overrides` | `{}` | `{"github.com/acme": "members", "github.com/acme/docs": "anyone"}` — a repository's entry wins over its namespace's, which wins over `pr_open` |
| `pr_exempt` | `["dependabot[bot]"]` | forge logins always allowed (compared case-insensitively) |
| `pr_close_message` | built in | the Markdown posted before closing, with `{author}`, `{repo}`, `{community}` and `{join_hint}` |
| `pr_join_hint` | derived | the sentence `{join_hint}` renders to; it may use `{community}` and `{repo}`. Absent, it names the community profile's public URL if there is one, and asks the author to link a forge account to their membership |

A value the VTC cannot read is logged and replaced by that key's default — for
`pr_open`, `"anyone"`. The shipped default policy sets `pr_open: "anyone"`, so
installing this changes nothing until a community opts in:

```rego
settings := {
	# … the other settings …
	"pr_open": "committers",
	"pr_open_overrides": {"github.com/acme/website": "anyone"},
	"pr_exempt": ["dependabot[bot]", "renovate[bot]"],
	"pr_close_message": "Thanks, {author}! **{repo}** takes pull requests from {community}'s committers only, so this one was closed automatically.\n\n{join_hint}",
}
```

### Who is allowed

A pull request on a repository the VTC does not record as `active` in a
bridge-mode namespace is ignored, as is every pull request under `"anyone"`.
Otherwise the author's forge account is matched — by forge and account id,
never by login — through account links ([Linking a forge
account](#linking-a-forge-account)) to a member, and:

| Level | Allowed when the author's linked account belongs to |
|---|---|
| `members` | a current member |
| `committers` | a holder of `git.commit.sign` on the repository, explicit or implied (a namespace-wide grant, `maintain`, `own`, a namespace admin) |
| `maintainers` | a holder of `git.repo.maintain` or higher, explicit or implied |
| `roles` | a current member whose VTC ACL role is listed |

Whatever the level, these are **always allowed**: an owner or maintainer of
the repository (explicit or implied, so a namespace admin), the bridge's own
app account (`<slug>[bot]`, once the bridge has reported its app), and a login
in `pr_exempt`. An account linked to nobody is allowed only under `"anyone"`.
`pr_exempt` matches logins, which a forge can reassign after a rename; use it
for bot accounts (`[bot]` logins are reserved on GitHub), not people.

**Reopening.** When an owner or maintainer of the repository (or the bridge)
reopens a pull request the gate closed, that is an **override**: the VTC
leaves it open and does not close it again in answer to that reopen. A reopen
by anyone else — the author included — is checked again exactly as an opening
is: it neither overrides the earlier close nor is refused for being a reopen.
The bridge also declines a queued close of a pull request reopened after the
job was issued.

### The message

The message is public once posted, so it carries only the four placeholders:
the author's forge login (which the forge already shows; a value that is not
a plausible login renders as "there"), the repository as `owner/name`, the
community's name and the join hint. No DID, membership state, role or reason
from the VTC's records can be rendered into it. It is capped at 16384
characters.

### What is recorded

Only the closes. Each close the VTC orders is a `closePullRequest` job,
which appears in `git-ns/activity/list` as `gitNs.job.closePullRequest` with
its state, and in `git-ns/bridge/job/list/0.2` with the pull request's
`number` (0.1, whose job-kind list predates job 0.5, leaves it out); when the bridge reports the pull request closed
(`succeeded`, `close` applied), the VTC audits
`gitNs.pullRequest.closed` with the repository and a detail of `{number,
author (login), level}`. A pull request that was allowed, or reopened by a
maintainer, leaves no record. A failed close is the job's `failed` or
`partial` state; jobs are retried on transport failures like any other.

### Bridge requirements

The bridge must take `git-ns/bridge/job/0.5` (and report events at
`git-ns/bridge/event/0.4`), and its forge credentials must be able to comment
on and close pull requests — for a GitHub App, the **Pull requests: write**
permission and the `pull_request` webhook event. If the gate is configured
for a namespace whose bridge does not list job 0.5, the VTC sends it no
`closePullRequest`, drops any it had queued, and tells the namespace's
administrators once: a warning in the log and a `gitNs.pullRequest.gateUnenforced`
row in their activity feed. It is told again only if the bridge later takes
0.5 and then loses it.

The configured level is not yet shown on the namespace card or in `cnm git
view --admin`: `git-ns/namespace/list/0.1`'s namespace rows admit no further
members. Read the active `gitNamespace` policy instead (the admin console's
policy view, or `GET /v1/policies`).

## Drift

In bridge mode the bridge compares each repository with the projection and
reports every difference as a drift item, which members see in `git-ns/view`
and administrators in `GET /v1/git-ns/drift`. An owner of the repository (or
a namespace admin over it) answers an item with `git-ns/drift/resolve`:

- **adopt** records the forge-side role as a right — evaluated exactly as a
  `git-ns/right/grant` from the resolver, so the same fixed rules, policy and
  consent class apply. The policy sees it as `right.grant` with
  `via: "drift.adopt"`, so a community can refuse every adoption and still
  grant. The item must still be outstanding as it was selected when the right
  is written; a forge that changed meanwhile adopts nothing. Only a role item (`roleAdded`, or a `roleChanged` that
  raises the member above their *projected* right — the highest right in their
  own name that reaches the repository; `git.ns.admin` projects to no forge
  role, so a namespace admin holding `maintain` there can have a forge `admin`
  adopted as `own`) held by a forge account linked to a current member, at a
  role a right projects to, can be adopted. Nobody adopts an elevated right
  (`git.repo.own`, or a right the bridge's role map projects to forge `admin`
  there — and, while no map is reported, `git.repo.maintain`) for themselves — the member the item names is compared with
  the resolver after console-key delegation, and a match is refused
  `git-ns:selfGrantNotAllowed`: another owner adopts it, or the resolver uses
  `git-ns/right/break-glass` (in single-administrator mode, with nobody else
  who could adopt it, it is waived on the resolver's step-up instead — see
  *Separation of duties*). Adopting `commit.sign`, or `maintain` where it is
  not elevated, for oneself is allowed. The right is the **lowest** whose role in the bridge's reported role map (the
  repository's own entry where it has one) is the observed role — under the
  default map `admin` is `git.repo.own`, `maintain` is `git.repo.maintain`,
  and on a personal account collaborator `write` is `git.repo.maintain`.
  With no report the right is unknown and adoption is refused
  (`git-ns:roleMapUnknown`). So where maintainers get `admin`, a forge `admin` is
  adopted as `git.repo.maintain`; where committers get `write`, `write` is
  `git.commit.sign`; a role no right's is (`triage`, `read`, `none`) projects
  nothing.
- **revert** changes no right and has the bridge undo the change: a
  `roleAdded` role is removed with `removeAccounts`, sent in-line so that a
  bridge that refuses it is answered `notRevertible` instead of a revert that
  does nothing (a namespace admin at no role may be named there too); a
  `roleChanged` or `roleRemoved` role re-sends the complete `desiredRoles`;
  protection items re-run the `requiredCheck` bootstrap step, and
  `bootstrapMissing` the whole plan. Reverting a role at or above the one
  `own` projects to (`admin` under the default map; `write` on a personal
  account) has the impact of revoking `own`, and is elevated; with no map
  reported, so does reverting any role.

The item is selected by type, account (role items) and — required to adopt —
the `observed` value the owner read, and a resolution is followed by an
`inspect` job so it is confirmed rather than assumed.

```sh
cnm git drift resolve github.com/acme/widgets revert --type roleAdded \
  --account-id 5550123 --account-login eve-dev --observed write
```

## Linking a forge account

The bridge gives a member the forge role their rights call for only once it
knows which forge account is theirs. A member links it with
`git-ns/account/link` and follows it with `git-ns/account/link-status`;
`cnm git link` does both, signed as the community profile's DID:

```sh
cnm git link --forge github.com      # prints the URL (and on GitHub a device code), then waits
cnm git link --status lnk_4Tq9Xw2P   # follow a link begun earlier
cnm git link --list                  # the accounts linked to this DID (git-ns/view/0.2)
```

It polls every five seconds until the link is `linked`, `expired` or
`failed`; `--no-wait` prints where to authorise and returns. Anything but
`linked` exits non-zero, with `--json` too (which prints the last answer on
stdout either way). A link needs a bridge-mode namespace on the forge
(`unsupportedForge` otherwise). `failed` means the forge refused it — the
member declined the authorisation, or the bridge could not complete it — or
the account is already linked to another member. The authorisation URL is
printed only if it is an `https://` URL, in its parsed form, and nothing the
VTC or bridge returns reaches the terminal with control or format (bidi,
zero-width) characters in it. Linking again
replaces the account linked on that forge.

`cnm git unlink --forge <host>` removes it (`git-ns/account/unlink`). It reads
the account linked there first and sends its id as the task's guard, so a
re-link in between is never removed (`--account-id` names it instead). The
VTC deletes the binding and queues the complete `desiredRoles` of every
bridge-mode namespace on that forge at once; the account is in none of them,
so the bridge withdraws the roles it gave it on its next dispatch. It never
sends `removeAccounts` for this: a role the bridge did not give stays and is
reported as drift, for the owners to revert. The member's rights are
unchanged, and the audit record (`gitNs.account.unlinked`, one per affected
namespace) names the member and the forge, not the account. A caller with
nothing linked — a non-member included — is answered `notLinked`, so the
answer says nothing about membership; a member whose access lapsed can still
unlink (with `--account-id`, since `git view` answers current members only).

One forge account links to one member. Link completion checks and records it
in one step under the member-row lock, inside the git-ns store lock that
serialises every link and unlink, so two members can never both hold it. A
member whose access lapsed keeps the account — nobody else may link it — but
it projects no role and cannot be adopted; `GET /v1/git-ns/accounts` says so
with `memberCurrent`. A departed member's links are deleted by the departure
sweep whether or not they held a right.

Only the DID the account is linked to can unlink it: `git-ns/account/unlink`
0.1 has no subject, so there is no path by which anyone unlinks, or frees for
themselves, an account that is someone else's. A community administrator who
needs a member's forge roles withdrawn revokes the rights or resolves the
drift; one who needs a lapsed member's account freed removes the member, and
the departure sweep deletes the binding. Unlinking gives no right and no role:
the next projection is computed without the account.

## Reseating a headless namespace

A namespace whose every `git.ns.admin` has left the community or lapsed is
*headless*. A community administrator restores one with
`git-ns/namespace/reseat` 0.3 (the only version served; it queues no forge
projection) — `cnm git reseat <namespace> --subject <did>
--statement "…"` — which grants a current member a permanent `git.ns.admin`,
with the statement as its reason. It is refused (`notHeadless`) while any
live admin record of a current member remains, so it cannot be used to go
around an admin; the audit record keeps the statement and how each earlier
admin record ended. The subject is never the administrator reseating:
reseating a namespace to yourself is a self-grant of `git.ns.admin`, refused
with `git-ns:selfGrantNotAllowed` (separation of duties) — another community
administrator reseats it to you, or (once this VTC serves it) you record it
explicitly with `git-ns/right/break-glass`. In single-administrator mode it
is waived on your passkey gesture instead ([below](#single-administrator-mode-waives-it)).

## Separation of duties and break-glass

Nobody grants themselves an **elevated** right — `git.ns.admin`,
`git.repo.create` or `git.repo.own` — even when their own rights carry the
authority to grant it to anyone else (`git-ns/right/grant/0.3`, fixed rule
7). It is refused with `git-ns:selfGrantNotAllowed`, and the same rule binds
every task that records a right on the actor's own authority: an adopted
drift item whose linked member is the resolver, `repo/adopt` naming oneself
an owner, and `namespace/reseat` to oneself. The bridge's role map can
make `git.repo.maintain` elevated too: where it projects `maintain` to the
forge's `admin` role on the repository (`Right::is_elevated_in`), a
self-grant of it is refused the same way — and while a bridge-mode
namespace's map is unknown, so is every self-grant of `maintain` (fail
closed). Break-glass does not carry `maintain`; another owner or
administrator grants it. A manual-mode namespace projects no forge role, so
there the three rights above are the only elevated ones. Self-grants of
`git.commit.sign`, and of `git.repo.maintain` where the map keeps it below
`admin`, stay allowed. `namespace/bind`
(the binder's first `git.ns.admin`) and `repo/create` (the creator's first
`own`) are not self-grants — but `repo/create` (served at 0.3) makes its
creator the owner only on an **explicit** `git.repo.create` record (granted by
someone else, or a break-glass). A `git.repo.create` implied by `git.ns.admin`
carries no creator ownership: a namespace admin names another member with
`owners` (`cnm git create --owner <did>`), or is refused
`git-ns:selfGrantNotAllowed`. A community in single-administrator mode has
these self-grants waived on a passkey gesture
([below](#single-administrator-mode-waives-it));
one with a single git administrator but not in that mode breaks the glass once
for `git.repo.create` on the namespace, not once per repository.

Elevated rights (`own`, `repo.create`, `ns.admin`) go only to a current
member with an ACL entry, and are granted only by one — on grant, adopt,
create, transfer, drift adopt and reseat alike (fixed rule 5; policy cannot
waive it). A throwaway `did:key` cannot stand in for a second person. Two
member DIDs held by one person are out of scope for the DID comparison. This VTC serves grant and revoke at 0.3 only:
0.1 and 0.2 are refused as unknown task types, so no client reaches a grant
that skips the rule or a record without its `breakGlass` flag.

When nobody else can grant it, the actor **breaks the glass**
(`git-ns/right/break-glass/0.1`):

```sh
cnm git break-glass --right=git.repo.own --resource=github.com/acme/widgets \
  --justification='Both owners unreachable; CVE fix must ship tonight'
```

- **Entitlement**: authority the actor already has — grant authority over the
  right on the resource, or, for `git.ns.admin` on a *headless* namespace, the
  community-administrator capability (`notHeadless` otherwise).
- **Step-up, always**: an operation-bound passkey gesture (user-verified,
  aal2) bound to this one document by digest (`acl::bound_step_up`). The first
  send is refused `permissionDenied` with `details.stepUpRequest`; the
  operator answers it in the admin console (`cnm` prints the
  `<vtc>/admin/step-up#request=…` link) and the identical document is sent
  again. Because a real step-up applies, `[git_ns] elevated_requires_admin`
  does not gate it: a namespace admin who is not a community administrator
  can break the glass, provided they have a passkey this community knows — a
  console passkey, or a **step-up passkey** (below).
- **Immediate, no expiry**: the right takes effect at once and lasts until
  another administrator acts on it.
- **Flagged**: the record carries `breakGlass {by, at, justification,
  effectiveAt?, ratifiedBy?, ratifiedAt?}`. An *unratified* record is a real,
  published right — the registry projection is unchanged — but it does not
  count toward the last-owner or last-admin invariants.
- **Visible**: an `AuditEvent::GitNsBreakGlass` row at
  `AuditSeverity::Critical` with the justification, the entitlement, the
  step-up evidence (credential id, bound digest), the policy version and who
  could not be told; a `gitNs.right.breakGlass` activity item; a signed
  `git-ns/right/break-glass-notice/0.1` to every community administrator and
  every live namespace admin except the actor, over the VTC's mediator
  connection; the flag in `git-ns/view/0.4` to every administrator it
  concerns; and the console's banner and *Break-glass grants* list
  (`git-ns/view/0.5` with `scope: administrator` and `breakGlass: true`). If
  the audit row cannot be written, the
  break-glass is undone.
- **Ratify or revoke**: another administrator — a community administrator, or
  someone whose *confirmed* rights carry grant authority over it — ratifies
  it with `cnm git ratify --subject=<did> --right=<right> --resource=<res>
  --break-glass-at=<rfc3339>` (`git-ns/right/ratify/0.1`; bound to the
  `breakGlass.at` they read). Any community administrator may revoke an
  unratified one with the ordinary `git-ns/right/revoke`, and no policy can
  refuse that. Both are audited and announced like the break-glass.
  `cnm git break-glass-list [--resource <res>]` shows them all.
- **In the action list**: every unratified break-glass is also a queue item
  (`gitNs.breakGlass.review`) in the **Actions** list of the namespace's other
  administrators, with **Ratify** and **Revoke**, which call the two tasks
  above as the decider. It never expires into acceptance; it closes when the
  break-glass is ratified or revoked by any route (`admin-access.md` §3.2a).

**Policy** (`git_ns.rego` `settings`) may disable or tighten it, never quieten
it: `break_glass` (`"enabled"` by default, or `"disabled"`),
`break_glass_delay_seconds` (the right takes effect later; at most a day;
revocable meanwhile), `break_glass_min_justification_chars`, and any deny
decision on `input.action == "right.breakGlass"` (or `"right.ratify"`).

### Single-administrator mode waives it

A community run by one person (`[acl] single_admin_mode`, set at install —
[admin-access §2.1a](admin-access.md#21a-single-administrator-mode)) has nobody
to make its administrator's elevated grants and nobody to ratify a
break-glass, so separation of duties would make ordinary work impossible:
`cnm git adopt github.com/<login>/<repo> --owner <your DID>` would be refused,
and every break-glass would stay unratified forever. In that mode rule 7 is
waived for the one operation under the same discipline as the consent waiver
(VTI-APV-022):

- **Whoever else holds an entry.** The mode states that every administrator
  is one person, under as many identifiers as they hold (one per device, say),
  and the VTC cannot tell one person's identifiers from two people's — so it
  does not count them. Another administrator entry, or a member whose git
  rights could make the grant, does not bring the refusal back; turning the
  mode off on the host does.
- **Every path the rule covers**: `git-ns/right/grant`, `repo/create` naming
  the requester owner on an implied `git.repo.create` (or by default),
  `repo/adopt` naming the requester owner, `namespace/reseat` to the requester,
  and a `drift/resolve` adoption whose linked member is the resolver. Rules 1,
  2 and 5, the granter-covers floor, `[git_ns] elevated_requires_admin` and the
  community's policy all still apply.
- **Step-up**: the requester's operation-bound passkey gesture, the one
  break-glass takes, bound by digest to the document as sent (the
  `drift/resolve` document, for an adoption). The first send is refused
  `permissionDenied` with `details.stepUpRequest`, whose message says
  *single-administrator mode*; `cnm git grant|create|adopt|reseat|drift resolve`
  print a note saying the gesture stands in for a second administrator, show
  the `<vtc>/admin/step-up#request=…` link, and send the identical document
  again — the same flow as `cnm git break-glass`.
- **Audited first**: a `Critical` `SingleAdminMode { event: selfGrantWaived }`
  row naming the rule (`git-ns/right/grant/0.3#rule-7`), the task, its digest,
  the git-ns action (`right.grant`, `repo.create`, `repo.adopt`,
  `namespace.reseat`, `drift.adopt`), the right and the resource, written
  **before** the record. If it cannot be written the operation is refused and
  nothing is recorded.
- **Marked**: the record carries `singleAdmin {at, task}` (never published);
  the task's answer carries `ext.org.openvtc.selfGrantWaived {mode:
  "singleAdministrator", requirement, right, resource}`, which `cnm` reports
  as *Single-administrator waiver applied*; `git-ns/view` 0.4 and 0.5 list such
  records under `ext.org.openvtc.selfGrantWaived`; the ACL entry's resource
  grant shows `selfGrantWaived: true`; and a `gitNs.right.selfGrantWaived`
  activity item follows the write.
- **It counts**: unlike an unratified break-glass record, a waived record
  counts toward the last-owner and last-admin invariants — in such a community
  it is how rights are normally held. There is nothing to ratify.

With the mode off, self-grants are refused and go through another
administrator or break-glass.

**Specification status.** `git-ns/right/grant/0.3` states rule 7 as a MUST
and names break-glass as "the one way" to self-grant; it does not yet carve out
VTI-APV-022's single-administrator mode. This waiver is host configuration, not
community policy (which still cannot waive the rule), but it is a divergence
from the rule's text until the git-ns specification (dtgwg-trust-tasks-tf)
admits it and it is recorded in the VTI specification's divergence register
(Appendix F).


### Step-up passkeys for members

A member who is no console user acts only through signed documents and has no
passkey, so without one they could never answer a break-glass step-up. They
enrol a **step-up passkey** (`auth/passkey/enroll/invite/0.2`, `purpose:
stepUp`; `vtc-service/src/step_up_passkey.rs`). Every step is a Trust Task on
the spine (`trust_tasks::step_up_passkey_tasks`), served the same way over TSP,
DIDComm and HTTPS; no REST route issues, redeems or revokes one.

1. A community administrator opens the member's page (Members → the member →
   *Step-up passkeys*) and clicks *Invite…*. The console signs
   `auth/passkey/enroll/invite/0.2` with its console key, and the VTC asks for
   a passkey gesture bound to that one document before it issues anything. The
   console then shows a link and, separately, a **claim code**. It shows the
   code once, and the code is never part of the link.
2. The administrator sends the link over one channel and the code over
   another.
3. The member opens `<vtc>/admin/enrol-step-up#token=…` (no sign-in). The page
   shows the command that redeems it:

   ```sh
   cnm git enrol-step-up-passkey '<vtc>/admin/enrol-step-up#token=…'
   ```

   `cnm` asks for the claim code and signs
   `auth/passkey/enroll/redeem/start/0.1` as the member: an invite redeems only
   for the DID it names, so whoever else holds the two messages — another
   member, or the administrator who wrote them — cannot bind a passkey to it.
   `cnm` prints `<vtc>/admin/enrol-step-up#enrollment=…`.
4. The member opens that link, checks the DID shown is theirs, and creates the
   passkey. The browser sends `auth/passkey/enroll/redeem/finish/0.1`; its
   authority is the ceremony the signed start opened.
5. When `cnm` later prints a `<vtc>/admin/step-up#request=…` link, the member
   answers it with that passkey. The page cannot sign for someone who is no
   console user, so it shows an **answer code** (the passkey assertion); the
   member pastes it into `cnm`, which signs the
   `auth/step-up/approve-response` with the member's own `assertionMethod` key
   and sends the original document again.

The rules:

- **Step-up only, by construction.** The credentials live in their own
  keyspace (`step_up_passkeys`), which login and session step-up never read.
  The only place they count is `acl::bound_step_up`, for a step-up issued to
  their own member, while they are a current member. They confer no role and
  no scope.
- **Never instead of a proof.** Every approve-response carries the approver's
  `assertionMethod` proof; the passkey assertion is a second gate beside it
  (approve-response 0.5). An unsigned answer, or one signed by anyone but the
  step-up's subject, is refused before the pending step-up is touched.
- **Two factors, two parties.** A stolen signing key alone cannot enrol one
  (that takes the administrator's invite and its claim code), and the invite
  alone cannot either (that takes the member's signature on `redeem/start`).
- **Single use and time-bounded.** An invite redeems once, for the DID it
  names, and lasts one hour by default (at most 24 h). Its response is not
  kept in the duplicate-delivery record, so the claim code exists only in the
  one reply.
- **Five wrong attempts and the invite is void.** A wrong code and a signer
  the invite was not issued to both count, and get the same refusal as a
  wrong token.
- **A second one needs the first.** Once a member holds a step-up passkey, a
  further one also needs a user-verified gesture from it.
- **No self-invites.** An administrator does not invite themselves: they enrol
  their own passkeys under Settings → Passkeys.
- **Revocation.** A community administrator revokes one from the member's
  page, verifying with their own passkey (`auth/passkey/revoke/{start,finish}/0.2`
  with `subject`). A member may be left with none. A revoked passkey cannot
  answer a step-up that was already pending.
- **Audit.** Every step is an `AuditEvent::StepUpPasskeyChanged` row (`invited`,
  `registered`, `inviteInvalidated`, `revoked`), and every use is the
  `OperationStepUpRecorded` row of the step-up it answered. The token and code
  are never recorded.
- **Backup.** Like `passkey`, `step_up_passkeys` is excluded: after a restore,
  members enrol again through a fresh invite.
- **Listing.** An administrator lists a member's step-up passkeys with
  `auth/passkey/admin-list/0.1` (`purpose: stepUp`), signed, over any
  transport; the console sends it from the member's page. It takes
  `vtc.members.manage`, and for a member who is an administrator an entry that
  covers theirs (VTI-ACL-050). A non-administrator is
  refused `notAdministrator`, a subject outside the administrator's authority
  `subjectUnknown` (as one that does not exist), and a former member
  `subjectNotMember`. The answer is metadata only — id, label, when enrolled,
  when last used, signature counter — and reading it changes nothing.

## Administrator surface

### Signed reads

Every administrator read — the view, the namespace and repository listings,
the break-glass list, the rights lists, the bridge job queue, the Trust
Registry projection, the linked-account roster and the activity feed — is a
signed Trust Task, served on the document dispatcher the same way over TSP,
DIDComm and `POST /v1/trust-tasks` (`vtc-service/src/git_ns/admin_reads.rs`).
None has a bearer door.

Two authorization shapes. `namespace/list`, `repo/list`, `view`,
`bridge/job/list` and `activity/list` answer a namespace's administrators —
the community-administrator capability (every namespace) or a live,
explicitly recorded `git.ns.admin` on it, held by a current member. A caller
who administers nothing, or who names a namespace they do not administer or
one that does not exist, is refused with the task's `notAdministrator`, the
same way in each case. `right/list`, `right/issued-by-departed`,
`projection/show` and `account/list` answer the community-administrator
capability alone — each spans every namespace, and for the rights reads every
granter's reason — so holding `git.ns.admin` on some namespace is not enough;
a caller who lacks the capability is refused with the task's
`notCommunityAdministrator`. An unsigned document is refused `proofRequired`
either way.

Every listing among the six added in trustoverip/dtgwg-trust-tasks-tf#686
clamps `limit` to 1..=500 (default 100) and pages with an opaque `cursor`
bound to the request's own filters — a request that changes a filter mid-page
is refused `malformedRequest` rather than silently reinterpreted.

| Task | Answer | `cnm` |
|---|---|---|
| `git-ns/namespace/list/0.1` (`namespace?`) | administered namespaces with admins, bridge, headless flag, bridge-reported app/plan status, effective `role_drift` / `cascade_on_departure`, role map (`roleMap`, absent while unknown; `roleMapSource`: `reported` or `unknown`) | `cnm git namespace list` |
| `git-ns/repo/list/0.1` (`namespace?`) | repositories in them with owners, right counts, bootstrap, sync, guard in force, step outcomes, last check, effective role map, `roleMapStale`; for a community administrator also those an unbound namespace left | `cnm git repos [--namespace <id>]` |
| `git-ns/view/0.5` (`scope: administrator`) | every record and reason in the administered namespaces (0.4's response shape) | `cnm git view --admin` |
| `git-ns/view/0.5` (`breakGlass: true`) | only break-glass records, ratified ones included, and the namespaces holding them | `cnm git break-glass-list` |
| `git-ns/right/list/0.1` (`resource?`, `subject?`) | every right the VTC knows of, recorded and role-derived, across every namespace, with `subjectMember` / `granterDeparted` | — |
| `git-ns/right/issued-by-departed/0.1` | recorded rights whose granter has since left, grouped by granter, plus `cascadeOnDeparture` | — |
| `git-ns/bridge/job/list/0.2` (`namespace?`, `state?`) | bridge jobs in the administered namespaces, with kind, queue state, attempts and last error, and a `closePullRequest` job's pull request `number`. 0.1 is still served and leaves `closePullRequest` jobs out | — |
| `git-ns/projection/show/0.1` (`resource?`) | what is published to the Trust Registry, `registryConfigured` and `pendingChanges` | — |
| `git-ns/account/list/0.1` (`member?`, `forge?`) | every member's linked forge account, community-wide, each with `memberCurrent` | — |
| `git-ns/activity/list/0.1` (`namespace?`) | rights changes, drift and bridge jobs in the administered namespaces, newest first | — |

`view/0.5`, `namespace/list/0.1` and `repo/list/0.1` (trustoverip/dtgwg-trust-tasks-tf#659,
trust-tasks-rs 0.23.4) and the other six (trustoverip/dtgwg-trust-tasks-tf#686,
trust-tasks-rs 0.24.7) are all generated `trust_tasks_rs::specs::git_ns::*`
modules, which declare the proof REQUIRED; the dispatch spine refuses an
unsigned document before a handler runs.

One forge account links to one member. Link completion checks and records it
in one step under the member-row lock, inside the git-ns store lock that
serialises every link, so two members can never both hold it. A member whose
access lapsed but who has not left keeps the account — nobody else may link
it — but it projects no forge role and a role it holds cannot be adopted;
`accounts` says so with `memberCurrent`, and the console offers no adoption
for it. A departed member's links are deleted by the departure sweep whether
or not they held a right.

The bridge reports what the specification's payloads do not carry — its app
installation, missing permissions, the owner's plan, the guard in force on a
repository, the last check — in the `ext` member of its results and events,
under `org.openvtc.git-ns`: `{"namespace": {...}, "repo": {...}}`.

Every DID a `git-ns/*` task names — a grant's or revoke's subject, a
transfer's `to`, an adoption's owners, a reseat's subject, the member linking
an account — must be a DID by DID-core's syntax (`did:<method>:<id>`, the id
only letters, digits, `.`, `-`, `_`, `:` and percent-encoded octets), or the
task is refused `malformedRequest`. That is stricter than the specification's
`Did` pattern, which admits shell metacharacters (`did:web:x$(…|sh)`); a DID
that reaches the console or a `cnm` hint can be pasted into a shell safely.
`cnm` applies the same check before it signs, and quotes anything it prints
in a command.

A console signing key (a delegation enrolled under #1692) acts as the admin
DID it stands for on every member-facing `git-ns/*` task.

Every change is a signed `git-ns/*` Trust Task on `POST /v1/trust-tasks` (or
DIDComm/TSP). `cnm git …` signs them with the community profile's key.
`git-ns/view` is served as 0.1, 0.2, 0.4 and 0.5; 0.2 adds the caller's own
linked forge accounts (`accounts`, narrowed to a `resource`'s forge), never
another member's, and 0.5 the administrator's scope and the break-glass
narrowing above. `cnm git view` asks for 0.5.

The admin console's **Repos** plugin (`/admin/repos`) renders these reads —
the signed ones sent with the browser's console key, so a browser with no
console key enrolled is told to enable signing rather than shown an empty
page:
namespace cards (kind, mode, what the bridge reported of its App — missing
permissions, a pending permission upgrade, org rulesets — admins, the
bridge's service grant, the effective `role_drift` and
`cascade_on_departure`), each namespace's repositories with their four-step
bootstrap and sync state, a repository's people and rights, bootstrap
checklist and step outcomes, the guard in force (or, unreported, the one
design §9 expects, labelled so), the last check, the registry records it puts
in public, its drift and activity, and the grants departed members issued.
Each person's forge account shows the forge role their right projects to
under the repository's role map ("no forge role" for a namespace admin); a
namespace card shows the map and whether the bridge reported it; a stale
repository says so. Each change it offers — bind, create, grant, revoke,
adopt, transfer, archive, re-project roles — is signed with the browser's console key and sent where one is
enrolled, and otherwise handed to the administrator as the `cnm git …`
command that signs it, with the document itself.

The **Members** page shows each member's git rights and linked forge accounts
(from `rights` and `accounts`) in its list, and a member's page lists them in
a *Git rights* card — recorded rights with their resource, granter and expiry,
and role-derived ones marked as such. Both reads need the
community-administrator capability (`git.ns.admin` held community-wide); an
administrator without it sees that said instead of the column.

## Limits

- **No member step-up** — see *Consent classes* above.
- **A namespace with no admin.** The last-admin and last-owner invariants count
  only records with no expiry (`git-ns/namespace/reseat/0.3`), so an expiring
  `ns.admin` or `own` cannot be the one that keeps them. A departure can still
  leave a namespace headless; it is recovered with a reseat (above).
- **No binding credential.** `git-ns/account/link` says the VTC SHOULD issue a
  credential attesting a member's forge account; this VTC records the link on
  the member and issues none yet.
- **Legacy resources.** Unqualified `owner/repo` tuples are not dual-written
  during a migration window (the specification makes it optional).
