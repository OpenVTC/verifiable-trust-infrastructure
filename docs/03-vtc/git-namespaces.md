# Git namespaces

A VTC can govern repositories on the forges its community uses — GitHub, a
Forgejo instance such as Codeberg — and publish who may do what there to its
Trust Registry, where CI checks such as `did-git-sign verify-trust` read it.

- **Normative:** the `git-ns/*` Trust Tasks in dtgwg-trust-tasks-tf
  (`specs/git-ns/**`). The rights model is in `git-ns/right/grant/0.1`.
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
destructive git-namespace action only from a community administrator, *in
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
| `cascade_on_departure` | `false` | grants a departed member issued are revoked with them, instead of listed for review |
| `role_drift` | `"report"` | `"enforce"` re-projects forge roles changed outside the VTC |

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

## Membership

A member who leaves loses every git right. A repository they owned alone
becomes `orphaned` — governed by the namespace admins — until one of them
names an owner. Grants they issued stay, listed under *issued by departed
members* (`GET /v1/git-ns/rights/issued-by-departed`), unless the policy sets
`cascade_on_departure`. Their linked forge accounts are removed.

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
it with everything else.

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
The VTC serves 0.1, 0.2 and 0.3 — 0.3 only adds `roleMapReported` (below) —
and applies 0.2's rules to all three.

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

Every job goes out as `git-ns/bridge/job/0.4`
([trust-tasks #635](https://github.com/trustoverip/dtgwg-trust-tasks-tf/pull/635)),
and only to a bridge that lists 0.4 when asked with `trust-task-discovery`
(asked again hourly, so an upgrade is noticed). A bridge that does not is sent
nothing: in-line jobs (binding, account links, a `roleAdded` revert) are
refused with "upgrade the bridge", and queued jobs wait with that as their
last error. A bridge before 0.4 would read a `git.ns.admin` entry as
ownership, which is why there is no downgrade.

Jobs are queued in `git_ns_jobs`; role projection retries
forever, everything else within a budget. `GET /v1/git-ns/jobs` shows them.

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
  raises the member above what they hold) held by a forge account linked to a
  current member, at a role a right projects to, can be adopted. For a
  `roleChanged` item, "holds" counts implied rights (`git-ns/drift/resolve`
  0.2): a namespace admin's forge `admin` role on a repository where they
  hold `maintain` is not adoptable, though a `roleAdded` one is. The right
  is the **lowest** whose role in the bridge's reported role map (the
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
replaces the account linked on that forge. There is no unlink task: an
account is unlinked when its member leaves.

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
explicitly with `git-ns/right/break-glass`.

## Administrator surface

Read-only, admin session. `view`, `rights`, `rights/issued-by-departed`,
`projection`, `accounts` and `drift` show every member's rights, grant
reasons and forge identities — and, in drift, the forge accounts of people
outside the community — so they need a community-wide administrator (an admin
session not narrowed to a context); `activity` is for any session and shows
only the namespaces the caller administers. `view` also takes
`Trust-Task: https://trusttasks.org/spec/git-ns/view/0.1`, because its body is
that task's response; the rest are console projections no specification
defines, and carry no Trust-Task URL.

| Route | Body |
|---|---|
| `GET /v1/git-ns/view?resource=` | `git-ns/view/0.1#response`, every record and reason |
| `GET /v1/git-ns/namespaces` | namespaces with admins, bridge, headless flag, bridge-reported app/plan status, effective `role_drift` / `cascade_on_departure`, role map (`roleMap`, absent while unknown; `roleMapSource`: `reported` or `unknown`) |
| `GET /v1/git-ns/repos?namespace=` | repositories with owners, bootstrap, sync, guard in force, step outcomes, last check, effective role map, `roleMapStale` |
| `GET /v1/git-ns/rights?resource=&subject=` | recorded and role-derived rights |
| `GET /v1/git-ns/rights/issued-by-departed` | grants whose granter left |
| `GET /v1/git-ns/drift` | repositories with outstanding drift |
| `GET /v1/git-ns/jobs` | bridge jobs |
| `GET /v1/git-ns/projection` | what is published, and how many changes are pending |
| `GET /v1/git-ns/accounts` | members' linked forge accounts |
| `GET /v1/git-ns/activity?namespace=&limit=` | rights changes, drift and jobs in the namespaces the caller administers (any session) |

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
`git-ns/view` is served as 0.1 and 0.2; 0.2 adds the caller's own linked forge
accounts (`accounts`, narrowed to a `resource`'s forge), never another
member's. `cnm git view` asks for 0.2.

The admin console's **Repos** plugin (`/admin/repos`) renders these routes:
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
and role-derived ones marked as such. Both need a community administrator; a
scoped administrator sees that said instead of the column.

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
