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
configuration.

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
it with everything else. Jobs are queued in `git_ns_jobs`; role projection retries
forever, everything else within a budget. `GET /v1/git-ns/jobs` shows them.

## Administrator surface

Read-only, admin session. `view`, `rights`, `rights/issued-by-departed`,
`projection` and `accounts` show every member's rights, grant reasons and
forge identities, so they need a community-wide administrator (an admin
session not narrowed to a context); `activity` is for any session and shows
only the namespaces the caller administers. `view` also takes
`Trust-Task: https://trusttasks.org/spec/git-ns/view/0.1`, because its body is
that task's response; the rest are console projections no specification
defines, and carry no Trust-Task URL.

| Route | Body |
|---|---|
| `GET /v1/git-ns/view?resource=` | `git-ns/view/0.1#response`, every record and reason |
| `GET /v1/git-ns/namespaces` | namespaces with admins, bridge, headless flag, bridge-reported app/plan status, effective `role_drift` / `cascade_on_departure` |
| `GET /v1/git-ns/repos?namespace=` | repositories with owners, bootstrap, sync, guard in force, step outcomes, last check |
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

A console signing key (a delegation enrolled under #1692) acts as the admin
DID it stands for on every member-facing `git-ns/*` task.

Every change is a signed `git-ns/*` Trust Task on `POST /v1/trust-tasks` (or
DIDComm/TSP). `cnm git …` signs them with the community profile's key.

## Limits

- **No member step-up** — see *Consent classes* above.
- **A namespace with no admin.** The last-admin and last-owner invariants count
  only records with no expiry, so an expiring `ns.admin` or `own` cannot be the
  one that keeps them — lapse alone never leaves a namespace headless or a
  repository ownerless. A departure still can: if the last permanent
  `git.ns.admin` leaves the community, the namespace is *headless* and nobody
  can grant in it. The only recovery today is to unbind and bind again, which
  starts from no rights; a task to re-seat an admin is a specification gap.
- **No binding credential.** `git-ns/account/link` says the VTC SHOULD issue a
  credential attesting a member's forge account; this VTC records the link on
  the member and issues none yet.
- **Legacy resources.** Unqualified `owner/repo` tuples are not dual-written
  during a migration window (the specification makes it optional).
