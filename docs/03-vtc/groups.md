# Community groups

A community's **groups** — a working group, a chapter, the people running an event —
are records the community keeps beside its member directory, each with an identity of
its own. They are the `vtc/groups/*` Trust Tasks, sent over TSP, DIDComm or HTTPS like
every other; none has a REST route.

The design is §9 of [the member-directory design note](../05-design-notes/vtc-member-directory.md).
This page says what this build serves.

## What this build serves

| Task | Who may send it | What it does |
|---|---|---|
| `vtc/groups/create/0.1` | `vtc.groups.manage` at the community | Create a static group: mint its identity at the community's VTA and issue it the community's authority |
| `vtc/groups/update/0.1` | a manager of the group | Change its name, description, join policy, who sees it and its member list, and whether it issues credentials |
| `vtc/groups/delete/0.1` | a manager of the group | Delete it: its authority revoked, its memberships ended |
| `vtc/groups/list/0.1` | an active member or an administrator | The groups the caller may see, each as they may see it |
| `vtc/groups/show/0.1` | an active member or an administrator | One group the caller may see |

Membership (`members/*`, `join`, `leave`, `requests/*`), appointing managers
(`managers/*`), the members' own group credentials, and bindings to rooms or grants
come next. Until then a group has no members.

Only **static** groups are served. A dynamic group's rule is checked — it may read only
verified facts — and the create is then refused `kindNotServed`. Nothing is stored for
it.

## Turning groups on

Groups are off until the host's operator writes a `[groups]` section and restarts:

```toml
[groups]
# The context at the community's VTA the groups' keys are minted in. Absent: the
# `[rooms.community] context`.
context = "community"
# A did:webvh hosting server registered at the VTA, by its id there. Absent: each
# group's log is served here, at <public_url>/group-dids/<id>/did.jsonl.
webvh_server = "hosting"
# Days the community's authority credential to a group lasts. Default 365.
authority_valid_days = 365
# Days a member's group credential lasts, renewed while they stay. Default 30.
credential_valid_days = 30
```

Without it, or without a link to the community's VTA (`vta_did`, the community's
signing key and `[messaging]`), a create is refused `noKeyHolder` with what to add.

The community's own entry at its VTA needs, in that context, `key-mint` (to mint each
group's identity) and `sign-document` (to sign the community's authority credential as
the community).

## A group's identity

The community's VTA mints each group a `did:webvh` from the built-in **`vtc-group`**
template: a signing key and a key-agreement key, and nothing else. Its document carries
no service, name or description, so resolving it says nothing about the group, and the
VTA's own record of it is labelled only "Community group". This community never holds a
group key.

Where the group issues credentials (the default), the community then issues it an
**authority credential** — a DTG `AuthorityCredential` from the community to the group's
DID granting `issue-membership` within the community — signed by its VTA **as the
community** through `keys/sign-document`. It carries a slot in the community's
revocation list and an expiry. A verifier chains a member's group credential to it, and
it to the community.

The group is stored only after its identity and its authority exist. A VTA that does not
answer is `keyHolderUnavailable`, naming in `details.groupDid` any DID it had already
minted so an operator can retire it; one that refuses is `keyHolderRefused`, carrying
its code and message.

## Who sees what

| `visibility` | who sees that the group exists |
|---|---|
| `members` | every active member |
| `groupMembers` | its members and managers |
| `admins` | its managers only |

`showMembers` uses the same audiences for the member list, and is never wider than
`visibility`. A caller who may not see a group gets `notFound` for it on every task,
exactly as for one that does not exist. `memberCount` goes only to those who may see
the member list, and `managers` and `credentialAuthorityValidUntil` only to its
managers.

## Who manages a group

A manager holds **`vtc.groups.manage`**: unqualified, every group, and creating them; or
as a resource grant qualified `group:<groupId>`, one group. The grant lives on the
holder's access-control entry, beside its role, and every gate reads it there; a group's
record never decides who manages it. `managers` on a group lists the entries holding the
qualified grant, for information. The capability is in the community-admin role's
ceiling.

A manager's authority is over the group's membership and settings, and confers nothing
else: authority reaches a group only through a binding, and adding a member to a group
that carries authority will still take the consent such a grant requires.

## Policy

The `groups` policy purpose (`vtc.groups`) is asked after the community's own checks,
on a creation and on a member joining or asking to join. It can refuse (`policyRefused`)
and nothing else. The shipped default allows; a community that caps a group's size, for
example, uploads:

```rego
package vtc.groups
import rego.v1

default decision := {"effect": "allow"}

decision := {"effect": "deny", "with": {"code": "group-full",
    "reason": "this group is full"}} if {
    input.operation in {"join", "request"}
    input.group.memberCount >= 200
}
```

## Deleting a group

Deleting revokes the group's authority credential in the community's revocation list
and ends every membership. The group's DID log stays served, so credentials it issued
still resolve their issuer until they expire.

## Storage

Groups live in the `directory` keyspace (backed up), beside the cards whose `entryId`
keys every membership: `group:<groupId>`, the memberships as `gm:<groupId>:<entryId>` and
`mg:<entryId>:<groupId>`, and served identity logs as `group-did:<path>`. A rotation
keeps the member's entry, so it moves nothing. Every change is audited by reference
(`GroupChanged`): the group, what changed and the reason given, never a name or
description.
