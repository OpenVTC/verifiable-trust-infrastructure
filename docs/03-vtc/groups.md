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
| `vtc/groups/members/{add,remove}/0.1` | a manager of the group | Add an active member, or remove one |
| `vtc/groups/members/list/0.1` | anyone the group shows its members to | The members, each with their directory fields as `entries/show` projects them for the caller |
| `vtc/groups/join/0.1` | an active member, for themselves | Join an `open` group, or ask to join a `request` one |
| `vtc/groups/leave/0.1` | an active member, for themselves | Leave a group, or withdraw a request |
| `vtc/groups/requests/list/0.1` | a manager | The requests to the groups the caller manages |
| `vtc/groups/requests/decide/0.1` | a manager, never the requester | Approve or decline a request |
| `vtc/groups/managers/add/0.1` | a manager of the group | Appoint an active member a manager of it |
| `vtc/groups/managers/remove/0.1` | the manager, or `vtc.groups.manage` unqualified | End an appointment; a manager may step down |
| `vtc/groups/bindings/{add,remove}/0.1` | a manager of the group, after a bound gesture — with `vtc.rooms.manage` for a room, holding what it confers for grants | Bind the group to a community room or to capabilities, or end the binding |
| `vtc/groups/bindings/list/0.1` | a manager of the group | The group's bindings |

Room bindings ([Room bindings](#room-bindings)) and grants and role bindings
([Groups that carry authority](#groups-that-carry-authority)) are served. The member portal signs these tasks with its sign-in key
for the member (`signingScope` `vtc/groups`), as it does the directory's.

Only **static** groups are served. A dynamic group's rule is checked — it may read only
verified facts — and the create is then refused `kindNotServed`. Nothing is stored for
it.

## In the console and the portal

The console's **Groups** page (Membership) lists every group the administrator may see;
a holder of `vtc.groups.manage` creates one there. A group's page shows its settings,
its members by their directory name and picture, the requests to join it, its managers
and deleting it — each part shown to the group's managers only, and to anyone else only
what the community answers them.

The member portal's **Groups** page (`#/groups`) lists the groups a member belongs to
and the ones they may see, and a group's page lets them join an open group, ask to join
one by request (with an optional note for its managers) or leave. Its members are listed
where the group shows them, each linking to their directory entry.

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
# Days before the authority lapses that it is renewed. Default 30, or
# credential_valid_days where that is longer; never more than half its life.
authority_renew_within_days = 30
```

Without it, or without a link to the community's VTA (`vta_did`, the community's
signing key and `[messaging]`), a create is refused `noKeyHolder` with what to add.

### Where group identities are published, at runtime

`dids.webvh_server` chooses where the identities this community mints are published —
its groups' and its own rooms' alike — and can be changed without a restart, by an
administrator holding `vtc.config.admin`: on the Groups page (*Where identities are
published*), with `config/patch`, or in a `vtc/config/import`.

| Value | Each new identity is |
|---|---|
| `local` | served by this community, at `<public_url>/group-dids/<id>/did.jsonl` (rooms: `/room-dids/`) |
| a server id | published by the community's VTA on that `did:webvh` hosting server |
| unset (the default) | as `[groups] webvh_server` (rooms: `[rooms.community] webvh_server`) says, and served here where that is absent |

The page offers the hosting servers the community's VTA reports
(`vtc/config/did-hosting/list/0.1`, which the community asks its VTA as itself, through the
link it keeps); where it has no link, or the VTA does not answer, the server's id is typed.
`[dids] webvh_server` in `config.toml`, and `VTC_DIDS_WEBVH_SERVER`, set the same key at
their layers. A change applies to the next identity minted: one already minted stays
where it was published, because its DID names its host. The change is audited like any
configuration change; it confers no authority, so it is not held for another
administrator's consent.

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

A manager is appointed with `vtc/groups/managers/add`, by a manager of the group or an
administrator who manages every group: the grant is written on the appointee's entry,
delegated by the signer, and needs no administrative role. Managers of one group do not
remove one another; a manager may step down, and an administrator who manages every
group may end anyone's appointment. When a grant's granter leaves the community or no
longer manages the group, the grant goes to review: an `acl.grants.review` item asks the
community's administrators to re-affirm it under their own authority, and it is
withdrawn when the review is declined or its deadline (the action lifetime) passes.
Deleting a group withdraws every appointment to it.

A manager's authority is over the group's membership and settings, and confers nothing
else: authority reaches a group only through a binding, and adding a member to a group
that carries authority will still take the consent such a grant requires.

## Joining, and the member's group credential

A static group's `joinPolicy` decides how a member gets in: `closed` (a manager adds
them), `request` (they ask; a manager decides, never their own request) or `open` (they
join, where the `groups` policy allows). A request's note goes to the group's managers
only, and a declined requester never sees the managers' reason.

Where the group issues credentials, admitting a member — added, joined or approved —
first has the community's VTA sign, **as the group's DID**, a DTG
`MembershipCredential` to the member's membership DID, and offers it to them with the
group's authority credential on the credential-exchange path every credential this
community issues travels. Only then is the membership recorded: a VTA that does not
answer or refuses records nothing (`keyHolderUnavailable` / `keyHolderRefused`). The
credential lasts `[groups] credential_valid_days` (default 30) and carries no status
list — a small group's list would single its members out — so leaving, removal or
departure stops renewal and the credential lapses at its expiry. `credentialValidUntil`
is shown only to the member and the group's managers.

## Renewal

A sweeper renews both kinds of credential at the community's VTA before they lapse
(`vtc/groups/create` item 5). There is no task for it, and nothing to run by hand.

- **A group's authority** is renewed within `authority_renew_within_days` of its expiry,
  signed again by the VTA as the community. It keeps the group's one slot in the
  community's revocation list, so deleting the group revokes every authority it was ever
  issued. The old credential is not revoked: members present it until their own
  credential is renewed.
- **A member's credential** is renewed within a third of its life of its expiry (ten
  days of a 30-day credential), signed again as the group and offered with the group's
  current authority. Only an active member of the community is renewed.

The authority's window is at least a member credential's life, so every member receives
the new authority before the old one lapses. Nothing is recorded before the VTA has
signed; a VTA that does not answer is retried with a capped, jittered backoff (one minute
doubling to six hours), logged at `warn` each time and audited when a run of failures
begins (`GroupChanged` `authorityRenewalFailed`, `GroupMembershipChanged`
`credentialRenewalFailed`). Each renewal is audited by reference.

## Groups in the directory

A member's card can show a field only to people in their groups (the `groups`
audience). The groups that count are those both belong to **whose member list the
viewer may see**: a group that shows its members only to its managers never reveals,
through somebody's card, who is in it.

A member who leaves the community leaves every group with them, and their pending
requests are withdrawn.

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

## Room bindings

A **room binding** links a room the community owns ([community rooms](community-rooms.md))
to the group: every member of the group is offered admission to it with the binding's
`actions`, for `validFor` (`P30D`, say), and keeps it while they stay in the group.

- **Who may bind**: a manager of the group who also holds `vtc.rooms.manage` — the same
  authority as admitting one member to the room — after their gesture bound to the
  request, as `vtc/rooms/community/members/add` takes. It is not parked for other
  administrators: community room changes never are.
- **Offers.** A reconciler offers each active member admission through the room's usual
  offer path. The member accepts it as any offer, with their own key package on a sealed
  room, so nobody is put in an encrypted room without their own key. An offer is recorded
  only after the community's VTA issued its credentials.
- **What covers an admission.** Each admission records its sources: the bindings that
  cover it, and `direct` where an administrator also admitted the member. Leaving the group
  drops that binding's source; an admission with no source left is removed, through the
  same worker that removes a member who left the community. A direct admission is never
  removed because a binding that also covered it went.
- **Renewal.** Within a third of `validFor` of an admitted member's expiry, the community
  issues a fresh membership and authority with the same actions. The member collects them
  from `vtc/rooms/offers/list/0.3`'s `renewals` and stores them in place of the ones they
  renew ([community rooms](community-rooms.md#the-members-half--vtcroomsoffers)).
- **Ending a binding** puts it into `removing`: what only it covered is withdrawn, then it
  is deleted. One that covered nobody is deleted at once. Deleting the group ends all of
  its bindings the same way.

A VTA that does not answer is retried with a capped, jittered backoff; the reconciler runs
every minute and whenever a group's members or bindings change.

## Groups that carry authority

A **grants** binding (`{"kind": "grants", "grants": [{"capability": "vtc.invitations.manage"}]}`)
or a **role** binding (`{"kind": "role", "role": "moderator"}` — that role's ceiling, by
reference, read as it is defined now) makes the group carry authority: what it confers is
written onto each member's access-control entry, as `groupGrants` naming the group as their
source, and taken off when they leave (VTI-DIR-100). The group itself never answers whether
anyone may do anything; every gate reads the entry. The entry's
`ext["org.openvtc"].groupGrants` shows each row, its group and whether it is in effect.

- **Inside the member's role.** A group confers capabilities within the ceiling of the
  member's administrative role, never the ceiling (VTI-DIR-105): a row counts only while
  the role admits it and the entry may act. A member whose role does not admit something
  the group confers is refused `exceedsRoleCeiling`, so a member with no administrative
  role cannot join a group that carries authority. A row confers nothing to approve.
- **What the binder holds.** Each capability is provisioned only while the administrator
  who made the binding holds it themselves, other than through a group (VTI-DIR-102,
  VTI-ACL-071) — so binding what you do not hold is refused `exceedsBinderAuthority`, and
  a binder who loses it takes it from every member.
- **Static and closed.** Only a `closed` group may carry authority (`groupNotEligible`),
  and it stays closed while it does (`update` refuses `authorityGroupLocked`), so nobody
  joins it by their own act (VTI-DIR-103).
- **Consent** (VTI-DIR-104). Binding an authority-conferring capability is granting it,
  and adding a member to such a group is granting it to them: each is held in the action
  list for another administrator who holds and may approve it, and runs on the approval,
  re-checked then. Removing a member is a reduction of what the group gave them, on the
  same terms as any reduction — the consent of someone other than the requester and the
  member, or, where nobody is left, the requester's gesture, a `Critical` record and the
  cooling-off. Removing the binding or deleting the group is a reduction of every member at
  once: consented by someone who is not in the group, or, where nobody is, the gesture and
  a `Critical` record per member, with no cooling-off — a cooling-off suspends its one
  subject, and this reduction has many. Capabilities that confer no authority take the
  requester's gesture bound to the request. Leaving is the member's own and needs nobody.

Each change to a member's grants is audited (`GroupGrantsChanged`) by group, binding,
member entry and capability.

## Deleting a group

Deleting revokes the group's authority credential in the community's revocation list
and ends every membership, taking whatever it conferred with it. The group's DID log stays served, so credentials it issued
still resolve their issuer until they expire.

## Storage

Groups live in the `directory` keyspace (backed up), beside the cards whose `entryId`
keys every membership: `group:<groupId>`, the memberships as `gm:<groupId>:<entryId>` and
`mg:<entryId>:<groupId>`, bindings as `gbind:<groupId>:<bindingId>`, and served identity
logs as `group-did:<path>`. A rotation
keeps the member's entry, so it moves nothing. Every change is audited by reference
(`GroupChanged`): the group, what changed and the reason given, never a name or
description.
