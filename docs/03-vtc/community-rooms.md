# Rooms the community owns

A community hosts data rooms its members own ([quickstart](data-rooms-quickstart.md)).
It can also **own** rooms itself — the board's papers, a working group's drafts, a
members' library — run by its administrators and outliving any one of them. This page
is how to turn that on and run one. The design is
[`data-rooms-files.md` §8.4](../05-design-notes/data-rooms-files.md#84-community-owned-rooms);
the wire is `vtc/rooms/community/*` and `vtc/rooms/offers/*` (trust-tasks-tf #768; a
room's description and tags, and `update`, trust-tasks-tf #805).

## Who holds what

| | |
|---|---|
| **Owner** | the community: the room's `ownerDid` is the VTC's own DID |
| **Key holder** | the community's **VTA**: it mints the room's DID from the `room` template, signs the room's credentials, and holds the community's place in a sealed room's MLS group |
| **Host** | the VTC, as for every room it stores |

The VTC holds **no room key and no group secret**. It acts on a room the way any owner's
client does — by sending its VTA the `rooms/owner/*` tasks the VTA serves for every owner
(`group/create`, `invite`, `issue-membership`, `issue-authority`, `group/add`,
`group/remove`, `revoke`) — over the messaging link it already keeps to its VTA (TSP, else
DIDComm, through the mediator; the VTA needs no inbound address). The VTA applies its own
gates to each call.

The community keeps, as owner, a record of whom it offered admission to and admitted
(`community_rooms` keyspace, backed up). **Nothing on the host path reads it**: the room's
records are authorized by the room's credential chains exactly as a member's room's are,
so the room could move to another host with nothing re-issued.

## Turn it on

Absent, community rooms are off and an upgraded VTC starts exactly as before; a create
is refused `noKeyHolder` naming what to add, and `vtc/rooms/community/list` carries the
snippet in `ext["org.openvtc"].communityRooms` for the console.

```toml
# config.toml
vta_did = "<the community's VTA>"          # already there on a VTA-provisioned VTC
vta_context = "vtc"                         # the VTA context holding the VTC's own DID;
                                            # written by `vtc setup`, add it by hand if absent

[messaging]                                 # the link to the VTA rides it
mediator_did = "<mediator DID>"

[rooms.community]
context = "vtc"                             # the VTA context the rooms' keys are minted in
# webvh_server = "<hosting server id at the VTA>"   # absent: this VTC serves each room's log
# mediator_did = "<DID>"                    # the rooms' DIDComm mediator; default [messaging]
# authority_valid_days = 365                # the community's own admin authority per room
# authority_renew_within_days = 30          # renew it this long before it lapses
```

**Where a room's DID is published.** A room's DID must resolve before its credentials
can be checked — the VTA verifies the community's own credentials as it stores them.

- With `webvh_server`, the VTA publishes each room's log on that hosting server
  (registered at the VTA with `pnm webvh servers register`).
- Without it, the room's DID is minted serverless at
  `<public_url>/room-dids/<id>/did.jsonl`, and **this VTC serves the log** there, on
  every host, like its own `/.well-known/did.jsonl`. `public_url` must be set.

**At the community's VTA**, the VTC's own DID needs an entry that covers **both**
the context holding the VTC's own DID (the one `vtc setup` minted it in, `vta_context`)
**and** `[rooms.community] context`, and that may mint DIDs (`key-mint`), issue a
room's credentials (`credential-write`), keep the community's own in the vault
(`vault-write`) and write each room's profile into the room (`room-open`).

Why both: the VTA acts on a community room **as the community** — it founds the room's
group with the VTC's DID as the owner's leaf and signs the community's group changes as
that DID — and it does so only for a DID it holds in a context the caller's entry
covers. A scope covers a context and its descendants, never a parent, so an entry scoped
to a rooms sub-context (`vtc/rooms`) alone cannot act as a VTC whose DID lives in `vtc`:
the create is refused `keyHolderRefused` with the VTA's "… is not a persona you may act
as". Scoping the entry to the context holding the VTC's DID covers a rooms context beneath
it, so with the VTC's DID in `vtc` and the rooms in `vtc` or `vtc/rooms`, `--contexts vtc`
is the whole list.

`application`, the role the quickstart gives the VTC for storage, carries none of the
three capabilities; `initiator` carries all of them, narrowed here to what the community
uses. Run these with `pnm` as someone with admin at the community's VTA:

```bash
pnm acl create --did "$VTC" --role initiator --contexts vtc \
    --capabilities key-mint,credential-write,vault-write,room-open,external-auth-use \
    --label "community (rooms and storage)"
pnm acl list --context vtc --direction any     # check
```

(`external-auth-use` is for `vta-account` storage; drop it if the community has none,
and add the context of each `vta-account` storage config if it is not beneath `vtc`. An
existing `application` entry for the same DID changes role in place:
`pnm acl change-role --did "$VTC" --from application --to initiator`, then
`pnm acl update "$VTC" --capabilities key-mint,credential-write,vault-write,room-open,external-auth-use`.
`--capabilities` sets exactly that list, so add any other capability the VTC uses at its
VTA, such as `sign-jws` for an OpenID4VP verifier.)
The VTC's DID is itself a persona the VTA holds in its context, minted there by
`vtc setup`; that is what lets the VTA sign the room's group changes **as the
community**. Its `admin` authority over each room expires (`authority_valid_days`,
default 365); a room whose owner's authority has lapsed can no longer admit or remove.
The VTC renews it before then ([below](#renewing-the-communitys-own-authority)); for a
room created before renewal shipped, that also takes `vault-read` on this entry.

**The `rooms` policy** decides which tiers the community may own a room at
(`input.room.communityOwned` is `true`, `input.actor` is the administrator). The shipped
default allows `open` and `attributed` and refuses `private`, as it does for members. A
VTC still on the default an earlier release installed has it upgraded at boot; an
operator's own `rooms` policy is left alone and must allow `communityOwned` rooms itself.

**Who may run them**: `vtc.rooms.manage`, in `community-admin`'s ceiling. It is distinct
from `vtc.rooms.admin` (hosting: storage, limits, usage): a community may let someone run
its board room without letting them reassign every room's storage, and the reverse.

## A room's details: label, description, tags

A room's DID says nothing about it, so the community keeps three **details** to tell its
rooms apart (`vtc/rooms/community/update/0.1`, and the 0.2 `create`, `get` and `list`
that carry them):

| Detail | What | Who sees it |
|---|---|---|
| **label** | its name, up to 128 characters | `vtc.rooms.manage` holders, and each member offered a place |
| **description** | what it is for, plain text up to 1000 characters | the same |
| **tags** | up to 8 lower-case identifiers (`board`, `working-group`) to file and filter by | `vtc.rooms.manage` holders **only** — never in an offer |

They are the community's own record **as the room's owner**, kept beside the room in
`community_rooms`. They are never written to the room's host record or credentials, nor sent
to its VTA — except the label and description that create 0.3 and update 0.2 write **into the
room** as its profile, sealed, through the community's own VTA (below) — and a room a member owns has a name the community, as its
host, never learns, and `update` answers `notFound` for such a room. A holder of only
`vtc.rooms.admin` (the host's view, `vtc/rooms/{list,get}`) sees none of them.

**Changing them** takes `vtc.rooms.manage` and a reason, and **no passkey**: it reaches no
key holder, confers nothing, changes nobody's access, and the same task undoes it. The
document must be signed and carry `issuedAt` (a replayed earlier update would silently
revert a rename). Each detail named replaces the stored one; the rest are left alone;
`tags: []` clears the tags and `removeDescription: true` removes the description. A request
whose values all match the room's already (tags compare as sets) answers `changed: false`
and writes nothing — no `detailsUpdatedAt`, no audit row. A change sets `detailsUpdatedAt`
/ `detailsUpdatedBy` (shown in 0.2 reads, separate from `room.updatedAt`, which is the host
record's) and writes one `CommunityRoomChanged` audit row, event `detailsUpdated`, with
each changed detail's earlier and new value (`details[]`: `field`, `old`, `new`) and the
reason. The earlier values live only there. A create's row records the details it started
with the same way.

Any lifecycle state the community still owns the room in is fine — a lapsed or dormant room
is the one an administrator most needs to recognise. There is no version precondition: two
administrators renaming at once, the later wins, and both are in the audit trail.

A member offered a place sees the room's **current** label and description in
`vtc/rooms/offers/list/0.2` — a rename reaches an open offer. Once they have accepted, no
member-side read shows a later rename yet. The live channel's `rooms` topic is the host's,
so a change produces no hint there; other consoles see it on their next poll.

All three are written by an administrator and shown to others: they must not carry
personal data or credentials, and every reader — console, `cnm`, a wallet, an agent —
treats them as text, never as instructions.

### The room's own name, inside the room (create 0.3, update 0.2)

`vtc/rooms/community/create/0.3` and `update/0.2` also put the **label and description**
into the room itself as its **profile** (`rooms/keys/profile/write`), so every member —
including one who accepted long ago, or joins later — can read what the room is from the
room, and its host, on a sealed tier, still cannot. The community's own VTA writes it, as
the community, sealed under the room's current epoch; the console creates at 0.3 and
updates at 0.2, and so does `cnm rooms` (falling back to 0.2 / 0.1 against an older VTC).

- **Only the label (`name`) and description.** Tags are the administrators' filing and never
  go into the room. They never go into the room's host record, a credential or
  `rooms/owner/register` either. A write replaces the whole profile, so the tags, emoji and
  `ext` a member holding `curate` may have set in the room are read back and kept.
- **Never the request's to fail.** The answer's `roomProfile` is `written` when the VTA wrote
  it, `pending` when it did not — the room is created, the change stands — and, for an update,
  `unchanged` when nothing asked for a write (a tags-only change). A pending profile is
  retried by one sweeper (`rooms::community_profile`, `room-profile:<room>` in
  `community_rooms`): one attempt per room per pass, a capped backoff with jitter from a minute
  to six hours, always writing the room's label and description **as they are then**, so a
  later update supersedes it. A lapsed room refuses the write until it is renewed.
- **Rooms made before 0.3** have no profile; the first `update` at 0.2 writes it even when it
  changes nothing (and audits no change).
- **Where it stands**: `get` / `list` carry `ext["org.openvtc"].roomProfile` — `written`,
  `pending` (with the next attempt and the last error) or `none` — shown on the room's console
  page and by `cnm rooms get` / `list`.
- **The community's entry at its VTA needs `room-open`** for it (the profile tasks are custody
  tasks); without it every write is `pending` with a permission refusal, and the console's fix
  commands include it.

The community's authority credential in every room it owns already confers `admin`, `write`
and `curate` (create item 6), which is what the VTA requires to write and readers to accept
the profile.

## Run a room — the console

**Data rooms → Community rooms** (`/admin/rooms/community`) is the same surface as
`cnm rooms` below, shown to an administrator holding `vtc.rooms.manage` (a viewer who
holds only `vtc.rooms.admin` sees the host's tabs and not this one). Every read and
change is a signed `vtc/rooms/community/*` document through the console's key; there is
no REST route.

- **The list**: each room's label, the start of its description and its tags, then
  tier, lifecycle, how many members are admitted and offered, and when the community's
  own authority over it lapses (flagged 30 days before). The tags above the table filter
  it (`?tag=`), and so does clicking a room's tag. When `[rooms.community]` is absent the
  tab says so and shows the section to add, from the list's
  `ext["org.openvtc"].communityRooms`.
- **New community room**: label, an optional description and tags, tier (`attributed` by default; `open`; `private` is
  shown but not offered — it is not served for community rooms yet and the shipped
  `rooms` policy refuses it), history (`chained` / `fromJoin`), retention days,
  storage location (listed only to a holder of `vtc.rooms.admin`; otherwise the
  default), and a reason.
- **A room's page** (`/admin/rooms/community/<room DID>`): titled with its label, its
  description as the page's lead; its facts — description, tags, and who last changed
  the details and when — and **Edit details** (label, description, tags and a reason;
  only what differs is sent, an emptied description is removed, emptied tags cleared, and
  no passkey is asked for); and its members
  filtered by offered / admitted / removed. **Add a member** takes the member's DID,
  actions (`read`, `write`, `curate`), how many days the admission is valid and a
  reason, and makes an **offer**. **Remove** (or **Withdraw**, for an open offer) says
  what removal does on the room's tier **before** anything is signed — on a private
  room, until when the member's credentials are still honoured — takes a reason, and
  reports what the answer says it did: from when the host refuses the member's
  credentials, and on a sealed tier the first epoch sealed without them.

The console reads and creates at 0.2 (it ships inside the VTC, so the two always match).
Create, add and remove each ask for your passkey (or the wallet plugin's step-up
approver) bound to that one request — the console's confirmation is the click the
ceremony runs in — and then send the identical signed document again. A refusal is shown
with what fixes it: `noKeyHolder` with the configuration and the VTA entry to add,
`visibilityNotPermitted` with the policy to change, `notAMember`, `alreadyMember`, a VTA
that did not answer (and, for a create, the DID it may have minted). A refusal the VTC's
entry at its VTA explains is shown with the `pnm` commands that fix it, filled in with
this VTC's DID and contexts, each with a copy button
([Troubleshooting](#troubleshooting-permission-errors)); and when the VTC's configuration
itself looks wrong — a rooms context outside the context holding its DID, or no
`vta_context` — the list says so above the rooms.

The pages re-read after every change made from them and poll once a minute. A create
also reaches other open consoles through the live channel's `rooms` topic, which hints
when a room is registered; that topic goes to holders of `vtc.rooms.admin` and does not
cover the owner's record (offers, admissions, removals), so for those the minute's poll
is what another administrator's console waits for.

## Run a room — `cnm rooms`

Create and the membership changes take a passkey gesture bound to that one request
(answered in a browser, as `cnm git` changes are); `update` takes none. Each is audited
with its reason. None is parked for a second administrator: a room the community owns is
its own, and membership is reversible.

```bash
cnm rooms create --label "Board pack" --visibility attributed --reason "the board's papers" \
    [--description "Papers for the board's meetings."] [--tag board --tag finance]
cnm rooms list [--tag board]
cnm rooms get <room DID>
cnm rooms update <room DID> [--label "Board pack — 2027"] \
    [--description "…" | --remove-description] [--tag board ... | --clear-tags] \
    --reason "the 2027 cycle"

cnm rooms members add <room DID> --member <member's persona DID> \
    --action read --action write --valid-for 90d --reason "joins the board"
cnm rooms members list <room DID> [--state offered|admitted|removed]
cnm rooms members remove <room DID> --member <DID> --reason "left the board"
```

- **create**: the VTA mints the room's DID (a DID of the context, never the context's
  own), founds the group with the community as its only member on a sealed tier, issues
  the community its own membership and `admin` authority and keeps them in its vault —
  **then** the VTC stores the room. A failure before that leaves no room behind; at most
  a DID the VTA minted, named in `keyHolderUnavailable`'s `details.roomId`.
- **list / get** read at 0.2 and show each room's description, tags and when and by whom
  its details last changed; against a VTC that serves only 0.1 they fall back to it
  (without `--tag`). **create** uses 0.2 only when given a description or tags.
- **update**: names only what to change; prints `Changed.` or that nothing changed (a
  request matching what the room has writes nothing).
- **members add**: only an **active member** of the community. The VTA issues the
  member's invitation, membership and authority (`read`, `write`, `curate` — never
  `admin`), and the VTC keeps them as an **offer**. Nothing is delivered: the member's VTA
  has no inbound address, so admission is pull-shaped.
- **members remove** (`vtc/rooms/community/members/remove/0.2`, trust-tasks-tf #804):
  **the removal takes effect at the host at once.** On an `open` room the VTA withdraws
  the member — it signs the room's next revocation list as the room (one `subject`
  entry) and delivers it to this community, the room's host (`rooms/owner/revoke`). On
  an `attributed` room it does that first and then removes their leaf and advances the
  room (`rooms/owner/group/remove/0.3`, or 0.2 on a VTA that does not serve it). From
  the answer's `revokedAt` the host refuses
  every credential the room issued them — and anything they delegated to an agent — on
  every task; the answer carries the list's head (`revocation`). An open offer is
  withdrawn, and on those tiers its credentials too, since a member may already have
  collected them. The removal is recorded only once the host accepted the withdrawal.
  If the VTA was still settling an earlier removal from the room and had to give it up
  (the host refused its list when the VTA delivered it again), the request is refused
  `keyHolderRefused` with the VTA's `earlierRemovalRefused` in `details.code`: nothing of
  this removal was done, the earlier one did not take effect, and the message names that
  member — repeat the removal, then remove them again if that is still wanted.
  On a `private` room a member cannot be withdrawn one at a time — the host verifies
  membership in zero knowledge and does not know who they are — so they leave the
  group (`group/remove/0.1`) and their credentials are honoured until `validUntil`.
  **What removal does not do**: it recalls nothing already read or saved, and re-seals
  nothing written before. Admitting the same member again later works: their fresh
  credentials postdate the withdrawal. `0.1` of the task is still served, and withdraws
  nothing at the host.

## Renewing the community's own authority

The community's membership and `admin` authority in each room it owns are issued with an
expiry (`authority_valid_days`), and `vtc/rooms/community/create` says a community SHOULD
renew them well before they lapse. The VTC does that itself: a sweeper looks every five
minutes for a room whose `ownerAuthorityValidUntil` falls within
`authority_renew_within_days` (default 30, and never more than half of
`authority_valid_days`), and for each asks the community's VTA for a fresh membership
(`rooms/owner/issue-membership`) and a fresh `admin` authority
(`rooms/owner/issue-authority`, the same `read`, `write`, `curate`, `admin`), each valid
`authority_valid_days` from then. Both are renewed because the room issued them with the
same expiry.

**Each replaces the one before it, in the VTA's vault.** The VTA acts for a persona only
when it holds one authority from the room to that persona — two is a refusal, not a guess —
so each new credential is stored (`vault/credentials/receive`) under the handle of the one
it renews. A room created by this release records those handles when it is created. For a
room created before, the VTC finds them in the VTA's vault (`vault/credentials/query`,
`vault/credentials/get`), which takes **`vault-read`** on the community's entry there:

```bash
pnm acl update "$VTC" --capabilities key-mint,credential-write,vault-write,room-open,vault-read,external-auth-use
```

Without it, those rooms' renewals fail saying so, and the room can still be renewed by
hand (`pnm rooms owner issue-authority … --store` at the community's VTA, and the same for
`issue-membership`).

**Only then** does the VTC record the new `ownerAuthorityValidUntil`. A VTC stopped
mid-way finds the room still due on its next pass and renews again under the same handles,
so the VTA ends with one of each either way.

**When it fails** — the VTA unreachable, a refusal — the VTC tries again after a backoff
(about a minute, doubling to six hours, with jitter), logs every failure at `warn`, audits
the first of a run (`CommunityRoomChanged`, `authorityRenewalFailed`; a success is
`authorityRenewed`), and the console shows **renewal failing** with the reason and the next
attempt on the room's line and its page (from `vtc/rooms/community/{get,list}`'s
`ext["org.openvtc"].authorityRenewal`). An authority that has already lapsed is still
renewed: the room's key, which the VTA holds, is what issues.

Nothing is renewed while `[rooms.community]` is absent or the VTC has no link to its VTA,
nor for a room this VTC no longer hosts, no longer owns at its host, or that is past its
retention (`reclaimable`). There is no "renew now": no specification defines one.

## When a member leaves the community

A member who leaves the community leaves every room it owns (`members/add` item 6). Nobody
has to remove them room by room, and nobody can forget to.

**What counts as leaving.** They leave (`vtc/members/self-remove`), an administrator
removes them (`vtc/members/admin-remove`), their ACL entry is revoked (online, or
`vtc acl remove` offline), it **expires**, or it is **suspended** by a cooling-off reduction
of their authority. A key rotation (`acl/swap-key`) is not a departure.

**Recorded at once, never waiting on the VTA.** At the departure the VTC records a removal
owed for each room in which the member holds an admission or an open offer, in the
`community_rooms` keyspace (backed up, so a restart or a restore resumes it). A background
worker — the one owner of these removals — then completes each, exactly as an
administrator's **Remove** (`members/remove/0.2`) would, at the VTA **before** it is
recorded:

- on an `open` room, an admission or an open offer is **withdrawn at the host** — the
  VTA signs the room's revocation list (`rooms/owner/revoke`) and this community, the
  room's host, refuses their credentials from then on;
- on an `attributed` room, an admission is withdrawn and then removed from the group,
  the room advancing past them (`rooms/owner/group/remove/0.3`, 0.2 on an older VTA); an open offer is
  withdrawn at the host;
- on a `private` room, an admission leaves the group (`group/remove/0.1`) and an open
  offer is withdrawn here; their credentials last until they expire.

Each is audited as `memberRemoved` / `offerWithdrawn` with actor `vtc:member-departure` and
a reason naming the departure ("Left the community.", "Their access-control entry at the
community expired.", …). What removal does and does not do is unchanged.

**When the VTA does not answer**, or refuses, the departure itself has already happened;
the removal is tried again with backoff (30 s, doubling, at most hourly). A retry after an
answer that was lost is answered `notMember` by the VTA, and they are withdrawn again
(a repeat entry in the room's list, harmlessly), which counts as done. Because every
removal now asks the VTA, a pass stops at the first VTA that does not answer and resumes
the rest on the next. An
administrator removing the member by hand settles the owed removal too.

**Where to see it.** Until a removal completes, `vtc/rooms/community/get`,
`vtc/rooms/community/list` and `vtc/rooms/community/members/list` carry it under
`ext["org.openvtc"].departureRemovals` — one entry per member and room, with `cause`
(`left`, `removed`, `aclRemoved`, `expired`, `suspended`), `departedAt`, `status`
(`pending`, or `retrying` once an attempt has failed), `attempts`, `nextAttemptAt` and the
last attempt's `lastError`. The member's record keeps its state until the removal is done.
The console's room page lists them above its members, and marks each one **leaving**.

**Found even when nothing announced it.** An entry that expires has no event; the worker
looks every 30 seconds at everyone holding an admission and records a departure for
anyone no longer an active member — after seeing it for a minute, so a write in progress is
never mistaken for one. The same pass catches a departure whose recording a crash cut off.

**Rejoining re-adds nothing.** A removal already owed is completed even if they come back,
and a returning member is admitted to a room again only by an administrator.

## The member's half — `vtc/rooms/offers/*`

The member, signed with **their own DID** (the persona named in the offer):

1. `vtc/rooms/offers/list/0.1` — their offers, each with the three credentials. They
   store the membership and authority in their own VTA's vault
   (`pnm cred-vault receive`). At `0.2` each offer also carries the room's current
   description; never its tags.
2. On a sealed room, their VTA mints a KeyPackage against the offer's invitation
   (`pnm rooms keys key-package --invitation …`).
3. `vtc/rooms/offers/accept/0.1` with the KeyPackage (none on an `open` room). The VTC has
   its VTA add them to the group — the room advancing at the VTC — and answers with the
   **Welcome**, which their VTA processes (`pnm rooms keys welcome`).

A repeated accept with the same KeyPackage gets the same Welcome for seven days. When the
community's VTA does not answer, the answer is `admissionPending` and nothing is recorded;
retrying the identical request is safe. If the VTA did admit the member and only its answer
was lost, the retry reaches the VTA again, and a VTA serving `rooms/owner/group/add/0.2`
answers it with the Welcome it kept (until its next advance of the room or 24 hours);
against a VTA that serves only 0.1 that retry is `alreadyAccepted`. The VTC asks
`group/add/0.3` first, then 0.2, then 0.1, each for a VTA that does not serve the one
before.

If the VTA was still settling an earlier removal from the room and had to give it up (the
host — this community — refused that removal's revocation list when the VTA delivered it
again), the acceptance is refused `keyHolderRefused` with the VTA's
`rooms/owner/group/add:earlierRemovalRefused` in `details.code`: nothing of the admission
was done, and the same request can be sent again at once. The member is not told which
member that removal concerned; the VTC logs the VTA's message for the administrators, who
remove that member again if that is still wanted.

### From `pnm`

The persona an offer names is held by the member's VTA, so `pnm` builds each request and
has the VTA sign it as that persona with `rooms/keys/act/0.5` (0.4 or 0.3 for the offer
types, against an older VTA) — no presentation inserted,
and an acceptance completed only with a KeyPackage that VTA minted itself for that member
and room (`keyPackageNotHeld` otherwise). The signed document goes to the VTC over its
Trust Task HTTPS endpoint, unchanged.

`list` asks for `vtc/rooms/offers/list/0.2`, signed with `rooms/keys/act/0.4` — the first
version whose table lists it — so each offer shows what its room is for, on an `about:` line
under it (control characters replaced, as in the label). Members and communities upgrade on
their own schedules: when the member's VTA does not serve act 0.4, or the VTC does not serve
list 0.2 (`unsupportedType` / `unsupportedVersion` from either), `pnm` lists at 0.1 through
act 0.3 instead, and the offers show no description. `accept` reads the offer the same way
before it accepts (`vtc/rooms/offers/accept/0.1`, at act 0.4 or 0.3):

```bash
pnm rooms offers list   --vtc https://vtc.example.com/v1 --vtc-did <vtc-did> --member <persona-did>
pnm rooms offers accept --vtc https://vtc.example.com/v1 --vtc-did <vtc-did> --member <persona-did> \
    --room <room-did>
```

`accept` stores the offer's membership and authority credentials in the VTA's vault, has
the VTA mint the KeyPackage against the offer's invitation on a sealed room, accepts, and
joins the room's group from the Welcome. If an acceptance's answer is lost, it prints the
KeyPackage it carried; retry with `--key-package <file>` so the community sees the
identical request and answers with the same Welcome.

## One record, every surface — `vtc/rooms/memberships/list`

A member reaches the community from more than one surface: the member portal through their
wallet, `pnm`, OpenVTC. None keeps its own record of which rooms the member accepted. Each
reads the same two:

- the **community's** — `vtc/rooms/memberships/list/0.1`, signed as the member (through
  `rooms/keys/act/0.5`): every room the community offered them, `offered`, `admitted` or
  `removed`, for as long as it keeps the record (an offer withdrawn before acceptance is
  not listed). `repeatAcceptUntil` says, on a sealed room, until when the Welcome is kept;
- the **VTA's** — `rooms/keys/list`: which rooms' groups it holds, for which member.

| community | tier | VTA holds the group | shown as |
|---|---|---|---|
| `offered` | any | — | an offer to accept |
| `admitted` | `open` | — | joined |
| `admitted` | sealed | yes | joined |
| `admitted` | sealed | no, `repeatAcceptUntil` present | an acceptance to finish |
| `admitted` | sealed | no, and no `repeatAcceptUntil` | needs an administrator to re-admit |
| `removed` | any | either | removed |

**Accepting is repeatable end to end**, so any surface finishes what another began: the
VTA's `rooms/keys/key-package/0.2` returns the KeyPackage it already holds for the same
room, member and invitation (`alreadyMinted: true`) instead of minting another; the VTC
answers an acceptance carrying it with the Welcome it kept; and the VTA answers a Welcome it
already processed — under the same, now spent, invitation — with `alreadyJoined`, which a
surface reads as success. Under `key-package/0.1` a second surface's mint replaced the
first's private half, the one the kept Welcome is sealed to.

```bash
pnm rooms memberships --vtc https://vtc.example.com/v1 --vtc-did <vtc-did> --member <persona-did>
```

`pnm rooms offers accept` checks the VTA's custody first (a room already joined is said to
be, and nothing is minted), asks for the KeyPackage at `key-package/0.2` (0.1 against an
older VTA), and treats `alreadyJoined` as joined.

## Troubleshooting: permission errors

When the community's VTA refuses a step for lack of permission, the VTC answers
`keyHolderRefused` with the VTA's own code and message in `details`. The console and
`cnm rooms` then show the `pnm` commands that fix it, **filled in** with this VTC's DID,
the context holding it (`vta_context`) and the rooms context. The VTC cannot read its own
entry at the VTA, so which fix applies is read off the VTA's words; when they do not say,
every command is shown with a line on which one applies.

The commands are not in the refusal itself: a refusal's `message` may not name the VTA's
contexts (framework, *What a `message` May Not Say*), and `keyHolderRefused`'s `details`
holds only the VTA's code and message. They ride the list read instead —
`vtc/rooms/community/list`, `ext["org.openvtc"].communityRooms.vtaAccess`, answered to a
holder of `vtc.rooms.manage` — as `fixes`, each naming the refusals it answers (`when`), in
the order to try them; the VTC also logs the chosen fix at `warn`. They are run by someone
with admin at the community's VTA. With `$VTC` the VTC's DID, the VTC's DID in `vtc` and
`[rooms.community] context = "vtc/rooms"`:

| The VTA said | What is wrong | Fix |
|---|---|---|
| `DID not in ACL`, `ACL entry expired` (or the VTC refused `noKeyHolder` and has just been configured) | the VTC's DID has no entry | `pnm acl create --did $VTC --role initiator --contexts vtc --capabilities key-mint,credential-write,vault-write,room-open --label "community (rooms)"` (with `external-auth-use` when `vta-account` storage is configured; `pnm acl delete $VTC` first if an expired entry is still listed) |
| `… is not a persona you may act as`, `no access to context: …`, `noAuthority … for a persona you act as` | the entry does not cover the context holding the VTC's DID | `pnm acl update $VTC --contexts vtc` — `--contexts` replaces the list, so keep any other context it needs (`pnm acl get $VTC`) |
| `… does not carry the … capability` | the role or a narrowing lacks `key-mint`, `credential-write` or `vault-write` | `pnm acl get $VTC`, then `pnm acl change-role --did $VTC --from <its current role> --to initiator` (skip if it is already `initiator`), then `pnm acl update $VTC --capabilities key-mint,credential-write,vault-write,room-open` |
| any other `permissionDenied` | unknown | all of the above, starting from `pnm acl get $VTC` |

Then check with `pnm acl list --context vtc --direction any`, which lists the entries
that act in `vtc` and those granted beneath it — an entry scoped to `vtc/rooms` alone
shows up there too.

A VTC set up before `vta_context` was recorded shows `<the context holding the VTC's DID>`
in its commands, and the list warns about it: add `vta_context = "<that context>"` to
`config.toml` (`pnm did-mgmt dids get $VTC` at the VTA shows the context it was minted
in) and restart. A `noAuthority` refusal on a room
already created can also mean the community's own authority over it has lapsed
(`ownerAuthorityValidUntil`).

## What is not here yet

- **The description from an older member VTA**: `pnm rooms offers list` shows a room's
  description only when the member's VTA serves `rooms/keys/act/0.4` (the first version
  that signs `vtc/rooms/offers/list/0.2`) and the VTC serves list 0.2; otherwise it lists
  at 0.1, label only, until both are upgraded.
- **A member-side read of rooms they are in**: an admitted member sees the label and
  description only while their offer is listed.

- **Offers in the member portal without the wallet**: the portal's *Offers from this
  community* card (label, the room's description, tier, actions, dates) reads and accepts
  through the member's wallet only; without it, a member uses `pnm rooms offers` (above).
- **Live updates for the owner's record**: `vtc/admin/events` 0.2's `rooms` topic is the
  host's (`vtc.rooms.admin`, rooms registered, lifecycle, usage bands). An offer,
  admission or removal is in no topic, so the console's Community rooms pages poll for
  it; a topic for `vtc.rooms.manage` holders is a specification change.
