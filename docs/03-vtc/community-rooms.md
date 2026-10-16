# Rooms the community owns

A community hosts data rooms its members own ([quickstart](data-rooms-quickstart.md)).
It can also **own** rooms itself — the board's papers, a working group's drafts, a
members' library — run by its administrators and outliving any one of them. This page
is how to turn that on and run one. The design is
[`data-rooms-files.md` §8.4](../05-design-notes/data-rooms-files.md#84-community-owned-rooms);
the wire is `vtc/rooms/community/*` and `vtc/rooms/offers/*` (trust-tasks-tf #768).

## Who holds what

| | |
|---|---|
| **Owner** | the community: the room's `ownerDid` is the VTC's own DID |
| **Key holder** | the community's **VTA**: it mints the room's DID from the `room` template, signs the room's credentials, and holds the community's place in a sealed room's MLS group |
| **Host** | the VTC, as for every room it stores |

The VTC holds **no room key and no group secret**. It acts on a room the way any owner's
client does — by sending its VTA the `rooms/owner/*` tasks the VTA serves for every owner
(`group/create`, `invite`, `issue-membership`, `issue-authority`, `group/add`,
`group/remove`) — over the messaging link it already keeps to its VTA (TSP, else
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
room's credentials (`credential-write`) and keep the community's own in the vault
(`vault-write`).

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
    --capabilities key-mint,credential-write,vault-write,external-auth-use \
    --label "community (rooms and storage)"
pnm acl list --context vtc --direction any     # check
```

(`external-auth-use` is for `vta-account` storage; drop it if the community has none,
and add the context of each `vta-account` storage config if it is not beneath `vtc`. An
existing `application` entry for the same DID changes role in place:
`pnm acl change-role --did "$VTC" --from application --to initiator`, then
`pnm acl update "$VTC" --capabilities key-mint,credential-write,vault-write,external-auth-use`.
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

## Run a room — the console

**Data rooms → Community rooms** (`/admin/rooms/community`) is the same surface as
`cnm rooms` below, shown to an administrator holding `vtc.rooms.manage` (a viewer who
holds only `vtc.rooms.admin` sees the host's tabs and not this one). Every read and
change is a signed `vtc/rooms/community/*` document through the console's key; there is
no REST route.

- **The list**: each room's label, tier, lifecycle, how many members are admitted and
  offered, and when the community's own authority over it lapses (flagged 30 days
  before). When `[rooms.community]` is absent the tab says so and shows the section to
  add, from the list's `ext["org.openvtc"].communityRooms`.
- **New community room**: label, tier (`attributed` by default; `open`; `private` is
  shown but not offered — it is not served for community rooms yet and the shipped
  `rooms` policy refuses it), history (`chained` / `fromJoin`), retention days,
  storage location (listed only to a holder of `vtc.rooms.admin`; otherwise the
  default), and a reason.
- **A room's page** (`/admin/rooms/community/<room DID>`): its facts, and its members
  filtered by offered / admitted / removed. **Add a member** takes the member's DID,
  actions (`read`, `write`, `curate`), how many days the admission is valid and a
  reason, and makes an **offer**. **Remove** (or **Withdraw**, for an open offer) says
  what removal does on the room's tier and until when the member's authority is
  honoured **before** anything is signed, takes a reason, and reports the answer's
  `validUntil` and, on a sealed tier, the first epoch sealed without them.

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

Each change takes a passkey gesture bound to that one request (answered in a browser,
as `cnm git` changes are) and is audited with its reason. None is parked for a second
administrator: a room the community owns is its own, and membership is reversible.

```bash
cnm rooms create --label "Board pack" --visibility attributed --reason "the board's papers"
cnm rooms list
cnm rooms get <room DID>

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
- **members add**: only an **active member** of the community. The VTA issues the
  member's invitation, membership and authority (`read`, `write`, `curate` — never
  `admin`), and the VTC keeps them as an **offer**. Nothing is delivered: the member's VTA
  has no inbound address, so admission is pull-shaped.
- **members remove**: an open offer is withdrawn. An admitted member of a sealed room
  leaves the group and the room advances to an epoch sealed to everyone else, before the
  removal is recorded. **What removal does not do**: it recalls nothing already read, and
  the member's authority credential is not revoked — a host honours it until it expires,
  though on a sealed room it opens nothing written afterwards. On an `open` room it
  withdraws nothing cryptographically, so admit with short `--valid-for` there.

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
pnm acl update "$VTC" --capabilities key-mint,credential-write,vault-write,vault-read,external-auth-use
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

## The member's half — `vtc/rooms/offers/*`

The member, signed with **their own DID** (the persona named in the offer):

1. `vtc/rooms/offers/list/0.1` — their offers, each with the three credentials. They
   store the membership and authority in their own VTA's vault
   (`pnm cred-vault receive`).
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
against a VTA that serves only 0.1 that retry is `alreadyAccepted`.

### From `pnm`

The persona an offer names is held by the member's VTA, so `pnm` builds each request and
has the VTA sign it as that persona with `rooms/keys/act/0.3` — no presentation inserted,
and an acceptance completed only with a KeyPackage that VTA minted itself for that member
and room (`keyPackageNotHeld` otherwise). The signed document goes to the VTC over its
Trust Task HTTPS endpoint, unchanged:

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
| `DID not in ACL`, `ACL entry expired` (or the VTC refused `noKeyHolder` and has just been configured) | the VTC's DID has no entry | `pnm acl create --did $VTC --role initiator --contexts vtc --capabilities key-mint,credential-write,vault-write --label "community (rooms)"` (with `external-auth-use` when `vta-account` storage is configured; `pnm acl delete $VTC` first if an expired entry is still listed) |
| `… is not a persona you may act as`, `no access to context: …`, `noAuthority … for a persona you act as` | the entry does not cover the context holding the VTC's DID | `pnm acl update $VTC --contexts vtc` — `--contexts` replaces the list, so keep any other context it needs (`pnm acl get $VTC`) |
| `… does not carry the … capability` | the role or a narrowing lacks `key-mint`, `credential-write` or `vault-write` | `pnm acl get $VTC`, then `pnm acl change-role --did $VTC --from <its current role> --to initiator` (skip if it is already `initiator`), then `pnm acl update $VTC --capabilities key-mint,credential-write,vault-write` |
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

- **Offers in the member portal**: a member lists and accepts their offers with `pnm
  rooms offers` (below); the portal has no screen for them yet.
- **Live updates for the owner's record**: `vtc/admin/events` 0.2's `rooms` topic is the
  host's (`vtc.rooms.admin`, rooms registered, lifecycle, usage bands). An offer,
  admission or removal is in no topic, so the console's Community rooms pages poll for
  it; a topic for `vtc.rooms.manage` holders is a specification change.
- **Removing a departing member from every room the community owns** when they leave
  the community (`members/add` item 6, a SHOULD): today an administrator removes them
  room by room.
