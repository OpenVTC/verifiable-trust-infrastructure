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

[messaging]                                 # the link to the VTA rides it
mediator_did = "<mediator DID>"

[rooms.community]
context = "vtc"                             # the VTA context the rooms' keys are minted in
# webvh_server = "<hosting server id at the VTA>"   # absent: this VTC serves each room's log
# mediator_did = "<DID>"                    # the rooms' DIDComm mediator; default [messaging]
# authority_valid_days = 365                # the community's own admin authority per room
```

**Where a room's DID is published.** A room's DID must resolve before its credentials
can be checked — the VTA verifies the community's own credentials as it stores them.

- With `webvh_server`, the VTA publishes each room's log on that hosting server
  (registered at the VTA with `pnm webvh servers register`).
- Without it, the room's DID is minted serverless at
  `<public_url>/room-dids/<id>/did.jsonl`, and **this VTC serves the log** there, on
  every host, like its own `/.well-known/did.jsonl`. `public_url` must be set.

**At the community's VTA**, the VTC's own DID needs an entry in `context` that may mint
DIDs (`key-mint`), issue a room's credentials (`credential-write`) and keep the
community's own in the vault (`vault-write`). `application`, the role the quickstart
gives the VTC for storage, carries none of the three; `initiator` carries all of them,
narrowed here to what the community uses:

```bash
pnm acl create --did "$VTC" --role initiator --contexts vtc \
    --capabilities key-mint,credential-write,vault-write,external-auth-use \
    --label "community (rooms and storage)"
```

(`external-auth-use` is for `vta-account` storage; drop it if the community has none.
An existing `application` entry for the same DID changes role in place:
`pnm acl change-role --did "$VTC" --from application --to initiator`, then
`pnm acl update "$VTC" --capabilities key-mint,credential-write,vault-write,external-auth-use`.)
The VTC's DID is itself a persona the VTA holds in that context, minted there by
`vtc setup`; that is what lets the VTA sign the room's group changes **as the
community**. Its `admin` authority over each room expires (`authority_valid_days`,
default 365); a room whose owner's authority has lapsed can no longer admit or remove.

**The `rooms` policy** decides which tiers the community may own a room at
(`input.room.communityOwned` is `true`, `input.actor` is the administrator). The shipped
default allows `open` and `attributed` and refuses `private`, as it does for members. A
VTC still on the default an earlier release installed has it upgraded at boot; an
operator's own `rooms` policy is left alone and must allow `communityOwned` rooms itself.

**Who may run them**: `vtc.rooms.manage`, in `community-admin`'s ceiling. It is distinct
from `vtc.rooms.admin` (hosting: storage, limits, usage): a community may let someone run
its board room without letting them reassign every room's storage, and the reverse.

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

## What is not here yet

- **Console pages** (create, members, offers in the portal) — the tasks are served;
  the screens are follow-up work.
- **Renewing the community's own authority** before `ownerAuthorityValidUntil`: reissue
  with `pnm rooms owner issue-authority` at the community's VTA for now.
- **Removing a departing member from every room the community owns** when they leave
  the community (`members/add` item 6, a SHOULD): today an administrator removes them
  room by room.
