# Member badges

A badge is a picture with a name a member earns, holds and shows on their directory
card: hosting a workshop, a year in the community, coming to an event, or simply being
thanked by another member. Badges are the community's gamification layer. They carry no
authority: nothing a badge says is ever read by an authorization decision.

Specification: the VTI Community Badges chapter (VTI-BDG-001 – 095). Wire: the
`vtc/badges/*` 0.1 Trust Tasks. Design: [`vtc-badges.md`](../05-design-notes/vtc-badges.md).

## Two kinds

| | Community badge | Kudos badge |
|---|---|---|
| Defined by | a holder of `vtc.badges.admin` | any active member the settings admit |
| Given by | its **owners** | **any** active member, to any other |
| Backed by | a **badge group** with its own DID | nothing |
| Credential | an Open Badges 3.0 credential the group issues | none |
| Repeats | if marked `repeatable` | always; each giving counts |

**A community badge is a badge group.** Creating one creates a community group
(see [groups](groups.md)) that backs it: the badge's owners are the group's managers, its
holders the group's members, and the group's own DID signs each holder's badge
credential. Asking for a badge is `vtc/groups/join` on its group, decided by the owners
with `vtc/groups/requests/decide`. Appointing or removing an owner is
`vtc/groups/managers/{add,remove}`. Retiring the badge deletes the group, which revokes
the community's authority credential to it and so every credential it issued. A badge
group never carries authority, is not listed among the community's groups, and is not
counted among the groups two members share.

## Turning it on

Badges are off until an administrator turns them on with `vtc/badges/settings/update`
(`vtc.config.admin` and a step-up bound to the request). The settings:

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Off hides every badge surface and keeps every record; nothing is revoked, and nothing is given while off |
| `kudosMakers.policy` | `members` | Who may make a kudos badge: `nobody`, `roles` (holders of `roles`, or members of `groups`), or every active member |
| `limits.kudosPerGiverPerDay` | 10 | Kudos one member may give in a day |
| `limits.sameGiverSameMember` | `day` | The same member gives the same member kudos at most once a `day`, a `week`, or `unbounded` |
| `limits.minTenureDays` | 7 | Days of membership before giving kudos or making a kudos badge |
| `limits.kudosBadgesPerMakerPerMonth` | 5 | Kudos badges one member may make a month |
| `limits.maxPinned` | 2 | Badges a member may pin beside their name |
| `limits.offerExpiresAfterDays` | unset | Days an unanswered offer stands |
| `showKudosTotals` | `true` | Whether a member's kudos total shows on their wall |
| `automaticBadges` | `false` | Whether a community badge may be automatic (a dynamic badge group) |
| `membersMayRequest` | `true` | Whether a community badge may be marked `requestable` |

Community badges need what groups need: a link to the community's VTA and a `[groups]`
section, since the badge group's DID is minted there.

## An award is an offer until accepted

Giving a community badge (`vtc/badges/awards/offer`, by an owner) or a kudos badge
(`vtc/badges/kudos/give`, by any member) records an **award** in state `offered`. Nothing
is admitted to the badge group, issued or shown until the recipient accepts it
(`vtc/badges/mine/accept`). Then, for a community badge, the group's DID signs the badge
credential through the community's VTA and offers it to the member's wallet, and only
after that is the membership recorded. Declining (`mine/decline`) records nothing in any
group; the owners see the offer closed, and the badge can be offered again. An owner may
withdraw an open offer (`awards/withdraw`) or take an accepted award back
(`awards/revoke`), which ends the membership when it was the holder's last award of the
badge.

A repeatable badge accepted again appends an award: the holder's count rises and the
credential is re-issued with every accepted award as evidence.

The badge group's own paths give and end the badge the same way:

| Path | What it does to the badge |
|---|---|
| A member asks (`vtc/groups/join`) and an owner approves (`requests/decide`) | The approved request is the member's consent (VTI-BDG-024): an accepted award is recorded, given by the approving owner, as the evidence of the credential issued on admission |
| An automatic badge's rule admits a member | An accepted award the rule made (no giver), likewise (VTI-BDG-013) |
| An owner adds a member (`vtc/groups/members/add`) | Refused: a badge is given by an offer the member accepts (VTI-BDG-020) |
| The holder leaves, or opts out of an automatic badge (`vtc/groups/leave`) | Their awards of it are closed as declined |
| An owner removes the holder (`members/remove`), or the rule stops admitting them | Their awards of it are taken back |

Whenever the holding ends, any share of it stops and the credential's status is revoked
where it carries one (VTI-BDG-063), as a take-back does.

## Automatic badges and their counts

An automatic badge's rule reads verified facts as any dynamic group's does — role, an
administrator- or credential-sourced field, personhood, the join date — and, a badge's alone,
three counts the community keeps of its own records (VTI-BDG-015), each compared with
`atLeast` and a `count`:

| Fact | Counts |
|---|---|
| `kudosReceived` | Kudos awards the member accepted |
| `ideasSelected` | Ideas they proposed that a board selected |
| `electionTickets` | Elections in which the community issued them a ticket — never whether a ballot was cast, which the community never knows |

```json
{ "all": [ { "fact": "kudosReceived", "op": "atLeast", "count": 10 } ] }
```

The counts are read whenever the rule is evaluated: the groups' sweeper recomputes every few
minutes and at once after a kudos is accepted, an idea is selected or a ticket is issued. Any
other group's rule refuses them (`ruleInvalid`). In the console, *Given automatically by a
rule* offers them beside the other facts.

## Claim codes for events

A badge's owner, or a holder of `vtc.badges.admin`, issues a **claim code** for a community
badge — to hand out at an event — with what it is for, when it stops admitting anyone (at
most 90 days ahead) and how many claims it admits (`vtc/badges/claims/create`,
VTI-BDG-025). The code is 256 random bits, shown to the issuer once; the community keeps only
its digest. A member who enters it (`vtc/badges/claims/redeem`) holds the badge at once — the
redemption is their consent — with an award whose giver is the issuer, the credential issued
first (VTI-BDG-026). A code that is unknown, past its time, out of claims, withdrawn or for a
retired badge is refused alike; nobody claims one code twice, and a badge held once is not
claimed again. The owners list a badge's codes with their claims (`claims/list`, never a
code) and withdraw one (`claims/withdraw`); claims already made stand, and retiring the
badge withdraws its codes (VTI-BDG-027). In the console: *Claim codes* on a community badge's
page; in the portal: *Have a code?* on the badges page.

## The credential

A badge group issues each holder an Open Badges 3.0 `OpenBadgeCredential` in place of a
group membership credential: `issuer` the group's DID, `credentialSubject.id` the holder's
membership DID, the badge as the `Achievement` with the community as its `creator`, the
community's own `EndorsementCredential` of the Achievement embedded on it (signed by the
community's VTA as the community, once per badge, and kept), and one `evidence` entry per
accepted award. An outside verifier sees who stands behind the issuer from the credential
alone; the community's authority credential to the badge group says the same.

Two regimes, chosen per badge by `shareableOutside` when it is defined or promoted and fixed
from then on:

- **Inside only** (the default): short-lived (`[groups] credential_valid_days`, default 30)
  and renewed by the groups' renewal sweeper while the holder stays, with no status
  mechanism, as a group membership credential. Taking the badge back stops the renewal.
- **May be shown outside**: long-lived (`settings.credentialValidDays`, default 730; 30 to
  3650) with a `credentialStatus` slot in the **community's** revocation list, the one every
  community credential uses, allocated at random: one slot per badge and holder, reused by
  every re-issue and renewal. The community flips the bit when the badge is taken back,
  retired or the holder departs. The status list credential is the community's while the
  badge credential's issuer is the group; the W3C Bitstring Status List algorithm compares
  no issuers and expects they may differ.

A badge that may be shown outside also has two **public artefacts** at stable locations its
credentials name (VTI-BDG-051), served without authentication to any Open Badges verifier:

| Location | What |
|---|---|
| `<public_url>/badges/<badgeId>` | The badge's Achievement document (`application/ld+json`), with the community as its creator and the community's endorsement |
| `<public_url>/badges/<badgeId>/image` | The badge's picture, the community's own re-encoding |

Neither names a holder or a count (VTI-BDG-071). A badge kept inside the community answers
`404` at both, as an unknown one does: its picture is shown to active members only, through
`vtc/badges/images/get` (VTI-BDG-050). The routes sit at the parent root beside the identity
logs and pass the host-surface gate on every host. Without `public_url` the credential names
the Achievement and picture by URN and digest instead.

## Showing an award outside

A holder shows one of their awards outside the community award by award, by their own
choice (`vtc/badges/awards/share`, VTI-BDG-070), and only for a badge marked
`shareableOutside`. The community answers two public locations under a token of 256
random bits made for that share and derived from nothing:

| Location | What |
|---|---|
| `<public_url>/badges/shared/<token>` | The holder's badge credential **exactly as issued**, with its status in the community's revocation list (`application/vc+ld+json`), to any verifier; to a browser (`Accept: text/html`), a page saying what the community verifies of it: issued by it, in its validity period, not revoked |
| `<public_url>/badges/shared/<token>/image.png` | The badge's picture as a PNG with that credential baked in (an Open Badges `iTXt` chunk, keyword `openbadgecredential`), for a website or an email signature |

Neither names another holder or how many hold the badge (VTI-BDG-071). The credential served
is the one last issued to the holder for that badge, kept each time one is issued in the
outside regime, so a repeat award or a renewal is served at the same locations. A holder
whose credential predates that is issued it again on their first share. Sharing again
answers the same locations. The share ends — the locations answer `404`, as a token never
issued does — when the holder stops it (`vtc/badges/awards/unshare`, which revokes nothing),
when the award is taken back, when the badge is retired and when the holder departs. Without
`public_url`, `share` answers `publicLocationUnavailable`. A kudos badge, or one kept inside,
answers `notShareable`.

The credential names the holder by their membership identifier and carries each award's
note, so the portal says so before a member shares.

## In the member portal and the console

Members use the holder's tasks with the portal's delegated key (`vtc/badges` is in the
portal's signing scope): their own list (`mine/list`), accepting and declining, hiding and
showing a badge (`mine/hide`, `mine/show`: hidden is portal-only — the badge leaves their
wall, the holder list and the counts, while owners and administrators see the holder
marked hidden), arranging and pinning (`mine/arrange`), a member's wall (`wall/show`), a
badge's holders (`holders/list`), giving kudos, and making a kudos badge. Defining,
changing, retiring and promoting a community badge, offering and taking back awards,
listing a badge's awards and changing the settings take the administrator's or owner's
own key.

**In the member portal** (`#/badges`): the offers waiting for the member, accepted or declined
one by one; what shows on their card, in their order, pinned up to the community's limit,
hidden or shown again, and who sees it (members who see their card, or nobody); every badge
they may browse, each opening to the badge and who holds it; asking a community badge's
owners for it, which is a request to join its badge group; giving a kudos badge from the
badge's page or from another member's card; and making a kudos badge of their own
(`#/badges/new`), with a picture uploaded from the browser. A member's card shows their
wall, pinned badges first, with their kudos total where the community shows totals. The
home page says how many badges show and how many offers wait. On a badge they hold that may
be shown outside, *Show it outside the community* lists their awards of it, each with
**Share outside** and, once shared, the link to check it, the picture with the credential
inside, and **Stop sharing** (`vtc/badges/show` answers the member's own awards as
`myAwards`).

**In the console** (*Community → Badges*): every badge the administrator or owner may see;
the settings (on or off, who may make a kudos badge, the limits; `vtc.config.admin` and a
step-up with the administrator's passkey); defining a community badge (`vtc.badges.admin`):
its picture, rules, who sees its holders, and its owners; and one badge's page: changing
it, giving it to chosen members or to everyone in a group, deciding the requests for it,
appointing and removing owners, every award given and taken back with a reason, a kudos
badge's givings and its promotion to a community badge, and retiring it (a community
badge's retirement takes the step-up too). The nav entry shows to holders of
`vtc.badges.admin`, `vtc.groups.manage` (an owner's qualified grant) or `vtc.config.admin`.

## Pictures

A badge's picture goes through the directory's picture pipeline (`vtc/badges/images/upload`):
decoded, scaled, re-encoded with every metadata block removed, and stored under the
community's own digest, never a byte as sent. An upload is the uploader's until a badge
holds it; `create` and `update` accept a digest only from the signer's own upload that no
other badge holds, and an upload no badge takes up within 24 hours is erased.
`images/get` answers the picture of a badge the caller may see.

## The trust registry

Where the community publishes to a trust registry, each active community badge's group is
published there as an issuer the community recognises (VTI-BDG-080): one authorization
record under the community's authority, `{entity: the group's DID, action: issue, resource:
the badge's Achievement id}` — the identifier every credential of the badge names — with a
`context` of `{kind: "vtcBadgeIssuer", badgeId}`. The record never carries the badge's name
or picture. Kudos badges have no group and are not published.

An outside verifier asks the registry whether the community stands behind the issuer of a
badge, and the community's status set whether the award still stands: the two answer
different questions, and neither replaces the other.

The community's own records stay the source of truth. A projector publishes what is
missing, removes a retired badge's record, and retries anything the registry refused, on a
one-minute tick and at once after a badge is defined, promoted or retired. Every fifteen
minutes it checks itself against the badge records the registry holds, where the registry
can list them. It runs only when a registry and the community's DID are both configured,
and needs the registry reachable over TSP or DIDComm (REST has no write surface). It never
touches the community's other `issue` records.

## Departure and audit

A member's departure ends their badge-group memberships, withdraws their open offers, stops
every share of theirs, removes their wall preferences, and leaves the awards they gave standing by entry reference; an
erasure removes the notes they wrote. Every change is audited as `BadgeChanged` by
reference — the badge, the award, the entries — never a note or a picture.

## Storage

The `badges` keyspace (backed up): the settings, each badge, each award (indexed by badge,
recipient and giver, with its share where there is one), each holder's preferences, each
holder's status slot for a badge shown outside (`bslot:`), the credential last issued to them
in that regime (`bcred:`), each share token (`bshare:`), each claim code's record
(`bclaim:`, indexed by badge and by the code's digest, with who redeemed it), and the badge issuer records the
trust registry accepted (`breg:`). Pictures in `badge_images` (backed up).
The badge group, its DID, its authority credential and its memberships are the groups'.
