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

## The credential

A badge group issues each holder an Open Badges 3.0 `OpenBadgeCredential` in place of a
group membership credential: `issuer` the group's DID, `credentialSubject.id` the holder's
membership DID, the badge as the `Achievement` with the community as its `creator`, and one
`evidence` entry per accepted award.

This build serves the **inside-only** regime: short-lived (`[groups] credential_valid_days`,
default 30) and renewed by the groups' renewal sweeper while the holder stays, with no
status mechanism, as a group membership credential. A badge whose holders may show it
outside the community (long-lived, with a status in the community's own status set) is
not served yet: `create` refuses `shareableOutside` until it is.

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
home page says how many badges show and how many offers wait.

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

## Departure and audit

A member's departure ends their badge-group memberships, withdraws their open offers and
their wall preferences, and leaves the awards they gave standing by entry reference; an
erasure removes the notes they wrote. Every change is audited as `BadgeChanged` by
reference — the badge, the award, the entries — never a note or a picture.

## Storage

The `badges` keyspace (backed up): the settings, each badge, each award (indexed by badge,
recipient and giver) and each holder's preferences. Pictures in `badge_images` (backed up).
The badge group, its DID, its authority credential and its memberships are the groups'.
