# VTC member badges: design

Status: **phase 1 complete** (backend served, #2477; console plugin and portal pages, this
PR). Next: phase 3, the outside regime. Specification: VTI Community Badges chapter
(VTI-BDG-001 – 095). Wire: trust-tasks-tf `specs/vtc/badges/*/0.1`, plus `badgeId` on the shared
`Group` record. Mockups: the "VTC Member Badges" design canvas (seven screens: a member's page with
the badge wall, one badge with its holders, the member's own badges, a member making a badge, and
the console's settings, badge management and badge editor).

## What a badge is

A **badge** is a picture with a name that a member earns and shows on their directory card: hosting
a workshop, a year in the community, coming to an event, or simply being thanked by another member.
Badges are the community's gamification layer. They are **fun first**: pictures, counts, a wall on
the card, a holder list behind every badge. They carry **no authority** at the community
(VTI-VTC-020): nothing a badge says is ever read by an authorization decision.

Two kinds:

- A **community badge** is defined by the community and given by its **owners**. It may carry a
  credential, and a credential-backed badge may be shown outside the community.
- A **kudos badge** is made by a member and given by **any** member to any other, as many times as
  they like within limits. It is a picture and a count, never a credential.

## The decisions

1. **A community badge is a badge group.** Creating a community badge creates a community group
   (`vtc/groups/*`) that backs it, referenced by `groupId` on the badge and `badgeId` on the group.
   The badge's **owners are the group's managers** (`vtc.groups.manage` qualified `group:<id>`, by
   appointment, so owners change over time and a departing granter's appointments go to review).
   Its **holders are the group's members**. An **automatic badge** is a badge whose group is
   `dynamic`: tenure, role, a credential-sourced field, and, as new verified facts, elections voted
   in, ideas selected and kudos received. **Asking for a badge** is `vtc/groups/join` on its group
   (`joinPolicy: request`), decided by its managers with `vtc/groups/requests/decide`; nobody decides
   their own. **Retiring a badge** deletes its group, so the community's one revocation bit on the
   group's authorization credential voids every credential the group issued. A badge group never
   carries authority (`carriesAuthority` is always false; a `grants` or `role` binding is refused),
   is left out of `vtc/groups/list` unless asked for, and is not counted in the directory's
   `sharedGroups`. A kudos badge has no group.
2. **Acceptance before issuance.** An owner's award is an **offer** (`vtc/badges/awards/offer`), a
   record of the badge's own, not a group membership. The member accepts in the portal
   (`vtc/badges/mine/accept`), and only then is the group's credential issued (as `members/add`
   items 3 – 5 describe: credential first, membership recorded after) and the member admitted.
   Declining records no membership and issues nothing; a declined badge can be offered again. A
   request the member made is their consent, so an approved request admits at once. A dynamic
   badge group admits by rule, and its credential offer reaches the member's wallet as any group
   credential does; opting out (`vtc/groups/leave`) is the decline.
3. **The credential.** A badge group issues its members an **Open Badges 3.0**
   `OpenBadgeCredential` (a W3C VC 2.0 profile) **in place of** a DTG group membership credential:
   `issuer` the group's DID, the `Achievement`'s `creator` the community's DID, the community's
   `EndorsementCredential` of the Achievement embedded, `credentialSubject.id` the member's
   membership DID, the badge's picture and criteria on the Achievement, and one `evidence` entry
   per award. Signed as the group through `keys/sign-document`, exactly as a group membership
   credential is (VTI-DIR-080). Two regimes, chosen per badge by `shareableOutside`:
   - **Inside only**: short-lived and renewed, no status mechanism, as VTI-DIR-085 requires of a
     group credential and for the same reason (a per-group status set singles out a small group's
     members, VTI-CRD-014).
   - **May be shown outside**: long-lived (the community's setting; two years is a reasonable
     default) with a slot in the **community's shared status set**, the one every community
     credential uses, allocated at random. The community owns and flips the bit; the status list
     credential is the community's. The set is the whole community's, so VTI-CRD-014 holds.
   A badge credential is not a group membership credential, so VTI-DIR-084/085 do not govern it;
   the badges chapter does.
4. **Hidden is portal-only.** A holder who hides a badge keeps it: the membership and the
   credential stand, owners and administrators see the holder marked hidden, and the holder is left
   out of the portal's wall, of the badge's holder list for members, and of its count. Holders set
   who sees their badges (`members` by default; never wider than the directory shows the card),
   pin up to two beside their name, and order the wall.
5. **Kudos are given by anyone and add up.** A kudos badge is given with `vtc/badges/kudos/give`
   by any active member to any other active member, never to themselves, within the community's
   limits (per giver per day, the same giver to the same member at most once a day, a minimum
   tenure before giving). Each giving is its own award, accepted or declined on its own; a badge
   is hidden as a whole. The wall shows the badge once with its count, and the card a kudos total.
   Administrators see who gave a kudos badge to whom; members see what they received and gave.
   A kudos badge may be **promoted** to a community badge by an administrator: a badge group is
   created, and existing holders are offered its credential like any award.
6. **Repeat awards.** A community badge marked `repeatable` can be awarded again to a holder: the
   new award is offered and accepted like the first, appends an `evidence` entry, and the credential
   is re-issued with the full list; under the outside regime the previous credential's bit is
   flipped. The count on the wall is the number of accepted awards.
7. **Pictures** go through the directory's image pipeline (`directory::images::reencode`): decoded,
   scaled, re-encoded, no metadata, stored as the community's own bytes under its own digest, read
   through `vtc/badges/images/get` by members only. A badge that may be shown outside publishes its
   picture, and an Achievement document, at the public URLs its credential names.
8. **Registry.** A badge group is projected to the trust registry as a recognised issuer under the
   community, exactly as capability modules are projected: the VTC is the source of truth, the
   registry a projection, the projector the one retry owner; retiring the badge removes the record.
   An outside verifier asks the registry about the issuer and the status set about the award.
9. **Settings** (`vtc/badges/settings/*`) are the community's: badges on or off (off hides every
   surface and keeps every record; nothing is revoked), who may make kudos badges (administrators
   only, chosen roles and groups, every active member), the limits, whether kudos totals show, and
   whether automatic badges run. Changing them takes `vtc.config.admin` and a step-up bound to the
   document, like every community setting, never the action list (they confer nothing).
10. **Defining community badges** takes a new capability `vtc.badges.admin` (Appendix C.3), within
    `community-admin`'s ceiling. Giving one out and deciding requests is the group's management.
    Every `community-admin` may give any badge, since it holds `vtc.groups.manage` unqualified.
11. **The portal key.** `vtc/badges` joins `PORTAL_SIGNING_SCOPE`: the holder's tasks (`mine/*`,
    `kudos/give`, `images/upload` for a kudos badge, `create` of a kudos badge) accept a delegated
    document. Owners' and administrators' tasks (`create` of a community badge, `update`, `retire`,
    `awards/*`, `settings/*`) resolve the signer through `member_signer` only and never do, as
    boards' facilitator tasks (VTI-BRD-051).
12. **Departure and erasure.** Departure ends every badge-group membership (`groups::on_departure`),
    withdraws the member's open offers and requests, and keeps their givings by entry reference so
    other members' counts stand. Erasure removes the text they wrote (award notes). Audit is by
    reference (`BadgeChanged`, `BadgeAwarded`, `KudosGiven`), never a note.
13. **Showing a badge outside** is the holder's choice per award (`vtc/badges/awards/share`): the
    community answers a public verification URL for that award and serves the credential **baked**
    into the badge's picture (the Open Badges baking profile) for a website or an email signature.
    The member's published external card may list those URLs. Nothing public ever lists holders.
    The public artefacts (the Achievement document, the picture, the verification page, the baked
    image) are served over HTTPS to Open Badges verifiers, a foreign protocol, and are declared
    REST exceptions.

## Storage

A `badges` keyspace (backed up): badge records, awards (one per offer, keyed by badge, entry and
award id, with state `offered` / `accepted` / `declined` / `withdrawn` / `revoked`), kudos givings,
each member's badge settings (visibility, pins, order, hidden set), share tokens, and the
settings record. Badge pictures in `badge_images`, keyed by the community's digest. The group
itself, its DID, its authorization credential and its memberships are the groups subsystem's.

## The task family (`vtc/badges/*` 0.1)

| Group | Tasks | Signer |
|---|---|---|
| Settings | `settings/show`, `settings/update` | administrator (`vtc.config.admin`, bound step-up) |
| Definitions | `create`, `update`, `retire`, `list`, `show` | `vtc.badges.admin` for a community badge; a member for a kudos badge they may make; `update`/`retire` of a kudos badge by its maker or an administrator |
| Pictures | `images/upload`, `images/get` | the badge's maker or an owner; any active member reads |
| Awards | `awards/offer`, `awards/withdraw`, `awards/revoke`, `awards/list` | an owner (the group's manager) |
| The holder | `mine/list`, `mine/accept`, `mine/decline`, `mine/hide`, `mine/show`, `mine/arrange` | the member, delegated key accepted |
| Walls | `wall/show`, `holders/list` | any active member; projected through the directory's visibility and the holder's own |
| Kudos | `kudos/give`, `kudos/list` | the member, delegated key accepted |
| Outside | `awards/share`, `awards/unshare` | the holder (phase 3) |

Requests reuse `vtc/groups/join` and `vtc/groups/requests/{list,decide}`; owners reuse
`vtc/groups/managers/{add,remove}`. No new request or owner tasks.

## Phases

| Phase | Delivers |
|---|---|
| 0 | This note; the VTI chapter (VTI-BDG-*); `vtc/badges/*` 0.1 and `Group.badgeId` upstream; the pins |
| 1 | Settings; community badges on static groups; offers, accept, decline, hide; wall, holders, pictures; the inside-only credential; kudos, per-giving acceptance, totals, limits; pins and order; promote — backend (#2477), then the console plugin (`admin-ui/src/plugins/badges.tsx`) and the portal pages (`admin-ui/src/members/Badges.tsx`, the wall on a member's card, the home tile) |
| 2 | Folded into phase 1 |
| 3 | Outside: the long-lived credential in the community's status set, the registry issuer projection, share links, the baked image, the public artefacts |
| 4 | Dynamic badge groups with the new rule facts (elections voted in, ideas selected, kudos received); claim codes for events |

## Open

- **The status list credential's issuer.** The community issues the list; the badge credential's
  issuer is the group. Whether the W3C Bitstring Status List validation algorithm requires the two
  to match is to be confirmed; if it does, the community still owns and flips the list and the VTA
  signs the list credential as the group through the same signing path.
- **New rule facts** (`electionsVotedIn`, `ideasSelected`, `kudosReceived`) extend `RuleCondition`
  in the groups family; they are phase 4 and not in the 0.1 badges family.
- **A leaderboard** is a setting that is off by default and that members join themselves; not in
  phase 1.
