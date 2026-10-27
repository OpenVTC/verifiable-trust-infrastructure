# VTC member directory — design

Status: **proposal** (2026-10-18). Q1–Q3 decided 2026-10-18 (§13). Nothing here is implemented. It needs
specification work in two repositories before any code
(§12), and it records the decisions that are still open (§13).

## 1. What we are building

A community's **member directory** is the address book that members and
administrators share. Members find each other, recognise each other and
reach each other through it. Later work will build on it:

- adding people to data rooms by group, not one DID at a time;
- giving people roles because they belong to a group;
- chat (names, avatars, nicknames, 1:1 and group conversations).

It has to be simple by default and still cover many kinds of community:

- a five-person working group where everyone is listed;
- a 50 000-member professional body where the member list stays hidden and
  only search works;
- an anonymous support community where nobody's DID is ever shown.

Everything that differs between those communities is **policy and
configuration**, never a code path.

### 1.1 Requirements as given

| # | Requirement | Where it lands |
|---|---|---|
| R1 | Contacts-list-like directory | §4 cards, §8 reads |
| R2 | Admin-defined, extensible member fields | §4.2 field schema |
| R3 | Member controls discoverability, inside the community and outside it (trust registry) | §5 |
| R4 | Generic, comprehensive Trust Tasks | §11 |
| R5 | In the member portal and the admin console | §10 |
| R6 | Show who I have a Verified Relationship (VRC) with | §7.3 |
| R7 | Star members | §6 (personal layer) |
| R8 | Groups made by admins (community) and by members for themselves (personal) | §6, §9 |
| R9 | Notes: admin notes private to admins; personal notes private to their author | §6, §4.5 |
| R10 | Add community groups to rooms | §9.3 |
| R11 | Groups and roles: a role assigned to a group follows people in and out | §9.4 |
| R12 | Chat-ready profile: name, avatar, nickname, … all optional | §4.1 |
| R13 | DIDs shown or hidden; persona DID vs pairwise DIDs | §7 |
| R14 | Policy-driven wherever possible | §8 |

## 2. What already exists, and must be built on

The VTC already has **a directory, but it is a minimal one**. A new design
extends it. It must not sit beside it under the same name.

- **`vtc/directory/query/0.1`** (tf `specs/vtc/directory/query/0.1`). A
  member asks for **one subject DID**. The answer is a policy projection
  (`PolicyPurpose::Directory`, `policies/default/directory.rego`), capped
  by `DIRECTORY_FIELD_WHITELIST = [did, role, joined_at, status]`
  (`vtc-service/src/routes/directory.rs`). Two rules from it carry over
  unchanged. A withheld field is **absent**, never null. "Nothing visible"
  and "no such member" both answer `notFound`.
- **`Member`** (`vtc-service/src/members/mod.rs`). It has no name, avatar
  or profile. Its `extensions` blob (16 KiB) is already used by git-ns
  (`forges`), and `members/update` replaces it whole. **It is not a place
  for directory data.**
- **`VtcAclEntry.label`.** This is the only human name today. An admin
  sets it, or the subject does (`label_set_by_subject`). The admin
  console's `NameBook` ranks it against `alsoKnownAs`.
- **`vtc/community/requested-attributes`.** The admin lists the claim
  *types* asked for at join, never their values. The answers stay on the
  `JoinRequest` and are never copied to the member. Reusing them for the
  directory is a purpose the applicant did not consent to
  (`join-requests/submit/0.3`), so they can only be *offered* for reuse
  (§4.4).
- **Registry publication.** Only members with `publishConsent = true` are
  published. The record is a TRQP recognition tuple
  (`entity=member DID, authority=VTC, recognise, trust-graph`) and carries
  no profile data. An admin can withdraw consent but never grant it.
- **VRC graph** (`vtc/relationships/*`). An edge is published in one of
  two forms. *Pairwise*: an R-DID with `pop`, and the VTC does **not**
  record which member it belongs to. *Attributed*: membership DIDs on
  both ends. Only attributed edges can be shown against directory
  entries, unless the viewer's own VTA supplies the link (§7.3).
- **Holder-side contacts** (`vta-persona::contact`, tf `persona/contact/*`
  1.0). The VTA keeps one revisioned contact per relationship, never
  merged across personas, with notes. **This is already the member's
  private address book.** It has no stars, lists or petnames yet.
- **Rooms.** `vtc/rooms/community/members/add` admits one DID per call,
  through offers that the member accepts. Nothing targets a set of
  members.
- **Roles.** A `VtcAclEntry` holds **one** community role (`VtcRole`)
  plus an `AdminAuthority`, and its `resource_grants` are additive
  qualified capabilities with `delegatedBy` (the git-ns rights).
  VTI-VTC-020 forbids a second authority model.

## 3. Principles

1. **Three owners, three stores.**
   - The *community* owns the field schema, groups and admin notes.
   - The *member* owns their card and what it shows.
   - The *viewer* owns what they think of others: stars, lists, notes and
     nicknames.

   Each kind of data lives with its owner. Viewer-owned data never
   reaches the VTC (§6).
2. **Visibility per field, ceiling and choice.** The admin sets the
   widest audience a field may reach. The member chooses within that.
   Policy may narrow either and never widen past the member's choice.
   This mirrors `publishConsent`: an admin can withdraw it, never grant
   it.
3. **Narrowest useful default** (GDPR Art. 25). A new card shows the
   display name and community role to members. It shows nothing outside
   the community, and the DID only to admins. A community can choose
   wider defaults by policy, and it says so publicly (§5.4).
4. **The directory never needs a DID to work.** Entries are addressed by
   an opaque, community-scoped `entryId`. Showing a DID is a field choice
   like any other. Contact is made through an introduction that mints a
   fresh pairwise DID (§7.2).
5. **Groups provision; the ACL authorises.** A group never answers an
   authorisation question. When a group carries authority, the VTC
   *writes* it into the ACL entry with the group as its provenance, and
   removes it again when the member leaves. Every gate still asks
   `VtcAclEntry::can` (VTI-VTC-020).
6. **No oracle.** No lookup by DID or other identifier unless the subject
   allows it. Answers are uniform `notFound`. Cursors are bound to the
   question (VTI-ACL-066). Facet counts below *k* are suppressed. Members
   cannot bulk-export (§8.3).
7. **Departure propagates** (VTI-MEM-033). A card, its group memberships
   and the notes about the member follow the member's departure
   disposition. Rotation carries them to the new DID (VTI-MEM-041). Both
   work because the stores are keyed by `entryId`, not by DID.

## 4. The community layer: fields and cards

### 4.1 Base fields

Every community has the same **base fields**, mapped to JSContact
(RFC 9553) so a card exports to any address book. All of them are
optional. A community can disable any of them, and change any of their
ceilings.

| Key | JSContact | Type | Default ceiling | Default visibility | Notes |
|---|---|---|---|---|---|
| `displayName` | `name.full` | text ≤ 64 | `public` | `members` | Seeded from the ACL `label` when the subject set it |
| `nickname` | `nicknames` | text ≤ 32 | `public` | `members` | The handle chat shows. Unique within the community if the policy says so |
| `avatar` | `media{photo}` | image ref | `public` | `members` | Content-addressed blob (§4.6) |
| `pronouns` | `speakToAs.pronouns` | text ≤ 32 | `public` | `members` | |
| `bio` | `notes` | text ≤ 500 | `public` | `members` | |
| `links` | `links` | url[] ≤ 5 | `public` | `members` | Verified with `rel=me` when the target links back |
| `role` | `ext` | derived | `members` | `members` | Read from the ACL, never stored on the card |
| `joinedAt` | `ext` | derived | `members` | `admins` | |
| `did` | `ext` | derived | `members` | `admins` | See §7. Admins always see it |
| `personhood` | `ext` | derived | `members` | `admins` | Shows that a personhood assertion is on file, never its evidence |

Derived fields are views over existing records. They are never copied.

### 4.2 Community fields (admin-defined)

Administrators holding `vtc.directory.admin` define more fields. A field
definition looks like this:

```jsonc
{
  "key": "org.example.employer",       // reverse-DNS outside the base set
  "label": "Employer",
  "description": "Where you work today",
  "type": "text",                      // text | longText | url | email | phone
                                       // | enum | multiEnum | date | country
                                       // | image | did | claim
  "constraints": { "maxLength": 80 },  // per type: options, pattern, ranges
  "source": "member",                  // member | admin | credential
  "required": false,                   // required for listing, never for membership
  "ceiling": "members",                // public | members | connections | groups | admins
  "defaultVisibility": "members",
  "searchable": true,                  // full-text search, within visibility
  "facet": true,                       // filterable; enum/multiEnum/country only
  "order": 40,
  "state": "active"                    // active | retired
}
```

- **`source`** decides who writes the value.
  - `member`: self-asserted.
  - `admin`: staff-asserted; the member reads it and cannot change it
    (Discourse's "not editable after signup").
  - `credential`: the value is a claim disclosed from a credential the
    member presents (`claim` type, e.g. a verified employer or "over 18").
    The card shows the issuer as a verification badge, and self-asserted
    values are never badged.
- **`required`** only gates being *listed*: an incomplete card is not
  listed. It never gates membership, which belongs to join criteria.
- **Retiring** a field hides it at once and purges its values after the
  community's retention period. Deleting a definition while values exist
  is refused, so a field key is never reused with a different meaning.
- **Limits.** 64 active fields; 16 KiB per card excluding blobs.
- **Who may change field definitions.** Narrowing (lower ceiling,
  retire) applies immediately. **Widening a ceiling is privacy-affecting
  policy** (VTI-VTC-031/032, VTI-CMP-090). It parks in the action list
  and never widens anyone's existing choice. A member who chose
  `members` stays at `members`.

### 4.3 Audiences

One enum, ordered from narrowest to widest:

| Audience | Who sees the field |
|---|---|
| `admins` | Holders of `vtc.directory.admin` (and `vtc.members.manage` for derived fields) |
| `groups` | Members who share at least one *community* group with the subject (the member can pick which groups) |
| `connections` | Members with an **attributed, in-force** VRC edge with the subject (§7.3) |
| `members` | Every active member |
| `public` | Anyone, including what the registry publishes (§5.3) |

The subject always sees their whole card. `onlyMe` is not an audience. A
value nobody else should see is not directory data, and belongs in the
member's own VTA.

`groups` and `connections` are not a strict chain. The viewer must
satisfy the field's chosen audience **or** a wider one the subject also
chose. The host computes this, and it is not left to policy (§8.2).

### 4.4 The card

A card is the subject's own record: their values, a visibility for each
field, and discoverability settings (§5). It is keyed by `entryId`.

```jsonc
{
  "entryId": "dir_7Q2…",           // opaque, community-scoped, stable across rotation
  "values": { "displayName": "Ana", "org.example.employer": "Acme" },
  "visibility": { "displayName": "members", "org.example.employer": "connections" },
  "discoverability": { "listing": "listed", "search": "byName", "external": false },
  "revision": 7,
  "updatedAt": "2026-10-18T09:00:00Z"
}
```

- The card is written by a signed `card/update` from the member's DID
  (proof and `issuedAt` required). Out-of-order documents are refused
  `superseded`, as `registry-consent` does.
- **Seeding from join.** At join, the applicant may tick "use these
  answers for my directory card". That writes the values with the
  narrowest visibility (`admins`) for the member to widen later. Without
  the tick nothing is copied, and the join answers stay where they are.

### 4.5 Admin notes

Admin notes are a separate record type. They are **never** on the card
and never in a projection.

- **Who.** Read and written by holders of `vtc.directory.notes`, which
  the built-in admin roles carry. A community can give it to a moderator
  role without directory-admin.
- **Shape.** Append-only entries: author, time, text ≤ 2000, an optional
  `followUp` date. An entry is redacted by a later entry, never edited.
- **Audit.** Reads and writes are audited by reference (VTI-AUD-005):
  the row records which entry, never its text.
- **Disclosure to the subject.** By default the subject does not see
  admin notes. That admins *can* keep notes is part of the community's
  published directory disclosure (§5.4). Answering a data-subject access
  request is an export path for admins (`notes/export`), not a member
  read.
- **On departure.** Notes follow the disposition: purged with a `Purge`
  departure, kept for the retention period with `Tombstone`/`Historical`.

### 4.6 Avatars and other blobs

An avatar is a content-addressed blob in the `directory` keyspace:
`sha256` plus media type, ≤ 256 KiB, images only, re-encoded on upload
(`vtc/directory/images/upload`: orientation applied, metadata stripped, at most
512 px, JPEG or PNG). The card holds a reference to it, and only to a picture
its own writer uploaded. Readers fetch the bytes with
`vtc/directory/images/get`, which projects the entry for them first, so a
member-only avatar is never a public URL; the optional short-lived `url` of a
`CardBlobRef` is not offered. An upload no card holds is erased after 24 hours,
and a picture no card holds any longer at the next directory pass.

## 5. Discoverability

Discoverability answers three questions, asked separately because uptake
of each is different (Mastodon's opt-in search reached about 10 %).

### 5.1 Listing (inside the community)

`discoverability.listing`:

- `listed`: the entry appears when members browse the directory.
- `findable`: the entry does not appear when browsing, but a search that
  matches it returns it (see `search`).
- `hidden`: no member finds it. Admins still see the entry, and members
  who share a group or room see it in that group's or room's member list,
  if the group shows members (§9.1).

`discoverability.search`:

- `byName`: a search can match `displayName` or `nickname`.
- `exactNickname`: only an exact nickname matches (Signal-style).
- `off`: no search matches.

**A DID is never a search key** for members. Searching by DID is an
admin read.

### 5.2 Community default

The community sets the *initial* listing for new cards
(`directory.defaultListing`, default `listed`). Every member may always
choose `hidden`. There is no floor, because a floor would let the
community widen a member's choice (DIR-003). Big or sensitive communities
set `defaultListing = findable` or `hidden`. Raising the default changes
new cards only, and parks like any privacy-affecting change.

### 5.3 External (trust registry)

`discoverability.external = true` publishes a **public card**: the fields
whose visibility is `public`. This is a second consent, separate from
`publishConsent` (recognition):

- `publishConsent` says "other communities may recognise my membership".
- `external` says "anyone may find my card".

External needs `publishConsent`, because the card hangs off the
recognition record. Recognition does not need external.

The **member signs the public card**, and the VTC never asserts profile
data externally (ActivityPub's lesson: the member's own document is
authoritative and the community mirrors it). The registry gets the
existing recognition tuple plus a pointer (URL + digest) to the signed
card. The VTC serves the card for as long as the entry is external and
the member is active. Departure withdraws the pointer before anything
else (VTI-MEM-033).

**This collided with VTI-REG-001** ("no personal data published beyond
what recognition requires"). The specification resolved it (dtgwg-vti-spec
#68): REG-001 is scoped to recognition, and VTI-REG-004 bounds publication for
any other purpose — purpose stated, subject told first, nothing beyond the
purpose. `vtc/directory/card/publish` meets each: the pointer carries its
purpose, the wallet shows the member every value before they sign, and the card
carries exactly their public values.

As built (trust-tasks-tf #826, #827): the card's shape is fixed member for
member, so the community compares it with the member's public values and two
wallets sign the same bytes for the same values. It is served by
`vtc/directory/card/public` and pointed to from `context.directoryCard` on the
recognition record. The moment the public values change for any reason it is
withdrawn to `awaitingSignature`; every serving path checks first, and the
hourly directory pass catches what no write path saw (a policy change, a
suspension).

The DTG r-card (a "self-updating vCard") is the natural long-term format,
but its specification is unwritten. Until it exists, the public card is a
JSContact `Card` in a Data-Integrity-signed envelope. Moving to the
r-card later is a new card version, not a reshape.

### 5.4 The published disclosure statement

cred-spec (`issuerScope`, line 162) requires a VTC issuing VMCs to
publish whether member identifiers are disclosed beyond the VTA, and to
whom. A member directory is exactly that disclosure.

The VTC **generates** the statement from its configuration: the field
schema, the ceilings, the default listing, whether admin notes are kept,
and whether `did` can reach `members`. It publishes the statement in the
join manifest (`vtc/join-requests/manifest/0.4`, `directoryDisclosure`),
which every applicant reads before applying, and on its own as
`vtc/directory/disclosure/0.1`. Because it is generated, it cannot drift from
what the directory actually does. (The first draft of this note put it in the
community profile; the manifest is where an applicant already looks, and the
one read that discloses nothing about them.)

## 6. The personal layer: stars, lists, notes, nicknames

The four things a member keeps *about others* — a star, a personal list
("my mentors"), a private note and a private nickname — **live in the
member's own VTA, never at the VTC.**

Why:

- **No social graph at the community.** If the VTC stored stars, its
  operator would learn who watches whom. Instagram's Close Friends rule
  is the right one: being on someone's list must not be inferable by
  anyone else, including the operator.
- **It already exists.** `vta-persona::contact` keeps one revisioned
  contact per relationship, per persona, with notes. It needs four
  additions, not a new store:
  - `starred: bool`;
  - `petname`: the private nickname (Zooko's petnames; distinct from the
    subject's own `nickname`);
  - `lists: [listId]`;
  - `directoryRef: { vtcDid, entryId }`, which links a contact to a
    directory entry.

  Plus a small `lists` record (`listId`, name, colour, order).
- **It spans communities, within one VTA context.** "My mentors" can
  hold people from two communities whose contacts the member keeps in the
  same context, and the VTC of neither learns it. A list never spans VTA
  contexts, because that would join what the context boundary keeps
  apart (tf `persona/contact/lists/*`).
- **Member-owned rooms.** A member who owns a room adds a personal list
  to it the same way a community adds a group (§9.3), because the
  member's VTA is that room's key holder.

The portal reaches the personal layer through the wallet
(`window.vtaWallet`), as the Rooms pages already do. The page **joins**
VTC entries with VTA contacts in the browser: stars sort first, petnames
show beside display names, and "My lists" appear as filters. Neither
server sees the other half.

**Vocabulary.** On screen, personal collections are **lists** and
community collections are **groups**. This keeps "group" for one thing,
and stays clear of the persona UI's "world" (`persona-vocabulary.md`
reserves "group" away from worlds).

## 7. DIDs: membership, pairwise, persona

### 7.1 Which identifier is used where

| Identifier | `issuerScope` | Used for | In the directory |
|---|---|---|---|
| **Membership DID** (the DID in the ACL) | `directed` to this community | Being a member: ACL, VMC, signing Trust Tasks to the VTC | Field `did`: `admins` by default; the member may widen to `members`/`public` |
| **Pairwise relationship DID** | `pairwise` | One relationship with one other member: the VRC, 1:1 chat, direct messages | Never shown. It is what an introduction (§7.2) creates |
| **Persona DID** (shared across contexts) | `directed`/`public` | Deliberate correlation across communities (a VPC) | Only as a `claim` field the member chooses to present |
| **Room identity** | per room | Speaking inside one room | Not directory data |

The rules that follow:

- **One membership DID per community** (VTI-KEY-006). The directory never
  joins entries across communities. The portal does that in the member's
  own browser, from the member's own VTA.
- **Default to pairwise for every new relationship** (VTI-KEY-005,
  cred-spec VRC: `pairwise` RECOMMENDED). Correlation happens only on
  purpose: an attributed VRC, a VPC, or a widened `did` field.
- **The directory leaks no correlator of its own.** `entryId` is random,
  scoped to the community, and not derived from any DID. Avatars are
  re-encoded so their hashes don't link communities.
- **Showing the DID is a real choice for some communities.** A community
  whose members sign git commits under their membership DID gains from
  `did → members`. That community widens the ceiling and, through §5.4,
  says so.

### 7.2 Reaching someone without their DID: introductions

`vtc/directory/introduce/0.1`: member A asks the VTC to introduce A to
entry B.

1. A's VTA mints a **fresh pairwise DID** for the relationship. A sends
   `introduce` with B's `entryId`, a short message (≤ 280 chars), A's
   pairwise DID and A's chosen card snapshot. The snapshot holds only
   fields whose visibility already covers B.
2. The VTC checks the following:
   - A and B are both active;
   - B may be found by A under B's discoverability settings;
   - B accepts introductions (`card.introductions = anyone | groups |
     connections | off`);
   - A is under the rate limit (per sender, and per sender→recipient
     pair).

   It then pushes `vtc/directory/introduction/0.1` to B's membership DID
   (TSP > DIDComm). **Every refusal looks like delivery to A**: A's
   answer is always `accepted`, so introductions are not a membership
   oracle.
3. B ignores the introduction, or answers A's pairwise DID **directly**
   with the existing peer flow (`vrc/relationships/propose`), from a
   pairwise DID of B's own. The VTC never sees the answer.
4. Both VTAs record the contact with `directoryRef` (§6).

The VTC learns that A asked to meet B. It does not learn whether they
met. The introduction is kept for 30 days, for abuse handling only, and
A's request is audited by reference.

### 7.3 "We have a verified relationship"

The badge on an entry has two sources:

- **Attributed edges at the VTC.** An in-force edge whose two endpoints
  are A's and B's membership DIDs is computed by the VTC for the viewer.
  It is shown **only to the two parties** unless both halves say
  otherwise. The edge's disclosure is the wider of its two halves
  (cred-spec privacy item 9), so either party can keep it private.
- **The viewer's own VTA.** The viewer's own contact has a `directoryRef`
  and holds an in-force VRC with that contact's pairwise DID. The badge
  is computed in the browser and the VTC never learns about it. This is
  the normal case, because relationships are pairwise by default.

"Mutual connections" are shown only when the viewer could see every edge
involved anyway, which in practice means attributed edges whose parties
opted in. The directory never walks the graph for a member
(`relationships/list/0.2` warns about exactly this).

## 8. Policy

### 8.1 Purposes

- **`directory`** (existing; read-time projection). It grows from a
  four-field whitelist to the whole projection. Input:
  - viewer: role, capabilities, community groups, relation to the subject
    (`sharesGroup`, `sharesRoom`, `connected`);
  - subject: card, visibility, discoverability, derived facts;
  - the field schema.

  Output: per entry, either `allow` with `{fields, listed}`, or `deny`.
- **`directoryWrite`** (new; write-time). It decides:
  - whether a card update is accepted (e.g. require a `displayName`,
    forbid links to certain domains, make nicknames unique);
  - whether an admin-sourced field write is allowed;
  - the community defaults in §5.2.
- **`groups`** (new). It decides:
  - who may create a community group (default: `vtc.groups.manage`);
  - whether a self-join to an `open`/`request` group is admitted;
  - dynamic-group rules (§9.2), evaluated over **verified facts only**.

Each new purpose follows the existing checklist: `PolicyPurpose` variant,
`ALL`, a default `.rego`, `facts.rs`, the admin-UI rule IR, and the
purpose enum in trust-tasks-rs.

### 8.2 Host invariants policy cannot cross

Policy can only narrow these. The host enforces them before and after
evaluation.

1. A field leaves only if all three hold:
   - its visibility, as the **member** set it, covers the viewer;
   - its **ceiling** covers the viewer;
   - policy allows it.

   The three are intersected and never unioned.
2. `admin`-sourced and `credential`-sourced values are written only
   through their own paths. A member's card update that touches them is
   refused.
3. Departed, suspended and `application` members are never projected to
   members (VTI-MEM-001).
4. Admin notes are never in a projection, whatever policy returns.
5. `public` fields leave the community only through the member-signed
   card of §5.3.
6. Withheld means absent. Nothing visible means `notFound`.
7. A dynamic group cannot confer authority (§9.4).

### 8.3 Anti-enumeration

- **Browse** returns only `listed` entries, paginated. Cursors are bound
  to (viewer, query, filters) under the community cursor key
  (`vti_common::pagination`, VTI-ACL-066).
- **Search** needs a query of at least 3 characters (or exactly one
  nickname under `exactNickname`). Matches are capped at 50.
- **Facets** are offered only on fields that are `facet: true` *and*
  visible to the viewer. A count below *k* (default 5) is shown as
  "fewer than 5", so filtering cannot single out a hidden value.
- **Per-viewer rate limits** on `entries/list` and `introduce`, as
  runtime config keys like the existing limiter.
- **Export** of the directory is admin-only (`vtc.directory.admin`),
  step-up bound and audited `Critical`. Members cannot export.

## 9. Groups

### 9.1 Community groups

A community group is a VTC record:

```jsonc
{
  "groupId": "grp_…",
  "groupDid": "did:webvh:…",       // minted by the community's VTA (§9.5)
  "issuesCredentials": true,
  "name": "Working Group: Identity",
  "description": "…",
  "kind": "static",                 // static | dynamic
  "rule": null,                     // dynamic only (§9.2)
  "joinPolicy": "closed",           // closed | request | open   (static only)
  "visibility": "members",          // admins | groupMembers | members
  "showMembers": "groupMembers",    // admins | groupMembers | members
  "managers": ["dir_…"],            // via resource grants, see below
  "bindings": [ /* §9.3, §9.4 */ ],
  "createdBy": "dir_…", "createdAt": "…"
}
```

- **Managers.** Group managers hold `vtc.groups.manage` qualified
  `group:<groupId>`, a **resource grant** on their ACL entry, as git-ns
  rights do. The granter must cover it (VTI-ACL-071), and a departing
  granter's grants go to review. An admin without the resource qualifier
  manages every group.
- **Showing a group is separate from showing its members.** A
  `visibility: members, showMembers: admins` group is a label everyone
  sees, with a member list only staff see. WhatsApp Communities works the
  same way.
- **No nesting** in this version. The cycles and effective-membership
  cost of nesting are not worth it until a real case needs them.
- **Membership pages.** A member list is never inlined into a group
  read; it is paginated (`groups/members/list`). SCIM's
  100 MB-group-payload lesson applies.
- Membership is keyed by `entryId`, so it survives rotation, and departure
  removes it.

### 9.2 Dynamic groups

`kind: dynamic` computes membership from a rule (the `groups` purpose)
over **verified facts only**: community role, admin-sourced and
credential-sourced fields, personhood, join date. A rule never reads a
self-asserted field. Otherwise a member could join a group by editing
their card.

Membership is recomputed whenever a fact it reads changes (the
storage-seam events that already feed `admin_events`). A sweeper
reconciles every few minutes.

A member may **opt out** of any dynamic group: `leave` records an
exclusion and `join` undoes it. An opted-out member is not a member, so
their group VMC stops renewing and room bindings treat them as gone.
Because a dynamic group never confers authority, nothing the community
relies on depends on it, and the community never overrides the member's
choice.

Dynamic groups are for **organising, browsing, room access and future
chat**. They never confer authority (§9.4). Entra refuses to make a
dynamic group role-assignable for the same reason: a rule change could
silently hand someone a role.

### 9.3 Groups in rooms

A **room binding** links a community room to a group:

```jsonc
{ "kind": "room", "roomId": "…", "actions": ["read", "write"], "validFor": "P365D" }
```

- **Joining** the group creates a room *offer* for the member through the
  existing `rooms/offers` path. The member still accepts with a
  KeyPackage, so nobody is placed in an encrypted room without their own
  key.
- **Leaving** the group, or leaving the community, removes the member
  from the room through `group/remove`, unless another binding or a
  direct admission still covers them. A room member record carries its
  **sources** (`direct`, `group:<id>`…). Removal happens when the last
  source goes, which is the same rule as for roles.
- **Remote first.** The binding is recorded, and a reconciler, the one
  owner of retries, drives the offers and removals. It uses capped
  backoff and jitter, and each step is idempotent (the HookRelay pattern
  of `vtc-membership-hooks.md`). The room member record is written only
  after the VTA answered.
- Binding a group to a room needs `vtc.rooms.manage` on the room **and**
  `vtc.groups.manage` on the group. Bindings with `curate` or `admin`
  actions are authority. They follow §9.4.
- Dynamic groups may bind to rooms with `read`/`write`. A room's whole
  point may be "everyone in the Sydney chapter".

### 9.4 Groups and roles

"Assign a role to a group and roles follow membership" is what SCIM-style
provisioning does. It must not become a second authority model
(VTI-VTC-020; F.7 records git-ns having to undo exactly that).

**The model: a group carries a grant set, and the VTC provisions it into
the ACL.**

```jsonc
{ "kind": "grants", "grants": [
    { "capability": "vtc.rooms.manage", "resource": "room:…" },
    { "capability": "vtc.members.manage" } ] }
```

Or, by reference, a defined role's capability set:

```jsonc
{ "kind": "role", "role": "custom:moderator" }
```

- When a member joins the group, the VTC writes each grant onto the
  member's ACL entry as a **resource grant with `source: group:<groupId>`**,
  bounded by the role ceiling and by the binder's own holdings
  (VTI-ACL-071). When the member leaves, grants whose only source is that
  group are removed. Grants held directly, or through another group,
  stay.
- **Every gate still asks the ACL entry.** A group record is never read
  to answer "may X do Y". Audit shows *why* an entry holds a grant
  (`source`).
- **Static only.** A group with a `grants` or `role` binding must be
  `static` with `joinPolicy: closed`, and stays so for as long as the
  binding exists.
- **Consent.**
  - Binding an authority-conferring grant set to a group parks in the
    action list as `Act::BindGroupAuthority`.
  - Adding a member to such a group is an authority-conferring grant.
    It parks too, exactly as an `acl/grant` would (VTI-APV-018).
  - Removing a member from it is a reduction (APV-019), with its
    cooling-off.

  Groups give no way round consent.
- **Administrative roles are not group-assignable** in this version. The
  `AdminRole` ceiling stays a direct assignment. Groups confer
  capabilities within a ceiling, never the ceiling itself.
- **The community role** (`member`/`moderator`/custom community role) is
  single-valued on the entry today. A group therefore cannot set it
  without deciding precedence between groups. That is open question
  **Q2**. The recommended answer is "groups confer grants only", leaving
  the community role a direct assignment.

### 9.5 Group identity and credentials

Every community group has **its own DID** and issues a **membership
credential** to each of its members, just as a community room does.

- **Signing.** The VTA signs both credentials through the generic
  `keys/sign-document/0.1`. The custodian builds a Data Integrity proof
  with a named key, under its own `sign-document` capability. The task
  refuses a document whose `issuer` is not the key's DID, and `sign` is
  never accepted in its place.
  - There is no groups-specific signer. The VTC is the authority on group
    membership and the VTA is only its custodian, as with rooms.
  - `keys/sign` cannot do this job, because it frames caller bytes
    (`SigningDomain::Opaque`).
- **Template.** `vtc-group` is did:webvh with a signing key and a
  key-agreement key. It has **no service**, because nothing serves
  messages to a group yet; group chat adds one by DID update. It has **no
  label variable**.
- **Minting.** `groups/create` asks the community's own VTA, over
  `vta_link`, to mint the group's DID from a DID template (working name
  `vtc-group`), exactly as a community room's DID is minted from the
  `room` template. The VTC never holds a group key, and never falls back
  to one (`noKeyHolder`).
  - The group is recorded only after the mint has answered (remote
    first).
  - Serverless group DIDs are served at `/group-dids/<id>/did.jsonl`.
  - The DID document carries no name or description, so resolving it
    reveals nothing about the group.
- **Authority to issue.** The community issues the group DID a VAC (DTG
  `AuthorizationCredential`, community → group) that authorises it to
  issue membership credentials. A verifier chains: member's group VMC →
  group VAC → the community, recognised as usual.
- **Membership credential.** A member who joins the group receives a VMC
  issued by the group DID to their membership DID. Joining covers
  `members/add`, an `open` join, a decided request and a dynamic
  recompute. The VMC is
  `["VerifiableCredential","DTGCredential","MembershipCredential"]`
  and is delivered on the existing credential-exchange offer path.
  `issuesCredentials` (default `true`) turns this off for a group that
  doesn't need it.
- **Revocation.** Leaving the group, leaving the community, or deleting
  the group revokes the VMC.
  - **Decided: short-lived, renewed.** Group VMCs are short-lived and
    the community's VTA renews them for as long as the member stays.
    Expiry is the revocation, as room authority renewal works.
  - There is no status list per group. A ten-member group's list would
    single its members out (VTI-CRD-014).
  - Leaving stops renewal. Deleting the group stops renewal and revokes
    the group's VAC.
  - Validity is a host/policy setting. The default is 30 days, renewed
    when 10 days remain; sensitive groups go shorter. Deleting a group
  also revokes its VAC, and the reconciler of §9.3 owns those retries.
- **Not authority at the VTC.** The group VMC is evidence for **others**:
  - a room admitting by presentation;
  - a chat peer checking "is this person in the Identity WG";
  - another community recognising the group.

  The VTC's own gates never read it. They read the ACL entry, which §9.4
  keeps in step (VTI-VTC-020). A VMC is portable, and its holder decides
  where to present it. That is independent of `showMembers`, which only
  governs what the VTC itself lists.
- **Rooms.** With a group VMC, a group-bound room can admit by
  presentation as well as by offer. That is a later option; §9.3's offers
  remain the first implementation.

## 10. User interface

### 10.1 Member portal (`/members`)

- **Directory.**
  - Search box first. Below it, facets for visible fields, "My lists" and
    "Groups".
  - A card grid for fewer than 50 results and a dense list beyond, with a
    toggle.
  - Each entry shows the avatar, display name (with a ★ and petname from
    the member's VTA), role badge, verification badges on
    credential-sourced fields, and the VRC badge.
  - Quick actions: **Introduce**, **Star**, **Add to list**, **Note**.
- **Entry page.** Visible fields; shared groups and rooms; the
  relationship badge; your private note and petname, labelled "only you
  see this".
- **My card.**
  - The editor, with a visibility picker on each field. The picker only
    offers audiences up to the ceiling.
  - **Preview as**: an admin, a member, a group-mate, a connection, the
    public. Each preview runs the same projection the server runs.
  - Listing, search and introductions settings, plus the external toggle
    with the community's disclosure statement next to it.
- **Groups.** The groups I am in, and open groups to join or request.
  Groups I manage get add/remove and bindings when I hold the grant.
- **Lists.** Personal lists (VTA), across communities.

**How the portal calls the VTC.** Directory and groups Trust Tasks are
signed by the portal's sign-in browser key (`K_b`) as a key the member
delegated, limited to those families, this community and the session. It
works like the console key. A delegated signature never satisfies a task
that needs the member's own DID. The mechanism is specified separately
(§12.2).

Stars, lists, petnames and notes reach the page through the wallet, as
the Rooms pages do. When no wallet is present, those controls are hidden
rather than stored at the VTC.

### 10.2 Admin console

- **Directory settings.**
  - Field schema editor (base fields + community fields; drag to order;
    ceiling and default per field).
  - Listing defaults and floor.
  - Introduction limits.
  - A live preview of the generated disclosure statement (§5.4).
  - Widening changes show "will go to the action list".
- **Groups.** Create and edit groups, manage members, set managers, and
  edit bindings (rooms, grants), with a "who would gain what" preview
  before a grants binding is saved.
- **Member detail** (existing page) gains:
  - the card, read through the admin projection;
  - admin-sourced field editors;
  - group memberships, each with its source;
  - the **Admin notes** timeline.
- **Protected screens.** Every deciding screen renders inside
  `components/Protected.tsx`, the shadow tree the community theme cannot
  reach (`vtc/community/theme/show/0.1`, client item 2). That covers
  grant-binding previews, parked-action confirmations, and the
  introduction and export confirmations. The Groups plugin sets
  `protected: true`.
- **Live updates.** New admin-events topics `directory` and `groups`
  (events 0.3), carrying hints only, as always.

## 11. Trust Tasks

Everything is a Trust Task on the spine (TSP > DIDComm > HTTPS), signed,
and specified first in dtgwg-trust-tasks-tf. Payload and response types
come from `trust_tasks_rs::specs`. Every URI is classified in
`vta_sdk::retry_safety`. Every family has a `list` + `show` pair.

### 11.1 `vtc/directory/*` (extends the existing family)

| Task | Caller | Gate | Effect |
|---|---|---|---|
| `fields/list/0.1` | member, admin | active member | The schema as the viewer may see it (ceilings, labels, types) |
| `fields/define/0.1` | admin | `vtc.directory.admin` | Add a field |
| `fields/update/0.1` | admin | `vtc.directory.admin`; widening **parks** | Change label, order, constraints, ceiling |
| `fields/retire/0.1` | admin | `vtc.directory.admin` | Hide, then purge after retention |
| `card/show/0.1` | subject | self | My full card + settings + `revision` |
| `card/update/0.1` | subject | self; proof + `issuedAt` required | Values, visibility, discoverability, introductions; `superseded` on stale |
| `card/assert/0.1` | admin | `vtc.directory.admin` + `directoryWrite` | Write `admin`-sourced values |
| `card/present/0.1` | subject | self | Attach a VP for `credential`-sourced fields; the VTC verifies and keeps only the disclosed claims |
| `entries/list/0.1` | member, admin | active member | Browse/search/filter; `{query?, filters?, group?, cursor, limit}` → entries + facets |
| `entries/show/0.1` | member, admin | active member | One entry by `entryId`. Admins may also address by `did` |
| `query/0.1` | — | — | Kept and served, answered through the new projection. Deprecated in favour of `entries/show` |
| `introduce/0.1` | member | active member | §7.2; always `accepted` |
| `introduction/0.1` | VTC → member | push | The introduction B receives |
| `notes/list/0.1` | admin | `vtc.directory.notes` | Notes for one entry |
| `notes/append/0.1` | admin | `vtc.directory.notes` | Add an entry, or redact an earlier one |
| `notes/export/0.1` | admin | `vtc.directory.notes` + step-up | For subject-access requests; audited `Critical` |
| `export/0.1` | admin | `vtc.directory.admin` + step-up | Whole directory as JSContact; audited `Critical` |

Error codes:

- `notFound`: the uniform one.
- `superseded`.
- `fieldUnknown`, `fieldRetired`, `valueInvalid` (with `detailsSchema`
  naming the field).
- `aboveCeiling`.
- `notAvailable`: `external: true` sent to `card/update` when the card is not
  already published (publication is `card/publish`, with a signed card).
- `rateLimited`.

### 11.2 `vtc/groups/*` (new)

| Task | Gate | Notes |
|---|---|---|
| `list/0.1`, `show/0.1` | member/admin, by group `visibility` | |
| `create/0.1`, `update/0.1`, `delete/0.1` | `vtc.groups.manage` + `groups` policy | Delete removes bindings first (remote first) |
| `members/list/0.1` | by `showMembers` | Paginated |
| `members/add/0.1`, `members/remove/0.1` | group manager | Parks when the group carries authority (§9.4) |
| `join/0.1`, `leave/0.1` | self | `open` joins at once; `request` creates a request; `leave` is always allowed except for an authority group, where it is a self-reduction |
| `requests/list/0.1`, `requests/decide/0.1` | group manager | For `joinPolicy: request` |
| `bindings/list/0.1` | group manager / admin | |
| `bindings/add/0.1`, `bindings/remove/0.1` | per §9.3 / §9.4 | `grants`/`role` bindings park |

### 11.3 `persona/contact/*` (holder side, VTA; a minor version)

The VTA's contact family gains `starred`, `petname`, `lists`,
`directoryRef` on the contact, and `persona/contact/lists/{list,show,put,delete}`.
The VTC is not involved. The wallet's `vtaWallet.directory` channel
exposes these to the portal page under the same origin and per-write
confirmation rules as rooms.

### 11.4 Capabilities (Appendix C.3)

- `vtc.directory.admin`: field schema, admin-sourced values, defaults,
  export.
- `vtc.directory.notes`: admin notes.
- `vtc.groups.manage`: resource-qualifiable `group:<id>`.

The appendix should also list `vtc.rooms.manage`, which the room specs
already use and the appendix omits.

### 11.5 Storage

- **Keyspace `directory`**:
  - `field:<key>`;
  - `card:<entryId>`;
  - `entry-by-did:<did>` (the index, rewritten on rotation);
  - `search:` tokens (only for fields that are searchable at `members` or
    wider);
  - `intro:<id>` (TTL).
- **Keyspace `directory_notes`**: kept separate so erasure and export
  handle it on its own.
- **Keyspace `groups`**:
  - `group:<id>`;
  - `gm:<groupId>:<entryId>`;
  - `mg:<entryId>:<groupId>`;
  - `binding:<id>`;
  - `greq:<id>`.

All three are `BACKED_UP`; they are the community's social state.
Blobs go in the existing blob store. `Member.extensions` is not used.

## 12. Specification work, in order

Code waits for all of this. A new family cannot be dispatched until its
schema is published and `trust-tasks-rs` is bumped.

### 12.1 dtgwg-vti-spec

1. **New chapter `12a-vtc-directory.md`, area `DIR`.** Register it in
   `specs.json`, `intro.md`, `STRUCTURE.md` and the area and profile
   tables in `95-conformance.md`. Draft requirements:
   - **DIR-001** A member directory MUST be a projection: a field leaves
     only where the subject's visibility, the community's ceiling and
     policy all permit (intersection).
   - **DIR-002** A withheld field MUST be absent. A subject with nothing
     visible MUST be indistinguishable from no subject.
   - **DIR-003** A community MUST NOT widen a member's visibility or
     discoverability choice. Widening a ceiling or default MUST NOT
     change existing choices.
   - **DIR-004** Entries MUST be addressed by an identifier that is not
     derived from, and does not reveal, any DID of the member.
   - **DIR-005** A member DID MUST NOT be a search key for non-admins.
   - **DIR-006** A directory MUST NOT store a member's annotations about
     other members (stars, personal lists, personal notes, petnames).
   - **DIR-007** Self-asserted values MUST NOT be presented as verified.
     A verified value MUST name its issuer.
   - **DIR-008** A request to contact another member MUST NOT reveal to
     the requester whether it was delivered, declined or refused.
   - **DIR-009** A group MUST NOT be consulted to decide authority.
     Authority a group carries MUST be provisioned into the ACL with the
     group as its source (VTI-VTC-020).
   - **DIR-010** A group whose membership confers authority MUST have
     explicit membership. Adding to it MUST be treated as a grant
     (VTI-APV-018), removing from it as a reduction (APV-019).
   - **DIR-011** Dynamic membership MUST be computed from verified facts
     only.
   - **DIR-012** Departure MUST remove the entry from every projection
     and every group, and apply the member's disposition to the card and
     to admin notes (VTI-MEM-033). Rotation MUST carry them (MEM-041).
   - **DIR-013** The community MUST publish a disclosure statement
     derived from its directory configuration, and show it to applicants
     (cred-spec `issuerScope`).
   - **DIR-014** Facet and count answers MUST NOT single out fewer than
     *k* members.
   - **DIR-015** Directory export MUST be limited to administrators and
     audited.
2. **`13-registries.md`.** Land the F.5 proposal: scope REG-001 to
   recognition, and add a publication-purpose requirement. External
   cards are its first user.
3. **Appendix C.3.** The capabilities in §11.4.
4. **`12-vtc-lifecycle.md`.** A note on MEM-033 that names directory
   entries, group memberships and admin notes as things published about
   the member.

### 12.2 dtgwg-trust-tasks-tf

1. `specs/vtc/directory/{fields,card,entries,introduce,introduction,notes,export}/…/0.1`,
   with a shared `_shared/0.1/directory-card.schema.json` (JSContact-based)
   and `field-definition.schema.json`.
2. `specs/vtc/groups/**/0.1`, with a shared `group.schema.json`.
3. `admin/events/{subscribe,event}/0.3` adding the `directory` and
   `groups` topics.
4. `persona/contact` minor version (stars, petnames, lists,
   `directoryRef`) and `persona/contact/lists/*`.
5. The `directoryWrite` and `groups` purposes in the policy schemas.

Each spec carries the linted `## Security & Privacy` sections. Each
declares `identifierScope: pairwise` where it can (introductions), and
`exposure` honestly (`entries/*` discloses personal data).

## 13. Decisions and open questions

Decided 2026-10-18 (second round): `keys/sign-document` for issuance, a minimal `vtc-group` template, purposes defined in VTI, portal delegated signing, 30/10-day group VMC validity, dynamic-group opt-out, and C2/C4–C8 kept as drafted in tf #817/#815. Decided earlier: every community group has its own DID and issues group VMCs (§9.5). **Q1** member's VTA, **Q2** grant sets only, **Q3** `listed` with display name + role. Q4–Q7 follow the recommendation unless the specification review says otherwise.

| # | Question | Recommendation |
|---|---|---|
| Q1 | Where the personal layer (stars, lists, notes, petnames) lives | **The member's VTA** (§6). The alternative, VTC-stored ciphertext only the member can open, still shows the operator who annotates whom, through timing and volume |
| Q2 | Groups → roles: grant sets only, or let a group set the single community role? | **Grant sets only** in this version. Making the community role multi-valued is an ACL-chapter change, and a group-set role needs a precedence rule between groups |
| Q3 | New cards `listed` by default, or opt-in? | **`listed`, with only display name and role visible to members.** Big or sensitive communities change the default by config. An opt-in default empties directories (Mastodon) |
| Q4 | A new spec chapter (`DIR`) or a section under `MEM`? | **New chapter**: one area per chapter, and groups are not lifecycle |
| Q5 | External card format before the r-card exists | **Member-signed JSContact card**, moved to the r-card later as a new card version |
| Q6 | Should `connections` count pairwise edges known only to the viewer's VTA? | **No.** The server cannot see them, so the server cannot project by them. The viewer's VTA only shows badges |
| Q7 | Do group managers need their own consent rules for adding members to a room-bound group? | No for `read`/`write` rooms. Yes (park) when the binding carries `curate`/`admin` |

## 14. Phasing

| Phase | Scope | Depends on |
|---|---|---|
| **P0** | Specs §12 (tf first; vti-spec DIR chapter + C.3) | — |
| **P1** | Field schema, cards, listing/search, `entries/*`, `query/0.1` re-pointed, portal Directory + My card, console settings | P0 tf + trust-tasks-rs bump |
| **P2** | Static community groups with their own DID + group VMCs (§9.5), managers, `groups/*`, room bindings + reconciler | P1; `vtc-group` DID template |
| **P3** | Personal layer in the VTA (`persona/contact` minor), wallet channel, stars/lists/petnames/notes in the portal, VRC badges, introductions | P1; wallet release |
| **P4** | Admin notes and export, `credential`-sourced fields (`card/present`) — **built** | P1 |
| **P5** | Grant bindings (§9.4) with action-list consent | P2 |
| **P6** | Dynamic groups | P2 |
| **P7** | Pictures, and external cards via the registry — **built** | REG change landed (vti-spec #68); tf #826, #827 |

## 15. Sources

### Products and standards

- Slack, custom profile fields:
  <https://slack.com/help/articles/212281478-Customize-member-profiles>
- Discourse, user fields:
  <https://meta.discourse.org/t/create-and-configure-custom-user-fields/113192>
- Google Workspace, custom attributes:
  <https://knowledge.workspace.google.com/admin/users/create-custom-attributes-for-user-profiles>
- Mastodon, profile directory and opt-in discovery:
  <https://docs.joinmastodon.org/user/profile>
- Matrix (Synapse), user directory search scope:
  <https://element-hq.github.io/synapse/latest/user_directory.html>
- Signal, usernames and private nicknames/notes:
  <https://signal.org/blog/phone-number-privacy-usernames/>
- JSContact, RFC 9553: <https://www.rfc-editor.org/rfc/rfc9553>
- JMAP Contacts, RFC 9610: <https://www.rfc-editor.org/rfc/rfc9610>
- vCard 4, RFC 6350: <https://datatracker.ietf.org/doc/html/rfc6350>
- SCIM, RFC 7643: <https://datatracker.ietf.org/doc/html/rfc7643>
- SCIM group-members draft:
  <https://datatracker.ietf.org/doc/draft-zollner-scim-group-members/>
- Entra role-assignable groups:
  <https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept>
- Okta group rules:
  <https://help.okta.com/en-us/Content/Topics/users-groups-profiles/usgp-create-group-rules.htm>
- Facebook contact-importer scrape and fine (enumeration):
  <https://thehackernews.com/2022/11/irish-regulator-fines-facebook-277.html>
- Peer DID method: <https://identity.foundation/peer-did-method-spec/>
- GDPR Art. 25: <https://gdpr-info.eu/art-25-gdpr/>

### Within this workspace and its sibling repositories

- dtgwg-vti-spec, chapters 11–14 and Appendix F.5
- dtgwg-cred-spec, `issuerScope`, VRC, privacy items
- tf `vtc/directory/query/0.1`, `vtc/members/registry-consent/0.1`,
  `vtc/relationships/*/0.2`, `persona/contact/*`
- `design-docs/persona-profiles-design.md`, `persona-vocabulary.md`,
  `vtc-membership-hooks.md`
- `docs/05-design-notes/vtc-admin-roles.md`, `vtc-ceremony-catalog.md` §5
