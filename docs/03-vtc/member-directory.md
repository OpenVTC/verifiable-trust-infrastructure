# Member directory

A community's **member directory** lets members find, recognise and reach one
another. It is built from three things, each with its own owner:

| | Owner | Where it lives |
|---|---|---|
| **The field schema**: what a card can hold, and the widest audience each field may reach | The community's administrators | This VTC (`directory` keyspace) |
| **Each member's card**: their values, who sees each one, and how findable they are | The member | This VTC, keyed by an entry identifier |
| **Stars, personal lists, private notes, nicknames for others** | Each viewer | The viewer's own VTA, never here (VTI-DIR-001) |

Specification: *Community Directory and Groups* in the VTI specification
(`VTI-DIR-*`), and the `vtc/directory/*` Trust Tasks. Design:
[`vtc-member-directory.md`](../05-design-notes/vtc-member-directory.md).

## What this build serves

| Task | Who | What |
|---|---|---|
| `vtc/directory/fields/list/0.1` | members, administrators | The schema; retired fields to `vtc.directory.admin` only |
| `vtc/directory/fields/define/0.1` | `vtc.directory.admin` | Add a community field (reverse-DNS key, at most 64 active) |
| `vtc/directory/fields/update/0.1` | `vtc.directory.admin` | Change a field; a **widening parks** in the action list (below) |
| `vtc/directory/fields/retire/0.1` | `vtc.directory.admin` | Hide a community field at once; its values are erased after the retention period; its key is never reused |
| `vtc/directory/card/show/0.1` | the member | Their own card, whole |
| `vtc/directory/card/update/0.1` | the member | Their values, visibilities, listing, search and introductions settings |
| `vtc/directory/card/assert/0.1` | `vtc.directory.admin` | Values of `admin`-sourced fields (a chapter, a grade); the member sees them and cannot change them |
| `vtc/directory/entries/list/0.1` | members, administrators | Browse, search and filter, each entry projected for the caller |
| `vtc/directory/entries/show/0.1` | members, administrators | One entry by entry identifier; by DID only for `vtc.directory.admin` or `vtc.members.manage` |
| `vtc/directory/query/0.1` | members, administrators | The older lookup by DID, answered through the same projection |
| `vtc/directory/disclosure/0.1` | anyone the join manifest answers | The disclosure statement (below) |
| `vtc/join-requests/manifest/0.4` | anyone, unless join discovery is closed | The join criteria **and** the disclosure statement, as `directoryDisclosure`; 0.3 is still served without it |

## What applicants are told

Before anyone applies, they are told what the directory would disclose about
them and to whom (VTI-DIR-130). The VTC **generates** this statement each time
it is read, from what it runs — nobody writes it, so it cannot describe a
directory other than this one:

- every active field: who writes it (the member, the community, a
  credential, the community's records), what a new card shows it to, and the
  widest audience a member may show it to (its ceiling);
- a new card's listing (`[directory] default_listing`) and search setting;
- how far a member's membership DID can reach: the `did` field's ceiling, or
  administrators only when that field is disabled;
- whether administrators keep notes, whether there are groups, and whether a
  card can be published beyond the community. This build has none of these, so
  it says so; the answers are read from which tasks it serves, and change by
  themselves when those features arrive;
- a `statementDigest`, so an applicant can record which statement they saw.

Every audience is the widest a value can reach. The `directory` policy only
narrows, so the statement never understates what can be disclosed.

Applicants receive it in the join manifest (0.4), which every applicant reads,
and anyone can read it on its own with `vtc/directory/disclosure/0.1`. Both
are answered to exactly the callers the manifest is: closing public join
discovery (`vtc/community/join-discovery/update`) closes both to callers the
community cannot identify.

Administrators see it on the console's **Directory → What applicants see**
tab, in the same plain words a wallet would show, next to a table of every
field.

## In the member portal

Members use the directory from the portal: **Directory** (browse, search, one
entry) and **Your card** (values, who sees each, listing, search and
introductions). The pages sign with the browser's sign-in key, which the member
lets act for them in the directory when they sign in with their wallet:

- The VTC serves `auth/oob/{prove,respond}/0.2`. A member sign-in's step 2
  offers `signingScope: ["vtc/directory"]`, and the member's wallet shows it
  and copies it into the `auth/oob/grant/0.2` their VTA signs.
- At `redeem` the VTC records the delegation for the browser key
  (`member_portal::delegation`). Directory documents that key signs are read
  as the member's while the session lives; signing out or revoking the session
  disarms it at once, and a delegated document never keeps the session alive.
- A delegated key can never make a value `public`, publish the card beyond
  the community, or sign anything outside the scope — `auth`, `acl`,
  `consent`, `task-consent` and `confirm` are refused whatever a grant says.
- The portal keeps the key in the browser's storage for the session and
  forgets it at sign-out. A passkey sign-in, or a 0.1 grant, delegates
  nothing: the pages ask the member to sign in with their wallet.

Not yet served: groups (`vtc/groups/*`), introductions, administrators' notes,
export, credential-sourced fields (`card/present`), images (an avatar has no
upload task yet, so image values are refused), and external cards
(`discoverability.external: true` is refused `notAvailable`).

## The projection

Nobody reads another member's card. They read a **projection** of it: a field
is shown to a viewer only where **all three** of these hold (VTI-DIR-020):

1. the visibility the **member** chose for it (or the field's default) admits the viewer;
2. the field's **ceiling** admits the viewer;
3. the community's `directory` policy permits it.

The audiences, narrowest first: `admins`, then `groups` and `connections`
(neither inside the other), `members`, `public`. A withheld field is absent,
never `null`, and an entry with nothing visible is answered exactly as one that
does not exist (VTI-DIR-110).

A new card shows the member's **display name and community role to members**,
and everything else to administrators only (VTI-DIR-041). Their DID is never
shown beyond the administrators until they choose (VTI-DIR-042).

`connections` are members holding an in-force verified relationship with each
other under their membership DIDs (VTI-DIR-023). `groups` admits nobody until
community groups ship.

## Discoverability

Each member chooses, separately:

- **listing**: `listed` (shown when browsing), `findable` (only by a search that
  matches it) or `hidden` (by nobody but the administrators). Every member may
  always choose `hidden`.
- **search**: what a search may match: name or nickname (`byName`), only an
  exact nickname (`exactNickname`), or nothing (`off`). A DID is never a search
  key for a member (VTI-DIR-044).
- **external**: not available yet.

Browsing lists only `listed` cards whose required fields are filled in (by
default, the display name). A search needs three characters, or an exact
nickname, and returns at most 50 matches. Cursors are bound to the caller and
the question, so a page cannot be resumed under another (VTI-DIR-112). Facet
counts below the threshold are shown only as "fewer than *k*" (VTI-DIR-113).

## Widening is held for a second administrator

Narrowing a field — a lower ceiling, disabling a base field, making it
unsearchable — applies at once. Widening one — a higher ceiling or default, a
field made searchable or a facet, a field re-enabled, a requirement dropped —
is parked in the [action list](admin-access.md) as `directory.field.widen` for
the other holders of `vtc.directory.admin`, and runs on their approval against
the field as it is then (VTI-DIR-024). In single-administrator mode the
requester's bound step-up stands in, as for every consent.

No widening ever changes a choice a member already made.

## Policy

| Purpose | Package | Decides | Shipped |
|---|---|---|---|
| `directory` | `vtc.directory` | Whether a reader sees an entry, and may narrow its fields (`with.fields`) | Members and administrators see the community's own projection, unnarrowed |
| `directoryWrite` | `vtc.directory_write` | Whether a card may hold what a write leaves on it; refuses with `field` and `reason` | Accepts everything the community's checks accept |

Neither can widen anything. `directoryWrite` is never asked about a change that
only narrows. A `directory` default installed by an earlier build answered
members with `fields: ["did", "role"]`; it is replaced at boot while it is still
the workspace's own row.

## Configuration

```toml
[directory]
default_listing = "listed"   # or "findable", "hidden": where a new card starts
retention_days = 30          # how long a retired field's values are kept
facet_threshold = 5          # k: smaller counts are never exact (at least 2)
list_rate_per_minute = 60    # entries/list requests per caller
```

All optional. A value the VTC cannot use stops it at boot. These are host
settings, not runtime-patchable.

## Departure and rotation

A member's departure erases their card with a `purge` or `tombstone`
disposition and keeps it with `historical` — kept, it is never read again by
anyone but an administrator (VTI-DIR-121, VTI-DIR-111). A rotation of their DID
carries the card to the new DID with the same entry identifier (VTI-DIR-122).

## Audit

`DirectoryFieldChanged` (define, update, retire, purge, and whether it widened)
and `DirectoryCardChanged` (the entry, who wrote it, the fields named, the
revision) — never a value (VTI-AUD-005).
