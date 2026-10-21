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
| `vtc/directory/images/upload/0.1` | members, `vtc.directory.admin` | Hand the community a picture for a card; it keeps its own re-encoding (below) |
| `vtc/directory/images/get/0.1` | anyone, through the projection | A picture's bytes, where the caller's projection of that entry shows it |
| `vtc/directory/card/publish/0.1` | the member, as their membership DID | Publish their external card: their public values, signed by them (below) |
| `vtc/directory/card/public/0.1` | anyone, signed or not | A published external card, exactly as its member signed it |
| `vtc/directory/card/present/0.1` | the member, holding the credential | Fill `credential`-sourced fields from a presentation; the community keeps only the claims (below) |
| `vtc/directory/notes/{append,list}/0.1` | `vtc.directory.notes` | Administrators' notes about a member (below) |
| `vtc/directory/notes/export/0.1` | `vtc.directory.notes`, with a bound passkey | Every note about a member, to answer their request for the data held about them |
| `vtc/directory/export/0.1` | `vtc.directory.admin`, with a bound passkey | Every active member's card as JSContact |
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
  card can be published beyond the community. The answers are read from which
  tasks this build serves and, for external cards, from `[directory]
  external_cards`, so they change by themselves when a feature arrives or the
  operator turns one off. This build keeps no notes and has no groups, and
  publishes external cards unless turned off;
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

The portal's home page greets the member by name and shows **Your card**: their
picture, what every member sees, and whether the card is published. **Directory**
lists members by name with their picture (or their initials on a colour of their
own), pronouns and a line of their About text; members who show no name are
folded into one line rather than listed as blank cards. A member's page shows
their About text, links (http and https only) and any other field the viewer may
see, and **Save contact** downloads a vCard of exactly that, made in the browser.
Every page has a breadcrumb back to the portal.

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

A member sets their picture on **Your card**: the portal scales it down in the
browser before sending, and shows other members' pictures only once their bytes
match the digest the card names. **Show every field to** sets every field at once —
a starting point, capped at each field's own limit — and each field can still be
changed on its own before saving. Publishing the card beyond the community is the
member's own signature, made in their wallet: where the wallet offers
`window.vtaWallet.directory`, **Publish from your wallet** hands it over, and the
wallet shows every value before anything is signed. The portal also shows where
a published card stands, and offers **Stop publishing**, which a delegated key
may do because it narrows.

Not yet served: introductions. Groups are their own family ([community groups](groups.md)). A member cannot yet
present a credential from the portal: that waits on the wallet offering it.

## Verified values (`card/present`)

A field of type `claim` is `credential`-sourced: nobody types its value. Its
definition names the claim it reads — `constraints.claim`, a `credentialType`
the credential must carry, a `claimPath` (a JSON Pointer into
`credentialSubject`, or into an SD-JWT's disclosed claims) and optionally the
`issuers` it accepts. A member fills it by presenting a credential:

- **The binding.** A Data Integrity presentation carries `nonce` equal to the
  request's `id` and `domain` equal to the community's DID, signed by its
  holder's proof; a proof that also states `challenge` or `domain` must state
  the same. An SD-JWT's key-binding JWT carries them as `nonce` and `aud`
  (trust-tasks-tf #831).
- **The holder is the member.** A Data Integrity presentation's holder proof
  must be the member's own DID, and a credential naming a subject must name
  them. An SD-JWT's holder key is the member's DID itself (a `did:key`), or a
  key the member's DID document lists for `authentication` that the
  key-binding JWT names in its `kid`. A presentation another member obtained is
  `presentationInvalid`, whatever else about it verifies.
- **The credential.** Its issuer's proof, its validity window (either
  spelling) and its status (`credentialStatus` or a token status list) must
  all hold; a status that cannot be read is not in force.
- **The issuer.** One the field lists; with no list, one the community trusts
  — its own DID, an issuer its trust registry recognises, or one its swiyu
  trust vouches for. Anything else is `issuerNotAccepted`.
- **What is kept.** Each field stores `{ value, issuer, credentialType,
  verifiedAt, validUntil }`. The presentation, the credential and every other
  claim are dropped before the card is written, and refusals log their reason
  rather than answer it. The member's visibility choices are left alone.
- **Expiry.** A value whose `validUntil` has passed is shown to nobody at once,
  and the directory's hourly pass withdraws it from the card (audited, by
  `expiry`).

`clear: true` withdraws a named field the presentation does not answer, instead
of refusing with `claimMissing`. The portal and the console show a verified
value with its credential type as the badge, and its issuer.

## Administrators' notes

Administrators who hold `vtc.directory.notes` keep notes about members
(VTI-DIR-030 – 033). The capability is apart from `vtc.directory.admin`, so a
community can let someone keep notes without changing what the directory
discloses; `community-admin` holds both.

- **Never on the card.** Notes are stored apart from cards and appear in no
  directory read, whatever the `directory` policy says. A member never sees them.
- **Never edited.** A correction or withdrawal is a later note that redacts the
  earlier one. A redacted note's text is withheld from every read except the
  export below.
- **Released to the member only deliberately.** `notes/export` returns every
  note about the member, redacted ones as written, to answer their request for
  the data held about them. It takes the exporter's passkey bound to that one
  export, and is audited at Critical.
- **Audited by reference.** Every write and read is audited with the entry and
  the note, never its text (`DirectoryNoteAccessed`, `DirectoryExported`).
- **At departure** a purge erases them; a tombstone or historical record keeps
  them for `[directory] retention_days`, after which the hourly directory pass
  erases them.
- The disclosure statement says the community keeps notes, by itself, now that
  `notes/append` is served.

In the console, a member's page shows an **Administrators' notes** card to
holders of the capability: add a note (with an optional follow-up date),
withdraw one, or export them for a data request.

## Export

`vtc/directory/export` returns every active member's card as JSContact, every
field included (derived ones as vendor properties), a page at a time with
cursors bound to the exporter. The first page takes the exporter's passkey bound
to it and is audited at Critical with the number of cards; no note is ever in
it. The console's **Directory → Entries** tab has **Export the directory**,
which downloads the whole export as JSON.

## Pictures

An avatar, or a community field of type `image`, holds a `CardBlobRef` — a
digest, a media type and a size — never a URL.

- **Re-encoded, never kept as sent.** `images/upload` decodes the picture,
  applies its orientation, scales it to at most 512 pixels on the longer side,
  and encodes it afresh (JPEG, or PNG where it has transparency). No metadata
  block — EXIF, XMP, ICC, comments — and no byte the member sent survives, so
  the digest is the community's own and links nothing across communities
  (VTI-DIR-051). PNG, JPEG and WebP are read; a picture that claims more pixels
  than the community decodes is refused `tooLarge`.
- **Yours until a card holds it.** An upload belongs to whoever sent it: a
  member's picture can go only on their own card, an administrator's only on
  an `admin`-sourced field. A digest seen on someone else's card never puts
  their picture on yours. An upload no card takes up within 24 hours is erased,
  and so is a picture no card holds any more.
- **Read through the projection.** `images/get` names the entry and the field,
  and answers exactly when `entries/show` would show that field to the same
  caller. A caller the directory does not answer is the public, and is answered
  only a picture on a published external card. Every refusal is the same
  `notFound`.

## External cards

A member may publish their card so that anyone can find it (VTI-DIR-046). The
card is theirs, not the community's: a JSContact card holding exactly their
**public values** — what the public would be shown, by their visibility, the
field's ceiling and the `directory` policy — in the fixed shape
`card/publish` defines, naming their membership DID as `issuer` and signed
with it — so a wallet whose agent holds the key can have it signed with
`keys/sign-document`, which signs only as the DID a document names. The community never
composes, signs or edits it (VTI-REG-004 item 4).

- **Publishing** needs the member's consent to registry publication, a card
  that is exactly their public values (`cardMismatch` names the fields that
  differ), and their own signature for `assertionMethod` (`signatureInvalid`).
  A delegated portal key never publishes. The community stores the card exactly
  as received, turns `external` on, and adds a pointer to the member's
  recognition record in its trust registry (`context.directoryCard`: the
  purpose, the entry, the card's digest, and the task to read it with) — no
  profile value goes into the registry.
- **Serving.** `card/public` answers anyone, signed or not, with the card as
  signed, its digest and when it was published.
- **Never stale.** The moment the member's public values change — their own
  update, an administrator's assertion, a ceiling narrowed, a field retired, a
  policy change, a suspension — the card stops being served and its pointer is
  removed; the card shows `awaitingSignature` until the member signs the current
  values. Every serving path checks first, so a change no write path saw is
  caught too, and the hourly directory pass catches the rest.
- **Withdrawal** — the member turning `external` off, withdrawing registry
  consent, or leaving — stops serving and erases the card at once, then removes
  the pointer (retried until it lands). At departure this happens before
  anything else (VTI-DIR-120).

The shipped `directory` policy answers the public question — what a card
published beyond the community may carry — with the community's own
projection; a policy that denies it keeps every external card empty. A default
installed by a build before external cards denied it, and is replaced at boot
while it is still the workspace's own row.

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
- **external**: whether their card is published beyond the community. Turned
  on only by publishing a card they signed (`card/publish`); turned off by
  `card/update` with `external: false`, which withdraws it.

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
external_cards = true        # members may publish their card beyond the community
image_uploads_per_hour = 30  # pictures one member or administrator may upload
```

All optional. A value the VTC cannot use stops it at boot. These are host
settings, not runtime-patchable.

## Correlators (VTI-DIR-053)

What the directory introduces that can link a member across time or places
(VTI-CMP-062):

- **Entry identifiers** (`dir_…`): random, never derived from a DID, and kept
  across a rotation — so they link a member's entry to itself over time inside
  this community, and nothing else.
- **A published external card**, its digest and the `directoryCard` pointer on
  the member's recognition record: public by the member's choice, and the
  widest correlator the directory makes — anyone holding it can link the entry,
  the recognition record and what the member chose to show.
- **Picture digests**: of this community's own re-encoding, so the same
  photograph has a different digest in every community.

## Departure and rotation

A member's departure first withdraws any external card, then erases their card
with a `purge` or `tombstone` disposition and keeps it with `historical` — kept, it is never read again by
anyone but an administrator (VTI-DIR-121, VTI-DIR-111). A rotation of their DID
carries the card to the new DID with the same entry identifier (VTI-DIR-122).

## Audit

`DirectoryFieldChanged` (define, update, retire, purge, and whether it widened),
`DirectoryCardChanged` (the entry, who wrote it, the fields named, the
revision), `DirectoryCardPublication` (the entry, `published` or `withdrawn`
and why, the card's digest, the signed document) and `DirectoryImageStored`
(the digest, and whose it is) — never a value or a picture (VTI-AUD-005). A
publication or withdrawal names the member as its target, which is how the
registry syncer learns to re-publish their recognition record.
