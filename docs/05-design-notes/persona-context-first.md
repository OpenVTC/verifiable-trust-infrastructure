# Persona — context-first identity

**Status:** proposed. The first design note for the `persona/*` family.

Written after reviewing `vta-persona`, the `persona/*` Trust Tasks, and the
upstream specifications in `dtgwg-trust-tasks-tf/specs/persona/` against the UX
work and discussion in
[dtgwg-htx-tf#11](https://github.com/trustoverip/dtgwg-htx-tf/discussions/11).

## Summary

The storage model is right and should not be rewritten. The **authoring** model
is inverted, one layer has a role collision, and the privacy guard has a blind
spot that the proposed UX would funnel every user directly into.

| | verdict |
|---|---|
| Pool above contexts, faces as projections | **keep** — it carries the privacy properties |
| One-way boundary, materialised copies pushed down | **keep** — the strongest part of the design |
| Pool-first authoring | **invert** — author from the context |
| Worlds / facets as a creation step | **derive** — offer them, never ask for them |
| Correlation index | **fix first** — it cannot see the path we are about to recommend |

Nothing below requires abandoning the pool. The limitation that prompted the
rewrite — *"how do I have two faces with different names"* — is not a
data-model limitation; see [§3.1](#31-the-missing-designation).

## 1. What exists today

```
Attribute pool   agent-scoped   one value, held once, `attribute_id` is identity
      ↑ referenced by
Face (Profile)   agent-scoped   ordered entries: ref | pinned | override | inline
      ↑ bound by
Binding          context-scoped face ↔ persona DID; pushes a materialised copy down
Facet ("world")  agent-scoped   an arrangement over faces and attributes
Local face       context-scoped inline-only; cannot reference the pool
```

Three properties are load-bearing and this note preserves all three.

**The boundary is one-way by address space, not by permission check.** A context
receives `MaterialisedClaim` — values, flat, with no `attribute_id`. A separate
type from `ResolvedClaim` precisely so no future edit can leak a pool identifier
by forgetting to clear a field. Under compromise of a context, the rest of the
pool is not merely forbidden, it is absent.

**A context-local face cannot reach the pool, and that is enforced by the
parser.** `LocalProfileEntry` has no `ref` member, so a document attempting the
reach fails to deserialise (`a_local_entry_cannot_reference_the_pool`). Not a
handler that might forget.

**`PersonaHolder` is additive.** No role derives it (`ADDITIVE_CAPABILITIES`),
and granting it is super-admin-only. Managing your own identity does not require
handing a client authority over every context on the agent.

## 2. The inversion

Both reviewers in #11 arrive independently at the same conclusion: do not start
from the identity screen. Start from the context — an invitation arrives, the
holder is told what is needed, and a face is composed *there*. The comprehensive
identity view becomes a curation surface populated over time, not the place
anything is authored.

The decisive argument is not ergonomic, it is informational. **The context
arrival is the only moment at which the system knows what is actually being
asked for.** Everywhere else the holder is guessing at contexts they might one
day need, and pre-thinking a set of faces for contexts that do not exist yet is
work that is mostly wasted and entirely unguided.

We already hold the primitive. `persona/local/*` is, verbatim, "a face that
lives inside one context, built only from values typed there". That is the
compose-here step, it exists, and it is the *safest* default: nothing enters the
pool, so no cross-context link is created by an act the holder took for one
context only.

The journey, in primitives we have or nearly have:

```
invitation → manifest: what is asked for            (§5.2 — gap)
           → offer existing faces, or compose here  (§5.3 — new, local by default)
           → later: promote local → pool             (§5.3 — new, the explicit share act)
           → later: notice a cluster, offer to name it (§4)
```

This inverts today's default, where entering the pool is the *only* way to build
a face at all, because `put_profile` refuses dangling references. Sharing
becomes a deliberate act rather than a precondition.

### 2.1 Promotion changes a face's scope, and is one-way

A face that references the pool cannot live in context-addressable space — that
is the boundary, not a detail. So promoting one value in a local face moves the
whole face up:

1. create the pool attribute from the inline value;
2. create an agent-scoped face with the same entries, the promoted one now a
   `ref`, the rest still inline;
3. rebind the persona DID to it;
4. delete the local face.

It is one-way. Demoting cannot be defined, because the pool attribute may by
then have other referrers, and removing it would silently change what other
faces present. The UI must say "this value becomes reusable across faces" and
not offer an undo it cannot honour.

## 3. Findings

Four defects found during review. The first is a blocker for §2; the rest are
small.

### 3.1 The missing designation

**Two faces with different names already work, three ways over.**
`Attribute.attribute_id` is identity and `type` is not — `model.rs` says so
explicitly ("three phone numbers, a legal name and a preferred name"). So: two
pool attributes of type `name.display`; or `ProfileEntry::Override`; or
`ProfileEntry::Inline`.

What is missing is that **nothing designates which entry is the face's presented
name.** `Face.entries` is a flat `Vec<ProfileEntry>` with no slots, and
`Face.name` is the holder's *private* label ("Work", "Gaming"), documented as
not disclosed. A consumer rendering "what does this face call itself" must scan
for `name.*` and guess, and with both a `name.legal` and a `name.display`
present it guesses wrong half the time.

**Fix:** an optional `slot` on `ProfileEntry` (§5.5). Not a model rewrite.

### 3.2 The correlation index cannot see override or inline values

`correlation::blind` is called from exactly five sites, **all in `store.rs`**,
on the attribute put/delete/count paths. `analyze_correlation` walks pool
attributes and the reverse index. Therefore:

- an `Override` value is never indexed;
- an `Inline` value is never indexed;
- the same throwaway address typed into two local faces in two different
  contexts — precisely the link the index exists to report — produces no
  finding;
- `persona correlate --profile-id` analyses a face and silently skips every
  override and inline entry in it.

Today this is a defect. Under §2 it becomes a structural contradiction: the
recommended journey funnels every user down the one path the guard cannot see,
so *the better the UX gets at steering people local, the blinder the guard
becomes*. This must be fixed before the flow is built, not after.

### 3.3 `OverrideValue.label` is written and never read

`ResolvedClaim` has no `label` member, and the `Override` arm of
`resolve_profile` copies only `value` — while `profile.rs:162` documents the
form as replacing "value **and label**". A holder who labels an override loses
it silently. Either carry it or remove the field; do not leave a member the
wire accepts and the store discards.

### 3.4 The holder's private face name crosses the boundary

`binding/get` and `binding/list` are `Reach::Context` and return `profileName`
(`persona.rs:1120`, `:1152`), cached on `BindingRecord` for exactly that
purpose. But `model.rs` documents `Profile.name` as "Not disclosed", and the
sibling `Facet.name` doc makes the case sharply: *"'Work' discloses nothing and
'the divorce' discloses a great deal."* The upstream `CONVENTIONS.md` §3 permits
it; the code comment forbids it. One of the two is wrong, and the conservative
reading is the code comment's.

**Fix:** drop `profileName` from the context-reach responses and replace it with
a per-binding label the holder sets — a name chosen *for* that context (§5.6).

### 3.5 Super-admin bypasses `PersonaHolder`

`authorize` computes `granted` only when `!claims.is_super_admin()`
(`persona.rs:217`), and `decide` returns `Ok` for super-admin unconditionally
(`:239`). The capability's premise is that no role implies it — yet the one
credential most likely to be sitting in tooling implies it anyway, and the same
credential is what grants it.

Not obviously wrong, but it is a decision that should be recorded rather than
inherited. Listed here so it is taken deliberately.

## 4. Worlds are a result, not a step

`Facet` is already the right *shape* for what the mockups call a World: a pure
arrangement with no semantics, where `delete_facet` deliberately has no
cascading form, because "an arrangement that could take its members with it is a
folder, and a holder who reads it as a folder is right to be afraid of it."

That is exactly the property a thing needs if the system is going to **suggest**
it. After three joins, notice that three faces cluster and offer "shall I call
these Work?". Accepting, renaming or dismissing costs nothing and risks nothing.
An "Add a World" screen, by contrast, asks the holder to pre-think the taxonomy
before they have the members — the same mistake as pool-first authoring, one
level up.

**A context is not a subset of a world.** This was asked directly in #11 and the
model answers it: worlds group *faces*; contexts relate to faces through
*bindings*. A world spans contexts, and one context can host faces from
different worlds. The "Contexts" list on the world screen is a derived read —
*where the faces in this world are currently worn* — and today it cannot even be
queried (§5.4). A screen implying containment would teach a mental model the
system does not have.

## 5. The changes

In dependency order. Every wire change lands in `dtgwg-trust-tasks-tf` first and
reaches this workspace through a `trust-tasks-rs` bump — never as a local edit
to a generated type.

| # | change | crate | breaking |
|---|---|---|---|
| 5.1 | index override + inline values | `vta-persona` | no (additive prefix) |
| 5.2 | manifest can request attributes | `vtc-service` + spec | no (new criterion form) |
| 5.3 | `face/compose` + `attribute/promote` | spec, `vta-persona`, SDK, CLI | no (new tasks) |
| 5.4 | `FaceReach` + `face/usage` | spec, `vta-persona` | yes — `Face` gains a member |
| 5.5 | `slot` on `ProfileEntry` | spec, `vta-persona` | yes — untagged union |
| 5.6 | drop `profileName`, add binding label | spec, `vta-persona` | yes — response shrinks |
| 5.7 | `Provenance::Derived`, endorsements | spec, `vta-persona` | yes — enum grows |
| 5.8 | facets suggested, not authored | CLI / UI | no |

### 5.1 Index override and inline values — do this first

Add a second index prefix for face-carried values, unioned by the reader, rather
than changing the existing `blind → Vec<Ulid>` rows. Additive, so no store
migration.

Write points: `put_profile`, `put_local_profile`, and both deletes. Subject is
the carrying face plus the entry position, not an attribute id — there is no
attribute.

**The index for a context-local value stays agent-scoped, and this is
deliberate.** It looks like a boundary violation and is not: the index is read
only by holder-reach tasks, a context cannot address it, and what crosses is an
`HMAC-SHA256(agent_key, canonical(value))` that reveals nothing under a database
dump. The alternative is a per-context index, which cannot see across contexts
by construction — and seeing across contexts is the entire reason the guard
exists. What is recorded above the boundary is the *existence* of a value, never
the value.

### 5.2 The manifest must be able to ask for attributes

Today `join-requests/manifest` returns `criteria` — DCQL presentation
definitions over registered credential types. It cannot ask for an attribute, so
a community wanting a display name and a country has nothing to put on the
"what's required" screen, and **there is currently no connection at all between
the VTC join ceremony and the persona store.** Under the assumption that most
holders arrive by invitation, this is the load-bearing gap for the whole flow.

A criterion gains an alternative form beside `presentationDefinition`:

```jsonc
{
  "id": "profile-basics",
  "description": "A display name and a country, so members can find you.",
  "attributes": [
    { "type": "name.display", "required": true },
    { "type": "address.country", "required": false }
  ]
}
```

A criterion carries one form or the other, never both. The manifest **names
types and never values**, and stays unauthenticated public discovery — it is a
statement of the community's requirements, and must not become a probe of
anyone's pool.

### 5.3 `persona/face/compose` and `persona/attribute/promote`

Context-scoped, local by default:

```jsonc
{
  "contextId": "…",
  "name": "…",                 // the holder's private label
  "personaDid": "did:key:…",   // optional: bind immediately
  "facetId": "…",              // optional
  "claims": [
    { "type": "name.display", "value": "Alice", "valueType": "string",
      "label": "the one the co-op sees", "slot": "displayName",
      "share": "local" },
    { "attributeId": "01J…" }  // reuse something already in the pool
  ]
}
```

- `share: "local"` (default) → an inline entry; nothing enters the pool.
- `share: "pool"` → find-or-create a pool attribute and reference it.
- `attributeId` → reference an existing pool attribute.

**Scope falls out of the claims:** every claim local → a context-local face.
Any claim pooled or referenced → an agent-scoped face, bound into the context.
That preserves the boundary without a scope parameter anyone can get wrong.

The response carries `correlationFindings` inline, from the existing candidate
path — `analyze_correlation` already accepts a value the holder has not written,
built for exactly this. That is what lets the collect step warn *before* the
mistake, which matters most for derived attributes (§5.7), where bulk
pre-population puts the same values into several faces at once.

`persona/attribute/promote` performs §2.1. It is one-way and the UI must say so.

**As built** (trust-tasks-tf #569):

- **Named `persona/profile/compose`, not `face/compose`.** Every other task in
  the family says `profile`, and a second noun in the URI space for the same
  record is the vocabulary problem §7 item 3 already raises. If "face" wins,
  it should win everywhere at once.
- **No inline `correlationFindings`.** The warning that matters is the one
  *before* the write, and `correlation/analyze` with `candidate` already gives
  it per value, holder-authorized, with identifiers. The compose response
  carries the advisory count `profile/put` carries, so the family's rule —
  writes return counts, analyze returns identifiers — holds.
- **No `facetId`.** A facet is arranged with `facet/put`; composing does not
  also arrange.
- **Reuse matches self-asserted attributes only.** A credential-backed
  attribute holding the same value presents an issuer's attestation and goes
  stale with its credential; a value typed at compose is neither.
- **§9.7 is not folded in.** `personaDid` is optional and binds an existing
  persona. A persona in openvtc is a `did:webvh` minted from a DID template
  with its own services — not something the persona store can mint — so
  "wear this face here without naming a DID" needs the minting step designed
  on its own.
- **Promote keeps the face's id.** The pool and the local address space are
  separate, and the correlation index's carriers already distinguish a local
  face from a pool one, so the same id in both for the length of a promote is
  safe — and it means a client holding the id keeps working. The steps are
  ordered so an interrupted promote leaves the local face worn, and a retry
  finishes it.

### 5.4 `FaceReach` and `persona/face/usage`

A face gains an opt-in allow-list, enforced in `set_binding`:

```rust
pub enum FaceReach {
    Anywhere,                 // default
    Only(Vec<String>),        // context ids
}
```

**An enum, not `allowed_contexts: Vec<String>`.** This workspace has been bitten
three times (#746, #769, #770) by an empty context list meaning two opposite
things, and carries a standing rule against testing `.is_empty()` for that
reason. An enum makes "unrestricted" and "nowhere" unconfusable rather than
remembered. A context-local face's reach is its context by construction; do not
store one.

`persona/face/usage/1.0` — holder-reach — returns `[{contextId, personaDid,
boundAt}]` for a face. Needed to audit an allow-list, and to render the
"Contexts" list on the world screen (§4). `bindings_to_anywhere`
(`binding.rs:345`) already computes it for correlation and is exposed nowhere.

**As built** (trust-tasks-tf #577): `persona/profile/usage`, named for the
family's noun as compose was. `reach` is a tagged object on the wire —
`{kind: anywhere}` or `{kind: only, contextIds: [...]}` with at least one
context — so the enum survives the JSON. **An omitted `reach` on
`profile/put` keeps the face's current one**, the one member a put does not
reset: a reach is a restriction, and a client written before it existed would
otherwise lift it with every edit. Narrowing past a context the face is worn
in is refused (`boundOutsideReach`, naming them) rather than unbinding.

### 5.5 `slot` on `ProfileEntry`

An optional face-local role name. `slot: "displayName"` designates the entry
answering "what this face calls itself"; unslotted entries are carried as today.
Generalises to a face's primary email or address.

**Hazard:** `ProfileEntry` is `#[serde(untagged, deny_unknown_fields)]`, and
that pairing is the only thing stopping an override from silently degrading into
a live reference. All four variants must gain the member in the same change, and
`each_profile_entry_form_survives_a_round_trip` must be extended to cover the
slotted forms in both this crate and `vta-sdk`. A partial addition makes a
slotted override fail to parse rather than degrade — noisy rather than
dangerous — but the round-trip test is what keeps it that way.

### 5.6 Per-binding label

Drop `profileName` from `binding/get` and `binding/list` (§3.4). Add an optional
`label` on the binding, set by the holder, returned in its place. A context
learns the name the holder chose to show it, and never the name they use for
themselves.

### 5.7 Derived provenance, and vouching as a credential reference

**Derived attributes** (connect a GitHub profile, upload a CV) fit neither
existing variant: the holder did not type it, and no issuer signed it.

```rust
Derived { source: String, derived_at: String }
```

Ranking below `CredentialBacked` and above `SelfAsserted`. `Provenance` is not
`#[non_exhaustive]`, so this is a breaking change — add the attribute in the
same commit that adds the variant, so the next one is an addition.

**Vouching stays off the provenance axis.** A vouched self-assertion is still
self-asserted; a third party has merely co-signed it. Folding it into
`Provenance` would make a vouched value render as attested, which is the one
thing provenance exists to prevent. Per the workspace rule that an authorization
claim between parties is a VC, a vouch is a credential, so:

```rust
/// Credentials from third parties endorsing this value. Inventory, not
/// evidence: the value remains the holder's own assertion.
pub endorsements: Vec<String>,   // vault credential ids
```

`Attribute` is `#[non_exhaustive]`, so this is additive. The distinction between
*inventory* and *evidence* is one the codebase has already drawn once, at the
face level — `Profile.credential_refs` is documented in exactly those terms.
This is the same distinction one level down, and should read the same way.

**As built** (trust-tasks-tf #582): `Derived { source, derivedAt }`, with
`source` the *kind* of source (`github`, `cvUpload`) and never a handle or URL
— provenance reaches the verifier, so a handle there would disclose an
identifier the holder never chose to share. It is previewed as `derived` at
the whole rung, and correlates the way a typed value does, since there is no
issuer signature to link. `endorsements` is checked at write: every id must
name a credential the vault holds (`endorsementNotFound`).

**Found while building it:** `attribute/put` rule 3 — resolve a
`credentialBacked` provenance's credential at write, `credentialNotFound` —
is not implemented; the VTA accepts any `credentialId`. The endorsement check
added here is the same shape, and the credential-backed one should follow it.

### 5.8 Facets become suggested

No "Add a World" step. The CLI and UI surface facets as an offer once a cluster
exists (§4). No store change; `put_facet` already does what is needed.

## 6. What is deliberately not changing

- **The pool stays above contexts.** It is what lets the correlation index see
  the same value presented by two personas in two contexts. A per-context store
  cannot, by construction.
- **`persona/disclosure/preview` and `present` stay two calls.** A single-call
  form would remove the only point at which a human sees what is about to leave.
- **The materialised copy keeps no back-reference.** `MaterialisedClaim` stays a
  distinct type from `ResolvedClaim`.
- **Local faces stay inline-only, enforced by the parser.**

## 7. Open questions

Decided so far: retained attribute versions are acceptable when bounded by
reference, with purge as the holder's explicit override (§9.1); binding expiry
retires a face rather than deleting it (§9.5).

1. **§3.5** — should super-admin continue to imply `PersonaHolder`?
2. **§5.1** — recording the existence of a context-local value in an
   agent-scoped blinded index is argued above as correct. It deserves an
   explicit decision rather than an implementation.
3. **Vocabulary.** "Face" and "facet" share a stem and both name private
   groupings; `Facet.face_ids` already reads awkwardly. If "world" wins in the
   UI, consider renaming the type to match rather than carrying two words for
   adjacent ideas.
4. **§5.2** — does an attribute criterion belong in `accepts` beside the
   credential criteria, or in a separate member? Beside is proposed; the
   ceremony code may prefer otherwise.

## 8. Sequencing

1. **5.1** — correlation index. Blocks everything in §2; do it alone and first.
2. **3.3**, **3.4/5.6**, **3.5** — the small findings, independently landable.
3. **5.5** — `slot`, with the round-trip tests extended.
4. **5.2** — manifest attribute criteria. The other half of the flow, in
   `vtc-service`.
5. **5.3** — `compose` and `promote`. The flow itself.
6. **5.4** — `FaceReach` and `face/usage`.
7. **5.7** — derived provenance and endorsements.
8. **5.8** — suggested facets.

Steps 1–3 are worth landing before the UX work is redone, because they change
what the screens can honestly say.

## 9. Lifecycle — the events a human actually has

Everything above is about *composing* an identity. This section is about what
happens to one over time, which is where identity systems usually fail people:
names change, relationships end, a face was for one weekend, and the holder
later needs to know who was told what. Each event below is checked against what
the store can do today.

The organising principle for the whole section: **treat changes as events, not
edits; retain by reference, not by timer; and never expose the write counter as
"version" to a human.** `Attribute.version` is a store-wide optimistic-
concurrency token that jumps by arbitrary amounts — it means nothing to a
person. The history a person wants is a different thing and has to be built.

### 9.1 A name change is an event, not an edit

Marriage, divorce, deed poll, transition. Three things must be true at once, and
today only the first is:

1. **Faces on live refs follow.** The push on edit already does this — "edit
   once, everywhere" is right for most counterparties.
2. **Some counterparties must keep the old name until a formal process.** The
   bank that KYC'd the old name is not updated by a push. The mechanism for
   this is `ProfileEntry::Pinned`, and **pinning is currently broken by
   design**: `profile.rs:222` — "prior versions are not retained yet, so a pin
   to anything but the current version cannot be honoured", and resolution
   reports the claim stale. The only working freeze is `Override`, which copies
   the value and loses the link.
3. **The old name must be able to disappear entirely.** For a deadname, the
   holder wants no trace. So retention cannot be a timer and `name.previous`
   must be an *offer*, never automatic.

**Retain by reference.** Keep a prior attribute version exactly as long as a
pinned entry cites it — the pattern `ContactRevision.cited` already uses on the
other side of the store, reference-counted "because a cited revision is
evidence the holder can still be asked to account for". Un-pinning the last
citation reaps the version. This makes `Pinned` honest, and it satisfies the
audit module's own argument against keeping copies (`persona.rs:330`): a
retained version is "a second copy with a different lifetime", and this ties
its lifetime to the thing that needs it.

**Purge breaks pins loudly.** `persona/attribute/purge-version` removes a
retained version and reports every face that pinned it, which then resolves
stale — the existing behaviour — rather than silently serving the new value.
The holder chooses between updating those faces and leaving them short.

**Decided (2026-09-21):** retained versions are acceptable, bounded by
reference as above. Purge is the holder's explicit override for permanently
removing something themselves; it is never automatic and never timed.

**The rename flow itself** (`pnm persona attribute rename`, or the UI's
equivalent) is a guided edit over the reverse index and §5.4's `face/usage`:

> `name.legal` is used by 4 faces, worn in 3 contexts, and has been disclosed
> to 6 parties. Follow everywhere (default), or keep the old name for: [ ] Bank
> [ ] Employer … File the old name as `name.previous`? [no]

### 9.2 Who still has the old value

The disclosure record names claim *types* and never values, for the right
reason. But a type says what kind of thing went, not whether what went is still
true, so after a change the question "who has my old name" is answerable only by
date arithmetic.

**Revised during implementation.** This section first proposed recording the
attribute's `version` on each disclosed claim. That is wrong twice. A version is
the store-wide write counter, so carrying it down in `MaterialisedClaim` would
tell anyone who can read a context how much the holder writes. And it is
ambiguous: with two `name.display` attributes, "version 38" does not say *which*
attribute without an attribute id — which is exactly what must never cross the
boundary.

Instead, `present` records a **keyed hash** (`blind`) of each value that left —
it has the value in hand and the key is the agent's own — and
`disclosure/history` compares it at read time with what the same persona
presents *now* in the same context:

| `claimCurrency` | meaning |
|---|---|
| `current` | the verifier holds what the persona still presents |
| `changed` | the persona presents a different value — the verifier's copy is outdated |
| `removed` | the persona no longer presents that type; the verifier keeps what it got |
| `unknown` | recorded before fingerprints existed — never read as `current` |

Nothing above the boundary is read, no value is stored, and no identifier or
counter crosses. `changed` rows are the **re-present list** — parties holding a
value you have since changed, one tap to send the new one — which is the one
screen a person wants after a change. Specified in dtgwg-trust-tasks-tf as
`disclosure/history` `claimCurrency`.

### 9.3 An edit must say what it touched

`attribute/put` returns `Written { version, created }` and nothing about what
the push did. The holder cannot tell whether the edit refreshed one face or
nine. Return:

```jsonc
{ "version": 41, "created": false,
  "refreshed": [ { "faceId": "…", "contextId": "…" } ],
  "heldByPin": [ { "faceId": "…", "pinnedVersion": 38 } ] }
```

Cheap — the push already walks the referrers — and it is the difference between
an edit the holder can trust and one they have to go and check.

### 9.4 Removing a face means one of three things

| the holder means | today | proposed |
|---|---|---|
| stop wearing it *here* | `binding/set` with `profileId: null` | keep |
| stop wearing it *anywhere*, keep it | — | **retire** (reversible) |
| destroy it | `profile/delete` + `unbind` | keep, with a disclosure warning |

The vault already has this exact lifecycle — `VaultStatus {Active, Archived,
Deleted}` with a grace window — and a face should reuse its shape rather than
invent a sibling. A retired face is unbound everywhere and hidden from pickers;
its history stays.

Delete today refuses while bound and warns about *personas*; it does not
consult the disclosure history. The response must say **"disclosed to N parties
across M contexts — deleting does not un-tell them."** The record exists to say
this and the handler does not read it.

**Retiring a persona** — unbind, stop presenting, optionally deactivate the DID,
keep the disclosure history — does not exist as one act and should. It is the
"this relationship is over" button.

### 9.5 A face for one weekend

A conference, a marketplace listing, a dating app. The docs already call the
throwaway persona "a legitimate and common state", but nothing lets it end on
its own. Add `until: Option<String>` to the binding: at expiry the binding
clears and the face is retired (§9.4) — not deleted, so the history survives.
Cheap, and it converts the most privacy-preserving pattern from a discipline
into a default.

**Decided (2026-09-21):** expiry retires, never deletes. A holder who wants no
trace uses the delete and purge paths deliberately (§9.1, §9.4).

**As built** (trust-tasks-tf #570, §9.4 and §9.5 together):

- `persona/profile/retire` and `persona/profile/reinstate`, for pool and
  context-local faces alike. Retire marks the face before clearing its
  bindings, so an interrupted retire leaves a face that cannot be newly worn,
  and a repeat finishes the clearing. Reinstate binds nothing.
- **A lapsed binding is cleared at read time**, not only when the sweeper
  runs: every binding read decodes through `BindingRecord::into_read`, and
  `present` refuses a preview whose persona no longer wears a face. The
  sweeper (`expire_bindings`, on the storage thread, audited as
  `persona.binding.expire`) makes the clear durable and does the retiring.
- **Expiry retires a face only when it is then worn nowhere.** An `until` is
  about one context; retiring a face still worn in another would take it off
  contexts the holder said nothing about.
- **`disclosedTo`** counts distinct verifiers and contexts. Disclosure records
  now carry the face they were made through; an older record is attributed
  through the binding it was made under where that still wears the face, which
  can only undercount.
- **Not yet:** `until` on `persona/profile/compose`. It belongs there — the
  weekend face is usually composed at the door — and waits for the next spec
  change to that task.

### 9.6 One timeline per face

Every event above is recorded somewhere — attribute versions, bindings,
disclosure records — and nothing joins them. `persona/face/timeline` returns,
in order: composed, worn in X, disclosed to Y (types + versions), value
changed (type + version), un-worn, retired. **Never values, never the holder's
private labels** — the `Facet.name` rule ("MUST NOT reach an operational log")
applies to every private name here, and a census test should hold it for every
persona audit `detail` string.

**As built** (trust-tasks-tf #577): the pieces were not all recorded
somewhere — a binding taken off left no trace in the one that replaced it — so
each face gets an append-only event log (`pft:`, agent-scoped, ULID-keyed so
recording never takes the write lock), written after the change it describes
and never failing it. The timeline is that log joined with the disclosure
records. A face from before the log reports its composition from `createdAt`.
The log goes with a deleted face; a promoted face keeps it, since it keeps its
id. `FaceEvent` has no member a value or a label could go in, and a test holds
that none reaches the wire.

### 9.7 The persona DID should disappear from the primary flow

`binding/set` requires the caller to bring a persona DID. A person should say
"wear this face here" and the agent should mint or reuse the pairwise DID —
`present.rs` already derives one per verifier ("the account is not the face").
The DID stays reachable for anyone who wants it; it stops being a noun a
first-time user has to learn.

With that, the concept count a first-time user meets drops from nine
(attribute, face, world, binding, persona DID, context, local face, contact,
disclosure) to three: **who I am**, **who I am to X**, **what I have told
whom**. The rest is discovered — the pool appears the first time a second face
reuses a value; worlds appear when faces cluster (§4).

### 9.8 Face templates are the manifest, from the other side

§5.2 gives a VTC manifest an attribute criterion: `[{type, required}]`. That is
also exactly what a **face template** is — "a Work face wants `name.display`,
`email.work`, `phone.mobile`". One schema, two producers. Ship starter templates
the way DID templates ship — JSON files, built-ins with the service, operator-
addable — and Nicky's *work / life / play, money in the middle* becomes the
default set rather than a diagram. The workspace rule against hand-rolling
where a template exists applies here too.

### 9.9 Security of the edit path

An edit propagates to every bound context with no gate beyond the holder
capability. A compromised holder credential can rewrite the holder's address
everywhere in one call. Two mitigations, neither requiring new machinery:

- The approvals model is keyed on Trust Task type URI, so `pnm approvals
  require persona/attribute/put …` gates every edit today. Recommend it as the
  documented default for a device-held VTA.
- `release: stepUp` already exists per attribute for *leaving*. The
  corresponding gate for *changing* a `sensitivity: high` attribute is the same
  step-up bound to the write, and should reuse the preview-bound approval
  rather than add a fourth axis.

### 9.10 Privacy of the history itself

Retaining history is a privacy cost, which is why §9.1 retains by reference and
§9.2 records numbers rather than values. Two further tests are worth pinning:

- **No ULID crosses to a verifier.** A ULID's leading 48 bits are a timestamp;
  `MaterialisedClaim` already carries no `attributeId`, and a census over every
  rendered output should hold that no identifier-typed member does either.
- **No private label reaches a log.** See §9.6.

`PERSONA` is in the backed-up keyspace partition, so all of the above survives
a restore; nothing here changes that.

### 9.11 Revised sequencing

The lifecycle items slot into §8 as follows. Two of them move ahead of the
compose work because they change what the compose screens can promise.

1. **5.1** correlation index
2. **9.2** disclosure currency; **9.3** edit reports what it
   touched — both tiny, both change what every later screen can say
3. small findings (3.3, 3.4/5.6, 3.5)
4. **9.1** retain-by-reference and honest pinning; purge
5. **5.5** `slot`
6. **5.2** manifest criteria ≡ **9.8** face templates — one schema
7. **5.3** compose / promote, with **9.7** DID minting folded in
8. **9.4** retire + delete warning; **9.5** `until`
9. **5.4** `FaceReach` + `face/usage`; **9.6** timeline
10. **5.7** derived provenance and endorsements
11. **5.8** suggested facets
