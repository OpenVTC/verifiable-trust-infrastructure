# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.3.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-persona-v0.3.2...vta-persona-v0.3.3) — 2026-09-12


## [0.3.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-persona-v0.3.0...vta-persona-v0.3.1) — 2026-09-09


### Added

- **persona**: Say whether a link crosses a part of the holder's life ([#1342](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1342))

Serves the members added in dtgwg-trust-tasks-tf#408, published in
  trust-tasks-rs 0.18.10: `crossesFacets` and `facetIds` on a finding,
  `facetId` on each `sharedWith` location. This needs a floor of 0.18.10 —
  the spine validates OUTGOING responses, so under an older schema an analysis
  that fully succeeded would come back 500 `responseSchemaViolation` — and no
  longer moves one: main reached 0.18.11 while this sat open, which satisfies
  it. The bump this branch carried is dropped rather than resolved downward.

  **Severity is how linkable. Facets are whether the holder minds.** Nothing
  here touches `severity`, and that is the design rather than an omission. A
  value shared between two profiles in one facet still links them for anyone
  who sees both — the holder's filing changes nothing a counterparty can do —
  so softening severity on intent would report a false all-clear. What the
  facets add is a second axis: which of these findings the holder would
  actually want to act on.

  **Absent is unknown, not false.** `crosses_facets` is `Option<bool>` and is
  `None` when the holder keeps no facets, because `false` asserts these
  identities sit in one part of a life and an agent with no facets has made no
  such finding. `FacetIndex::any` is what carries that distinction, which is
  why the index is a struct rather than a map.

  **An unarranged profile is not a second facet.** Only distinct, named facets
  count toward a crossing. Counting "no facet" as one would make every holder
  who has arranged one part of their life and not the rest see a crossing on
  everything they own — the dismissal problem arriving from the other
  direction.

  `facet_index` is built once per analysis for the reason `disclosure_index`
  is: `analyze_correlation` with no `attributeId` walks the whole pool, and
  the per-finding shape re-lists every facet for every finding.

  The conformance witness now exercises the three new members rather than
  merely permitting them — they are the ones added last, and an outgoing
  member the embedded schema has not caught up with is a 500 on a call that
  succeeded.

  vta-persona 118/118 (6 new, one per rule above), vta-service lib 1063/1063,
  clippy --all-targets clean.

- **persona**: Serve persona/facet — the holder's arrangement of their identity ([#1338](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1338))

Implements the three tasks specified in dtgwg-trust-tasks-tf#405, published
  in trust-tasks-rs 0.18.9.

  A holder who uses this model for a while ends up with twenty profiles, and a
  flat list of twenty is a list nobody reads. A facet is the arrangement over
  them — "Work", "Home", "Play" — and it is agent-scoped, like the pool and
  the profiles it groups.

  **An arrangement, not a container.** Nothing is stored inside a facet, and
  `delete_facet` touches no profile and no attribute. There is no cascading
  form because there is no cascading form of the idea: a grouping that could
  take its members with it is a folder, and a holder who reads it as a folder
  is right to be afraid of it. `releasedFaces` reports what now belongs
  nowhere, which is what a screen needs to say what it will look like
  afterwards. `deleting_a_facet_deletes_nothing_it_named` pins it.

  **Membership lives on the facet.** A `facet_id` on `Attribute` would be the
  obvious alternative and is the wrong shape: `attribute/put` REPLACES, and a
  well-behaved consumer does not hold the values it would have to resend —
  `attribute/list` withholds `sensitivity: high` plaintext unless asked by
  name. It would either request every sensitive value the holder owns to
  perform an arrangement that has nothing to do with values, or send a put
  without one and destroy them.



## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-persona-v0.2.0...vta-persona-v0.3.0) — 2026-09-08


### Added

- **persona**: Let a deployment declare its own claim types ([#1327](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1327))

Teaching an agent one word cost five steps across two repositories: a pull
  request against the specification, a publish, a hand-transcription into
  `vta-persona`'s table, a release, a deploy. So nobody did it, every local token
  — `profile.github`, `employer`, whatever an ecosystem actually keeps about its
  people — resolved to the unregistered floor, and holders were shown their own
  values masked as though each were a passport number.

  `CLAIM-TYPES.md` §6 anticipated exactly this: the served-table task was "worth
  doing when the first extension type ships, not before". It ships now.

  `VTA_CLAIM_TYPE_EXTENSIONS` names a JSON file of rows in the shape the agent
  already serves, so an operator can copy a row out of
  `persona/claim-types/list`, change it, and put it back.

  **Extensions feed the same lookup the resolution uses.** `declared()` is one
  iterator over core plus extensions, and `defaults_for`, the family walk and
  `registry_listing` all read it. That is the task's central MUST — what is served
  and what is enforced cannot disagree — and two tables walked separately are two
  tables that resolve differently. The family step is where it would have shown:
  an extension family the exact lookup knew about and the walk did not.

  **What an operator may declare, and why the line falls there:**

  - Anything core does not cover. A token core has never heard of resolves to the
    floor *because nobody has reasoned about it* — §4 rule 3 says so — and an
    operator declaring it is that reasoning arriving.
  - Tightenings of anything core does cover. That direction takes nothing from
    anyone.
  - Not loosenings, compared against what core resolves — exactly (`email.work`)
    or through a family (`payment.giftCard` under `payment`). Otherwise a
    deployment could declare a passport unremarkable, or escape a gated family by
    inventing a member of it, which is the hole rule 3 exists to close.
  - Never an `x:` token. §4's last rule makes that namespace unregistered by
    construction; a row declaring one is a row no conforming client would honour.

  **A bad file stops the agent starting**, rather than dropping the offending row.
  Serving a table the operator did not write means a tightening they believe is in
  force is not, and the values it was meant to protect are the ones they would
  hear about last. An unknown axis value is refused rather than defaulted for the
  same reason — `"hgih"` reading as `normal` looks exactly like a rule that works.
  Loaded rows are logged with the path and the count, because "why is this masked"
  is the question an operator will actually have.

  Configured rather than administered, and the reason is upstream: serving an
  admin task to edit the registry live needs a published task specification first,
  since the dispatcher refuses a URI the registry does not declare. A file is
  diffable, reviewable, and belongs to whoever owns the deployment.

  Nine new tests over the rules, plus `docs/02-vta/claim-type-registry.md` for the
  operator. 99 vta-persona and 1047 vta-service unit tests pass; `cargo fmt
  --check` and `cargo clippy --all-features` clean.

- **persona**: Serve the claim-type registry ([#1315](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1315))

* feat(persona): serve the claim-type registry

  The agent side of trust-tasks #390, now that trust-tasks-rs 0.18.5 is
  published. Bumps the pin and implements `persona/claim-types/list/1.0`.

  Served from `vta_persona::claim_types` — the same REGISTRY and UNREGISTERED
  that `defaults_for` resolves through — because the task's central MUST is that
  a maintainer serves the table it actually applies. A served table that differs
  from the enforced one is worse than serving nothing: a client would mask and
  gate by one rule while the agent disclosed by another, and nothing would report
  it. The end-to-end test asserts that behaviourally, not by comparison: the
  agent serves `payment.card: stepUp` and then refuses a `payment.card`
  disclosure for want of one.

  `strictness` is carried because §4 rule 3 is not computable without it. The
  orderings come from new MOST_PROTECTIVE_FIRST constants, which are hand-written
  — Rust cannot enumerate variants — so a unit test asserts each agrees with
  `Ord`, the ordering the module actually resolves by. A disagreement would be
  silent and served to every client as the rule.

  `minimumSet` and `oidc` are omitted: both optional, and this agent's table does
  not carry them. Transcribing them at the serving layer would be a second copy
  of data nothing here resolves against.

- **persona**: Honour a holder's release override at disclosure ([#1310](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1310))

#1304 enforced `release: stepUp` from the claim-type registry only; a holder's
  per-attribute override was ignored. `Attribute` carried a comment explaining
  why the field had been withheld — "a stored override for a gate that does not
  exist is a promise the holder would be entitled to rely on". The gate now
  exists, so the field can be stored honestly.

  The override is set above the boundary and enforced below it, so it travels
  with the projection: Attribute.release → ResolvedClaim → MaterialisedClaim →
  the gate. Nothing reads up. Re-materialisation on an attribute edit already
  propagates, so changing the override changes what every bound context enforces.

  Resolved once at preview creation onto `Preview.step_up_required` rather than
  derived at read like `sensitivity`, because `PreviewClaim` is serialised
  straight into the preview response and that schema declares
  `additionalProperties: false` — this is an at-rest decision, not something a
  verifier is owed. A preview is a single-use snapshot expiring in minutes, so
  freezing it for that window is also the honest reading.

  An override wins in both directions, per CLAIM-TYPES §4 rule 1. Loosening is
  not a hole because `attribute/put` is holder-scoped: no verifier and no
  context-scoped caller can reach it. The audit row records the decision either
  way, since relaxing a card from stepUp to consent is the most consequential
  thing this task can do.



### Changed

- **persona**: Attribute is not exhaustively constructible from outside ([#1328](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1328))

`Attribute` grew `sensitivity` in #1299 and `release` in #1310. Each was a
  `pub` field added to a struct any consumer could write as a literal, so each
  was a compatibility break — the informational semver report has been carrying
  `constructible_struct_adds_field` for the second one since it landed, which is
  how this was noticed.

  The record is not finished growing. The persona specification keeps adding
  members and this crate keeps following it, so without `#[non_exhaustive]` every
  one of those is another break for the same reason. Marked now, in a release that
  already carries a break, so the next member is an addition instead.

  `release-plz` has `semver_check = true` for this crate, so the bump was never
  going to be missed — this is about how many breaks get paid, not whether one is
  noticed. `cargo semver-checks` now reports two majors where it reported one, and
  both belong to the same release.

  Nothing outside this crate constructs an `Attribute`: it arrives from the store
  or from a deserialised document. Inside the crate, literal construction is
  unaffected, so the eight construction sites are untouched.

  Also corrects `claim_types`'s module header, which said "nothing consults
  `ReleaseRequirement`: `persona/disclosure/present` does not yet demand a fresh
  authentication for a `stepUp` attribute, and a holder **cannot** record a
  `release` override". Both halves stopped being true in #1310. The paragraph is
  "what this module decides, and what it does not" — the first thing a reader
  looks at, and the easiest to leave describing a version of the crate that no
  longer exists.

  99 vta-persona tests pass; `cargo fmt --check` and `cargo clippy --all-targets
  --all-features` clean.



### Documentation

- **persona**: Say "attribute" on screen, not "fact" ([#1319](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1319))

`design-docs/persona-vocabulary.md` translated `attribute` to **fact** for
  everything a person reads. That was wrong in two independent ways.

  It asserts what the model cannot promise. What a holder keeps in the pool is
  self-asserted until a credential backs it, and a face exists so a person can
  choose what to show — an old value, a pinned version, a value overridden for one
  context, or a value that is simply not true. The step-up card said "Approve
  disclosing 1 fact" about exactly that.

  And the word was already spent: `fact` is the VTC ceremony engine's term for a
  *verified* policy input (`vtc-service/src/ceremony/facts.rs`, `Facts` assembly,
  every `.rego`) — very nearly the opposite meaning, in the same product.

  `detail` is the persona audit envelope's own field, `trait` is a keyword,
  `entry` names an entry in a face and `value` is the field inside an attribute,
  so the spec word comes to the screen instead and that row stops translating.
  Truth is carried by the provenance beneath the value, never by the noun.

  - step-up approval card: "1 fact" → "1 attribute" (the string an approver reads
    on their phone)
  - `pnm persona …` help text and `vta-cli-common` printed output: "Your facts:"
    → "Your attributes:", "Fact:" → "Attribute:", and the surrounding guidance
  - `vta-persona` doc comments that define the model in the old word

  Commands, flags, task URIs and wire records are untouched — they always said
  `attribute`. Nothing in `vtc-service/src/ceremony/` is touched; that `Facts` is
  the other meaning.

  vta-persona 88 tests and vta-service persona_trust_task 23 tests pass.



### Fixed

- **persona**: A bad claim-type row is refused, not fatal ([#1331](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1331))

The first version exited on a bad extension file, on the reasoning that serving
  a table the operator did not write is worse than not serving at all. That is
  right for a laptop and wrong for a hosted agent: refusing to boot takes out
  sessions, credentials and mediation over a mis-typed claim type, and in a hosted
  deployment nobody is reading stderr.

  Rejection is per row now. The good rows apply, the agent starts, and every
  refusal is reported — an ERROR log line each, and carried on
  `persona/claim-types/list` under `ext["org.openvtc.claim-types"]` as
  `rejected: [{type, reason}]`, with `fileError` beside it when the file itself
  could not be read. `ext` is the specification's vendor-namespaced member, so
  this needs no spec change and a client that does not know the key ignores it.

  **The direction it fails in is stated rather than assumed.** A refused row is
  not applied, so its token resolves as if the file had never mentioned it. For a
  word core has never heard of that is the most protective answer. For a row that
  meant to *tighten* a core type it is not — the looser answer stays in force,
  which is the case the old behaviour existed to prevent. Nothing makes that safe
  except somebody seeing it, which is why the reasons travel to a screen instead
  of stopping at a log line, and why a test pins the resolution rather than only
  the refusal.

  A duplicated token disqualifies **every** row naming it rather than letting the
  first win: applying one of two conflicting declarations is a guess at what the
  operator meant, and an invisible one.

  102 vta-persona tests pass (3 new), `cargo fmt --check` and `cargo clippy
  --all-features` clean.



## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-persona-v0.1.0...vta-persona-v0.2.0) — 2026-09-07


### Fixed

- **persona**: The audit trail says what changed, and correlation/analyze conforms ([#1283](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1283))

* fix(persona): the audit trail says what changed

  Every persona write recorded action, actor, resource and outcome and
  nothing else. `audit_persona` called `audit::record(...)`, which has no
  `detail` parameter, so a console audit pane showed twenty rows of
  `persona.attribute.put` against opaque ULIDs with no way to tell a
  create from an update, a cascade delete from a no-op against a typo'd
  id, or a binding that materialised forty claims from one that cleared
  them.

  The console side was never the problem: `AuditEnvelope` already renders
  `detail` in full as `detail.reason`. There was simply nothing to render.

  So the write handlers now go through `audit::record_with_detail` and
  supply one: attribute put/delete, profile put/delete, binding/set, and
  the three context-local writes each say what changed — created or
  updated, the claim type, the value type, the provenance kind, entry and
  claim counts, whether the record existed, how many profiles or personas
  were affected, and the resulting version. Reads still pass `None`; a
  read changes nothing, and a sentence restating the request would be
  noise in an append-only store.

  The attribute VALUE stays out, and `audit_persona` now explains why at
  length, because the reason is not the one people assume. It is NOT an
  access-control reason. Persona rows are recorded with `context_id:
  None`, and `operations::audit::authorize` already refuses every entry
  not confined to a named context to anyone but an unrestricted admin —
  exactly the caller `Reach::Holder` admits to `attribute/list`, which
  returns the plaintext outright. Nobody gains a read by us writing one.

  The reason is lifetime. The audit keyspace is append-only and pruned on
  its own retention schedule; the pool is deleted when the holder deletes
  an attribute. Copy a value across and `attribute/delete` quietly stops
  being a delete — the value outlives the record it came from, in a store
  the holder's delete does not reach. Stating that distinction matters,
  because "don't log values" as a bare prohibition is the rule somebody
  relaxes the first time an operator asks for a better trail, and the
  access-control argument does not survive that conversation.

  The new test asserts both halves together. A test that only checks the
  value is absent passes against a handler that records no detail at all,
  which is precisely the state being fixed.

- **persona**: "edit once, everywhere" reached nothing ([#1281](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1281))

A holder edited their name and the verifier was still shown the old
  one. `rematerialise` — the function whose docstring explains that a
  context holds a materialised copy and can only be updated by a write
  from above the boundary — was **called from no handler in the
  codebase**. The only reference outside its own file was a comment in a
  test.

  A context may never read the pool, so its copy changes only if
  something pushes. Nothing did. `attribute/put`, `attribute/delete
  --cascade` and `profile/put` all changed what a profile projects and
  left every bound context presenting the state from before the edit,
  which `disclosure/preview` and `disclosure/present` then handed to a
  verifier.

  **The push now belongs to the write, not to the call site.** `put`,
  `delete` and `put_profile` push before returning, from inside the lock
  they already hold. Leaving it to handlers is the same decision taken
  once per call site and forgetting it is silent — the pool shows the new
  value, the console shows the pool, and only the verifier sees the old
  one.



## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vta-persona-v0.1.0) — 2026-09-06


### Added

- **persona**: The holder's own identity, and a boundary a context cannot read across ([#1255](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1255))

* feat(persona): register the persona keyspace

  Fourth holder store, beside the vault, agent memory and application state.
  It is distinct because disclosure control is its point, and app-state
  promises never to interpret its records — so it cannot host something whose
  whole job is deciding which members may leave.

  Two scopes share the keyspace and the split is a control, not filing: the
  pool and profiles are agent-scoped so the correlation index can see the same
  value presented by two personas in two contexts, which a per-context index
  cannot see by construction.

  BACKED_UP, because a restore without the holder's identity returns an agent
  that no longer knows who its holder is.

  Cascade on DID deletion, with the nuance the per-keyspace enum cannot
  express: only the context-scoped half is DID-keyed. Bindings and contacts
  cascade; the pool survives, because a profile may be bound to several
  personas and deleting one must not destroy facts presented through another.

  * feat(persona): vta-persona crate — models, key layout, correlation index

  The fourth holder store. Distinct from app-state because disclosure control
  is its point, and a store that promises never to interpret its records cannot
  gate what leaves them.

  model.rs carries the shapes the specs made normative. Two choices are
  load-bearing. ProofRung derives Ord so that 'the highest rung this format
  supports' is a max() rather than a hand-written table that can disagree with
  itself. And ProfileEntry::referenced() returns None only for inline entries,
  which is what makes a context-local profile checkable: one is valid exactly
  when no entry references the pool.

  storage.rs builds every key in one place, because the agent-scoped and
  context-scoped prefixes are a security boundary and a call site that formats
  its own key can put a record on the wrong side of it. scope_of() returns
  Option rather than defaulting — a key nobody recognises must not be assumed
  safe to serve a context-scoped caller. Local profiles get their own prefix
  rather than a flag, so a context-scoped scan reaches a space that
  structurally cannot hold a pool profile; a filter is a line of code that can
  be got wrong, an address space cannot.

  correlation.rs is keyed by HMAC over a canonicalised value, so exact-match
  lookup works with no plaintext index over the holder's PII — and prefix and
  substring search are out of scope by construction, which is the trade.
  Canonicalisation sorts object members, or two serialisations of one fact
  would hash differently and the guard would miss the reuse it exists to catch.
  Comparison is constant-time, or an attacker submitting candidates could use
  timing to learn what the holder holds.

  severity() encodes the inversion that is easy to get backwards: a credential
  presented WHOLE correlates more than a self-asserted value, because the
  issuer signature is identical at every verifier, while a derived proof
  correlates less because it differs every presentation. Scoring on provenance
  alone would rank an attested claim safer than a typed one and push holders
  toward the riskier option.

  * feat(persona): pin trust-tasks-rs 0.17.9 and assert the contract in tests

  The persona family is published, so the generated payload types are now the
  contract this crate stores against. Taken as a dev-dependency rather than a
  real one: storage needs none of it, and depending on it only in tests means a
  spec change that lands upstream without a matching change here fails a test
  instead of a production dispatch.

  Two assertions earn their place. The proof and issuedAt constants are how a
  dispatcher learns those were declared REQUIRED, so a relaxation upstream
  surfaces as a failing test rather than as an accepted unsigned write. And our
  ValueType is compared to the published enum on the wire, because a variant
  added upstream without a matching arm here would silently reject a value the
  spec calls legal.

  * feat(persona): attribute store — versions, preconditions, tombstones, indexes

  Read-modify-write is serialised by a process-local lock rather than a CAS,
  following the conclusion app-state reached: there is no reachable multi-writer
  topology, and a CAS would be atomic exactly where the lock already suffices
  while staying non-atomic on the vsock proxy that would need it.

  The version counter is reserved BEFORE the write it belongs to. A crash
  between reserving and writing leaks a number, which is harmless because
  versions are opaque and monotonic and never an edit count. The opposite order
  would reuse one, which is not.

  Index maintenance runs before the record write, deliberately. A crash then
  leaves an index entry with no record — a false positive in the correlation
  guard — rather than a record with no index entry, which would read as a false
  ALL-CLEAR. Over-warning is recoverable; under-warning is the failure the
  guard exists to prevent.

  A tombstone is not a live record, so expectedVersion 0 succeeds over one and
  the new record takes a later counter value. A repeat delete returns
  existed: false and takes NO version: had it taken one, every consumer
  watching the store would see a change that did not happen and delete could
  not be safely retried — asserted by a test that measures the counter either
  side.

  correlation_count returns a count and never identifiers, because returning
  them on a write would disclose the holder's other compositions to whatever
  tool made it.

  * feat(persona): profiles, resolution, and the reverse index

  put_profile validates every reference before taking a version, so a refused
  write consumes nothing, and refuses the whole composition on a dangling
  reference — a partially-resolved profile would disclose less than the holder
  composed and tell them nothing about it.

  The reverse index drops its old edges before adding new ones. Without that an
  attribute removed from a profile keeps a stale referrer, and its delete is
  refused for a reference that no longer exists.

  An override replaces value and label only; provenance is inherited. A pin
  naming a version the store no longer holds resolves stale with no value
  rather than silently serving the current one, which would defeat the entire
  point of pinning.

  Deleting a profile leaves the pool untouched. A profile references rather
  than owns, so removing a composition destroys no facts — the asymmetry with
  attribute deletion, where removal does change what compositions present.

  **Fixes a real serde defect the tests caught.** ProfileEntry is untagged, and
  untagged tries variants in declaration order while serde ignores unknown
  fields — so the permissive Ref variant was matching {ref, override} and
  {ref, pinVersion}, silently degrading an override into a live reference and a
  pin into an unpinned one. A disclosure changing behind the holder's back.
  deny_unknown_fields is not available on a variant, so the fix is declaration
  order with Ref last, documented at the enum and pinned by a test.

  * feat(persona): bindings — the push across the context boundary

  Setting a binding is the moment a composition crosses from agent scope into a
  context, and the crossing has a direction: the holder pushes a materialised
  projection down, and a context never pulls.

  MaterialisedClaim is a distinct type from ResolvedClaim rather than the same
  one with a field left empty. The difference IS the security property — a
  function handed a MaterialisedClaim cannot obtain a pool identifier, so no
  future edit leaks one across the boundary by forgetting to clear it. The
  compiler enforces what a reviewer would otherwise have to notice. Asserted on
  the serialised bytes, because what crosses the boundary is what was written.

  rematerialise() keeps 'edit once, everywhere' working without opening a read
  path: it is a write initiated ABOVE the boundary, never a pull from below.

  Binding to a missing profile is refused rather than written — a binding that
  appears configured and presents nothing is a failure the holder discovers
  from the other side. Clearing is a first-class state, not an absence: a
  persona with no profile is legitimate and common.

  A second persona on one profile is counted and returned, because that act
  makes them the same person by construction and no later narrowing undoes it.
  A count, not identifiers — the association between the holder's personas is
  exactly what an attacker wants.

  BindingSummary is what a context-scoped caller may learn: whether bound, the
  label, a claim count. It has nowhere to put a value, which is the point.

  * feat(persona): contacts — revisions, diffs, and reference-counted retention

  A contact is what a peer disclosed, appended as a revision and never
  overwritten. An address book that silently replaces a payment address is a
  phishing surface; one that reports what changed and when is a defence — which
  is what changed_claims and has_unreviewed_change exist for. A revision
  history nobody is shown is an archive, not a defence.

  Keyed on (context, subject, knownByPersona): the same peer met through two
  personas is two contacts. Collapsing them would correlate the holder's own
  personas inside their own address book, which is the one place nobody would
  think to look for that linkage.

  The diff counts a claim that VANISHED as changed. A diff reporting only
  mutations stays quiet when a peer stops disclosing their payment address,
  which is exactly when it should speak up.

  A reaped revision returns Gone, never NotFound. A caller comparing a current
  value against history must tell 'never existed' from 'no longer kept' —
  only the second means their comparison is unsound rather than mistaken, and
  collapsing them lets a producer conclude 'nothing changed' from an absence
  that means the opposite.

  Retention counts references rather than days. A revision cited by a
  disclosure record is evidence of what the holder was shown before they
  presented; a flat TTL would delete it precisely when it mattered. Deletion
  reports what it retained, because an incomplete erasure the holder believes
  is complete is worse than one they know about.

  The outgoing revision is archived BEFORE the new one lands, so a crash leaves
  a duplicate rather than a gap — and a gap in a history that exists to prove
  what changed is worse than a repeat.

  * feat(persona): the disclosure record, and the caller retention was built for

  Append-only, and written BEFORE the artifact is returned. A crash between
  signing and recording would release data the holder could never afterwards
  discover they had released; recording first can only produce a record of a
  disclosure that did not happen, which is a false positive they can
  investigate. One of those is recoverable.

  Records name claim TYPES and rungs, never values. Re-storing the values would
  double the exposure the record exists to describe, and put a second plaintext
  copy of the holder's data in a structure whose whole purpose is to be read
  later. The rung is recorded because the same claim type at two rungs is two
  very different disclosures.

  contexts_reached_by() pays the debt the scope split incurred. Putting the
  pool above the context boundary bought a correlation check that sees across
  contexts; the cost is that a holder can no longer tell from one context where
  a fact has gone. This answers it directly.

  record_disclosure cites the contact revisions a disclosure relied on — the
  caller reference-counted retention was built for, and until now had none.
  Citation happens after the record lands: a citation with no record retains a
  revision nobody needs, while a record with no citation would let the evidence
  behind it be reaped. Only one of those loses something.

  * feat(persona): task URIs and retry-safety classification

  Adding the 24 URIs to ALL_URIS made every_uri_is_classified fail until each
  was classified, which is the census working: a task cannot join the catalogue
  without someone deciding what a lost reply costs it.

  Writes are Keyed following the app-state precedent — without a precondition a
  replay writes twice and bumps the counter twice, so a watcher sees a change
  that never happened. Deletes are RetrySafe because they converge: a repeat
  finds a tombstone, returns existed: false, and takes no counter value.

  Two entries are worth reading twice. disclosure/preview looks like a read and
  is Keyed, because it mints the single-use token present consumes — a replayed
  preview hands out a second authorisation to disclose. And disclosure/present
  is Keyed because a replay is a second release of personal data to a third
  party and a second permanent record of it: the one task in this family where
  a lost reply must never be retried blind.

  * feat(persona): the authorization boundary, enforced and pinned by census

  The pool and profiles are agent-scoped; bindings, contacts and disclosure
  records are context-scoped. Nothing inside a context may read the pool. That
  is a rule about direction rather than a permission — an access-control failure
  over a readable pool discloses everything, while a pool no context can address
  has nothing to disclose.

  The gate is require_super_admin (Admin AND unrestricted scope), not a role
  check. A guard written as 'is this caller an administrator' PASSES for an
  administrator scoped to a single context, who would then read and write
  identity data belonging to every other one. vti-common's own act_scope docs
  warn about the same edge from the other side: an empty context list means
  unrestricted for Admin and nothing at all for every other role, so a call site
  testing is_empty() without the role gets one of the two backwards. Both halves
  are asserted.

  REACH classifies all 24 tasks and is exhaustive by test, so a task cannot join
  the family without someone deciding which side it is on — and an unknown URI
  is refused rather than defaulted, because defaulting to Context is exactly how
  a pool read becomes reachable from inside one.

  The test that matters is a_context_scoped_admin_is_refused_every_holder_task:
  it iterates every holder-only task and asserts an admin scoped to ctx-work is
  turned away. That is the conformance witness the design asked for, and the
  test that would have caught the trap.



### Fixed

- **persona**: Drive the slice end to end, and fix the four things that found ([#1258](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1258))

Every layer of the persona slice was tested and none of the seams between
  them were. The unit tests assert that `authorize` refuses a context-scoped
  caller; they cannot say whether the dispatcher ever calls `authorize`. The
  store tests assert that a materialised claim carries no pool identifier;
  they cannot say what a context receives on the wire. Those are different
  claims and only one of them is about the system.

  `vta-service/tests/persona_trust_task.rs` posts real Trust Task documents
  through the real dispatch spine into the real store. It failed on four
  counts the first time it ran.

  **`renderers/list` refused the most privileged caller.** The handler
  supplied a context from `auth.allowed_contexts.first()`, reasoning that a
  caller should name one so the request is attributable. That was wrong
  twice: the context did not come from the request, so it attributed
  nothing; and reading the caller's own list inverted the gate — an `Admin`
  with an unrestricted (empty) list is the most privileged caller there is,
  and was the only one refused, while every scoped caller was admitted.
  This is the `allowed_contexts.is_empty()` family CLAUDE.md warns about,
  reached by a route the warning does not name.

  The fix is a third reach rather than a different one of the two, because
  both are wrong for this task in opposite directions. `Context` refuses the
  unscoped holder — the payload schema has no `contextId`, so there is no
  context to name. `Holder` would refuse the callers who most need it:
  `disclosure/preview` is context-scoped and takes a renderer name, so an
  application that cannot list renderers cannot choose one, and choosing
  blind is how a holder discloses through a format that silently drops
  provenance. `Reach::Any` says what is true — the response is a
  compile-time constant naming nothing about anybody.

  **Two responses emitted `null` where the schema types a string.**
  `disclosure/present` for an unminted `credentialId`, and `binding/get` for
  `profileId` / `profileName` / `boundAt` when nothing is bound. `json!`
  renders a `None` as `null`; an unset optional must be *absent*. This is
  the response-side twin of the rule `payload_null_census` pins on requests
  in `vta-sdk`, and it has no census — the response-conformance layer caught
  it at run time, which is the only reason either was noticed. Both now go
  through `put_opt`.

  Note which case failed: `binding/get` conformed while bound and did not
  while unbound. That is the wrong way round — "nobody is bound here" is
  exactly the reading a caller needs to be able to trust.

  **`profile/get --resolve` omitted three required members**, because
  `ResolvedClaim` never carried them. It now carries `valueType`, `version`
  and `updatedAt`, which are also the members that make a resolved read
  useful: a holder can see that an entry is pinned to v3 while the pool is
  at v5.

  **And a spec defect the same test surfaced.** That response types each
  resolved entry as the pool `Attribute` shape, requiring `attributeId`,
  `updatedAt` and `version`. An inline entry has none of them — it has no
  pool record behind it, which is the reason inline exists. So `resolved` is
  a projection that may contain non-pool values and the pool record's shape
  cannot describe them.

  Until that is fixed upstream the handler refuses, naming the reason. The
  two alternatives are both dishonest: a synthesised `attributeId` lies
  about where a value lives, and omitting the entry returns a profile that
  appears to present less than it does — the failure this store exists to
  prevent. `an_inline_entry_is_refused_until_the_schema_allows_one` pins the
  interim behaviour so it expires rather than settles; when the schema takes
  the three members as optional, that test fails and the refusal goes with
  it.


