# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
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


