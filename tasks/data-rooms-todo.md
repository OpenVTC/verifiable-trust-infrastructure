# Todo: Data rooms

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

There is no `tasks/data-rooms-plan.md`. The problem statements live in the
design notes, and each item below names the one that governs it:

- [`docs/05-design-notes/data-rooms.md`](../docs/05-design-notes/data-rooms.md) — the design, §14 is its own open-questions list
- [`data-rooms-verified-reads.md`](../docs/05-design-notes/data-rooms-verified-reads.md) — the commitment, traces, and what they do and do not buy
- [`data-rooms-read-through.md`](../docs/05-design-notes/data-rooms-read-through.md) — reading through the agent; §5 carries the two decisions
- [`data-rooms-epoch-anchoring.md`](../docs/05-design-notes/data-rooms-epoch-anchoring.md) — the witnessed anchor; §6.1/§6.2 carry its costs
- [`data-rooms-demo-site.md`](../docs/05-design-notes/data-rooms-demo-site.md) — the browser as the member

Record the PR number next to each task as it merges. Spec PRs are in
`trustoverip/dtgwg-trust-tasks-tf` and are written `tt#N`; everything else is
this repository.

Sizes: S ≤ ½ day · M 1–2 days · L 3–5 days · XL needs a design note first.

**Three decisions are made and are not to be re-litigated** (2026-09-09, and
recorded in the notes above):

1. A client that catches a host **serves reads and refuses writes**. The refusal
   is the mechanism; a flag that blocks nothing is not.
2. Anchoring takes **shape 3a** — a typed service entry in the room's log entry.
3. `vti-rooms` is **alpha with no external consumers**; its API may break freely.

---

## Phase 0 — Verified reads (shipped)

Kept because the arc below only makes sense against it, and because each PR
number is the answer to "when did this stop being true".

- `[x]` **V0.1** (M) Merkle store under `vti_rooms::merkle` — sorted leaves, RFC
  6962 domain separation, whole-record leaves — PR: #1346 (merged)
- `[x]` **V0.2** (S) `DigestMultibase` on the wire, not bare hex — PR: #1349 (merged)
- `[x]` **V0.3** (S) `dataCommitment` on both read responses — tt#411, PR: #1351 (merged)
- `[x]` **V0.4** (M) The two design decisions researched and answered — PR: #1343 (merged)
- `[x]` **V0.5** (L) **Traces**, and the leaf preimage pinned exactly as
  `CommittedRecord` — a commitment need only be comparable between two of the
  same implementation; a trace must be *computable by someone else* — tt#419,
  PR: #1368 (merged). Also fixed: `rooms/records/get`'s response had **never**
  conformed to its published schema, and `room-host`'s mirror depended on that.
- `[x]` **V0.6** (M) **The tree head** — a root names no state, so `headVersion`
  and `recordCount` travel with it — tt#422, PR: #1375 (merged)
- `[x]` **V0.7** (S) Design notes: read-through, the three decisions, anchoring's
  real cost, the root memory's shape — PRs: #1370, #1377, #1378, #1379 (merged)
- `[x]` **V0.8** (S) Specs for `rooms/keys/{read,browse}` — tt#426 (merged)
- `[x]` **V0.9** (M) `rooms/records/list` **paginates honestly**. The published
  schema had `cursor` on request and response; this implementation had neither,
  so `limit` truncated silently and a conforming client's second page was
  refused as malformed. Branch `feat/rooms-list-paginates`; mirror, CLI and
  example now read to the end — PR: _pending_

## Phase 1 — Read through the agent (deps: V0.8, V0.9)

The console cannot address a host and a commitment is inert without a party that
remembers roots. Both are the member's own agent.

- `[x]` **R1.1** (L) `rooms/keys/read` in `vta-service` — present, fetch, verify
  the host's proof *and* signer binding, verify the trace, open. Six census
  sites (URI constant, `ALL_URIS`, `retry_safety`, dispatch, conformance
  witness, `vta-mcp` guard verb). `priorRoots: "notChecked"` until R1.3.
- `[x]` **R1.2** (M) `rooms/keys/browse` — same shape, plus the **count check**,
  which is the one verification a listing can do without an anchor or a second
  party. Follows the cursor to the end; `complete: false` when it stops of its
  own accord — PR: #1385
- `[x]` **R1.3** (M) **The root memory.** Keyed by **room, not host** — which
  buys a fourth comparison the specification does not list: two hosts of one
  room disagreeing at one `headVersion`. A map of the last 16 `headVersion →
  root`, plus the highest ever seen; dropped when the membership ends.
- `[x]` **R1.4** (M) The write path **refuses** on a caught host. Deps: R1.3 —
  a refusal that lasts only as long as the process that noticed is not one.
- `[x]` **R1.5** (M) The words. A refused write must explain itself in the room's
  own vocabulary — *two different record sets, both claimed as this room at
  version N* — or the member concludes their own agent is broken. Needs a rooms
  equivalent of `design-docs/persona-vocabulary.md`; a pill cannot carry it —
  plugin PR: OpenVTC/vta-browser-plugin#223, six render tests against the words

## Phase 2 — The witnessed anchor (deps: R1.2)

Shape decided (3a). What turns a root from the host's own assertion into
evidence — and the only one of the commitment's comparisons needing neither a
gossip channel rooms deliberately lack nor durable state in an agent.

- `[x]` **A2.1** (M) The owner assembles an anchor: `epoch_authenticator()` it
  holds, `headVersion` and `dataCommitment` it must **read from the host** — the
  note originally said this "sits entirely on the owner's side" and that was
  wrong (§6.1) — spec tt#429, PR: #1390
- `[x]` **A2.2** (S) Publish it through `vta/webvh/dids/update/1.0`. No new task
  needed — but supplying a `document` **rotates the DID's update key** and
  refreshes pre-rotation commitments, so each anchor is an update *and* a
  rotation (§6.2) — PR: #1390
- `[x]` **A2.3** (M) A member verifies: resolve the room DID, read the anchor,
  compare. `ReadVerification.anchor` — the only one of the three comparisons a
  **first-time reader** can make, and the only place a **rollback** is visible.
- `[x]` **A2.4** (S) Cadence as a room parameter — `anchorCadence` on
  `rooms/create`. Deliberately not a duration: a room promising "daily" makes a
  claim its owner's availability cannot keep, and a member comparing against a
  clock would read an owner's holiday as a host's misbehaviour. What it buys is
  that **silence becomes legible**.

## Phase 3 — The surfaces (deps: R1.1, R1.2)

- `[x]` **S3.1** (M) `@openvtc/pnm-core/rooms` gains `roomsKeysRead` /
  `roomsKeysBrowse` on `@openvtc/trust-tasks` 0.18.3. The agent verifies; the
  plugin **renders the verdict** and does not re-implement the verifier — PR:
  OpenVTC/vta-browser-plugin#222, which also cut this library over to
  `present/0.2` and `issue-authority/0.2` after a resync found it had drifted
- `[x]` **S3.2** (L) Record browse / read / write panes in the console — the last
  rooms UI piece — PR: OpenVTC/vta-browser-plugin#223

## Phase 4 — Off the arc

- `[x]` **X4.1** (L) **`RoomGroup::self_update()`.** `add_member`,
  `remove_member` and `apply_commit` exist; there is **no way to advance an
  epoch without a membership change**. So "a room renews" currently means "a
  room adds or removes somebody", which is not what renewal means — and §9's
  lifecycle, and every anchor, rides renewals. OpenMLS work in the most delicate
  module in the system — PR: #1389
- `[~]` **X4.2** (L) **Commit relay** for `open`/`attributed` rooms, so a
  renewal's commit reaches every member without the owner fanning out O(n).
  Belongs beside `rooms/epoch/chain`. **Spec merged-ready: tt#432** —
  `rooms/epoch/mint` gains an optional `commit` and `rooms/epoch/commits` serves
  them, ordered and with no gaps. A host may relay a commit although it may not
  relay a Welcome: a commit is ciphertext plus a leaf index and names nobody.
  VTI implementation still to do.
- `[x]` **X4.3** (S) Bump `js-yaml` in `vtc-service/admin-ui`. Dependabot calls
  it high; it is **dev-only**, via `@redocly/openapi-core`, and the vulnerability
  is CPU exhaustion parsing hostile YAML — the only YAML it sees is our own
  OpenAPI spec. The real cost is that a standing "1 high" trains everyone to
  ignore the alert list — PR: #1384, done with `overrides` rather than
  `--save-dev`, which would have declared a dependency this package does not have.
- `[~]` **X4.4** (S) A **prune verb** over `prune_epoch_links_before`. Nothing
  needs it yet; it is written down so its absence is a decision. **Spec
  merged-ready: tt#431.** VTI implementation still to do.
- `[!]` **X4.5** (XL) The `private` tier's **ZK profile**. Blocked on a working
  group decision — the cred-spec puts ZK protocols out of scope, and
  `SubjectBindingVerifier` is the seam with no implementation behind it.
- `[x]` **X4.6** (M) **Cache the Merkle store** — measured, and deliberately not cached. Deliberately uncached today:
  a stale root is worse than a slow one, because the failure it produces is an
  honest host appearing to equivocate. Do this only with a measurement saying
  where. **Measured** (PR: #1388): 3.4 µs per record, linear — 3.5 ms for a
  thousand records, 34 ms for ten thousand. The answer is still not to cache, and
  now that is a decision from evidence: the obvious cache moves the cost to
  writes rather than removing it, and removing it needs an incremental Merkle
  update.
- `[!]` **X4.7** (M) A **join ceremony**, blocked on the demo rather than on us.
  Twenty-two room tasks and not one is a join request; admission is push-shaped
  (the owner calls `rooms/keys/key-package` on the member's VTA), which a browser
  tab cannot receive. Worked out in
  [`data-rooms-joining.md`](../docs/05-design-notes/data-rooms-joining.md): the
  mechanism is smaller than it looks, because the room is **already addressable**
  and `room.json` says so, and it must not route through the host — a join
  through a `private` room's host tells it exactly who wants in, which is better
  intelligence than the membership it was denied. What is genuinely open is
  **what makes an applicant admissible**: policy, differing per tier, and the one
  thing a spec written now would freeze wrongly. `data-rooms-demo-site.md` §4.3
  already says to upstream this *after* the demo shows its shape; this records
  that as a block.
