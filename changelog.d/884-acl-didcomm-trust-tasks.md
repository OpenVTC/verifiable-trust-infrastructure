### vta-sdk 0.20.31 / vta-service 0.13.22 — the ACL slice speaks Trust Tasks on every transport (#884)

`pnm acl get <did>` against a DIDComm-connected VTA failed with

```
✗ Error: serialization error: missing field `entry`
```

while the VTA logged `ACL entry retrieved … status="ok(response)"`. Both were
right: the maintainer answered, and the client could not read the answer.

**Root cause.** Folding the ACL surface onto canonical `acl/*` (#842, #855) moved
the REST routes and the Trust Task spine onto the canonical bodies — `{ entry }`,
`{ entries, truncated, … }` over the shared camelCase `AclEntry` — and moved the
SDK client with them. The legacy `acl-management/1.0/*` DIDComm handlers were
folded only partway: `create`, `update` and `revoke` moved, while `get-acl`,
`list-acl` and `change-role` kept calling the maintainer's **stored** shape
(`CreateAclResultBody`: flat, snake_case, `did`/`allowed_contexts`). The SDK
deserializes both transports with the same type, so the same call worked over
REST and failed over DIDComm. Nothing caught it — each side of that wire is
tested against its own hand-written fixture.

Three ACL calls were affected over DIDComm, in two directions:

| call | failure |
|---|---|
| `acl get` | response `missing field 'entry'` |
| `acl list` | request rejected (`ListAclBody` is `deny_unknown_fields` and the client sent the pre-fold `context`), response a bare array |
| `acl change-role` | response `missing field 'entry'` |

**The client now sends Trust Tasks for the whole ACL slice** — `acl/show/0.1`,
`acl/list/0.1`, `acl/update/0.1`, `acl/change-role/0.1`, joining the `grant` and
`revoke` that #861 had already moved. The REST leg of each call is byte-identical
to before; only the DIDComm leg changes shape, and TSP — which carries the
Trust-Task surface and nothing else — reaches these four calls for the first
time.

`update_acl` gained back what the legacy leg dropped. It hand-built three members
of its DIDComm body (`subject`, `label`, `scopes`), so an operator narrowing a
step-up approver, an approve scope, an expiry or an `allowedKeys` filter over
DIDComm silently changed none of them and got a healthy-looking entry back. The
task payload is now the full canonical `UpdateAclBody`.

**Why it cannot drift back.** The stored-shape operations
(`operations::acl::{get_acl, list_acl, update_acl, change_role}`) are private to
`operations::acl`. Transports reach them only through the canonical wrappers —
`show_by_subject`, `list_entries`, `update_from_params`, and the new
`change_role_by_subject`, which replaces the identical hand-wrapping REST and the
Trust Task spine each did. A handler that returns the internal shape no longer
compiles.

The DIDComm handlers keep answering the legacy type URIs with the canonical
bodies, so an already-installed `pnm` gets working `acl get` and `acl change-role`
from a VTA upgrade alone; `acl list` needs the rebuilt client, since its old
request is refused at the maintainer.

## `swap_acl` works again, on all three transports

Self-service key rotation was broken the same way, but everywhere at once: the
client parsed the canonical entry (`subject`/`scopes`) while REST `/acl/swap` and
legacy DIDComm both answered the flat stored row and the Trust Task spine
answered `{ entry, previousSubject }`. Three shapes, one parser, no working
caller — `missing field 'subject'` on every transport.

It now sends canonical `acl/swap-key/0.1` **everywhere**, over REST through the
trust-task endpoint rather than the legacy route (which stays mounted, unchanged,
for the non-Rust consumers reading it). `newSubject` is read from the
presentation's own `iss` via the new `swap::peek_presentation_holder` — which
`AclSwapPresentation::peek_holder` now delegates to, so producer and verifier
cannot disagree about what a proof says. `currentSubject` comes from the DID the
client sends as (new `VtaClient::caller_did`). Both are declarations the
maintainer cross-checks against the proof and the authenticated caller.

A REST client has a bearer token, not a DID, so it has nothing to infer the
swapped-out VID from: `swap_acl` there fails before the request leaves the
process, naming the additive `swap_acl_for(current_subject, req)` that takes it.

Server-side, the bare-DIDComm `acl/swap-key/0.1` route answered the flat row too,
so the same canonical URI had two shapes depending on which envelope carried it.
It now answers `{ entry, previousSubject }` like the spine. The legacy
`swap-acl` type keeps the flat row — that is its documented contract.

## Sweep of the remaining legacy `rpc` surfaces

`rpc`'s TSP arm is an `UnsupportedTransport` error, so **every method still on it
is unavailable over TSP** — which is what made this worth auditing rather than
just fixing the reported call. Findings for the eight that remained:

| method | DIDComm shape | disposition |
|---|---|---|
| `swap_acl` | broken (above) | → canonical task, all transports |
| `update_webvh_server` | agrees | → `webvh/servers/register/1.0`, whose payload is byte-identical to what it already sent (#850 folded add + update into it) |
| `update_did_webvh`, `rotate_did_webvh_keys` | agree | left: their canonical twins key on `did`, while these take `(context_id, scid)` — moving them is a signature change plus a CLI lookup, not a transport swap |
| `import_key`, `backup_export`, `backup_import`, `list_webvh_server_domains` | agree | left: no canonical twin exists, and minting task URIs is spec work (VTI #856/#857), not something to do inside a bug fix |

The four left behind are shape-correct over REST and DIDComm and dead over TSP.
None of them is the defect class this PR fixes; all of them are on the TSP gap
list.

**Testing.** `tests/e2e/tests/client_didcomm.rs` pins each moved call as a Trust
Task — including the members `update` used to drop, the canonical `scope` filter
name that replaced `context`, and a `swap_acl` whose `currentSubject` is the
session's own DID and whose `newSubject` is read out of an SDK-built
presentation. `vta-sdk/tests/client_rest.rs` pins swap's REST leg on
`/api/trust-tasks` and the error that names `swap_acl_for`.
