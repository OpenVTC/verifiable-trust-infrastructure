### vta-sdk 0.20.31 / vta-service 0.13.22 — the ACL slice speaks Trust Tasks on every transport (#883)

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

**Testing.** `tests/e2e/tests/client_didcomm.rs` pins each of the four as a Trust
Task, including the members `update` used to drop and the canonical `scope`
filter name that replaced `context`.
