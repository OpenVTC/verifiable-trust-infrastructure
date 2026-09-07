# vti-rooms

Data-room storage, wire types, and authorization — the parts of a room that are
not a service.

A **data room** is a shared space whose access is governed by credentials the
*room itself* issues, not by anything the host stores. Everything here is
arranged around that one property, and it inverts the assumption most storage is
built on.

## There is no member list

Not "not yet" — there must not be one.

Authorization is a presentation carrying a membership credential and an
authority chain, verified against the room's own identifier. A host that kept a
roster and consulted it would become part of the room's membership, and the room
could no longer move to a different host without that host's cooperation. The
absence is what makes a room portable.

So this crate holds records and the rules for reading them, and knows nothing
about who belongs to anything.

## What it does not depend on

`vti-rooms` depends on `vti-common` and nothing else — no credential library, no
DID resolver. A host can reuse the storage without taking on the machinery of
verification, which lives in
[`vti-rooms-dtg`](https://crates.io/crates/vti-rooms-dtg) behind a
`ChainVerifier` trait.

That split is also what keeps this crate honest: it can decide whether a
presentation is *shaped* right, and it structurally cannot decide whether it is
*true*.

## Status

Early. The API will change.

## Licence

Apache-2.0
