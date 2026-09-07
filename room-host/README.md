# room-host

Stores data-room records for rooms it does not govern — a delivery service, not
a community.

Not published to crates.io; it is deployed as a binary.

## What it deliberately is not

A room host holds records — ciphertext on every tier but `open` — and answers
`rooms/*` Trust Tasks against them. It has **no member roster, no policy engine,
no credential issuance, no admin surface**, and no opinion about who belongs to
any room it stores.

That is not minimalism for its own sake. A room is authorized by credentials the
room itself issued, so a host that kept its own record of who belongs would
become part of that room's membership — and the room could no longer move to a
different host without the old host's cooperation.

The absence of a roster is what makes a room portable, and it is the property
this binary exists to preserve.

## Licence

Apache-2.0
