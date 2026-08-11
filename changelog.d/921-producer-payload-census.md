### vta-sdk 0.21.13 / vta-service 0.14.26 — check what we *send*, not what we wrote down (#921)

#919 fixed `keys/create` sending `"mnemonic": null`. It did not answer the
question the fix raised: how many more are there, and what would have caught
this? Both defects of this shape (#895, #919) were found in production, by a
person, from a rejected request. This adds the two checks that find them
without one.

**A source census, in `vta-sdk`** (`tests/payload_null_census.rs`). Every
`Option` member of every `Serialize` struct under `protocols/` must skip `None`,
because every Trust Task schema types its optional members by what they hold and
none of them accepts null. Exceptions go in `NULLABLE_BY_DESIGN` with a reason
and are checked in both directions, so an exemption cannot outlive the member it
exempts. Parsed with `syn` rather than grepped — the attribute is routinely
written across several lines, which a line-oriented regex misreads in exactly
the direction that lets a violation through.

It found five on its first run, all latent, all now fixed:
`CreateAclResultBody::label`, `CreateContextResultBody::{did,description}`,
`CreateKeyResultBody::label`, `SeedRecordBackup::retired_at`, plus
`AclEntryBackup::label`. Each sits in a struct whose *sibling* members already
skip, so these were oversights rather than decisions. Only
`GetKeyResponseBody::key` is exempt, and that one is spec-mandated:
`keys/show/0.1#response` types it `oneOf: [KeyRecord, null]` and requires it
present, because "no such key" is a successful answer.

**A producer census, in `vta-service`**
(`tests/producer_payload_conformance.rs`). The census above cannot see a payload
built by hand, and the conformance sweep (#857) cannot see one at all — it
checks a witness written in the test, and no client method runs during it. So
this drives the client methods themselves, through a new in-process transport
(`vta_sdk::client::loopback`, behind `test-loopback`), with **every optional
argument unset** — the shape that broke `keys/create` — and validates what they
emit against the published schema. No VTA, no mediator, no socket.

It found a live one immediately: **`derive_and_sign_document` sent
`"proofPurpose": null`** on every call that did not name a purpose. Omitting the
purpose is what selects the documented `assertionMethod` default, so the
documented way to call it was the way that could not work. #919's fix had
already added `skip_serializing_if` to `DeriveAndSignDocumentBody` — and the
method did not use it, building a `json!` map instead. That is the gap between
the two censuses in one example: fixing the struct does not fix a producer that
never touches the struct. It now builds the canonical body, as #888 intended.

The census also makes four unvalidatable tasks visible in `UNPUBLISHED`, each
with its reason. They share a pattern worth naming: every one is a legacy
`vta/`-namespaced task the canonical folds have not reached, so the
unvalidatable surface is exactly the un-folded surface, and each closes for free
when its family is folded.

**On the loopback seam.** It intercepts ahead of the transport rather than
adding a `Transport` variant. A variant would have to be answered at each of the
~20 sites that match on `Transport`, almost all of which would say
"unsupported" — twenty arms of noise in production code to serve a test. The
hook touches the three functions that dispatch a Trust Task and leaves every
transport match exhaustive over the transports that really exist.

**Not covered, deliberately.** Framing — TSP sealing, DIDComm authcrypt,
mediator routing — sits below the loopback point and still needs a harness with
a real mediator. And 26 of the sweep's 70 witnesses still transcribe their
request as a `json!` fixture rather than building it from the producer; 21 of
those name a client method that exists today, so the module comment calling
those slices "module-private" is stale. Converting them is follow-up work this
does not do.
