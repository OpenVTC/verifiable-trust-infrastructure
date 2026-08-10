### vta-sdk 0.21.11 / vta-service 0.14.24 — provisioning speaks 0.2, and the messaging SDK stops stalling shutdown (#917)

Three fixes that ship together because they land in the same release: the client
had to move to the 0.2 wire tags, the server had to stop re-imposing its own
casing on a signed document, and both want the messaging SDK that no longer
holds a lock through shutdown. One `vta-sdk` release, one VTA redeploy.

#### `ask.type` goes out camelCase — provisioning works again

`BootstrapAsk` serialised the **0.1** PascalCase tags (`AdminRotation`,
`TemplateBootstrap`) while the client submitted under
`provision/integration/**0.2**`. The two schemas differ in exactly that constant
— 0.1 requires `AdminRotation`, 0.2 requires `adminRotation` — so the VTA's
payload-schema gate rejected every request:

```
malformed request: payload does not conform to
https://trusttasks.org/spec/provision/integration/0.2:
{"adminTemplate":{…},"contextHint":"openvtc","note":"openvtc","type":"AdminRotation"}
is not valid under any of the schemas listed in the 'oneOf' keyword
```

Latent since the client moved to the 0.2 URI; fatal once the schema gate landed.
No config could bypass it — `policy.require_payload_schema` only governs *unknown*
URIs, and a known schema is always enforced.

The variants now `rename_all = "camelCase"`, with the PascalCase spellings kept
as inbound **aliases** so a 0.1 holder still parses. That direction matters: the
tag is inside the signed VP, so an existing holder that signed `AdminRotation`
must keep verifying.

Reported from OpenVTC, whose setup wizard could not get past
"Provision integration DID + admin credential".

#### The trust-task handler verifies the bytes it received

`handle_request` called `req.request.verify()`, which re-serialises the typed
struct — re-imposing this crate's serde casing on the very bytes the holder
signed. It only worked while both sides happened to agree; changing either one's
casing breaks the signature over a document nobody tampered with.

It now uses `verify_value` over the raw `doc.payload["request"]`, which is what
the DIDComm handler already did and what `verify_value`'s own documentation
tells network handlers to do. Client and server casing no longer have to match.

Fixing only the client would have moved the failure one step later rather than
resolving it.

#### `affinidi-messaging-sdk` 0.19.3 → 0.19.4

Carries [affinidi-tdk-rs#694](https://github.com/affinidi/affinidi-tdk-rs/pull/694):
`live_stream_next*` held a **read** guard on `ws_channel_tx` across its wait,
while `stop_websocket` needs the **write** guard — so a poll in flight blocked
every shutdown until the poll window elapsed.

For the delivery layer that is 10s, and its inbound pump issues a read-ahead
after every frame, so any consumer finishing mid-window paid the remainder on
exit. `pnm` showed it as a fixed pause *after* its output. Measured against a
live VTA: **13.1s → ~3.5s**, with the remaining time genuine mediator
round-trips.

Lockfile-only on our side — the `affinidi-tdk = "0.8.5"` pin already admits it
via a caret requirement. The lockfile also reassigns which `socket2` / `syn` a
few dependents use; both versions were already present, and this is the resolver
normalising on any lock touch, not a downgrade of the graph.

#### Tests

- `the_request_payload_conforms_to_the_0_2_schema` builds the exact
  AdminRotation request from the report and validates it against the **real**
  published schema, through the same `trust_tasks_rs::validate` call the VTA
  runs. Reverting the casing fix reproduces the reported error character for
  character.
- `ask_type_serialises_with_the_0_2_camelcase_tags` pins the wire tags, asserted
  on serialized JSON rather than a round-trip — the inbound aliases accept both
  spellings, so a round-trip passes either way and would not have caught this.
- `the_0_1_pascalcase_tags_are_still_accepted_inbound` pins the alias direction,
  since dropping one while renaming the variants would strand existing holders
  silently.

`admin_rotation_ask_round_trips_through_sign_verify` asserted the old
PascalCase tag incidentally — its stated subject is the `adminTemplate` field
name — and is updated to the 0.2 form.

#### Downstream

OpenVTC needs only a dependency bump; no code change there.
