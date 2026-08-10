### vta-sdk 0.21.12 / vta-service 0.14.25 — an unset member is absent, never `null` (#919)

`keys/create` was unusable over DIDComm and TSP. Every call that did not supply
a BIP-39 phrase — which is every call that is not importing external seed
material — sent `"mnemonic": null`, and `keys/create/0.1` types that member
`"string"`:

```text
malformed request: payload does not conform to
https://trusttasks.org/spec/keys/create/0.1: payload failed schema validation:
null is not of type "string"
```

Nothing downstream could mint a key. An OpenVTC community join, whose first act
is to create a persona's signing key, died on its first round-trip with that
text and rolled back.

This is the same defect as #895 (`vta/webvh/dids/update/1.0`, where every
partial update was unusable for the same reason), reintroduced on a different
task by the canonical-body fold in #888: `create_key` moved off a hand-rolled
map — which skipped its `None`s — onto `CreateKeyBody`, which did not.

- **`vta-sdk`**: `CreateKeyBody`'s `mnemonic` / `label` / `contextId`,
  `DeriveAndSignDocumentBody`'s `proofPurpose`, and `SelfRemoveBody`'s
  `disposition` all skip `None` now. The other two were latent variants of the
  same bug, not collateral: `vtc/members/self-remove/0.1` constrains
  `disposition` to an enum of strings, so a member removing themselves under
  the community's default preference was sending the one value the schema
  cannot accept.
- **`vta-service`**: the schema-conformance sweep (#857) now validates each
  witness's request against its embedded `payload.schema.json` — the check
  `validate_payload` runs on the dispatch spine — and not only parses it into
  the generated type.

That last part is why this shipped. The sweep already built its `keys/create`
witness from a real `CreateKeyBody` with `mnemonic: None`, and it passed:
serde reads `null` into an `Option<String>` without complaint, while JSON
Schema types the member `"string"` and refuses it. Parsing is strictly weaker
than validating, so the witness proved the shape and said nothing about the
wire. Reverting the SDK fix now fails the sweep with the exact production
error.

The REST leg was never affected — it serializes `CreateKeyRequest`, which
already skipped its `None`s. Only the transports the stack prefers were broken.

Requests only: `trust-tasks-rs` codegen emits `ValidatedPayload` for `Payload`
but not for `Response` (0.4 and 0.5 alike), so there is no embedded response
schema to validate against. The response side keeps its parse check. Closing
that half needs the codegen to emit response schemas, which is an upstream
change and is not included here.
