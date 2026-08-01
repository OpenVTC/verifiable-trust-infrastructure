### vta-sdk 0.21.1 / vta-service 0.14.1 — the keys surface folds onto canonical `keys/*` (#888)

**Breaking.** The VTA now emits the canonical key shapes on **every** transport:
camelCase members, and the single-record responses (`create`, `show`, `import`)
wrapped as `{ key }`. Snake_case is still accepted on *intake* via serde aliases,
so a producer written against the old spelling keeps working — but a consumer
reading responses must be rebuilt. `pnm` needs a rebuild for `keys` commands.

This is phase D of the canonical-task reduction. The specs were authored upstream
first (`trustoverip/dtgwg-trust-tasks-tf` #167, #169) and published as
`trust-tasks-rs` 0.2.53; this binds them.

## What moved

| Was | Now |
|---|---|
| `vta/keys/{list,create,get,rename,revoke,sign,derive-and-sign,derive-and-sign-document}/1.0` | `keys/{list,create,show,rename,revoke,sign,derive-and-sign,derive-and-sign-document}/0.1` |
| *(no task)* | `keys/import/0.1` — new binding |

Nine entries leave `UNSPECCED_DISPATCHED_URIS`, which is the metric that
programme tracks. `SignAlgorithm` moves to the IANA JOSE spellings (`EdDSA`,
`ES256`) with the lowercase forms accepted on intake.

## `keys/import` refuses the cleartext carrier

The new task accepts `privateKeySealed` and `privateKeyJwe` and **refuses
`privateKeyMultibase` outright**. One dispatcher serves the trust-task surface
over REST, DIDComm *and* TSP, so a handler there cannot tell whether the request
travelled end to end — and cleartext is admissible only where it did. Refusing is
the only reading that cannot leak a key.

The client forks on the same line: a sealed or JWE carrier rides the canonical
task (so it reaches TSP); a raw multibase key stays on the legacy DIDComm
message, where authcrypt has already established the guarantee. No capability is
lost, and none moves to a transport that cannot carry it safely.

## What conformance caught

The round-trip harness rejected the first cut of the spec:

```
keys/create/0.1: request is not canonical: unknown field `mnemonic`
```

`create_key` has always been able to derive from a caller-supplied BIP-39 phrase,
and the published schema had no member for it. Binding the task as it stood would
have compiled cleanly and **silently dropped the capability** — create-from-a-phrase
would have kept "working" while deriving from the wrong seed. Fixed at the source
(#169), which is why the dependency is 0.2.53 rather than 0.2.52.

That is the second time in this programme that a hand-rolled client payload has
been the defect (after `update_acl` in #884), so `create_key`, `list_keys` and
`import_key` now build their task payloads from the canonical Rust bodies rather
than a `json!` map. A member that exists in the type but not in the map is a
compile error; a member that exists in neither is a schema failure. Neither is
silence.

**Testing.** Nine conformance witnesses — every task in the family round-trips
through its generated `Payload`/`Response` types. `tests/e2e/tests/client_didcomm.rs`
pins the canonical envelope and the sealed-vs-multibase import fork, including
the assertion that the cleartext carrier never rides the canonical task.
`vta-sdk/tests/client_rest.rs` moves its fixtures to the canonical shape; the
imported-key fixture carries `origin: "imported"` so a broken mapping cannot pass.
