### Dependencies — the enforced-authcrypt TDK is pinned, not merely resolved (#908)

`affinidi-tdk = "0.8"` accepted any 0.8.x. The enforced-authcrypt fix
(affinidi-tdk-rs #671) — DIDComm `unpack` rejecting plaintext / anoncrypt /
forged-`from` envelopes **by default** — first ships in **0.8.5**, through
`affinidi-messaging-sdk` 0.19 and `affinidi-messaging-didcomm` 0.15.8.

`Cargo.lock` happened to hold 0.8.5, so the property held by accident rather
than by requirement. A `cargo update`, a lockfile regeneration, or a clean
checkout resolving afresh could each move sender authentication back out of the
library, with nothing in the build to notice. The pin is now `0.8.5`, with the
reason recorded beside it.

The guarantee above the library is unchanged: `bind_authcrypt_sender` and the
DIDComm `inbound_gate` still enforce authcrypt themselves, as defence in depth.

## A dead workspace dependency, removed

`affinidi-messaging-didcomm-service` is dropped from `[workspace.dependencies]`.
No member consumes it — it is absent from `Cargo.lock` entirely, and both
`vta-service` and `vtc-service` carry comments recording that they replaced it
with local `shim.rs` / `router.rs` equivalents. A requirement that resolves
nothing reads as a supported edge and invites maintenance against something the
build never sees.

## Lockfile refresh

`cargo update` collapses two long-standing duplicate trees:

- **`affinidi-messaging-sdk` 0.18.65 is gone.** It survived behind
  `affinidi-messaging-test-mediator` → `affinidi-messaging-mediator`, the
  dev-only e2e / `vtc-service` fixture chain. `test-mediator` 0.2.47 moved to
  sdk 0.19 and `mediator` 0.18.9 with it, so the graph now holds **one**
  messaging SDK — the assumption the `tsp` feature pins depend on, now true of
  dev builds too.
- **The legacy `ssi-*` stack drops out** (`ssi-jwk`, `ssi-jws`,
  `ssi-dids-core`, `ssi-json-ld` and ~15 siblings), taking `reqwest` 0.11,
  `sha2` 0.9, `ripemd160`, `tiny-keccak`, `uint` and `windows-sys` 0.48 with it.
  `reqwest` unifies on 0.13.4. Net −1393 lockfile lines.

`curve25519-dalek` (5) and `ed25519-dalek` (3) remain single. `elliptic-curve`,
`ecdsa`, `p256` and `sha2` are still doubled across the RustCrypto 0.13 → 0.14
transition, which remains upstream-gated.

Manifest and lockfile only — no workspace crate's source changes, so no version
bumps.

Supersedes #900, whose source change and `affinidi-messaging-sdk` 0.19 pins had
already landed in #902.
