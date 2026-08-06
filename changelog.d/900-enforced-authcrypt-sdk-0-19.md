### vti-common 0.11.35 / vta-sdk 0.21.7 / vta-service 0.14.11 — move onto the enforced-authcrypt messaging SDK (#900)

Bumps the Affinidi TDK to the released enforced-authcrypt line: `affinidi-tdk`
0.8.5, which pulls `affinidi-messaging-sdk` 0.19.0 and
`affinidi-messaging-didcomm` 0.15.8. This is the upstream fix (affinidi-tdk-rs
#671) that makes DIDComm `unpack` reject plaintext / anoncrypt / forged-`from`
envelopes **by default**, moving the sender-authentication guarantee down into
the library.

## What changed

- **Workspace dependency pins** (`Cargo.toml`): `affinidi-tdk` `0.8` → `0.8.5`
  and `affinidi-messaging-didcomm-service` `0.3` → `0.3.22`, pinned to a minimum
  patch so a fresh resolve cannot land on a pre-fix messaging crate (0.15.7 was
  published as pre-fix code and renumbered to 0.15.8).
- **Direct `affinidi-messaging-sdk` pins** (`vta-sdk`, `vta-service`, the e2e
  crate): `0.18` → `0.19` — a semver-breaking bump, required so the `tsp`
  feature and the e2e mediator fixture resolve to the same 0.19 line the default
  build already gets transitively through `affinidi-tdk` 0.8.5. Leaving them at
  `^0.18` splits the graph into two `affinidi-messaging-sdk` copies.
- **`Cargo.lock`**: `sdk` 0.18.65 → 0.19.0, `didcomm` 0.15.6 → 0.15.8, `tdk`
  0.8.4 → 0.8.5, `mediator` 0.18.1 → 0.18.5, `test-mediator` 0.2.44 → 0.2.46.

## Source

`affinidi-messaging-sdk` 0.19 makes `UnpackMetadata` `#[non_exhaustive]`, so the
`meta()` test helper in `vti-common/src/auth/didcomm.rs` can no longer use a
struct literal; it now starts from `Default` and assigns the fields under test.
This is the only source change — the production `bind_authcrypt_sender` guard and
the DIDComm `inbound_gate` are unchanged and remain in place as defence in depth.

## Scope

Dependency + test-helper only. No production behaviour, wire types, or config
change: VTA already required authcrypt on both inbound paths, so the new library
default is aligned with existing enforcement rather than a new constraint. The
CVE-class guards (`rejects_plaintext`, `rejects_anoncrypt`,
`rejects_sender_mismatch`) stay green.

