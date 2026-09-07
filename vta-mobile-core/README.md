# vta-mobile-core

The shared engine behind the VTA mobile agent (Android and iOS), exposed to both
platforms through a single UniFFI surface.

Not published to crates.io — it ships as a UniFFI binding inside the mobile
apps.

## The FFI surface is pure functions over bytes

Deliberately. Everything stateful or platform-bound stays **native** and is
handed to this crate as input:

- key custody (Secure Enclave / StrongBox) and biometric gating,
- the mediator WebSocket transport and APNs/FCM push wake-up,
- storage.

The engine builds and parses documents; the platform holds the keys and the
sockets. That line is what keeps one implementation of the protocol serving two
platforms without either platform's lifecycle leaking into it — and it is why a
key never crosses the boundary in either direction.

## Licence

Apache-2.0
