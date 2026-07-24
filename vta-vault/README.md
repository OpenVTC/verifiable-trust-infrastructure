# vta-vault

The VTA's **holder credential vault** — storage, query, receive/verify, present,
and status refresh for the third-party credentials a holder stores on a VTA.

Extracted from `vta-service` as a subsystem crate. It takes narrow dependencies
(`vti_common::store::KeyspaceHandle`, `vti_common::acl::ActScope`, resolver
arguments) and never the service's `AppState`, so the storage/query/present
logic is reusable and independently testable. `vta-service` re-exports it as
`vta_service::vault`, so its dispatch handlers, sweeper, and credential-exchange
paths reach it through the same `crate::vault::…` paths as before.

## Features

- `bbs` — BBS+ (`bbs-2023`) selective-disclosure credentials (receive/present of
  pseudonym credentials). Pulls in BLS12-381 + the `bbs-2023` cryptosuite.
- `webvh` — holder-side status refresh (`HttpStatusListResolver`): fetch an
  issuer's `BitstringStatusList` over the SSRF-hardened foreign-fetch client to
  re-check a held credential's validity.

Both are off by default.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
