# vta-external

**External accounts** for the VTA: identities the VTA holds at clouds and
third-party services, used by the integrations bound to them only through
short-lived, downscoped credentials or protocol-defined signatures.

The wire surface is the `external/*` Trust Task family; the design is
`docs/05-design-notes/vta-external-accounts.md`. This crate holds what does not
depend on the service spine — the account store, the auth-model drivers, scope
and binding checks, the per-binding rate, keyed fingerprints — and takes narrow
dependencies (`KeyspaceHandle`, the seed store) rather than the service's
`AppState`. `vta-service` re-exports it as `vta_service::external` and serves
the tasks.

## Models

| Model | Status |
|---|---|
| `s3-static-presign` | served: SigV4 query presigning; the secret never leaves the VTA |
| `gcp-wif-pinned`, `aws-roles-anywhere`, `azure-cert`, `oauth2-private-key-jwt`, `sui-signer`, `static-secret` | specified; not yet served — `create` refuses them |
