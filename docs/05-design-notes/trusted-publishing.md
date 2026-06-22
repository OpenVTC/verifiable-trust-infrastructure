# Trusted Publishing to crates.io

The workspace publishes its crates to crates.io using **Trusted Publishing**
— crates.io accepts the GitHub Actions OIDC identity of the
`.github/workflows/publish.yml` workflow instead of a stored API token.
There is no `CARGO_REGISTRY_TOKEN` secret in the repo; each run mints a
short-lived token via the OIDC exchange.

## What auto-publishes

`publish.yml` runs on every push to `main` (and on manual dispatch). It
walks the publishable crates in dependency order and publishes **only the
versions not already on crates.io**, so the flow is idempotent:

1. Bump the version of each crate you want to release (in a PR).
2. Merge to `main`.
3. The workflow publishes exactly those crates; everything else is skipped
   because its version already exists.

Publish order (bottom-up; each crate after its internal deps):

```
vta-sdk → vti-webauthn → vti-common → vti-secrets → vta-cli-common
        → vtc-service → vta-service → pnm-cli → cnm-cli
```

Non-publishable crates (`publish = false`) are excluded: `vta-mcp`,
`vta-enclave`, `vta-mobile-core`, `didcomm-test`, `tests/e2e`.

## One-time setup on crates.io (per crate)

Trusted Publishing is configured **per crate** in the crates.io UI by an
owner. Do this once for each of the nine crates above:

1. Sign in to <https://crates.io> and open the crate, e.g.
   `https://crates.io/crates/vta-sdk`.
2. **Settings → Trusted Publishing → Add**.
3. Fill in:
   - **Repository owner**: `OpenVTC`
   - **Repository name**: `verifiable-trust-infrastructure`
   - **Workflow filename**: `publish.yml`
   - **Environment name**: *(leave blank)* — the workflow does not use a
     GitHub Environment. If you later add one for protection rules
     (see below), set it here too; the two must match.
4. Save.

Repeat for: `vta-sdk`, `vti-webauthn`, `vti-common`, `vti-secrets`,
`vta-cli-common`, `vtc-service`, `vta-service`, `pnm-cli`, `cnm-cli`.

Until a crate has this config, its publish step fails the OIDC check — the
others still publish.

## How the workflow authenticates

`publish.yml` grants `id-token: write`, then `rust-lang/crates-io-auth-action`
exchanges the OIDC token for a short-lived crates.io token exported as
`CARGO_REGISTRY_TOKEN`. The token is valid only for the crates whose
Trusted Publisher config matches this repo + workflow, and it expires
shortly after the run.

## Optional hardening: a GitHub Environment

For a manual approval gate or to scope the OIDC claim further, create a
GitHub Environment (e.g. `release`) with required reviewers, add
`environment: release` to the `publish` job, and set the same **Environment
name** in each crate's Trusted Publishing config. Note this makes
publishing wait for approval rather than running hands-off on every push to
`main`.
