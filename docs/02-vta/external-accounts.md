# External accounts

A VTA can hold identities at clouds and third-party services — an S3-compatible
bucket today — and let the integrations bound to them use those identities only
through something short-lived. The integration never holds the provider secret,
and no administrator can read it back.

Design and threat model: [`../05-design-notes/vta-external-accounts.md`](../05-design-notes/vta-external-accounts.md).
Wire surface: the `external/*/0.1` Trust Tasks.

## What this VTA serves

| Model | Served | What a consumer gets |
|---|---|---|
| `s3-static-presign` (R2, B2, MinIO, any S3-compatible store) | yes | one presigned URL per issuance: one method, one object, minutes |
| `gcp-wif-pinned`, `aws-roles-anywhere`, `azure-cert`, `oauth2-private-key-jwt`, `sui-signer`, `static-secret` | not yet | — `create` refuses them with `external:invalidSettings` (`details.member: "model"`) |

## Walkthrough: an R2 bucket for a VTC's data rooms

```bash
# 1. The account. Settings never carry a secret.
pnm external create r2-rooms --context community --label "R2 — rooms" \
    --settings '{"model":"s3-static-presign","endpoint":"https://<acct>.r2.cloudflarestorage.com",
                 "region":"auto","bucket":"rooms","pathStyle":true,"accessKeyId":"<key id>"}'

# 2. Who may use it, and how far. Grant before the secret: the generated
#    provider policy is the union of the bindings' prefixes.
pnm external bind r2-rooms --context community --consumer did:webvh:…:vtc \
    --prefix rooms/ --action put --action get --action delete --max-ttl 900 --rate 120

# 3. What to set up at the provider (an access key scoped to those prefixes).
pnm external setup r2-rooms --context community

# 4. The secret half: read without echo, sealed in pnm to a single-use
#    wrapping key together with the account's access key id, never shown
#    again. Only a keyed fingerprint (`hmacsha256:…`) comes back.
pnm external secret-set r2-rooms --context community

# 5. Prove it works. Only a probe that is ok *and* complete (the canary was
#    written, read and deleted) clears `providerSetupRequired`; nothing is
#    issued before that. Before anything is bound, set `probePrefix` in the
#    settings, or the probe stops early with `complete: false`.
pnm external probe r2-rooms --context community
```

The consumer (here the VTC) holds `external-auth-use` in the context — every
role that holds `sign` derives it — and calls `external/credentials/issue/0.1`.
The credential comes back sealed to its own key-agreement key (the X25519
derivation of a `did:key`, otherwise the first X25519 `keyAgreement` method of
its DID document — with neither, the VTA refuses with `noKeyAgreement` before
signing anything), inside a signed response. The consumer verifies that
response's proof before opening the bundle: it is what anchors it.

A caller with no binding on the account — or naming an account that does not
exist — gets `external:notFound`, the same answer either way. Only a bound
consumer learns an account's state.

**The kill switch** is `pnm external suspend r2-rooms --context community`:
immediate, alone, never consent-gated. `resume` turns it back on.

## Consent: declare it

Changing an account should need a second administrator. This VTA ships **no**
approval rules (they are operator policy, and enforcement is off until
`policy.enforcement = true`), so declare the ones the specification recommends:

```bash
for t in accounts/create accounts/update accounts/secret/set accounts/bindings/grant \
         accounts/keys/rotate accounts/resume accounts/delete; do
  pnm approvals require "https://trusttasks.org/spec/external/$t/0.1" --consent --set admins
done
```

Leave `suspend` and `bindings/revoke` out: taking authority away must be fast
and possible alone. The approvers decide with `task-consent/decision` signed by
their own DIDs; a relayer such as the VTC console never counts as one.

## Backup and restore

Accounts, settings and bindings are backed up (`external_accounts`). Secrets
are **not** (`external_secrets` is excluded): a portable, password-protected
backup must not be a way to take a provider key away. After a restore, set
each secret again and probe; until then the account reports
`providerSetupRequired` and issues nothing.

An archived account answers `external:archived` to anything that would change
or use it (update, secret, bindings, probe, suspend, resume); restore it first.
Reads still answer.
