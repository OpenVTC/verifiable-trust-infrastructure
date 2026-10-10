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
#    wrapping key, never shown again. Only a keyed fingerprint comes back.
pnm external secret-set r2-rooms --context community

# 5. Prove it works. A successful probe clears `providerSetupRequired`;
#    nothing is issued before that.
pnm external probe r2-rooms --context community
```

The consumer (here the VTC) holds `external-auth-use` in the context — every
role that holds `sign` derives it — and calls `external/credentials/issue/0.1`.
The credential comes back sealed to its own key-agreement key, inside a signed
response.

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
