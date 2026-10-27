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
#    wrapping key (named by its keyId, and spent whether or not the bundle
#    opens) together with the account's access key id, never shown
#    again. Only a keyed fingerprint (`hmacsha256:…`) comes back.
pnm external secret-set r2-rooms --context community

# 5. Prove it works. Only a probe that is ok *and* complete (the canary was
#    written, read and deleted) clears `providerSetupRequired`; nothing is
#    issued before that. Before anything is bound, set `probePrefix` in the
#    settings, or the probe stops early with `complete: false`.
pnm external probe r2-rooms --context community
```

**A store on a private network or loopback** (MinIO on a LAN, LocalStack) is
refused by default: `create`/`update` answer `external:invalidSettings`
(`details.member: "endpoint"`) for a private or loopback IP literal or a local
name, and the probe's resolver refuses a name that resolves to one, so the probe
stops at `sign` and the account stays `providerSetupRequired`. Set
`VTA_ALLOW_PRIVATE_ENDPOINTS=1` in the VTA's environment — the same switch that
lets it resolve a DID on such a host — to admit them. Link-local and
cloud-metadata targets are refused either way, and the probe never follows a
redirect. The endpoint must be `https://` in both modes.

The consumer (here the VTC) holds `external-auth-use` in the context — every
role that holds `sign` derives it — and calls `external/credentials/issue`
(0.1, or 0.3 for a batch).
The credential comes back sealed to its own key-agreement key (the X25519
derivation of a `did:key`, otherwise the first X25519 `keyAgreement` method of
its DID document — with neither, the VTA refuses with `noKeyAgreement` before
signing anything), inside a signed response. The consumer verifies that
response's proof before opening the bundle: it is what anchors it.

For an `s3-static-presign` account, `external/credentials/issue/0.3` takes a
**presign batch** instead of a scope: up to 64 operations on one object (and at
most one multipart upload of it) — `put`, `get`, `head`, `delete`,
`create-multipart`, `upload-part`, `list-parts`, `complete-multipart`,
`abort-multipart` — each presigned exactly as the specification's table says,
with a write bound to its `Content-Length` and `x-amz-checksum-sha256`. The
binding's ceiling is unchanged: multipart writes and `list-parts` need `put`,
`head` needs `get`, `abort-multipart` needs `delete`. The batch counts once
against the rate, and comes back sealed as one `PresignedRequestSet`.

**A batch whose sealed answer would not fit is refused, never trimmed.** The
response bounds `sealedCredential` at 256 KiB, and a sealed presigned request
is about 2.9 KiB with a short object key — but far more with a long one: at the
longest key and upload id the schema allows (1024 characters each) only 10 fit.
So for a batch the VTA resolves the caller's key-agreement key (`noKeyAgreement`
first), presigns and seals — none of which contacts the provider — and refuses a
set over the bound with `external/credentials/issue:responseTooLarge`, its
`details.maxOperations` naming how many of the batch's operations, in order,
fit. The count is computed from the longest armor the set could seal to, so a
part of that size always fits. Only then does the issuance count against the
rate: a request refused at any check, `responseTooLarge` included, costs
nothing, and a refused set is dropped unreturned and never logged. The caller
splits — to `maxOperations`, else in half — and asks again for each part
(consumer item 5); the SDK's `VtaClient::external_credentials_issue_presign`
and the VTC do this.

`pnm external issue <account> --context <id> --presign @batch.json` sends one
from the CLI, printed still sealed (an array of answers when it had to split).
`0.1` and `0.2` are served beside it. `0.2` keeps its own behaviour for a VTC
on an older build: up to 128 operations, the rate counted before the answer is
sized, and an oversized answer refused as `invalidBatch` — `responseTooLarge`
is not one of 0.2's codes, and no standard code says it.

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
