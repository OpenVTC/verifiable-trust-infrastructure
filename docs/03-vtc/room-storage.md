# Room storage: where a community keeps its rooms' files

A **storage config** is one named backend — a directory on this host (`local`), an
S3-compatible bucket (`s3`) or a Google Cloud Storage bucket (`gcs`) — and how the
community authenticates to it. Every room is assigned to one config, which receives
its new uploads; every file remembers the config it was written to. Configs are
managed in the console (**Data rooms → Storage**), with `cnm storage …`, or with the
`vtc/storage/configs/*` Trust Tasks; every change is parked for another holder of
`vtc.rooms.admin`. The design is `docs/05-design-notes/data-rooms-files.md` §7.

## How a config authenticates

| Mode | What it is | Who permits it |
|---|---|---|
| `vta-account` (recommended, `s3`) | An external account at the community's VTA. The VTA keeps the key and signs one request per file for five minutes; the community holds nothing. | Always available. |
| `ambient` (`s3`, `gcs`) | This machine's own cloud identity (an instance role, workload identity). On `s3` it may name the IAM role it assumes (`roleArn`). | The host operator, `[rooms.files.auth] ambient = true`. |
| `sealed` (discouraged, `s3`, `gcs`) | A long-lived credential the community keeps, encrypted. | The host operator, `[rooms.files.auth] sealed = true`. |

With `ambient` and `sealed` the community does what the VTA would: for each room it
mints a credential limited to that room's prefix (`rooms/<32 hex of SHA-256(roomId)>/`
under the config's prefix) and to read, write or delete objects, for at most 15
minutes, and never uses one for another room or the bucket as a whole
(`vtc/storage/configs/create/0.2`, "Room-scoped credentials"). If it cannot get one,
the operation fails — it never falls back to the unscoped identity or key.

**`sealed` does not protect the credential from whoever operates this machine.** The
process must be able to use the key, so an operator with access to the process or
its secret store can reconstruct it. It protects against every administrator through
every surface the community offers. Where administrators and operators are the same
people, leave it off.

## Host configuration

Absent, neither `ambient` nor `sealed` is offered: an upgraded community starts with
exactly the modes it had.

```toml
[rooms.files.auth]
# Configs on this machine's own cloud identity.
ambient = true
# Configs with a stored credential (discouraged).
sealed = false
# The IAM role an `ambient` `s3` config assumes when it names none. Absent, the
# ambient identity's own role (which must trust itself to be assumed).
aws_role_arn = "arn:aws:iam::123456789012:role/community-rooms"
# This host's stable egress, added to every AWS session policy as `aws:SourceIp`.
aws_source_ip = "203.0.113.7/32"
# The service account an ambient Google token is minted for, with a 900-second
# lifetime. Absent, the ambient token itself, used for at most 15 minutes.
gcs_service_account = "rooms@northwind.iam.gserviceaccount.com"
```

Turning a mode off later keeps the configs that use it: each reports its credential
`notAllowed` and stores nothing until an administrator changes its authentication.

### What the cloud side needs

- **`s3`, `ambient`**: the role the community assumes allows `s3:PutObject`,
  `s3:GetObject`, `s3:DeleteObject`, `s3:AbortMultipartUpload` and
  `s3:ListMultipartUploadParts` on `arn:aws:s3:::<bucket>/<prefix>rooms/*` and
  `…/<prefix>probe/*`, and its trust policy lets this machine's identity assume it.
  Each session is narrowed further by an inline policy naming one room.
- **`s3`, `sealed`, AWS**: the IAM user's key may call `sts:GetFederationToken` and
  holds the same object permissions; each federated session names one room.
- **`s3`, `sealed`, R2 / B2 / MinIO**: an access key for the bucket. These stores have
  no STS, so the key only presigns single objects under a room's prefix for at most
  15 minutes.
- **`gcs`**: the identity (or the sealed service account) holds
  `roles/storage.objectUser` on the bucket; for `gcs_service_account`, this machine's
  identity holds `roles/iam.serviceAccountTokenCreator` on it. Each token is narrowed
  by a Credential Access Boundary naming one room's prefix.

## Setting a sealed credential

The credential is never typed into the console. From a terminal holding an
administrator's `cnm` profile:

```sh
# s3: {"accessKeyId": "…", "secretAccessKey": "…"[, "sessionToken": "…"]}
# gcs: the service-account key file exactly as Google issued it
cnm storage credentials set --config r2-archive --file ./r2-key.json --reason "evaluation"
```

`cnm` reads the config, seals the credential to the community's DID (the X25519
derivation of the Ed25519 key its DID document lists), and sends
`vtc/storage/credentials/set/0.2` after your passkey gesture; another administrator
approves it like any storage change. The community opens it, checks it is a
credential for that config and kind, stores it encrypted, probes the config with it
and shows it from then on only as a fingerprint. Setting another replaces — destroys —
the one before.

A backup never carries a sealed credential, and importing one destroys every
credential this community holds: after a restore each `sealed` config reports
`credential required` until it is set again.

## Versions

`vtc/storage/configs/{list,get,create,update}` are served at 0.1 and 0.2, each
answered at its own version; the console speaks 0.2. A 0.1 reader is shown a config
without its `roleArn` and a `notAllowed` credential as `required` (0.1 has neither).
`vtc/storage/credentials/set` is served at 0.2.
