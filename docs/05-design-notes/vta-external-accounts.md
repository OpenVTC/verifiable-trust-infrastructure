# The VTA as the key authority for cloud and third-party accounts

Status: **proposal.** Nothing here is built. First consumer: room file storage
([`data-rooms-files.md`](data-rooms-files.md) §7). The design is general on
purpose.

Integrations keep needing to authenticate to someone else:
- a VTC to an S3 bucket or a GCS bucket;
- a VTC to Sui, to pay Walrus for storage;
- an agent to a SaaS API;
- a mediator to a push service.

The default answer everywhere is a long-lived secret (an access key, a
service-account JSON, a wallet key) pasted into the integration's config. Every
copy of it is a liability, and every administrator who saw it can still use it.

The VTA already is the key authority, and it already has the right shape for
this. `vault/proxy-login` uses a stored secret *inside* the VTA (it mints a
SIOP token, or posts a password to a login URL) and returns only a short-lived
session. `keys/sign-sshsig` signs one externally defined format, which the VTA
builds itself, under its own narrow capability. This note generalises both into
**external accounts**: a third-party identity the VTA holds, which bound
integrations can use only in the ways the account allows, getting back only
something short-lived.

---

## 1. Threat model

| Actor | Must not be able to |
|---|---|
| **One administrator of several**, or one administrator's compromised device | create, retarget or widen an account, or bind a new consumer to it, alone; recover any secret or key |
| **The consuming integration's host** (a VTC's machine and its operator) | use an account beyond its binding, beyond the scope it asks for, or after it is cut off; recover anything that outlives a compromise by more than a credential lifetime |
| **Whoever hosts public verification material** (a JWKS, a CRL) | mint credentials the cloud accepts |
| **A network observer, or an intermediary** (mediator, proxy, CDN) | read an issued credential |
| **The VTA's operator** | out of scope for the plain VTA, as for every key the VTA holds. **In a TEE VTA, in scope**: keys are enclave-bound and the seed is not exportable (`MnemonicExportGuard`) |

Five rules follow from that table, and the rest of this note implements them.

1. **No long-lived bearer secret outside the VTA.** Consumers get credentials
   that expire in minutes, and only in a sealed envelope (§6).
2. **Keys are pinned at the cloud, never fetched from a host we must trust**,
   wherever the cloud allows it (§3). A trust model where an attacker who can
   edit one file on one web server can mint credentials is the weakest link,
   so it is the last choice rather than the first.
3. **The VTA builds what it signs** (`SigningDomain::ProtocolDefined`). The
   general oracle's opaque domain is never used, and could not be: its output
   verifies as a VTA opaque payload and as nothing else.
4. **Least privilege at three layers.**
   - **The cloud's trust policy** pins this account's identity.
   - **The VTA's binding** pins which integration may use the account, and its
     ceiling.
   - **Each issuance is downscoped further** to the one prefix or operation
     asked for (§5).
5. **Changing an account needs other administrators**, and their approval is
   signed by **their own DIDs**, so a compromised relayer (the VTC) can ask but
   never approve (§7).

---

## 2. What an account is

```jsonc
// external_accounts:<context>:<accountId>
{
  "id": "eu-s3-primary",
  "label": "EU S3 — main account",
  "context": "community",                       // owning VTA context; act scope decides who manages it
  "model": "aws-roles-anywhere",                 // §3
  "settings": { … },                             // per model; never a secret
  "keyId": "…",                                  // VTA key this account signs with (§4), when the model has one
  "secret": { "fingerprint": "…", "setAt": "…" } // when the model has one (§3, static only); value never returned
  "bindings": [                                  // §5
    { "consumer": "did:webvh:…vtc", "scopeCeiling": { … }, "maxTtl": "15m", "rate": "120/min" }
  ],
  "state": "active | suspended | archived",
  "createdAt": "…", "approvals": [ … ]           // the consent that created or last changed it
}
```

Accounts live in their own keyspace, **not** the password vault. They reuse the
vault's lifecycle code (archive, restore, purge, `VaultStatus`), but a vault
entry is a person's secret released to that person, and an account is an
authority used by integrations. Putting them in one list would let
`vault/release` reach something it was never meant to.

---

## 3. Auth models

Ranked by how much has to be trusted. Each is a driver behind one trait:

```rust
trait ExternalAuthDriver {
    fn validate_settings(&self, s: &Settings) -> Result<()>;
    fn setup(&self, acct: &Account, vta: &KeyView) -> CloudSideSetup;      // §8: what to paste into the cloud
    async fn issue(&self, acct: &Account, req: &Scoped, vta: &Signer) -> Result<IssuedCredential>;
    async fn probe(&self, acct: &Account, vta: &Signer) -> ProbeReport;
}
```

| Model | What the cloud pins | Public endpoint needed | VTA key | Notes |
|---|---|---|---|---|
| **`aws-roles-anywhere`** | **a CA certificate** (the trust anchor), uploaded once | **none** | P-256 CA key + per-account end-entity key | **Recommended for AWS.** The VTA is the CA. It issues short-lived end-entity certificates (24 h, re-issued) to its own account keys, and signs `CreateSession` with the end-entity key. Revocation is a CRL the VTA generates and an administrator imports (`ImportCrl`): pushed, never fetched. |
| **`gcp-wif-pinned`** | **an uploaded JWKS** (≤ 8 keys) on the Workload Identity pool provider | **none** | P-256, or RSA if ES256 is refused | **Recommended for GCP.** The VTA signs an ID token. GCP's STS exchanges it, then optionally impersonates a service account. Rotation is a re-upload, overlapping old and new keys. |
| **`oidc-discovery`** (AWS IAM OIDC, GCP, Azure federated credential) | the **issuer URL**; keys are fetched from its JWKS | **yes**: discovery + JWKS over public HTTPS | P-256 or RSA (Azure documents RS256 only) | **The JWKS host is a trust root.** Anyone who can change that file can assume the role. Serve it from the VTA itself (a declared REST exception) rather than a shared host. Offered for clouds or tenants with no pinned alternative. |
| **`azure-cert`** (later) | an uploaded certificate on the app registration | none | RSA | Client-assertion JWT (RFC 7523) to Entra's token endpoint. Azure's pinned equivalent of the two above. |
| **`oauth2-private-key-jwt`** | the public key, registered with the provider | none | P-256 or RSA | RFC 7523 client authentication for SaaS APIs and IdPs that support it. Brokered like the cloud models. |
| **`s3-static-presign`** | an access-key pair | none | — (holds a **secret**) | For S3-compatible stores that cannot federate (R2, B2, MinIO). The secret **never leaves the VTA**: consumers get **per-object presigned URLs** (SigV4), each one operation on one key for minutes. |
| **`sui-signer`** | the address (from the VTA key) | none | P-256 (Sui `secp256r1`) | **Sign-only.** The VTA signs a Sui transaction only if it is an allow-listed call: Walrus `register`, `certify`, `extend` or `delete`, against the configured system object, with a gas and amount cap. The intent message and Blake2b digest are built by the VTA. Sui's internal SHA-256 and low-`s` rules are to be confirmed against its reference implementation before use. |
| **`static-secret`** | an API key or token | none | — (holds a **secret**) | **Last resort.** Brokered only through a driver that uses it inside the VTA, as `password` + `loginConfig` does today. **Never released.** A provider that can only be reached by handing the consumer the raw key is not supported, because that defeats every rule in §1. |

**Ambient cloud identity** (an EC2 role, GKE workload identity) is not an account
model; it belongs to the consumer's host. A consumer may use it where it runs on
the target cloud. It has no VTA audit or binding, and §1 rule 1's guarantee then
rests on the cloud's own host isolation instead.

---

## 4. Keys

- **P-256 keys are derived** in the owning context's key space through
  `key_custody`, like every other VTA key. Their paths are recorded on the
  account, never chosen by a caller (key custody rules 3 and 4).
- **RSA keys** (3072-bit, for Azure and any provider that refuses ES256) cannot
  come from BIP-32. They are generated in the VTA with `aws-lc-rs`, already the
  workspace's RSA implementation, and stored wrapped like imported keys
  (`vta-keys`, AES-GCM). They never leave the VTA. **They are not in a backup**,
  for the reason in §9. The provider-side setup has to be redone after a
  disaster restore, and the console says so.
- **The CA** for `aws-roles-anywhere` is a derived P-256 key per context.
  - **Its certificate** is self-signed with a 5-year validity and path length 0.
  - **Signing input** for certificates and CRLs is built by the VTA (`rcgen`):
    `ProtocolDefined` again.
  - **It only certifies** the VTA's own account keys. Its issuance is never
    exposed as a task.
- **Rotation**: `external/accounts/keys/rotate/0.1`.
  - **Pinned models** stage the new key beside the old one: both in the uploaded
    JWKS (GCP), or a second end-entity certificate under the same anchor (AWS).
  - **The old key retires** after the administrator confirms the cloud side was
    updated, which the probe verifies.

---

## 5. Using an account

Two consumer tasks, and only two.

| Task | Models | Returns |
|---|---|---|
| `external/credentials/issue/0.1` | every brokered model | cloud credentials or a presigned URL, **sealed** (§6), with an expiry |
| `external/sign/0.1` | `sui-signer` | a signature over a transaction the VTA validated |

**The VTA does the exchange.** For brokered models the consumer never sees the
signed assertion: the VTA signs, calls the provider's token endpoint, and
returns only the result. This is deliberate. If the VTA returned a signed
assertion for the consumer to exchange, the consumer would choose the session
policy, and §1 rule 4's third layer would be the consumer's promise rather than
the VTA's enforcement.

**Every issuance is downscoped** to the request, inside the binding's ceiling:

```jsonc
// external/credentials/issue/0.1
{ "account": "eu-s3-primary",
  "scope":   { "prefix": "rooms/3f9a…/", "actions": ["put", "get", "delete"] },
  "ttl":     "15m" }
```

- **AWS**: an inline session policy on the session (or a chained `AssumeRole`
  with `Policy`), limited to `s3:{Put,Get,Delete}Object` on
  `arn:aws:s3:::<bucket>/<prefix>*`. Optionally `aws:SourceIp` or
  `aws:SourceVpc`, pinned to the consumer's egress when the binding names it, so
  a stolen credential is useless off that network.
- **GCS**: a Credential Access Boundary with
  `resource.name.startsWith('projects/_/buckets/<bucket>/objects/<prefix>')`.
- **Presign**: the URL is the scope (one method, one key, one expiry).

Scope values are **never interpolated from caller strings**. They are built from
validated identifiers (a hex digest prefix, a bucket name checked against the
account's settings), because a crafted value breaking out of a CEL or JSON
policy string is a known class of bug (CVE-2026-42811, a CEL injection in Apache Polaris's downscoped GCS credentials).

**The binding is checked before anything is signed.**
- The caller must be the binding's `consumer` DID, proven by the Trust Task's
  own proof, never a header.
- The caller must hold `external-auth-use` in the account's context, through
  `act_scope()` (never `allowed_contexts.is_empty()`).
- The requested scope must be inside the ceiling, and the TTL under `maxTtl`.
- It is rate-limited per binding.

A refusal says which of those failed, and is audited with `security_alert` when
it is a scope or binding violation, since those are what a compromised consumer
looks like.

**Retry class**: `issue` is `Idempotent` in effect, because a second credential
is harmless and expires. `sign` is `NotRetrySafe` for `sui-signer`: a second
signature over the same transaction is harmless, but over a rebuilt one it is a
second payment. Both are classified in `vta_sdk::retry_safety`.

---

## 6. Delivering a credential

An issued credential is a secret. **The workspace has one secret-bearing wire
format, `sealed_transfer`, and this uses it.** The response payload is a
`SealedPayloadV1::ExternalCredential` variant (new and additive, per the
variant rules), HPKE-sealed to the caller's DID, inside whichever transport
carried the task. TSP and DIDComm are already end-to-end. The seal is what
keeps HTTPS-terminating proxies, the VTA's own request logs, and a consumer's
debug logging of "the response" from ever holding a usable key.

The consumer keeps credentials in memory only, re-issues before expiry, and
drops them on shutdown. It never writes them to config or disk.

---

## 7. Managing accounts: Trust Tasks, so the VTC can be the console

Every management operation is a VTA Trust Task, so `pnm`, an agent and the VTC
console all drive the same surface:

| Task | Does |
|---|---|
| `external/accounts/{list,get}/0.1` | Read. Never a secret or private key; fingerprints and public material only |
| `external/accounts/create/0.1` | Creates an account and derives or generates its key |
| `external/accounts/update/0.1` | Changes settings (bucket, role ARN, pool provider) |
| `external/accounts/secret/set/0.1` | Static models only. The payload is a `sealed_transfer` armor block sealed **in the administrator's browser** to the VTA. Write-only |
| `external/accounts/bindings/{grant,revoke}/0.1` | Who may use it, with what ceiling |
| `external/accounts/setup/0.1` | §8's cloud-side setup, regenerated on demand |
| `external/accounts/probe/0.1` | §8's check |
| `external/accounts/keys/rotate/0.1` | §4 |
| `external/accounts/{suspend,resume,archive,restore,delete}/0.1` | Lifecycle. **Suspend is the kill switch**: one task, immediate, refusing every issuance |

**Authorization**: a new capability, `external-accounts-manage`, in the owning
context. Separately from that, **consent**. The shipped approvals bundle
(`pnm approvals`, DTTE) carries `requires: consent` for:
- `create`, `update` and `secret/set`;
- `bindings/grant`;
- `keys/rotate`;
- `delete`.

The approver set is the context's administrators. `suspend` and `revoke` are
deliberately **not** consent-gated: taking authority away must be fast and
possible alone.

**How the VTC console drives it.**
1. The VTC holds an ACL entry on the community's VTA as an integration:
   `external-accounts-manage` (to *request*) and `external-auth-use` (to
   *consume* its own bindings), in the community's context.
2. An administrator's action in the console becomes a VTA Trust Task the VTC
   sends over TSP/DIDComm, carrying in `ext["org.openvtc"]` which administrator
   asked and the VTC action id, for correlation in both audit trails.
3. The VTA parks it for consent and pushes `task-consent/request` to the
   approvers.
4. The approvers decide **in the VTC console**, which already knows how: the
   wallet's `approveDecision` signs a `task-consent/decision` with the
   approver's own DID, and the VTC relays it.
5. The VTA counts decisions by signer DID, never by relayer.

So the console is a convenient front end and nothing more. **A compromised VTC
can propose a change and can relay a decision, but cannot make one.** That is
the property the VTC's own action list gives VTC operations, here held at the
authority that owns the key. Storage operations that are VTC-side (assigning a
room to a config) stay in the VTC's action list. The console shows both queues
in one place, so an administrator does not care which authority parked an item.

---

## 8. Setup and probe

`external/accounts/setup/0.1` returns exactly what an administrator pastes into
the cloud, generated, never hand-written. **The VTA never asks for cloud
administrator credentials**, and nobody types an ARN into a trust policy by
hand.
- **`aws-roles-anywhere`**:
  - the trust anchor PEM, and the `aws rolesanywhere create-trust-anchor` and
    `create-profile` commands;
  - a role whose trust policy conditions on the certificate's subject
    (`aws:PrincipalTag/x509Subject/CN` = the account id);
  - a permissions policy at the binding's ceiling;
  - the current CRL and its `import-crl` command.
- **`gcp-wif-pinned`**:
  - the JWKS file;
  - the `gcloud iam workload-identity-pools create` and
    `providers create-oidc --jwk-json-path` commands, with an attribute
    condition on `assertion.sub`;
  - the bucket IAM binding.
- **`oidc-discovery`**: the issuer URL, the IAM OIDC provider or federated
  credential commands, the trust policy, and a warning that the JWKS endpoint is
  now a trust root.

`probe` runs before consent is even requested:
1. sign;
2. exchange;
3. at the ceiling's narrowest scope, put, get and delete one canary object.

Approvers see the probe report with the request, so they approve something
shown to work, and the cloud's own error appears verbatim when a step fails.

---

## 9. Backup, restore, and what "unrecoverable" means

- **Derived keys** (P-256) come back with the seed, by construction: the seed
  is the VTA's root, and its holder can derive everything. In a TEE VTA the
  mnemonic cannot be exported, so nobody holds it in the clear.
- **RSA keys and static secrets** are in `EXCLUDED_FROM_BACKUP`. A VTA backup
  is portable and password-protected, so a super-admin holding a backup and its
  password could otherwise take them away. After a restore those accounts show
  **"provider setup required"**: rotate (new RSA key, new upload) or set the
  secret again.
- **The accounts themselves** (settings, bindings, approvals) are backed up.

What no administrator can get, through any surface the VTA or VTC offers
(Trust Tasks, console, CLI, backups, logs, audit, telemetry):
- a private key;
- a static secret;
- a credential issued to someone else.

What the VTA's own operator can get is what they can get for every key the VTA
holds. That is why the TEE VTA exists, and a community using external accounts
for anything it would be hurt to lose should run one.

---

## 10. Audit

Every issuance writes one audit row:
- account and binding;
- the consumer DID;
- the downscoped scope and its expiry;
- the provider's session or request id, so a CloudTrail or GCP audit-log entry
  can be traced back to this row.

Never the credential.

Every management task, decision and refusal is audited like any other Trust
Task. An unusual issuance rate per binding raises a hint on the VTC console's
live channel.

---

## 11. Specifications

All in `dtgwg-trust-tasks-tf` first:
- the `external/accounts/*` family;
- `external/credentials/issue`;
- `external/sign`;
- the sealed `ExternalCredential` payload's shape, documented beside
  `sealed_transfer`.

Each task is classified in `vta_sdk::retry_safety` and carries a `vta-mcp`
guard verb. `external/credentials/issue` is one an MCP host must never approve
once for all (an agent could then mint cloud credentials indefinitely), so the
guard treats it as per-call.

## 12. Phases

| # | Phase | Size |
|---|---|---|
| E0 | Specs; `ExternalAuthDriver`; accounts keyspace; capabilities; approvals defaults; management tasks; `pnm external …` | L |
| E1 | `gcp-wif-pinned` + GCS downscoping (the simplest pinned model, and it settles ES256 vs RSA for GCP) | M |
| E2 | `aws-roles-anywhere`: VTA CA, `rcgen` certificates and CRL, `CreateSession` signing, session policies | L |
| E3 | `s3-static-presign` | S |
| E4 | `sui-signer` with the Walrus call allow-list | M |
| E5 | VTC console: External accounts pages, setup and probe, the combined consent queue | M |
| E6 | `oidc-discovery` (AWS IAM OIDC, Azure) with the VTA-served JWKS; then `azure-cert`, `oauth2-private-key-jwt` | M |

## 13. Open

1. **Roles Anywhere downscoping.** Whether `CreateSession` takes a per-request
   session policy, or downscoping needs a chained `AssumeRole`, which caps the
   session at one hour. Either works; it changes one code path.
2. **`sui-signer` amounts.** What gas and WAL caps per transaction and per day
   are sane defaults, and who may raise them (consent, presumably).
3. **Egress from a TEE VTA.** Brokered models need outbound HTTPS to STS
   endpoints. The enclave's egress proxy must allow exactly those hosts, with TLS
   verified inside the enclave.
4. **Folding `keys/sign-sshsig` in** as a sign-only model, once this exists.
   Not proposed: it works, and renaming a shipped task costs every client.
