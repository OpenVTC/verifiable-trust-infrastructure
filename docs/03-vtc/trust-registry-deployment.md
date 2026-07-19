# Trust-registry deployment runbook

A step-by-step guide to standing up an
`affinidi-trust-registry-rs` instance, giving it an identity from a
VTA, and wiring a VTC to it.

Where [trust-registry integration](trust-registry.md) explains
*what* the VTC publishes and *why*, this document is the
operational sequence: which command to run, in which order, and
what to check before moving on.

## The three wirings

Deploying a registry into a VTI stack means establishing three
independent relationships. They are often conflated, and they fail
in different ways.

```mermaid
graph TB
    VTA["VTA<br/>(key custody)"]
    TR["Trust Registry"]
    VTC["VTC<br/>(community governance)"]
    MED["Mediator"]

    VTA -->|"1 · identity: DID + keys<br/>via sealed bundle"| TR
    TR <-->|"2 · DIDComm transport"| MED
    VTC -->|"3 · registry.url (REST/TRQP)<br/>registry.did (DIDComm writes)"| TR

    classDef vta fill:#d4e6f9,stroke:#3a6fb0,color:#08305f
    classDef vtc fill:#e9d7f7,stroke:#7e3fa6,color:#3a0a5a
    classDef tr fill:#e8f5e9,stroke:#3e8e41,color:#1b3a1f
    classDef med fill:#f5f5f5,stroke:#555,color:#111
    class VTA vta
    class VTC vtc
    class TR tr
    class MED med
```

The VTA relationship is **not** peering. The registry does not
register itself with a VTA the way a VTC does. In VTA mode the
registry simply holds no private keys: at startup it authenticates
to the VTA, pulls its DID + keys for a named context, and uses
those to reach the mediator. Identity custody, nothing more.

## Order of operations

| Stage | Establishes | Gate |
|---|---|---|
| 1 | Registry runs standalone, fjall store opens | `curl /health`, `POST /recognition` → 404 |
| 2 | Real DID, mediator connection | `/.well-known/did.json` resolves |
| 3 | Trust Tasks round-trip | `test-trust-registry` mediator tests |
| 4 | Identity sourced from the VTA | stages 1–3 pass again, new identity |
| 5 | VTC points at the registry | VTC `registry_status` |

Do not start at stage 4. The registry's `vta` feature has no
end-to-end test coverage — three unit tests over `string://`
fixtures, no VTA server ever contacted — and it is excluded from
the published Docker image. Prove the mediator path first so a
stage-4 failure has exactly one candidate cause.

---

## Stage 0 — Values you will need

| Value | Source | Example |
|---|---|---|
| Mediator DID | mediator deployment | `did:webvh:Qm…:webvh.example:mediator` |
| VTA URL | VTA deployment | `https://vta.example.com` |
| WebVH host | DID-hosting server | `https://webvh.example.com` |
| Admin DID(s) | operators permitted to write records | `did:peer:2.Vz6Mk…` |
| VTC DID | VTC `config.toml` | `did:webvh:Qm…:webvh.example:vtc` |

The mediator's transport URL is never configured — it is resolved
from the mediator's DID document. Confirm that resolves before
anything else:

```bash
curl -s https://webvh.example/mediator/did.json | jq .
```

---

## Stage 1 — Registry standalone

Proves the binary, storage layer, and HTTP surface with no DIDComm
involved.

This runbook assumes the **fjall** backend: an embedded LSM store,
no external database, state on local disk. See
[storage backends](#storage-backends) for how it differs from the
CSV and DynamoDB paths — the differences affect stages 1 and 2.

```bash
cd affinidi-trust-registry-rs
cp .env.example .env
```

Reduce `.env` to:

```dotenv
TR_STORAGE_BACKEND=fjall
TR_FJALL_PATH=/var/lib/trust-registry/records.fjall
LISTEN_ADDRESS=127.0.0.1:3232
CORS_ALLOWED_ORIGINS=*
AUDIT_LOG_FORMAT=json
```

`TR_FJALL_PATH` defaults to `./trust_records.fjall` — relative to
the working directory, which is rarely what a service unit wants.
Set it explicitly to a durable, writable, **backed-up** location.
Delete the `FILE_STORAGE_PATH` and `DDB_TABLE_NAME` lines inherited
from `.env.example`; they are ignored under fjall and only mislead.

fjall is behind a Cargo feature. It must be on **every** build and
run command from here on:

```bash
ENABLE_DIDCOMM=false RUST_LOG=info \
  cargo run --bin trust-registry --features storage-fjall
```

Omitting it is at least a clean failure — the storage factory
returns *"TR_STORAGE_BACKEND=fjall selected but fjall support was
not compiled; rebuild with --features storage-fjall"* rather than
silently falling back to CSV.

The registry exposes five routes: `/health`, `/recognition`,
`/authorization`, `/trust-tasks`, and `/.well-known/did.json`.
TRQP request bodies are the flattened 4-tuple plus an optional
`context` object:

```bash
curl -s localhost:3232/health          # -> {"status":"OK"}

curl -s -X POST localhost:3232/recognition \
  -H 'content-type: application/json' \
  -d '{"entity_id":"did:example:entity3",
       "authority_id":"did:example:authority3",
       "action":"action3",
       "resource":"resource3"}' | jq .
```

**A fresh fjall store is empty**, so that query returns **404
`Trust record not found`** — and on a new deployment that *is* the
correct answer. There is no import path from `sample-data/data.csv`
into fjall; records arrive only via Trust Tasks, which is stage 3.

**Gate:** `/health` returns `{"status":"OK"}`, the process creates
the directory at `TR_FJALL_PATH`, and `/recognition` returns a
well-formed 404 rather than a 500. A 500 here means the store
could not be opened — check permissions on the parent directory.

If you want the query path proven against real data before
touching DIDComm, run this stage once with
`TR_STORAGE_BACKEND=csv` and `FILE_STORAGE_PATH=./sample-data/data.csv`
(no rebuild required — CSV is in the default feature set). The
`entity3/authority3/action3/resource3` row is the `recognition`
record; `entity1/…` is the `authorization` one. Then switch back
to fjall. The two backends share no state, so nothing carries over.

---

## Stage 2 — Real DID and mediator

Use the provisioning CLI rather than hand-authoring
`PROFILE_CONFIG`.

> **The setup CLI cannot express a fjall configuration.**
> `--storage-backend` carries `value_parser = ["csv", "ddb",
> "redis"]`, so `--storage-backend fjall` is rejected by clap
> before the tool runs. Its storage arguments are therefore a
> throwaway here — run it for the *identity* work and re-apply the
> storage settings afterwards.

```bash
cargo run --bin setup-trust-registry --features dev-tools -- \
  --mediator-did "did:webvh:Qm…:webvh.example:mediator" \
  --did-method webvh \
  --didweb-url https://webvh.example.com \
  --admin-dids "did:peer:2.Vz6Mk…" \
  --storage-backend csv \
  --acl-mode ExplicitDeny \
  --audit-log-format json \
  --non-interactive
```

The tool **rewrites `.env` wholesale**, seeded from
`.env.example` — so it will overwrite the fjall settings from
stage 1 with `TR_STORAGE_BACKEND=csv`. Put them back:

```dotenv
TR_STORAGE_BACKEND=fjall
TR_FJALL_PATH=/var/lib/trust-registry/records.fjall
```

and delete the `FILE_STORAGE_PATH` line it wrote. Re-check this
after *any* future `setup-trust-registry` run; it is not
idempotent with respect to storage.

Points worth knowing:

- `--non-interactive` skips a raw-mode "press any key once the DID
  document is hosted" pause. Without it a non-TTY run hangs.
- `--did-method webvh` writes `did.json` and `did.jsonl` locally.
  **You must host them at `--didweb-url` yourself** — with
  `--non-interactive` nothing waits for you to do so.
- Prefer `webvh` over `peer` if VTA key rotation is ever wanted;
  rotation requires a `did:webvh`.
- The tool rewrites `.env` and `.env.test`, and sets the mediator
  ACL to `ExplicitDeny` for the new DID.
- Export `TR_ADVERTISE_TSP=true` beforehand to add a
  `TSPTransport` service entry to the generated DID document.

```bash
RUST_LOG=info cargo run --bin trust-registry --features storage-fjall
curl -s localhost:3232/.well-known/did.json | jq .
```

**Gate:** the DID document serves locally, resolves at the WebVH
URL, and the logs show the mediator profile added with live
streaming enabled.

### Choosing an ACL mode

`ExplicitDeny` is public — anyone may connect, listed DIDs are
blocked. `ExplicitAllow` is private — only listed DIDs may
connect. Only the exact literal `ExplicitAllow` selects private
mode; **any typo falls back silently to `ExplicitDeny`**. If you
intended a private registry, verify rather than assume.

---

## Stage 3 — Trust Tasks round-trip

```bash
cargo test -p test-trust-registry --features mediator \
  --test mediator -- --ignored
```

The routed tests are `#[ignore]`d by default. Add `--features tsp`
for the TSP-multiplexed variant. This uses an in-process test
mediator, so it exercises the code path without your real one.

These tests use their own in-process storage, not your fjall
store — passing here says the Trust Task path works, not that
fjall persists correctly. Confirm that separately: write a record
via a Trust Task, restart the process, then re-run the stage-1
`/recognition` query. It should now return 200 with the record
rather than 404. That round trip is the only real proof the store
is durable and that `TR_FJALL_PATH` points where you think.

**Gate:** tests green, and a written record survives a restart.

---

## Stage 4 — Move identity to the VTA

Two roles, which may be the same person. Provisioning is done with
the `pnm` CLI; see
[provision-integration](../02-vta/provision-integration.md) for the
general sealed-transfer pattern.

### Build with the feature

Features accumulate — `storage-fjall` must be carried forward
alongside `vta`:

```bash
cargo build --release --bin trust-registry \
  --features "vta,storage-fjall"
```

`vta` is in neither the default build nor the Docker image — the
shipped `docker-compose.yaml` cannot run VTA mode. Containerised
deployments need a custom image, and that image must carry
`storage-fjall` too. Append a secrets backend, e.g.
`--features "vta,storage-fjall,secrets-aws"`, to keep the offline
cache off local disk.

Note that fjall and the VTA offline cache are **separate stores**
with separate paths: `TR_FJALL_PATH` holds trust records,
`TR_SECRETS_DATA_DIR` (default `./.trust-registry`) holds the
cached credential bundle. Both need durable storage; neither is a
backup of the other.

### Registry operator — recipient request

Run **on the machine that will run the registry**; it writes a
secret to `~/.config/pnm/bootstrap-secrets/` that exists nowhere
else.

```bash
export VTA_URL=https://vta.example.com
pnm health

pnm bootstrap request \
  --out tr-request.json \
  --label "trust-registry"
```

`tr-request.json` holds only a public key and nonce. Send it to
the VTA operator out of band; keep the local secret.

### VTA operator — provision the context

```bash
pnm contexts provision \
  --id trust-registry \
  --name "Trust Registry" \
  --server https://webvh.example.com \
  --did-path trust-registry \
  --mediator-service \
  --recipient tr-request.json
```

- `--id trust-registry` becomes `TR_VTA_CONTEXT_ID`.
- `--mediator-service` is **required here** — it adds the mediator
  service endpoint the registry needs to connect over DIDComm.
- `--server` creates the registry's `did:webvh` on that host; use
  `--did-url` when self-hosting.
- `--did-path` fixes the DID's path label on the hosting server, so
  the registry's DID reads
  `did:webvh:<scid>:webvh.example.com:trust-registry` rather than
  whatever label the host would otherwise allocate. Optional, but
  worth setting for a long-lived service other communities will
  recognise by DID. Requires `--server` or `--did-url`. Pass
  `.well-known` to claim the host's reserved root slot.
- `--pre-rotation <N>` pre-generates rotation keys. Decide now;
  retrofitting is harder.

The command emits an armored sealed bundle and a SHA-256 digest.
Send the bundle as a file and the digest over a *different*
channel.

### Registry operator — open the bundle

```bash
sudo mkdir -p /etc/trust-registry

pnm bootstrap open \
  --bundle tr-sealed.txt \
  --expect-digest <sha256-hex> \
  --out /etc/trust-registry/vta-credential.json
```

The digest check is mandatory; there is no trust-on-first-use.
`--no-verify-digest` exists for testing only.

`--out` writes the credential bundle as JSON at `0600`:

```json
{
  "did": "did:key:z6Mk...",
  "privateKeyMultibase": "z...",
  "vtaDid": "did:webvh:...:vta.example.com:...",
  "vtaUrl": "https://vta.example.com"
}
```

> **`--out` is not optional in practice.** Without it, `bootstrap
> open` only inspects the bundle — it prints a payload summary and
> writes nothing. `privateKeyMultibase` is never printed, so the
> credential cannot be recovered from terminal output.
>
> Opening also consumes the single-use bootstrap secret under
> `~/.config/pnm/bootstrap-secrets/`. A second `open` on the same
> file fails. Recovering from a forgotten `--out` means a fresh
> `pnm bootstrap request` **and** a fresh `pnm contexts provision`
> — the whole ceremony, from the top.

Both `AdminCredential` and `ContextProvision` payloads yield a
credential; `pnm contexts provision` produces the latter. Other
payload variants are rejected with a per-variant message.

`--out` requires a `pnm` build that carries the flag. Older builds
reject it at argument parsing and have no file-writing path at
all, so upgrade rather than working around it.

### Configure the registry

Start from `.env.vta.example`. Minimum viable:

```dotenv
ENABLE_DIDCOMM=true
MEDIATOR_DID=did:webvh:Qm…:webvh.example:mediator
TR_VTA_CREDENTIAL=file:///etc/trust-registry/vta-credential.json
TR_VTA_CONTEXT_ID=trust-registry
TR_STORAGE_BACKEND=fjall
TR_FJALL_PATH=/var/lib/trust-registry/records.fjall
LISTEN_ADDRESS=0.0.0.0:3232
ACL_MODE=ExplicitDeny
AUDIT_LOG_FORMAT=json
RUST_LOG=info
```

`.env.vta.example` does not mention storage at all, so the two
fjall lines must be added by hand when starting from that
template.

Four traps, all silent:

1. **Remove `PROFILE_CONFIG`.** VTA takes precedence and it is
   never read; a stale value only misleads later readers.
2. `ENABLE_DIDCOMM` must be exactly `true`. Any other value skips
   the VTA entirely and boots with empty DIDComm config — which
   looks healthy.
3. `TR_VTA_CONTEXT_ID` is mandatory whenever `TR_VTA_CREDENTIAL`
   is set; omitting it is a hard startup error.
4. `TR_VTA_CREDENTIAL` goes through a URI loader in which an
   **unrecognised scheme is treated as a literal string**. A typo
   such as `fille://…` does not error — it tries to parse the path
   itself as JSON.

Valid schemes: `file://`, `aws_secrets://`,
`aws_parameter_store://`, `string://`.

### Offline cache

If the VTA is unreachable at boot the registry falls back to the
last cached bundle. **If the VTA is down and the cache is empty,
startup fails — there is no fallback to `PROFILE_CONFIG`.**

The default cache is the local directory `./.trust-registry`. For
AWS (requires `--features "vta,secrets-aws"`):

```dotenv
TR_SECRETS_AWS_SECRET_NAME=trust-registry/vta-cache
TR_SECRETS_AWS_REGION=ap-southeast-1
```

Boot once while the VTA is up to populate the cache *before*
depending on it.

### Verify

```bash
RUST_LOG=info ./target/release/trust-registry

curl -s localhost:3232/health
curl -s localhost:3232/.well-known/did.json | jq .
```

The logs should show the bundle fetched from the VTA, then
mediator authentication. The VTA bundle *is* the mediator
credential — there is no separate mediator-key step.

**Gate:** stages 1 and 3 pass again under the new identity.

---

## Stage 5 — Point the VTC at the registry

In the VTC's `config.toml`:

```toml
[registry]
url = "https://trust-registry.example.org"
health_probe_interval_seconds = 60
http_timeout_seconds = 5
rtbf_batch_window_hours = 24
```

Deliberately omit `did` for now — see the caveat below.

- `url` unset → registry features no-op and `registry_status`
  reads `degraded`.
- `did` unset → membership hooks are not spawned.
- `degraded_threshold_seconds` appears in
  [trust-registry.md](trust-registry.md) but not in
  `RegistryConfig`. Setting it has no effect.

The health probe is a `GET /.well-known/did.json` against `url`,
so a passing stage 4 means the VTC will report the registry
healthy.

---

## Known defects on this seam

Tracked as **D6** in the networking remediation plan. Both change
how you should read symptoms.

**DIDComm writes are not yet functional.**
`UpstreamRegistryClient::publish_member` and `delete_member`
return `RegistryError::Permanent` unconditionally — the DIDComm
transport is still pending, and `with_atm` is never called. Every
membership sync fails. Because `health()` only issues a `GET
/.well-known/did.json`, **`registry_status` stays green while
nothing syncs.** This is why stage 5 leaves `registry.did` unset:
setting it today buys failing hooks and a misleading indicator.

**The `recognized` field is a two-sided optionality mismatch.**
The registry serialises `recognized` with
`skip_serializing_if = Option::is_none`; the VTC's
`RecognitionResponse` requires it. A 200 response omitting the
field fails to parse, is misclassified as transient, and surfaces
as `RegistryUnreachable` — so cross-community session mint returns
**503 indefinitely instead of a clean 403**. Persistent 503s on
cross-community mint are this, not a network fault. Absence must
be treated restrictively rather than as transport failure.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Boots cleanly, no mediator activity | `ENABLE_DIDCOMM` not exactly `true` |
| Startup fails when VTA unreachable | empty offline cache; no `PROFILE_CONFIG` fallback |
| Parse error on a valid credential file | mistyped URI scheme → treated as a literal |
| Private ACL not enforced | `ACL_MODE` typo → silent `ExplicitDeny` |
| Peers cannot reach the registry | `did:webvh` generated but never hosted |
| VTC green, membership never syncs | DIDComm write defect above |
| Cross-community mint 503s forever | `recognized` mismatch above |
| `bootstrap open` produced no file | `--out` omitted; the bundle is now spent, start over from `bootstrap request` |
| Second `bootstrap open` fails | single-use secret already consumed by the first open |
| Docker image ignores VTA settings | `vta` not compiled into the shipped image |
| Keys still in plaintext `.env` | setup tool writes both, cloud backend or not |
| "fjall support was not compiled" | missing `--features storage-fjall` on this build |
| Registry looks empty after a restart | `TR_FJALL_PATH` relative → resolved against a different working directory |
| Records silently absent, no error | `TR_STORAGE_BACKEND` typo → silent fallback to `csv` |
| Storage config reverted to CSV | a `setup-trust-registry` run rewrote `.env` |
| 500 on every query at first boot | fjall cannot open the store — parent directory permissions |
| Second replica fails or corrupts | fjall is single-writer; only one process per directory |

## Storage backends

`TR_STORAGE_BACKEND` selects the store. Anything unrecognised
falls back to `csv` **silently** — there is no error for a typo,
so `fjal` or `Fjall-db` yields a CSV registry that looks like it
started fine.

| Backend | Value | Extra config | Feature |
|---|---|---|---|
| CSV file | `csv` (default) | `FILE_STORAGE_PATH`, `FILE_STORAGE_UPDATE_INTERVAL_SEC` | built in |
| DynamoDB | `ddb` / `dynamodb` | `DDB_TABLE_NAME`, `AWS_REGION`, `AWS_ENDPOINT` | built in |
| Redis | `redis` | `REDIS_URL` | built in |
| fjall | `fjall` | `TR_FJALL_PATH` | `storage-fjall` |

### Why fjall, and what it costs

fjall is an embedded LSM store: no external database, no network
dependency in the read path, state on local disk. That makes it a
good fit for a single-node registry where DynamoDB is unwanted
operational surface.

The trade-offs are worth stating plainly, because the rest of this
runbook assumes you have accepted them:

- **Single-writer, single-node.** The store is embedded in the
  process. You cannot run two registry replicas over one fjall
  directory, so horizontal scaling and rolling restarts both need
  rethinking. Use DynamoDB if you need more than one instance.
- **Backups are your problem.** No managed snapshots. Back up
  `TR_FJALL_PATH` on whatever schedule your record durability
  requires, and test a restore.
- **The node becomes stateful.** Container deployments need a
  persistent volume mounted at `TR_FJALL_PATH`; the shipped
  `docker-compose.yaml` mounts `./sample-data` for the CSV path
  and has no volume suitable for fjall.
- **No seed-data import.** CSV starts populated from
  `sample-data/data.csv`; fjall starts empty and is filled only by
  Trust Tasks.
- **The feature must be compiled in** on every build, including
  any custom Docker image.

Also note that the CSV backend rewrites its file on an interval
(`FILE_STORAGE_UPDATE_INTERVAL_SEC`, default 60s) while fjall
writes are durable per-operation. Migrating between the two means
replaying Trust Tasks; there is no converter.

## Configuration notes

- The registry has **no config file** — environment variables
  only, loaded from `.env` via `dotenvy`. The TOML in stage 5 is
  the VTC's, not the registry's.
- Identity precedence is **VTA → secret store → `PROFILE_CONFIG`**.
- Backend selection deliberately excludes the OS keyring, so a
  keyring-only configuration silently continues using
  `PROFILE_CONFIG`.

## See also

- [Trust-registry integration](trust-registry.md) — what the VTC
  publishes, membership sync, cross-community recognition.
- [Provision-integration](../02-vta/provision-integration.md) —
  the general DID-template and sealed-transfer flow.
- [VTA secret backends](../02-vta/secret-backends.md) — backend
  choices that also apply to the registry's offline cache.
