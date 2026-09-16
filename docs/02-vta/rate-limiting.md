# Rate limiting

A VTA rate-limits its **unauthenticated** REST endpoints per client IP. This
page covers what is limited, how the limits are keyed and counted, how to set
them in `config.toml` or at setup, how to change them on a running VTA, and how
to tell a VTA 429 from one produced by something else in the path.

## What is limited

There are three limiters. Each keeps its own bucket per client IP, so running
out of one never spends another.

| Limiter (`x-rate-limit-scope`) | Routes | Default |
|---|---|---|
| `auth` | `POST /auth/challenge`, `POST /auth/`, `POST /auth/refresh`, passkey login start/finish, `POST /bootstrap/request`, the unauthenticated TEE attestation routes (`/attestation/status`, `/attestation/report`, `/attestation/config-report`) | burst 10, then 1 token every 5 s |
| `did-log` | `GET /.well-known/did.jsonl`, the canonical `GET /<path>/did.jsonl` for a pathful self-hosted DID (and every other unmatched `GET`, which answers 404), `GET /did/{did}/log`, and under TEE `GET /attestation/did-log` | burst 60, then 1 token every 1 s |
| `backup-blob` | `GET` / `POST /backup/blob/{bundle_id}` (token-gated, not JWT-gated) | same quota as `auth` |

The `auth` limiter is tight because those endpoints run cryptography on
caller-supplied bytes. The `did-log` limiter is separate and looser because
serving a `did.jsonl` is a store read with no cryptography — and because
resolving a self-hosted VTA DID is the first step of every client command. A
`pnm` command fetches the log and then runs challenge + authenticate from the
same address; the mediator and the VTA's own readiness gate fetch the log too.
When the log shared the auth budget, a handful of commands in a row returned
429.

The public log responses also carry `Cache-Control: public, max-age=60` and a
strong `ETag`, and answer `If-None-Match` with `304 Not Modified`, so a resolver
or proxy that revalidates spends a cheap request rather than a full transfer.

**Not limited:**

- Authenticated (JWT-gated) REST routes, including `POST /trust-tasks`. The
  token is the gate, and operator traffic against the management plane should
  not be throttled.
- DIDComm and TSP traffic. It reaches the VTA through its mediator session, not
  through the REST router. The mediator applies its own limits (below).
- `/health`, `/auth/portal` and `/openapi.json`.

## Keying: one bucket per client IP

Each request is charged to a client IP chosen by `[server] trust_xff`:

- **`trust_xff = false` (default)** — the TCP peer address. Spoof-proof when
  clients connect to the VTA directly.
- **`trust_xff = true`** — the client address from `X-Forwarded-For` /
  `X-Real-IP` / `Forwarded`, falling back to the peer. Only safe behind a
  reverse proxy that overwrites or strips those headers on every external
  request; otherwise any client can pick its own bucket and evade the limit.

> **The proxy trap.** Behind a load balancer or reverse proxy with
> `trust_xff = false`, the TCP peer of *every* request is the proxy, so every
> client shares **one** bucket per limiter. Ten logins from anywhere in the
> world then exhaust the `auth` burst for everyone. If you run behind a proxy,
> make the proxy set `X-Forwarded-For` from the real peer (discarding any value
> the client sent) and set `trust_xff = true`.

`trust_xff` is read when the REST router is built: changing it needs a restart
(`POST /vta/restart` or a process restart). The quotas below do not.

## Units: an interval is seconds per token, not a rate

Each limiter is a token bucket with two numbers:

- **burst** — how many requests can arrive back-to-back before throttling
  starts (the bucket size);
- **interval** — how many **seconds** it takes to earn back **one** token.

A bigger interval is a *tighter* limit. The interval is not "requests per
second", and reading it that way gets tuning backwards.

Worked examples:

| interval | burst | Meaning |
|---|---|---|
| 5 | 10 | 10 requests at once, then one every 5 s (12/minute sustained). The `auth` default. |
| 1 | 60 | 60 at once, then one per second (60/minute sustained). The `did-log` default. |
| 1 | 30 | A development `auth` setting: bootstrap scripts that fire many auth calls in a row do not stall. |
| 2 | 10 | Tighter than the `auth` default on burst, looser on sustained rate: 10 at once, then 30/minute. |
| 60 | 5 | Very tight: 5 at once, then one a minute. |

A client that has exhausted the burst gets 429 with a `Retry-After` saying how
many whole seconds until its next token (rounded up, never below 1).

Zero is not "unlimited": a `0` in `config.toml` is clamped to `1`. The limiters
cannot be switched off from configuration.

## Setting limits in `config.toml` and at setup

The four keys live in `[server]`. Omit any of them to take the default.

```toml
[server]
host = "0.0.0.0"
port = 8100
# trust_xff = true            # only behind a header-sanitising proxy

# auth limiter (also sizes backup-blob): seconds per token, bucket size
rate_limit_interval_secs = 5
rate_limit_burst = 10

# did-log limiter: seconds per token, bucket size
did_log_rate_limit_interval_secs = 1
did_log_rate_limit_burst = 60
```

The same `[server]` table is accepted by `vta setup --from <file>` (see
[Non-interactive setup](non-interactive-setup.md)), which writes it into the
generated `config.toml`. The interactive `vta setup` writes the defaults.

## Changing limits on a running VTA

The four keys are runtime configuration keys on the canonical
`config/patch/0.1` Trust Task (REST `PATCH /config`), super-admin only. A
change is persisted to `config.toml` and takes effect on the **next request**,
with no restart:

```sh
# Loosen the auth limiter for a provisioning run
pnm config update --rate-limit-interval-secs 1 --rate-limit-burst 30

# Give a busy resolver more room on did.jsonl
pnm config update --did-log-rate-limit-burst 300

# See what is in force
pnm config get
```

| Registry key | `pnm config update` flag | Accepted values |
|---|---|---|
| `rate_limit_interval_secs` | `--rate-limit-interval-secs` | integer 1 – 3600 |
| `rate_limit_burst` | `--rate-limit-burst` | integer 1 – 10000 |
| `did_log_rate_limit_interval_secs` | `--did-log-rate-limit-interval-secs` | integer 1 – 3600 |
| `did_log_rate_limit_burst` | `--did-log-rate-limit-burst` | integer 1 – 10000 |

A value outside its range is reported under `Rejected` and nothing is written.
Over the wire the value is a JSON integer (a string of decimal digits is also
accepted). Every applied change is recorded in the audit log as a
`config.update` row naming each key and its new value (`pnm audit list`).

**Changing a limiter's quota resets that limiter's buckets**: every client
starts again from a full burst at the new quota. A patch that leaves a
limiter's quota unchanged — including a patch of an unrelated key — keeps its
buckets. The runtime bounds apply to the patch only; `config.toml` accepts any
value ≥ 1.

## Recognising who returned a 429

A 429 on the path to a VTA can come from several places. The VTA's own carry a
header that the others do not:

| Source | How to recognise it | Limits | Where to change them |
|---|---|---|---|
| **This VTA** | `x-rate-limit-source: vta`, plus `x-rate-limit-scope: auth` / `did-log` / `backup-blob`, `Retry-After`, and a JSON body `{"error":"rate_limited","limiter":"…","message":"…","retryAfterSecs":N}` | as configured above | `[server]` keys / `pnm config update` |
| **Mediator** (TDK `affinidi-messaging-mediator`) | no `x-rate-limit-source`; appears on the mediator's own host (websocket / inbound HTTP), not the VTA's | per IP: `limits.rate_limit_per_ip` requests per second (default 100), `limits.rate_limit_burst` (default 50); optional per authenticated DID: `limits.did_rate_limit_per_second` (default 0 = off) / `did_rate_limit_burst` | the mediator's `mediator.toml` (`LIMIT_*` env vars) |
| **did-hosting-control** | no `x-rate-limit-source`; on the DID host's `/api/auth/challenge` | 30 requests per 60 s per IP (fixed window) | the did-hosting service |
| **A reverse proxy / CDN / API gateway** | no `x-rate-limit-source`; usually a proxy-branded body or `Server` header | whatever the proxy enforces | the proxy |

If a 429 from a VTA's address lacks `x-rate-limit-source: vta`, it did not come
from the VTA — look at what sits in front of it. `pnm` and `cnm` (through
`vta_sdk::rate_limit`) read these headers and print who refused the request and
which of the settings above to change. If many unrelated clients all
see VTA `auth` 429s at once, suspect the proxy trap above.

## See also

- `vta-service/src/routes/rate_limit.rs` — the limiters and the 429 contract.
- `vta-service/src/operations/config.rs` — the runtime configuration registry.
- [Mediator connection](mediator-connection.md) — the readiness gate that
  fetches the VTA's own log.
