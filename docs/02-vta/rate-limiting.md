# Rate limiting

A VTA rate-limits its **unauthenticated** REST endpoints per client IP, and can
bound its Trust Task work with operation budgets: per appliance, per client,
and for DIDComm / TSP senders without standing. This
page covers what is limited, how the limits are keyed and counted, how to set
them in `config.toml` or at setup, how to change them on a running VTA, and how
to tell a VTA 429 from one produced by something else in the path.

## What is limited

There are five limiters. Each keeps its own bucket per client IP, so running
out of one never spends another.

| Limiter (`x-rate-limit-scope`) | Routes | Default |
|---|---|---|
| `auth` | **Anonymous** `POST /trust-tasks` requests other than the two below — `auth/challenge/0.1` and the public Trust Tasks (`vta/attestation/{status,report,config-report}/0.1`) — plus passkey login start/finish and `POST /bootstrap/request`. Authenticated `/trust-tasks` calls stay off every limiter | burst 10, then 1 token every 5 s |
| `auth-authenticate` | Anonymous `POST /trust-tasks` carrying `auth/authenticate/0.2` or `0.3` | same quota as `auth` |
| `auth-refresh` | Anonymous `POST /trust-tasks` carrying `auth/refresh/0.2` | same quota as `auth` |
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

A login is two requests, a challenge and then an authenticate, and they draw
on separate buckets. With one bucket, every token that refilled went to
whichever request arrived first, so behind one busy address (a NAT gateway, an
app host running many agents) new challenges took every token, each
authenticate was refused, and no login finished. Refresh has its own bucket for
the same reason: a host's refreshing sessions and its new logins must not
starve each other. The bucket is chosen from the document's `type`, not the
client-chosen `Trust-Task` header, so labelling challenges as authenticates
does not buy more of them. To choose, the VTA reads an anonymous body — at most
the 64 KiB an anonymous request may carry — before charging it.

The cost of separating them: one address now has three budgets on these steps
instead of one, so at the defaults its anonymous burst is 30 requests — 10
challenges or public tasks, 10 authenticates, 10 refreshes — where it was 10
across all of them. Lower `rate_limit_burst` if that is too generous.

Separately from these per-IP limits, a subject has at most 10 outstanding
challenges (VTI-SES-005). Asking for another evicts the oldest; an expired
challenge does not count. A challenge request is never refused for this, so
the answer does not reveal whether the subject is enrolled (VTI-SES-007).

The public log responses also carry `Cache-Control: public, max-age=60` and a
strong `ETag`, and answer `If-None-Match` with `304 Not Modified`, so a resolver
or proxy that revalidates spends a cheap request rather than a full transfer.

**Not limited per IP:**

- Authenticated (JWT-gated) REST routes, including `POST /trust-tasks`. The
  token is the gate. What bounds them is the operation budgets (below), when
  set.
- DIDComm and TSP traffic. It reaches the VTA through its mediator session, not
  through the REST router. The mediator applies its own limits (below), and the
  operation budgets cover it when set.
- `/health`, `/auth/portal` and `/openapi.json`, which nothing limits.

## Operation budgets: Trust Task work, per appliance and per client

Unset (the default), a VTA serves every Trust Task it is sent. Offered more
than it can serve, it stops answering in time: on a TEE appliance the load
balancer returns 502s, health checks fail, and after five minutes the runtime
watchdog restarts the enclave. Three budgets bound that work instead, so work
past them is refused before it runs and the rest is served at normal latency.
They implement VTI-TRN-029: a node bounds what any one subject can consume, and
bounds unauthenticated peers separately.

| Budget (`x-rate-limit-scope`) | Charged to | Key |
|---|---|---|
| appliance (`operations`) | every client with standing, together | `operation_rate_limit_per_sec`, `operation_rate_limit_burst` |
| per client (`operations-subject`) | each client with standing, by its DID | `operation_rate_limit_per_subject_per_sec` |
| unauthenticated | every DIDComm / TSP sender without standing, together | `operation_rate_limit_unauthenticated_per_sec` |

- **Who has standing.** A REST request with a valid bearer, or a DIDComm / TSP
  sender with an ACL entry. It is charged to its own share first and then to
  the appliance budget, so one busy client is refused before it spends what the
  others share, and the appliance budget still bounds many clients together.
- **Who has none.** A DIDComm / TSP sender without an ACL entry: the login
  steps, public tasks, credential-exchange counterparties, approvers. It is
  charged to the unauthenticated budget only, so strangers never spend the
  clients' budget. Anonymous REST requests are not charged here: the per-IP
  limiters above already bound them, and DIDComm and TSP have no equivalent.
- **Charged after authentication**, before the task runs, on every transport.
  The passkey-VM enrolment routes (`/did/verification-methods/passkey…`) are
  not Trust Tasks and are not charged.
- **The unauthenticated budget is shared.** One sender can use it up and delay
  everyone else without standing — approvers, counterparties, logins over
  DIDComm and TSP — until it refills. Past it a document gets no reply, so a
  flood cannot make the VTA sign a refusal per message; the sender's client
  times out and retries. Refusals to senders without standing (an unsigned
  document, an unknown sender) are charged to it too.
- **A client's share is spent first.** When the appliance budget then refuses,
  the client's share is still spent, so a client retrying against a saturated
  appliance can next be refused for its own share.
- **Weighted by cost.** A task is charged what it costs relative to a sign,
  measured on TEE appliances: a vault release 2, a DID create or delete
  (`vta/webvh/dids/create`, `vta/webvh/dids/delete`) 10, every other task 1.
  The weights are fixed in code (`trust_tasks::operation_budget`) and change
  with a release; the budgets follow the hardware. A task not listed costs 1,
  measured or not.
- **Refusals.** REST answers `429` with `x-rate-limit-source: vta`,
  `x-rate-limit-scope: operations` or `operations-subject` and `Retry-After`,
  and the usual JSON body with the same `limiter`. DIDComm and TSP answer with a
  signed `unavailable` error carrying `retryAfter` (the SDK's retryable
  `VtaError::Unavailable`). A refused task did not run and its `id` was not
  recorded, so resending the same document is a retry.
- **Observability.** Each refusal increments
  `vta_operation_budget_refused_total{scope}`; the VTA logs at most one warning
  a minute per budget while it is refusing.

All values are operations per second, 1 or more; unset means unbounded. The
appliance burst defaults to one second's worth; every burst is at least 10, the
heaviest weight, so any task can be served on an idle appliance.

Unlike the per-IP keys, these are a **rate** (higher is looser), and they are
**not** runtime `config/patch` keys: a patch on a TEE VTA does not survive an
enclave restart. Set them in `config.toml`; a fleet TEE VTA receives them in
its tenant overlay's `server` block, which the parent sends on every boot
(`deploy/nitro/render-tenant-overlay.sh --operation-rate-limit-per-sec …`).

**Sizing.** Load-test the instance you deploy on and set the appliance budget to about
70% of the rate at which its slowest common operation is still healthy (every
request served, p95 within your target), counted in signs: a budget of 100 on
an appliance that signs 140 a second healthily. Where one operation dominates
and costs more than its weight says on that hardware, size from that
operation instead. Set the per-client share from how many clients should be
able to work at once, and the unauthenticated budget from how many logins a
second you expect over DIDComm and TSP.

## Keying: one bucket per client IP

Each request is charged to a client IP chosen by `[server] trust_xff_cidrs` —
the list of reverse proxies that sit in front of this VTA.

- **`trust_xff_cidrs = []` (default)** — the TCP peer address. Spoof-proof, and
  correct whenever clients connect to the VTA directly.
- **`trust_xff_cidrs = ["10.0.0.0/24"]`** — for a request whose peer is inside
  one of these ranges, the VTA reads `X-Forwarded-For`; for any other peer it
  keys on the peer, so a client that reaches the socket directly cannot talk
  its way into someone else's bucket.

The header is read as the chain it is. Each proxy *appends* the address it
accepted the request from, so the entries grow left-to-right from "whatever the
client sent" to "what the nearest proxy saw". The VTA walks that chain from the
**right** and takes the first entry that is not itself in `trust_xff_cidrs`.
With one proxy that is the client; with `ALB → nginx → VTA` it steps over both
declared hops and still finds the client. Anything the client wrote sits
further left and is never reached.

So list **every** hop, not just the nearest one. Listing only the innermost
proxy in a two-hop chain is safe but useless: the walk stops at the outer
proxy's address and every client shares its bucket again.

> **`trust_xff_cidrs` is a claim about your deployment, and a wrong claim is a
> bypass.** Naming a proxy asserts that it rewrites or appends
> `X-Forwarded-For` **and** that nothing else can reach the VTA's socket. A
> layer-4 (TCP) forwarder — socat, a plain NLB stream listener, an SSH tunnel —
> satisfies neither: it passes the client's header through untouched while
> making every request appear to come from itself. Name it here and any client
> can set `X-Forwarded-For` to a fresh value per request and never be limited
> at all. That is strictly worse than the shared bucket you were trying to fix.
>
> Check the proxy, not the topology: an nginx with
> `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` qualifies, an
> AWS ALB qualifies, `socat TCP-LISTEN:…` does not.

> **The proxy trap (why the list exists).** Behind a load balancer with an empty
> `trust_xff_cidrs`, the TCP peer of *every* request is the proxy, so all
> clients share **one** bucket per limiter. Ten logins from anywhere in the
> world then exhaust the `auth` burst for everyone.

Everything uncertain falls back to the peer rather than guessing: a request
with no peer address at all is refused outright, and a malformed or absurdly
long chain is charged to the peer.

`trust_xff_cidrs` is read when the REST router is built: changing it needs a
restart (`POST /vta/restart` or a process restart). The quotas below do not.

> **Upgrading from `trust_xff`.** The old boolean is gone, and a config that
> still sets it **fails to load** rather than being ignored — silently
> reverting to peer keying would reintroduce the shared bucket. Replace
> `trust_xff = true` with the actual proxy addresses
> (`trust_xff_cidrs = ["10.0.0.0/24"]`); replace `trust_xff = false` by
> deleting the line.

### Inside a Nitro enclave

The TEE deployment is the case where this is easiest to get wrong. The enclave
VTA serves REST on vsock itself and accepts only its parent instance (CID 3),
which it reports as the peer `0.0.0.3` — for every client in the world.
`0.0.0.3` is never a valid TCP source address, so no TCP peer and nothing
inside the enclave can present it.

`deploy/nitro/config.toml` therefore ships
`trust_xff_cidrs = ["127.0.0.1/32", "0.0.0.3/32"]`. The VTA reads it for
`0.0.0.3` — the parent and nothing else. The parent's `enclave-proxy` reads the
same key as its own `trusted_upstream_cidrs`, for `127.0.0.1`: a TLS
terminator on the parent's loopback whose header it extends. No TCP peer of
the proxy is ever `0.0.0.3`, and the enclave VTA opens no TCP port, so none of
its peers is ever `127.0.0.1`. Trusting the parent is safe **only** with
`deploy/nitro/enclave-proxy` on the parent: it
terminates HTTP/1.1, strips every client-supplied identity header and sets
`X-Forwarded-For` from the address it accepted the connection from. The
socat-based `parent-proxy.sh` cannot do this, and refuses to start against a
config that sets `trust_xff_cidrs`.

**Upgrading.** Before the VTA served vsock directly, an in-enclave `socat` made
the peer `127.0.0.1` and the configs trusted `127.0.0.1/32` — which anything
else inside the enclave could also have been. A config that still trusts
`127.0.0.1` keeps working: on vsock the VTA binds no TCP, so that entry can only
ever have meant the hop from the parent, and the VTA trusts the parent
(`0.0.0.3`) for it, logging once at boot how to make that explicit. That is
safe because a non-empty `trust_xff_cidrs` implies `enclave-proxy` — the
byte-bridging `parent-proxy.sh` refuses to start while it is set. A non-empty
list naming neither address reads no header (one shared bucket) and is warned
at boot. An empty list trusts nothing and is not warned — it is how a
byte-bridging parent must be configured.

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

The keys live in `[server]`. Omit any of them to take the default.

```toml
[server]
host = "0.0.0.0"
port = 8100
# Every reverse proxy in front of this VTA, innermost or not. Only set this
# for a proxy that rewrites X-Forwarded-For; see "Keying" above.
# trust_xff_cidrs = ["10.0.0.0/24"]

# auth limiter (also sizes auth-authenticate, auth-refresh and backup-blob):
# seconds per token, bucket size
rate_limit_interval_secs = 5
rate_limit_burst = 10

# did-log limiter: seconds per token, bucket size
did_log_rate_limit_interval_secs = 1
did_log_rate_limit_burst = 60

# operation budgets: appliance, per client, and DIDComm/TSP senders without
# standing; operations per second (a rate, unlike the intervals above).
# Unset = unbounded.
# operation_rate_limit_per_sec = 110
# operation_rate_limit_burst = 220
# operation_rate_limit_per_subject_per_sec = 30
# operation_rate_limit_unauthenticated_per_sec = 20
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
| **This VTA** | `x-rate-limit-source: vta`, plus `x-rate-limit-scope: auth` / `auth-authenticate` / `auth-refresh` / `did-log` / `backup-blob` / `operations` / `operations-subject`, `Retry-After`, and a JSON body `{"error":"rate_limited","limiter":"…","message":"…","retryAfterSecs":N}` | as configured above | `[server]` keys / `pnm config update` |
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
- `vta-service/src/trust_tasks/operation_budget.rs` — the operation budgets and
  their weights.
- `vta-service/src/operations/config.rs` — the runtime configuration registry.
- [Mediator connection](mediator-connection.md) — the readiness gate that
  fetches the VTA's own log.
