# Auth-architecture consolidation (S1+S2+S3)

**Status**: landed in vti-common 0.7 + vta-sdk 0.7 + did-hosting-common
0.8 + `@openvtc/rp-sdk` 0.1.0. May 2026.

## Problem

Five separate codebases each carried their own implementation of the
`/auth/challenge` → `/auth/authenticate` → `/auth/refresh` flow:

| Service                | Transport(s)        | KeyspaceHandle  | Role enum     |
|------------------------|---------------------|-----------------|---------------|
| `vta-service`          | REST + DIDComm      | `vti-common`    | `vti-common`  |
| `vtc-service`          | REST + DIDComm      | `vti-common`    | `VtcRole`     |
| `did-hosting-control`  | REST (SIOPv2)       | `did-hosting`   | `did-hosting` |
| `did-hosting-server`   | DIDComm             | `did-hosting`   | `did-hosting` |
| `did-hosting-witness`        | DIDComm             | `did-hosting`   | `did-hosting` |

The flow logic was 90% identical across all five. The 10% that
differed (TEE attestation on VTA, SIOPv2 id_token verification on
did-hosting-control, per-DID rate-limit shape, JWT minter) had
drifted in subtle, security-relevant ways. The May 2026 cross-system
security review surfaced:

- VTA + VTC had no per-DID challenge rate limit; did-hosting-server +
  did-hosting-witness had one but used an O(N) prefix-scan; did-hosting-control
  had an O(1) tracker.
- `session_pubkey_b58btc` support existed only on did-hosting-control;
  server + witness silently ignored the field.
- AAL preservation across refresh was added in three places by hand
  instead of once at the trait layer.
- VTC's refresh response shape lagged behind the canonical
  `{ session, tokens }` from the SIOPv2 spec.

The structural fix is one canonical implementation that all five
services dispatch to. Per-service variation lives in a thin
`AuthBackend` impl, not in copy-pasted route handlers.

## Trait shape

```rust
#[async_trait]
pub trait AuthBackend: Send + Sync + 'static {
    type Store: SessionStore;
    type Error: From<AuthError> + Debug + Send + Sync + 'static;
    type Role: std::fmt::Display + Serialize + Clone + ...;

    fn sessions(&self) -> &Self::Store;

    async fn mint_access_token(
        &self, subject: &str, session_id: &str, role: &Self::Role,
        contexts: &[String], amr: &[String], acr: &str,
        tee_attested: bool, ttl_secs: u64,
    ) -> Result<String, Self::Error>;

    async fn check_acl(&self, did: &str)
        -> Result<RoleResolution<Self::Role>, Self::Error>;

    // Default-method policy hooks — backends override only when needed.
    async fn validate_did(&self, _did: &str) -> Result<(), Self::Error> { Ok(()) }
    async fn attest_challenge(&self, _: &[u8; 32]) -> Result<AttestationOutcome, Self::Error> { ... }
    fn max_pending_challenges_per_did(&self) -> usize { 10 }
    fn audit(&self, event: AuthAuditEvent<'_>) { /* tracing::info!(audit=true, ...) */ }

    fn challenge_ttl(&self) -> u64;
    fn access_token_ttl(&self) -> u64;
    fn access_token_ttl_for_aal2(&self) -> u64 { max(60, self.access_token_ttl() / 3) }
    fn refresh_token_ttl(&self) -> u64;
    fn didcomm_freshness_window(&self) -> u64 { 60 }
}
```

### Associated types over generic params

`type Store`, `type Error`, `type Role` rather than `<S, E, R>`
generic parameters on every handler call. Each backend has
*exactly one* concrete impl; nobody wants `handle_challenge::<KeyspaceSessionStore,
AppError, Role>(backend, input)` at every call site. The
trade-off is that you can't have two `AuthBackend` impls with
the same `Self::Store` but different `Self::Error` for one
service — which would be nonsensical anyway.

### Why `Error: From<AuthError>` instead of returning `AuthError` directly

The canonical handler raises typed `AuthError` variants
(`Forbidden`, `ChallengeMismatch`, `SignerMismatch`, etc.). Each
backend's local error type (`vti_common::error::AppError`,
`did_hosting_common::server::error::AppError`) converts via
`From<AuthError>` so the route layer's existing `IntoResponse`
plumbing renders the response — no backend-specific glue.

A backend that wants to log or instrument the typed variant
before conversion can implement a richer `From<AuthError>`. The
default conversion maps each variant to the standard HTTP
status (Forbidden → 403, ChallengeMismatch → 401, etc.) plus
the canonical body shape.

## `SessionStore` trait

```rust
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    type Error: Debug + Send + Sync + 'static;
    async fn store_session(&self, s: &Session) -> Result<(), Self::Error>;
    async fn get_session(&self, id: &str) -> Result<Option<Session>, Self::Error>;
    async fn delete_session(&self, id: &str) -> Result<(), Self::Error>;
    async fn store_refresh_index(&self, token: &str, sid: &str) -> Result<(), Self::Error>;
    async fn take_session_id_by_refresh(&self, token: &str) -> Result<Option<String>, Self::Error>;
    async fn count_pending_challenges(&self, did: &str) -> Result<usize, Self::Error>;
}
```

Two impls ship in the workspace:

- `vti_common::auth::handlers::KeyspaceSessionStore` — wraps
  `vti_common::store::KeyspaceHandle` (enum dispatch: local
  fjall, vsock-proxied). VTA + VTC use it directly.
- `did_hosting_common::server::auth::DidHostingSessionStore` —
  wraps did-hosting's `KeyspaceHandle` struct (separate trait
  with fjall / Redis / DynamoDB / Firestore / Cosmos DB
  backends). did-hosting-control + server + did-hosting-witness use it.

A future Redis-backed direct impl could ship here when the
canonical handler runs in a cloud deployment; the trait
boundary keeps the canonical flow agnostic.

### `take_session_id_by_refresh` — atomic GETDEL semantics

The classic Redis-`GETDEL` shape. Exactly one concurrent caller
observes `Some` for any given refresh token; the cross-replica
race is closed at the storage layer.

- `vti_common::store::KeyspaceHandle::take_raw` runs `get + remove`
  inside a single `blocking_with_timeout` closure on `LocalKeyspaceHandle`
  (single-process fjall serialises per-keyspace). On `Vsock` it falls
  back to two RPCs with a per-call `warn!()` and a doc note — single-
  replica TEE deployments are unaffected; cross-replica vsock would
  need a new opcode.
- did-hosting's `KeyspaceHandle::take_raw_atomic` delegates to the
  backend trait, which has primitives for each cloud store's atomic
  GETDEL equivalent.

## Canonical flows

### `/auth/challenge`

1. `validate_did` (backend hook; default no-op).
2. `check_acl` (raises `Forbidden` on miss / expired).
3. Per-DID rate limit (`count_pending_challenges` vs.
   `max_pending_challenges_per_did`).
4. Mint 32-byte hex challenge from OS RNG.
5. Optional `attest_challenge` (backend hook; default not-
   attested).
6. Persist `ChallengeSent` session with `tee_attested` from
   step 5 and empty `amr`/`acr`.
7. Emit `ChallengeIssued` audit event.
8. Return canonical `ChallengeResponse`.

### `/auth/`

Transport-specific layer (REST JSON parse / DIDComm
`unpack_signed` / SIOPv2 JWS verify) produces an
`AuthenticateInput { session_id, challenge, signer_did,
created_time?, session_pubkey_b58btc? }`. The canonical handler:

1. Load session by `session_id`; reject if missing or already
   `Authenticated`.
2. Constant-time challenge match.
3. `signer_did == session.did` (load-bearing — without this any
   leaked challenge could be redeemed by any signer).
4. Challenge TTL + DIDComm `created_time` freshness window.
5. Re-look-up ACL role (propagates revocation between issue and
   use).
6. `mint_access_token` (backend hook). TTL = `access_token_ttl_for_aal2`
   if `acr == "aal2"`, else `access_token_ttl`.
7. Transition session → `Authenticated`, persist
   `(amr, acr, refresh_token, refresh_expires_at,
   session_pubkey_b58btc?)`.
8. Emit `Authenticated` audit event.
9. Return canonical `AuthenticateResponse { session, tokens }`.

### `/auth/refresh`

1. **Atomic claim** of the `refresh_token → session_id` index via
   `take_session_id_by_refresh`. Exactly one caller proceeds per
   token, cross-replica safe. A token that is *not* in the index
   diverts to the reuse-detection path below.
2. Load session.
3. (DIDComm transports) `signer_did == session.did` binding.
4. State check (`Authenticated`).
5. Refresh-token expiry check.
6. **Preserve `(amr, acr)`** from the pre-rotation session. A
   step-upped `aal2` session stays at `aal2` across rotation
   instead of dropping to `aal1`.
7. Delete old session.
8. Re-look-up ACL role.
9. Mint new session (new `session_id`, access token, refresh
   token; AAL preserved; TTL acr-dependent).
10. **Tombstone the spent token** (`store_refresh_tombstone`),
    ordered after the replacement index is durable. A write
    failure is logged, not returned: the rotation is already
    committed, and failing the request would withhold the only
    live token from its owner.
11. Emit `Refreshed` audit event.
12. Return canonical `AuthenticateResponse`.

### Refresh-token reuse detection

Rotation alone makes a stolen refresh token worth exactly one
access token, but it says nothing about the theft. Deleting the
live index leaves a replayed token and a token this node never
issued looking identical — both simply absent — so the clearest
sign of compromise, a token presented after it was spent, arrives
as an ordinary 401.

Every rotation therefore writes a `RefreshTombstone` at
`rotated:{sha256(token)}`:

```rust
struct RefreshTombstone {
    session_id: String,
    did: String,            // so the alert can name the account
    rotated_at: u64,
    expires_at: u64,      // rotated_at + refresh_token_ttl
    successor_hash: String, // sha256 of the token that replaced it
    cause: TombstoneCause,  // Rotated | Superseded
}
```

No bearer secret is stored: the tombstoned token is the *key*
(hashed), and its successor is recorded as a hash.

A token that misses the live index is looked up here. No
tombstone ⇒ plain rejection, no alert — nothing to attribute.
A tombstone ⇒ this node issued the token and already spent it,
which is either theft or one specific non-attack.

**The lenient concession.** A client whose rotation response is
lost in flight still holds only the old token, and retrying with
it is correct behaviour. Strict detection would read that retry
as theft and sign the user out — so the common network fault
would raise the alarm while a patient attacker would not. A
replay is treated as an innocent retry only when *all* of:

- the tombstone's cause is `Rotated`, never `Superseded` (below);
- the session is alive and `Authenticated`;
- `now - rotated_at < refresh_reuse_grace()` (default 30s,
  strictly inside, so `0` disables the concession entirely);
- the tombstone's `successor_hash` is **still** the session's
  live refresh token.

30s is a starting point, not a ceiling. A client only discovers a
lost response when its own HTTP timeout fires, and 30s is a common
default — so a deployment whose clients retry later than that may
see legitimate retries land just outside the window and be signed
out. Raising this to 60s is the intended adjustment if that shows
up in practice; it is a user-experience call rather than a
security one, because the successor condition below, not the
clock, is what keeps the concession narrow.

The successor condition is what keeps this narrow: it holds only
while the successor has never been used, which is exactly the
situation of a client that never received it. Once anyone spends
the successor the window shuts early, so a stolen token replayed
seconds after a legitimate refresh is still caught.

An innocent retry re-serves the *same* pair, with the access
token re-minted against the session's existing `token_id` — so
the lost copy and this one are the same token as far as the `jti`
pin is concerned, nothing rotates, and the reported
`refresh_expires_in` is the time actually left rather than a
fresh TTL. It still issues an access token, so it emits
`Refreshed` like any refresh (VTI-SES-041).

This conforms with VTI-SES-030 (exactly one concurrent claimant
succeeds). The claim is still the atomic take of the live index; a
caller racing it misses the index before the tombstone exists and
is refused. Only a caller arriving *after* the claim completed is
answered, and it gets that claim's own result — no second session
and no second refresh token, which is what the requirement's
rationale rules out.

**The residual race, stated plainly.** While the window is open
*and* the successor is unspent, a party replaying a stolen token
receives that same successor. Leniency buys tolerance of a
routine network fault at the cost of a ≤30s race that also
requires the attacker to beat the legitimate client to the
replacement. It is a deliberate trade, not an oversight, and it
is the reason the window is both short and conditional on the
successor being untouched. Deployments that would rather sign a
user out than concede the race set:

```toml
[auth]
refresh_reuse_grace = 0
```

which makes every replay of a rotated token a compromise signal.
Note the cost of that setting: each dropped connection then logs
its user out and reports a compromise, so the alarm fires for the
routine fault while an attacker who waits out any window never
trips it either way.

**A token retired by a newer login** is refused and audited as
`AuthAuditEvent::RefreshSuperseded` (`warn!`, `security_alert =
true`), and the session is **left running**. The retired token is
already dead — the login took its index entry — so revoking adds
nothing against a thief, while the ordinary cause is a second
device presenting what it was issued before the user signed in
elsewhere. Killing the session there would sign out the client
that is demonstrably live, and the re-login it forces would set
the same trap again.

**Anything else is reuse**: the session is deleted (which takes
its live refresh index down with it, killing every descendant of
the replayed token), and `AuthAuditEvent::RefreshReuseDetected`
fires with a `RefreshReuseReason` of `GraceExpired`,
`ChainAdvanced`, or `SessionGone`. The default `audit` impl emits
it at `error!` with `security_alert = true`.

### A fresh login retires the previous token

Rotation and detection between them only catch a token that is
presented *twice*. `/auth/` is keyed per DID and overwrites
`session:{did}`, but the reverse index is a separate
`refresh:{hash}` row per token, and `/auth/refresh` authorises
from that index alone — it never consults `session.refresh_token`.

So a login that merely added its new index row left the previous
one live: two working chains on one account that never shared a
token, therefore never replayed, therefore never detected. A
token stolen before a re-login kept working indefinitely and
silently, which is the impact paragraph of the original finding.
It also defeated the one recovery step available to a user
unaided — logging in again did nothing to the thief's token.

`handle_authenticate` therefore retires the outgoing token before
returning: it reads the prior session's `refresh_token` *before*
`store_session` overwrites the row, removes that token's index
entry by claim-and-delete (atomic, so two racing logins cannot
both retire it), and leaves a `Superseded` tombstone. Ordered
after the new chain is durable, as on the rotation path — a crash
in between leaves the old token live, which is merely the former
behaviour, rather than leaving the account with no usable token.

`Superseded` is a distinct cause because the grace window must
**not** apply to it. The concession answers a lost rotation
response; a client that has just logged in holds its new token and
has no reason to present the old one. Were the concession allowed
here, whoever replayed a token stolen before the re-login would be
handed the token that replaced it — strictly worse than the gap
being closed.

One consequence to be aware of: a stale second device now surfaces.
Under coalesce-per-DID that device was already signed out (its
access token is superseded by the `token_id` pin), and its next
refresh attempt is now refused rather than silently rotating into
a parallel chain. It raises `RefreshSuperseded` but does **not**
revoke the newer session — the node cannot distinguish a forgotten
device from a thief, and of the two readings only one is worth
acting on automatically: the retired token has already stopped
working either way, so revoking would penalise the current client
for the stale one's request and the forced re-login would recreate
the same situation. Re-authentication remains the recovery path
for the device; the audit event is the operator's signal.

**Only the current token refreshes.** Retirement at login is not
enough on its own. The login reads the outgoing token from the row
before overwriting it, and a refresh racing that read can spend
the token and write its successor's index entry *after* the login
has chosen what to retire — leaving exactly the parallel chain this
section exists to close. So `/auth/refresh` also refuses a claimed
token unless it is the one the session currently issues, and treats
it as superseded: tombstoned, `RefreshSuperseded`, session left
running. Whichever of the two racing writes lands last is current;
the other chain dies at its next refresh. One live chain per session
then holds by construction rather than by cleanup, and a login's
own claim-and-delete matters only for attribution. For that reason
the login writes its `Superseded` tombstone **only when its claim
wins**: a lost claim means a refresh already spent the token and
tombstoned it `Rotated`, and relabelling it would downgrade a
genuine-reuse replay to a non-revoking alert.

Currency is **not** read from `session.refresh_token`. Several
writers read-modify-write the session row without atomicity —
`resolve_did_session` on every DIDComm/TSP message, `touch_last_seen`,
step-up's `update_session` — and each writes back whatever
`refresh_token` it read. A rotation landing between such a read
and write is reverted in the row, and a check against the row would
refuse (and a sweep would delete) the token the client actually
holds. `store_refresh_index` therefore records the current token's
hash under its own key, `refresh-current:{session_id}`, which no
other writer touches; it writes that record before the index entry,
so an entry that exists was current when written and only a newer
issuance can move the record off it. Sessions issued before the
record existed fall back to the row, which is the best evidence
they have.

**Sweeping the index.** `refresh:` rows carry no TTL.
`cleanup_expired_sessions` drops any entry whose session row is gone
or whose token is not current, by the same record and fallback, and
drops `refresh-current:` records whose session row is gone. This is
hygiene: refresh already refuses those entries.

Both outcomes return the same `RefreshTokenInvalid` a stranger's
token gets. Reporting detection to the caller would tell an
attacker precisely when to stop; the party that needs to know is
the operator, who learns it from the audit event.

**Retention.** Tombstones are reaped purely on time by
`cleanup_expired_sessions`, at `rotated_at + refresh_token_ttl` —
the window in which the token could still be replayed; past it
the token is refused on expiry grounds anyway. They are
deliberately *not* removed when their session dies: replay after
a revocation is the case most worth catching, and sweeping them
alongside the session would blind exactly that. Cost is ~120 B
per rotation, so ~12 KB/session/day at a 15-minute refresh
cadence.

**Degradation.** `store_refresh_tombstone` / `get_refresh_tombstone`
are `SessionStore` methods with no-op defaults, so an out-of-tree
store (did-hosting) adopts this release unchanged and keeps
exactly the pre-detection behaviour: replay refused, just not
attributed. `KeyspaceSessionStore` overrides both, so VTA and VTC
get detection.

## What stays out of the trait

- **Transport** (REST vs. DIDComm) — the canonical handler takes
  the pre-extracted `*Input` struct; transport-specific
  unpacking stays in the route handler.
- **id_token-internal checks** (SIOPv2 `aud`, `iat`, `exp`) —
  these are properties of the SIOPv2 token, not the
  challenge-response session. did-hosting-control's route
  handler runs them before dispatching to the canonical
  handler.
- **Wire-shape serialisation** — canonical request / response
  types live in `vta_sdk::protocols::auth` and are shared with
  clients.
- **The `StepUpAuth` extractor** — separate from the canonical
  handler; runs on every gated route the handler doesn't own.

## Cross-repo dependency

did-hosting's repo doesn't currently consume vti-common from
crates.io. During the consolidation window, did-hosting-common
and its consumers pin `vti-common` and `vta-sdk` by git rev
(same rev for both, kept in lock-step). When this PR merges and
vti-common 0.7 + vta-sdk 0.7 publish, the git deps flip to
`version = "0.7"`.

A standalone follow-up PR makes that flip — it's a five-line
Cargo.toml change in each of `did-hosting-common`,
`did-hosting-control`, `did-hosting-server`, `did-hosting-witness`,
and the workspace root.

## Security review follow-ups closed by the consolidation

| ID  | Item                                                  | How                                                   |
|-----|-------------------------------------------------------|-------------------------------------------------------|
| H3  | server/witness O(N) rate-limit scan                   | canonical handler uses O(1) backend count             |
| H4  | VTA/VTC missing per-DID rate limit                    | canonical handler enforces it everywhere              |
| H5  | `allowed_did_methods` error leak                      | canonical `Forbidden` swallows the configured list    |
| L3  | `session_pubkey_b58btc` only on did-hosting-control   | now threaded through `AuthenticateInput` everywhere   |
| M3  | DIDComm freshness window not enforced on VTA/VTC      | `msg.created_time` now threaded into `AuthenticateInput` |

Each of H1/M1/M2/M4/M5/M6/L1/L2/L4 land as point-fixes in
focused commits. See the CHANGELOG `Unreleased` block for
per-item commit pointers.

## Open follow-ups

- **vti-common 0.7 + vta-sdk 0.7 publish to crates.io.** Once
  this PR merges, two `cargo publish` runs from main.
- **did-hosting flip to crates.io deps.** Five-line follow-up
  PR in the did-hosting repo.
- **H1 operator-visible flow** — settings toggle, first-enroll
  passkey ceremony, migration UX for existing plaintext
  wallets, lock/unlock surfaced from the popup. Infrastructure
  is in (`SecretWrap` trait + `WebAuthnPrfSecretWrap` impl);
  not yet auto-enabled in `holder.ts`.
- **L5 — workspace lint for trust-task `recipient` enforcement.**
  Tooling-heavy; needs its own design pass.
