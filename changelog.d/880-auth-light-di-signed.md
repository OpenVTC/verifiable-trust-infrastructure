### vta-sdk 0.20.29 / vti-common 0.11.31 / vta-service 0.13.21 / vtc-service 0.11.48 / vtc-client 0.2.0 — REST auth signs again, and the VTC accepts it (#880)

Every REST client authenticating through the SDK's lightweight tier was failing
with `authentication failed: {"error":"authentication error: authenticate
message must be an authenticated (authcrypt) DIDComm envelope"}`. Most visibly
the VTC setup wizard, which degraded to "Could not reach the VTA to list
did-hosting servers … the VTA will auto-select one (or self-host)" and skipped
the server/domain picker entirely — so the operator silently lost control of
where the community DID gets published.

`auth_light` packed its `auth/authenticate/0.1` message as an **anoncrypt**
DIDComm envelope (`didcomm_light::pack_auth_message`) and discarded the caller's
private key: the sender was merely *asserted* in a plaintext `from` header. VTI
#771 correctly closed that hole by requiring an authenticated (authcrypt)
envelope on `/auth/` and `/auth/refresh` — which rejects every anoncrypt message,
so the whole tier had been dead since. It surfaced now because the VTC wizard is
the one caller with no fallback; `integration::auth::try_rest` had been quietly
absorbing it by dropping to the heavyweight ATM path.

The fix is the transport the VTA already prefers and tries **first**: a
`auth/authenticate/0.1` Trust Task carrying the holder's `eddsa-jcs-2022`
Data-Integrity proof, where the signature *is* the authentication. No mediator,
no ATM, works against a REST-only VTA, and the key the caller already holds now
proves the sender instead of a header claiming it.

**vta-sdk**

- **New `vta_sdk::auth_di`** (feature `client`): `sign_authenticate_doc`,
  `build_refresh_doc`, `parse_auth_response`. `provision_client::auth_rest`,
  which had the only working copy of this logic, now builds its documents here
  too — the two transports can't drift apart again.
- `challenge_response_light` and `refresh_token_light` keep their signatures;
  callers (`VtaClient` re-auth + auto-refresh, `vtc-client`, the VTC setup
  wizard, `integration::auth::try_rest`) need no change.
- Payloads are built from the **generated spec types** (`authenticate::Payload`,
  `refresh::Payload`) rather than hand-written JSON, so wire casing can't drift
  (R3.1) and the spec's own validation runs client-side — a short challenge is
  now a clear local error instead of a 401.
- Both paths **send the `Trust-Task` URL header**. The VTA ignores it; the VTC
  gates every route on it and answers 400 without it, so its absence made this
  client VTC-incompatible at the transport layer regardless of the body.
- `refresh_token_light` posts an *unsigned* `auth/refresh/0.1` Trust Task: the
  opaque refresh token is the bearer credential (RFC 6749 §10.4).
- Both accept either response shape — the Trust-Task `#response` document or
  flat JSON.
- The server resolves the proof's verification method with a `did:key`-only
  resolver, so **`challenge_response_light` now requires a `did:key` holder**
  and returns `VtaError::Validation` for any other method, refused locally
  before a round trip. Other methods need `session::challenge_response` over
  DIDComm authcrypt — the fallback `integration::auth::try_rest` already takes.
- Conversely the VTA's DID is no longer resolved by the client at all — it is
  just the document's `recipient` — so the `did:webvh` log fetch that preceded
  every login is gone.
- `didcomm_light` is documented as unusable for `/auth/*` and left in place for
  any consumer packing anoncrypt on a non-auth surface.

**vti-common / vta-service** — the Trust-Task DI-proof verifier moves to
`vti_common::auth::di_proof`. It had already drifted into two copies inside the
VTA and a third when the VTC ported it; both services verify the same holder
proof over the same wire shape, so a divergence between them is a divergence in
what a signature *means*. `vta_service::auth::di_proof` is re-exported at its
original path — no VTA call site changes.

**vtc-service** — `POST /auth/` gains the DI-signed Trust-Task login path,
tried after SIOP and before the DIDComm envelope. A body is claimed only when it
parses as a Trust Task, carries the authenticate Type URI, **and** has a `proof`
— the proof requirement is what keeps it from shadowing the SIOP envelope, which
shares that URI. `/auth/refresh` had grown this path already; login had not,
which left a client able to *rotate* a token it had no way to obtain.

**vtc-client 0.2.0** — was broken on **every** route, by three independent
faults that each hid behind the others:

1. `connect` sent the anoncrypt envelope above (fixed by the SDK + the VTC's new
   login path).
2. Nothing sent the mandatory `Trust-Task` header, so every call 400'd before
   reaching a handler. All requests now go through one `tt(...)` helper, with the
   per-route URLs collected in a `task` module that can be read against the
   server's router in one pass.
3. `approve_join` / `reject_join` posted to `/approve` + `/reject` mounts that
   were replaced by a single `/decide` endpoint carrying the decision in the
   body, and `submit_join` posted to a route that is **no longer mounted at all**
   — the holder-facing join verbs moved to the Trust-Task document endpoint.

  Breaking: `reject_join` takes an optional `reason` (the `/decide` body carries
  it). `submit_join` now returns a typed `VtcError::Unsupported` naming the
  endpoint that replaced it, rather than issuing a silent 404 — submitting needs
  the applicant's holder key to sign a Trust Task, which is a different shape
  from this method's signature and is driven today by `vta-cli-common` /
  `vta-mobile-core`.

**Regression cover.** The gap that let all of this accumulate was that no test
ever ran a client and its server together — client tests stubbed the server,
server tests hand-wrote the request. Three suites now close that:
`vta-service/tests/auth_flow.rs` and `vtc-service/tests/auth_di_trust_task.rs`
drive each service's real `/auth/` route with the SDK's own document (login
succeeds; a challenge swapped in after signing is refused 401; an unsigned
document falls through rather than being claimed), and
`vtc-service/tests/vtc_client_live.rs` drives `vtc-client` against a live
`MockVtc`. A builder that drifts from what the route accepts now fails the
build rather than an operator's setup run.
