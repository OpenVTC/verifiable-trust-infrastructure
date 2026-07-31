### vta-sdk 0.20.29 / vtc-client 0.1.6 — REST auth signs again: `auth_light` moves to the DI-signed Trust Task (#880)

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

- **New `vta_sdk::auth_di`** (feature `client`): `sign_authenticate_doc`,
  `build_refresh_doc`, `parse_auth_response`. `provision_client::auth_rest`,
  which had the only working copy of this logic, now builds its documents here
  too — the two transports can't drift apart again.
- `challenge_response_light` and `refresh_token_light` keep their signatures;
  callers (`VtaClient` re-auth + auto-refresh, `vtc-client`, the VTC setup
  wizard, `integration::auth::try_rest`) need no change.
- `refresh_token_light` posts an *unsigned* `auth/refresh/0.1` Trust Task: the
  opaque refresh token is the bearer credential (RFC 6749 §10.4), which is what
  the VTA's refresh path verifies.
- Both now accept either response shape — the Trust-Task `#response` document
  the server returns to a Trust-Task request, or flat JSON.
- The VTA resolves the proof's verification method with a `did:key`-only
  resolver, so **`challenge_response_light` now requires a `did:key` holder** and
  returns `VtaError::Validation` for any other method (refused locally, before a
  round trip). Callers holding another DID method need
  `session::challenge_response` over DIDComm authcrypt — the fallback
  `integration::auth::try_rest` already takes.
- Conversely the VTA's DID is no longer resolved by the client at all — it is
  just the document's `recipient` — so the `did:webvh` log fetch that preceded
  every login is gone.
- `didcomm_light` is documented as unusable for `/auth/*` and left in place for
  any consumer packing anoncrypt on a non-auth surface.

**Known gap, unchanged by this PR (`vtc-client` 0.1.6, docs only).** The VTC's
`POST /auth/` accepts a VTA-wallet SIOP envelope or an authcrypt DIDComm
envelope, and has no Trust-Task login path — only its `/auth/refresh` does. So
`VtcClient::connect`, which borrows the VTA SDK's flow, still cannot authenticate
against a live VTC; it has been unable to since #771 rejected the anoncrypt
envelope it used to send, and this change only alters which error comes back.
Documented on the crate root, with `with_token` as the interim route. Giving the
VTC the same DI-signed login path as the VTA is the fix and is not attempted
here.

Regression cover: `vta-service/tests/auth_flow.rs` drives the real `/auth/` route
with the SDK's own document (login succeeds; a challenge swapped after signing is
rejected 401), so a client-side builder that drifts from what the route accepts
fails the build rather than the operator's setup run.
