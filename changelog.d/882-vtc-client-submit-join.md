### vtc-client 0.3.0 — `submit_join` works: signs its own document, needs no token (#882)

`VtcClient::submit_join` posted the VP-framed body to `POST /join-requests`, a
route that is **no longer mounted**. The holder-facing join verbs
(`submit`/`request`, `manifest`, `status`) were folded into the single Trust-Task
document endpoint `POST /trust-tasks`, routed by document `type`, with the
holder's `eddsa-jcs-2022` proof as the authentication. #880 stopped it silently
404ing by returning a typed error naming the replacement; this implements it.

That fold moved the applicant's authentication from "a signature somewhere inside
the body" to "a proof over the whole document" — which is why the signature grew
the key:

```rust
submit_join(&body, applicant_did, private_key_multibase) -> VerdictResponse
```

**Breaking.** The two extra parameters, and the return type: the server answers a
Trust-Task request with a `#response` document carrying a `VerdictResponse`
(`allow` with the VMC + role VEC inline on auto-admit, `refer` when queued for an
admin, `deny`, `requestMore`), which is not the old `DecideResult`.

- **New `VtcClient::anonymous(base_url, vtc_did)`.** `submit_join` authenticates
  with the document's own proof, so an applicant — by definition not yet a member,
  with no token to get — needs a client with no token. Every other method returns
  `NotAuthenticated`, which beats a 401 from the server.
- `applicant_did` must be a `did:key` (the server's proof resolver accepts no
  other method) and is the DID that becomes the member on admission — *not*
  whatever identity the client may hold a token for. A fleet manager submitting on
  behalf of a VTA signs with that VTA's key.
- The document is addressed to the client's `vtc_did`. The VTC enforces
  `recipient == its own DID`, so a submit signed for one community cannot be
  replayed into another.

Built on `vta_sdk::trust_task_sign` (#881) rather than a fourth copy of the
signing logic.

**Testing.** `vtc-service/tests/vtc_client_live.rs` drives the real client
against a live `MockVtc` through all three server-side gates, each of which was a
way to get this wrong: the proof verifies under the `did:key` resolver, the
document `issuer` equals the proven signer (a document signed by one key while
claiming another as issuer is refused), and the submitted request lands in the
admin queue attributed to the *signing* DID rather than anything the body claimed.
