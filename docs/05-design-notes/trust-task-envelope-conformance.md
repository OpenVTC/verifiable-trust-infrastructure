# `proofRequired` on `pnm contexts create` — the envelope-conformance gap

**Status:** root cause identified and fixed. The transport constructors were
fixed in #1184 (released in `vta-sdk` 0.31.1); the deeper restriction — that
only a `did:key` holder could sign a Trust Task at all — is lifted in the
follow-up recorded below. This note carries the diagnosis, the operator-visible
remedy, and the rule that replaced the restriction.

## The report

Against a production VTA, with `pnm` 0.14.0:

```
$ pnm contexts create --id openvtc-gt1 --name "OpenVTC" \
    --admin-did did:key:z6Mko3iZZCNn6LprU7iTEe86LbXfKFqaGigs4e8T9PJYGPAQ \
    --admin-expires 1h
X Protocol error: trust task failed [proofRequired]: proof required but not present
```

The code and message come from the VTA, not the client: it is
`RejectReason::ProofRequired`, raised by `SpecPolicy::enforce` on the dispatch
spine (`vta-service/src/trust_tasks/mod.rs`), rendered by the SDK's
`trust_task_error`.

## Root cause

SPEC §7.2 shipped in two halves that were never checked against each other.

- **The consumer half** (#1146) taught the VTA to enforce the flags a
  specification declares: `recipient` REQUIRED (item 5b), `proof` REQUIRED
  (item 7a), `issuedAt` REQUIRED (§7.3 item 17), and audience binding (item 8).
- **The producer half** (also #1146) taught `VtaClient` to address and sign the
  documents it sends — but only where the client carried a `ClientIdentity`.
  `didcomm_transport` and `tsp_transport` built every client with
  `identity: None`, so `build_task_document` set neither `issuer` nor
  `recipient`, and `signed_task_document` attached no proof.

The guard meant to catch this was gated on `has_token()`, which is false by
construction for DIDComm and TSP — it covered the one transport whose
constructor was already correct.

### Why the message differs by transport

The same defect reports itself under two names, which is why it was diagnosed
twice:

| Transport | Document as sent | First check it fails | Operator sees |
|---|---|---|---|
| DIDComm | no `issuer`, no `recipient`, no `proof` | item 5b | `malformedRequest: … no in-band recipient` |
| TSP | `issuer`/`recipient` back-filled, no `proof` | item 7a | **`proofRequired: proof required but not present`** |

The difference is `address_trust_task`, which the TSP paths call on the
already-built document to set `issuer` and `recipient` from the transport. That
back-fill satisfies item 5b, so a TSP document sails past the recipient check
and lands on the proof check instead. #1184's changelog describes only the
DIDComm spelling; this is the TSP one, and it is the same bug.

### Why it was not caught earlier — and why reads kept working

The proof flag falls almost exactly along read-versus-mutate. In
`trust-tasks-rs` 0.17, of the 344 request payloads:

- **210 declare `proof` REQUIRED** — `vta/contexts/create/1.0` among them.
- **343 declare `recipient` REQUIRED** — `vta/contexts/list/1.0` among those.

So on an affected build the failure is transport-dependent *and*
operation-dependent: over TSP, reads succeed and mutations fail; over DIDComm,
essentially everything fails. A session that listed contexts before creating one
saw a working client right up to the moment it mattered.

## The fix, and what an operator should do now

#1184 makes the identity a required argument of both transport constructors and
turns the guard into an unconditional local error. It is released in **`vta-sdk`
0.31.1** (2026-08-28).

`pnm-cli` 0.14.0 was cut on 2026-08-28 against `vta-sdk` 0.31.0 and **has not
been re-released**, so an installed 0.14.0 binary still carries the defect.
Remedies, in order of preference:

1. Rebuild / reinstall `pnm` against `vta-sdk` ≥ 0.31.1.
2. `pnm --transport rest …` as a stop-gap: `SessionStore::rest_client` builds
   through `VtaClient::authenticated`, which has always carried an identity.

## Same root cause, still live on `main`

Three instances remain. None is a regression from #1184; all are the same shape
— *a client that cannot produce a conforming envelope*.

### 1. `did:webvh` bundle holders cannot sign at all — **fixed**

`VtaClient::connect_didcomm_bundle` and `connect_didcomm_bundle_on` passed
`identity: None` deliberately: the holder is the bundle's `did:webvh`, and
`trust_task_sign` refused any holder that was not a `did:key`, because both
services verified with a `did:key`-only resolver.

The consequence was not a missing member but a missing capability: **a
provisioned integration could not dispatch any of the 210 proof-requiring Trust
Tasks**, over any transport — every mediator, did-hosting daemon and app
provisioned through `provision-integration`.

**The rule is: any DID that can name a key may sign.** The DID method is not
the authorization; resolving the verification method and checking the signature
is. `did:key:z6Mk…#z6Mk…`, `did:webvh:<scid>:example.com:glenn#key-0` and
`did:web:example.com#key-1` are all ordinary holders.

The restriction was never a policy anyone chose. It was the shape of two
helpers:

- **The signer** took `(holder_did, private_key)` and *derived* the
  verification method as `<did>#<multibase>`. That derivation only exists for
  `did:key`, whose key is its identifier. A `did:webvh` document decides what
  its keys are called, so nothing can guess `#key-0` — and a signer that takes
  only a DID therefore cannot serve any method but one.
  `HolderKey` now carries the verification method explicitly;
  `HolderKey::from_did_key` keeps the derivation for the one method that has
  one.
- **The verifier** used `DidKeyResolver`, which refuses everything else.
  `TrustTaskVmResolver` resolves `did:key` locally and every other method
  through the configured DID cache.

`ClientIdentity` gained `verification_method`, and the bundle constructors now
build one from the bundle's own Ed25519 `SecretEntry` — whose `key_id` *is* the
verification method the DID document publishes, so nothing has to be guessed.

#### What this costs, and why it is still right

`did:key` resolves with no I/O. Every other method needs a DID document, which
means network resolution — on the login routes, before the caller is anybody.
That widening is real and is bounded rather than dismissed:

- the `did:key` fast path is checked first, so the common case never touches
  the network;
- resolution goes through the shared `DIDCacheClient`, which caches and carries
  its own timeouts, so a flood of repeats costs one resolution;
- the unauthenticated routes that verify proofs are already behind the
  per-source-IP rate limiter;
- a resolver is optional — `TrustTaskVmResolver::did_key_only()` is exactly the
  previous behaviour, and `verify_trust_task_proof` still means that, so a
  deployment that wants no outbound resolution on an unauthenticated route
  configures it and a caller that wants it says so.

The alternative is that no `did:webvh` holder can ever authenticate, which is
not a security property — it is the absence of a feature the rest of the stack
already assumes.

### 2. `VtaClient::new(url)` + `set_token_async(token)` carries no identity

`set_token_async` sets the bearer token and nothing else, so the classic
"REST client with a token" has `identity: None` and now fails every Trust Task
locally. This is reachable through `AgentConnect`'s `ConnectMode::Token` — the
documented `url + token` rung. `from_credential` and `authenticated` are the
only REST constructors that set an identity.

The local error names the missing piece, so this fails loudly rather than
silently; it is listed because the ladder still advertises the rung.

### 3. `address_trust_task` used to rewrite what the proof covers

Fixed in this change. It assigned `issuer` and `recipient` unconditionally,
after signing. A Data-Integrity proof covers every member but `proof`, so a
disagreement between the document and the transport would have converted a valid
signature into `proofInvalid` at the far end — a failure that names the proof and
says nothing about the rewrite that caused it. The values came from the same
triple, so it was a no-op in practice; "it happens to be equal" was not
something the next constructor had to keep true, and nothing was checking. It
now fills only an absent member and refuses a disagreement.

## The guard

`client_identity_tests::the_built_document_satisfies_its_own_specification`
builds the document the SDK actually sends and runs it through
`schema_index::spec_policy_for(uri).enforce(..)` — the same `SpecPolicy::enforce`
the VTA's dispatch spine calls.

Asserting against the registry rather than a list of member names is the point:
the previous tests checked `issuer`, `recipient` and `proof` by name and passed,
because they were written from the same understanding as the code. When a
specification adds a flag, this test starts checking it without being edited.
