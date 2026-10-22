# CLAUDE.md — vti-witness

Crate guidance for the witness host service. The workspace `CLAUDE.md`
applies too.

## What this crate is

(The crate's full entry from the workspace `CLAUDE.md` crate map.)

**Witness host service** (`publish = false`): up to 10 witness identities, each a `did:webvh` the operator's VTA mints from the `dtg-witness` template, each on its own mediator session (TSP + DIDComm, one socket per DID). P1 serves `trust-task-discovery` only; `witness/session*` (VWC issuance) is P2. Design: `docs/05-design-notes/witness-host-service.md`; docs: `docs/06-witness/README.md`

## Integration flows

Moved here from the workspace `CLAUDE.md`, which keeps an index of every
flow. Each entry: what it does, the invariants to preserve, code, docs.
When adding a flow, add it here and a line to the root index.

### Witness host service (`vti-witness`)
- **What**: The witness of `witness/session/0.2` / `witness/session/submit/0.2`
  as a **host service**, never a VTA or VTC role: it must be independent of what
  it witnesses, and its DID is public by design, so it is never a node's own
  (VTI-KEY-007). Up to 10 identities per service (an 11th fails config load).
- **Setup**: two-phase and VTA-provisioned like the VTC —
  `vti-witness setup --setup-key-out <path>` (`run_phase1_init`) → `pnm` grant →
  `vti-witness setup --from <toml>`, one `provision-integration` per identity
  with the built-in `dtg-witness` template (Ed25519 auth + assertion, X25519 KA,
  `#tsp` + `#didcomm` at the mediator, **no `VTARest`**). No admin-DID
  hand-off: a witness holds no VTA credential. Keys go to the `[secrets]` store
  (`vti_secrets::create_seed_store`), never `config.toml`.
- **Runtime**: one ATM + one mediator websocket per enabled identity (default
  `enabled = false`), supervised per *Mediator connection* (self-resolution
  gate, jittered capped backoff, `MIN_HEALTHY_SESSION`, `graceful_shutdown` on
  every error path, inbox watch that ends a non-delivering session).
- **Invariants to preserve**: no ACL and no admin surface on the wire; a reply
  is signed by **that identity's own key**, its `issuer` set to that identity
  (never copied from the request), never naming the operator VTA; inbound goes
  through freshness → expiry/`recipient` → issuer consistency → routing →
  spec policy → proof; errors and unclaimed `#response`s are dropped, never
  answered. Discovery lists only what is served: in P1 the witness tasks are
  refused `unsupportedType` and **not** listed — add them to
  `dispatch::SERVED` only when P2 serves them. Shared-mediator / shared-domain
  correlators (§3.6) are **warnings**, never refusals.
- **Code**: `vti-witness/src/{config,dispatch,messaging,setup,run,correlation,keys}.rs`,
  `vta-sdk/templates/dtg-witness.json`, `ProvisionAsk::dtg_witness`. (Not the
  did:webvh log witness: `init witness` stays an alias for `did-host-didcomm`.)
- **Docs**: `docs/06-witness/README.md`,
  `docs/05-design-notes/witness-host-service.md`.
