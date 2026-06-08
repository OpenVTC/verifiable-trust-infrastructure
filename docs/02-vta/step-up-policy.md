# Step-up Policy & Delegated AAL2

Operator guide for the VTA's **AAL2 step-up policy** — when (and how) a
session must elevate to a higher assurance level before a gated operation
runs — and for wiring a **delegated approver** (e.g. a holder's phone) that
ratifies those step-ups out-of-band.

Spec: `auth/step-up/policy/0.2`, `auth/step-up/approve-request/0.2`,
`auth/step-up/approve-response/0.2` (in `dtgwg-trust-tasks-tf`).

The policy **ships disabled** — a fresh VTA has no registered approver, so
enforcing a gate that requires one would brick onboarding. You enable it
deliberately, after registering at least one approver.

## Concepts

- **Floor** — a per-operation-class minimum mode. Operation-classes:
  `acl/grant`, `acl/change-role`, `acl/revoke`, `acl/swap-key`,
  `context/delete`, `key/revoke`, or `*` (catch-all).
- **Mode** — `none` (AAL1, no step-up) < `self` < `delegated-any` < `delegated`.
  - `self` — the caller elevates its own session with its own key.
  - `delegated` — a **separate** approver named on the caller's ACL entry
    (`stepUp.approver`) must ratify.
- **Override** — a per-entry `stepUp.require` may only *raise* the floor for
  that subject, never lower it.
- **Carve-out** — `allowAal1IfNonEscalating: true` admits a non-escalating
  self-service request (key rotation / authenticator enrolment) at AAL1 even
  when the floor demands AAL2, so a holder with no authenticator yet can still
  bootstrap.

## Manage the policy (online, `pnm`)

Requires a **super-admin** session.

```bash
# Inspect current posture.
pnm step-up policy show

# Enable from a JSON document (the auth/step-up/policy/0.2 payload shape).
pnm step-up policy set --from policy.json     # or `--from -` to read stdin

# Disable — revert to AAL1 everywhere.
pnm step-up policy disable
```

`policy.json`:

```json
{
  "enabled": true,
  "floors": [
    { "operation": "*", "mode": "self" },
    { "operation": "acl/grant", "mode": "delegated" },
    { "operation": "acl/swap-key", "mode": "self", "allowAal1IfNonEscalating": true }
  ]
}
```

The VTA validates (`unknownOperation` for an unrecognized op-class), refuses a
**self-lockout** (`lockoutRefused` — enabling a `delegated` floor when no ACL
entry carries a `stepUp.approver`), canonicalizes the floors, and returns the
effective policy. The change is applied live and persisted to the config file.

## Set a delegated approver

The approver is the `stepUp.approver` on the **subject's** ACL entry — the VID
the VTA addresses the approve-request to when a `delegated` floor applies.

```bash
# At grant time:
pnm acl create --did <subject-did> --role application \
               --step-up-approver <approver-did>

# Or on an existing entry (empty string clears it):
pnm acl update <subject-did> --step-up-approver <approver-did>
```

## Break-glass (offline, `vta`)

If an over-strict policy locks every remote credential out, recover **locally**
— direct config access, no wire auth, no step-up gate. The daemon must be
stopped (exclusive store lock).

```bash
vta step-up policy show       # alias of `vta step-up show`
vta step-up disable           # the recovery lever — always permitted
vta step-up set-floor --operation acl/grant --mode self
vta step-up enable
```

Offline `vta acl update <did> --step-up-approver <approver-did>` likewise sets
an approver without the wire path.

## Full delegated end-to-end loop

A **requester** at AAL1 hits a `delegated`-gated operation; the VTA delegates
approval to the requester's registered approver (e.g. the iOS holder); the
approver ratifies over DIDComm; the requester's session elevates to AAL2.

1. **Register the approver** on the requester's entry:
   ```bash
   pnm acl create --did <requester-did> --role application \
                  --step-up-approver <ios-holder-did>
   ```
2. **Enable a delegated floor** (now lockout-safe — an approver exists):
   ```bash
   echo '{"enabled":true,"floors":[{"operation":"acl/grant","mode":"delegated"}]}' \
     | pnm step-up policy set --from -
   ```
3. **Approver listens**: the iOS holder authenticates and taps *Listen for
   step-ups* (or stays push-registered). It connects to the VTA's mediator.
4. **Trigger**: the requester (AAL1) performs the gated op (e.g. `pnm acl
   create …` as the requester). The VTA returns a `403` step-up challenge,
   buffers an `auth/step-up/approve-request` to the approver's mediator, and
   (if a wake channel is registered) sends a push.
5. **Ratify**: the iOS holder drains the request and signs an
   `auth/step-up/approve-response` (issuer = the holder, subject = the
   requester). The VTA verifies the gate against the holder's key, confirms the
   holder is the subject's authorized approver, and **elevates the requester's
   session to AAL2**.
6. The requester refreshes its token (`/auth/refresh`) to mint an AAL2 access
   token and retries the operation, which now passes.

> The whole loop runs on canonical DIDs over DIDComm — no bespoke side channel.
> See `docs/05-design-notes/mobile-agent-architecture.md` for the holder side.
