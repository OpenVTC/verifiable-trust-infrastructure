# Demo plan: an agent connects to a person's context over HCP, and is revoked

**Status:** plan; the demo week starts on 2026-11-26 (Day 1), with the demo on
Day 7.
**Companion to:** [hcp.md](../docs/05-design-notes/hcp.md) (the design),
[hcp-plan.md](../docs/05-design-notes/hcp-plan.md) (V0 is this demo) and
[hcp-tasks.md](../docs/05-design-notes/hcp-tasks.md) (the VTI checklist). The
Keyring side, its screens and copy, is in the Keyring companion plan
(keyring-wallet, `docs/plans/agent-connect-plan/2026-11-25-bam.md`).
**Owner:** Brendan Miller, Alberto Leon
**Last updated:** 2026-11-25

## Demo narrative

A person's AI agent asks for access to their context. The person sees exactly
what it is asking for on their phone, in Keyring, and approves it for four
hours. The agent answers from what the VTA holds about them. The person tells
Keyring something new, and the agent's next answer uses it. Then the person
revokes the agent: Keyring shows the agent being told, then when it was told;
the agent prints the notice, forgets what it held, and its next request is
refused.

The demo is `agent-connect-p0-hcp`: Keyring's P0 tier with its HCP increment
and VTI's milestone V0. It runs from a branch on a fork, against the
unpublished `hcp/*` suite as frozen at X0; nothing merges to `main`.

---

## What already exists (reuse, do not rebuild)

**VTA (`vta-service`)**
- Someone-else-approves: `task-consent/request` and `decision`, bound to a
  salted digest of the payload, single-use, pushed to the approver
  (`trust_tasks/task_consent.rs`, `trust_tasks/consent_request.rs`), with a
  producer for a request the policy engine did not raise
  (`operations/vault/oob_sign_in.rs`, `remote_approval`).
- Outbound push to a party with no ACL entry, re-signed when a retry would
  fall outside the acceptance window (`vti-common/src/trust_task_push.rs`,
  `PushReissuer`); A5 makes the notice a fresh document on every attempt.
- The counterparty admission pattern for a sender with no ACL entry
  (`messaging/auth.rs`).
- The chained audit sink and its censuses.

**Keyring**
- Receives a `task-consent/request` live while the app is open, checks it,
  gates the decision on the owner's biometric or passcode and signs
  `task-consent/decision`. The VTA accepts that proof only for
  `assertionMethod`, so the admin DID must carry an `assertionMethod` key.

**openvti-starter**
- MODE=tunnel: an HTTPS `did:webvh` VTA and a mediator with DIDComm and TSP,
  each behind a quick tunnel with no account needed.
- The mediator session and TSP client patterns the agent client's receive
  loop reuses.

## The delta

There is no HCP code in VTI, the agent client does not exist yet, and Keyring
has no HCP screens. The work is [hcp-plan.md](../docs/05-design-notes/hcp-plan.md)
§3.1–3.3: the VTI tasks A1–A6, A8 and A9, the agent client B1–B4 and B6, the
Keyring screens C0–C3 and C6–C8, and the environment D1–D4.

## The environment, in portable terms

Read the diagram as two devices reaching one stack through public tunnels:
the phone never talks to the agent, and everything either of them sends goes
through the mediator to the VTA.

```text
  phone: Keyring (flag on)                     laptop: agent client (CLI)
        | wss (mediator), https (VTA)                | TSP over the mediator mailbox
        v                                            v
  +-------------------------- public quick tunnels (new names every run) -----------------+
  +----------------+------------------------------------+---------------------------------+
                   |                                    |
  +----------------v----------------+   +---------------v---------------------------------+
  | VTA: image from the VTI branch, |   | mediator: DIDComm and TSP, holds the client's   |
  | `hcp` added to its features     |<->| mailbox; the phone's live socket                |
  +---------------------------------+   +-------------------------------------------------+
         openvti-starter, MODE=tunnel, demo variant; hcp_* keyspaces reset before each run
```

- **Why MODE=tunnel.** MODE=local binds loopback only, uses `localhost` DIDs,
  which a phone cannot resolve over plain HTTP, and runs no mediator, so
  neither the phone nor the agent client's notice can reach it.
- **The phone leg of MODE=tunnel has not been tested before this week.** The
  tunnels get new hostnames and DIDs on every run, so Keyring is re-linked
  after each restart, and the mediator may need its CORS origin set for the
  phone's WebSocket.
- **Foreground only.** Keyring is not woken in the background, so the app is
  open and in the foreground at approval, and it polls
  `hcp/disclosures/summary` for the notice state.
- **The VTI baseline is the `3ee07a12` pin** (vta-service 0.83.0,
  openvti-starter's current VTA pin) or a later `main`, which contains it.
  It has the consent push's delivery receipts and the mediator-wake fallback;
  keyring-wallet's own VTI pin, `f7b78e29d`, has neither. If X0 has to fall
  back from `main`, it falls back to `3ee07a12`, never to `f7b78e29d`. Whether
  the starter's pinned mediator serves the wake task is not verified, so the
  demo relies on Keyring in the foreground (or a `DeviceBinding` wake), not on
  the mediator wake.
- **The image** is built through openvti-starter's tooling from the VTI branch
  ref, with `hcp` added to the image's features, tagged `vta:<ref8>` and
  `vta:<version>-<ref8>` (never `:local` or `latest`), and not pushed to a
  registry. `pins.json` changes only through the tooling, and the main pin is
  untouched. Do not run openvti-starter's cleanup with `--apply` until after
  the demo: it keeps only the main pin's tags and would remove the demo image.
- **An environment file** (DIDs, endpoints, image tags) is written by D3 and
  read by the agent client and the Keyring build.
- **Purposes** are the DTG registry's draft IRIs, `task-execution/1` and
  `personalisation/1` under `https://registry.trustoverip.org/dtg/purpose/`,
  read from configuration.

## The script

1. **Reset.** Start the stack; reset the `hcp_*` keyspaces; seed the person's
   context. Link Keyring to this run's VTA; keep the app in the foreground.
2. **The agent asks.** The CLI shows a QR (its VID, a `threadId`, the VTA's
   DID) and a four-digit number.
3. **The person checks.** Keyring scans the QR; the person types the number.
4. **The person approves.** Keyring shows the checklist: the categories and
   what they mean, the actions, the purposes by their descriptions, "For 4
   hours", how long a copy may be used, the agent and who operates it. The
   person approves with a biometric.
5. **The agent answers from context.** The CLI resubmits, receives its grant,
   asks a question and answers from the retrieved entries, printing each
   entry's purpose and `useUntil`.
6. **The person adds a memory.** In Keyring: "I'm vegetarian"
   (`hcp/entries/create`, `person-declared`).
7. **The next answer uses it.** The CLI asks for a dinner suggestion; the
   answer is vegetarian and cites the new entry.
8. **The person revokes.** Keyring shows "Telling…", then "was told at
   <time>".
9. **The agent is told.** The CLI prints the notice, purges what it held and
   stops; its next query, with the old token, is refused.

"What my agent saw" and "Answers on" are not in this script; they moved to P1
with the work behind them.

## Week plan

| Day | VTI | Agent client, Keyring, environment | Gate at the end of the day |
|---|---|---|---|
| 1 (2026-11-26) | X0 freeze, X0b skeleton, A1 | B1; C0; D1 dry run of an image from `main` to expose drift | Suite frozen; skeleton builds with and without `hcp` |
| 2 | A2, with the trait and `StubHcp` frozen by evening; A8 on the stub | B2 and C1 against the fakes | Trait frozen |
| 3 | A3 live; A4, A6 | B2 and C1 switch to the VTA; phone-leg smoke test on MODE=tunnel | A held request approved from the phone |
| 4 | A5; A9 transcript | B3, B4; C2, C3, C6; image from the A5 ref (D1, D2); lab stack (D3) | Fakes regenerated from A9's transcript |
| 5 | A9 green; X4 gate and review | B6, C7; the first full run | The script passes once end to end |
| 6 | Fixes | On-device tests on one iPhone and one Android; rehearsal 1; D4 runbook | Rehearsal passes |
| 7 | — | Rehearsal 2; the demo | — |

## Go / no-go

**Before the demo day: all must hold.**
- The script has passed end to end on the tunnelled lab twice, on the image
  built from the branch ref that will be shown.
- The phone-leg smoke test passed: Keyring linked to the tunnelled VTA and
  received one `task-consent/request` live, with the mediator's CORS origin
  set if it was refused.
- The image's `pins:verify` passed.
- A9 is green; the X4 gate is green, with known false failures recorded; the
  security-path review (A2, A3, A5, A8 and Keyring's approve screen) is done.
- With the flags off, Keyring's P0 behaves exactly as before.
- The reset leaves the `hcp_*` keyspaces empty and the seeded context in
  place.
- A recorded video of a full run exists.

**On the day.** Go if a dry run of steps 1–9, on the venue network, passes in
the hour before. No-go: show the recorded video and walk through A9's
transcript.

## Key design decisions

- **Consent through task-consent**, not step-up: step-up elevates the
  requester's own session, which VTI-APV-005 forbids for someone else's
  approval, and task-consent binds the approval to the request's digest
  ([hcp.md](../docs/05-design-notes/hcp.md) §5).
- **The agent has no ACL entry.** It is admitted through a zero-authority
  hook, and its authority is the grant ([hcp.md](../docs/05-design-notes/hcp.md)
  §4.3).
- **Keyring manages by DID-proven request** (admin DID, proof, ACL admin
  role, no `accessToken`); management tokens come in V1.
- **Temporary grants only**, 4 hours by default; persistent is never offered
  in the demo.
- **`hcp/*` over TSP and DIDComm only**; REST is refused.
- **openvti-starter's MODE=tunnel**, because a phone cannot reach MODE=local
  (see "The environment, in portable terms").
- **Purposes are DTG registry IRIs**
  (`https://registry.trustoverip.org/dtg/purpose/<name>/<n>`), the draft
  entries `task-execution/1` and `personalisation/1`, read from configuration.
- **The agent answers deterministically**, citing entries and purposes, so the
  demo repeats and nothing reaches a model provider.
- **The pairing (QR and number) is for the demo only**; P1 merges it with
  Keyring's agent-connect pairing.
