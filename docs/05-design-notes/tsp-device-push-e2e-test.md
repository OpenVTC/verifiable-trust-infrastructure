# TSP device-push — end-to-end test plan

Verifies "the VTA should use TSP when it can" for the mobile approver: a
TSP-capable device announces reachability, the VTA learns it, and a task-consent
/ step-up push routes to the device over TSP (falling back to DIDComm). Built on
§3 = 3c (relationship-free routed send — see `tsp-outbound-send.md`).

The loop, once assembled:

```
device toggles TSP ──▶ inbox connects & announces (ping over TSP)
        │
        ▼
VTA dispatch_one records the PROVEN sender_vid as TSP-reachable (300s TTL)
        │
        ▼
next push (push_one / maybe_push_step_up): tsp_reach.fresh(dev)?
        ├─ yes ▶ send_routed over TSP  ── device receives on its TSP inbox
        └─ no  ▶ send_guaranteed over DIDComm (fallback)
```

## 0. What's already covered by automated tests

Run (no mediator needed):

```
cargo test -p vta-service --features tsp messaging::tsp_reach
cargo test -p vta-service --features tsp dispatch_one_records_sender
```

- `tsp_reach::records_and_reads_back_fresh` — record → fresh; unknown DID → not fresh.
- `tsp_reach::entry_expires_after_ttl` — a record goes stale after the TTL (the decay that makes push fall back to DIDComm).
- `tsp_reach::record_refreshes_the_window` — a re-announce before expiry keeps a device continuously reachable.
- `tsp_inbound::dispatch_one_records_sender_as_tsp_reachable` — the learn hook records the proven `sender_vid`.

What these **don't** cover (and why this plan exists): the live `atm.tsp().send_routed` round-trip and the device receive path can't be exercised without a real mediator + device.

## 1. Prerequisites

- A **TSP-enabled VTA**: built with `--features tsp`, its DID document advertising a `#tsp` (`TSPTransport`) service on your mediator. Run at `RUST_LOG=vta_service=debug` so the learn/push logs below appear.
- A **mediator** both the VTA and the device are local accounts on.
- **`pnm`** built with the (default) `tsp` feature — used for the VTA-side smoke in §2.
- For §3: the **iOS app** (`vta-mobile-agent-ios` ≥ the announce-on-connect build) on a device/simulator, paired to the same VTA + mediator, with an **approver ACL entry** for its holder DID (`vta acl create --did <holder> --role reader --approve-contexts <ctx>`).

## 2. VTA-side smoke (no device) — proves learn + selection fire live

Confirms the reachability record and the TSP send arm against a real mediator,
using `pnm` as a stand-in TSP sender.

1. **Baseline reachability probe.** `pnm health` against the TSP VTA → the *VTA TSP → Trust-ping* line reads `✓ pong`. In the VTA log:
   ```
   DEBUG … recorded TSP reachability (learn-from-inbound) sender=did:key:z<pnm-client>
   INFO  … TSP trust-task dispatched sender=did:key:z<pnm-client>
   ```
   That `sender` is now fresh in `tsp_reach` for 300s.

2. **Make that DID a push target.** Give the `pnm` client DID an approver ACL entry and drive a task-consent whose approver is it (or a step-up addressed to it). Within the 300s window, the VTA log shows the push chose TSP:
   ```
   DEBUG … delivered Trust-Task over TSP (learn-from-inbound) recipient=did:key:z<pnm-client>
   ```
   (No `send_guaranteed`/DIDComm-buffer line for that push.)

3. **Fallback on decay.** Wait > 300s (no re-announce) and repeat the push. The TSP line is **absent**; the DIDComm path runs instead — the record went stale, so `try_push_over_tsp` returned `false`. This is the safety net that protects a device that toggled back to DIDComm.

## 3. Full device end-to-end

1. **DIDComm baseline.** Device with **TSP off** (default). Trigger a delegated DID edit / step-up that pushes to this device. It arrives over DIDComm as today. VTA log: no TSP delivery line.
2. **Enable TSP.** In the app: Settings → **Receive over TSP** on. The listener re-opens on TSP (`restartListeningIfActive`) and announces. VTA log:
   ```
   DEBUG … recorded TSP reachability (learn-from-inbound) sender=did:key:z<holder>
   ```
3. **Push over TSP.** Trigger another push to this device within 300s. Expect:
   - VTA: `DEBUG … delivered Trust-Task over TSP … recipient=did:key:z<holder>`.
   - Device: the consent / step-up sheet appears (received on the TSP inbox, classified by `nextInboundTsp`).
   - Approve with Face ID → the decision still returns over the existing reply path (REST/DIDComm — the reply is not yet TSP).
4. **Staying fresh.** Leave the app listening > 5 min. The 150s re-announce keeps the device continuously reachable, so pushes keep choosing TSP (watch for a repeated `recorded TSP reachability` every ~150s).
5. **Toggle-off fallback.** Turn **Receive over TSP** off. The device drops its TSP socket; within 300s the VTA's record expires and pushes revert to DIDComm. Confirm the next push arrives on the DIDComm inbox and the VTA log shows no TSP delivery line.

## 4. Pass criteria

- §2.1 / §3.2: an inbound TSP frame produces `recorded TSP reachability`.
- §2.2 / §3.3: a push to a fresh DID produces `delivered Trust-Task over TSP` and the device receives it over TSP.
- §2.3 / §3.5: after TTL decay (or toggle-off), the same push silently reverts to DIDComm — **no lost message**.
- Nothing pushes over TSP to a device that has never announced (first contact is always DIDComm).

## 5. Known limitations at this stage

- **Reply is not TSP.** The device's decision returns over REST/DIDComm; only the VTA→device push is TSP. A TSP reply is future work.
- **`push_granted` is DIDComm-only** by design (targets the browser requester, which doesn't speak TSP).
- **In-memory, per-process reachability.** A VTA restart empties the map; devices re-announce within one 150s cycle. No persistence by design.
