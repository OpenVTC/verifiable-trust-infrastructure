### vta-sdk 0.21.3 / pnm-cli 0.11.18 — backup defaults to the descriptor flow, and CI stops restoring other jobs' caches (#892)

## CI: no job restores another job's cache

`Test` failed on #891 with `No space left on device` — reported from the runner's
*own* log writer, so there was no failing step and no job log, only a red job that
reads exactly like a code failure. The successful rerun logged the cause:

```
Cache Size: ~2962 MB
Cache restored from key: Linux-cargo-features-74bb9c97…
```

`Test` missed its own cache keys, fell through to the shared
`${{ runner.os }}-cargo-` fallback, and unpacked ~3 GB of the **Feature combos**
job's `target/` before building its own. Almost none of it is reusable —
different feature sets mean different fingerprints — so it is pure cost: disk,
and download time. This workspace's `target/` after a full `cargo test
--workspace` is enormous (196 GB locally), so a job that starts by importing a
foreign tree is the one that runs out.

The shared fallback is removed from **every** job. Each keeps its own prefix
(`Linux-cargo-test-` and friends), which is what actually warms a branch build
from `main`; only the cross-job fallback goes. This is the same fix #884 applied
to MSRV, now supported by a log line naming the foreign cache — and the same
shared key that let one fat Enclave cache evict the repo's whole 10 GB
allowance.

`Test` also prints `df -h /` after the cache restore, so the next occurrence says
so in one line instead of presenting as an unexplained failure.

## Backup: the descriptor flow is the default

Rollout step 5 of `docs/05-design-notes/backup-descriptor-pattern.md`, whose
bake-in condition ("one release cycle") has been met several times over.
`pnm backup export|import` now use the two-phase trust-task flow; the escape
hatch is `--use-rest-legacy`, which step 6 removes along with the route it calls.

**This corrects something I had wrong.** Backup was described as blocked on the
descriptor's `chunked-trust-task` algorithm. It is not: the two-phase flow has
been implemented, tested and CLI-exposed for some time, and only the *byte
transfer* uses the descriptor's HTTPS URL — deliberately, so a multi-megabyte
envelope never enters a message envelope. `chunked-trust-task` would move those
bytes too, which is a refinement, not a prerequisite.

The SDK's inline `backup_export` / `backup_import` are now `#[deprecated]`: they
ride a legacy protocol message and therefore have no TSP dispatcher at all, which
is the concrete reason the descriptor flow is the default rather than merely the
newer option.

## The one remaining first-party legacy send is deliberate

`import_key`'s cleartext `privateKeyMultibase` carrier stays on the legacy
DIDComm message, because that is the transport where authcrypt has already
established end-to-end confidentiality — the canonical task refuses cleartext
precisely because one dispatcher serves REST, DIDComm and TSP and cannot tell
which carried a request. Sealed and JWE carriers ride the canonical task and
reach TSP. Both legs are covered by tests, so the fork is a recorded decision
rather than an unexamined leftover.
