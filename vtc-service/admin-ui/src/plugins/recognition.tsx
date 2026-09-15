// Recognition plugin — the operator's view of the trust (recognition) graph.
//
// TRQP recognition is a per-DID query against the upstream trust registry (not
// a listable set), so this surfaces the configured-registry status plus a
// lookup tool: enter an issuer / community DID and see whether this community
// recognises it. That recognition verdict is what decides whether a third-party
// invitation issuer is trusted (M2).

import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, Check, Network, X } from "lucide-react";

import {
  checkRecognition,
  fetchDiagnostics,
  type DriftEntry,
  type FailedSyncJob,
  type RecognitionCheck,
} from "@/lib/api";
import { useToast } from "@/lib/toast";
import { CopyButton } from "@/components/CopyButton";
import { formatDuration, formatIso } from "@/lib/format";

/** Protocol names as the specs write them, not as the wire encodes them. */
function protocolName(protocol: string): string {
  switch (protocol) {
    case "tsp":
      return "TSP";
    case "didcomm":
      return "DIDComm";
    case "rest":
      return "REST";
    default:
      return protocol;
  }
}

export function Recognition() {
  const toast = useToast();
  const [did, setDid] = useState("");

  // Polled, not fetched once: the queue below is the live picture of a
  // background reconciler, and a snapshot frozen at page-load would show a
  // drained queue as permanently stuck (or a stuck one as briefly busy).
  const diagnostics = useQuery({
    queryKey: ["diagnostics"],
    queryFn: fetchDiagnostics,
    refetchInterval: 15_000,
  });

  const lookup = useMutation<RecognitionCheck, Error, string>({
    mutationFn: (d: string) => checkRecognition(d),
    onError: (e) => toast.pushFromError(e),
  });

  const result = lookup.data;
  const oldestPending = diagnostics.data?.oldestPendingAgeSeconds;
  const failedJobs = diagnostics.data?.ext["org.openvtc"].failedJobs ?? [];
  // `unsupportedType` in any failed job means the deployed registry does not
  // route a Trust Task this VTC sends — a version skew, not a bad request.
  // Called out on its own because the remedy is "upgrade the registry", which
  // is not something an operator would infer from a queue of failures.
  const incompatible = failedJobs.some(isUnsupportedType);
  // `undefined` is "no check has completed yet", which is not the same as
  // "no drift" and must not render as a clean result.
  const drift = diagnostics.data?.ext["org.openvtc"].registryDrift;

  return (
    <div className="page">
      <header className="page-header">
        <h2>
          <Network size={20} strokeWidth={1.75} /> Recognition
        </h2>
        <p className="muted">
          The trust (recognition) graph decides which foreign issuers and
          communities this community trusts — including which third parties may
          issue invitations that auto-admit. Recognition is queried per-DID
          against the trust registry.
        </p>
      </header>

      <section className="card">
        <h3>Trust registry</h3>
        {diagnostics.isPending && <p className="muted">Loading…</p>}
        {diagnostics.data && (
          <dl>
            <dt>Status</dt>
            <dd>
              <code>{diagnostics.data.registryStatus}</code>
            </dd>
            {diagnostics.data.registryTransport?.did && (
              <>
                <dt>Registry DID</dt>
                <dd>
                  <code>{diagnostics.data.registryTransport.did}</code>
                  <CopyButton
                    value={diagnostics.data.registryTransport.did}
                    label="Copy trust registry DID"
                    successMessage="Trust registry DID copied"
                  />
                </dd>
              </>
            )}
            {diagnostics.data.registryTransport?.url && (
              <>
                <dt>Registry URL</dt>
                <dd>
                  <code>{diagnostics.data.registryTransport.url}</code>
                </dd>
              </>
            )}
            {diagnostics.data.registryTransport && (
              <>
                {/* Advertised is the registry's own claim, read from its DID
                    document; active is what the last call chose. Shown apart
                    because "advertises TSP, talking DIDComm" and "advertises
                    TSP, nothing in common" are different problems. */}
                <dt>Advertises</dt>
                <dd>
                  <code>
                    {diagnostics.data.registryTransport.advertised.length
                      ? diagnostics.data.registryTransport.advertised
                          .map(protocolName)
                          .join(", ")
                      : "(not resolved)"}
                  </code>
                </dd>
                <dt>Connecting over</dt>
                <dd>
                  <code>
                    {diagnostics.data.registryTransport.active
                      ? protocolName(diagnostics.data.registryTransport.active)
                      : "(none selected)"}
                  </code>
                </dd>
              </>
            )}
            {diagnostics.data.registryTransport?.error && (
              <>
                <dt>Last transport error</dt>
                <dd>{diagnostics.data.registryTransport.error}</dd>
              </>
            )}
          </dl>
        )}
      </section>

      <section className="card">
        <h3>Membership sync</h3>
        <p className="muted">
          Member changes reach the registry through a durable queue with
          exponential backoff. These counts are the only place a stalled
          reconciler is visible — <code>registryStatus</code> reports whether
          the registry answers, not whether our writes are landing.
        </p>
        {diagnostics.isPending && <p className="muted">Loading…</p>}
        {diagnostics.data && (
          <>
            <div className="stat-tiles">
              <QueueTile
                label="Pending"
                value={diagnostics.data.queueDepth}
                // `null` (empty queue) and `undefined` (no response yet) both
                // mean nothing is waiting; `== null` covers both.
                foot={
                  oldestPending == null
                    ? "nothing waiting"
                    : `oldest ${formatDuration(oldestPending)}`
                }
                // A queue an hour behind is the spec's degraded SLI. Rising
                // depth on its own is normal (a burst of joins drains); depth
                // that stays *old* is the shape of a stuck reconciler.
                tone={
                  oldestPending != null && oldestPending >= 3600
                    ? "warn"
                    : "neutral"
                }
              />
              <QueueTile
                label="Failed"
                value={diagnostics.data.failedCount}
                // Terminal rows: the syncer has given up on them, so unlike
                // pending they will never clear on their own. The count used
                // to be the whole surface, which named a condition without
                // giving anyone a way to see or act on it — the table below
                // is the triage it was asking for.
                foot={
                  diagnostics.data.failedCount > 0
                    ? "given up — see below"
                    : "none"
                }
                tone={diagnostics.data.failedCount > 0 ? "warn" : "ok"}
              />
              <QueueTile
                label="RTBF batched"
                value={diagnostics.data.rtbfBatchedCount}
                foot="held for the daily flush"
              />
              <QueueTile
                label="Syncer"
                value={
                  !diagnostics.data.syncerEnabled
                    ? "off"
                    : diagnostics.data.syncerRunning
                      ? "running"
                      : "stopped"
                }
                // Enabled but not running means the task is spawned and dead —
                // mid-restart after a panic, or wedged. Rising restarts is the
                // "keeps crashing" signal.
                foot={
                  !diagnostics.data.syncerEnabled
                    ? "no registry configured"
                    : diagnostics.data.syncerRestarts > 0
                      ? `${diagnostics.data.syncerRestarts} restart${
                          diagnostics.data.syncerRestarts === 1 ? "" : "s"
                        }`
                      : "no restarts"
                }
                tone={
                  !diagnostics.data.syncerEnabled
                    ? "neutral"
                    : diagnostics.data.syncerRunning &&
                        diagnostics.data.syncerRestarts === 0
                      ? "ok"
                      : "warn"
                }
              />
            </div>
            <dl>
              <dt>Last success</dt>
              <dd>
                {diagnostics.data.lastSuccessAt
                  ? formatIso(diagnostics.data.lastSuccessAt)
                  : "(never)"}
              </dd>
              <dt>Last failure</dt>
              <dd>
                {diagnostics.data.lastFailureAt
                  ? formatIso(diagnostics.data.lastFailureAt)
                  : "(none)"}
              </dd>
              {diagnostics.data.lastError && (
                <>
                  <dt>Last error</dt>
                  <dd>{diagnostics.data.lastError}</dd>
                </>
              )}
            </dl>

            {incompatible && (
              <p className="finding warn" role="status">
                <strong>
                  <AlertTriangle
                    size={15}
                    strokeWidth={1.75}
                    aria-hidden
                    style={{ verticalAlign: "-2px" }}
                  />{" "}
                  The trust registry does not route a Trust Task this VTC
                  sends.
                </strong>
                <span className="muted">
                  At least one job below was refused with{" "}
                  <code>unsupportedType</code>. That is a version skew — the
                  deployed registry does not serve that task at all — not a
                  rejection of anything we sent, so nothing about this
                  community&rsquo;s configuration will fix it. Upgrade the
                  trust registry, then requeue with{" "}
                  <code>vtc sync-jobs retry --all</code> on a stopped daemon.
                </span>
              </p>
            )}

            {failedJobs.length > 0 && (
              <>
                <h4>Failed jobs</h4>
                <p className="muted">
                  These are terminal. The syncer skips them on every tick and
                  boot recovery does not rescue them, so each member below is
                  absent or stale in the registry until an operator acts — or
                  until the retention sweeper purges the row, which clears the
                  failure without fixing it. Fix the cause, then{" "}
                  <code>vtc sync-jobs retry</code> on a stopped daemon.
                </p>
                <div className="table-scroll">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Member</th>
                        <th>Operation</th>
                        <th>Attempts</th>
                        <th>Gave up</th>
                        <th>Registry said</th>
                      </tr>
                    </thead>
                    <tbody>
                      {failedJobs.map((job) => (
                        <FailedJobRow key={job.jobId} job={job} />
                      ))}
                    </tbody>
                  </table>
                </div>
                {failedJobs.length < diagnostics.data.failedCount && (
                  <p className="muted">
                    Showing {failedJobs.length} of{" "}
                    {diagnostics.data.failedCount}. Run{" "}
                    <code>vtc sync-jobs list</code> for the rest.
                  </p>
                )}
              </>
            )}
          </>
        )}
      </section>

      <section className="card">
        <h3>Registry records</h3>
        <p className="muted">
          What this community believes it published, against what the registry
          actually holds. The two are compared on their own timer, not on page
          load — <code>registryStatus</code> says the registry answers, and the
          sync counters say our writes were <em>accepted</em>; only this says
          they are still <em>there</em>.
        </p>
        {diagnostics.isPending && <p className="muted">Loading…</p>}
        {diagnostics.data && !drift && (
          <p className="finding info">
            <strong>Not checked yet.</strong>
            <span className="muted">
              The first comparison runs shortly after boot, then every 15
              minutes by default. This is <em>unknown</em>, not{" "}
              <em>no drift</em>. Set <code>[registry]</code>{" "}
              <code>drift_check_interval_seconds = 0</code> to disable it
              entirely.
            </span>
          </p>
        )}
        {drift && (
          <>
            <dl>
              <dt>Last checked</dt>
              <dd>{formatIso(drift.checkedAt)}</dd>
              <dt>Ours / registry</dt>
              <dd>
                <code>{drift.localCount}</code> / <code>{drift.registryCount}</code>
              </dd>
            </dl>
            {drift.error && (
              <p className="finding warn">
                <strong>The last comparison did not complete.</strong>
                <span className="muted">
                  {drift.error} — any findings below are from the last check
                  that did complete, and are deliberately kept rather than
                  cleared: a registry that was briefly unreachable is not
                  evidence that drift went away.
                </span>
              </p>
            )}
            {drift.total === 0 && !drift.error && (
              <p className="finding ok">
                <strong>The two views agree.</strong>
                <span className="muted">
                  Every record this community published is present at the
                  registry with the status we expect.
                </span>
              </p>
            )}
            {drift.entries.length > 0 && (
              <>
                <div className="table-scroll">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Member</th>
                        <th>Disagreement</th>
                        <th>Ours</th>
                        <th>Registry</th>
                      </tr>
                    </thead>
                    <tbody>
                      {drift.entries.map((e) => (
                        <DriftRow key={`${e.disagreement}:${e.memberDid}`} entry={e} />
                      ))}
                    </tbody>
                  </table>
                </div>
                {drift.entries.length < drift.total && (
                  <p className="muted">
                    Showing {drift.entries.length} of {drift.total}.
                  </p>
                )}
              </>
            )}
          </>
        )}
      </section>

      <section className="card">
        <h3>Check recognition</h3>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (did.trim()) lookup.mutate(did.trim());
          }}
        >
          <label className="field">
            <span className="field-label">Issuer / community DID</span>
            <input
              type="text"
              value={did}
              onChange={(e) => setDid(e.target.value)}
              placeholder="did:webvh:… or did:key:…"
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <button
            type="submit"
            className="btn primary"
            disabled={!did.trim() || lookup.isPending}
          >
            {lookup.isPending ? "Checking…" : "Check"}
          </button>
        </form>

        {result && (
          <p style={{ marginTop: 12 }}>
            {result.recognised ? (
              <span>
                <Check
                  size={16}
                  strokeWidth={1.75}
                  className="status-icon ok"
                  aria-label="Recognised"
                />{" "}
                <strong>Recognised</strong> — <code>{result.did}</code> is
                trusted by this community.
              </span>
            ) : (
              <span>
                <X
                  size={16}
                  strokeWidth={1.75}
                  aria-label="Not recognised"
                />{" "}
                <strong>Not recognised</strong> — <code>{result.did}</code> is
                not in the recognition graph
                {result.registryConfigured ? "" : " (no trust registry configured)"}.
              </span>
            )}
            {result.error && (
              <span className="muted">
                {" "}
                (registry error: {result.error})
              </span>
            )}
          </p>
        )}
      </section>
    </div>
  );
}

/**
 * One member whose two views disagree.
 *
 * The direction is the whole content of the row, so it is named in prose
 * rather than shown as a status word: "missing at registry" and "unknown
 * locally" are opposite problems with opposite fixes, and an operator
 * scanning a column of near-identical DIDs should not have to decode which
 * is which.
 */
function DriftRow({ entry }: { entry: DriftEntry }) {
  const fault = entry.disagreement !== "unknownLocally";
  const says: Record<DriftEntry["disagreement"], string> = {
    missingAtRegistry: "we published it; the registry does not have it",
    unknownLocally: "the registry has it; we have no record of publishing it",
    statusMismatch: "both have it and disagree on whether the member is active",
  };
  return (
    <tr>
      <td>
        <code>{entry.memberDid}</code>
        <CopyButton
          value={entry.memberDid}
          label="Copy member DID"
          successMessage="Member DID copied"
        />
      </td>
      <td>
        <span className={fault ? "warn" : undefined}>
          {says[entry.disagreement]}
        </span>
      </td>
      <td>{entry.localStatus ?? "—"}</td>
      <td>{entry.registryStatus ?? "—"}</td>
    </tr>
  );
}

/** Whether a failed job was refused because the registry doesn't route it. */
function isUnsupportedType(job: FailedSyncJob): boolean {
  return (job.lastError ?? "").includes("unsupportedType");
}

/** The wire-form `SyncJobKind`, as an operator would say it. */
function kindName(kind: string): string {
  switch (kind) {
    case "publishMember":
      return "Publish member";
    case "updateMember":
      return "Update member";
    case "deleteMember":
      return "Delete member";
    case "markDeparted":
      return "Mark departed";
    default:
      return kind;
  }
}

/**
 * One terminally-failed sync job.
 *
 * The member DID is shown in full rather than shortened: it is the thing the
 * operator has to act on, and the failure's audit envelope carries only
 * `targetDidHash` (§11.1), so this row is the only place the plaintext DID is
 * legible. `attempts === 1` is worth distinguishing — it means the registry
 * refused outright rather than going quiet for eighteen hours of backoff, and
 * those two have completely different causes.
 */
function FailedJobRow({ job }: { job: FailedSyncJob }) {
  const gaveUp = job.lastAttemptedAt ?? job.createdAt;
  return (
    <tr>
      <td>
        <code>{job.memberDid}</code>
        <CopyButton
          value={job.memberDid}
          label="Copy member DID"
          successMessage="Member DID copied"
        />
      </td>
      <td>{kindName(job.kind)}</td>
      <td>
        {job.attempts}
        {job.attempts === 1 && (
          <span className="muted"> (refused outright)</span>
        )}
      </td>
      <td>
        {formatIso(gaveUp)}
        <br />
        <span className="muted">purged {formatIso(job.purgeDueAt)}</span>
      </td>
      <td>
        <span className={isUnsupportedType(job) ? "warn" : undefined}>
          {job.lastError ?? "(no error recorded)"}
        </span>
      </td>
    </tr>
  );
}

/**
 * One queue counter. Deliberately the same visual language as the dashboard's
 * `StatTile` — an operator reading "3 failed" here and a warn-toned tile there
 * should not have to work out whether the two mean the same thing.
 */
function QueueTile({
  label,
  value,
  foot,
  tone = "neutral",
}: {
  label: string;
  value: React.ReactNode;
  foot?: string;
  tone?: "ok" | "warn" | "neutral";
}) {
  return (
    <div className="stat-tile">
      <span className="stat-tile-label">{label}</span>
      <span className="stat-tile-value">{value}</span>
      {foot && (
        <span
          className={`stat-tile-foot${tone === "ok" ? " ok" : tone === "warn" ? " warn" : ""}`}
        >
          {foot}
        </span>
      )}
    </div>
  );
}
