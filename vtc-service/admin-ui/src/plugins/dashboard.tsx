import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { Link } from "react-router-dom";

import { CopyButton } from "@/components/CopyButton";
import { fetchHealth, fetchBuildInfo, fetchDiagnostics } from "@/lib/api";
import { formatDuration } from "@/lib/format";
import {
  fetchPendingWithVetting,
  fetchRevocations,
  vettingKeys,
} from "@/plugins/vetting/api";

export function Dashboard() {
  const health = useQuery({ queryKey: ["health"], queryFn: fetchHealth });
  const build = useQuery({
    queryKey: ["build-info"],
    queryFn: fetchBuildInfo,
  });
  // VTA + mediator identity moved off the unauth `/health` payload to
  // the admin-gated diagnostics endpoint (P3.7); the SPA is already
  // authenticated as admin, so it can read them there.
  const diagnostics = useQuery({
    queryKey: ["diagnostics"],
    queryFn: fetchDiagnostics,
  });
  // Vetting work waiting on an admin: pending join requests that carry vetting
  // facts, and withdrawn statements a current membership rests on.
  const pendingVetting = useQuery({
    queryKey: vettingKeys.pendingWithVetting,
    queryFn: fetchPendingWithVetting,
  });
  const withdrawals = useQuery({
    queryKey: vettingKeys.revocations,
    queryFn: fetchRevocations,
  });
  const needsReview = withdrawals.data?.filter(
    (r) => r.reviewState === "needsReview",
  ).length;

  const status = health.data?.status;
  const mediatorDid = diagnostics.data?.mediatorDid;
  const vtaDid = diagnostics.data?.vtaDid;
  const registry = diagnostics.data?.registryTransport;
  const registryStatus = diagnostics.data?.registryStatus;

  // The two queue states worth interrupting the dashboard for. Failed rows are
  // terminal — the syncer has given up, so they never clear on their own — and
  // a queue an hour behind is the spec's degraded SLI. Plain depth is not
  // trouble: a burst of joins drains.
  const failed = diagnostics.data?.failedCount ?? 0;
  // `null` and `undefined` both mean "no dispatchable job is waiting": the
  // daemon sends `null` when the queue is empty, and the field is absent
  // before the first diagnostics response lands. `!= null` covers both, which
  // a `!== undefined` test did not — it read an empty queue as a number and
  // only got away with it because the hand-written response type here claimed
  // the field was never null.
  const oldestPending = diagnostics.data?.oldestPendingAgeSeconds;
  const queueTrouble =
    failed > 0
      ? `${failed} sync job${failed === 1 ? "" : "s"} failed`
      : oldestPending != null && oldestPending >= 3600
        ? `sync ${formatDuration(oldestPending)} behind`
        : undefined;

  // The messaging transports this VTC actually serves right now. "DIDComm
  // transport ready" was true of every deployment and told an operator
  // nothing: a VTC on TSP, or one advertising a transport its build cannot
  // answer, read identically. Name the protocols instead.
  const transports = diagnostics.data?.transports ?? [];
  const messaging = transports.filter((t) => t.protocol !== "rest");
  const live = messaging.filter((t) => t.advertised && t.serviceable);

  // Every *interpretation* of the document-versus-binary comparison comes from
  // the daemon, off `transport_capability::findings_for_build` — the same
  // function `vtc status` and the boot gate read. The console used to re-derive
  // its own from the `transports` booleans, which was wrong twice over: two of
  // the four findings are statements about the shape of the advertised set
  // ("TSP with no DIDComm fallback", "no messaging advertised at all") and are
  // not reconstructable from any one protocol's pair of flags, so the console
  // silently dropped them — including the one that explains why the
  // informational line it *did* show matters. And `serviceable` is
  // build-capability AND live-connection, so a transient mediator disconnect
  // rendered as "a client will choose this and fail", which is a document
  // defect the operator did not have.
  //
  // Under `ext["org.openvtc"]` rather than at the top level because the
  // published response schema is `additionalProperties: false`: the extension
  // point is what ships this without waiting on a spec release.
  const findings =
    diagnostics.data?.ext?.["org.openvtc"]?.transportFindings ?? [];
  const hasBrokenAdvertisement = findings.some((f) => f.severity === "error");

  const mediatorFoot = !mediatorDid
    ? "REST-only deployment"
    : live.length
      ? `${live.map((t) => protocolName(t.protocol)).join(" + ")} live`
      : messaging.some((t) => t.advertised)
        ? "advertised, not connected"
        : "no messaging transport advertised";

  // An advertised transport this build cannot answer is the failure that
  // motivated the boot-time check: every conforming client picks it, and the
  // more correct the client, the more certainly it fails.
  const mediatorTone = !mediatorDid
    ? "neutral"
    : hasBrokenAdvertisement || !live.length
      ? "warn"
      : "ok";

  return (
    <section className="page">
      <h2>Dashboard</h2>

      <div className="stat-tiles">
        <StatTile
          label="Daemon status"
          value={status ?? "…"}
          foot={
            status === "ok"
              ? "Health check passing"
              : status === undefined
                ? undefined
                : "Investigate `/health` payload"
          }
          tone={
            status === "ok" ? "ok" : status === undefined ? "neutral" : "warn"
          }
        />
        <StatTile
          label="Build"
          value={build.data?.version ?? "…"}
          foot={build.data ? `mode: ${build.data.mode}` : undefined}
          mono
        />
        <StatTile
          label="VTA"
          value={vtaDid ? "Connected" : "Not set"}
          foot={
            vtaDid
              ? "Key-management agent provisioned"
              : "Run `vtc setup` to bind a VTA"
          }
          tone={vtaDid ? "ok" : "warn"}
        />
        <StatTile
          label="Mediator"
          value={
            mediatorDid
              ? live.length
                ? live.map((t) => protocolName(t.protocol)).join(" · ")
                : "Configured"
              : "Not set"
          }
          foot={mediatorFoot}
          tone={mediatorTone}
        />
        {registry && (
          <StatTile
            label="Trust registry"
            value={
              registry.active
                ? protocolName(registry.active)
                : registryStatus === "active"
                  ? "Active"
                  : "Unreachable"
            }
            // Queue trouble outranks the transport line. A registry we are
            // happily connected to while jobs pile up unsent is the exact
            // state the old green indicator hid, so when there is a backlog
            // this tile says so instead of reporting the protocol.
            foot={
              registry.error
                ? summarise(registry.error)
                : queueTrouble
                  ? queueTrouble
                  : registry.active
                    ? `${registryStatus ?? "unknown"} · advertises ${
                        registry.advertised.length
                          ? registry.advertised.map(protocolName).join(", ")
                          : "nothing"
                      }`
                    : "no transport selected yet"
            }
            tone={
              registry.error || queueTrouble
                ? "warn"
                : registryStatus === "active"
                  ? "ok"
                  : "warn"
            }
          />
        )}
        <StatTile
          label="Awaiting a vetting decision"
          value={
            pendingVetting.data
              ? `${pendingVetting.data.count}${pendingVetting.data.more ? "+" : ""}`
              : pendingVetting.error
                ? "—"
                : "…"
          }
          foot={
            pendingVetting.error
              ? "Could not check pending join requests"
              : pendingVetting.data
                ? pendingVetting.data.count
                  ? "pending join requests with vetting facts"
                  : "no join request is waiting"
                : undefined
          }
          tone={
            pendingVetting.error || pendingVetting.data?.count
              ? "warn"
              : pendingVetting.data
                ? "ok"
                : "neutral"
          }
          to="/join-requests"
        />
        <StatTile
          label="Withdrawn statements"
          value={needsReview ?? (withdrawals.error ? "—" : "…")}
          foot={
            withdrawals.error
              ? "Could not load withdrawal notices"
              : needsReview === undefined
                ? undefined
                : needsReview
                  ? `${needsReview === 1 ? "admission" : "admissions"} to review`
                  : "no admission to review"
          }
          tone={
            withdrawals.error || needsReview
              ? "warn"
              : needsReview === 0
                ? "ok"
                : "neutral"
          }
          to="/vetting/withdrawals"
        />
      </div>

      {/* The document-versus-binary comparison, always shown rather than only
          when something is wrong.

          Two reasons it is a card and not a tile tone. It is about a *document*
          — the fix is a DID-document change, not a restart — and it is about
          *this* community's document, where every tile above it describes some
          other party: the mediator this VTC dials, the registry it syncs with.
          An operator reading "advertises TSP, DIDComm" on the registry tile and
          "not advertised" here is looking at two different documents and,
          before this said so, had no way to tell.

          Always shown because its absence was ambiguous: a silent dashboard
          meant either "everything agrees" or "we never resolved the DID", and
          those want opposite reactions. */}
      {diagnostics.data && (
        <section className="card">
          <h3>Transport advertisement</h3>
          <p className="muted">
            What <strong>this community&rsquo;s own</strong> DID document
            advertises, against what this binary serves. The mediator and trust
            registry tiles above describe other parties&rsquo; documents.
          </p>

          {transports.length === 0 ? (
            <p className="finding warn">
              <strong>
                This VTC&rsquo;s DID did not resolve, so there is nothing to
                compare.
              </strong>
              <span className="muted">
                That is <em>unknown</em>, not <em>nothing advertised</em>.
                Confirm the DID is published and resolvable before reading
                anything into the transport tiles above.
              </span>
            </p>
          ) : (
            <>
              <table className="data-table transport-table">
                <thead>
                  <tr>
                    <th>Transport</th>
                    <th>In the DID document</th>
                    <th>Serviceable now</th>
                    <th>Advertised endpoint</th>
                  </tr>
                </thead>
                <tbody>
                  {transports.map((t) => (
                    <tr key={t.protocol}>
                      <td>{protocolName(t.protocol)}</td>
                      <td className={t.advertised ? "yes" : "no"}>
                        {t.advertised ? "advertised" : "not advertised"}
                      </td>
                      <td className={t.serviceable ? "yes" : "no"}>
                        {t.serviceable ? "yes" : "no"}
                      </td>
                      <td>
                        {t.endpoint ? (
                          <code>{t.endpoint}</code>
                        ) : (
                          <span className="muted">&mdash;</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="muted">
                A client resolving this DID commits to the highest-preference
                transport it finds &mdash; TSP, then DIDComm, then REST &mdash;
                so the topmost advertised row is the one that gets used. For a
                messaging transport, &ldquo;serviceable&rdquo; means both that
                this build supports it and that the mediator connection is live
                right now, so a <em>no</em> there can be a disconnect rather
                than a document problem; the findings below say which.
              </p>

              {findings.length === 0 ? (
                <p className="finding ok">
                  <strong>Document and binary agree.</strong>
                </p>
              ) : (
                <ul className="finding-list">
                  {findings.map((f, i) => (
                    <li
                      key={`${f.code}:${f.protocol ?? ""}:${i}`}
                      className={`finding ${f.severity}`}
                    >
                      <strong>{f.summary}</strong>
                      <span className="muted">{f.message}</span>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </section>
      )}

      <section className="card">
        <h3>Identity</h3>
        <dl>
          <dt>VTC DID</dt>
          <dd>
            <code>{health.data?.vtc_did ?? "…"}</code>
            <CopyButton
              value={health.data?.vtc_did}
              label="Copy VTC DID"
              successMessage="VTC DID copied"
            />
          </dd>
          <dt>VTA DID</dt>
          <dd>
            <code>{vtaDid ?? "(not configured)"}</code>
            <CopyButton
              value={vtaDid}
              label="Copy VTA DID"
              successMessage="VTA DID copied"
            />
          </dd>
          <dt>Mediator DID</dt>
          <dd>
            <code>{mediatorDid ?? "(none configured)"}</code>
            <CopyButton
              value={mediatorDid}
              label="Copy mediator DID"
              successMessage="Mediator DID copied"
            />
          </dd>
          {registry?.did && (
            <>
              <dt>Trust registry DID</dt>
              <dd>
                <code>{registry.did}</code>
                <CopyButton
                  value={registry.did}
                  label="Copy trust registry DID"
                  successMessage="Trust registry DID copied"
                />
              </dd>
            </>
          )}
          {registry?.url && !registry.did && (
            <>
              <dt>Trust registry URL</dt>
              <dd>
                <code>{registry.url}</code>
                <CopyButton
                  value={registry.url}
                  label="Copy trust registry URL"
                  successMessage="Trust registry URL copied"
                />
              </dd>
            </>
          )}
          <dt>Health endpoint</dt>
          <dd>
            <a href="/health" target="_blank" rel="noreferrer">
              <code>GET /health</code>{" "}
              <ExternalLink size={12} aria-hidden="true" />
            </a>
          </dd>
        </dl>
      </section>

      {(health.error || build.error || diagnostics.error) && (
        <section className="card error">
          <h3>Errors</h3>
          {health.error && <p>health: {String(health.error)}</p>}
          {build.error && <p>build-info: {String(build.error)}</p>}
          {diagnostics.error && (
            <p>diagnostics: {String(diagnostics.error)}</p>
          )}
        </section>
      )}
    </section>
  );
}

/**
 * Trim a transport error to a tile-sized line.
 *
 * These errors quote both parties' advertised sets and a full `did:webvh`,
 * which runs to five wrapped lines in a stat tile and pushes the rest of the
 * dashboard down. The Recognition page shows the whole thing; here it only has
 * to be recognisable.
 */
function summarise(error: string, max = 90): string {
  const oneLine = error.replace(/\s+/g, " ").trim();
  return oneLine.length > max ? `${oneLine.slice(0, max - 1)}…` : oneLine;
}

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

function StatTile({
  label,
  value,
  foot,
  tone = "neutral",
  mono = false,
  to,
}: {
  label: string;
  value: React.ReactNode;
  foot?: string;
  tone?: "ok" | "warn" | "neutral";
  mono?: boolean;
  /** Where acting on the tile happens; makes the whole tile a link. */
  to?: string;
}) {
  const body = (
    <>
      <span className="stat-tile-label">{label}</span>
      <span className={`stat-tile-value${mono ? " mono" : ""}`}>{value}</span>
      {foot && (
        <span
          className={`stat-tile-foot${tone === "ok" ? " ok" : tone === "warn" ? " warn" : ""}`}
        >
          {foot}
        </span>
      )}
    </>
  );
  return to ? (
    <Link to={to} className="stat-tile">
      {body}
    </Link>
  ) : (
    <div className="stat-tile">{body}</div>
  );
}
