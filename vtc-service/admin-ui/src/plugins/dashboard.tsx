import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import { fetchHealth, fetchBuildInfo, fetchDiagnostics } from "@/lib/api";

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

  const status = health.data?.status;
  const mediatorDid = diagnostics.data?.mediator_did;
  const vtaDid = diagnostics.data?.vta_did;
  const registry = diagnostics.data?.registry_transport;
  const registryStatus = diagnostics.data?.registry_status;

  // The messaging transports this VTC actually serves right now. "DIDComm
  // transport ready" was true of every deployment and told an operator
  // nothing: a VTC on TSP, or one advertising a transport its build cannot
  // answer, read identically. Name the protocols instead.
  const messaging = (diagnostics.data?.transports ?? []).filter(
    (t) => t.protocol !== "rest",
  );
  const live = messaging.filter((t) => t.advertised && t.serviceable);
  const advertisedOnly = messaging.filter((t) => t.advertised && !t.serviceable);
  const servedOnly = messaging.filter((t) => !t.advertised && t.serviceable);

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
    : advertisedOnly.length || !live.length
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
            foot={
              registry.error
                ? registry.error
                : registry.active
                  ? `${registryStatus ?? "unknown"} · advertises ${
                      registry.advertised.length
                        ? registry.advertised.map(protocolName).join(", ")
                        : "nothing"
                    }`
                  : "no transport selected yet"
            }
            tone={
              registry.error
                ? "warn"
                : registryStatus === "active"
                  ? "ok"
                  : "warn"
            }
          />
        )}
      </div>

      {/* Advertised-but-unservable is worth its own line rather than a tone:
          it is the one state where a *more* conforming client fails harder,
          and the fix is a document change, not a restart. */}
      {mediatorDid && (advertisedOnly.length > 0 || servedOnly.length > 0) && (
        <section className="card">
          <h3>Transport advertisement</h3>
          {advertisedOnly.length > 0 && (
            <p>
              Advertised but not servable:{" "}
              <strong>
                {advertisedOnly.map((t) => protocolName(t.protocol)).join(", ")}
              </strong>
              . A client resolving this community's DID will choose it and fail.
            </p>
          )}
          {servedOnly.length > 0 && (
            <p className="muted">
              Served but not advertised:{" "}
              <strong>
                {servedOnly.map((t) => protocolName(t.protocol)).join(", ")}
              </strong>
              . No client will choose it — add the service entry to the DID
              document to start receiving that traffic.
            </p>
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
}: {
  label: string;
  value: React.ReactNode;
  foot?: string;
  tone?: "ok" | "warn" | "neutral";
  mono?: boolean;
}) {
  return (
    <div className="stat-tile">
      <span className="stat-tile-label">{label}</span>
      <span className={`stat-tile-value${mono ? " mono" : ""}`}>{value}</span>
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
