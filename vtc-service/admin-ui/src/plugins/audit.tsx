// Audit trail viewer.
//
// Wraps `GET /v1/audit`. Super-admin only — the endpoint is gated
// server-side, and a non-super-admin caller gets a 403 rendered as
// a toast.
//
// Pagination is forward-only ("Show older" button). The page shows
// timestamp + event-kind + actor/target DIDs + a collapsible JSON
// detail panel per row. Auto-refreshes when the operator clicks
// Refresh — we deliberately don't poll, because the audit log can
// grow large and a poll would refetch the whole page each tick.

import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ClipboardList, RefreshCw } from "lucide-react";

import { getJson } from "@/lib/api";
import { formatIso } from "@/lib/format";
import { useToast } from "@/lib/toast";

// Human-readable label per event kind. Falls through to the
// camelCase tag for variants we haven't catalogued yet (new event
// types just show as raw kind until this map is updated, which is a
// quieter failure mode than throwing).
const EVENT_DESCRIPTIONS: Record<string, string> = {
  AdminUiServed: "Admin UI bundle pinned at daemon boot",
  CommunityInstalled: "Community installation completed",
  EmergencyBootstrapInvoked: "Emergency bootstrap triggered",
  AdminPasskeyRegistered: "Admin registered a passkey",
  AdminPasskeyRevoked: "Admin revoked a passkey",
  ConfigChanged: "Daemon configuration changed",
  ConfigReloaded: "Daemon configuration reloaded",
  RestartRequested: "Daemon restart requested",
  CommunityProfileUpdated: "Community profile updated",
  AuditKeyRotated: "Audit key rotated",
  MemberUpdated: "Member record updated",
  RoleChanged: "Member role changed",
  AdminPromoted: "Member promoted to admin",
  JoinRequestSubmitted: "Applicant submitted a join request",
  JoinRequestApproved: "Join request approved",
  JoinRequestRejected: "Join request rejected",
  MemberAdded: "New member joined",
  MemberRemoved: "Member removed from community",
  PolicyUploaded: "Policy revision uploaded",
  PolicyActivated: "Policy activated for a purpose",
  VmcIssued: "Membership credential (VMC) issued",
  VecIssued: "Role credential (VEC) issued",
  MembershipRenewed: "Membership renewed",
  StatusListFlipped: "Status-list bit flipped",
  DidRotated: "Member rotated their DID",
  RegistryStatusChanged: "Trust-registry reachability changed",
  RegistrySyncSucceeded: "Trust-registry sync succeeded",
  RegistrySyncFailed: "Trust-registry sync failed",
  RegistryRecordPolicyOverride: "Registry record disposition overridden",
  CrossCommunitySessionMinted: "Cross-community session issued",
  VrcPublished: "Relationship credential (VRC) published",
  VrcRevoked: "Relationship credential revoked",
  PersonhoodAsserted: "Personhood asserted",
  PersonhoodRevoked: "Personhood revoked",
  CustomEndorsementIssued: "Custom endorsement issued",
  CustomEndorsementRevoked: "Custom endorsement revoked",
  EndorsementTypeRegistered: "Endorsement type registered",
  EndorsementTypeDeleted: "Endorsement type deleted",
  WebsiteFileWritten: "Public website file written",
  WebsiteFileDeleted: "Public website file deleted",
  WebsiteBundleDeployed: "Public website bundle deployed",
  WebsiteGenerationRolledBack: "Public website rolled back",
};

// Events that fire on a schedule or at daemon-internal lifecycle
// transitions, not in response to an operator/member action. The
// audit log keeps them for security pinning + completeness, but the
// default UI filters them so "who did what" reads cleanly.
const SYSTEM_EVENT_KINDS = new Set([
  "AdminUiServed",
  "RegistryStatusChanged",
  "RegistrySyncSucceeded",
  "RegistrySyncFailed",
]);

const TRUST_TASK = "https://trusttasks.org/spec/audit/list/0.1";

// Canonical `audit/list/0.1` entry shape. The maintainer-specific
// fields VTC used to expose at the top level (keyed actor/target
// hashes, the audit key id, the per-variant version) now live under
// `ext.vtc`, because the canonical envelope is
// `additionalProperties: false`.
interface AuditEntry {
  eventId: string;
  recordedAt: string;
  action: string;
  actor: string | null;
  target?: string | null;
  schemaVersion: number;
  prevHash: string;
  entryHash: string;
  detail: Record<string, unknown>;
  ext?: {
    vtc?: {
      eventVersion?: number;
      auditKeyId?: string;
      actorDidHash?: string;
      targetDidHash?: string | null;
    };
  };
}

interface AuditListResponse {
  entries: AuditEntry[];
  truncated: boolean;
  cursor?: string | null;
}

async function fetchAuditPage(
  cursor: string | null,
  pageSize: number,
): Promise<AuditListResponse> {
  const q = new URLSearchParams();
  if (cursor) q.set("cursor", cursor);
  q.set("pageSize", String(pageSize));
  return getJson<AuditListResponse>(`/v1/audit?${q}`, {
    trustTask: TRUST_TASK,
  });
}

export function Audit() {
  const [cursor, setCursor] = useState<string | null>(null);
  const [items, setItems] = useState<AuditEntry[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [showSystem, setShowSystem] = useState(false);
  const [filterText, setFilterText] = useState("");
  const toast = useToast();

  const query = useQuery({
    queryKey: ["audit", cursor],
    queryFn: () => fetchAuditPage(cursor, 50),
    staleTime: 0,
  });

  // Accumulate pages: first page replaces, subsequent appends. We
  // could let TanStack manage this with `useInfiniteQuery` instead,
  // but the read-once pattern keeps it simpler.
  useEffect(() => {
    if (!query.data) return;
    if (cursor === null) {
      setItems(query.data.entries);
    } else {
      setItems((prev) => [...prev, ...query.data!.entries]);
    }
    setNextCursor(query.data.cursor ?? null);
  }, [query.data, cursor]);

  useEffect(() => {
    if (query.error) toast.pushFromError(query.error, "Failed to load audit");
  }, [query.error, toast]);

  // Visible items = the accumulated set minus system events (when
  // hidden) minus rows that don't match the free-text filter.
  // Filter matches against event kind, description, and either DID
  // — case-insensitive substring so an operator pasting half a DID
  // still finds the row.
  const visibleItems = useMemo(() => {
    const needle = filterText.trim().toLowerCase();
    return items.filter((env) => {
      const kind = env.action;
      if (!showSystem && SYSTEM_EVENT_KINDS.has(kind)) return false;
      if (!needle) return true;
      const haystack = [
        kind,
        EVENT_DESCRIPTIONS[kind] ?? "",
        env.actor ?? "",
        env.target ?? "",
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [items, showSystem, filterText]);

  const hiddenCount = items.length - visibleItems.length;

  return (
    <section className="page">
      <h2>Audit trail</h2>
      <p className="lead">
        Tamper-evident operations log. Newest first. Super-admin only —
        envelopes carry plaintext actor / target DIDs until an RTBF
        redaction nulls them.
      </p>

      <section className="card">
        <div className="toolbar">
          <label className="field inline">
            <span className="field-label">Filter</span>
            <input
              type="search"
              placeholder="kind, description, actor or target DID"
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
            />
          </label>
          <label
            className="field inline"
            style={{ flex: "0 0 auto", minWidth: 0 }}
          >
            <span className="field-label">Show system events</span>
            <input
              type="checkbox"
              checked={showSystem}
              onChange={(e) => setShowSystem(e.target.checked)}
              style={{ width: "auto", height: "auto" }}
            />
          </label>
          <span className="muted">
            {visibleItems.length} of {items.length}
            {hiddenCount > 0 ? ` (${hiddenCount} filtered)` : ""}
            {nextCursor ? ", more available" : ""}
          </span>
          <div className="spacer" />
          <button
            type="button"
            className="secondary"
            disabled={query.isFetching && cursor === null}
            aria-busy={query.isFetching && cursor === null}
            onClick={async () => {
              // Refresh resets the accumulator + re-fetches the first
              // page. We can't lean on the `useEffect` below to wire
              // the response into state: React Query's default
              // `structuralSharing` keeps `query.data` byte-stable
              // when the response is identical, so the effect's
              // dependency array never sees a new reference and the
              // post-clear `setItems([])` would stick. Pull the
              // result out of `refetch()`'s promise and assign
              // explicitly instead.
              setCursor(null);
              setItems([]);
              setNextCursor(null);
              const result = await query.refetch();
              if (result.data) {
                setItems(result.data.entries);
                setNextCursor(result.data.cursor ?? null);
              }
            }}
          >
            <RefreshCw size={14} aria-hidden="true" />
            {query.isFetching && cursor === null ? "Refreshing…" : "Refresh"}
          </button>
        </div>
      </section>

      <section className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Event</th>
              <th>Actor</th>
              <th>Target</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {visibleItems.length === 0 && !query.isPending && (
              <tr>
                <td colSpan={5}>
                  <div className="empty-state">
                    <span className="empty-icon" aria-hidden="true">
                      <ClipboardList />
                    </span>
                    <h4>
                      {items.length === 0
                        ? "No audit entries yet"
                        : "No entries match this filter"}
                    </h4>
                    <p>
                      {items.length === 0
                        ? "Audit envelopes appear here once the community starts emitting events."
                        : "Clear the search box or enable system events to widen the view."}
                    </p>
                  </div>
                </td>
              </tr>
            )}
            {query.isPending && cursor === null && (
              <tr>
                <td colSpan={5}>Loading…</td>
              </tr>
            )}
            {visibleItems.map((env) => (
              <AuditRow key={env.eventId} env={env} />
            ))}
          </tbody>
        </table>
        {nextCursor && (
          <div className="pagination">
            <button
              type="button"
              className="secondary"
              disabled={query.isFetching}
              aria-busy={query.isFetching && cursor !== null}
              onClick={() => setCursor(nextCursor)}
            >
              {query.isFetching && cursor !== null ? "Loading…" : "Show older"}
            </button>
          </div>
        )}
      </section>
    </section>
  );
}

function AuditRow({ env }: { env: AuditEntry }) {
  const [open, setOpen] = useState(false);
  const kind = env.action;
  const description = EVENT_DESCRIPTIONS[kind];
  return (
    <>
      <tr>
        <td title={env.recordedAt}>{formatIso(env.recordedAt)}</td>
        <td>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span>{description ?? kind}</span>
            {description && (
              <code
                className="muted"
                style={{ fontSize: "var(--text-xs)" }}
              >
                {kind}
              </code>
            )}
          </div>
        </td>
        <td>
          {env.actor ? (
            <code className="truncate" title={env.actor}>
              {env.actor}
            </code>
          ) : (
            <span className="muted" title="Redacted by RTBF">
              redacted
            </span>
          )}
        </td>
        <td>
          {env.target ? (
            <code className="truncate" title={env.target}>
              {env.target}
            </code>
          ) : env.ext?.vtc?.targetDidHash ? (
            <span className="muted" title="Redacted by RTBF">
              redacted
            </span>
          ) : (
            <span className="muted">—</span>
          )}
        </td>
        <td>
          <button
            type="button"
            className="link"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? "Hide" : "Details"}
          </button>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={5}>
            <pre className="audit-detail">{formatEvent(env)}</pre>
          </td>
        </tr>
      )}
    </>
  );
}

// `eventKind` used to dig the serde tag out of the nested `event`
// object. Canonical `audit/list` hands back `action` as a plain string
// and the payload separately as `detail`, so the helper is gone.

function formatEvent(env: AuditEntry): string {
  try {
    return JSON.stringify(env, null, 2);
  } catch {
    return String(env);
  }
}

