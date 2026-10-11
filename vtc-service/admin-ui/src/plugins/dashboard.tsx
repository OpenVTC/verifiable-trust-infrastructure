// The dashboard: "what needs me", then health.
//
//   Overview
//   Good afternoon, Aroha                                [Invite a member]
//   [Members 248] [Join requests 5] [Awaiting vetting 2] [Waiting for you 3]
//   ┌ Waiting for you ───────────────┐ ┌ Service health ─────────────┐
//   │ Grant … to Tama R.   Critical  │ │ ● Daemon status   ok        │
//   │ …                              │ │ ● VTA             Connected │
//   └────────────────────────────────┘ └─────────────────────────────┘
//   Transport advertisement · Identity (the detail, below the fold)
//
// The counts are tiles, each linking to where the work is done and shown only
// to a viewer holding what that screen needs. "Waiting for you" is the first
// few actions from the same signed read as the Actions screen, each summary
// re-derived and checked before it is shown (`lib/action-summary.ts`). Service
// health is the daemon, its agents and this browser's signing key, one row
// each with a status dot and a word, so it reads without colour.

import { useQuery } from "@tanstack/react-query";
import { ArrowRight, ExternalLink, Inbox, UserPlus } from "lucide-react";
import { Link } from "react-router-dom";

import { CopyButton } from "@/components/CopyButton";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { NamedDid } from "@/components/NamedDid";
import { PageHeader } from "@/components/PageHeader";
import { fetchHealth, fetchBuildInfo, fetchDiagnostics } from "@/lib/api";
import { WAITING_COUNT_KEY } from "@/lib/action-badge";
import {
  coolingOffOf,
  fetchActionsAttention,
  isAcknowledgeItem,
  isQueueItem,
  landsIn,
  listActions,
  type Action,
} from "@/lib/actions-api";
import {
  countPendingJoinRequests,
  formatTally,
  JOIN_DECIDE_CAP,
  MEMBERS_MANAGE_CAP,
  mayCount,
  PENDING_JOIN_REQUESTS_KEY,
  useMemberCount,
} from "@/lib/community-counts";
import type { SigningStatus } from "@/lib/console-keys-api";
import { formatDuration, formatIso, formatRelative } from "@/lib/format";
import { fetchHiddenVettingSupport, hiddenVettingKeys } from "@/lib/hidden-vetting";
import { useNameBook, type NameBook } from "@/lib/names";
import { useCapabilities, useViewerDid } from "@/lib/viewer";
import { SIGNING_STATUS_KEY } from "@/pages/SetupSigning";
import { useVerifiedSummary } from "@/plugins/actions";
import {
  fetchPendingWithVetting,
  fetchRevocations,
  vettingKeys,
} from "@/plugins/vetting/api";

/** The capability the Invitations screen needs (`plugins/index.ts`). */
const INVITATIONS_CAP = "vtc.invitations.manage";
/** How many waiting actions the dashboard lists before "All actions". */
const WAITING_SHOWN = 5;

type Tone = "ok" | "warn" | "neutral";

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
  // Single-administrator mode (VTI-APV-022) and the waiting count: the same
  // signed action-list read the shell's badge and banner make, shared through
  // its cache key.
  const attention = useQuery({
    queryKey: WAITING_COUNT_KEY,
    queryFn: fetchActionsAttention,
    retry: false,
  });
  const singleAdminMode = attention.data?.singleAdminMode === true;
  // Members and pending join requests (lib/community-counts.ts): each tile only
  // for a viewer holding what its screen needs. The join-request count is the
  // shell's nav-badge read, shared through its cache key.
  const caps = useCapabilities();
  const showMembers = mayCount(caps, MEMBERS_MANAGE_CAP);
  const showJoins = mayCount(caps, JOIN_DECIDE_CAP);
  const canInvite = mayCount(caps, INVITATIONS_CAP);
  const members = useMemberCount(showMembers);
  const pendingJoins = useQuery({
    queryKey: PENDING_JOIN_REQUESTS_KEY,
    queryFn: countPendingJoinRequests,
    enabled: showJoins,
    retry: false,
  });
  // Whether this build can do hidden vetting at all — nothing else in the
  // console says, and a criterion offering it on a build that cannot would be
  // refused only when an applicant tried.
  const hiddenVetting = useQuery({
    queryKey: hiddenVettingKeys.support,
    queryFn: fetchHiddenVettingSupport,
    retry: false,
    staleTime: Infinity,
  });
  // This browser's signing key, as the shell last checked it (`App.tsx`); read
  // from its cache, never fetched again here.
  const me = useViewerDid();
  const signing = useQuery<SigningStatus>({
    queryKey: [SIGNING_STATUS_KEY, me],
    queryFn: () => Promise.reject(new Error("not fetched here")),
    enabled: false,
  });
  const book = useNameBook();

  const needsReview = withdrawals.data?.filter(
    (r) => r.reviewState === "needsReview",
  ).length;
  const waiting = attention.data?.waiting;

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
  const mediatorTone: Tone = !mediatorDid
    ? "neutral"
    : hasBrokenAdvertisement || !live.length
      ? "warn"
      : "ok";

  const signingKey =
    signing.data?.state === "ready"
      ? (signing.data as Extract<SigningStatus, { state: "ready" }>)
      : null;
  const keyDaysLeft = signingKey
    ? Math.max(0, Math.floor((Date.parse(signingKey.key.expiresAt) - Date.now()) / 86_400_000))
    : null;

  return (
    <section className="page dashboard">
      <PageHeader
        title={greeting(new Date(), firstName(me ? book.nameOf(me) : undefined))}
        crumbs={[{ label: "Overview" }]}
        actions={
          canInvite ? (
            <Link to="/invitations" className="button primary">
              <UserPlus size={14} aria-hidden="true" /> Invite a member
            </Link>
          ) : undefined
        }
      />

      <div className="stat-tiles dashboard-tiles">
        {singleAdminMode && (
          <StatTile
            label="Administration"
            value="Single admin mode"
            foot="Your step-up stands in for a second administrator's consent (VTI-APV-022)"
            tone="warn"
            to="/actions"
          />
        )}
        {showMembers && (
          <StatTile
            label="Members"
            value={
              members.data
                ? formatTally(members.data)
                : members.error
                  ? "—"
                  : "…"
            }
            foot={members.error ? "Could not count members" : "current members"}
            tone={members.error ? "warn" : "neutral"}
            to="/members"
          />
        )}
        {showJoins && (
          <StatTile
            label="Join requests"
            value={
              pendingJoins.data
                ? formatTally(pendingJoins.data)
                : pendingJoins.error
                  ? "—"
                  : "…"
            }
            foot={
              pendingJoins.error
                ? "Could not count join requests"
                : pendingJoins.data
                  ? pendingJoins.data.count
                    ? "awaiting a decision"
                    : "none awaiting a decision"
                  : undefined
            }
            tone={
              pendingJoins.error || pendingJoins.data?.count
                ? "warn"
                : pendingJoins.data
                  ? "ok"
                  : "neutral"
            }
            to="/join-requests"
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
                  ? pendingVetting.data.more && pendingVetting.data.pending !== undefined
                    ? `with vetting facts, of the first 50 of ${pendingVetting.data.pending} pending`
                    : "pending join requests with vetting facts"
                  : pendingVetting.data.pending
                    ? `none of the first ${Math.min(50, pendingVetting.data.pending)} pending carry vetting facts`
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
          label="Waiting for you"
          value={waiting ?? (attention.error ? "—" : "…")}
          foot={
            attention.error
              ? "Could not read the action list"
              : waiting === undefined
                ? undefined
                : waiting
                  ? `action${waiting === 1 ? "" : "s"} to decide or acknowledge`
                  : "nothing to decide"
          }
          tone={attention.error || waiting ? "warn" : waiting === 0 ? "ok" : "neutral"}
          to="/actions"
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

      <div className="dashboard-columns">
        <WaitingForYou book={book} />

        <section className="card dashboard-health" aria-labelledby="dashboard-health-title">
          <h3 id="dashboard-health-title">Service health</h3>
          <ul className="health-list">
            <HealthRow
              label="Daemon status"
              value={status ?? "…"}
              detail={
                status === "ok"
                  ? "Health check passing"
                  : status === undefined
                    ? undefined
                    : "Investigate the /health payload"
              }
              tone={status === "ok" ? "ok" : status === undefined ? "neutral" : "warn"}
            />
            <HealthRow
              label="VTA"
              value={vtaDid ? "Connected" : diagnostics.data ? "Not set" : "…"}
              detail={
                vtaDid
                  ? "Key-management agent provisioned"
                  : diagnostics.data
                    ? "Run `vtc setup` to bind a VTA"
                    : undefined
              }
              tone={vtaDid ? "ok" : diagnostics.data ? "warn" : "neutral"}
            />
            <HealthRow
              label="Mediator"
              value={
                mediatorDid
                  ? live.length
                    ? live.map((t) => protocolName(t.protocol)).join(" · ")
                    : "Configured"
                  : diagnostics.data
                    ? "Not set"
                    : "…"
              }
              detail={diagnostics.data ? mediatorFoot : undefined}
              tone={diagnostics.data ? mediatorTone : "neutral"}
            />
            {registry && (
              <HealthRow
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
                // this row says so instead of reporting the protocol.
                detail={
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
            {signingKey && keyDaysLeft !== null && (
              <HealthRow
                label="Signing key"
                value={
                  keyDaysLeft === 0
                    ? "expires today"
                    : `${keyDaysLeft} day${keyDaysLeft === 1 ? "" : "s"} left`
                }
                detail={`This browser's key · expires ${formatIso(signingKey.key.expiresAt)}`}
                tone={signingKey.renewSoon ? "warn" : "ok"}
                to="/console-keys"
              />
            )}
            <HealthRow
              label="Build"
              value={build.data?.version ?? "…"}
              detail={build.data ? `mode: ${build.data.mode}` : undefined}
              tone="neutral"
              mono
            />
            <HealthRow
              label="Hidden vetting (PCS)"
              value={
                hiddenVetting.data
                  ? hiddenVetting.data.publish
                    ? "Supported"
                    : "Not in this build"
                  : hiddenVetting.error
                    ? "—"
                    : "…"
              }
              detail={
                hiddenVetting.error
                  ? "Could not ask this VTC what it serves"
                  : hiddenVetting.data
                    ? hiddenVetting.data.publish
                      ? "zero-knowledge vetter proofs can be turned on per criterion"
                      : "built without the vetting-pcs feature; vetting is by named vetters only"
                    : undefined
              }
              tone={
                hiddenVetting.error ? "warn" : hiddenVetting.data?.publish ? "ok" : "neutral"
              }
              to={hiddenVetting.data?.publish ? "/vetting/requirements" : undefined}
            />
          </ul>
        </section>
      </div>

      {/* The document-versus-binary comparison, always shown rather than only
          when something is wrong.

          Two reasons it is a card and not a health row. It is about a
          *document* — the fix is a DID-document change, not a restart — and it
          is about *this* community's document, where every row above describes
          some other party: the mediator this VTC dials, the registry it syncs
          with. An operator reading "advertises TSP, DIDComm" on the registry
          row and "not advertised" here is looking at two different documents
          and, before this said so, had no way to tell.

          Always shown because its absence was ambiguous: a silent dashboard
          meant either "everything agrees" or "we never resolved the DID", and
          those want opposite reactions. */}
      {diagnostics.data && (
        <section className="card">
          <h3>Transport advertisement</h3>
          <p className="muted">
            What <strong>this community&rsquo;s own</strong> DID document
            advertises, against what this binary serves. The mediator and trust
            registry rows above describe other parties&rsquo; documents.
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
                anything into the service health above.
              </span>
            </p>
          ) : (
            <>
              <DataTable columns={TRANSPORT_COLUMNS} className="transport-table">
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
              </DataTable>
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

// ── Waiting for you ──────────────────────────────────────────────────

/**
 * The first few actions waiting for this administrator, newest first, each a
 * link to its own page on the Actions screen. Its own cache key under
 * `actions`, so whatever refreshes the Actions screen refreshes this too.
 */
function WaitingForYou({ book }: { book: NameBook }) {
  const query = useQuery({
    queryKey: ["actions", "dashboard", "waitingForMe"],
    queryFn: () => listActions({ view: "waitingForMe", limit: WAITING_SHOWN }),
    retry: false,
  });
  const actions = query.data?.actions ?? [];
  const total = query.data?.counts?.waitingForMe ?? actions.length;
  return (
    <section className="card dashboard-waiting" aria-labelledby="dashboard-waiting-title">
      <div className="card-title-row">
        <h3 id="dashboard-waiting-title">Waiting for you</h3>
        <Link to="/actions?tab=waitingForMe" className="card-title-link">
          All actions <ArrowRight size={12} aria-hidden="true" />
        </Link>
      </div>
      {query.isPending && <p className="muted">Loading…</p>}
      {query.error && (
        <p className="muted">Could not read the action list. The Actions screen says why.</p>
      )}
      {query.isSuccess && actions.length === 0 && (
        <EmptyState icon={Inbox} title="Nothing is waiting for you">
          Changes other administrators ask for appear here.
        </EmptyState>
      )}
      {actions.length > 0 && (
        <ul className="waiting-list">
          {actions.map((a) => (
            <WaitingRow key={a.actionId} action={a} book={book} />
          ))}
        </ul>
      )}
      {total > actions.length && (
        <p className="muted waiting-more">
          and {total - actions.length} more on the{" "}
          <Link to="/actions?tab=waitingForMe">Actions</Link> screen
        </p>
      )}
    </section>
  );
}

function WaitingRow({ action, book }: { action: Action; book: NameBook }) {
  const summary = useVerifiedSummary(action);
  const ack = isAcknowledgeItem(action);
  const cooling = coolingOffOf(action);
  return (
    <li className="waiting-row">
      <Link
        to={`/actions?action=${encodeURIComponent(action.actionId)}`}
        className="waiting-link"
      >
        <span className="waiting-title">
          {summary.state === "ok"
            ? summary.summary.title
            : summary.state === "refused"
              ? "Summary refused — open to see why"
              : "Checking this action…"}
        </span>
        <span className="waiting-meta">
          {ack ? (
            "Written by the operator, offline"
          ) : (
            <>
              Requested by <NamedDid book={book} did={action.requester} />
            </>
          )}
          {" · "}
          <time dateTime={action.createdAt} title={formatIso(action.createdAt)}>
            {formatRelative(action.createdAt)}
          </time>
          {cooling && <> · {landsIn(cooling.landsAt)}</>}
        </span>
      </Link>
      <span className="waiting-chips">
        {ack && <span className="chip danger">Critical</span>}
        {cooling && <span className="chip warning">Cooling off</span>}
        {isQueueItem(action) && <span className="chip">Queue</span>}
        {summary.state === "refused" && <span className="chip danger">Refused</span>}
      </span>
    </li>
  );
}

// ── Health ───────────────────────────────────────────────────────────

const TONE_WORD: Record<Tone, string> = { ok: "OK", warn: "Needs attention", neutral: "" };

function HealthRow({
  label,
  value,
  detail,
  tone,
  mono = false,
  to,
}: {
  label: string;
  value: React.ReactNode;
  detail?: string;
  tone: Tone;
  mono?: boolean;
  /** Where to act on it; makes the label a link. */
  to?: string;
}) {
  return (
    <li className={`health-row health-row--${tone}`} data-health={label}>
      <span className={`health-dot ${tone}`} aria-hidden="true" />
      <span className="health-text">
        <span className="health-label">
          {to ? <Link to={to}>{label}</Link> : label}
          {TONE_WORD[tone] && <span className="visually-hidden">: {TONE_WORD[tone]}</span>}
        </span>
        {detail && <span className="health-detail">{detail}</span>}
      </span>
      <span className={`health-value${mono ? " mono" : ""}`}>{value}</span>
    </li>
  );
}

const TRANSPORT_COLUMNS = [
  { key: "transport", label: "Transport" },
  { key: "advertised", label: "In the DID document" },
  { key: "serviceable", label: "Serviceable now" },
  { key: "endpoint", label: "Advertised endpoint" },
] as const;

/** "Good morning", "Good afternoon" or "Good evening", and the name if any. */
export function greeting(now: Date, name?: string | null): string {
  const h = now.getHours();
  const part = h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
  return name ? `${part}, ${name}` : part;
}

/** The first word of a display name, without an `[unverified]` marker. */
function firstName(name: string | undefined): string | null {
  if (!name) return null;
  const clean = name.replace(/\[unverified\]/i, "").trim();
  if (!clean || clean.startsWith("did:")) return null;
  return clean.split(/\s+/)[0] ?? null;
}

/**
 * Trim a transport error to a row-sized line.
 *
 * These errors quote both parties' advertised sets and a full `did:webvh`,
 * which runs to five wrapped lines and pushes the rest of the dashboard down.
 * The Recognition page shows the whole thing; here it only has to be
 * recognisable.
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
  tone?: Tone;
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
  const className = `stat-tile${tone === "warn" ? " stat-tile--warn" : ""}`;
  return to ? (
    <Link to={to} className={className}>
      {body}
    </Link>
  ) : (
    <div className={className}>{body}</div>
  );
}
