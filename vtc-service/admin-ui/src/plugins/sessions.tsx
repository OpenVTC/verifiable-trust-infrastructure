// Sessions plugin — list + revoke active sessions.
//
// Signed `auth/sessions/list/0.1` and `auth/revoke-session/0.2` documents.
// Lists every live session the operator may end — their own, and those of
// every subject whose access they could withdraw — marks the caller's own
// session (so an operator who clicks Revoke on themselves understands
// they're about to be signed out), and offers per-session revoke +
// "revoke all of this DID" buttons.
//
// Purpose: if an operator suspects a cookie has been stolen, they
// open this and revoke the suspect session without having to nuke
// every credential they hold. The backend already enforces that you
// can only see and revoke sessions whose subject's access you could withdraw.

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Smartphone } from "lucide-react";

import { postSignedRead, postSignedTrustTask, WhoamiResponse } from "@/lib/api";
import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/Field";
import { PageHeader } from "@/components/PageHeader";
import { formatIso, shorten as shortId } from "@/lib/format";
import { useNameBook } from "@/lib/names";
import { NamedDid } from "@/components/NamedDid";
import { useToast } from "@/lib/toast";

type SortKey = "subject" | "acr" | "issuedAt" | "expiresAt";
type SortDir = "asc" | "desc";

const TRUST_TASK_LIST =
  "https://trusttasks.org/spec/auth/sessions/list/0.1";
// One session, or every session of a subject: the two forms of one task.
const TRUST_TASK_REVOKE =
  "https://trusttasks.org/spec/auth/revoke-session/0.2";

import type { SessionListResponse, SessionView } from "@/lib/wire-types";
async function fetchSessions(): Promise<SessionView[]> {
  const body = await postSignedRead<SessionListResponse>(TRUST_TASK_LIST, {});
  return body.sessions;
}

// `revokedCount` is 0 when there was no such session this operator may end —
// already gone, or outside their authority; the VTC answers both alike.
async function revokeSession(sessionId: string): Promise<number> {
  const body = await postSignedTrustTask<{ revokedCount: number }>(TRUST_TASK_REVOKE, {
    sessionId,
  });
  return body.revokedCount;
}

async function revokeAllForDid(did: string): Promise<void> {
  await postSignedTrustTask<{ revokedCount: number }>(TRUST_TASK_REVOKE, { subject: did });
}

export function Sessions() {
  const nameBook = useNameBook();
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const [filterText, setFilterText] = useState("");
  // Default sort = newest first by created time. Click a header to
  // toggle direction; clicking a different header switches the sort
  // key with sensible-for-that-column default direction.
  const [sortKey, setSortKey] = useState<SortKey>("issuedAt");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const sessionsQuery = useQuery({
    queryKey: ["sessions"],
    queryFn: fetchSessions,
  });

  // Whoami is already populated by the App shell via
  // `probeSession`. Reading the cached value via `getQueryData`
  // (rather than declaring our own `useQuery({queryKey:["whoami"]})`
  // with `fetchWhoami` as `queryFn`) avoids two pitfalls:
  //   1. Two `useQuery`s sharing a key but with different `queryFn`s
  //      race each other on cache miss; whichever fires first wins
  //      and the other view gets stale data.
  //   2. `fetchWhoami` throws on 401, but `probeSession` returns
  //      null. A stale-cache refetch here on a logged-out session
  //      would surface a misleading toast.
  // The session-expiry handler in App.tsx invalidates this key, so
  // any change to the live session re-flows through that path
  // before reaching us.
  const whoami = qc.getQueryData<WhoamiResponse | null>(["whoami"]);

  const revokeOne = useMutation({
    mutationFn: revokeSession,
    onSuccess: (revokedCount, sessionId) => {
      toast.push(
        "success",
        revokedCount > 0
          ? `Revoked session ${shortId(sessionId)}`
          : `Session ${shortId(sessionId)} was already gone`,
      );
      void qc.invalidateQueries({ queryKey: ["sessions"] });
      // If the operator revoked themselves, the whoami probe will
      // flip to null on next refetch and the shell shows Login.
      void qc.invalidateQueries({ queryKey: ["whoami"] });
    },
    onError: (err) => toast.pushFromError(err, "Revoke failed"),
  });

  const revokeMany = useMutation({
    mutationFn: revokeAllForDid,
    onSuccess: (_, did) => {
      toast.push("success", `Revoked every session for ${did}`);
      void qc.invalidateQueries({ queryKey: ["sessions"] });
      void qc.invalidateQueries({ queryKey: ["whoami"] });
    },
    onError: (err) => toast.pushFromError(err, "Bulk revoke failed"),
  });

  const allSessions = sessionsQuery.data ?? [];
  const myDid = whoami?.session.subject;
  const mySessionId = whoami?.session.id;

  // Filter on substring match against either identifier, then sort.
  // useMemo so revoke-button clicks (which mutate React Query
  // queries that re-render this component) don't re-do this work on
  // every keystroke / button click.
  const sessions = useMemo(() => {
    const needle = filterText.trim().toLowerCase();
    const filtered = needle
      ? allSessions.filter((s) =>
          (s.subject + " " + s.id + " " + (s.acr ?? ""))
            .toLowerCase()
            .includes(needle),
        )
      : allSessions;
    const sorted = [...filtered].sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      if (av === bv) return 0;
      // Blanks sort last regardless of direction so they don't crowd the top.
      // Both emptinesses count: `acr` is optional, so the generated type
      // admits `undefined` as well as `null`.
      const aEmpty = av === null || av === undefined;
      const bEmpty = bv === null || bv === undefined;
      if (aEmpty && bEmpty) return 0;
      if (aEmpty) return 1;
      if (bEmpty) return -1;
      const cmp = av < bv ? -1 : 1;
      return sortDir === "asc" ? cmp : -cmp;
    });
    return sorted;
  }, [allSessions, filterText, sortKey, sortDir]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
      return;
    }
    setSortKey(key);
    // Timestamps default descending (most recent first); strings
    // default ascending (A → Z).
    setSortDir(key === "issuedAt" || key === "expiresAt" ? "desc" : "asc");
  };

  // Group "revoke all for this DID" by DID — only show on the first
  // row of each DID block.
  const seenDids = new Set<string>();

  return (
    <section className="page">
      <PageHeader
        count={sessionsQuery.isPending ? undefined : allSessions.length}
        countLabel={`${allSessions.length} active sessions`}
        lead={
          <>
            Active server-side sessions in the daemon's session store. If a
            cookie has been compromised, revoke its session here — the
            browser holding it will be signed out on its next request.
          </>
        }
      />

      {sessionsQuery.isPending && (
        <section className="card">
          <p>Loading sessions…</p>
        </section>
      )}

      {!sessionsQuery.isPending && (
        <section className="card">
          <div className="toolbar">
            <Field label="Filter" inline>
              <input
                type="search"
                placeholder="DID, session id, or assurance"
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
              />
            </Field>
            <span className="muted">
              {sessions.length} of {allSessions.length}
              {filterText.trim() && sessions.length !== allSessions.length
                ? " filtered"
                : ""}
            </span>
          </div>
        </section>
      )}

      {sessions.length === 0 && !sessionsQuery.isPending && (
        <section className="card">
          <EmptyState
            icon={Smartphone}
            title={
              allSessions.length === 0
                ? "No active sessions"
                : "No sessions match this filter"
            }
          >
            {allSessions.length === 0
              ? "Sessions appear here when an operator signs in."
              : "Clear the search box to see every active session."}
          </EmptyState>
        </section>
      )}

      {sessions.length > 0 && (
        <section className="card">
          <DataTable
            caption="Active sessions"
            sort={{ key: sortKey, dir: sortDir }}
            onSort={handleSort}
            columns={[
              { key: "subject", label: "DID", sortKey: "subject" },
              { key: "session", label: "Session" },
              { key: "acr", label: "Assurance", sortKey: "acr" },
              { key: "issuedAt", label: "Created", sortKey: "issuedAt" },
              { key: "expiresAt", label: "Expires", sortKey: "expiresAt" },
              { key: "actions", label: <span className="visually-hidden">Actions</span> },
            ]}
          >
            {sessions.map((s) => {
              const isMine = s.id === mySessionId;
              const showBulk = !seenDids.has(s.subject);
              seenDids.add(s.subject);
              const sameDidCount = sessions.filter(
                (x) => x.subject === s.subject,
              ).length;
              return (
                <tr key={s.id}>
                  <td>
                    <NamedDid book={nameBook} did={s.subject} />
                    {s.subject === myDid && (
                      <span className="chip accent" title="Your DID">
                        you
                      </span>
                    )}
                  </td>
                  <td>
                    <code className="truncate" title={s.id}>
                      {shortId(s.id)}
                    </code>
                    {isMine && (
                      <span className="chip accent" title="This browser tab">
                        this tab
                      </span>
                    )}
                  </td>
                  <td>
                    {s.acr ? <code>{s.acr}</code> : <span className="muted">—</span>}
                  </td>
                  <td>{formatIso(s.issuedAt)}</td>
                  <td>{formatIso(s.expiresAt)}</td>
                  <td>
                    <div className="row-actions">
                      <button
                        type="button"
                        className="secondary destructive"
                        disabled={revokeOne.isPending}
                        aria-busy={revokeOne.isPending}
                        onClick={async () => {
                          const ok = await confirm({
                            title: isMine
                              ? "Revoke your own session?"
                              : `Revoke session ${shortId(s.id)}?`,
                            message: isMine
                              ? "You'll be signed out of this tab."
                              : `${s.subject} loses this session immediately.`,
                            confirmLabel: "Revoke",
                            destructive: true,
                          });
                          if (ok) revokeOne.mutate(s.id);
                        }}
                      >
                        Revoke
                      </button>
                      {showBulk && sameDidCount > 1 && (
                        <button
                          type="button"
                          className="secondary destructive"
                          disabled={revokeMany.isPending}
                          aria-busy={revokeMany.isPending}
                          title={`Revoke all ${sameDidCount} sessions for ${s.subject}`}
                          onClick={async () => {
                            const ok = await confirm({
                              title: `Revoke all sessions for ${s.subject}?`,
                              message: `${sameDidCount} active sessions will be terminated immediately.`,
                              confirmLabel: "Revoke all",
                              destructive: true,
                            });
                            if (ok) revokeMany.mutate(s.subject);
                          }}
                        >
                          Revoke all for DID
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </DataTable>
        </section>
      )}
    </section>
  );
}
