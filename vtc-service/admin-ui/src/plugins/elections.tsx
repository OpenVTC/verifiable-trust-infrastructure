// Elections — the community's polls, surveys and elections, as their registrar
// runs them (`lib/elections-api.ts`, docs/03-vtc/elections.md).
//
// The list, one election's page (its disclosure, tickets issued, board
// checkpoints and, once certified, the result), and the administrator's four
// acts: create from a manifest (`ElectionBuilder.tsx`), close early, cancel, and certify. Certifying
// is the VTC re-verifying the ballot box's whole board from its own voting key,
// so a refusal there names what the board got wrong.
//
// Members take tickets and vote through their own VTA; nothing here can see or
// cast a ballot, and nothing here shows who took a ticket.

import { useMemo, useState } from "react";
import { Link, Route, Routes, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/Field";
import {
  ELECTIONS_KEY,
  STATE_LABEL,
  cancelElection,
  certifyElection,
  closeElection,
  fetchElection,
  fetchElections,
  fetchElectionsServed,
  type Election,
  type ElectionListItem,
  type ElectionResult,
  type QuestionResult,
} from "@/lib/elections-api";
import { listBoards } from "@/lib/boards";
import { MEMBER_OF_KIND_TEXT, textReleaseWarning } from "@/lib/election-manifest";
import { groupByBoard, stageSummary } from "@/lib/election-origin";
import { formatIso, shorten } from "@/lib/format";
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";
import { NewElection } from "@/plugins/ElectionBuilder";
import { Refusal } from "@/plugins/ElectionRefusal";

export function Elections() {
  const served = useQuery({
    queryKey: [...ELECTIONS_KEY, "served"],
    queryFn: fetchElectionsServed,
    retry: false,
    staleTime: Infinity,
  });
  if (served.isPending) return null;
  if (served.data === false) {
    return (
      <div className="page">
        <header className="page-header">
          <h1>Elections</h1>
        </header>
        <section className="card">
          <h2>Elections are not built into this VTC</h2>
          <p className="muted">
            Community elections are a build feature (<code>voting</code>). The host operator
            installs a VTC built with it — <code>cargo install vtc-service --features voting</code>{" "}
            — and names the voting services it trusts under <code>[voting]</code> in its
            configuration.
          </p>
        </section>
      </div>
    );
  }
  return (
    <Routes>
      <Route index element={<ElectionList />} />
      <Route path="new" element={<NewElection />} />
      <Route path=":electionId" element={<ElectionRoute />} />
    </Routes>
  );
}

function ElectionRoute() {
  const { electionId = "" } = useParams<{ electionId: string }>();
  return <ElectionPage electionId={electionId} />;
}

function ElectionList() {
  const list = useQuery({ queryKey: [...ELECTIONS_KEY, "list"], queryFn: fetchElections });
  // Only to name the boards elections came from: a viewer who may not list boards, or a read
  // that fails, still sees every election, grouped under the board's identifier.
  const boards = useQuery({ queryKey: ["boards"], queryFn: listBoards, retry: false });
  const titles = useMemo(
    () => (boards.data ? new Map(boards.data.map((b) => [b.boardId, b.title])) : null),
    [boards.data],
  );
  return (
    <div className="page">
      <header className="page-header">
        <h1>Elections</h1>
        <Link className="button" to="new">
          New election
        </Link>
      </header>
      <p className="muted">
        Polls, surveys and elections this community runs. The community issues each eligible
        member one ticket, blind; the ballot box each names counts the votes and keeps the board.
        This page never sees a ballot, or who took a ticket.
      </p>
      {list.isError && <Refusal title="Could not read the elections" error={list.error} />}
      {list.data && list.data.length === 0 && (
        <EmptyState title="No elections yet">Create one from its manifest.</EmptyState>
      )}
      {list.data && list.data.length > 0 && <GroupedElections items={list.data} titles={titles} />}
    </div>
  );
}

const ALL = "all";
const STANDALONE = "standalone";

/**
 * Stand-alone elections first, then one group per board its ideas' elections came from
 * (`board.<boardId>.<ideaId>`, VTI-BRD-031). `titles` is `null` until the boards are read, or
 * when they cannot be: the groups are then named by the board's identifier.
 */
function GroupedElections({ items, titles }: { items: ElectionListItem[]; titles: ReadonlyMap<string, string> | null }) {
  const grouped = useMemo(() => groupByBoard(items, titles, "Deleted board"), [items, titles]);
  const [show, setShow] = useState(ALL);
  if (grouped.boards.length === 0) return <ElectionsTable items={grouped.standalone} />;
  const label = (e: ElectionListItem) => STATE_LABEL[e.state] ?? e.state;
  const boards = show === ALL ? grouped.boards : grouped.boards.filter((b) => b.boardId === show);
  return (
    <>
      <div className="toolbar">
        <Field label="Show">
          <select value={show} onChange={(e) => setShow(e.target.value)} aria-label="Show">
            <option value={ALL}>All elections</option>
            <option value={STANDALONE}>Stand-alone only</option>
            {grouped.boards.map((b) => (
              <option key={b.boardId} value={b.boardId}>
                {b.title} ({b.items.length})
              </option>
            ))}
          </select>
        </Field>
      </div>
      {(show === ALL || show === STANDALONE) && grouped.standalone.length > 0 && (
        <section aria-label="Stand-alone elections">
          <h2>Stand-alone</h2>
          <ElectionsTable items={grouped.standalone} />
        </section>
      )}
      {show === STANDALONE && grouped.standalone.length === 0 && (
        <EmptyState title="No stand-alone elections">Every election here came from a board.</EmptyState>
      )}
      {show !== STANDALONE &&
        boards.map((b) => (
          <details key={b.boardId} className="card election-group" open>
            <summary>
              <strong>{b.title}</strong> · {b.items.length} election{b.items.length === 1 ? "" : "s"}
              <span className="muted"> · {stageSummary(b.items, label)}</span>
            </summary>
            {b.known && (
              <p className="muted rooms-sub">
                <Link to={`/boards/${encodeURIComponent(b.boardId)}`}>Open the board</Link>
              </p>
            )}
            <ElectionsTable items={b.items} fromBoard />
          </details>
        ))}
    </>
  );
}

/** `fromBoard`: the rows are one board's ideas, so their generated identifier is left out. */
function ElectionsTable({ items, fromBoard = false }: { items: ElectionListItem[]; fromBoard?: boolean }) {
  return (
    <DataTable
      columns={[
        { key: "election", label: fromBoard ? "Idea" : "Election" },
        { key: "state", label: "State" },
        { key: "voting", label: "Voting" },
        { key: "binding", label: "Binding" },
      ]}
    >
      {items.map((e) => (
        <tr key={e.electionId}>
          <td>
            <Link to={encodeURIComponent(e.electionId)}>{e.title || e.electionId}</Link>
            {e.title && !fromBoard && (
              <div className="muted rooms-sub">
                <code>{e.electionId}</code>
              </div>
            )}
          </td>
          <td>{STATE_LABEL[e.state] ?? e.state}</td>
          <td>
            {formatIso(e.votingOpensAt)}
            <div className="muted rooms-sub">to {formatIso(e.votingClosesAt)}</div>
          </td>
          <td>{e.binding ? "Binding" : ""}</td>
        </tr>
      ))}
    </DataTable>
  );
}

function ElectionPage({ electionId }: { electionId: string }) {
  const election = useQuery({
    queryKey: [...ELECTIONS_KEY, "show", electionId],
    queryFn: () => fetchElection(electionId),
  });
  return (
    <div className="page">
      <header className="page-header">
        <h1>{election.data?.manifest.title || electionId}</h1>
        <Link to="..">All elections</Link>
      </header>
      {election.isError && <Refusal title="Could not read the election" error={election.error} />}
      {election.data && <ElectionDetail electionId={electionId} e={election.data} />}
    </div>
  );
}

function ElectionDetail({ electionId, e }: { electionId: string; e: Election }) {
  const d = e.disclosure;
  // VTI-VOT-090: below 10, members are told that a written answer may identify its author.
  const release = e.manifest.textReleaseThreshold;
  const releaseWarning = textReleaseWarning(release);
  // VTI-VOT-090: under a credential roll, whose membership credential counts.
  const roll = d.rollCredential;
  return (
    <>
      <section className="card">
        <dl className="kv">
          <dt>State</dt>
          <dd>{STATE_LABEL[e.state] ?? e.state}</dd>
          <dt>Identifier</dt>
          <dd>
            <code>{electionId}</code>
          </dd>
          <dt>Tickets from</dt>
          <dd>{formatIso(e.manifest.registrationOpensAt)}</dd>
          <dt>Voting</dt>
          <dd>
            {formatIso(e.manifest.votingOpensAt)} to {formatIso(e.manifest.votingClosesAt)}
          </dd>
          <dt>Binding</dt>
          <dd>{e.manifest.binding ? "Yes — the result decides something in the community's name" : "No"}</dd>
          <dt>Tickets issued</dt>
          <dd>
            {e.ticketsIssued ?? "—"}
            {roll && (
              // VTI-VOT-028: the community cannot know how many the roll admits.
              <div className="muted">
                Who may vote is proven when each ticket is claimed, so there is no roll size:
                turnout is counted ballots against tickets issued.
              </div>
            )}
          </dd>
          <dt>Manifest digest</dt>
          <dd>
            <code title={e.manifestDigest}>{shorten(e.manifestDigest, 12, 6)}</code>
          </dd>
        </dl>
      </section>
      <section className="card">
        <h2>What members are told</h2>
        <p className="muted">
          Every member sees this before taking a ticket, so they know who could learn what about
          their vote. It comes from the election&rsquo;s settings and the ballot box you chose.
        </p>
        <dl className="kv">
          <dt>Ballot box</dt>
          <dd>
            Run by {d.ballotBoxOperator} (<code title={d.ballotBox}>{shorten(d.ballotBox, 16, 6)}</code>).
            Members send their votes there directly, never through this community.
            {d.sameOperator && (
              <div className="warning-text">
                {d.ballotBoxOperator} also runs this community. Tickets are signed blind, so a
                ballot cannot be matched to a member from the data alone, but an operator that runs
                both could match them by when a ticket was taken and when a vote arrived. Fine for
                informal polls; use an independent ballot box for anything sensitive.
              </div>
            )}
          </dd>
          <dt>Who can see the ballots</dt>
          <dd>
            {d.boardVisibility === "public"
              ? "Anyone. The ballot box publishes every ballot on its board, under one-time keys that never name the member."
              : "Only this community and its auditors can read the ballot box's board."}
            {d.auditors.length > 0 && ` Auditors: ${d.auditors.join(", ")}.`}
          </dd>
          <dt>Changing a vote</dt>
          <dd>
            {d.revote === "replace"
              ? "Allowed: a member can vote again, and only their latest vote counts."
              : "Not allowed: a member's first vote is final."}
          </dd>
          {release !== undefined && (
            <>
              <dt>Written answers</dt>
              <dd>
                Released once {release} {release === 1 ? "ballot is" : "ballots are"} counted,
                never while voting is open.
                {releaseWarning && <div className="warning-text">{releaseWarning}</div>}
              </dd>
            </>
          )}
          {roll && (
            <>
              <dt>Whose credential counts</dt>
              <dd>
                A membership credential issued by{" "}
                {roll.memberOfName ? <strong>{roll.memberOfName}</strong> : "the party"} (
                <code title={roll.memberOf}>{shorten(roll.memberOf, 16, 6)}</code>),{" "}
                {MEMBER_OF_KIND_TEXT[roll.memberOfKind] ?? roll.memberOfKind}. Claiming a ticket shows
                this community the member&rsquo;s membership of that party.
                {roll.memberOfKind === "memberParty" && (
                  <div className="muted">
                    Shown only to this community&rsquo;s election managers, the party itself, and a
                    reader who presents that party&rsquo;s membership in reading it — so reading it
                    already shows the community that membership. It never appears in members&rsquo;
                    election lists.
                  </div>
                )}
              </dd>
            </>
          )}
          <dt>Pressure to vote a certain way</dt>
          <dd>
            Not protected against. A member can prove how they voted, so someone could demand that
            proof from them.
          </dd>
        </dl>
      </section>
      {e.certified && (
        <section className="card success">
          <h2>Certified result</h2>
          <p className="muted">
            Certified {formatIso(e.certified.certifiedAt)}. {e.certified.result.ballotsCounted}{" "}
            {e.certified.result.ballotsCounted === 1 ? "ballot" : "ballots"} counted. The ballot
            box&rsquo;s board holds {e.certified.result.head.treeSize}{" "}
            {e.certified.result.head.treeSize === 1 ? "entry" : "entries"} (every vote cast,
            including any a later vote replaced), and this community checked it itself.
          </p>
          <ResultTable result={e.certified.result} manifest={e.manifest} />
        </section>
      )}
      <section className="card">
        <h2>Board checkpoints</h2>
        <p className="muted">
          Each time this community reads the ballot box&rsquo;s board, it keeps a fingerprint of
          it. Certifying the result checks the final board still holds everything every
          fingerprint covered, so no ballot can be dropped or changed afterwards without it
          showing.
        </p>
        {e.checkpoints.length === 0 ? (
          <p className="muted">None yet.</p>
        ) : (
          <ul>
            {e.checkpoints.map((c) => (
              <li key={`${c.head.treeSize}-${c.head.rootHash}`}>
                {formatIso(c.head.issuedAt)}: {c.head.treeSize}{" "}
                {c.head.treeSize === 1 ? "ballot" : "ballots"} on the board, fingerprint{" "}
                <code title={c.head.rootHash}>{shorten(c.head.rootHash, 10, 4)}</code>
              </li>
            ))}
          </ul>
        )}
      </section>
      <ElectionActions electionId={electionId} e={e} />
    </>
  );
}

type ManifestQuestion = Election["manifest"]["questions"][number];

function optionLabel(q: ManifestQuestion | undefined, key: string): string {
  return q?.options?.find((o) => o.key === key)?.label || key;
}

function abstainedLine(n: number) {
  return n > 0 ? (
    <p className="muted">
      {n} {n === 1 ? "ballot" : "ballots"} left this question blank.
    </p>
  ) : null;
}

/** One question's totals, in the words the members were asked in. */
function QuestionTotals({
  r,
  q,
  counted,
  threshold,
}: {
  r: QuestionResult;
  q: ManifestQuestion | undefined;
  counted: number;
  threshold: number | undefined;
}) {
  if (r.choice) {
    const rows = Object.entries(r.choice).sort((a, b) => b[1] - a[1]);
    return (
      <>
        <ul>
          {rows.map(([k, n]) => (
            <li key={k}>
              {optionLabel(q, k)}: <strong>{n}</strong>
            </li>
          ))}
        </ul>
        {abstainedLine(r.abstained)}
      </>
    );
  }
  if (r.ranking) {
    const rows = Object.entries(r.ranking).sort((a, b) => (b[1][0] ?? 0) - (a[1][0] ?? 0));
    return (
      <>
        <p className="muted">How many ballots put each option in each place.</p>
        <table>
          <thead>
            <tr>
              <th>Option</th>
              {(rows[0]?.[1] ?? []).map((_, i) => (
                <th key={i}>#{i + 1}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map(([k, places]) => (
              <tr key={k}>
                <td>{optionLabel(q, k)}</td>
                {places.map((n, i) => (
                  <td key={i}>{n}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {abstainedLine(r.abstained)}
      </>
    );
  }
  if (r.score) {
    return (
      <>
        <ul>
          {Object.entries(r.score).map(([k, v]) => {
            const { sum, count } = v as { sum: number; count: number };
            return (
              <li key={k}>
                {optionLabel(q, k)}: average <strong>{count ? (sum / count).toFixed(1) : "—"}</strong> from{" "}
                {count} {count === 1 ? "score" : "scores"}
              </li>
            );
          })}
        </ul>
        {abstainedLine(r.abstained)}
      </>
    );
  }
  if (r.text) {
    return (
      <>
        {r.text.length === 0 ? (
          <p className="muted">No answers.</p>
        ) : (
          <ul className="election-texts">
            {r.text.map((t, i) => (
              <li key={i} className="election-description">
                {String(t)}
              </li>
            ))}
          </ul>
        )}
        {abstainedLine(r.abstained)}
      </>
    );
  }
  if (r.withheld) {
    return (
      <p className="muted">
        Answers held back: written answers are shown only once at least {threshold ?? "the set number of"}{" "}
        ballots are counted, and this election counted {counted}. With so few, an answer could point to
        who wrote it. Set a lower &ldquo;text release threshold&rdquo; on a future election if that is
        acceptable for it.
      </p>
    );
  }
  return abstainedLine(r.abstained);
}

function ResultTable({ result, manifest }: { result: ElectionResult; manifest: Election["manifest"] }) {
  return (
    <>
      {result.questions.map((r) => {
        const q = manifest.questions.find((x) => x.key === r.question);
        return (
          <div key={r.question}>
            <h3>{q?.text || r.question}</h3>
            <QuestionTotals
              r={r}
              q={q}
              counted={result.ballotsCounted}
              threshold={manifest.textReleaseThreshold}
            />
          </div>
        );
      })}
    </>
  );
}

function ElectionActions({ electionId, e }: { electionId: string; e: Election }) {
  const confirm = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const [attestations, setAttestations] = useState("");
  const refresh = () => void queryClient.invalidateQueries({ queryKey: ELECTIONS_KEY });
  const gesture = gestureFromConfirm(confirm);

  const close = useMutation({
    mutationFn: () => closeElection(electionId, reason, gesture),
    onSuccess: () => {
      toast.push("success", `Closed ${electionId}.`);
      refresh();
    },
  });
  const cancel = useMutation({
    mutationFn: async () => {
      const ok = await confirm({
        title: `Cancel ${electionId}?`,
        message: "Ticket issuance stops at once and is never resumed. The ballot box is then asked to cancel it.",
        confirmLabel: "Cancel the election",
      });
      if (!ok) throw new Error("Not cancelled.");
      return cancelElection(electionId, reason, gesture);
    },
    onSuccess: () => {
      toast.push("success", `Cancelled ${electionId}.`);
      refresh();
    },
  });
  let parsedAttestations: unknown[] | null = [];
  if (attestations.trim()) {
    try {
      const v: unknown = JSON.parse(attestations);
      parsedAttestations = Array.isArray(v) ? v : [v];
    } catch {
      parsedAttestations = null;
    }
  }
  const certify = useMutation({
    mutationFn: () => certifyElection(electionId, parsedAttestations ?? [], gesture),
    onSuccess: (r) => {
      toast.push("success", `Certified ${electionId}: ${r.result.ballotsCounted} ballots counted.`);
      refresh();
    },
  });

  const open = e.state === "voting";
  const ended = e.state === "closed" || e.state === "tallied" || e.state === "cancelled";
  if (e.certified || e.state === "cancelled") return null;
  return (
    <section className="card">
      <h2>Act on it</h2>
      <Field label="Reason" hint="Kept in the audit trail. Required to cancel.">
        <input value={reason} onChange={(ev) => setReason(ev.target.value)} />
      </Field>
      <div className="form-actions">
        {open && e.manifest.allowEarlyClose && (
          <button type="button" className="secondary" onClick={() => close.mutate()} disabled={close.isPending}>
            Close early
          </button>
        )}
        {!ended && (
          <button
            type="button"
            className="secondary destructive"
            onClick={() => cancel.mutate()}
            disabled={cancel.isPending || !reason.trim()}
          >
            Cancel the election
          </button>
        )}
      </div>
      {ended && (
        <>
          <Field
            label="Auditors' attestations"
            hint="Optional: verifiable credentials from auditors the manifest names, as JSON (one, or an array). Kept exactly as given, beside the community's own verification."
            error={parsedAttestations === null ? "Not JSON." : undefined}
          >
            <textarea
              rows={6}
              spellCheck={false}
              className="mono"
              value={attestations}
              onChange={(ev) => setAttestations(ev.target.value)}
            />
          </Field>
          <button className="primary"
            type="button"
            onClick={() => certify.mutate()}
            disabled={certify.isPending || parsedAttestations === null}
          >
            Certify the result
          </button>
        </>
      )}
      <Refusal title="Not closed" error={close.error} />
      <Refusal title="Not cancelled" error={cancel.error} />
      <Refusal title="Not certified" error={certify.error} />
    </section>
  );
}
