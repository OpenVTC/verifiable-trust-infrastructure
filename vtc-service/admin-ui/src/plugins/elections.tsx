// Elections — the community's polls, surveys and elections, as their registrar
// runs them (`lib/elections-api.ts`, docs/03-vtc/elections.md).
//
// The list, one election's page (its disclosure, tickets issued, board
// checkpoints and, once certified, the result), and the administrator's four
// acts: create from a manifest, close early, cancel, and certify. Certifying
// is the VTC re-verifying the ballot box's whole board from its own voting key,
// so a refusal there names what the board got wrong.
//
// Members take tickets and vote through their own VTA; nothing here can see or
// cast a ballot, and nothing here shows who took a ticket.

import { useState } from "react";
import { Link, Route, Routes, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { ErrorOrParked } from "@/components/ParkedNotice";
import { Field } from "@/components/Field";
import { vtcDid } from "@/lib/api";
import {
  ELECTIONS_KEY,
  STATE_LABEL,
  cancelElection,
  certifyElection,
  closeElection,
  createElection,
  fetchElection,
  fetchElections,
  fetchElectionsServed,
  refusalHint,
  sampleManifest,
  type Election,
  type ElectionListItem,
  type ElectionResult,
} from "@/lib/elections-api";
import { formatIso, shorten } from "@/lib/format";
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";

function codeOf(e: unknown): string | undefined {
  const c = (e as { code?: unknown } | null)?.code;
  return typeof c === "string" ? c : undefined;
}

function Refusal({ title, error }: { title: string; error: unknown }) {
  if (!error) return null;
  const hint = refusalHint(codeOf(error));
  return (
    <>
      <ErrorOrParked title={title} error={error} />
      {hint && <p className="community-fix">{hint}</p>}
    </>
  );
}

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
      {list.data && list.data.length > 0 && <ElectionsTable items={list.data} />}
    </div>
  );
}

function ElectionsTable({ items }: { items: ElectionListItem[] }) {
  return (
    <DataTable
      columns={[
        { key: "election", label: "Election" },
        { key: "state", label: "State" },
        { key: "voting", label: "Voting" },
        { key: "binding", label: "Binding" },
      ]}
    >
      {items.map((e) => (
        <tr key={e.electionId}>
          <td>
            <Link to={encodeURIComponent(e.electionId)}>{e.title || e.electionId}</Link>
            {e.title && (
              <div className="muted rooms-sub">
                <code>{e.electionId}</code>
              </div>
            )}
          </td>
          <td>{STATE_LABEL[e.state] ?? e.state}</td>
          <td>
            {formatIso(e.votingOpens)}
            <div className="muted rooms-sub">to {formatIso(e.votingCloses)}</div>
          </td>
          <td>{e.binding ? "Binding" : ""}</td>
        </tr>
      ))}
    </DataTable>
  );
}

function NewElection() {
  const confirm = useConfirm();
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [text, setText] = useState("");
  const [box, setBox] = useState("");
  let parsed: Record<string, unknown> | null = null;
  let parseError: string | undefined;
  if (text.trim()) {
    try {
      const v: unknown = JSON.parse(text);
      if (v && typeof v === "object" && !Array.isArray(v)) parsed = v as Record<string, unknown>;
      else parseError = "The manifest is a JSON object.";
    } catch (e) {
      parseError = `Not JSON: ${(e as Error).message}`;
    }
  }
  const create = useMutation({
    mutationFn: () => createElection(parsed ?? {}, gestureFromConfirm(confirm)),
    onSuccess: (r) => {
      toast.push(
        "success",
        r.state === "registered"
          ? `Created ${r.electionId}; the ballot box registered it.`
          : `Created ${r.electionId}; the community keeps delivering it to the ballot box.`,
      );
      void queryClient.invalidateQueries({ queryKey: ELECTIONS_KEY });
      navigate(`../${encodeURIComponent(r.electionId)}`);
    },
  });
  return (
    <div className="page">
      <header className="page-header">
        <h1>New election</h1>
        <Link to="..">All elections</Link>
      </header>
      <section className="card">
        <p className="muted">
          The manifest says what is asked, who may vote, when, and which ballot box counts. It is
          sent exactly as written: every ticket and every vote is bound to its digest. The ballot
          box must be one of this community&rsquo;s trusted voting services. A binding election
          (<code>&quot;binding&quot;: true</code>) is sent for another administrator&rsquo;s
          approval before it is created.
        </p>
        <form
          className="form-stack"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <Field label="Ballot box DID" hint="To start from a sample manifest that names it.">
            <input value={box} onChange={(e) => setBox(e.target.value)} placeholder="did:webvh:…" />
          </Field>
          <button
            type="button"
            className="secondary"
            disabled={!box.trim()}
            onClick={async () => setText(sampleManifest(await vtcDid(), box.trim()))}
          >
            Start from a sample
          </button>
          <Field label="Manifest" error={parseError}>
            <textarea
              rows={24}
              spellCheck={false}
              className="mono"
              value={text}
              onChange={(e) => setText(e.target.value)}
            />
          </Field>
          <button type="submit" disabled={!parsed || create.isPending}>
            Create
          </button>
        </form>
      </section>
      <Refusal title="The election was not created" error={create.error} />
    </div>
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
  return (
    <>
      <section className="card">
        <dl className="detail-list">
          <dt>State</dt>
          <dd>{STATE_LABEL[e.state] ?? e.state}</dd>
          <dt>Identifier</dt>
          <dd>
            <code>{electionId}</code>
          </dd>
          <dt>Tickets from</dt>
          <dd>{formatIso(e.manifest.registrationOpens)}</dd>
          <dt>Voting</dt>
          <dd>
            {formatIso(e.manifest.votingOpens)} to {formatIso(e.manifest.votingCloses)}
          </dd>
          <dt>Binding</dt>
          <dd>{e.manifest.binding ? "Yes — the result decides something in the community's name" : "No"}</dd>
          <dt>Tickets issued</dt>
          <dd>{e.ticketsIssued ?? "—"}</dd>
          <dt>Manifest digest</dt>
          <dd>
            <code title={e.manifestDigest}>{shorten(e.manifestDigest, 12, 6)}</code>
          </dd>
        </dl>
      </section>
      <section className="card">
        <h2>What members are told</h2>
        <p className="muted">
          Generated from the manifest and the trusted ballot box&rsquo;s entry, and shown to every
          member before they take a ticket.
        </p>
        <dl className="detail-list">
          <dt>Ballot box</dt>
          <dd>
            <code title={d.ballotBox}>{shorten(d.ballotBox, 16, 6)}</code>, run by {d.ballotBoxOperator}
            {d.sameOperator && (
              <div className="warning-text">
                Run by the same operator as this community: they could see who took a ticket and
                every ballot.
              </div>
            )}
          </dd>
          <dt>Board</dt>
          <dd>
            {d.boardVisibility}
            {d.auditors.length > 0 && `, auditors: ${d.auditors.join(", ")}`}
          </dd>
          <dt>Changing a vote</dt>
          <dd>{d.revote === "replace" ? "A later vote replaces the earlier one" : "The first vote stands"}</dd>
          <dt>Coercion</dt>
          <dd>Not resisted: a member can prove how they voted.</dd>
        </dl>
      </section>
      {e.certified && (
        <section className="card success">
          <h2>Certified result</h2>
          <p className="muted">
            Certified {formatIso(e.certified.certifiedAt)}: {e.certified.result.ballotsCounted}{" "}
            ballots counted, from a board of {e.certified.result.head.treeSize} entries the
            community verified itself.
          </p>
          <ResultTable result={e.certified.result} />
        </section>
      )}
      <section className="card">
        <h2>Board checkpoints</h2>
        <p className="muted">
          Heads of the ballot box&rsquo;s board the community read and kept. Certification
          checks the final board extends every one.
        </p>
        {e.checkpoints.length === 0 ? (
          <p className="muted">None yet.</p>
        ) : (
          <ul>
            {e.checkpoints.map((c) => (
              <li key={`${c.head.treeSize}-${c.head.rootHash}`}>
                {formatIso(c.head.issuedAt)} — {c.head.treeSize} entries,{" "}
                <code>{shorten(c.head.rootHash, 10, 4)}</code>
              </li>
            ))}
          </ul>
        )}
      </section>
      <ElectionActions electionId={electionId} e={e} />
    </>
  );
}

function ResultTable({ result }: { result: ElectionResult }) {
  return (
    <>
      {result.questions.map((q) => (
        <div key={q.question}>
          <h3>{q.question}</h3>
          {q.choice && (
            <ul>
              {Object.entries(q.choice).map(([k, n]) => (
                <li key={k}>
                  {k}: {n}
                </li>
              ))}
              <li className="muted">abstained: {q.abstained}</li>
            </ul>
          )}
        </div>
      ))}
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
      <div className="button-row">
        {open && e.manifest.allowEarlyClose && (
          <button type="button" className="secondary" onClick={() => close.mutate()} disabled={close.isPending}>
            Close early
          </button>
        )}
        {!ended && (
          <button
            type="button"
            className="danger"
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
          <button
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
