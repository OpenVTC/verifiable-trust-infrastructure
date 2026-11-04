// Community boards, for facilitators (`vtc/boards`, docs/03-vtc/boards.md).
//
//   /boards        Every board this administrator facilitates; create one.
//   /boards/:id    One board: decide its proposed ideas, select among tallied ones, hide notes,
//                  close or archive it.
//
// Members propose and leave notes from the member portal; this page never writes as a member.
// Accepting an idea opens its election from the board's template — the result is shown here once
// the ballot box publishes it, beside the decision, and the decision may depart from it
// (VTI-BRD-041). Nothing here ever shows who took a ticket or voted (VTI-BRD-033).

import { useMemo, useState } from "react";
import { Route, Routes, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, EyeOff, GitMerge, Plus, RotateCcw, SquareKanban, Trash2, X } from "lucide-react";

import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/Field";
import { PageHeader } from "@/components/PageHeader";
import {
  BOARDS_KEY,
  BOARDS_MANAGE,
  ELECTIONS_MANAGE,
  createBoard,
  decideIdea,
  defaultTemplate,
  fromLocalInput,
  hideNote,
  listAllNotes,
  listBoards,
  pendingOf,
  scheduleProblem,
  selectIdea,
  showBoard,
  slotLabel,
  toLocalInput,
  updateBoard,
  type Board,
  type Idea,
  type Note,
  type Slot,
} from "@/lib/boards";
import { fetchTrustedBallotBoxes } from "@/lib/elections-api";
import { listGroups } from "@/lib/groups";
import { useToast } from "@/lib/toast";
import { holds, useCapabilities } from "@/lib/viewer";

export function Boards() {
  return (
    <section className="page">
      <Routes>
        <Route index element={<BoardsList />} />
        <Route path=":id" element={<BoardDetail />} />
      </Routes>
    </section>
  );
}

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function phaseWords(b: Board, now = Date.now()): string {
  if (b.status !== "open") return b.status === "closed" ? "Closed" : "Archived";
  if (now < Date.parse(b.proposals.opensAt)) return "Not open yet";
  if (now >= Date.parse(b.voting.closesAt)) return "Counting";
  const proposing = now < Date.parse(b.proposals.closesAt);
  const voting = now >= Date.parse(b.voting.opensAt);
  return proposing && voting ? "Proposals and voting" : proposing ? "Taking proposals" : "Voting";
}

// ── The list ────────────────────────────────────────────────────────────────

function BoardsList() {
  const caps = useCapabilities();
  const navigate = useNavigate();
  const [creating, setCreating] = useState(false);
  const list = useQuery({ queryKey: BOARDS_KEY, queryFn: listBoards });
  const items = list.data ?? [];
  // A board's template opens elections, so creating one takes both (VTI-BRD-002).
  const mayCreate = holds(caps, BOARDS_MANAGE) && holds(caps, ELECTIONS_MANAGE);
  return (
    <>
      <PageHeader
        count={list.data ? items.length : null}
        countLabel={list.data ? `${items.length} boards` : undefined}
        lead="Members propose ideas and leave notes from the member portal. Each idea you accept is put to its own election, from the template the board was created with; you choose among them once the counts are in."
        actions={
          mayCreate && (
            <button type="button" className={creating ? "secondary" : "primary"} onClick={() => setCreating(!creating)}>
              <Plus size={14} aria-hidden="true" /> New board
            </button>
          )
        }
      />
      {creating && <CreateBoardForm onDone={() => setCreating(false)} />}
      {list.error && (
        <section className="card error">
          <h3>Failed to read the boards</h3>
          <p>{(list.error as Error).message}</p>
        </section>
      )}
      <section className="card table-card">
        <DataTable
          caption="Boards"
          columns={[
            { key: "title", label: "Board" },
            { key: "phase", label: "Now" },
            { key: "ideas", label: "Ideas" },
            { key: "closes", label: "Votes close" },
          ]}
        >
          {list.isSuccess && items.length === 0 && (
            <tr>
              <td colSpan={4}>
                <EmptyState icon={SquareKanban} title="No boards yet">
                  An unconference, a roadmap, a retrospective
                  {mayCreate ? ": create one with New board." : "."}
                </EmptyState>
              </td>
            </tr>
          )}
          {items.map((b) => {
            const c = b.ideaCounts;
            return (
              <tr key={b.boardId} className="clickable" onClick={() => navigate(encodeURIComponent(b.boardId))}>
                <td>
                  <strong>{b.title}</strong>
                  {b.audience.kind === "group" && <div className="muted">One group's members</div>}
                </td>
                <td>{phaseWords(b)}</td>
                <td>
                  {c.proposed ?? 0} proposed · {c.open ?? 0} voting · {c.selected ?? 0} selected
                </td>
                <td>{when(b.voting.closesAt)}</td>
              </tr>
            );
          })}
        </DataTable>
      </section>
    </>
  );
}

// ── Creating a board ────────────────────────────────────────────────────────

interface SlotDraft {
  label: string;
  startsAt: string;
  endsAt: string;
}

function slotsFrom(drafts: SlotDraft[]): Slot[] {
  return drafts
    .filter((s) => s.label.trim() && s.startsAt && s.endsAt)
    .map((s, i) => ({
      slotId: `s${i + 1}`,
      label: s.label.trim(),
      startsAt: fromLocalInput(s.startsAt),
      endsAt: fromLocalInput(s.endsAt),
    }));
}

const list = (v: string) =>
  [...new Set(v.split(",").map((x) => x.trim()).filter(Boolean))];

function CreateBoardForm({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const now = Date.now();
  const day = 86_400_000;
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [audience, setAudience] = useState("members");
  const [pOpen, setPOpen] = useState(toLocalInput(new Date(now).toISOString()));
  const [pClose, setPClose] = useState(toLocalInput(new Date(now + 7 * day).toISOString()));
  const [vOpen, setVOpen] = useState(toLocalInput(new Date(now + 5 * day).toISOString()));
  const [vClose, setVClose] = useState(toLocalInput(new Date(now + 9 * day).toISOString()));
  const [topics, setTopics] = useState("");
  const [formats, setFormats] = useState("Discussion, Talk, Workshop, Demo");
  const [maxIdeas, setMaxIdeas] = useState("3");
  const [rule, setRule] = useState("");
  const [question, setQuestion] = useState("Would you attend this session?");
  const [visibility, setVisibility] = useState<"public" | "private">("public");
  const [ballotBox, setBallotBox] = useState("");
  const [slots, setSlots] = useState<SlotDraft[]>([]);
  const groups = useQuery({ queryKey: ["groups"], queryFn: listGroups });
  const boxes = useQuery({ queryKey: ["elections", "ballot-boxes"], queryFn: fetchTrustedBallotBoxes });
  const box = ballotBox || boxes.data?.[0]?.did || "";

  const proposals = { opensAt: fromLocalInput(pOpen), closesAt: fromLocalInput(pClose) };
  const voting = { opensAt: fromLocalInput(vOpen), closesAt: fromLocalInput(vClose) };
  const schedule = scheduleProblem(proposals, voting);

  const create = useMutation({
    mutationFn: () => {
      const template = defaultTemplate(box);
      const q = template.questions[0] as { text?: string };
      q.text = question.trim();
      template.board = { visibility, auditors: [] };
      const ts = list(topics);
      const fs = list(formats);
      const tt = slotsFrom(slots);
      const max = Number(maxIdeas);
      return createBoard({
        title: title.trim(),
        ...(description.trim() ? { description: description.trim() } : {}),
        audience: audience === "members" ? { kind: "members" } : { kind: "group", groupId: audience },
        proposals,
        voting,
        ...(ts.length ? { topics: ts } : {}),
        ...(fs.length ? { formats: fs } : {}),
        ...(Number.isInteger(max) && max > 0 ? { maxIdeasPerMember: max } : {}),
        ...(rule.trim() ? { selectionRule: rule.trim() } : {}),
        ...(tt.length ? { timetable: tt } : {}),
        template,
      } as never);
    },
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: BOARDS_KEY });
      toast.push("success", `Created ${r.board.title}.`);
      onDone();
    },
    onError: (err) => toast.pushFromError(err, "The board was not created"),
  });
  const ok = title.trim() && question.trim() && box && !schedule;

  return (
    <section className="card" aria-labelledby="new-board-title">
      <h3 id="new-board-title">New board</h3>
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (ok) create.mutate();
        }}
      >
        <div className="form-grid">
          <Field label="Title">
            <input value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} />
          </Field>
          <Field label="Who can see and use it" hint="Every member, or one group's members. Fixed once voting opens.">
            <select value={audience} onChange={(e) => setAudience(e.target.value)} aria-label="Who can see and use it">
              <option value="members">Every member</option>
              {(groups.data ?? []).map(({ group }) => (
                <option key={group.groupId} value={group.groupId}>
                  {group.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Description" className="span-2" hint="Optional. What the board is for.">
            <textarea className="prose" rows={2} maxLength={4000} value={description} onChange={(e) => setDescription(e.target.value)} />
          </Field>
          <Field label="Proposals open">
            <input type="datetime-local" value={pOpen} onChange={(e) => setPOpen(e.target.value)} />
          </Field>
          <Field label="Proposals close">
            <input type="datetime-local" value={pClose} onChange={(e) => setPClose(e.target.value)} />
          </Field>
          <Field label="Voting opens" hint="Ideas accepted before this take tickets early.">
            <input type="datetime-local" value={vOpen} onChange={(e) => setVOpen(e.target.value)} />
          </Field>
          <Field label="Voting closes" error={schedule} errorRole="alert">
            <input type="datetime-local" value={vClose} onChange={(e) => setVClose(e.target.value)} />
          </Field>
          <Field label="Topics" hint="Comma-separated. Optional; members file each idea under one.">
            <input value={topics} onChange={(e) => setTopics(e.target.value)} />
          </Field>
          <Field label="Formats" hint="Comma-separated. Optional.">
            <input value={formats} onChange={(e) => setFormats(e.target.value)} />
          </Field>
          <Field label="Ideas per member" hint="At most this many each, not counting withdrawn or declined.">
            <input type="number" min={1} max={100} value={maxIdeas} onChange={(e) => setMaxIdeas(e.target.value)} />
          </Field>
          <Field label="How you'll choose" hint="Shown to members, e.g. “The twelve sessions most members would attend”.">
            <input value={rule} maxLength={500} onChange={(e) => setRule(e.target.value)} />
          </Field>
        </div>

        <fieldset className="form-stack">
          <legend>Each idea's election</legend>
          <p className="muted">
            Fixed for every idea the board's facilitators accept. Never binding. Changing it later takes{" "}
            <code>vtc.elections.manage</code>, and applies only to ideas accepted after.
          </p>
          <div className="form-grid">
            <Field label="Question" className="span-2" hint="Answered Yes, I'd attend / Not for me.">
              <input value={question} maxLength={2048} onChange={(e) => setQuestion(e.target.value)} />
            </Field>
            <Field label="Ballot box">
              {boxes.data && boxes.data.length > 0 ? (
                <select value={box} onChange={(e) => setBallotBox(e.target.value)} aria-label="Ballot box">
                  {boxes.data.map((b) => (
                    <option key={b.did} value={b.did}>
                      {b.operator}
                    </option>
                  ))}
                </select>
              ) : (
                <input value={ballotBox} placeholder="did:…" onChange={(e) => setBallotBox(e.target.value)} />
              )}
            </Field>
            <Field
              label="Board"
              hint={visibility === "public" ? "Members see how many ballots each idea has while voting is open." : "Only counts after close."}
            >
              <select value={visibility} onChange={(e) => setVisibility(e.target.value as "public" | "private")} aria-label="Board">
                <option value="public">Public</option>
                <option value="private">Private</option>
              </select>
            </Field>
          </div>
        </fieldset>

        <fieldset className="form-stack">
          <legend>Timetable</legend>
          <p className="muted">Optional. The slots selected ideas are placed in.</p>
          {slots.map((s, i) => (
            <div key={i} className="toolbar">
              <input
                aria-label={`Slot ${i + 1} place`}
                placeholder="Room A"
                value={s.label}
                onChange={(e) => setSlots(slots.map((x, j) => (j === i ? { ...x, label: e.target.value } : x)))}
              />
              <input
                type="datetime-local"
                aria-label={`Slot ${i + 1} starts`}
                value={s.startsAt}
                onChange={(e) => setSlots(slots.map((x, j) => (j === i ? { ...x, startsAt: e.target.value } : x)))}
              />
              <input
                type="datetime-local"
                aria-label={`Slot ${i + 1} ends`}
                value={s.endsAt}
                onChange={(e) => setSlots(slots.map((x, j) => (j === i ? { ...x, endsAt: e.target.value } : x)))}
              />
              <button type="button" className="secondary" aria-label={`Remove slot ${i + 1}`} onClick={() => setSlots(slots.filter((_, j) => j !== i))}>
                <Trash2 size={14} aria-hidden="true" />
              </button>
            </div>
          ))}
          <div>
            <button
              type="button"
              className="secondary"
              onClick={() => {
                const last = slots[slots.length - 1];
                setSlots([...slots, { label: last?.label ?? "", startsAt: last?.endsAt ?? "", endsAt: "" }]);
              }}
            >
              <Plus size={14} aria-hidden="true" /> Add a slot
            </button>
          </div>
        </fieldset>

        <div className="form-actions">
          <button type="button" className="secondary" onClick={onDone}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={!ok || create.isPending}>
            Create board
          </button>
        </div>
      </form>
    </section>
  );
}

// ── One board ───────────────────────────────────────────────────────────────

const PENDING_ORDER = ["decide", "refused", "select", "opening", "voting", "decided", "none"] as const;

function BoardDetail() {
  const { id = "" } = useParams();
  const boardId = decodeURIComponent(id);
  const qc = useQueryClient();
  const toast = useToast();
  const key = ["board", boardId];
  const shown = useQuery({ queryKey: key, queryFn: () => showBoard(boardId) });
  const notes = useQuery({ queryKey: [...key, "notes"], queryFn: () => listAllNotes(boardId) });
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: key });
    void qc.invalidateQueries({ queryKey: BOARDS_KEY });
  };
  const status = useMutation({
    mutationFn: (s: "closed" | "archived") => updateBoard({ boardId, status: s } as never),
    onSuccess: (_r, s) => {
      refresh();
      toast.push("success", s === "closed" ? "Closed to new ideas and notes." : "Archived.");
    },
    onError: (err) => toast.pushFromError(err, "The board was not changed"),
  });

  const ideas = useMemo(
    () =>
      [...(shown.data?.ideas ?? [])].sort(
        (a, b) => PENDING_ORDER.indexOf(pendingOf(a)) - PENDING_ORDER.indexOf(pendingOf(b)),
      ),
    [shown.data],
  );
  if (shown.isPending) return <p className="muted">Loading…</p>;
  if (shown.isError) {
    return (
      <section className="card error">
        <h3>Failed to read the board</h3>
        <p>{(shown.error as Error).message}</p>
      </section>
    );
  }
  const board = shown.data.board;
  const titleOf = (ideaId?: string) => ideas.find((i) => i.ideaId === ideaId)?.title;

  return (
    <>
      <PageHeader
        title={board.title}
        trail={[{ label: board.title }]}
        lead={`${phaseWords(board)} · proposals close ${when(board.proposals.closesAt)} · votes close ${when(board.voting.closesAt)}`}
        actions={
          board.facilitator && (
            <>
              {board.status === "open" && (
                <button type="button" className="secondary" onClick={() => status.mutate("closed")} disabled={status.isPending}>
                  Close to new ideas
                </button>
              )}
              {board.status === "closed" && (
                <button type="button" className="secondary" onClick={() => status.mutate("archived")} disabled={status.isPending}>
                  Archive
                </button>
              )}
            </>
          )
        }
      />
      {board.selectionRule && (
        <p className="muted">
          <strong>How you said you'd choose:</strong> {board.selectionRule}
        </p>
      )}

      <section className="card table-card">
        <DataTable
          caption="Ideas"
          columns={[
            { key: "idea", label: "Idea" },
            { key: "state", label: "Where it stands" },
            { key: "result", label: "Ballots" },
            { key: "act", label: "" },
          ]}
        >
          {ideas.length === 0 && (
            <tr>
              <td colSpan={4}>
                <EmptyState icon={SquareKanban} title="No ideas yet" compact>
                  Members propose them from the member portal.
                </EmptyState>
              </td>
            </tr>
          )}
          {ideas.map((i) => (
            <IdeaRow key={i.ideaId} board={board} idea={i} ideas={ideas} titleOf={titleOf} onChanged={refresh} />
          ))}
        </DataTable>
      </section>

      <NotesModeration notes={notes.data ?? []} titleOf={titleOf} error={notes.error} onChanged={() => void qc.invalidateQueries({ queryKey: [...key, "notes"] })} />
    </>
  );
}

function stateWords(i: Idea, titleOf: (id?: string) => string | undefined): string {
  switch (pendingOf(i)) {
    case "decide":
      return "Proposed — waiting for you";
    case "opening":
      return "Accepted — the ballot box hasn't registered its election yet";
    case "refused":
      return `Its election was refused (${i.opening?.refusal?.code ?? "unknown"}) — still proposed`;
    case "voting":
      return "Open for votes";
    case "select":
      return "Tallied — choose whether it's selected";
    case "decided":
      return i.state === "selected" ? "Selected" : "Not selected";
  }
  if (i.state === "merged") return `Merged into “${titleOf(i.decision?.mergedInto) ?? "another idea"}”`;
  if (i.state === "declined") return `Declined${i.decision?.reason ? `: ${i.decision.reason}` : ""}`;
  return "Withdrawn by its proposer";
}

function resultWords(i: Idea): string {
  const r = i.election?.result;
  if (r) {
    const counts = r.questions[0]?.choice as Record<string, number> | undefined;
    const total = counts ? Object.values(counts).reduce((a, b) => a + b, 0) : 0;
    const yes = counts?.yes;
    const share = total && yes !== undefined ? ` · ${Math.round((yes / total) * 100)}% yes` : "";
    return `${r.ballotsCounted} counted${share}${i.election?.certified ? " · certified" : ""}`;
  }
  if (i.election?.ballotsOnBoard !== undefined) return `${i.election.ballotsOnBoard} on the board`;
  return "—";
}

function IdeaRow({
  board,
  idea,
  ideas,
  titleOf,
  onChanged,
}: {
  board: Board;
  idea: Idea;
  ideas: Idea[];
  titleOf: (id?: string) => string | undefined;
  onChanged: () => void;
}) {
  const toast = useToast();
  const [mode, setMode] = useState<null | "decline" | "merge" | "select">(null);
  const [reason, setReason] = useState("");
  const [into, setInto] = useState("");
  const [slot, setSlot] = useState("");
  const [departs, setDeparts] = useState(false);
  const pending = pendingOf(idea);
  const done = (msg: string) => {
    setMode(null);
    setReason("");
    onChanged();
    toast.push("success", msg);
  };
  const decide = useMutation({
    mutationFn: (d: Parameters<typeof decideIdea>[1]) =>
      decideIdea(idea.ideaId, d, { reason, ...(d === "merge" ? { mergeInto: into } : {}) }),
    onSuccess: (r, d) =>
      done(
        d === "accept"
          ? r.idea.state === "open"
            ? "Accepted: its election is open."
            : "Accepted: its election opens once the ballot box registers it."
          : d === "reopen"
            ? "Moved back to proposed."
            : d === "merge"
              ? "Merged."
              : "Declined.",
      ),
    onError: (err) => toast.pushFromError(err, "The idea was not changed"),
  });
  const select = useMutation({
    mutationFn: (d: "selected" | "notSelected") =>
      selectIdea(idea.ideaId, d, { slotId: slot || undefined, departsFromRule: departs, reason }),
    onSuccess: (_r, d) => done(d === "selected" ? "Selected." : "Marked not selected."),
    onError: (err) => toast.pushFromError(err, "The decision was not recorded"),
  });
  const taken = new Set(
    ideas.filter((x) => x.ideaId !== idea.ideaId && x.state === "selected").map((x) => x.decision?.slotId),
  );
  const freeSlots = (board.timetable ?? []).filter((s) => !taken.has(s.slotId));
  const mergeTargets = ideas.filter(
    (x) => x.ideaId !== idea.ideaId && !["withdrawn", "declined", "merged"].includes(x.state),
  );
  const busy = decide.isPending || select.isPending;
  const facilitates = board.facilitator;

  return (
    <>
      <tr>
        <td>
          <strong>{idea.title}</strong>
          <div className="muted">
            {idea.proposer.formerMember ? "A former member" : idea.proposer.name ?? "A member"}
            {idea.format ? ` · ${idea.format}` : ""}
            {idea.topic ? ` · ${idea.topic}` : ""} · {idea.noteCount} notes
          </div>
        </td>
        <td>{stateWords(idea, titleOf)}</td>
        <td>{resultWords(idea)}</td>
        <td className="row-actions">
          {facilitates && (pending === "decide" || pending === "refused") && (
            <>
              <button type="button" className="primary" disabled={busy} onClick={() => decide.mutate("accept")}>
                <Check size={14} aria-hidden="true" /> {pending === "refused" ? "Try again" : "Accept"}
              </button>
              <button type="button" className="secondary" disabled={busy} onClick={() => setMode(mode === "merge" ? null : "merge")}>
                <GitMerge size={14} aria-hidden="true" /> Merge
              </button>
              <button type="button" className="secondary" disabled={busy} onClick={() => setMode(mode === "decline" ? null : "decline")}>
                <X size={14} aria-hidden="true" /> Decline
              </button>
            </>
          )}
          {facilitates && (pending === "select" || pending === "decided") && (
            <button type="button" className={pending === "select" ? "primary" : "secondary"} disabled={busy} onClick={() => setMode(mode === "select" ? null : "select")}>
              {pending === "select" ? "Decide" : "Change"}
            </button>
          )}
          {facilitates && idea.state === "declined" && board.status === "open" && (
            <button type="button" className="secondary" disabled={busy} onClick={() => decide.mutate("reopen")}>
              <RotateCcw size={14} aria-hidden="true" /> Reopen
            </button>
          )}
        </td>
      </tr>
      {mode && (
        <tr>
          <td colSpan={4}>
            <form
              className="toolbar"
              onSubmit={(e) => {
                e.preventDefault();
                if (mode === "decline" && reason.trim()) decide.mutate("decline");
                if (mode === "merge" && into) decide.mutate("merge");
              }}
            >
              {mode === "merge" && (
                <select aria-label="Merge into" value={into} onChange={(e) => setInto(e.target.value)}>
                  <option value="">Merge into…</option>
                  {mergeTargets.map((x) => (
                    <option key={x.ideaId} value={x.ideaId}>
                      {x.title}
                    </option>
                  ))}
                </select>
              )}
              {mode === "select" && (board.timetable?.length ?? 0) > 0 && (
                <select aria-label="Slot" value={slot} onChange={(e) => setSlot(e.target.value)}>
                  <option value="">No slot yet</option>
                  {freeSlots.map((s) => (
                    <option key={s.slotId} value={s.slotId}>
                      {slotLabel(s)}
                    </option>
                  ))}
                </select>
              )}
              {mode === "select" && board.selectionRule && (
                <label className="checkbox">
                  <input type="checkbox" checked={departs} onChange={(e) => setDeparts(e.target.checked)} />
                  <span className="checkbox-text">This departs from how we said we'd choose</span>
                </label>
              )}
              <input
                aria-label="Reason"
                placeholder={mode === "decline" ? "Why (members see this)" : "Reason (optional, members see it)"}
                maxLength={500}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
              {mode === "decline" && (
                <button type="submit" className="primary" disabled={!reason.trim() || busy}>
                  Decline
                </button>
              )}
              {mode === "merge" && (
                <button type="submit" className="primary" disabled={!into || busy}>
                  Merge
                </button>
              )}
              {mode === "select" && (
                <>
                  <button type="button" className="primary" disabled={busy || (departs && !reason.trim())} onClick={() => select.mutate("selected")}>
                    Select
                  </button>
                  <button type="button" className="secondary" disabled={busy || (departs && !reason.trim())} onClick={() => select.mutate("notSelected")}>
                    Not this time
                  </button>
                </>
              )}
              <button type="button" className="secondary" onClick={() => setMode(null)}>
                Cancel
              </button>
            </form>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Notes ───────────────────────────────────────────────────────────────────

function NotesModeration({
  notes,
  titleOf,
  error,
  onChanged,
}: {
  notes: Note[];
  titleOf: (id?: string) => string | undefined;
  error: unknown;
  onChanged: () => void;
}) {
  const toast = useToast();
  const [hiding, setHiding] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const act = useMutation({
    mutationFn: (p: { noteId: string; action: "hide" | "unhide" }) => hideNote(p.noteId, p.action, reason),
    onSuccess: (_r, p) => {
      setHiding(null);
      setReason("");
      onChanged();
      toast.push("success", p.action === "hide" ? "Note hidden." : "Note shown again.");
    },
    onError: (err) => toast.pushFromError(err, "The note was not changed"),
  });
  return (
    <section className="card table-card" aria-labelledby="notes-title">
      <h3 id="notes-title">Notes</h3>
      {error ? <p className="error">{(error as Error).message}</p> : null}
      <DataTable
        caption="Notes"
        columns={[
          { key: "note", label: "Note" },
          { key: "on", label: "On" },
          { key: "state", label: "" },
          { key: "act", label: "" },
        ]}
      >
        {notes.length === 0 && (
          <tr>
            <td colSpan={4} className="muted">
              No notes yet.
            </td>
          </tr>
        )}
        {notes.map((n) => (
          <tr key={n.noteId}>
            <td>
              {n.text ?? <span className="muted">—</span>}
              <div className="muted">
                {n.author.formerMember ? "A former member" : n.author.name ?? "A member"} · {when(n.createdAt)}
              </div>
            </td>
            <td>{n.ideaId ? titleOf(n.ideaId) ?? "An idea" : "The board"}</td>
            <td>{n.state === "visible" ? "" : n.state === "hidden" ? `Hidden: ${n.hiddenReason ?? ""}` : "Withdrawn"}</td>
            <td className="row-actions">
              {n.state === "visible" &&
                (hiding === n.noteId ? (
                  <form
                    className="toolbar"
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (reason.trim()) act.mutate({ noteId: n.noteId, action: "hide" });
                    }}
                  >
                    <input aria-label="Why hide it" placeholder="Why (shown in its place)" maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />
                    <button type="submit" className="primary" disabled={!reason.trim() || act.isPending}>
                      Hide
                    </button>
                    <button type="button" className="secondary" onClick={() => setHiding(null)}>
                      Cancel
                    </button>
                  </form>
                ) : (
                  <button type="button" className="secondary" onClick={() => setHiding(n.noteId)}>
                    <EyeOff size={14} aria-hidden="true" /> Hide
                  </button>
                ))}
              {n.state === "hidden" && (
                <button type="button" className="secondary" disabled={act.isPending} onClick={() => act.mutate({ noteId: n.noteId, action: "unhide" })}>
                  Show again
                </button>
              )}
            </td>
          </tr>
        ))}
      </DataTable>
    </section>
  );
}
