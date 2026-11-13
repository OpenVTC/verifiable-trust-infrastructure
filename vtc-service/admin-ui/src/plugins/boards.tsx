// Community boards, for facilitators (`vtc/boards`, docs/03-vtc/boards.md).
//
//   /boards        Every board this administrator facilitates; create one.
//   /boards/:id    One board: edit it, decide its proposed ideas, select among tallied ones, hide
//                  notes, close it (which ends its voting), archive or delete it.
//
// Members propose and leave notes from the member portal; this page never writes as a member.
// Accepting an idea opens its election from the board's template — the result is shown here once
// the ballot box publishes it, beside the decision, and the decision may depart from it
// (VTI-BRD-041). Nothing here ever shows who took a ticket or voted (VTI-BRD-033).

import { useMemo, useState } from "react";
import { Link, Route, Routes, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, EyeOff, GitMerge, Pencil, Plus, RotateCcw, SquareKanban, Trash2, X } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { byFace, EntryName, faceLabel, useEntryFaces } from "@/components/EntryName";
import { Field } from "@/components/Field";
import { PageHeader } from "@/components/PageHeader";
import {
  BOARDS_KEY,
  BOARDS_MANAGE,
  ELECTIONS_MANAGE,
  appointFacilitator,
  createBoard,
  decideIdea,
  deleteBoard,
  defaultTemplate,
  fromLocalInput,
  hideNote,
  listAllNotes,
  listBoards,
  listFacilitators,
  pendingOf,
  removeFacilitator,
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
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";
import { holds, useCapabilities } from "@/lib/viewer";
import { formatDateTime } from "@/lib/format";

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

/** A deadline, with its zone (#2613). */
const when = formatDateTime;

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
                  {/* A link, so a keyboard or screen reader reaches the board;
                      the row click stays as a convenience (#2611). */}
                  <Link to={encodeURIComponent(b.boardId)} onClick={(e) => e.stopPropagation()}>
                    <strong>{b.title}</strong>
                  </Link>
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

// ── Editing a board ─────────────────────────────────────────────────────────

/**
 * What `vtc/boards/update` changes, as only the fields that differ from the board as read — so
 * an unchanged voting window or audience is never sent once voting has opened, when the board
 * refuses any change to them (`fixedAfterVotingOpens`). The election template is not edited
 * here: it takes `vtc.elections.manage` as well, and applies only to ideas accepted after.
 */
export function boardChanges(
  b: Board,
  d: {
    title: string;
    description: string;
    audience: string;
    proposals: { opensAt: string; closesAt: string };
    voting: { opensAt: string; closesAt: string };
    topics: string[];
    formats: string[];
    maxIdeas: string;
    rule: string;
    timetable: Slot[];
  },
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const same = (a: unknown, b: unknown) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
  // A datetime input holds whole minutes, so a time read back from one is compared to the minute:
  // an untouched window must not come back as a change.
  const minute = (t: string) => Math.floor(Date.parse(t) / 60_000);
  const instant = (w: { opensAt: string; closesAt: string }) => [minute(w.opensAt), minute(w.closesAt)];
  if (d.title.trim() && d.title.trim() !== b.title) out.title = d.title.trim();
  if (d.description.trim() && d.description.trim() !== (b.description ?? "")) out.description = d.description.trim();
  const aud = b.audience.kind === "group" ? (b.audience as { groupId: string }).groupId : "members";
  if (d.audience !== aud) out.audience = d.audience === "members" ? { kind: "members" } : { kind: "group", groupId: d.audience };
  if (!same(instant(d.proposals), instant(b.proposals))) out.proposals = d.proposals;
  if (!same(instant(d.voting), instant(b.voting))) out.voting = d.voting;
  if (!same(d.topics, b.topics ?? [])) out.topics = d.topics;
  if (!same(d.formats, b.formats ?? [])) out.formats = d.formats;
  const max = Number(d.maxIdeas);
  if (Number.isInteger(max) && max > 0 && max !== b.maxIdeasPerMember) out.maxIdeasPerMember = max;
  if (d.rule.trim() && d.rule.trim() !== (b.selectionRule ?? "")) out.selectionRule = d.rule.trim();
  const slotKey = (t: Slot[]) => t.map((x) => [x.slotId, x.label, minute(x.startsAt), minute(x.endsAt)]);
  if (!same(slotKey(d.timetable), slotKey(b.timetable ?? []))) out.timetable = d.timetable;
  return out;
}

interface EditSlot extends SlotDraft {
  slotId?: string;
}

function EditBoardForm({ board, onDone }: { board: Board; onDone: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const votingOpened = Date.now() >= Date.parse(board.voting.opensAt);
  const [title, setTitle] = useState(board.title);
  const [description, setDescription] = useState(board.description ?? "");
  const [audience, setAudience] = useState(
    board.audience.kind === "group" ? (board.audience as { groupId: string }).groupId : "members",
  );
  const [pOpen, setPOpen] = useState(toLocalInput(board.proposals.opensAt));
  const [pClose, setPClose] = useState(toLocalInput(board.proposals.closesAt));
  const [vOpen, setVOpen] = useState(toLocalInput(board.voting.opensAt));
  const [vClose, setVClose] = useState(toLocalInput(board.voting.closesAt));
  const [topics, setTopics] = useState((board.topics ?? []).join(", "));
  const [formats, setFormats] = useState((board.formats ?? []).join(", "));
  const [maxIdeas, setMaxIdeas] = useState(board.maxIdeasPerMember ? String(board.maxIdeasPerMember) : "");
  const [rule, setRule] = useState(board.selectionRule ?? "");
  const [slots, setSlots] = useState<EditSlot[]>(
    (board.timetable ?? []).map((t) => ({
      slotId: t.slotId,
      label: t.label,
      startsAt: toLocalInput(t.startsAt),
      endsAt: toLocalInput(t.endsAt),
    })),
  );
  const groups = useQuery({ queryKey: ["groups"], queryFn: listGroups });

  const proposals = { opensAt: fromLocalInput(pOpen), closesAt: fromLocalInput(pClose) };
  const voting = { opensAt: fromLocalInput(vOpen), closesAt: fromLocalInput(vClose) };
  const schedule = scheduleProblem(proposals, voting);

  // A slot keeps its identifier, so a selected idea placed in it stays placed; a new slot takes
  // one no other slot has used.
  const timetable = (): Slot[] => {
    const used = new Set(slots.map((s) => s.slotId).filter(Boolean));
    let n = 0;
    const fresh = () => {
      do n += 1;
      while (used.has(`s${n}`));
      used.add(`s${n}`);
      return `s${n}`;
    };
    return slots
      .filter((s) => s.label.trim() && s.startsAt && s.endsAt)
      .map((s) => ({
        slotId: s.slotId ?? fresh(),
        label: s.label.trim(),
        startsAt: fromLocalInput(s.startsAt),
        endsAt: fromLocalInput(s.endsAt),
      }));
  };
  const changes = () =>
    boardChanges(board, {
      title,
      description,
      audience,
      proposals,
      voting,
      topics: list(topics),
      formats: list(formats),
      maxIdeas,
      rule,
      timetable: timetable(),
    });

  const save = useMutation({
    mutationFn: () => updateBoard({ boardId: board.boardId, ...changes() } as never),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["board", board.boardId] });
      void qc.invalidateQueries({ queryKey: BOARDS_KEY });
      toast.push("success", "Board saved.");
      onDone();
    },
    onError: (err) => toast.pushFromError(err, "The board was not changed"),
  });
  const dirty = Object.keys(changes()).length > 0;
  const ok = title.trim() && !schedule && dirty;

  return (
    <section className="card" aria-labelledby="edit-board-title">
      <h3 id="edit-board-title">Edit board</h3>
      <p className="muted">
        Changes apply to the board and to ideas accepted from now on. An idea already open for votes keeps the
        voting window it opened with.
      </p>
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (ok) save.mutate();
        }}
      >
        <div className="form-grid">
          <Field label="Title">
            <input value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} />
          </Field>
          <Field
            label="Who can see and use it"
            hint={votingOpened ? "Fixed: voting has opened." : "Every member, or one group's members. Fixed once voting opens."}
          >
            <select
              value={audience}
              disabled={votingOpened}
              onChange={(e) => setAudience(e.target.value)}
              aria-label="Who can see and use it"
            >
              <option value="members">Every member</option>
              {(groups.data ?? []).map(({ group }) => (
                <option key={group.groupId} value={group.groupId}>
                  {group.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Description" className="span-2">
            <textarea className="prose" rows={2} maxLength={4000} value={description} onChange={(e) => setDescription(e.target.value)} />
          </Field>
          <Field label="Proposals open">
            <input type="datetime-local" value={pOpen} onChange={(e) => setPOpen(e.target.value)} />
          </Field>
          <Field label="Proposals close">
            <input type="datetime-local" value={pClose} onChange={(e) => setPClose(e.target.value)} />
          </Field>
          <Field label="Voting opens" hint={votingOpened ? "Fixed: voting has opened." : "Ideas accepted before this take tickets early."}>
            <input type="datetime-local" value={vOpen} disabled={votingOpened} onChange={(e) => setVOpen(e.target.value)} />
          </Field>
          <Field label="Voting closes" error={schedule} errorRole="alert" hint={votingOpened ? "Fixed: voting has opened." : undefined}>
            <input type="datetime-local" value={vClose} disabled={votingOpened} onChange={(e) => setVClose(e.target.value)} />
          </Field>
          <Field label="Topics" hint="Comma-separated.">
            <input value={topics} onChange={(e) => setTopics(e.target.value)} />
          </Field>
          <Field label="Formats" hint="Comma-separated.">
            <input value={formats} onChange={(e) => setFormats(e.target.value)} />
          </Field>
          <Field label="Ideas per member">
            <input type="number" min={1} max={100} value={maxIdeas} onChange={(e) => setMaxIdeas(e.target.value)} />
          </Field>
          <Field label="How you'll choose">
            <input value={rule} maxLength={500} onChange={(e) => setRule(e.target.value)} />
          </Field>
        </div>

        <fieldset className="form-stack">
          <legend>Timetable</legend>
          <p className="muted">A slot a selected idea is placed in cannot be removed.</p>
          {slots.map((s, i) => (
            <div key={s.slotId ?? `new-${i}`} className="toolbar">
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
          <button type="submit" className="primary" disabled={!ok || save.isPending}>
            Save changes
          </button>
        </div>
      </form>
    </section>
  );
}

// ── Deleting a board ────────────────────────────────────────────────────────

/**
 * Delete a closed board (VTI-BRD-007): the operator types its title, gives a reason, and is told
 * what goes and what a tombstone keeps before the passkey gesture the deletion is bound to.
 */
function DeleteBoardPanel({ board, onDone }: { board: Board; onDone: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const confirm = useConfirm();
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const del = useMutation({
    mutationFn: () => deleteBoard(board.boardId, reason.trim(), gestureFromConfirm(confirm)),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: BOARDS_KEY });
      void qc.invalidateQueries({ queryKey: ["elections"] });
      const t = r.tombstones;
      const kept =
        t.kept === 0
          ? "No tombstone kept."
          : t.removeAt
            ? `${t.kept} tombstone(s) kept until ${when(t.removeAt)}.`
            : `${t.kept} tombstone(s) kept for ever.`;
      toast.push("success", `Deleted ${board.title}: ${r.ideasRemoved} idea(s), ${r.notesRemoved} note(s). ${kept}`);
      navigate("/boards");
    },
    onError: (err) => toast.pushFromError(err, "The board was not deleted"),
  });
  const ok = typed.trim() === board.title.trim() && reason.trim().length > 0;
  return (
    <section className="card error" aria-labelledby="delete-board-title">
      <h3 id="delete-board-title">Delete this board</h3>
      <p>
        This removes the board, every idea and note on it, and its elections&rsquo; titles, descriptions, rolls and ticket
        records. It cannot be undone.
      </p>
      <p className="muted">
        Each election keeps a <strong>tombstone</strong> — its identifier, its manifest&rsquo;s digest and the board heads the
        community kept — for the community&rsquo;s tombstone retention (<code>[boards] tombstone_retention</code>, twelve
        months unless set). Until it goes, a voter can still check a receipt against it; after, nobody can. Every
        election must have closed or been cancelled first.
      </p>
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (ok) del.mutate();
        }}
      >
        <div className="form-grid">
          <Field label={`Type the board's title, ${board.title}`}>
            <input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
          </Field>
          <Field label="Why" hint="Recorded with the deletion in the audit trail.">
            <input value={reason} maxLength={1024} onChange={(e) => setReason(e.target.value)} />
          </Field>
        </div>
        <div className="form-actions">
          <button type="button" className="secondary" onClick={onDone}>
            Cancel
          </button>
          <button type="submit" className="destructive" disabled={!ok || del.isPending}>
            <Trash2 size={14} aria-hidden="true" /> Delete board
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
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const caps = useCapabilities();
  // Deleting takes vtc.boards.manage unqualified: a facilitator of this one board cannot
  // (VTI-BRD-007).
  const mayDelete = holds(caps, BOARDS_MANAGE);
  const key = ["board", boardId];
  const shown = useQuery({ queryKey: key, queryFn: () => showBoard(boardId) });
  const notes = useQuery({ queryKey: [...key, "notes"], queryFn: () => listAllNotes(boardId) });
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: key });
    void qc.invalidateQueries({ queryKey: BOARDS_KEY });
  };
  const status = useMutation({
    mutationFn: (s: "closed" | "archived") => updateBoard({ boardId, status: s } as never),
    onSuccess: (r, s) => {
      refresh();
      const c = (r as { closing?: { closedEarly: number; cancelled: number; runningToClose: string[] } }).closing;
      const ended = c
        ? ` Voting ended: ${c.closedEarly} closed early (counts final), ${c.cancelled} cancelled` +
          (c.runningToClose.length ? `; ${c.runningToClose.length} cannot close early and run to their own close.` : ".")
        : "";
      toast.push("success", (s === "closed" ? "Closed to new ideas and notes." : "Archived.") + ended);
    },
    onError: (err) => toast.pushFromError(err, "The board was not changed"),
  });

  const confirm = useConfirm();
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
  // Ending voting with final counts is the least reversible thing a
  // facilitator does: say what it does in a dialog, not only in a hover title
  // that touch and keyboard users never see (#2608).
  const changeStatus = async (s: "closed" | "archived") => {
    const ok = await confirm(
      s === "closed"
        ? {
            title: `Close ${board.title} and end voting?`,
            message:
              "New ideas and notes stop. Elections open for voting close early with their counts final; those not yet open are cancelled.",
            confirmLabel: "Close and end voting",
            destructive: true,
          }
        : {
            title: `Archive ${board.title}?`,
            message: "An archived board takes no change at all, and members no longer see it.",
            confirmLabel: "Archive",
            destructive: true,
          },
    );
    if (ok) status.mutate(s);
  };

  return (
    <>
      <PageHeader
        title={board.title}
        trail={[{ label: board.title }]}
        lead={`${phaseWords(board)} · proposals close ${when(board.proposals.closesAt)} · votes close ${when(board.voting.closesAt)}`}
        actions={
          board.facilitator && (
            <>
              {board.status !== "archived" && !editing && (
                <button type="button" className="secondary" onClick={() => setEditing(true)}>
                  <Pencil size={14} aria-hidden="true" /> Edit board
                </button>
              )}
              {board.status === "open" && (
                <button
                  type="button"
                  className="secondary"
                  title="Stops new ideas and notes, and ends the voting: elections open for voting close early with their counts final; those not yet open are cancelled."
                  onClick={() => void changeStatus("closed")}
                  disabled={status.isPending}
                >
                  Close and end voting
                </button>
              )}
              {board.status === "closed" && (
                <button type="button" className="secondary" onClick={() => void changeStatus("archived")} disabled={status.isPending}>
                  Archive
                </button>
              )}
              {board.status !== "open" && mayDelete && !deleting && (
                <button type="button" className="destructive" onClick={() => setDeleting(true)}>
                  <Trash2 size={14} aria-hidden="true" /> Delete board
                </button>
              )}
            </>
          )
        }
      />
      {editing && <EditBoardForm board={board} onDone={() => setEditing(false)} />}
      {deleting && <DeleteBoardPanel board={board} onDone={() => setDeleting(false)} />}
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

      {board.facilitator && <BoardFacilitators board={board} mayRemoveOthers={mayDelete} />}
    </>
  );
}

// ── Facilitators (VTI-BRD-090 – 093) ────────────────────────────────────────

/** Who facilitates this board by appointment, and appointing or removing them. Any facilitator
 *  of the board appoints; only a holder of vtc.boards.manage for every board ends someone
 *  else's appointment (VTI-BRD-091). Holders for every board facilitate it without being listed. */
export function BoardFacilitators({ board, mayRemoveOthers }: { board: Board; mayRemoveOthers: boolean }) {
  const qc = useQueryClient();
  const toast = useToast();
  const faces = useEntryFaces();
  const [adding, setAdding] = useState("");
  const [reason, setReason] = useState("");
  const key = ["board", board.boardId, "facilitators"];
  const list = useQuery({ queryKey: key, queryFn: () => listFacilitators(board.boardId) });
  const appointed = list.data ?? [];
  const refresh = () => void qc.invalidateQueries({ queryKey: key });
  const add = useMutation({
    mutationFn: () => appointFacilitator(board.boardId, adding, reason.trim() || undefined),
    onSuccess: () => {
      setAdding("");
      setReason("");
      refresh();
      toast.push("success", "Appointed. They can now decide, select and moderate on this board.");
    },
    onError: (err) => toast.pushFromError(err, "Not appointed"),
  });
  const remove = useMutation({
    mutationFn: (entryId: string) => removeFacilitator(board.boardId, entryId),
    onSuccess: () => {
      refresh();
      toast.push("success", "Appointment ended.");
    },
    onError: (err) => toast.pushFromError(err, "Not changed"),
  });
  const nameOf = (e: string) => faces.get(e)?.name ?? e;
  return (
    <section className="card" aria-labelledby="board-facilitators-title">
      <h3 id="board-facilitators-title">Facilitators</h3>
      <p className="muted">
        A facilitator decides, selects and moderates on this board, and nothing else in the community: a member with
        no administrative role can be one. Administrators who run every board are not listed.
      </p>
      {list.isError ? (
        <p className="error">Failed to read the facilitators: {(list.error as Error).message}</p>
      ) : appointed.length === 0 ? (
        <EmptyState compact title={list.isPending ? "Loading…" : "Nobody is appointed to this board."} />
      ) : (
        <ul className="group-list">
          {appointed.map((a) => (
            <li key={a.entryId}>
              <EntryName entryId={a.entryId} faces={faces} />
              <span className="muted">
                since {when(a.appointedAt)}
                {a.appointedBy ? ` · appointed by ${nameOf(a.appointedBy)}` : ""}
              </span>
              {a.reviewEndsAt && (
                <span className="chip warning" title="Whoever appointed them no longer stands behind it. An administrator who runs this board can re-affirm it from the action list.">
                  Under review until {when(a.reviewEndsAt)}
                </span>
              )}
              {mayRemoveOthers && (
                <div className="row-actions">
                  <button type="button" className="secondary" onClick={() => remove.mutate(a.entryId)} disabled={remove.isPending}>
                    End appointment
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {board.status !== "archived" && (
        <form
          className="toolbar"
          onSubmit={(e) => {
            e.preventDefault();
            if (adding) add.mutate();
          }}
        >
          <Field label="Appoint a facilitator" inline>
            <select aria-label="Member to appoint" value={adding} onChange={(e) => setAdding(e.target.value)}>
              <option value="">Choose a member…</option>
              {[...faces.entries()]
                .filter(([e]) => !appointed.some((a) => a.entryId === e))
                .sort(byFace)
                .map(([entryId, f]) => (
                  <option key={entryId} value={entryId} title={f.did ?? undefined}>
                    {faceLabel(f)}
                  </option>
                ))}
            </select>
          </Field>
          <Field label="Why (optional)" inline>
            <input value={reason} maxLength={1024} onChange={(e) => setReason(e.target.value)} placeholder="Convenes the security track" />
          </Field>
          <button type="submit" className="secondary" disabled={!adding || add.isPending}>
            Appoint
          </button>
        </form>
      )}
    </section>
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
