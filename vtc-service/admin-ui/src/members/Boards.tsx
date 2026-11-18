// The community's boards in the member portal (`vtc/boards`, VTI Community Boards chapter):
//
//   #/boards        The boards you can see.
//   #/boards/<id>   One board: its ideas in lanes, its notes, its timetable.
//
// Proposing, notes and withdrawing your own are signed by this browser's portal key for you
// (`boards-api.ts`). Voting is not the board's: each accepted idea is its own election, and the
// buttons here hand off to your wallet exactly as the Elections page does (`wallet-elections.ts`).
// The board never says whether you took a ticket or voted (VTI-BRD-033); "ticket held" on a card
// is your wallet's answer, read in this browser.

import { useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CalendarDays,
  Lock,
  MessageSquare,
  Plus,
  Search,
  SquareKanban,
  StickyNote,
  TicketCheck,
  Vote,
  X,
} from "lucide-react";

import {
  LANES,
  LANE_LABEL,
  LANE_NOTE,
  PHASE_LABEL,
  addNote,
  authorName,
  grid,
  laneIdeas,
  leadingShare,
  listAllBoards,
  listNotes,
  phaseOf,
  notYetVoting,
  type NotYetVoting,
  proposeIdea,
  showBoard,
  takesNotes,
  takesProposals,
  withdrawIdea,
  withdrawNote,
  type Board,
  type Idea,
  type Note,
} from "./boards-api";
import { useConfirm } from "@/components/ConfirmDialog";
import { useModal } from "@/components/useModal";
import { DirectoryError } from "./directory-api";
import { electionHref } from "./Elections";
import { Crumbs } from "./member-card";
import { declinedInWallet, walletElections } from "./wallet-elections";
import { formatDate, formatDateTime, parseTime } from "@/lib/format";
import { messageOf } from "@/lib/messages";

export function boardHref(boardId: string): string {
  return `#/boards/${encodeURIComponent(boardId)}`;
}

/** A deadline, with its zone (`formatDateTime`, #2613); `opts` only for a
 *  schedule slot's own short form. */
function when(iso: string, opts?: Intl.DateTimeFormatOptions): string {
  if (!opts) return formatDateTime(iso);
  const d = parseTime(iso);
  return d ? d.toLocaleString(undefined, opts) : iso;
}

function problem(e: unknown): string {
  if (e instanceof DirectoryError && e.code === "noKey") {
    return "Sign in with your wallet to use boards: it lets this browser propose ideas and add notes as you, for this session.";
  }
  return messageOf(e);
}

function Problem({ error }: { error: unknown }) {
  return (
    <div className="alert" role="alert">
      <p className="alert-title">The board couldn&rsquo;t be read.</p>
      <p>{problem(error)}</p>
    </div>
  );
}

/** What a member is told before they first write on a board (VTI-BRD-070). */
function Disclosure() {
  return (
    <p className="bd-disclosure">
      <Lock size={14} aria-hidden="true" />
      <span>
        What you write here is shown under your name to everyone who can see this board, and its
        facilitators can decline, merge or hide it. Voting on an idea is a separate election in your
        wallet: the board never learns whether you took a ticket or how you voted. Once an idea is put
        to a vote, its title and description can&rsquo;t change.
      </span>
    </p>
  );
}

// ── The list ────────────────────────────────────────────────────────────────

export function BoardsPage() {
  const boards = useQuery({ queryKey: ["boards"], queryFn: listAllBoards, retry: false });
  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Boards" }]} />
      <section className="welcome">
        <p className="eyebrow">Member portal</p>
        <h1>Boards</h1>
        <p className="lead">
          Propose ideas, leave notes, and vote on the ones you want. Each idea a facilitator accepts is put to its own
          election in your wallet.
        </p>
      </section>
      {boards.isPending ? (
        <p className="muted">Loading…</p>
      ) : boards.isError ? (
        <Problem error={boards.error} />
      ) : boards.data.boards.length === 0 ? (
        <p className="muted">There are no boards you can see right now.</p>
      ) : (
        <ul className="bd-board-list" aria-label="Boards">
          {boards.data.boards.map((b) => (
            <li key={b.boardId} className="card">
              <div className="card-head">
                <SquareKanban size={18} aria-hidden="true" />
                <h2>
                  <a href={boardHref(b.boardId)}>{b.title}</a>
                </h2>
                <span className={phaseOf(b) === "closed" || phaseOf(b) === "archived" ? "pill" : "pill pill-ok"}>
                  {PHASE_LABEL[phaseOf(b)]}
                </span>
              </div>
              {b.description && <p className="muted bd-clamp">{b.description}</p>}
              <p className="muted small">
                Proposals until {when(b.proposals.closesAt)} · votes close {when(b.voting.closesAt)}
              </p>
              <a className="btn btn-ghost btn-sm" href={boardHref(b.boardId)}>
                Open board
              </a>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}

// ── One board ───────────────────────────────────────────────────────────────

export function BoardPage({ boardId, hostDid, member }: { boardId: string; hostDid?: string; member?: string }) {
  const shown = useQuery({ queryKey: ["board", boardId], queryFn: () => showBoard(boardId), retry: false });
  const title = shown.data?.board.title ?? boardId;
  return (
    <main className="home bd-page" id="main">
      <Crumbs trail={[{ label: "Boards", href: "#/boards" }, { label: title }]} />
      {shown.isPending ? (
        <p className="muted">Loading…</p>
      ) : shown.isError ? (
        <Problem error={shown.error} />
      ) : (
        <BoardView board={shown.data.board} ideas={shown.data.ideas} hostDid={hostDid} member={member} />
      )}
    </main>
  );
}

/** Which of the board's elections the member's wallet holds a ticket for. Only the wallet knows. */
function useTickets(hostDid: string | undefined, member: string | undefined) {
  const wallet = walletElections();
  const list = useQuery({
    queryKey: ["member-elections", hostDid, member],
    queryFn: () => wallet!.list({ hostDid: hostDid!, ...(member ? { member } : {}) }),
    enabled: !!wallet && !!hostDid,
    retry: false,
  });
  const held = useMemo(
    () => new Set((list.data?.elections ?? []).filter((e) => e.ticketHeld).map((e) => e.electionId)),
    [list.data],
  );
  return { wallet, held, ready: list.isSuccess };
}

function BoardView({
  board,
  ideas,
  hostDid,
  member,
}: {
  board: Board;
  ideas: Idea[];
  hostDid?: string;
  member?: string;
}) {
  const qc = useQueryClient();
  const [view, setView] = useState<"board" | "schedule">("board");
  const [topic, setTopic] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [proposing, setProposing] = useState(false);
  const [taking, setTaking] = useState<string | null>(null);
  const [takeError, setTakeError] = useState<string | null>(null);
  const tickets = useTickets(hostDid, member);
  const phase = phaseOf(board);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["board", board.boardId] });

  const visible = ideas.filter(
    (i) =>
      (!topic || i.topic === topic) &&
      (!query || `${i.title} ${i.description}`.toLowerCase().includes(query.toLowerCase())),
  );
  const open = ideas.filter((i) => i.state === "open" && i.election);
  const missing = tickets.ready ? open.filter((i) => !tickets.held.has(i.election!.electionId)) : [];
  const set = ideas.filter((i) => i.state === "declined" || i.state === "merged");
  const yours = ideas.filter((i) => i.state === "withdrawn" && i.proposer.you);
  const current = ideas.find((i) => i.ideaId === openId) ?? null;

  // One decision in the wallet where it offers one; each ticket is still its own request
  // (VTI-BRD-034). An older wallet asks for each in turn.
  const takeAll = async () => {
    if (!tickets.wallet || !hostDid) return;
    const who = member ? { member } : {};
    if (tickets.wallet.takeTickets) {
      setTaking(missing.length === 1 ? missing[0]!.title : `${missing.length} tickets`);
      try {
        await tickets.wallet.takeTickets({ hostDid, electionIds: missing.map((i) => i.election!.electionId), ...who });
      } catch (e) {
        if (!declinedInWallet(e)) setTakeError(e instanceof Error ? e.message : String(e));
      }
      setTaking(null);
      void qc.invalidateQueries({ queryKey: ["member-elections", hostDid, member] });
      return;
    }
    for (const i of missing) {
      setTaking(i.title);
      try {
        await tickets.wallet.takeTicket({ hostDid, electionId: i.election!.electionId, ...who });
      } catch (e) {
        if (!declinedInWallet(e)) break;
      }
    }
    setTaking(null);
    void qc.invalidateQueries({ queryKey: ["member-elections", hostDid, member] });
  };

  return (
    <>
      <section className="bd-hero">
        <div>
          <p className="eyebrow">
            <SquareKanban size={16} aria-hidden="true" /> Board
          </p>
          <h1>{board.title}</h1>
          {board.description && <p className="lead">{board.description}</p>}
        </div>
        <div className="bd-hero-actions">
          {tickets.wallet && open.length > 0 && (
            <button
              type="button"
              className="btn btn-ghost"
              onClick={takeAll}
              disabled={missing.length === 0 || taking !== null}
              title="Your wallet takes one ticket per idea, each in its own window."
            >
              <TicketCheck size={16} aria-hidden="true" />
              {taking
                ? `Taking: ${taking}…`
                : missing.length > 0
                  ? `Take your tickets (${missing.length})`
                  : tickets.ready
                    ? "All tickets held"
                    : "Checking your wallet…"}
            </button>
          )}
          {takesProposals(board) && (
            <button type="button" className="btn btn-primary" onClick={() => setProposing(true)}>
              <Plus size={16} aria-hidden="true" /> Propose an idea
            </button>
          )}
        </div>
      </section>

      {takeError && (
        <div className="alert" role="alert">
          <p>{takeError}</p>
        </div>
      )}
      <section className="bd-strip" aria-label="Where the board stands">
        <div>
          <div className="bd-k">Phase</div>
          <div className="bd-v">{PHASE_LABEL[phase]}</div>
        </div>
        <div>
          <div className="bd-k">Proposals close</div>
          <div className="bd-v">{when(board.proposals.closesAt)}</div>
        </div>
        <div>
          <div className="bd-k">Votes close</div>
          <div className="bd-v">{when(board.voting.closesAt)}</div>
        </div>
        <div>
          <div className="bd-k">Ideas</div>
          <div className="bd-v">
            {ideas.filter((i) => i.state !== "withdrawn").length} <small>{open.length} open for votes</small>
          </div>
        </div>
      </section>
      {board.selectionRule && (
        <p className="muted bd-rule">
          <strong>How ideas are chosen:</strong> {board.selectionRule}
        </p>
      )}

      <div className="bd-toolbar">
        {(board.timetable?.length ?? 0) > 0 && (
          <div className="bd-tabs" role="tablist" aria-label="View">
            <button type="button" role="tab" aria-selected={view === "board"} onClick={() => setView("board")}>
              Board
            </button>
            <button type="button" role="tab" aria-selected={view === "schedule"} onClick={() => setView("schedule")}>
              Schedule
            </button>
          </div>
        )}
        {view === "board" && (board.topics?.length ?? 0) > 0 && (
          <div className="bd-chips" aria-label="Filter by topic">
            <button type="button" className="bd-chip" aria-pressed={topic === null} onClick={() => setTopic(null)}>
              All
            </button>
            {board.topics!.map((t) => (
              <button key={t} type="button" className="bd-chip" aria-pressed={topic === t} onClick={() => setTopic(t)}>
                {t}
              </button>
            ))}
          </div>
        )}
        {view === "board" && (
          <label className="bd-search">
            <Search size={16} aria-hidden="true" />
            <input
              type="search"
              placeholder="Search ideas"
              aria-label="Search ideas"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
        )}
      </div>

      {view === "board" ? (
        <>
          <div className="bd-board-wrap">
            <div className="bd-board">
              {LANES.map((lane) => {
                const list = laneIdeas(visible, lane);
                return (
                  <section key={lane} className="bd-lane" data-lane={lane} aria-labelledby={`lane-${lane}`}>
                    <div className="bd-lane-head">
                      <span className="bd-dot" aria-hidden="true" />
                      <h2 id={`lane-${lane}`}>{LANE_LABEL[lane]}</h2>
                      <span className="bd-count">{list.length}</span>
                    </div>
                    <p className="bd-lane-note">{LANE_NOTE[lane]}</p>
                    <div className="bd-lane-list">
                      {list.map((i) => (
                        <IdeaCard
                          key={i.ideaId}
                          idea={i}
                          ticketHeld={i.election ? tickets.held.has(i.election.electionId) : false}
                          walletKnows={tickets.ready}
                          slot={board.timetable?.find((s) => s.slotId === i.decision?.slotId)}
                          votingFrom={notYetVoting(i, board)}
                          onOpen={() => setOpenId(i.ideaId)}
                        />
                      ))}
                      {lane === "proposed" && takesProposals(board) && (
                        <button type="button" className="bd-add" onClick={() => setProposing(true)}>
                          <Plus size={16} aria-hidden="true" /> Propose an idea
                        </button>
                      )}
                    </div>
                  </section>
                );
              })}
            </div>
          </div>

          {(set.length > 0 || yours.length > 0) && (
            <section className="bd-settled" aria-labelledby="settled-heading">
              <h2 id="settled-heading">Declined, merged and withdrawn</h2>
              <ul>
                {[...set, ...yours].map((i) => (
                  <li key={i.ideaId}>
                    <button type="button" className="bd-link" onClick={() => setOpenId(i.ideaId)}>
                      {i.title}
                    </button>{" "}
                    <span className="muted">— {settledWords(i, ideas)}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <NotesWall board={board} />
        </>
      ) : (
        <Schedule board={board} ideas={ideas} onOpen={setOpenId} />
      )}

      {current && (
        <IdeaPanel
          board={board}
          idea={current}
          hostDid={hostDid}
          member={member}
          ticketHeld={current.election ? tickets.held.has(current.election.electionId) : false}
          onClose={() => setOpenId(null)}
          onChanged={refresh}
        />
      )}
      {proposing && <ProposeDialog board={board} onClose={() => setProposing(false)} onDone={refresh} />}
    </>
  );
}

function settledWords(i: Idea, ideas: Idea[]): string {
  if (i.state === "withdrawn") return "you withdrew it";
  if (i.state === "merged") {
    const into = ideas.find((x) => x.ideaId === i.decision?.mergedInto);
    return into ? `merged into “${into.title}”` : "merged into another idea";
  }
  return i.decision?.reason ? `declined: ${i.decision.reason}` : "declined";
}

// ── Cards ───────────────────────────────────────────────────────────────────

/** What a member reads while an idea's election takes tickets but not yet ballots. */
function opensWords(v: NotYetVoting): string {
  return v.at ? `Voting opens ${when(v.at)}` : "Voting on this idea hasn't opened yet";
}

function Meter({ idea, votingFrom }: { idea: Idea; votingFrom: NotYetVoting | null }) {
  if (idea.state === "proposed") {
    return (
      <div className="bd-meter-row">
        <span>{idea.opening ? "Election opening…" : "No election yet"}</span>
      </div>
    );
  }
  const lead = leadingShare(idea);
  if (lead) {
    const pct = Math.round(lead.share * 100);
    return (
      <div className="bd-meter">
        <div className="bd-meter-bar" title={`${pct}% ${lead.label}`}>
          <b className="bd-yes" style={{ width: `${pct}%` }} />
        </div>
        <div className="bd-meter-row">
          <span>
            {pct}% {lead.label === "yes" ? "would attend" : lead.label}
          </span>
          <span>{lead.counted} ballots</span>
        </div>
      </div>
    );
  }
  const n = idea.election?.ballotsOnBoard;
  return (
    <div className="bd-meter-row">
      <span>
        {votingFrom
          ? opensWords(votingFrom)
          : n === undefined
            ? "Voting"
            : `${n} ballot${n === 1 ? "" : "s"} on the board`}
      </span>
    </div>
  );
}

function IdeaCard({
  idea,
  ticketHeld,
  walletKnows,
  slot,
  votingFrom,
  onOpen,
}: {
  idea: Idea;
  ticketHeld: boolean;
  walletKnows: boolean;
  slot?: { label: string; startsAt: string };
  votingFrom: NotYetVoting | null;
  onOpen: () => void;
}) {
  return (
    <button type="button" className="bd-idea" onClick={onOpen}>
      <span className="bd-idea-top">
        {idea.format && <span className="bd-fmt">{idea.format}</span>}
        {idea.topic && <span className="bd-tag">{idea.topic}</span>}
        <span className="bd-push">
          {idea.state === "open" && walletKnows ? (
            ticketHeld ? (
              <span className="pill pill-ok">
                <TicketCheck size={12} aria-hidden="true" /> Ticket held
              </span>
            ) : (
              <span className="pill bd-pill-warn">No ticket yet</span>
            )
          ) : slot ? (
            <span className="bd-slot">
              {slot.label} · {when(slot.startsAt, { weekday: "short", hour: "2-digit", minute: "2-digit" })}
            </span>
          ) : null}
        </span>
      </span>
      <span className="bd-idea-title">{idea.title}</span>
      <span className="bd-idea-desc">{idea.description}</span>
      <Meter idea={idea} votingFrom={votingFrom} />
      <span className="bd-idea-foot">
        <span className="bd-who">{authorName(idea.proposer)}</span>
        <span className="bd-notes">
          <MessageSquare size={14} aria-hidden="true" />
          {idea.noteCount}
        </span>
      </span>
    </button>
  );
}

// ── One idea ────────────────────────────────────────────────────────────────

function IdeaPanel({
  board,
  idea,
  hostDid,
  member,
  ticketHeld,
  onClose,
  onChanged,
}: {
  board: Board;
  idea: Idea;
  hostDid?: string;
  member?: string;
  ticketHeld: boolean;
  onClose: () => void;
  onChanged: () => void;
}) {
  const qc = useQueryClient();
  const votingFrom = notYetVoting(idea, board);
  const closeRef = useRef<HTMLButtonElement>(null);
  const drawerRef = useRef<HTMLElement>(null);
  const [after, setAfter] = useState<string | null>(null);
  // The shared modal contract (`useModal`, #2610): Tab stays in the drawer and
  // focus goes back to the idea that opened it.
  const dismiss = useModal(drawerRef, onClose, { initialFocus: closeRef });

  const wallet = walletElections();
  const who = member ? { member } : {};
  const electionId = idea.election?.electionId;
  const refreshTickets = () => void qc.invalidateQueries({ queryKey: ["member-elections", hostDid, member] });
  const ticket = useMutation({
    mutationFn: () => wallet!.takeTicket({ hostDid: hostDid!, electionId: electionId!, ...who }),
    onSettled: refreshTickets,
  });
  const vote = useMutation({
    mutationFn: () => wallet!.vote({ hostDid: hostDid!, electionId: electionId!, ...who }),
    onSuccess: () =>
      setAfter("Your wallet window closed. If you cast a ballot, the count on the board updates within a few minutes."),
    onSettled: refreshTickets,
  });
  const withdraw = useMutation({ mutationFn: () => withdrawIdea(idea.ideaId), onSuccess: onChanged });
  const confirm = useConfirm();
  const failure = [ticket.error, vote.error, withdraw.error].find((x) => x && !declinedInWallet(x));
  const lead = leadingShare(idea);
  const q = board.template.questions[0];

  return (
    <>
      <div className="bd-scrim" onClick={dismiss} aria-hidden="true" />
      <aside ref={drawerRef} className="bd-drawer" role="dialog" aria-modal="true" aria-labelledby="idea-title">
        <div className="bd-drawer-head">
          <StatePill idea={idea} votingFrom={votingFrom} />
          <span className="bd-fmt">{[idea.format, idea.topic].filter(Boolean).join(" · ")}</span>
          <button ref={closeRef} type="button" className="btn btn-ghost btn-sm bd-push" onClick={onClose} aria-label="Close">
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <div className="bd-drawer-body">
          <div>
            <h2 id="idea-title" className="bd-drawer-title">
              {idea.title}
            </h2>
            <p className="muted bd-pre">{idea.description}</p>
            <p className="small muted">
              Proposed by {authorName(idea.proposer)} on {formatDate(idea.proposedAt)}
            </p>
          </div>

          {failure ? (
            <div className="alert" role="alert">
              <p>{problem(failure)}</p>
            </div>
          ) : null}

          {idea.state === "proposed" && idea.proposer.you && (
            <div className="actions">
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={async () => {
                  const ok = await confirm({
                    title: "Withdraw your idea?",
                    message: "It leaves the board for good; to put it forward again, propose it anew.",
                    confirmLabel: "Withdraw",
                    destructive: true,
                  });
                  if (ok) withdraw.mutate();
                }}
                disabled={withdraw.isPending}
              >
                Withdraw your idea
              </button>
            </div>
          )}

          <section className="bd-block" aria-labelledby="election-heading">
            <div className="card-head">
              <Vote size={16} aria-hidden="true" />
              <h3 id="election-heading">Election</h3>
              {electionId && (
                <a className="bd-push small" href={electionHref(electionId)}>
                  Election details
                </a>
              )}
            </div>
            {!idea.election ? (
              <p className="muted">
                {idea.state === "proposed"
                  ? "Not open yet. A facilitator reviews new ideas and opens an election for each one they accept. Until then, notes are the best way to show interest."
                  : "This idea was not put to a vote."}
              </p>
            ) : lead ? (
              <>
                {idea.election.result!.questions[0] && (
                  <Results counts={idea.election.result!.questions[0].choice as Record<string, number> | undefined} labels={q} />
                )}
                <p className="small muted">
                  {idea.election.result!.ballotsCounted} ballots counted
                  {idea.election.certified ? " · certified by the community" : " · checked against the board, not yet certified"}
                </p>
              </>
            ) : (
              <>
                <Meter idea={idea} votingFrom={votingFrom} />
                <p className="small muted">How people voted is counted when voting closes on {when(board.voting.closesAt)}.</p>
                {idea.state === "open" &&
                  (wallet && hostDid ? (
                    <div className="actions">
                      {ticketHeld && votingFrom ? (
                        <>
                          <span className="pill pill-ok">
                            <TicketCheck size={12} aria-hidden="true" /> Ticket held
                          </span>
                          <p className="small muted">{opensWords(votingFrom)}. Your ticket is ready; come back then to vote.</p>
                        </>
                      ) : ticketHeld ? (
                        <>
                          <button type="button" className="btn btn-primary" onClick={() => vote.mutate()} disabled={vote.isPending}>
                            <Vote size={16} aria-hidden="true" /> Vote in your wallet
                          </button>
                          <span className="pill pill-ok">
                            <TicketCheck size={12} aria-hidden="true" /> Ticket held
                          </span>
                        </>
                      ) : (
                        <button type="button" className="btn btn-primary" onClick={() => ticket.mutate()} disabled={ticket.isPending}>
                          Take your ticket
                        </button>
                      )}
                    </div>
                  ) : (
                    <p className="muted">You vote with your VTA Wallet browser extension. Install it, or allow it on this site, then reload.</p>
                  ))}
                {after && <p className="small muted" role="status">{after}</p>}
              </>
            )}
            {idea.election && (
              <p className="bd-privacy">
                <Lock size={14} aria-hidden="true" />
                <span>
                  Your wallet takes the ticket and sends your ballot to the ballot box itself. This page never sees your
                  choice, and can&rsquo;t tell whether you voted.
                  {board.template.revote === "replace" ? " You can vote again before voting closes; only your last ballot counts." : ""}
                </span>
              </p>
            )}
            {q && (
              <dl className="facts">
                <div>
                  <dt>Question</dt>
                  <dd>{q.text ?? q.key}</dd>
                </div>
                <div>
                  <dt>Ballots</dt>
                  <dd>{board.template.secrecy === "open" ? "Open ballot" : "Secret ballot"}, {board.template.board.visibility} board</dd>
                </div>
                <div>
                  <dt>Binding</dt>
                  <dd>No. Facilitators choose ideas with the results in view.</dd>
                </div>
              </dl>
            )}
          </section>

          <section className="bd-block" aria-labelledby="notes-heading">
            <div className="card-head">
              <MessageSquare size={16} aria-hidden="true" />
              <h3 id="notes-heading">Notes</h3>
            </div>
            <NotesThread board={board} ideaId={idea.ideaId} closed={idea.state === "withdrawn"} onAdded={onChanged} />
          </section>
        </div>
      </aside>
    </>
  );
}

function StatePill({ idea, votingFrom }: { idea: Idea; votingFrom: NotYetVoting | null }) {
  switch (idea.state) {
    case "open":
      return <span className="pill bd-pill-brand">{votingFrom ? "Voting soon" : "Voting"}</span>;
    case "selected":
      return <span className="pill pill-ok">Selected</span>;
    case "notSelected":
      return <span className="pill">Not this time</span>;
    case "declined":
      return <span className="pill">Declined</span>;
    case "merged":
      return <span className="pill">Merged</span>;
    case "withdrawn":
      return <span className="pill">Withdrawn</span>;
    default:
      return <span className="pill">Proposed</span>;
  }
}

type FirstQuestion = Board["template"]["questions"][number];

function Results({ counts, labels }: { counts?: Record<string, number>; labels?: FirstQuestion }) {
  if (!counts) return null;
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const optionLabel = (key: string) => {
    const opts = (labels as { options?: { key: string; label?: string }[] } | undefined)?.options;
    return opts?.find((o) => o.key === key)?.label ?? key;
  };
  return (
    <div className="bd-results">
      {Object.entries(counts).map(([k, n]) => (
        <div key={k} className="bd-result-row">
          <span>{optionLabel(k)}</span>
          <span className="bd-bar">
            <b style={{ width: `${Math.round((n / total) * 100)}%` }} className={k === "yes" ? "bd-yes" : ""} />
          </span>
          <span>{Math.round((n / total) * 100)}%</span>
        </div>
      ))}
    </div>
  );
}

// ── Notes ───────────────────────────────────────────────────────────────────

function NoteSlip({ note, onWithdrawn, tilt }: { note: Note; onWithdrawn?: () => void; tilt?: number }) {
  const withdraw = useMutation({ mutationFn: () => withdrawNote(note.noteId), onSuccess: onWithdrawn });
  const confirm = useConfirm();
  const gone = note.state !== "visible";
  return (
    <div className={gone ? "bd-slip bd-slip-gone" : "bd-slip"} style={tilt ? { ["--tilt" as string]: `${tilt}deg` } : undefined}>
      {note.text && !gone ? (
        <p>{note.text}</p>
      ) : note.state === "hidden" ? (
        <p className="muted">
          Hidden by a facilitator{note.hiddenReason ? `: ${note.hiddenReason}` : ""}.{note.text ? ` Your note: “${note.text}”` : ""}
        </p>
      ) : (
        <p className="muted">A note was withdrawn.</p>
      )}
      <div className="bd-by">
        <span>{authorName(note.author)}</span>
        {note.author.you && note.state !== "withdrawn" && (
          <button
            type="button"
            className="bd-link small"
            onClick={async () => {
              const ok = await confirm({
                title: "Withdraw your note?",
                message: "Its text is taken off the board; the thread shows that a note was withdrawn.",
                confirmLabel: "Withdraw",
                destructive: true,
              });
              if (ok) withdraw.mutate();
            }}
            disabled={withdraw.isPending}
          >
            Withdraw
          </button>
        )}
      </div>
    </div>
  );
}

function Compose({
  board,
  ideaId,
  onAdded,
  label,
}: {
  board: Board;
  ideaId?: string;
  onAdded: () => void;
  label: string;
}) {
  const [text, setText] = useState("");
  const id = `note-${ideaId ?? "board"}`;
  const add = useMutation({
    mutationFn: () => addNote(board.boardId, text.trim(), ideaId),
    onSuccess: () => {
      setText("");
      onAdded();
    },
  });
  return (
    <form
      className="bd-compose"
      onSubmit={(e) => {
        e.preventDefault();
        if (text.trim()) add.mutate();
      }}
    >
      <label htmlFor={id} className="small">
        {label}
      </label>
      <textarea id={id} maxLength={1000} value={text} onChange={(e) => setText(e.target.value)} placeholder="Signed as you, visible to this board" />
      {add.isError && <p className="error small">{problem(add.error)}</p>}
      <div>
        <button type="submit" className="btn btn-ghost btn-sm" disabled={!text.trim() || add.isPending}>
          Add note
        </button>
      </div>
    </form>
  );
}

function NotesThread({ board, ideaId, closed, onAdded }: { board: Board; ideaId: string; closed: boolean; onAdded: () => void }) {
  const qc = useQueryClient();
  const key = ["board-notes", board.boardId, ideaId];
  const notes = useQuery({ queryKey: key, queryFn: () => listNotes(board.boardId, ideaId), retry: false });
  const changed = () => {
    void qc.invalidateQueries({ queryKey: key });
    onAdded();
  };
  return (
    <>
      {notes.isPending ? (
        <p className="muted">Loading…</p>
      ) : notes.isError ? (
        <p className="error">{problem(notes.error)}</p>
      ) : notes.data.length === 0 ? (
        <p className="muted">No notes yet. Offer to help, ask a question, or say what you&rsquo;d want covered.</p>
      ) : (
        <div className="bd-thread">
          {notes.data.map((n) => (
            <NoteSlip key={n.noteId} note={n} onWithdrawn={changed} />
          ))}
        </div>
      )}
      {takesNotes(board) && !closed && (
        <>
          <Disclosure />
          <Compose board={board} ideaId={ideaId} onAdded={changed} label="Your note" />
        </>
      )}
    </>
  );
}

const TILTS = [-1.2, 0.8, -0.4, 1.1, -0.7, 0.5];

function NotesWall({ board }: { board: Board }) {
  const qc = useQueryClient();
  const key = ["board-notes", board.boardId, "board"];
  const notes = useQuery({ queryKey: key, queryFn: () => listNotes(board.boardId), retry: false });
  const changed = () => void qc.invalidateQueries({ queryKey: key });
  return (
    <section className="bd-wall" aria-labelledby="wall-heading">
      <div className="bd-section-head">
        <h2 id="wall-heading">
          <StickyNote size={18} aria-hidden="true" /> Notes on the board
        </h2>
        <span className="muted">Logistics, themes, offers to help.</span>
      </div>
      {notes.isError && <p className="error">{problem(notes.error)}</p>}
      <div className="bd-notes-wall">
        {(notes.data ?? []).map((n, i) => (
          <NoteSlip key={n.noteId} note={n} onWithdrawn={changed} tilt={TILTS[i % TILTS.length]} />
        ))}
        {takesNotes(board) && (
          <div className="bd-slip bd-slip-new">
            <Compose board={board} onAdded={changed} label="Add a note to the board" />
          </div>
        )}
      </div>
      {takesNotes(board) && <Disclosure />}
    </section>
  );
}

// ── The timetable ───────────────────────────────────────────────────────────

function Schedule({ board, ideas, onOpen }: { board: Board; ideas: Idea[]; onOpen: (id: string) => void }) {
  const slots = board.timetable ?? [];
  const g = grid(slots);
  const placed = (slotId: string) => ideas.find((i) => i.state === "selected" && i.decision?.slotId === slotId);
  return (
    <section aria-labelledby="schedule-heading">
      <div className="bd-section-head">
        <h2 id="schedule-heading">
          <CalendarDays size={18} aria-hidden="true" /> Schedule
        </h2>
        <span className="muted">Facilitators place selected ideas after the count. Open slots fill as more are chosen.</span>
      </div>
      <div className="bd-sched-wrap">
        <table className="bd-sched">
          <thead>
            <tr>
              <th scope="col">
                <span className="sr-only">Time</span>
              </th>
              {g.places.map((p) => (
                <th key={p} scope="col">
                  {p}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {g.times.map((t) => (
              <tr key={t}>
                <th scope="row">{when(t, { weekday: "short", hour: "2-digit", minute: "2-digit" })}</th>
                {g.places.map((p) => {
                  const slot = g.at(p, t);
                  const idea = slot ? placed(slot.slotId) : undefined;
                  return (
                    <td key={p}>
                      {idea ? (
                        <button type="button" className="bd-sess" onClick={() => onOpen(idea.ideaId)}>
                          <b>{idea.title}</b>
                          <span>
                            {authorName(idea.proposer)}
                            {idea.format ? ` · ${idea.format}` : ""}
                          </span>
                        </button>
                      ) : slot ? (
                        <span className="bd-open-slot">Open slot</span>
                      ) : null}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// ── Proposing ───────────────────────────────────────────────────────────────

function ProposeDialog({ board, onClose, onDone }: { board: Board; onClose: () => void; onDone: () => void }) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [format, setFormat] = useState(board.formats?.[0] ?? "");
  const [topic, setTopic] = useState(board.topics?.[0] ?? "");
  const titleRef = useRef<HTMLInputElement>(null);
  const surfaceRef = useRef<HTMLDivElement>(null);
  const propose = useMutation({
    mutationFn: () =>
      proposeIdea(board.boardId, {
        title: title.trim(),
        description: description.trim(),
        ...(format ? { format } : {}),
        ...(topic ? { topic } : {}),
      }),
    onSuccess: () => {
      onDone();
      onClose();
    },
  });
  // The shared modal contract (`useModal`, #2610); Escape does nothing while
  // the proposal is being sent.
  useModal(surfaceRef, onClose, { locked: propose.isPending, initialFocus: titleRef });
  const q = board.template.questions[0];
  return (
    <div ref={surfaceRef} className="bd-modal" role="dialog" aria-modal="true" aria-labelledby="propose-heading">
      <form
        className="bd-sheet"
        onSubmit={(e) => {
          e.preventDefault();
          propose.mutate();
        }}
      >
        <div>
          <p className="eyebrow">{board.title}</p>
          <h2 id="propose-heading">Propose an idea</h2>
        </div>
        <label className="field">
          <span>Title</span>
          <input ref={titleRef} required maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
        </label>
        <label className="field">
          <span>What would you cover?</span>
          <textarea
            required
            maxLength={4000}
            rows={4}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Two or three sentences. Who should come, and what will they leave with?"
          />
        </label>
        {(board.formats?.length ?? 0) > 0 && (
          <fieldset className="bd-seg">
            <legend>Format</legend>
            {board.formats!.map((f) => (
              <label key={f}>
                <input type="radio" name="format" value={f} checked={format === f} onChange={() => setFormat(f)} />
                <span>{f}</span>
              </label>
            ))}
          </fieldset>
        )}
        {(board.topics?.length ?? 0) > 0 && (
          <label className="field">
            <span>Topic</span>
            <select value={topic} onChange={(e) => setTopic(e.target.value)}>
              {board.topics!.map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </label>
        )}
        <div className="bd-template">
          <strong>When a facilitator accepts it, an election opens for this idea</strong>
          {q && <span>Question: “{q.text ?? q.key}”</span>}
          <span>Votes close {when(board.voting.closesAt)}. Not binding.</span>
        </div>
        <Disclosure />
        {propose.isError && (
          <div className="alert" role="alert">
            <p>{problem(propose.error)}</p>
          </div>
        )}
        <div className="bd-sheet-foot">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={propose.isPending || !title.trim() || !description.trim()}>
            Propose
          </button>
        </div>
      </form>
    </div>
  );
}
