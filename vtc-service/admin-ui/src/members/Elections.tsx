// The community's elections in the member portal:
//
//   #/elections        The elections the community lets you vote in.
//   #/elections/<id>   One election: what it asks, how it is run, and the
//                      buttons that hand off to your wallet.
//
// Everything here is read through the member's wallet (`wallet-elections.ts`).
// Taking a ticket and voting happen in the wallet's own window: this page never
// sees a choice, and after a vote it is not told whether one was cast.
//
// Beside the community's own list are the elections the member's agent holds a
// notification of (VTI-NTF-063): of those, the page shows only the identifier,
// the party it is put to, the period and whether it was withdrawn. Opening one
// passes that party on as `memberOf`, so the wallet — asking the member in its
// own window first — presents only the membership credential that party issued
// (VTI-VOT-015, 016). The page presents nothing itself.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleAlert, TicketCheck, Vote } from "lucide-react";

import { textReleaseWarning } from "@/lib/election-manifest";
import { groupByBoard } from "@/lib/election-origin";

import { listAllBoards } from "./boards-api";
import { InstallWallet } from "./InstallWallet";
import { Crumbs } from "./member-card";
import {
  STAGE_LABEL,
  actionableFirst,
  declinedInWallet,
  memberOfFor,
  notifiedOnly,
  refusalKind,
  stageOf,
  walletElections,
  type PageElection,
  type PageElectionView,
  type PageNotifiedElection,
  type WalletElections,
} from "./wallet-elections";
import { formatDateTime } from "@/lib/format";
import { messageOf } from "@/lib/messages";

/** A voting deadline, with its zone (#2613). */
const when = formatDateTime;

export function electionHref(electionId: string): string {
  return `#/elections/${encodeURIComponent(electionId)}`;
}

function NoWallet() {
  return (
    <section className="card" aria-labelledby="no-wallet-heading">
      <div className="card-head">
        <Vote size={18} aria-hidden="true" />
        <h2 id="no-wallet-heading">You vote with your wallet</h2>
      </div>
      <p className="muted">
        Elections open through your VTA Wallet browser extension. It takes your ticket and fills in your ballot in its
        own window, through your own agent, and sends your vote to the ballot box itself — so this site never sees how
        you voted. Install it, or allow it on this site from its popup, then reload this page.
      </p>
      <InstallWallet open={false} />
    </section>
  );
}

function WalletError({ error }: { error: unknown }) {
  return (
    <div className="alert" role="alert">
      <p className="alert-title">Your wallet couldn&rsquo;t read this community&rsquo;s elections.</p>
      <p>{error instanceof Error ? error.message : String(error)}</p>
    </div>
  );
}

/** What the community answered, through the wallet, in words. `electionUnknown` is the same
 *  answer whether the election does not exist, is not open to the member or is put to a party
 *  whose membership was not shown (VTI-VOT-015, 025), so it says all three; `indeterminate`
 *  is a check the community could not complete, which records nothing. */
export function Refusal({ error, memberOf }: { error: unknown; memberOf?: string }) {
  const said = messageOf(error);
  const kind = refusalKind(error);
  if (kind === "other") {
    return (
      <div className="alert" role="alert">
        <p>{said}</p>
      </div>
    );
  }
  return (
    <div className="alert" role="alert">
      {kind === "electionUnknown" ? (
        <>
          <p className="alert-title">This community shows you no such election.</p>
          <p>
            It may not exist, may not be open to you, or may be put only to the members of a party you did not show
            your membership of. The community gives the same answer in each case, so this page can&rsquo;t tell which.
            {memberOf ? (
              <>
                {" "}
                You were told about it as a member of <code>{memberOf}</code>: your wallet shows that membership only if
                you hold a credential that party issued, and only once you agree in its own window.
              </>
            ) : null}
          </p>
        </>
      ) : (
        <>
          <p className="alert-title">The community couldn&rsquo;t check your membership just now.</p>
          <p>
            Its issuer&rsquo;s DID document or status list could not be read, so nothing was decided and nothing was
            recorded. Try again in a little while.
          </p>
        </>
      )}
      <p className="muted">Your wallet said: {said}</p>
    </div>
  );
}

/** Who an election was put to, as a notification names it. */
function audienceOf(n: PageNotifiedElection, hostDid: string) {
  return n.audience === hostDid ? <>this community&rsquo;s members</> : <>the members of <code>{n.audience}</code></>;
}

function StagePill({ election }: { election: Pick<PageElection, "state" | "votingOpensAt" | "votingClosesAt"> }) {
  const stage = stageOf(election);
  const ok = stage === "voting" || stage === "ticketsOpen";
  return <span className={ok ? "pill pill-ok" : "pill"}>{STAGE_LABEL[stage]}</span>;
}

/** What opening an election from the list lets the member do there. */
function openLabel(e: PageElection): string {
  const stage = stageOf(e);
  if (stage === "voting") return "Open to vote";
  if (stage === "ticketsOpen" && !e.ticketHeld) return "Open to take your ticket";
  return "Open";
}

// ── The list ────────────────────────────────────────────────────────────────

/** `member`: the DID signed in to this portal — who the wallet acts as here. */
export function ElectionsPage({ hostDid, member }: { hostDid: string; member?: string }) {
  const wallet = walletElections();
  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Elections" }]} />
      <section className="welcome">
        <p className="eyebrow">Member portal</p>
        <h1>Elections</h1>
        <p className="lead">
          Polls and elections you can vote in. Your wallet takes your ticket and holds your ballot; this site never
          sees how you voted.
        </p>
      </section>
      {wallet ? <ElectionList wallet={wallet} hostDid={hostDid} member={member} /> : <NoWallet />}
    </main>
  );
}

function ElectionList({ wallet, hostDid, member }: { wallet: WalletElections; hostDid: string; member?: string }) {
  const list = useQuery({
    queryKey: ["member-elections", hostDid, member],
    queryFn: () => wallet.list({ hostDid, ...(member ? { member } : {}) }),
    retry: false,
  });
  // Only to name the boards elections came from; read through the portal like the Boards page.
  // Without it every board's elections are still shown, under the board's identifier.
  const boards = useQuery({ queryKey: ["member-boards", "all"], queryFn: listAllBoards, retry: false });
  if (list.isPending) return <p className="muted">Asking your wallet…</p>;
  if (list.isError) return <WalletError error={list.error} />;
  const elections = actionableFirst(list.data.elections);
  const told = notifiedOnly(list.data);
  if (elections.length === 0 && told.length === 0) {
    return <p className="muted">There are no elections you can vote in right now.</p>;
  }
  // Listed elections the member was also told about: one card each, marked.
  const toldIds = new Set(list.data.notified.filter((n) => n.status === "available").map((n) => n.electionId));
  const titles = boards.data ? new Map(boards.data.boards.map((b) => [b.boardId, b.title])) : null;
  // A board the member no longer sees is closed or archived to them, not necessarily deleted.
  const grouped = groupByBoard(elections, titles, "A board no longer shown");
  const notifiedCards = told.length > 0 ? <NotifiedCards notified={told} hostDid={hostDid} /> : null;
  if (grouped.boards.length === 0) {
    return (
      <>
        {grouped.standalone.length > 0 && <ElectionCards elections={grouped.standalone} label="Elections" told={toldIds} />}
        {notifiedCards}
      </>
    );
  }
  return (
    <>
      {grouped.standalone.length > 0 && (
        <ElectionCards elections={grouped.standalone} label="Stand-alone elections" told={toldIds} />
      )}
      {grouped.boards.map((b) => (
        <details key={b.boardId} className="election-group" open>
          <summary>
            <strong>{b.title}</strong> · {b.items.length} idea{b.items.length === 1 ? "" : "s"} to vote on
          </summary>
          {b.known && (
            <p className="muted">
              <a href={`#/boards/${encodeURIComponent(b.boardId)}`}>Open the board</a>
            </p>
          )}
          <ElectionCards elections={b.items} label={`${b.title} elections`} told={toldIds} />
        </details>
      ))}
      {notifiedCards}
    </>
  );
}

/** Elections the member was told about that the community's list does not show them: only what
 *  the notification says (VTI-NTF-063) until the member opens one. */
function NotifiedCards({ notified, hostDid }: { notified: PageNotifiedElection[]; hostDid: string }) {
  return (
    <section className="election-notified" aria-labelledby="notified-heading">
      <h2 id="notified-heading">You were told about these</h2>
      <p className="muted">
        Your agent holds a notification of each. This site sees only what the notification says until you open one;
        opening one put to another party&rsquo;s members, your wallet asks before it shows this community that
        membership.
      </p>
      <ul className="election-list" aria-label="Elections you were told about">
        {notified.map((n) => (
          <li key={n.electionId} className="card">
            <div className="card-head">
              <Vote size={18} aria-hidden="true" />
              <h2>{n.status === "available" ? <a href={electionHref(n.electionId)}>{n.electionId}</a> : n.electionId}</h2>
              <span className="pill">{n.status === "available" ? "You were told about this" : "Notice withdrawn"}</span>
            </div>
            <p className="muted">
              Put to {audienceOf(n, hostDid)}
              {n.votingOpensAt && n.votingClosesAt ? (
                <>
                  {" "}
                  · voting {when(n.votingOpensAt)} – {when(n.votingClosesAt)}
                </>
              ) : null}
            </p>
            {n.status === "available" ? (
              <a className="btn btn-ghost btn-sm" href={electionHref(n.electionId)}>
                Open in my wallet
              </a>
            ) : (
              <p className="muted">The community withdrew this notice: the election was cancelled or closed early.</p>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

function ElectionCards({ elections, label, told }: { elections: PageElection[]; label: string; told: Set<string> }) {
  return (
    <ul className="election-list" aria-label={label}>
      {elections.map((e) => (
        <li key={e.electionId} className="card">
          <div className="card-head">
            <Vote size={18} aria-hidden="true" />
            <h2>
              <a href={electionHref(e.electionId)}>{e.title || e.electionId}</a>
            </h2>
            <StagePill election={e} />
          </div>
          <p className="muted">
            Voting {when(e.votingOpensAt)} – {when(e.votingClosesAt)}
            {e.binding ? " · binding" : ""}
            {e.ticketHeld ? " · you have your ticket" : ""}
            {told.has(e.electionId) ? " · you were told about this" : ""}
          </p>
          <a className="btn btn-ghost btn-sm" href={electionHref(e.electionId)}>
            {openLabel(e)}
          </a>
        </li>
      ))}
    </ul>
  );
}

// ── One election ────────────────────────────────────────────────────────────

export function ElectionPage({ hostDid, member, electionId }: { hostDid: string; member?: string; electionId: string }) {
  const wallet = walletElections();
  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Elections", href: "#/elections" }, { label: electionId }]} />
      {wallet ? <ElectionDetail wallet={wallet} hostDid={hostDid} member={member} electionId={electionId} /> : <NoWallet />}
    </main>
  );
}

function ElectionDetail({
  wallet,
  hostDid,
  member,
  electionId,
}: {
  wallet: WalletElections;
  hostDid: string;
  member?: string;
  electionId: string;
}) {
  const qc = useQueryClient();
  const asMember = member ? { member } : {};
  // Whether the community issued the ticket, and whether the member was told about this
  // election, come from the member's own list.
  const listed = useQuery({
    queryKey: ["member-elections", hostDid, member],
    queryFn: () => wallet.list({ hostDid, ...asMember }),
    retry: false,
  });
  // The party a standing notification names, passed on so the wallet presents only the
  // credential that party issued, once the member agreed (VTI-VOT-016). Only a wallet that
  // reports notifications gives one, so an older wallet is never sent a field it refuses.
  const memberOf = memberOfFor(listed.data, electionId);
  const who = { ...asMember, ...(memberOf ? { memberOf } : {}) };
  const shown = useQuery({
    queryKey: ["member-election", hostDid, member, electionId, memberOf ?? null],
    queryFn: () => wallet.show({ hostDid, electionId, ...who }),
    // Wait for the list, so the read names the party at the first try rather than after.
    enabled: !listed.isPending,
    retry: false,
  });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["member-elections", hostDid, member] });
  const ticket = useMutation({
    mutationFn: () => wallet.takeTicket({ hostDid, electionId, ...who }),
    onSettled: refresh,
  });
  const vote = useMutation({
    mutationFn: () => wallet.vote({ hostDid, electionId, ...who }),
    onSettled: refresh,
  });
  const check = useMutation({
    mutationFn: () => wallet.checkVote!({ hostDid, electionId, ...who }),
  });

  if (shown.isPending) return <p className="muted">Asking your wallet…</p>;
  if (shown.isError) {
    if (declinedInWallet(shown.error)) {
      return (
        <p role="status" className="muted">
          {shown.error instanceof Error ? shown.error.message : String(shown.error)}{" "}
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => void shown.refetch()}>
            Ask my wallet again
          </button>
        </p>
      );
    }
    return refusalKind(shown.error) === "other" ? (
      <WalletError error={shown.error} />
    ) : (
      <Refusal error={shown.error} memberOf={memberOf} />
    );
  }
  const e: PageElectionView = shown.data;
  const held = listed.data?.elections.find((x) => x.electionId === electionId)?.ticketHeld ?? false;
  const stage = stageOf(e);
  const canTicket = !held && (stage === "ticketsOpen" || stage === "voting");
  const canVote = stage === "voting";
  // VTI-VOT-090: below 10, the member is told before taking a ticket.
  const releaseWarning = textReleaseWarning(e.textReleaseThreshold) !== null;
  // VTI-VOT-053: once voting has closed, the member's wallet can check their vote against the
  // board the community kept. This page is never told whether they voted, so it offers it to all.
  const canCheck = (e.state === "closed" || e.state === "tallied") && typeof wallet.checkVote === "function";
  const failure = [ticket.error, vote.error, check.error].find((x) => x && !declinedInWallet(x));

  return (
    <>
      <section className="welcome">
        <p className="eyebrow">
          Election <StagePill election={e} />
        </p>
        <h1>{e.title || e.electionId}</h1>
        {e.description && <p className="lead election-description">{e.description}</p>}
      </section>

      <div className="grid">
        <section className="card" aria-labelledby="take-part-heading">
          <div className="card-head">
            <TicketCheck size={18} aria-hidden="true" />
            <h2 id="take-part-heading">Take part</h2>
          </div>
          <p className="muted">
            {held
              ? "You have your ticket. When voting is open, vote through your wallet: it shows the ballot in its own window and sends your vote to the ballot box itself."
              : "First take your ticket — ideally well before you vote. The community signs it without seeing it, so it never knows which ballot is yours."}
          </p>
          {ticket.data && (
            <p role="status">{ticket.data.taken ? "Your ticket is in your wallet. Come back to vote later." : "You already had your ticket."}</p>
          )}
          {vote.data?.ticketTaken && (
            <p role="status">Your wallet took your ticket first. Come back later to vote — voting straight away could be paired with it by time.</p>
          )}
          {vote.isSuccess && !vote.data.ticketTaken && (
            <p role="status" className="muted">
              Your wallet shows how your vote went, and you can open it again here at any time to see whether you
              have voted or to change your vote. This site isn&rsquo;t told either way.
            </p>
          )}
          {failure ? <Refusal error={failure} memberOf={memberOf} /> : null}
          <p>
            {canTicket && (
              <button type="button" className="btn btn-ghost" disabled={ticket.isPending} onClick={() => ticket.mutate()}>
                Take my ticket
              </button>
            )}{" "}
            <button
              type="button"
              className="btn btn-primary"
              disabled={!canVote || vote.isPending}
              onClick={() => vote.mutate()}
            >
              {vote.isPending ? "Your wallet is open…" : "Vote, or see my vote, in my wallet"}
            </button>
          </p>
          {canCheck && (
            <>
              <p className="muted">
                Voting has closed. Your wallet can check that your vote is in the ballot box&rsquo;s board as the
                community kept it at the close — it shows the answer in its own window, and this site isn&rsquo;t told.
              </p>
              <p>
                <button type="button" className="btn btn-ghost" disabled={check.isPending} onClick={() => check.mutate()}>
                  {check.isPending ? "Your wallet is checking…" : "Check my vote in my wallet"}
                </button>
              </p>
            </>
          )}
          {!canVote && !canCheck && <p className="muted">Voting opens {when(e.votingOpensAt)}.</p>}
        </section>

        <section className="card" aria-labelledby="how-heading">
          <div className="card-head">
            <Vote size={18} aria-hidden="true" />
            <h2 id="how-heading">How it is run</h2>
          </div>
          <dl className="facts">
            <div>
              <dt>Voting</dt>
              <dd>
                {when(e.votingOpensAt)} – {when(e.votingClosesAt)}
              </dd>
            </div>
            <div>
              <dt>Ballot box</dt>
              <dd>
                Run by {e.disclosure.ballotBoxOperator}; its board is {e.disclosure.boardVisibility}.
              </dd>
            </div>
            <div>
              <dt>Secrecy</dt>
              <dd>
                {e.secrecy === "open"
                  ? "Ballots are on the board as cast, under keys that do not name you."
                  : "Ballots are encrypted until the election's trustees open them together."}
              </dd>
            </div>
            <div>
              <dt>Changing your vote</dt>
              <dd>{e.disclosure.revote === "replace" ? "A later vote replaces an earlier one." : "You can vote only once."}</dd>
            </div>
            {e.ticketsIssued !== undefined && (
              <div>
                <dt>Tickets taken</dt>
                <dd>{e.ticketsIssued}</dd>
              </div>
            )}
          </dl>
          {releaseWarning && (
            <p className="alert" role="note">
              <CircleAlert size={14} aria-hidden="true" /> Written answers are released once{" "}
              {e.textReleaseThreshold} {e.textReleaseThreshold === 1 ? "ballot is" : "ballots are"} counted. Below 10,
              a written answer may identify who wrote it.
            </p>
          )}
          {e.disclosure.rollCredential && (
            <p className="alert" role="note">
              <CircleAlert size={14} aria-hidden="true" /> Only holders of a membership credential issued by{" "}
              {e.disclosure.rollCredential.memberOfName ?? <code>{e.disclosure.rollCredential.memberOf}</code>} take a
              ticket. Taking one shows this community that you are a member of{" "}
              {e.disclosure.rollCredential.memberOfKind === "thisCommunity" ? "it" : "that party"}.
            </p>
          )}
          {e.disclosure.sameOperator && (
            <p className="alert" role="note">
              <CircleAlert size={14} aria-hidden="true" /> The same operator runs this community and its ballot box:
              together they could link your ticket to your ballot.
            </p>
          )}
          <p className="muted">
            You can prove how you voted, so this election cannot protect you against being made to vote a certain way.
          </p>
        </section>

        <section className="card" aria-labelledby="questions-heading">
          <div className="card-head">
            <Vote size={18} aria-hidden="true" />
            <h2 id="questions-heading">What it asks</h2>
          </div>
          <ol>
            {e.questions.map((q) => (
              <li key={q.key}>
                <strong>{q.text ?? q.key}</strong>
                {q.optional ? <span className="muted"> (optional)</span> : null}
                {q.options.length > 0 && (
                  <span className="muted"> — {q.options.map((o) => o.label ?? o.key).join(", ")}</span>
                )}
              </li>
            ))}
          </ol>
          <p className="muted">You answer these in your wallet, not here.</p>
        </section>
      </div>
    </>
  );
}
