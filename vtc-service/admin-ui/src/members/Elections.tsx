// The community's elections in the member portal:
//
//   #/elections        The elections the community lets you vote in.
//   #/elections/<id>   One election: what it asks, how it is run, and the
//                      buttons that hand off to your wallet.
//
// Everything here is read through the member's wallet (`wallet-elections.ts`).
// Taking a ticket and voting happen in the wallet's own window: this page never
// sees a choice, and after a vote it is not told whether one was cast.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleAlert, TicketCheck, Vote } from "lucide-react";

import { textReleaseWarning } from "@/lib/election-manifest";

import { InstallWallet } from "./InstallWallet";
import { Crumbs } from "./member-card";
import {
  STAGE_LABEL,
  actionableFirst,
  declinedInWallet,
  stageOf,
  walletElections,
  type PageElection,
  type PageElectionView,
  type WalletElections,
} from "./wallet-elections";

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

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
  if (list.isPending) return <p className="muted">Asking your wallet…</p>;
  if (list.isError) return <WalletError error={list.error} />;
  const elections = actionableFirst(list.data.elections);
  if (elections.length === 0) {
    return <p className="muted">There are no elections you can vote in right now.</p>;
  }
  return (
    <ul className="election-list" aria-label="Elections">
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
  const who = member ? { member } : {};
  const shown = useQuery({
    queryKey: ["member-election", hostDid, member, electionId],
    queryFn: () => wallet.show({ hostDid, electionId, ...who }),
    retry: false,
  });
  // Whether the community issued the ticket comes from the member's own list.
  const listed = useQuery({
    queryKey: ["member-elections", hostDid, member],
    queryFn: () => wallet.list({ hostDid, ...who }),
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

  if (shown.isPending) return <p className="muted">Asking your wallet…</p>;
  if (shown.isError) return <WalletError error={shown.error} />;
  const e: PageElectionView = shown.data;
  const held = listed.data?.elections.find((x) => x.electionId === electionId)?.ticketHeld ?? false;
  const stage = stageOf(e);
  const canTicket = !held && (stage === "ticketsOpen" || stage === "voting");
  const canVote = stage === "voting";
  // VTI-VOT-090: below 10, the member is told before taking a ticket.
  const releaseWarning = textReleaseWarning(e.textReleaseThreshold) !== null;
  const failure = [ticket.error, vote.error].find((x) => x && !declinedInWallet(x));

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
          {failure ? (
            <div className="alert" role="alert">
              <p>{failure instanceof Error ? failure.message : String(failure)}</p>
            </div>
          ) : null}
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
          {!canVote && <p className="muted">Voting opens {when(e.votingOpensAt)}.</p>}
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
