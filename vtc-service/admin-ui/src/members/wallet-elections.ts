// The member's elections, through their wallet extension.
//
// The portal is this community's own code and knows who is signed in, and the
// community is never trusted to learn how anyone voted or to link a ticket to a
// cast (`docs/05-design-notes/community-voting-threat-model.md`). So this page
// never holds a ballot: every election act goes through the member's wallet
// (`window.vtaWallet.elections`), which reads and takes tickets as the member
// through their VTA, fills the ballot in in its own window, and sends the cast
// to the ballot box itself — never through this community. From `vote` the
// page learns only that the wallet's window closed, and whether a ticket had
// to be taken first; never whether a vote was cast. The wallet accepts a call
// only from the portal this community's DID document names (`SignInPortal`).
//
// These types restate the extension's page-facing views
// (`packages/extension/src/bridge-protocol.ts` in OpenVTC/vta-browser-plugin):
// the portal imports nothing from the extension, and a member without it sees
// how to get it instead.

import { isThemePreview } from "@/lib/theme-preview";

/** One election as the community lists it to the member. */
export interface PageElection {
  electionId: string;
  title?: string;
  /** `registered`, `registration`, `voting`, `closed`, `tallied`, `cancelled`,
   *  `pendingRegistration`, `registrationRefused`. */
  state: string;
  votingOpensAt: string;
  votingClosesAt: string;
  binding: boolean;
  /** Whether the community has issued the member's ticket. */
  ticketHeld: boolean;
}

export interface PageElectionQuestion {
  key: string;
  type: "choice" | "ranking" | "score" | "text" | string;
  text?: string;
  options: { key: string; label?: string }[];
  optional: boolean;
}

/** One election as the community shows it: what it asks and how it is run. */
export interface PageElectionView {
  electionId: string;
  title?: string;
  description?: string;
  state: string;
  secrecy: string;
  registrationOpensAt: string;
  votingOpensAt: string;
  votingClosesAt: string;
  binding: boolean;
  questions: PageElectionQuestion[];
  /** The manifest's `textReleaseThreshold`: counted ballots before any written answer is
   *  disclosed (VTI-VOT-065). Below 10 the member is told, before taking a ticket, that a
   *  written answer may identify its author (VTI-VOT-090). Absent from a wallet that does not
   *  pass it on yet. */
  textReleaseThreshold?: number;
  disclosure: {
    ballotBox: string;
    ballotBoxOperator: string;
    sameOperator: boolean;
    boardVisibility: string;
    revote: string;
    auditors: string[];
  };
  ticketsIssued?: number;
  certified?: { certifiedAt: string; result: unknown };
}

export interface WalletElections {
  list(p: { hostDid: string; member?: string }): Promise<{ elections: PageElection[] }>;
  show(p: { hostDid: string; electionId: string; member?: string }): Promise<PageElectionView>;
  /** The member decides in the wallet's own window. */
  takeTicket(p: { hostDid: string; electionId: string; member?: string }): Promise<{ ticketHeld: true; taken: boolean }>;
  /** Opens the wallet's ballot (or, with no ticket held, takes one and stops).
   *  Resolves when the wallet's window closes, whatever the member did. */
  vote(p: { hostDid: string; electionId: string; member?: string }): Promise<{ ticketTaken: boolean }>;
}

/** The wallet's election methods, or `null` when no wallet (or an older one) is on this page. */
export function walletElections(): WalletElections | null {
  // A theme preview never reaches the member's agent.
  if (isThemePreview()) return null;
  const w = (window as { vtaWallet?: { elections?: Partial<WalletElections> } }).vtaWallet;
  const e = w?.elections;
  return e && typeof e.list === "function" && typeof e.vote === "function" ? (e as WalletElections) : null;
}

/** Where an election stands for the member, in their words, and what they can do now. */
export type Stage = "upcoming" | "ticketsOpen" | "voting" | "closed" | "cancelled" | "unavailable";

export function stageOf(e: Pick<PageElection, "state" | "votingOpensAt" | "votingClosesAt">, now = Date.now()): Stage {
  switch (e.state) {
    case "cancelled":
    case "registrationRefused":
      return "cancelled";
    case "closed":
    case "tallied":
      return "closed";
    case "pendingRegistration":
      return "upcoming";
  }
  const opens = Date.parse(e.votingOpensAt);
  const closes = Date.parse(e.votingClosesAt);
  if (now >= closes) return "closed";
  if (now >= opens) return "voting";
  return e.state === "registration" || e.state === "registered" ? "ticketsOpen" : "upcoming";
}

export const STAGE_LABEL: Record<Stage, string> = {
  upcoming: "Not open yet",
  ticketsOpen: "Tickets open",
  voting: "Voting open",
  closed: "Closed",
  cancelled: "Cancelled",
  unavailable: "Unavailable",
};

/** The elections a member can still act on first, the rest after. */
export function actionableFirst(list: readonly PageElection[], now = Date.now()): PageElection[] {
  const rank = (e: PageElection) => {
    const s = stageOf(e, now);
    return s === "voting" ? 0 : s === "ticketsOpen" ? 1 : s === "upcoming" ? 2 : 3;
  };
  return [...list].sort((a, b) => rank(a) - rank(b) || Date.parse(a.votingClosesAt) - Date.parse(b.votingClosesAt));
}

/** A wallet answer the member chose, in the wallet's own window — not an error to show. */
export function declinedInWallet(e: unknown): boolean {
  const text = e instanceof Error ? e.message : String(e);
  return /did not take a ticket|declined|did not allow/.test(text);
}
