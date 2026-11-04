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

/** One election of a `takeTickets` call: what came of it. The community knows all of it already. */
export interface PageBatchTicket {
  electionId: string;
  outcome: "taken" | "held" | "unavailable" | "notEligible" | "failed";
  error?: string;
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
    /** Under a credential roll, whose membership credential admits a party (voting/_shared/0.4
     *  `RollCredentialDisclosure`, VTI-VOT-090). Absent under any other rule, and from a
     *  wallet that does not pass it on yet. */
    rollCredential?: {
      memberOf: string;
      memberOfKind: "thisCommunity" | "communityGroup" | "memberParty" | string;
      memberOfName?: string;
    };
  };
  ticketsIssued?: number;
  certified?: { certifiedAt: string; result: unknown };
}

/** An election the member's agent holds a notification of from this community (VTI-NTF-063),
 *  as the page may show it until the member opens it: the community's identifier for it, the
 *  party it is put to, the period the notification states and whether it was withdrawn —
 *  nothing of the election itself. One the community does not list (put to a party that is
 *  itself a member of the community, VTI-VOT-015) is opened by its id with `memberOf` set to
 *  `audience`, and the wallet reads it as that party's member — asking first. */
export interface PageNotifiedElection {
  electionId: string;
  /** The DID the election is put to: under a credential roll, the party whose members may take
   *  part (`roll.memberOf`). */
  audience: string;
  status: "available" | "withdrawn";
  votingOpensAt?: string;
  votingClosesAt?: string;
}

/** What `list` comes to on this page, whichever wallet answered. */
export interface ElectionList {
  elections: PageElection[];
  /** Empty from a wallet that does not pass notifications on. */
  notified: PageNotifiedElection[];
}

/** Which identity reads, and — for an election the member was told about — whose member. */
export interface ReadAs {
  member?: string;
  /** The party to read the election as a member of. The wallet presents the member's credential
   *  issued by exactly this DID, and only after the member agreed in its own window
   *  (VTI-VOT-016); the page never presents anything. A wallet before credential rolls refuses
   *  the field, so it is passed only for a notification, which only a newer wallet reports. */
  memberOf?: string;
}

/** The wallet's methods as this page calls them. `list` is normalised (`electionListOf`). */
export interface WalletElections {
  list(p: { hostDid: string; member?: string }): Promise<ElectionList>;
  show(p: { hostDid: string; electionId: string } & ReadAs): Promise<PageElectionView>;
  /** The member decides in the wallet's own window. */
  takeTicket(p: { hostDid: string; electionId: string } & ReadAs): Promise<{ ticketHeld: true; taken: boolean }>;
  /** Several tickets in one decision (a board's ideas). Each is still its own request, a pause
   *  apart, so this resolves some seconds after the member agrees. Absent from an older wallet:
   *  take them one at a time instead. */
  takeTickets?(p: { hostDid: string; electionIds: string[]; member?: string }): Promise<{ tickets: PageBatchTicket[] }>;
  /** Opens the wallet's ballot (or, with no ticket held, takes one and stops).
   *  Resolves when the wallet's window closes, whatever the member did. */
  vote(p: { hostDid: string; electionId: string } & ReadAs): Promise<{ ticketTaken: boolean }>;
}

type RawWallet = Omit<WalletElections, "list"> & { list(p: { hostDid: string; member?: string }): Promise<unknown> };

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** A notification as the page keeps it: only the fields VTI-NTF-063 lets it see. */
function notifiedOf(v: unknown): PageNotifiedElection | null {
  if (!isRecord(v) || typeof v.electionId !== "string" || typeof v.audience !== "string") return null;
  if (v.status !== "available" && v.status !== "withdrawn") return null;
  return {
    electionId: v.electionId,
    audience: v.audience,
    status: v.status,
    ...(typeof v.votingOpensAt === "string" ? { votingOpensAt: v.votingOpensAt } : {}),
    ...(typeof v.votingClosesAt === "string" ? { votingClosesAt: v.votingClosesAt } : {}),
  };
}

/** `list`'s answer, whichever wallet gave it: `{ elections, notified }` (with notifications),
 *  `{ elections }` (before them), or a bare list of elections. Wallets update independently of
 *  this portal, so none of these is an error. */
export function electionListOf(raw: unknown): ElectionList {
  const elections = Array.isArray(raw) ? raw : isRecord(raw) && Array.isArray(raw.elections) ? raw.elections : [];
  const notified = isRecord(raw) && Array.isArray(raw.notified) ? raw.notified : [];
  return {
    elections: elections as PageElection[],
    notified: notified.map(notifiedOf).filter((n): n is PageNotifiedElection => n !== null),
  };
}

/** The wallet's election methods, or `null` when no wallet (or an older one) is on this page. */
export function walletElections(): WalletElections | null {
  // A theme preview never reaches the member's agent.
  if (isThemePreview()) return null;
  const w = (window as { vtaWallet?: { elections?: Partial<RawWallet> } }).vtaWallet;
  const e = w?.elections;
  if (!e || typeof e.list !== "function" || typeof e.vote !== "function") return null;
  const raw = e as RawWallet;
  const takeTickets = raw.takeTickets;
  return {
    list: async (p) => electionListOf(await raw.list(p)),
    show: (p) => raw.show(p),
    takeTicket: (p) => raw.takeTicket(p),
    ...(typeof takeTickets === "function" ? { takeTickets: (p) => takeTickets.call(raw, p) } : {}),
    vote: (p) => raw.vote(p),
  };
}

/** The notifications naming an election the community's list does not show the member, one
 *  per election (one still standing before a withdrawn one). The rest are in the list. */
export function notifiedOnly(list: ElectionList): PageNotifiedElection[] {
  const listed = new Set(list.elections.map((e) => e.electionId));
  const one = new Map<string, PageNotifiedElection>();
  for (const n of list.notified) {
    if (listed.has(n.electionId)) continue;
    const had = one.get(n.electionId);
    if (!had || (had.status === "withdrawn" && n.status === "available")) one.set(n.electionId, n);
  }
  return [...one.values()];
}

/** The party to read an election as a member of: the audience of a notification the member's
 *  agent holds for it that was not withdrawn (VTI-NTF-024), else none. Never the page's own
 *  choice. */
export function memberOfFor(list: ElectionList | undefined, electionId: string): string | undefined {
  return list?.notified.find((n) => n.electionId === electionId && n.status === "available")?.audience;
}

/** Which of the community's answers a wallet refusal is. The wallet passes the page only its
 *  message, so this matches both its own wording and a bare code. */
export type RefusalKind = "electionUnknown" | "indeterminate" | "other";

export function refusalKind(e: unknown): RefusalKind {
  const text = e instanceof Error ? e.message : String(e);
  if (/\bindeterminate\b|could not check your membership/i.test(text)) return "indeterminate";
  if (/\belectionUnknown\b|shows you no such election|no such election is open to you/i.test(text)) return "electionUnknown";
  return "other";
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
  return /did not take a ticket|did not take your tickets|declined|did not allow|chose not to show your membership/.test(text);
}
