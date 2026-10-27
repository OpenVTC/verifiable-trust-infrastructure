// Community elections — the community as registrar of its polls, surveys and
// elections (`vtc/elections/*`, docs/03-vtc/elections.md).
//
// The community decides who may vote and issues each of them a ticket, blind;
// the ballot box the manifest names (a voting service, never this VTC) admits
// the casts and keeps the board. This page is the administrator's: create an
// election from its manifest, read where each stands, close, cancel, and
// certify a tallied result — which the VTC does by re-verifying the ballot
// box's whole board from its own voting key.
//
// A **binding** election (`manifest.binding`) takes another holder of
// `vtc.elections.manage`: after the requester's passkey gesture it is parked
// as an administrator action, and the signed door throws a `ParkedAction`
// (`lib/parked-action.ts`) — a success, that completes itself on approval.

import { postSignedRead } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";

export const ELECTIONS_CREATE_TASK = "https://trusttasks.org/spec/vtc/elections/create/0.1";
export const ELECTIONS_LIST_TASK = "https://trusttasks.org/spec/vtc/elections/list/0.1";
export const ELECTIONS_SHOW_TASK = "https://trusttasks.org/spec/vtc/elections/show/0.1";
export const ELECTIONS_CLOSE_TASK = "https://trusttasks.org/spec/vtc/elections/close/0.1";
export const ELECTIONS_CANCEL_TASK = "https://trusttasks.org/spec/vtc/elections/cancel/0.1";
export const ELECTIONS_CERTIFY_TASK = "https://trusttasks.org/spec/vtc/elections/certify/0.1";

/** The capability every task here takes. */
export const ELECTIONS_MANAGE = "vtc.elections.manage";

/** The query key every election read sits under. */
export const ELECTIONS_KEY = ["elections"] as const;

/** Where an election stands, as the community holds it (`RegistrarState`). */
export type ElectionState =
  | "registered"
  | "registration"
  | "voting"
  | "closed"
  | "tallied"
  | "cancelled"
  | "pendingRegistration"
  | "registrationRefused";

/** What a state means to an administrator. */
export const STATE_LABEL: Record<ElectionState, string> = {
  registered: "Registered — tickets not open yet",
  registration: "Taking tickets",
  voting: "Voting",
  closed: "Closed",
  tallied: "Tallied",
  cancelled: "Cancelled",
  pendingRegistration: "Waiting on the ballot box",
  registrationRefused: "Refused by the ballot box",
};

export interface ElectionListItem {
  electionId: string;
  title?: string;
  state: ElectionState;
  votingOpens: string;
  votingCloses: string;
  binding: boolean;
  ticketHeld: boolean;
}

export interface BoardHead {
  electionId: string;
  treeSize: number;
  rootHash: string;
  issuedAt: string;
}

export interface QuestionResult {
  question: string;
  abstained: number;
  choice?: Record<string, number>;
  ranking?: Record<string, number[]>;
  score?: Record<string, unknown>;
  text?: unknown[];
}

export interface ElectionResult {
  electionId: string;
  manifestDigest: string;
  ballotsCounted: number;
  questions: QuestionResult[];
  head: BoardHead;
}

export interface Disclosure {
  ballotBox: string;
  ballotBoxOperator: string;
  sameOperator: boolean;
  boardVisibility: "public" | "private";
  auditors: string[];
  revote: "replace" | "refuse";
  coercionResistance: false;
}

/** `vtc/elections/show/0.1`'s answer. The manifest is carried as received. */
export interface Election {
  manifest: Record<string, unknown> & {
    electionId: string;
    title?: string;
    votingOpens: string;
    votingCloses: string;
    registrationOpens: string;
    binding: boolean;
    allowEarlyClose: boolean;
    questions: { key: string; type: string; text?: string }[];
  };
  manifestDigest: string;
  state: ElectionState;
  parameters: { suite: string; votingKey: string };
  disclosure: Disclosure;
  checkpoints: { head: BoardHead; document: unknown }[];
  ticketsIssued?: number;
  certified?: { result: ElectionResult; certifiedAt: string; auditAttestations: unknown[] };
}

export interface Created {
  electionId: string;
  manifestDigest: string;
  state: "registered" | "pendingRegistration";
  actionId?: string;
}

const TASK_DISCOVERY = "https://trusttasks.org/spec/trust-task-discovery/0.3";

/** Whether this VTC serves elections at all. They are built only with its `voting` feature,
 *  and the console cannot tell that from anything but discovery, which lists exactly the
 *  tasks this build dispatches. */
export async function fetchElectionsServed(): Promise<boolean> {
  const res = await postSignedRead<{ supportedTypes?: unknown[] }>(TASK_DISCOVERY, {
    patterns: ["vtc/elections/*"],
  });
  return (res.supportedTypes ?? []).includes(ELECTIONS_LIST_TASK);
}

/** The page size asked, within the specification's maximum. */
const PAGE = 100;
/** Pages read before stopping. */
const MAX_PAGES = 20;

/** Every election this administrator may see (all of them, holding the capability). */
export async function fetchElections(): Promise<ElectionListItem[]> {
  const out: ElectionListItem[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<{ elections: ElectionListItem[]; next?: string }>(
      ELECTIONS_LIST_TASK,
      { limit: PAGE, ...(cursor ? { cursor } : {}) },
    );
    out.push(...page.elections);
    if (!page.next) break;
    cursor = page.next;
  }
  return out;
}

export function fetchElection(electionId: string): Promise<Election> {
  return postSignedRead<Election>(ELECTIONS_SHOW_TASK, { electionId });
}

/** `vtc/elections/create/0.1`. Throws a `ParkedAction` for a binding election. */
export function createElection(
  manifest: Record<string, unknown>,
  confirmGesture: ConfirmGesture,
): Promise<Created> {
  return postSignedWithStepUp<Created>(ELECTIONS_CREATE_TASK, { manifest }, confirmGesture);
}

export function closeElection(
  electionId: string,
  reason: string,
  confirmGesture: ConfirmGesture,
): Promise<{ electionId: string; state: string }> {
  const r = reason.trim();
  return postSignedWithStepUp(
    ELECTIONS_CLOSE_TASK,
    r ? { electionId, reason: r } : { electionId },
    confirmGesture,
  );
}

export function cancelElection(
  electionId: string,
  reason: string,
  confirmGesture: ConfirmGesture,
): Promise<{ electionId: string; state: string }> {
  return postSignedWithStepUp(
    ELECTIONS_CANCEL_TASK,
    { electionId, reason: reason.trim() },
    confirmGesture,
  );
}

/** `vtc/elections/certify/0.1`, with auditors' attestations kept exactly as given. */
export function certifyElection(
  electionId: string,
  auditAttestations: unknown[],
  confirmGesture: ConfirmGesture,
): Promise<{ electionId: string; result: ElectionResult; head: BoardHead; certifiedAt: string }> {
  return postSignedWithStepUp(
    ELECTIONS_CERTIFY_TASK,
    { electionId, auditAttestations },
    confirmGesture,
  );
}

/** A manifest to start from: one choice question, open voting for a week from
 *  tomorrow, this community's DID and the given ballot box. */
export function sampleManifest(community: string, ballotBox: string, now = new Date()): string {
  const day = 24 * 3600 * 1000;
  const iso = (t: number) => new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z");
  const start = now.getTime() + day;
  return JSON.stringify(
    {
      electionId: `poll-${now.toISOString().slice(0, 10)}`,
      community,
      title: "",
      questions: [
        {
          key: "q1",
          type: "choice",
          text: "",
          options: [{ key: "yes", label: "Yes" }, { key: "no", label: "No" }],
          minSelections: 1,
          maxSelections: 1,
          optional: true,
        },
      ],
      secrecy: "open",
      roll: { rule: "members" },
      registrationOpens: iso(now.getTime()),
      votingOpens: iso(start),
      votingCloses: iso(start + 7 * day),
      revote: "replace",
      board: { visibility: "public", auditors: [] },
      ballotBox,
      binding: false,
      allowEarlyClose: false,
      resultsBeforeClose: false,
      textReleaseThreshold: 10,
    },
    null,
    2,
  );
}

/** The declared refusals an administrator can act on, with what to do. */
export function refusalHint(code: string | undefined): string | null {
  switch (code) {
    case "vtc/elections/create:ballotBoxNotTrusted":
      return "The ballot box is not one of this community's trusted voting services. The host operator adds it under [voting] trusted_ballot_boxes in the VTC's configuration and restarts it.";
    case "vtc/elections/create:electionExists":
      return "This community already holds an election under that electionId. Choose another.";
    case "vtc/elections/create:unsupportedSecrecy":
      return "Only open elections are served: set secrecy to \"open\" and remove trustees.";
    case "vtc/elections/certify:notTallied":
      return "The ballot box has not published a final result yet.";
    default:
      return null;
  }
}
