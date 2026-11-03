// Notifications the community holds as their addressee — `vtc/notifications/*`
// (VTI-NTF-070 – VTI-NTF-074).
//
// Another party (a community holding an election, say) tells this community
// that a thing exists its members may take part in. The community holds the
// notification and tells nobody anything because of it; it passes it on to
// its members only when an administrator decides a relay here, having been
// shown what a relay discloses about the community (VTI-NTF-046).
//
// A relay decision answers with how many members it added, never who they
// are, and nothing here ever shows the members reached.
//
// A relay to every member takes the requester's passkey (or approver) gesture
// bound to the document, as other stepped-up writes do; one to a group or a
// role does not, and `postSignedWithStepUp` sends it straight through.

import { postSignedRead } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";

export const NOTIFICATIONS_LIST_TASK = "https://trusttasks.org/spec/vtc/notifications/list/0.1";
export const NOTIFICATIONS_SHOW_TASK = "https://trusttasks.org/spec/vtc/notifications/show/0.1";
export const NOTIFICATIONS_RELAY_TASK = "https://trusttasks.org/spec/vtc/notifications/relay/0.1";

/** Lists and reads the notifications the community holds. */
export const NOTIFICATIONS_READ = "vtc.notifications.read";
/** Decides a relay to members; qualified by `group:<groupId>`, to that group only. */
export const NOTIFICATIONS_RELAY = "vtc.notifications.relay";

/** The query key every notification read sits under. */
export const NOTIFICATIONS_KEY = ["notifications"] as const;

/** `vtc/notifications/_shared/0.1` Recipients: exactly one selection. */
export type Recipients =
  | { scope: "allMembers" }
  | { scope: "group"; groupId: string }
  | { scope: "role"; role: string };

export type RecipientScope = Recipients["scope"];

/** `notifications/_shared/0.1` Notification. */
export interface Notification {
  notificationId: string;
  revision: number;
  kind: string;
  subject: { heldBy: string; id: string; openWith: string };
  audience: string;
  status: "available" | "withdrawn";
  relayable: boolean;
  validFrom?: string;
  validUntil?: string;
}

/** `vtc/notifications/_shared/0.1` RelayDecision: the selection and a count, never who. */
export interface RelayDecision {
  decidedAt: string;
  decidedBy: string;
  recipients: Recipients;
  recipientCount: number;
}

/** `vtc/notifications/_shared/0.1` ReceivedNotification. */
export interface ReceivedNotification {
  recordId: string;
  originator: string;
  relayedBy: string[];
  notification: Notification;
  receivedAt: string;
  mayRelay: boolean;
  relayDisclosure?: string;
  relayDecisions: RelayDecision[];
}

export interface NotificationsPage {
  items: ReceivedNotification[];
  nextCursor?: string;
}

/** `vtc/notifications/show/0.1`'s answer: the delivering document exactly as received. */
export interface NotificationShown {
  item: ReceivedNotification;
  document: Record<string, unknown>;
}

export interface RelayResult {
  recordId: string;
  revision: number;
  recipientCount: number;
}

export interface NotificationsFilter {
  kind?: string;
  heldBy?: string;
  includeLapsed?: boolean;
}

/** The page size asked, within the specification's maximum (200). */
const PAGE = 50;

/** One page of the notifications held, most recently received first. */
export function listNotifications(
  filter: NotificationsFilter,
  cursor?: string,
): Promise<NotificationsPage> {
  const payload: Record<string, unknown> = {};
  if (filter.kind) payload.kind = filter.kind;
  if (filter.heldBy) payload.heldBy = filter.heldBy;
  if (filter.includeLapsed) payload.includeLapsed = true;
  return postSignedRead<NotificationsPage>(NOTIFICATIONS_LIST_TASK, { ...payload, limit: PAGE, ...(cursor ? { cursor } : {}) });
}

export function showNotification(recordId: string): Promise<NotificationShown> {
  return postSignedRead<NotificationShown>(NOTIFICATIONS_SHOW_TASK, { recordId });
}

/**
 * `vtc/notifications/relay/0.1`. `disclosureAcknowledged` is sent only as the
 * administrator's own tick (VTI-NTF-046): the caller passes what they ticked,
 * and nothing here sets it on their behalf.
 */
export function relayNotification(
  recordId: string,
  recipients: Recipients,
  disclosureAcknowledged: boolean,
  confirmGesture: ConfirmGesture,
): Promise<RelayResult> {
  return postSignedWithStepUp<RelayResult>(
    NOTIFICATIONS_RELAY_TASK,
    disclosureAcknowledged ? { recordId, recipients, disclosureAcknowledged: true } : { recordId, recipients },
    confirmGesture,
  );
}

/** What a relay decision reached, said without naming anyone. */
export function relayedMessage(count: number): string {
  if (count === 0) return "Already relayed to everyone that selection reaches.";
  return `Relayed to ${count} ${count === 1 ? "member" : "members"}.`;
}

/** The declared refusals, in plain language. */
export function notificationRefusalHint(code: string | undefined): string | null {
  switch (code) {
    case "vtc/notifications/relay:notificationUnknown":
    case "vtc/notifications/show:notificationUnknown":
      return "The community no longer holds this notification — it was never held, or was discarded after it lapsed.";
    case "vtc/notifications/relay:notRelayable":
      return "This notification may not be relayed: its originator said so, its kind may not be passed on, or it has already passed through as many relays as allowed.";
    case "vtc/notifications/relay:lapsed":
      return "This notification is withdrawn or past its end: there is nothing left to tell members about.";
    case "vtc/notifications/relay:disclosureNotAcknowledged":
      return "A relay of this notification discloses something about the community. Read the statement below and tick the acknowledgement before relaying.";
    case "vtc/notifications/relay:groupUnknown":
      return "That group does not exist, or you may not see it. Choose another group.";
    default:
      return null;
  }
}

/** Where the viewer may relay to, read from their capabilities. */
export interface RelayStanding {
  /** Holds the capability community-wide: every selection. */
  anywhere: boolean;
  /** The groups a group-qualified holding names. */
  groups: string[];
}

export function relayStanding(caps: readonly string[]): RelayStanding {
  const prefix = `${NOTIFICATIONS_RELAY}@group:`;
  return {
    anywhere: caps.includes(NOTIFICATIONS_RELAY),
    groups: caps.filter((c) => c.startsWith(prefix)).map((c) => c.slice(prefix.length)),
  };
}
