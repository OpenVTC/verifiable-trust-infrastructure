// Community events, as a member sees, registers for and withdraws from them (`vtc/events/*`,
// docs/03-vtc/events.md).
//
// Signed by this browser's portal key for the member, which the member delegated
// `vtc/events` to at sign-in, as the directory, groups, boards and badges pages are. Only the
// member's own acts go this way — registering, changing and withdrawing a registration,
// reporting an event — and the reads any member makes. Creating, changing and publishing an
// event, and deciding registrations, take a host's own key in the console (VTI-EVT-095).
//
// Where an event happens is released to registrants who are going (VTI-EVT-060): it is read
// with `access/show`, never taken from the event itself unless the host made it public.

import type {
  EventAccessShowResponse,
  EventCalendarsListResponse,
  EventListResponse,
  EventMineListResponse,
  EventRegistrationsListResponse,
  EventRegistrationsRegisterPayload,
  EventRegistrationsRegisterResponse,
  EventRegistrationsWithdrawResponse,
  EventReportPayload,
  EventReportResponse,
  EventShowResponse,
} from "@/lib/wire-types";

import { send } from "./directory-api";

export const EVENTS_CALENDARS_TASK = "https://trusttasks.org/spec/vtc/events/calendars/list/0.1";
export const EVENTS_LIST_TASK = "https://trusttasks.org/spec/vtc/events/list/0.1";
export const EVENTS_SHOW_TASK = "https://trusttasks.org/spec/vtc/events/show/0.1";
export const EVENTS_MINE_TASK = "https://trusttasks.org/spec/vtc/events/mine/list/0.1";
export const EVENTS_ACCESS_TASK = "https://trusttasks.org/spec/vtc/events/access/show/0.1";
export const EVENTS_REGISTER_TASK = "https://trusttasks.org/spec/vtc/events/registrations/register/0.1";
export const EVENTS_WITHDRAW_TASK = "https://trusttasks.org/spec/vtc/events/registrations/withdraw/0.1";
export const EVENTS_ROSTER_TASK = "https://trusttasks.org/spec/vtc/events/registrations/list/0.1";
export const EVENTS_REPORT_TASK = "https://trusttasks.org/spec/vtc/events/report/0.1";

export type Calendar = EventCalendarsListResponse["items"][number];
export type CommunityEvent = EventShowResponse["event"];
export type ListedEvent = EventListResponse["items"][number];
export type MyRegistration = NonNullable<EventShowResponse["myRegistration"]>;
export type RegistrationStatus = MyRegistration["status"];
export type MineItem = EventMineListResponse["items"][number];
export type AccessDetails = EventAccessShowResponse["access"];
export type RosterItem = NonNullable<EventRegistrationsListResponse["roster"]>[number];
export type ReportReason = EventReportPayload["reason"];
export type RegisterChoice = EventRegistrationsRegisterPayload["status"];

export const eventsHref = "#/events";
export const eventHref = (eventId: string) => `#/events/${encodeURIComponent(eventId)}`;

/** The calendars the member may see: the community's own first. */
export const listCalendars = () =>
  send<EventCalendarsListResponse>(EVENTS_CALENDARS_TASK, { limit: 200 }).then((r) => r.items);

/** One page of the events the member may see, earliest first. `mine`: only those they are
 *  going to, said maybe to, wait on, or are waitlisted for. */
export const listEvents = (filters: { from?: string; to?: string; calendarId?: string; mine?: boolean } = {}) =>
  send<EventListResponse>(EVENTS_LIST_TASK, { ...filters, limit: 200 }).then((r) => r.items);

export const showEvent = (eventId: string) => send<EventShowResponse>(EVENTS_SHOW_TASK, { eventId });

/** The member's own registrations, each with the event as the community last described it. */
export const listMine = () => send<EventMineListResponse>(EVENTS_MINE_TASK, { limit: 100 }).then((r) => r.items);

/** Where it happens, released to a registrant who is going (VTI-EVT-060). */
export const showAccess = (eventId: string) =>
  send<EventAccessShowResponse>(EVENTS_ACCESS_TASK, { eventId }).then((r) => r.access);

/** Register, or change a registration; the answer is the member's receipt (VTI-EVT-092). */
export const register = (p: EventRegistrationsRegisterPayload) =>
  send<EventRegistrationsRegisterResponse>(EVENTS_REGISTER_TASK, p);

/** Withdraw: always allowed (VTI-EVT-037). */
export const withdraw = (eventId: string) =>
  send<EventRegistrationsWithdrawResponse>(EVENTS_WITHDRAW_TASK, { eventId });

/** Who else is going or maybe, on a `visible` roster only (VTI-EVT-053). */
export const listRoster = (eventId: string) =>
  send<EventRegistrationsListResponse>(EVENTS_ROSTER_TASK, { eventId, limit: 100 }).then((r) => r.roster ?? []);

export const reportEvent = (p: EventReportPayload) => send<EventReportResponse>(EVENTS_REPORT_TASK, p);

export const STATUS_WORDS: Record<RegistrationStatus, string> = {
  going: "You're going",
  maybe: "You said maybe",
  pending: "Waiting for the hosts",
  waitlisted: "On the waitlist",
  withdrawn: "You withdrew",
  declined: "The hosts declined",
  removed: "The hosts removed you",
};

export const REPORT_REASONS: { id: ReportReason; label: string }[] = [
  { id: "inappropriate", label: "Inappropriate" },
  { id: "spam", label: "Spam or advertising" },
  { id: "unsafe", label: "Unsafe" },
  { id: "misleading", label: "Not what it says" },
  { id: "other", label: "Something else" },
];
