// Community events, run from the console (`vtc/events/*`, docs/03-vtc/events.md).
//
// Calendars (the community's own and each group's), the events in them, their registrations
// and their hosts. Who runs what is `vtc.events.manage`: unqualified for the community's
// calendars and every event, at `group:<id>` for a group's calendar (a group's managers run it
// too), at `event:<id>` for a host by appointment (VTI-EVT-013, VTI-EVT-070).
//
// Every act is signed by this browser's console key, never a member portal key
// (VTI-EVT-095). The roster setting is fixed once an event is published: the editor says so
// before publishing and stops offering the choice after (VTI-EVT-051).

import { postSignedRead, postSignedTrustTask } from "./api";
import type {
  EventCalendarsCreatePayload,
  EventCalendarsCreateResponse,
  EventCalendarsListResponse,
  EventCalendarsUpdatePayload,
  EventCalendarsUpdateResponse,
  EventCancelResponse,
  EventCreatePayload,
  EventCreateResponse,
  EventDeleteResponse,
  EventHostsAppointResponse,
  EventHostsListResponse,
  EventHostsRemoveResponse,
  EventListPayload,
  EventListResponse,
  EventPublishResponse,
  EventRegistrationsDecideResponse,
  EventRegistrationsListResponse,
  EventRegistrationsRemoveResponse,
  EventShowResponse,
  EventUpdatePayload,
  EventUpdateResponse,
} from "./wire-types";

export const CALENDARS_CREATE = "https://trusttasks.org/spec/vtc/events/calendars/create/0.1";
export const CALENDARS_UPDATE = "https://trusttasks.org/spec/vtc/events/calendars/update/0.1";
export const CALENDARS_LIST = "https://trusttasks.org/spec/vtc/events/calendars/list/0.1";
export const CREATE = "https://trusttasks.org/spec/vtc/events/create/0.1";
export const UPDATE = "https://trusttasks.org/spec/vtc/events/update/0.1";
export const PUBLISH = "https://trusttasks.org/spec/vtc/events/publish/0.1";
export const CANCEL = "https://trusttasks.org/spec/vtc/events/cancel/0.1";
export const DELETE = "https://trusttasks.org/spec/vtc/events/delete/0.1";
export const SHOW = "https://trusttasks.org/spec/vtc/events/show/0.1";
export const LIST = "https://trusttasks.org/spec/vtc/events/list/0.1";
export const REGISTRATIONS_LIST = "https://trusttasks.org/spec/vtc/events/registrations/list/0.1";
export const REGISTRATIONS_DECIDE = "https://trusttasks.org/spec/vtc/events/registrations/decide/0.1";
export const REGISTRATIONS_REMOVE = "https://trusttasks.org/spec/vtc/events/registrations/remove/0.1";
export const HOSTS_APPOINT = "https://trusttasks.org/spec/vtc/events/hosts/appoint/0.1";
export const HOSTS_REMOVE = "https://trusttasks.org/spec/vtc/events/hosts/remove/0.1";
export const HOSTS_LIST = "https://trusttasks.org/spec/vtc/events/hosts/list/0.1";

/** Runs the community's calendars and every event (qualified: a group's calendar, or one event). */
export const EVENTS_MANAGE = "vtc.events.manage";
export const EVENTS_KEY = ["events"] as const;

export type Calendar = EventCalendarsListResponse["items"][number];
export type CommunityEvent = EventShowResponse["event"];
export type EventListItem = EventListResponse["items"][number];
export type Registration = NonNullable<EventRegistrationsListResponse["registrations"]>[number];
export type RegistrationStatus = Registration["status"];
export type EventDraft = EventCreatePayload;
export type EventChange = EventUpdatePayload;
export type Audience = NonNullable<EventCreatePayload["audience"]>;
export type RegistrationSettings = NonNullable<EventCreatePayload["registration"]>;
export type AccessDetails = NonNullable<EventCreatePayload["access"]>;
export type Accessibility = NonNullable<EventCreatePayload["accessibility"]>;

/** The listings' largest pages (`list-limits.json`). */
const PAGE = 200;
const REG_PAGE = 100;
/** How many pages a full read follows before it stops. */
const MAX_PAGES = 20;

export const STATUS_LABEL: Record<RegistrationStatus, string> = {
  going: "Going",
  maybe: "Maybe",
  pending: "Pending",
  waitlisted: "Waitlisted",
  withdrawn: "Withdrawn",
  declined: "Declined",
  removed: "Removed",
};

// ── Calendars ────────────────────────────────────────────────────────────

export async function listCalendars(includeArchived = true): Promise<Calendar[]> {
  const out: Calendar[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<EventCalendarsListResponse>(CALENDARS_LIST, {
      includeArchived,
      limit: PAGE,
      ...(cursor ? { cursor } : {}),
    });
    out.push(...page.items);
    cursor = page.nextCursor;
    if (!cursor) break;
  }
  return out;
}

export const createCalendar = (p: EventCalendarsCreatePayload) =>
  postSignedTrustTask<EventCalendarsCreateResponse>(CALENDARS_CREATE, p).then((r) => r.calendar);

export const updateCalendar = (p: EventCalendarsUpdatePayload) =>
  postSignedTrustTask<EventCalendarsUpdateResponse>(CALENDARS_UPDATE, p).then((r) => r.calendar);

// ── Events ───────────────────────────────────────────────────────────────

/** Every event this administrator or host may see in the filters, drafts and cancelled ones too. */
export async function listEvents(filters: Omit<EventListPayload, "cursor" | "limit"> = {}): Promise<EventListItem[]> {
  const out: EventListItem[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<EventListResponse>(LIST, {
      includeDrafts: true,
      includeCancelled: true,
      ...filters,
      limit: PAGE,
      ...(cursor ? { cursor } : {}),
    });
    out.push(...page.items);
    cursor = page.nextCursor;
    if (!cursor) break;
  }
  return out;
}

export const showEvent = (eventId: string) => postSignedRead<EventShowResponse>(SHOW, { eventId });

export const createEvent = (p: EventDraft) =>
  postSignedTrustTask<EventCreateResponse>(CREATE, p).then((r) => r.event);

export const updateEvent = (p: EventChange) =>
  postSignedTrustTask<EventUpdateResponse>(UPDATE, p).then((r) => r.event);

export const publishEvent = (eventId: string) =>
  postSignedTrustTask<EventPublishResponse>(PUBLISH, { eventId }).then((r) => r.event);

export const cancelEvent = (eventId: string, reason?: string) =>
  postSignedTrustTask<EventCancelResponse>(CANCEL, { eventId, ...(reason ? { reason } : {}) }).then((r) => r.event);

export const deleteEvent = (eventId: string) => postSignedTrustTask<EventDeleteResponse>(DELETE, { eventId });

// ── Registrations ────────────────────────────────────────────────────────

/** An event's registrations, as its hosts see them: every one, all of it (VTI-EVT-073). */
export async function listRegistrations(eventId: string, statuses?: RegistrationStatus[]): Promise<Registration[]> {
  const out: Registration[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<EventRegistrationsListResponse>(REGISTRATIONS_LIST, {
      eventId,
      ...(statuses && statuses.length ? { statuses } : {}),
      limit: REG_PAGE,
      ...(cursor ? { cursor } : {}),
    });
    out.push(...(page.registrations ?? []));
    cursor = page.nextCursor;
    if (!cursor) break;
  }
  return out;
}

export const decideRegistration = (registrationId: string, decision: "approve" | "decline", note?: string) =>
  postSignedTrustTask<EventRegistrationsDecideResponse>(REGISTRATIONS_DECIDE, {
    registrationId,
    decision,
    ...(note ? { note } : {}),
  });

export const removeRegistration = (registrationId: string, note?: string) =>
  postSignedTrustTask<EventRegistrationsRemoveResponse>(REGISTRATIONS_REMOVE, {
    registrationId,
    ...(note ? { note } : {}),
  });

// ── Hosts ────────────────────────────────────────────────────────────────

export const listHosts = (eventId: string) =>
  postSignedRead<EventHostsListResponse>(HOSTS_LIST, { eventId }).then((r) => r.hosts);

export const appointHost = (eventId: string, entryId: string) =>
  postSignedTrustTask<EventHostsAppointResponse>(HOSTS_APPOINT, { eventId, entryId }).then((r) => r.hosts);

export const removeHost = (eventId: string, entryId: string) =>
  postSignedTrustTask<EventHostsRemoveResponse>(HOSTS_REMOVE, { eventId, entryId }).then((r) => r.hosts);

// ── Time ─────────────────────────────────────────────────────────────────

/** A JSCalendar duration from minutes: `PT1H30M`, `P1D`. */
export function durationOf(minutes: number): string {
  const m = Math.max(1, Math.round(minutes));
  if (m % 1440 === 0) return `P${m / 1440}D`;
  const h = Math.floor(m / 60);
  const r = m % 60;
  return `PT${h ? `${h}H` : ""}${r ? `${r}M` : ""}`;
}

/** The IANA zones this browser knows, the viewer's own first. */
export function timeZones(): string[] {
  const own = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const all =
    typeof Intl.supportedValuesOf === "function" ? (Intl.supportedValuesOf("timeZone") as string[]) : [own, "Etc/UTC"];
  return [own, ...all.filter((z) => z !== own)];
}
