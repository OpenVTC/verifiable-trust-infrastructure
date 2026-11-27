// Community events, run from the console (`vtc/events/*`, docs/03-vtc/events.md).
//
//   /events             Every event this administrator or host may see: drafts, published and
//                       cancelled, filtered by calendar and range.
//   /events/calendars   The community's calendars and each group's: make one, change it, archive it.
//   /events/new         A new event, saved as a draft.
//   /events/:id         One event: change it, publish, cancel or delete it; its registrations
//                       (approve, decline, remove); its hosts (appoint, remove).
//
// Every act is signed by this browser's console key (VTI-EVT-095). The roster setting is fixed
// once the event is published (VTI-EVT-051): the editor says so before, and stops offering the
// choice after. Members register from the member portal; this page never writes as a member.

import { useMemo, useState } from "react";
import { Link, Route, Routes, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarDays, CalendarPlus, Eye, EyeOff, Lock, Plus, Trash2, UserMinus, UserPlus } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { EntryName, byFace, faceLabel, faceMatches, useEntryFaces } from "@/components/EntryName";
import { Field } from "@/components/Field";
import { PageHeader } from "@/components/PageHeader";
import { listBadges } from "@/lib/badges";
import { formatWhen, zoneNote } from "@/lib/event-time";
import {
  EVENTS_KEY,
  EVENTS_MANAGE,
  STATUS_LABEL,
  appointHost,
  cancelEvent,
  createCalendar,
  createEvent,
  decideRegistration,
  deleteEvent,
  durationOf,
  listCalendars,
  listEvents,
  listHosts,
  listRegistrations,
  publishEvent,
  removeHost,
  removeRegistration,
  showEvent,
  timeZones,
  updateCalendar,
  updateEvent,
  type Audience,
  type Calendar,
  type CommunityEvent,
  type EventDraft,
  type Registration,
  type RegistrationStatus,
} from "@/lib/events";
import { durationMinutes } from "@/lib/event-time";
import { listGroups } from "@/lib/groups";
import { listRoles } from "@/lib/roles";
import { useToast } from "@/lib/toast";
import { holds, useCapabilities } from "@/lib/viewer";
import { type DynamicRule, RuleEditor, emptyRule, ruleReady, wireRule } from "@/plugins/GroupRule";

const CALENDARS_KEY = [...EVENTS_KEY, "calendars"] as const;

export function Events() {
  return (
    <section className="page">
      <Routes>
        <Route index element={<EventsList />} />
        <Route path="calendars" element={<CalendarsPage />} />
        <Route path="new" element={<EventEditorPage />} />
        <Route path=":id" element={<EventPage />} />
      </Routes>
    </section>
  );
}

function useCalendars() {
  return useQuery({ queryKey: CALENDARS_KEY, queryFn: () => listCalendars(true), retry: false });
}

function statusChip(ev: CommunityEvent) {
  if (ev.status === "draft") return <span className="chip">Draft</span>;
  if (ev.status === "cancelled") return <span className="chip chip-warn">Cancelled</span>;
  return <span className="chip chip-ok">Published</span>;
}

function goingWords(ev: CommunityEvent): string {
  const c = ev.goingCount;
  const n = typeof c?.exact === "number" ? `${c.exact}` : "—";
  const cap = ev.registration.capacity;
  return cap ? `${n} / ${cap}` : n;
}

// ─── the list ─────────────────────────────────────────────────────────────

function EventsList() {
  const navigate = useNavigate();
  const caps = useCapabilities();
  const calendars = useCalendars();
  const [calendarId, setCalendarId] = useState("");
  const [status, setStatus] = useState<"" | CommunityEvent["status"]>("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const range = from && to ? { from: `${from}T00:00:00Z`, to: `${to}T00:00:00Z` } : {};
  const list = useQuery({
    queryKey: [...EVENTS_KEY, "list", calendarId, from, to],
    queryFn: () => listEvents({ ...(calendarId ? { calendarId } : {}), ...range }),
    retry: false,
  });
  const items = (list.data ?? []).filter((i) => !status || i.event.status === status);
  // Making an event takes a calendar's authority (VTI-EVT-013): unqualified, or for a group —
  // never a host's appointment to one event.
  const runs =
    holds(caps, EVENTS_MANAGE) ||
    caps.some((c) => c.startsWith(`${EVENTS_MANAGE}:group:`) || c.startsWith("vtc.groups.manage"));
  const calName = (id: string) => calendars.data?.find((c) => c.calendarId === id)?.name ?? "—";
  return (
    <>
      <PageHeader
        count={list.data ? items.length : null}
        countLabel={list.data ? `${items.length} events` : undefined}
        lead="Events in the community's calendars and each group's. Members see the ones their audience admits and register from the member portal; the community never sends reminders, members' own agents do."
        actions={
          <>
            <Link className="secondary" to="calendars">
              <CalendarDays size={14} aria-hidden="true" /> Calendars
            </Link>
            {runs && (
              <Link className="primary" to="new">
                <Plus size={14} aria-hidden="true" /> New event
              </Link>
            )}
          </>
        }
      />
      <section className="card ev-filters">
        <Field label="Calendar">
          <select value={calendarId} onChange={(e) => setCalendarId(e.target.value)}>
            <option value="">Every calendar</option>
            {(calendars.data ?? []).map((c) => (
              <option key={c.calendarId} value={c.calendarId}>
                {c.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Status">
          <select value={status} onChange={(e) => setStatus(e.target.value as typeof status)}>
            <option value="">Any</option>
            <option value="draft">Drafts</option>
            <option value="published">Published</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </Field>
        <Field label="From">
          <input type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
        </Field>
        <Field label="To">
          <input type="date" value={to} onChange={(e) => setTo(e.target.value)} />
        </Field>
      </section>
      {list.error && (
        <section className="card error">
          <h3>Failed to read the events</h3>
          <p>{(list.error as Error).message}</p>
        </section>
      )}
      <section className="card table-card">
        <DataTable
          caption="Events"
          columns={[
            { key: "title", label: "Event" },
            { key: "when", label: "When" },
            { key: "calendar", label: "Calendar" },
            { key: "going", label: "Going" },
            { key: "status", label: "Status" },
          ]}
        >
          {list.isSuccess && items.length === 0 && (
            <tr>
              <td colSpan={5}>
                <EmptyState icon={CalendarDays} title="No events yet">
                  A meetup, a workshop, an AGM{runs ? ": make one with New event." : "."}
                </EmptyState>
              </td>
            </tr>
          )}
          {items.map(({ event: ev }) => (
            <tr key={ev.eventId} className="clickable" onClick={() => navigate(encodeURIComponent(ev.eventId))}>
              <td>
                <Link to={encodeURIComponent(ev.eventId)} onClick={(e) => e.stopPropagation()}>
                  <strong>{ev.title}</strong>
                </Link>
                {ev.kind === "meeting" && <span className="muted"> · meeting</span>}
              </td>
              <td>
                {formatWhen(ev.when)}
                {zoneNote(ev.when) && <div className="muted">{zoneNote(ev.when)}</div>}
              </td>
              <td>{calName(ev.calendarId)}</td>
              <td>{goingWords(ev)}</td>
              <td>{statusChip(ev)}</td>
            </tr>
          ))}
        </DataTable>
      </section>
    </>
  );
}

// ─── calendars ────────────────────────────────────────────────────────────

function CalendarsPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const caps = useCapabilities();
  const calendars = useCalendars();
  const groups = useQuery({ queryKey: ["groups", "list"], queryFn: listGroups, retry: false });
  const [name, setName] = useState("");
  const [color, setColor] = useState("#5b5bd6");
  const [groupId, setGroupId] = useState("");
  const [roster, setRoster] = useState<"visible" | "hidden">("hidden");
  const [reminders, setReminders] = useState("1440, 60");
  const refresh = () => void qc.invalidateQueries({ queryKey: EVENTS_KEY });
  const create = useMutation({
    mutationFn: () =>
      createCalendar({
        name: name.trim(),
        color,
        ...(groupId ? { groupId } : {}),
        defaultRoster: roster,
        defaultReminderMinutes: parseMinutes(reminders),
      }),
    onSuccess: () => {
      setName("");
      setGroupId("");
      refresh();
      toast.push("success", "Calendar made.");
    },
    onError: (err) => toast.pushFromError(err, "The calendar was not made"),
  });
  const archive = useMutation({
    mutationFn: (c: Calendar) =>
      updateCalendar({ calendarId: c.calendarId, state: c.state === "archived" ? "active" : "archived" }),
    onSuccess: refresh,
    onError: (err) => toast.pushFromError(err, "The calendar was not changed"),
  });
  const runsAll = holds(caps, EVENTS_MANAGE);
  const groupName = (id?: string) => (id ? groups.data?.find((g) => g.group.groupId === id)?.group.name ?? id : null);
  return (
    <>
      <PageHeader
        title="Calendars"
        trail={[{ label: "Events", to: ".." }, { label: "Calendars" }]}
        lead="Every event is in one calendar: the community's own, or a group's. A group's calendar is run by those who run its events, its managers included."
      />
      <section className="card table-card">
        <DataTable
          caption="Calendars"
          columns={[
            { key: "name", label: "Calendar" },
            { key: "group", label: "Group" },
            { key: "roster", label: "New events' roster" },
            { key: "state", label: "State" },
            { key: "act", label: "" },
          ]}
        >
          {(calendars.data ?? []).map((c) => (
            <tr key={c.calendarId}>
              <td>
                {c.color && <span className="ev-swatch" style={{ background: c.color }} aria-hidden="true" />}{" "}
                <strong>{c.name}</strong>
                {c.community && <span className="muted"> · the community's own</span>}
              </td>
              <td>{groupName(c.groupId) ?? <span className="muted">—</span>}</td>
              <td>{c.defaultRoster ?? "hidden"}</td>
              <td>{c.state === "archived" ? <span className="chip">Archived</span> : "Active"}</td>
              <td>
                {!c.community && (
                  <button type="button" className="secondary" onClick={() => archive.mutate(c)}>
                    {c.state === "archived" ? "Restore" : "Archive"}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </DataTable>
      </section>
      <section className="card" aria-labelledby="new-cal">
        <h3 id="new-cal">New calendar</h3>
        <form
          className="form-stack"
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim()) create.mutate();
          }}
        >
          <div className="form-grid">
            <Field label="Name">
              <input value={name} maxLength={200} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Colour">
              <input type="color" value={color} onChange={(e) => setColor(e.target.value)} />
            </Field>
            <Field label="Group" hint={runsAll ? "Leave empty for a community calendar." : "The group whose events you run."}>
              <select value={groupId} onChange={(e) => setGroupId(e.target.value)}>
                {runsAll && <option value="">None (a community calendar)</option>}
                {(groups.data ?? []).map((g) => (
                  <option key={g.group.groupId} value={g.group.groupId}>
                    {g.group.name}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="New events' roster">
              <select value={roster} onChange={(e) => setRoster(e.target.value as "visible" | "hidden")}>
                <option value="hidden">Hidden</option>
                <option value="visible">Visible</option>
              </select>
            </Field>
            <Field label="Suggested reminders" hint="Minutes before the start, comma separated.">
              <input value={reminders} onChange={(e) => setReminders(e.target.value)} />
            </Field>
          </div>
          <div className="form-actions">
            <button type="submit" className="primary" disabled={!name.trim() || create.isPending}>
              Make calendar
            </button>
          </div>
        </form>
      </section>
    </>
  );
}

function parseMinutes(s: string): number[] {
  return [
    ...new Set(
      s
        .split(",")
        .map((x) => Number(x.trim()))
        .filter((n) => Number.isInteger(n) && n >= 1 && n <= 40320),
    ),
  ].slice(0, 4);
}

// ─── the editor ───────────────────────────────────────────────────────────

interface Question {
  questionId: string;
  label: string;
  kind: "text" | "choice" | "boolean";
  choices?: string[];
  required?: boolean;
}

/** What the editor holds; turned into a create or update payload by `draftOf`. */
interface Form {
  calendarId: string;
  kind: "event" | "meeting";
  title: string;
  description: string;
  date: string;
  time: string;
  timeZone: string;
  minutes: number;
  allDay: boolean;
  placeSummary: string;
  placeName: string;
  placeAddress: string;
  joinUri: string;
  accessNotes: string;
  accessPublic: boolean;
  revealAt: string;
  scope: Audience["scope"];
  groups: string[];
  roles: string[];
  useRule: boolean;
  rule: DynamicRule;
  mode: "open" | "approval" | "closed";
  capacity: string;
  waitlist: boolean;
  plusOnes: number;
  opensAt: string;
  closesAt: string;
  questions: Question[];
  cocUrl: string;
  cocSha: string;
  a11y: Record<"stepFree" | "captions" | "hearingLoop" | "quietSpace" | "remoteOption", boolean>;
  a11yNotes: string;
  roster: "visible" | "hidden";
  showCount: boolean;
  countThreshold: number;
  listed: boolean;
  reminders: string;
}

const A11Y_LABELS = [
  ["stepFree", "Step-free access"],
  ["captions", "Captions"],
  ["hearingLoop", "Hearing loop"],
  ["quietSpace", "Quiet space"],
  ["remoteOption", "Join remotely"],
] as const;

function blankForm(calendarId: string): Form {
  const d = new Date(Date.now() + 7 * 86400_000);
  return {
    calendarId,
    kind: "event",
    title: "",
    description: "",
    date: d.toISOString().slice(0, 10),
    time: "18:30",
    timeZone: timeZones()[0] ?? "Etc/UTC",
    minutes: 90,
    allDay: false,
    placeSummary: "",
    placeName: "",
    placeAddress: "",
    joinUri: "",
    accessNotes: "",
    accessPublic: false,
    revealAt: "",
    scope: "members",
    groups: [],
    roles: [],
    useRule: false,
    rule: emptyRule(),
    mode: "open",
    capacity: "",
    waitlist: false,
    plusOnes: 0,
    opensAt: "",
    closesAt: "",
    questions: [],
    cocUrl: "",
    cocSha: "",
    a11y: { stepFree: false, captions: false, hearingLoop: false, quietSpace: false, remoteOption: false },
    a11yNotes: "",
    roster: "hidden",
    showCount: false,
    countThreshold: 5,
    listed: true,
    reminders: "1440, 60",
  };
}

function formOf(ev: CommunityEvent): Form {
  const [date, t] = ev.when.start.split("T");
  const a = ev.access;
  const place = a?.places?.[0];
  const v = a?.virtualPlaces?.[0];
  const r = ev.registration;
  const toLocal = (iso?: string) => (iso ? iso.slice(0, 16) : "");
  return {
    calendarId: ev.calendarId,
    kind: ev.kind,
    title: ev.title,
    description: ev.description ?? "",
    date: date ?? "",
    time: (t ?? "00:00:00").slice(0, 5),
    timeZone: ev.when.timeZone,
    minutes: durationMinutes(ev.when.duration),
    allDay: !!ev.when.showWithoutTime,
    placeSummary: ev.placeSummary ?? "",
    placeName: place?.name ?? "",
    placeAddress: place?.address ?? "",
    joinUri: v?.uri ?? "",
    accessNotes: a?.notes ?? "",
    accessPublic: !!a?.public,
    revealAt: toLocal(a?.revealAt),
    scope: ev.audience.scope,
    groups: ev.audience.groups ?? [],
    roles: ev.audience.roles ?? [],
    useRule: !!ev.audience.rule,
    rule: (ev.audience.rule as DynamicRule | undefined) ?? emptyRule(),
    mode: r.mode,
    capacity: r.capacity ? String(r.capacity) : "",
    waitlist: !!r.waitlist,
    plusOnes: r.plusOnes ?? 0,
    opensAt: toLocal(r.opensAt),
    closesAt: toLocal(r.closesAt),
    questions: (r.questions ?? []) as Question[],
    cocUrl: r.codeOfConduct?.url ?? "",
    cocSha: r.codeOfConduct?.sha256 ?? "",
    a11y: {
      stepFree: !!ev.accessibility?.stepFree,
      captions: !!ev.accessibility?.captions,
      hearingLoop: !!ev.accessibility?.hearingLoop,
      quietSpace: !!ev.accessibility?.quietSpace,
      remoteOption: !!ev.accessibility?.remoteOption,
    },
    a11yNotes: ev.accessibility?.notes ?? "",
    roster: ev.roster,
    showCount: !!ev.showCount,
    countThreshold: ev.countThreshold ?? 5,
    listed: ev.listed,
    reminders: (ev.suggestedReminderMinutes ?? []).join(", "),
  };
}

const utcOf = (local: string) => (local ? new Date(local).toISOString().replace(/\.\d{3}Z$/, "Z") : undefined);

/** The payload a form stands for (create's members; update takes the same minus calendar and kind). */
function draftOf(f: Form): EventDraft {
  const access =
    f.placeName || f.joinUri || f.accessNotes
      ? {
          ...(f.placeName ? { places: [{ name: f.placeName, ...(f.placeAddress ? { address: f.placeAddress } : {}) }] } : {}),
          ...(f.joinUri ? { virtualPlaces: [{ uri: f.joinUri, features: ["video" as const] }] } : {}),
          ...(f.accessNotes ? { notes: f.accessNotes } : {}),
          ...(f.accessPublic ? { public: true } : {}),
          ...(f.revealAt ? { revealAt: utcOf(f.revealAt) } : {}),
        }
      : undefined;
  const audience: Audience = {
    scope: f.scope,
    ...(f.scope === "groups" ? { groups: f.groups } : {}),
    ...(f.scope === "roles" ? { roles: f.roles } : {}),
    ...(f.useRule ? { rule: wireRule(f.rule) } : {}),
  };
  const cap = Number(f.capacity);
  const a11y = Object.fromEntries(Object.entries(f.a11y).filter(([, v]) => v));
  return {
    calendarId: f.calendarId || undefined,
    kind: f.kind,
    title: f.title.trim(),
    ...(f.description.trim() ? { description: f.description.trim() } : {}),
    when: {
      start: f.allDay ? `${f.date}T00:00:00` : `${f.date}T${f.time}:00`,
      timeZone: f.timeZone,
      duration: f.allDay ? `P${Math.max(1, Math.round(f.minutes / 1440))}D` : durationOf(f.minutes),
      ...(f.allDay ? { showWithoutTime: true } : {}),
    },
    ...(f.placeSummary.trim() ? { placeSummary: f.placeSummary.trim() } : {}),
    ...(access ? { access } : {}),
    audience,
    registration: {
      mode: f.mode,
      ...(cap > 0 ? { capacity: cap } : {}),
      ...(cap > 0 && f.waitlist ? { waitlist: true } : {}),
      ...(f.plusOnes ? { plusOnes: f.plusOnes } : {}),
      ...(f.opensAt ? { opensAt: utcOf(f.opensAt) } : {}),
      ...(f.closesAt ? { closesAt: utcOf(f.closesAt) } : {}),
      ...(f.questions.length ? { questions: f.questions } : {}),
      ...(f.cocUrl && f.cocSha ? { codeOfConduct: { url: f.cocUrl, sha256: f.cocSha } } : {}),
    },
    roster: f.roster,
    ...(f.showCount ? { showCount: true, countThreshold: f.countThreshold } : {}),
    listed: f.listed,
    ...(Object.keys(a11y).length || f.a11yNotes ? { accessibility: { ...a11y, ...(f.a11yNotes ? { notes: f.a11yNotes } : {}) } } : {}),
    suggestedReminderMinutes: parseMinutes(f.reminders),
  } as EventDraft;
}

function ready(f: Form): boolean {
  if (!f.title.trim() || !f.date || f.minutes < 1) return false;
  if (f.scope === "groups" && f.groups.length === 0) return false;
  if (f.scope === "roles" && f.roles.length === 0) return false;
  if (f.useRule && !ruleReady(f.rule)) return false;
  if ((f.cocUrl && !/^https:\/\//.test(f.cocUrl)) || (f.cocSha && !/^[0-9a-f]{64}$/.test(f.cocSha))) return false;
  return true;
}

function EventEditorPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const qc = useQueryClient();
  const calendars = useCalendars();
  const first = calendars.data?.find((c) => c.community)?.calendarId ?? "";
  const [form, setForm] = useState<Form | null>(null);
  const f = form ?? blankForm(first);
  const create = useMutation({
    mutationFn: () => createEvent(draftOf(f)),
    onSuccess: (ev) => {
      void qc.invalidateQueries({ queryKey: EVENTS_KEY });
      toast.push("success", "Saved as a draft. Publish it when it is ready.");
      navigate(`../${encodeURIComponent(ev.eventId)}`);
    },
    onError: (err) => toast.pushFromError(err, "The event was not saved"),
  });
  return (
    <>
      <PageHeader title="New event" trail={[{ label: "Events", to: ".." }, { label: "New" }]} />
      <EventForm
        form={f}
        onChange={setForm}
        calendars={(calendars.data ?? []).filter((c) => c.state === "active")}
        published={false}
        submitLabel="Save draft"
        busy={create.isPending}
        onSubmit={() => create.mutate()}
      />
    </>
  );
}

function EventForm({
  form: f,
  onChange,
  calendars,
  published,
  submitLabel,
  busy,
  onSubmit,
}: {
  form: Form;
  onChange: (f: Form) => void;
  calendars: Calendar[];
  published: boolean;
  submitLabel: string;
  busy: boolean;
  onSubmit: () => void;
}) {
  const set = (patch: Partial<Form>) => onChange({ ...f, ...patch });
  const zones = useMemo(() => timeZones(), []);
  const groups = useQuery({ queryKey: ["groups", "list"], queryFn: listGroups, retry: false });
  const badges = useQuery({ queryKey: ["badges"], queryFn: listBadges, retry: false });
  const roles = useQuery({ queryKey: ["roles", "list"], queryFn: () => listRoles(true), retry: false });
  const audienceGroups = [
    ...(groups.data ?? []).map((g) => ({ id: g.group.groupId, label: g.group.name })),
    ...(badges.data ?? [])
      .filter((b) => b.badge.groupId)
      .map((b) => ({ id: b.badge.groupId!, label: `Badge: ${b.badge.name}` })),
  ];
  const toggle = (list: string[], id: string, on: boolean) => (on ? [...list, id] : list.filter((x) => x !== id));
  return (
    <form
      className="card form-stack ev-editor"
      onSubmit={(e) => {
        e.preventDefault();
        if (ready(f)) onSubmit();
      }}
    >
      <h3>The event</h3>
      <div className="form-grid">
        <Field label="Title">
          <input value={f.title} maxLength={200} onChange={(e) => set({ title: e.target.value })} />
        </Field>
        <Field label="Kind" hint="A meeting may later carry an agenda, quorum and minutes.">
          <select value={f.kind} disabled={published} onChange={(e) => set({ kind: e.target.value as Form["kind"] })}>
            <option value="event">Event</option>
            <option value="meeting">Meeting</option>
          </select>
        </Field>
        {!published && (
          <Field label="Calendar">
            <select value={f.calendarId} onChange={(e) => set({ calendarId: e.target.value })}>
              {calendars.map((c) => (
                <option key={c.calendarId} value={c.calendarId}>
                  {c.name}
                </option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Description" className="span-2">
          <textarea className="prose" rows={3} maxLength={10000} value={f.description} onChange={(e) => set({ description: e.target.value })} />
        </Field>
      </div>

      <h3>When</h3>
      <div className="form-grid">
        <Field label="Date">
          <input type="date" value={f.date} onChange={(e) => set({ date: e.target.value })} />
        </Field>
        {!f.allDay && (
          <Field label="Starts">
            <input type="time" value={f.time} onChange={(e) => set({ time: e.target.value })} />
          </Field>
        )}
        <Field label="Time zone" hint="The event's own zone; members see it in theirs too.">
          <select value={f.timeZone} onChange={(e) => set({ timeZone: e.target.value })}>
            {zones.map((z) => (
              <option key={z} value={z}>
                {z}
              </option>
            ))}
          </select>
        </Field>
        <Field label={f.allDay ? "Days" : "Minutes"}>
          <input
            type="number"
            min={1}
            value={f.allDay ? Math.max(1, Math.round(f.minutes / 1440)) : f.minutes}
            onChange={(e) => set({ minutes: (Number(e.target.value) || 1) * (f.allDay ? 1440 : 1) })}
          />
        </Field>
        <label className="checkbox span-2">
          <input type="checkbox" checked={f.allDay} onChange={(e) => set({ allDay: e.target.checked, minutes: e.target.checked ? 1440 : 90 })} />
          <span className="checkbox-text">All day</span>
        </label>
      </div>

      <h3>Where</h3>
      <div className="form-grid">
        <Field label="Place summary" hint="Shown to everyone who sees the event — a neighbourhood or Online, never the address.">
          <input value={f.placeSummary} maxLength={200} onChange={(e) => set({ placeSummary: e.target.value })} />
        </Field>
        <Field label="Place" hint="Released to registrants who are going.">
          <input value={f.placeName} maxLength={200} onChange={(e) => set({ placeName: e.target.value })} />
        </Field>
        <Field label="Address">
          <input value={f.placeAddress} maxLength={500} onChange={(e) => set({ placeAddress: e.target.value })} />
        </Field>
        <Field label="Join link" hint="https, tel, sip or sips.">
          <input value={f.joinUri} maxLength={2048} onChange={(e) => set({ joinUri: e.target.value })} />
        </Field>
        <Field label="Notes for attendees" className="span-2">
          <input value={f.accessNotes} maxLength={2000} onChange={(e) => set({ accessNotes: e.target.value })} />
        </Field>
        <Field label="Release from" hint="Optional: not before this, even to those going.">
          <input type="datetime-local" value={f.revealAt} onChange={(e) => set({ revealAt: e.target.value })} />
        </Field>
        <label className="checkbox">
          <input type="checkbox" checked={f.accessPublic} onChange={(e) => set({ accessPublic: e.target.checked })} />
          <span className="checkbox-text">Show where it happens to everyone who sees the event</span>
        </label>
      </div>

      <h3>Who may come</h3>
      <div className="form-grid">
        <Field label="Audience">
          <select value={f.scope} onChange={(e) => set({ scope: e.target.value as Form["scope"] })}>
            <option value="members">Every member</option>
            <option value="groups">Members of chosen groups or badges</option>
            <option value="roles">Members with chosen roles</option>
          </select>
        </Field>
        <label className="checkbox">
          <input type="checkbox" checked={f.listed} onChange={(e) => set({ listed: e.target.checked })} />
          <span className="checkbox-text">Listed (unlisted events are found only by their link)</span>
        </label>
        {f.scope === "groups" && (
          <div className="span-2 ev-pick" role="group" aria-label="Groups and badges">
            {audienceGroups.map((g) => (
              <label key={g.id} className="checkbox">
                <input type="checkbox" checked={f.groups.includes(g.id)} onChange={(e) => set({ groups: toggle(f.groups, g.id, e.target.checked) })} />
                <span className="checkbox-text">{g.label}</span>
              </label>
            ))}
          </div>
        )}
        {f.scope === "roles" && (
          <div className="span-2 ev-pick" role="group" aria-label="Roles">
            {(roles.data ?? []).map((r) => (
              <label key={r.name} className="checkbox">
                <input type="checkbox" checked={f.roles.includes(r.name)} onChange={(e) => set({ roles: toggle(f.roles, r.name, e.target.checked) })} />
                <span className="checkbox-text">{r.name}</span>
              </label>
            ))}
          </div>
        )}
        <label className="checkbox span-2">
          <input type="checkbox" checked={f.useRule} onChange={(e) => set({ useRule: e.target.checked })} />
          <span className="checkbox-text">Narrow it further by a rule (tenure, a verified field, personhood)</span>
        </label>
        {f.useRule && <RuleEditor value={f.rule} onChange={(rule) => set({ rule })} className="span-2" />}
      </div>

      <h3>Registration</h3>
      <div className="form-grid">
        <Field label="Mode">
          <select value={f.mode} onChange={(e) => set({ mode: e.target.value as Form["mode"] })}>
            <option value="open">Open: registrants are going at once</option>
            <option value="approval">Approval: hosts confirm each one</option>
            <option value="closed">Closed: for information only</option>
          </select>
        </Field>
        <Field label="Capacity" hint="Places, plus-ones included. Empty for no limit.">
          <input type="number" min={1} value={f.capacity} onChange={(e) => set({ capacity: e.target.value })} />
        </Field>
        <Field label="Plus-ones each">
          <input type="number" min={0} max={10} value={f.plusOnes} onChange={(e) => set({ plusOnes: Number(e.target.value) || 0 })} />
        </Field>
        <label className="checkbox">
          <input type="checkbox" checked={f.waitlist} disabled={!f.capacity} onChange={(e) => set({ waitlist: e.target.checked })} />
          <span className="checkbox-text">Keep a waitlist when full</span>
        </label>
        <Field label="Registration opens">
          <input type="datetime-local" value={f.opensAt} onChange={(e) => set({ opensAt: e.target.value })} />
        </Field>
        <Field label="Registration closes" hint="Empty: at the start.">
          <input type="datetime-local" value={f.closesAt} onChange={(e) => set({ closesAt: e.target.value })} />
        </Field>
        <QuestionsField questions={f.questions} onChange={(questions) => set({ questions })} />
        <Field label="Code of conduct link" hint="https only.">
          <input value={f.cocUrl} onChange={(e) => set({ cocUrl: e.target.value })} />
        </Field>
        <Field label="Code of conduct SHA-256" hint="The digest of the text registrants agree to.">
          <input value={f.cocSha} onChange={(e) => set({ cocSha: e.target.value.trim().toLowerCase() })} />
        </Field>
      </div>

      <h3>Accessibility</h3>
      <div className="form-grid">
        <div className="span-2 ev-pick" role="group" aria-label="Accessibility">
          {A11Y_LABELS.map(([k, label]) => (
            <label key={k} className="checkbox">
              <input type="checkbox" checked={f.a11y[k]} onChange={(e) => set({ a11y: { ...f.a11y, [k]: e.target.checked } })} />
              <span className="checkbox-text">{label}</span>
            </label>
          ))}
        </div>
        <Field label="Accessibility notes" className="span-2">
          <input value={f.a11yNotes} maxLength={1000} onChange={(e) => set({ a11yNotes: e.target.value })} />
        </Field>
      </div>

      <h3>Privacy</h3>
      <div className="form-grid">
        <Field label="Roster">
          <select aria-label="Roster" value={f.roster} disabled={published} onChange={(e) => set({ roster: e.target.value as Form["roster"] })}>
            <option value="hidden">Hidden: only hosts see who is coming</option>
            <option value="visible">Visible: registrants see each other</option>
          </select>
        </Field>
        <div className="ev-lock" role="note">
          <Lock size={14} aria-hidden="true" />
          {published
            ? "The roster setting was fixed when this event was published. To change it, cancel the event and make a new one."
            : "The roster setting locks when you publish, and registrants are told it before they register."}
        </div>
        <label className="checkbox">
          <input type="checkbox" checked={f.showCount} onChange={(e) => set({ showCount: e.target.checked })} />
          <span className="checkbox-text">Show how many are going</span>
        </label>
        {f.showCount && (
          <Field label="Below this, say “fewer than”">
            <input type="number" min={2} max={100} value={f.countThreshold} onChange={(e) => set({ countThreshold: Number(e.target.value) || 5 })} />
          </Field>
        )}
        <Field label="Suggested reminders" hint="Minutes before the start, comma separated. Members' own agents fire them.">
          <input value={f.reminders} onChange={(e) => set({ reminders: e.target.value })} />
        </Field>
      </div>

      <div className="form-actions">
        <button type="submit" className="primary" disabled={!ready(f) || busy}>
          {busy ? "Saving…" : submitLabel}
        </button>
      </div>
    </form>
  );
}

function QuestionsField({ questions, onChange }: { questions: Question[]; onChange: (q: Question[]) => void }) {
  const add = () =>
    onChange([...questions, { questionId: `q${questions.length + 1}`, label: "", kind: "text", required: false }]);
  return (
    <div className="span-2 ev-questions">
      <span className="field-label">Questions</span>
      {questions.map((q, i) => (
        <div key={q.questionId} className="ev-question">
          <input
            aria-label={`Question ${i + 1}`}
            value={q.label}
            maxLength={200}
            placeholder="e.g. Any dietary needs?"
            onChange={(e) => onChange(questions.map((x, j) => (j === i ? { ...x, label: e.target.value } : x)))}
          />
          <select
            aria-label={`Answer kind ${i + 1}`}
            value={q.kind}
            onChange={(e) =>
              onChange(
                questions.map((x, j) =>
                  j === i
                    ? {
                        ...x,
                        kind: e.target.value as Question["kind"],
                        choices: e.target.value === "choice" ? (x.choices ?? ["Yes", "No"]) : undefined,
                      }
                    : x,
                ),
              )
            }
          >
            <option value="text">Text</option>
            <option value="choice">Choice</option>
            <option value="boolean">Yes / no</option>
          </select>
          {q.kind === "choice" && (
            <input
              aria-label={`Choices ${i + 1}`}
              value={(q.choices ?? []).join(", ")}
              onChange={(e) =>
                onChange(
                  questions.map((x, j) =>
                    j === i ? { ...x, choices: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) } : x,
                  ),
                )
              }
            />
          )}
          <label className="checkbox">
            <input
              type="checkbox"
              checked={!!q.required}
              onChange={(e) => onChange(questions.map((x, j) => (j === i ? { ...x, required: e.target.checked } : x)))}
            />
            <span className="checkbox-text">Required</span>
          </label>
          <button type="button" className="ghost" aria-label={`Remove question ${i + 1}`} onClick={() => onChange(questions.filter((_, j) => j !== i))}>
            <Trash2 size={14} aria-hidden="true" />
          </button>
        </div>
      ))}
      {questions.length < 20 && (
        <button type="button" className="secondary" onClick={add}>
          <Plus size={14} aria-hidden="true" /> Add a question
        </button>
      )}
      <span className="muted">Answers are read by the hosts only, and deleted a while after the event.</span>
    </div>
  );
}

// ─── one event ────────────────────────────────────────────────────────────

type Tab = "details" | "registrations" | "hosts";

function EventPage() {
  const { id = "" } = useParams();
  const eventId = decodeURIComponent(id);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const calendars = useCalendars();
  const [tab, setTab] = useState<Tab>("details");
  const [form, setForm] = useState<Form | null>(null);
  const shown = useQuery({ queryKey: [...EVENTS_KEY, "show", eventId], queryFn: () => showEvent(eventId), retry: false });
  const ev = shown.data?.event;
  const refresh = () => void qc.invalidateQueries({ queryKey: EVENTS_KEY });
  const save = useMutation({
    mutationFn: () => {
      const d = draftOf(form!);
      const { calendarId: _c, kind: _k, ...rest } = d;
      const patch = { eventId, ...rest, ...(ev?.status === "published" ? { roster: undefined } : {}) };
      return updateEvent(patch);
    },
    onSuccess: () => {
      setForm(null);
      refresh();
      toast.push("success", "Saved.");
    },
    onError: (err) => toast.pushFromError(err, "The event was not saved"),
  });
  const publish = useMutation({
    mutationFn: () => publishEvent(eventId),
    onSuccess: () => {
      refresh();
      toast.push("success", "Published. Its audience sees it now.");
    },
    onError: (err) => toast.pushFromError(err, "The event was not published"),
  });
  const cancel = useMutation({
    mutationFn: (reason: string) => cancelEvent(eventId, reason || undefined),
    onSuccess: () => {
      refresh();
      toast.push("success", "Cancelled. Registrants see it cancelled.");
    },
    onError: (err) => toast.pushFromError(err, "The event was not cancelled"),
  });
  const remove = useMutation({
    mutationFn: () => deleteEvent(eventId),
    onSuccess: () => {
      refresh();
      navigate("..");
    },
    onError: (err) => toast.pushFromError(err, "The draft was not deleted"),
  });
  const [cancelReason, setCancelReason] = useState("");
  if (shown.isPending) return <p className="muted">Loading…</p>;
  if (!ev) {
    return (
      <>
        <PageHeader title="Event" trail={[{ label: "Events", to: ".." }, { label: "Event" }]} />
        <EmptyState title="There is no event you run with this identifier." />
      </>
    );
  }
  return (
    <>
      <PageHeader
        title={ev.title}
        trail={[{ label: "Events", to: ".." }, { label: ev.title }]}
        lead={`${formatWhen(ev.when)}${zoneNote(ev.when) ? ` · ${zoneNote(ev.when)}` : ""}`}
        actions={
          <>
            {statusChip(ev)}
            {ev.status === "draft" && (
              <>
                <button
                  type="button"
                  className="primary"
                  disabled={publish.isPending}
                  onClick={async () => {
                    const ok = await confirm({
                      title: `Publish ${ev.title}?`,
                      message: `Its audience sees it and may register. The roster setting — ${ev.roster} — is fixed from now on.`,
                      confirmLabel: "Publish",
                    });
                    if (ok) publish.mutate();
                  }}
                >
                  <CalendarPlus size={14} aria-hidden="true" /> Publish
                </button>
                <button
                  type="button"
                  className="secondary"
                  onClick={async () => {
                    const ok = await confirm({ title: "Delete this draft?", message: "Nothing of it is kept.", confirmLabel: "Delete", destructive: true });
                    if (ok) remove.mutate();
                  }}
                >
                  <Trash2 size={14} aria-hidden="true" /> Delete draft
                </button>
              </>
            )}
          </>
        }
      />
      <div className="ev-tabs" role="tablist" aria-label="Event">
        {(
          [
            ["details", "Details"],
            ["registrations", "Registrations"],
            ["hosts", "Hosts"],
          ] as const
        ).map(([t, label]) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t} onClick={() => setTab(t)}>
            {label}
          </button>
        ))}
      </div>
      {tab === "details" && (
        <>
          <section className="card ev-summary">
            <span>
              {ev.roster === "visible" ? <Eye size={14} aria-hidden="true" /> : <EyeOff size={14} aria-hidden="true" />}{" "}
              {ev.roster === "visible" ? "Visible roster" : "Hidden roster"}
              {ev.status !== "draft" && " · fixed"}
            </span>
            <span>Going: {goingWords(ev)}</span>
            <span>Sequence {ev.sequence}</span>
          </section>
          {ev.status === "cancelled" ? (
            <section className="card">
              <h3>Cancelled</h3>
              <p>{ev.cancelReason ?? "No reason was given."}</p>
            </section>
          ) : (
            <EventForm
              form={form ?? formOf(ev)}
              onChange={setForm}
              calendars={calendars.data ?? []}
              published={ev.status === "published"}
              submitLabel="Save changes"
              busy={save.isPending}
              onSubmit={() => save.mutate()}
            />
          )}
          {ev.status === "published" && (
            <section className="card form-stack">
              <h3>Cancel the event</h3>
              <p className="muted">Registrants see it cancelled, with your reason. A cancelled event is kept, never deleted.</p>
              <Field label="Reason">
                <input value={cancelReason} maxLength={1000} onChange={(e) => setCancelReason(e.target.value)} />
              </Field>
              <div className="form-actions">
                <button
                  type="button"
                  className="danger"
                  disabled={cancel.isPending}
                  onClick={async () => {
                    const ok = await confirm({ title: `Cancel ${ev.title}?`, message: "This can't be undone.", confirmLabel: "Cancel event", destructive: true });
                    if (ok) cancel.mutate(cancelReason.trim());
                  }}
                >
                  Cancel event
                </button>
              </div>
            </section>
          )}
        </>
      )}
      {tab === "registrations" && <RegistrationsTab eventId={eventId} />}
      {tab === "hosts" && <HostsTab eventId={eventId} />}
    </>
  );
}

const STATUSES: RegistrationStatus[] = ["going", "maybe", "pending", "waitlisted", "withdrawn", "declined", "removed"];

function RegistrationsTab({ eventId }: { eventId: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const faces = useEntryFaces();
  const [filter, setFilter] = useState<RegistrationStatus | "">("");
  const regs = useQuery({
    queryKey: [...EVENTS_KEY, "registrations", eventId, filter],
    queryFn: () => listRegistrations(eventId, filter ? [filter] : undefined),
    retry: false,
  });
  const refresh = () => void qc.invalidateQueries({ queryKey: EVENTS_KEY });
  const decide = useMutation({
    mutationFn: ({ r, d }: { r: Registration; d: "approve" | "decline" }) => decideRegistration(r.registrationId, d),
    onSuccess: refresh,
    onError: (err) => toast.pushFromError(err, "The registration was not decided"),
  });
  const remove = useMutation({
    mutationFn: (r: Registration) => removeRegistration(r.registrationId),
    onSuccess: refresh,
    onError: (err) => toast.pushFromError(err, "The registration was not removed"),
  });
  const items = regs.data ?? [];
  return (
    <section className="card table-card">
      <div className="ev-filters">
        <Field label="Status">
          <select aria-label="Filter registrations" value={filter} onChange={(e) => setFilter(e.target.value as RegistrationStatus | "")}>
            <option value="">Every status</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {STATUS_LABEL[s]}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <DataTable
        caption="Registrations"
        columns={[
          { key: "who", label: "Registrant" },
          { key: "status", label: "Status" },
          { key: "guests", label: "Guests" },
          { key: "answers", label: "Answers" },
          { key: "act", label: "" },
        ]}
      >
        {regs.isSuccess && items.length === 0 && (
          <tr>
            <td colSpan={5}>
              <EmptyState title="No registrations" />
            </td>
          </tr>
        )}
        {items.map((r) => (
          <tr key={r.registrationId}>
            <td>
              <EntryName entryId={r.entryId} faces={faces} />
            </td>
            <td>
              {STATUS_LABEL[r.status]}
              {r.status === "waitlisted" && r.waitlistPosition ? ` (${r.waitlistPosition})` : ""}
            </td>
            <td>{r.guests}</td>
            <td className="muted">
              {r.answers
                ? Object.entries(r.answers)
                    .map(([k, v]) => `${k}: ${String(v)}`)
                    .join("; ")
                : "—"}
            </td>
            <td>
              <div className="ev-row-actions">
                {r.status === "pending" && (
                  <>
                    <button type="button" className="primary" onClick={() => decide.mutate({ r, d: "approve" })}>
                      Approve
                    </button>
                    <button type="button" className="secondary" onClick={() => decide.mutate({ r, d: "decline" })}>
                      Decline
                    </button>
                  </>
                )}
                {["going", "maybe", "pending", "waitlisted"].includes(r.status) && (
                  <button type="button" className="ghost" onClick={() => remove.mutate(r)}>
                    Remove
                  </button>
                )}
              </div>
            </td>
          </tr>
        ))}
      </DataTable>
    </section>
  );
}

function HostsTab({ eventId }: { eventId: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const faces = useEntryFaces();
  const [filter, setFilter] = useState("");
  const hosts = useQuery({ queryKey: [...EVENTS_KEY, "hosts", eventId], queryFn: () => listHosts(eventId), retry: false });
  const refresh = () => void qc.invalidateQueries({ queryKey: [...EVENTS_KEY, "hosts", eventId] });
  const appoint = useMutation({
    mutationFn: (entryId: string) => appointHost(eventId, entryId),
    onSuccess: refresh,
    onError: (err) => toast.pushFromError(err, "The host was not appointed"),
  });
  const drop = useMutation({
    mutationFn: (entryId: string) => removeHost(eventId, entryId),
    onSuccess: refresh,
    onError: (err) => toast.pushFromError(err, "The host was not removed"),
  });
  const current = hosts.data ?? [];
  const candidates = [...faces.entries()]
    .filter(([id]) => !current.includes(id))
    .filter(([, f]) => filter && faceMatches(f, filter))
    .sort(byFace)
    .slice(0, 8);
  return (
    <section className="card form-stack">
      <h3>Hosts</h3>
      <p className="muted">
        Hosts change the event and decide its registrations. Holders of vtc.events.manage for the whole community or the
        calendar's group run it too, without being listed.
      </p>
      <ul className="ev-hosts">
        {current.length === 0 && <li className="muted">Nobody is appointed.</li>}
        {current.map((h) => (
          <li key={h}>
            <EntryName entryId={h} faces={faces} />
            <button type="button" className="ghost" aria-label={`Remove host ${faceLabel(faces.get(h))}`} onClick={() => drop.mutate(h)}>
              <UserMinus size={14} aria-hidden="true" />
            </button>
          </li>
        ))}
      </ul>
      <Field label="Appoint a host">
        <input type="search" placeholder="Find a member by name or DID…" value={filter} onChange={(e) => setFilter(e.target.value)} />
      </Field>
      <ul className="ev-hosts">
        {candidates.map(([id, f]) => (
          <li key={id}>
            {f.name ?? id}
            <button type="button" className="secondary" onClick={() => appoint.mutate(id)}>
              <UserPlus size={14} aria-hidden="true" /> Appoint
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
