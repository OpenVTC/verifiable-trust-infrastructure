// Community events in the member portal (`vtc/events/*`):
//
//   #/events          What's on: upcoming events you may come to, filtered by calendar; the
//                     events you registered for; a month at a glance.
//   #/events/<id>     One event: its details and accessibility, its roster setting, registering,
//                     changing and withdrawing, where it happens once you are going, who else is
//                     going on a visible roster, adding it to your calendar, reporting it.
//
// Signed by this browser's portal key for the member, as the directory is. Only the member's own
// acts go this way; hosts run events from the console. Nothing is shown that the community did
// not answer: where an event happens comes from `access/show`, which answers a registrant who is
// going (VTI-EVT-060), and the roster only on an event whose roster is visible (VTI-EVT-053).

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Accessibility as AccessibilityIcon,
  CalendarPlus,
  Check,
  Clock,
  Eye,
  EyeOff,
  Flag,
  MapPin,
  Users,
  X,
} from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { dateTile, formatWhen, icsFor, startOf, viewerZone, zoneNote } from "@/lib/event-time";

import {
  REPORT_REASONS,
  STATUS_WORDS,
  eventHref,
  eventsHref,
  listCalendars,
  listEvents,
  listMine,
  listRoster,
  register,
  reportEvent,
  showAccess,
  showEvent,
  withdraw,
  type AccessDetails,
  type CommunityEvent,
  type ListedEvent,
  type MyRegistration,
  type RegisterChoice,
  type ReportReason,
} from "./events-api";
import { DirectoryError } from "./directory-api";
import { Crumbs } from "./member-card";
import "./events.css";

type Tab = "upcoming" | "mine" | "month";

const EVENTS_KEY = ["events"] as const;

function countWords(ev: CommunityEvent): string | null {
  const c = ev.goingCount;
  if (!c) return null;
  if (typeof c.exact === "number") return `${c.exact} going`;
  if (typeof c.fewerThan === "number") return `Fewer than ${c.fewerThan} going`;
  return null;
}

function refusal(error: unknown): string {
  if (error instanceof DirectoryError) return error.message;
  return error instanceof Error ? error.message : "Something went wrong.";
}

/** The roster setting, said plainly (VTI-EVT-050). */
export function RosterNote({ roster, host = false }: { roster: CommunityEvent["roster"]; host?: boolean }) {
  return roster === "visible" ? (
    <div className="ev-roster-note">
      <Eye size={15} aria-hidden="true" />
      <div>
        <strong>Visible roster</strong>
        <span>
          People who are going or said maybe see each other.{" "}
          {host ? "" : "Set when this event was published; it can't be changed."}
        </span>
      </div>
    </div>
  ) : (
    <div className="ev-roster-note">
      <EyeOff size={15} aria-hidden="true" />
      <div>
        <strong>Hidden roster</strong>
        <span>
          Other attendees can't see who is coming. Hosts can.{" "}
          {host ? "" : "Set when this event was published; it can't be changed."}
        </span>
      </div>
    </div>
  );
}

function DateTile({ ev }: { ev: { when: CommunityEvent["when"] } }) {
  const t = dateTile(ev.when);
  return (
    <div className="ev-date" aria-hidden="true">
      <span className="ev-date-m">{t.month}</span>
      <span className="ev-date-d">{t.day}</span>
      <span className="ev-date-w">{t.weekday}</span>
    </div>
  );
}

function StatusPill({ status }: { status: MyRegistration["status"] }) {
  const tone = status === "going" ? "pill-ok" : status === "pending" || status === "waitlisted" || status === "maybe" ? "pill-warn" : "";
  return <span className={`pill ${tone}`}>{STATUS_WORDS[status]}</span>;
}

function EventCard({ item }: { item: ListedEvent }) {
  const ev = item.event;
  const note = zoneNote(ev.when);
  const count = countWords(ev);
  return (
    <a className="ev-card" href={eventHref(ev.eventId)}>
      <DateTile ev={ev} />
      <div className="ev-card-body">
        <h3>
          {ev.title}
          {ev.kind === "meeting" && <span className="pill">Meeting</span>}
          {ev.status === "cancelled" && <span className="pill pill-warn">Cancelled</span>}
        </h3>
        <p className="ev-meta">
          <span>
            <Clock size={13} aria-hidden="true" /> {formatWhen(ev.when)}
            {note && <span className="muted"> ({note})</span>}
          </span>
          {ev.placeSummary && (
            <span>
              <MapPin size={13} aria-hidden="true" /> {ev.placeSummary}
            </span>
          )}
        </p>
      </div>
      <div className="ev-card-side">
        {item.myStatus && <StatusPill status={item.myStatus} />}
        <span className="ev-roster-chip">
          {ev.roster === "visible" ? <Eye size={12} aria-hidden="true" /> : <EyeOff size={12} aria-hidden="true" />}
          {ev.roster === "visible" ? "Visible roster" : "Hidden roster"}
          {count ? ` · ${count}` : ""}
          {ev.full ? " · Full" : ""}
        </span>
      </div>
    </a>
  );
}

// ─── the events page ──────────────────────────────────────────────────────

export function EventsPage() {
  const [tab, setTab] = useState<Tab>("upcoming");
  const [calendarId, setCalendarId] = useState<string | null>(null);
  const from = useMemo(() => new Date(Date.now() - 6 * 3600_000).toISOString().replace(/\.\d{3}Z$/, "Z"), []);
  const calendars = useQuery({ queryKey: [...EVENTS_KEY, "calendars"], queryFn: listCalendars, retry: false });
  const upcoming = useQuery({
    queryKey: [...EVENTS_KEY, "upcoming", calendarId],
    queryFn: () => listEvents({ from, ...(calendarId ? { calendarId } : {}) }),
    retry: false,
  });
  const mine = useQuery({ queryKey: [...EVENTS_KEY, "mine"], queryFn: listMine, retry: false });
  const items = upcoming.data ?? [];
  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Events" }]} />
      <section className="welcome">
        <p className="eyebrow">Events</p>
        <h1>What's on</h1>
        <p className="lead">
          Events you may come to in this community. Times are shown in your zone ({viewerZone()}); your own agent reminds
          you, never the community.
        </p>
      </section>
      <div className="ev-tabs" role="tablist" aria-label="Events">
        {(
          [
            ["upcoming", "Upcoming"],
            ["mine", "Mine"],
            ["month", "Month"],
          ] as const
        ).map(([id, label]) => (
          <button key={id} type="button" role="tab" aria-selected={tab === id} onClick={() => setTab(id)}>
            {label}
            {id === "mine" && mine.data && mine.data.filter((m) => m.registration.status === "pending").length > 0 && (
              <span className="ev-tab-count">{mine.data.filter((m) => m.registration.status === "pending").length}</span>
            )}
          </button>
        ))}
      </div>
      {tab !== "mine" && (calendars.data?.length ?? 0) > 1 && (
        <div className="ev-chips" role="group" aria-label="Calendars">
          <button type="button" className={calendarId === null ? "on" : ""} onClick={() => setCalendarId(null)}>
            All
          </button>
          {calendars.data!.map((c) => (
            <button
              key={c.calendarId}
              type="button"
              className={calendarId === c.calendarId ? "on" : ""}
              onClick={() => setCalendarId(c.calendarId)}
            >
              {c.color && <span className="ev-swatch" style={{ background: c.color }} aria-hidden="true" />}
              {c.name}
            </button>
          ))}
        </div>
      )}
      {tab === "upcoming" && (
        <section className="bw-section" aria-label="Upcoming events">
          {upcoming.isPending && <p className="muted">Loading…</p>}
          {upcoming.isError && <p className="muted">{refusal(upcoming.error)}</p>}
          {upcoming.isSuccess && items.length === 0 && <p className="muted">Nothing on yet.</p>}
          <div className="ev-list">
            {items.map((i) => (
              <EventCard key={i.event.eventId} item={i} />
            ))}
          </div>
        </section>
      )}
      {tab === "mine" && (
        <section className="bw-section" aria-label="Your registrations">
          {mine.isPending && <p className="muted">Loading…</p>}
          {mine.isError && <p className="muted">{refusal(mine.error)}</p>}
          {mine.isSuccess && mine.data.length === 0 && <p className="muted">You haven't registered for anything.</p>}
          <div className="ev-list">
            {(mine.data ?? [])
              .slice()
              .sort((a, b) => startOf(a.event.when).getTime() - startOf(b.event.when).getTime())
              .map((m) => (
                <a key={m.registration.registrationId} className="ev-card" href={eventHref(m.event.eventId)}>
                  <DateTile ev={m.event} />
                  <div className="ev-card-body">
                    <h3>
                      {m.event.title}
                      {m.event.status === "cancelled" && <span className="pill pill-warn">Cancelled</span>}
                    </h3>
                    <p className="ev-meta">
                      <span>
                        <Clock size={13} aria-hidden="true" /> {formatWhen(m.event.when)}
                      </span>
                    </p>
                  </div>
                  <div className="ev-card-side">
                    <StatusPill status={m.registration.status} />
                  </div>
                </a>
              ))}
          </div>
        </section>
      )}
      {tab === "month" && <Month items={items} />}
    </main>
  );
}

/** A month at a glance: each day with its events, in the viewer's zone. */
function Month({ items }: { items: ListedEvent[] }) {
  const [offset, setOffset] = useState(0);
  const now = new Date();
  const first = new Date(now.getFullYear(), now.getMonth() + offset, 1);
  const days = new Date(first.getFullYear(), first.getMonth() + 1, 0).getDate();
  const lead = (first.getDay() + 6) % 7;
  const byDay = new Map<number, ListedEvent[]>();
  for (const i of items) {
    const s = startOf(i.event.when);
    if (s.getFullYear() === first.getFullYear() && s.getMonth() === first.getMonth()) {
      byDay.set(s.getDate(), [...(byDay.get(s.getDate()) ?? []), i]);
    }
  }
  const title = new Intl.DateTimeFormat(undefined, { month: "long", year: "numeric" }).format(first);
  return (
    <section className="bw-section" aria-label={title}>
      <div className="ev-month-head">
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => setOffset(offset - 1)}>
          Previous
        </button>
        <h2>{title}</h2>
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => setOffset(offset + 1)}>
          Next
        </button>
      </div>
      <div className="ev-month" role="grid">
        {["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((d) => (
          <div key={d} className="ev-month-dow" role="columnheader">
            {d}
          </div>
        ))}
        {Array.from({ length: lead }, (_, i) => (
          <div key={`pad-${i}`} className="ev-month-day ev-month-pad" />
        ))}
        {Array.from({ length: days }, (_, i) => i + 1).map((d) => (
          <div key={d} className="ev-month-day" role="gridcell">
            <span className="ev-month-n">{d}</span>
            {(byDay.get(d) ?? []).map((i) => (
              <a key={i.event.eventId} className="ev-month-ev" href={eventHref(i.event.eventId)}>
                {i.event.title}
              </a>
            ))}
          </div>
        ))}
      </div>
    </section>
  );
}

// ─── one event ────────────────────────────────────────────────────────────

/** Save the event as an `.ics` file, built here from what the community answered. */
function downloadIcs(ev: CommunityEvent, location: string | undefined) {
  const body = icsFor(
    {
      eventId: ev.eventId,
      title: ev.title,
      description: ev.description,
      when: ev.when,
      location,
      status: ev.status,
      sequence: ev.sequence,
      reminders: ev.suggestedReminderMinutes,
    },
    window.location.host || "community",
  );
  const url = URL.createObjectURL(new Blob([body], { type: "text/calendar" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `${ev.title.replace(/[^\w-]+/g, "-").slice(0, 60) || "event"}.ics`;
  a.click();
  URL.revokeObjectURL(url);
}

export function EventPage({ eventId }: { eventId: string }) {
  const qc = useQueryClient();
  const shown = useQuery({ queryKey: [...EVENTS_KEY, "show", eventId], queryFn: () => showEvent(eventId), retry: false });
  const ev = shown.data?.event;
  const mine = shown.data?.myRegistration;
  const going = mine?.status === "going";
  const access = useQuery({
    queryKey: [...EVENTS_KEY, "access", eventId],
    queryFn: () => showAccess(eventId),
    enabled: !!ev && going && ev.status !== "cancelled",
    retry: false,
  });
  const rosterOn = !!ev && ev.roster === "visible" && (mine?.status === "going" || mine?.status === "maybe");
  const roster = useQuery({
    queryKey: [...EVENTS_KEY, "roster", eventId],
    queryFn: () => listRoster(eventId),
    enabled: rosterOn,
    retry: false,
  });
  const refresh = () => void qc.invalidateQueries({ queryKey: EVENTS_KEY });

  if (shown.isPending) {
    return (
      <main className="home" id="main">
        <p className="muted">Loading…</p>
      </main>
    );
  }
  if (!ev) {
    return (
      <main className="home" id="main">
        <Crumbs trail={[{ label: "Events", href: eventsHref }, { label: "Event" }]} />
        <p className="muted">There is no event you may see here.</p>
      </main>
    );
  }
  const note = zoneNote(ev.when);
  const a11y = ev.accessibility;
  const a11yItems = a11y
    ? (
        [
          ["stepFree", "Step-free access"],
          ["captions", "Captions"],
          ["hearingLoop", "Hearing loop"],
          ["quietSpace", "Quiet space"],
          ["remoteOption", "Join remotely"],
        ] as const
      ).filter(([k]) => a11y[k])
    : [];
  const placeForIcs = access.data?.places?.[0]?.name ?? ev.placeSummary;
  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Events", href: eventsHref }, { label: ev.title }]} />
      <div className="ev-page">
        <div className="ev-main">
          <section className="ev-hero">
            <p className="eyebrow">{ev.kind === "meeting" ? "Meeting" : "Event"}</p>
            <h1>{ev.title}</h1>
          </section>
          {ev.status === "cancelled" && (
            <div className="ev-banner" role="status">
              <strong>This event was cancelled.</strong> {ev.cancelReason}
            </div>
          )}
          <dl className="ev-facts">
            <div>
              <dt>
                <Clock size={14} aria-hidden="true" /> When
              </dt>
              <dd>
                {formatWhen(ev.when)}
                {note && <span className="muted"> · {note}</span>}
              </dd>
            </div>
            {ev.placeSummary && (
              <div>
                <dt>
                  <MapPin size={14} aria-hidden="true" /> Where
                </dt>
                <dd>{ev.placeSummary}</dd>
              </div>
            )}
            {ev.registration.capacity && (
              <div>
                <dt>
                  <Users size={14} aria-hidden="true" /> Places
                </dt>
                <dd>
                  {ev.registration.capacity}
                  {ev.full ? " · full" : ""}
                  {ev.registration.waitlist ? " · waitlist" : ""}
                </dd>
              </div>
            )}
          </dl>
          {going && <AccessPanel access={access.data} error={access.error} pending={access.isPending} />}
          {ev.description && <p className="ev-desc">{ev.description}</p>}
          {a11yItems.length > 0 || a11y?.notes ? (
            <section className="ev-a11y" aria-label="Accessibility">
              <h2>
                <AccessibilityIcon size={15} aria-hidden="true" /> Accessibility
              </h2>
              <ul>
                {a11yItems.map(([k, label]) => (
                  <li key={k}>
                    <Check size={13} aria-hidden="true" /> {label}
                  </li>
                ))}
              </ul>
              {a11y?.notes && <p className="muted">{a11y.notes}</p>}
            </section>
          ) : null}
          {rosterOn && (
            <section className="ev-roster" aria-label="Who's going">
              <h2>Who's going</h2>
              {roster.isError && <p className="muted">{refusal(roster.error)}</p>}
              <ul>
                {(roster.data ?? []).map((r) => (
                  <li key={r.entryId}>
                    <a href={`#/directory/${encodeURIComponent(r.entryId)}`}>{r.entryId}</a>{" "}
                    <span className="muted">
                      {r.status === "maybe" ? "maybe" : "going"}
                      {r.guests ? ` · +${r.guests}` : ""}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}
          <ReportForm eventId={ev.eventId} />
        </div>
        <aside className="ev-aside">
          <Rsvp ev={ev} mine={mine} onChange={refresh} />
          <RosterNote roster={ev.roster} />
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => downloadIcs(ev, placeForIcs)}>
            <CalendarPlus size={14} aria-hidden="true" /> Add to calendar
          </button>
        </aside>
      </div>
    </main>
  );
}

/** Where it happens, once the member is going (VTI-EVT-060). */
function AccessPanel({ access, error, pending }: { access?: AccessDetails; error: unknown; pending: boolean }) {
  if (pending) return null;
  if (error instanceof DirectoryError && error.code === "notYet") {
    const at = typeof error.details.revealAt === "string" ? new Date(error.details.revealAt) : null;
    return (
      <div className="ev-reveal ev-reveal-later" role="status">
        <strong>Where it happens is shared closer to the time.</strong>
        {at && <span> From {at.toLocaleString()}.</span>}
      </div>
    );
  }
  if (error || !access) return null;
  return (
    <div className="ev-reveal" role="region" aria-label="Where it happens">
      {(access.places ?? []).map((p, i) => (
        <div key={`p-${i}`}>
          <strong>{p.name}</strong>
          {p.address && <span>{p.address}</span>}
          {p.description && <span className="muted">{p.description}</span>}
        </div>
      ))}
      {(access.virtualPlaces ?? []).map((v, i) => (
        <div key={`v-${i}`}>
          <strong>{v.name ?? "Join online"}</strong>
          <a href={v.uri} rel="noreferrer noopener" target="_blank">
            {v.uri}
          </a>
          {v.description && <span className="muted">{v.description}</span>}
        </div>
      ))}
      {access.notes && <span className="muted">{access.notes}</span>}
      <span className="muted">Shared with you because you're going.</span>
    </div>
  );
}

const LIVE = new Set(["going", "maybe", "pending", "waitlisted"]);

function Rsvp({ ev, mine, onChange }: { ev: CommunityEvent; mine?: MyRegistration; onChange: () => void }) {
  const confirm = useConfirm();
  const settings = ev.registration;
  const live = !!mine && LIVE.has(mine.status);
  const hostDecided = mine?.status === "declined" || mine?.status === "removed";
  const [editing, setEditing] = useState(false);
  const [choice, setChoice] = useState<RegisterChoice>(mine?.status === "maybe" ? "maybe" : "going");
  const [guests, setGuests] = useState(mine?.guests ?? 0);
  const [answers, setAnswers] = useState<Record<string, string | boolean>>(
    (mine?.answers as Record<string, string | boolean> | undefined) ?? {},
  );
  const [coc, setCoc] = useState(!!mine?.codeOfConductAcknowledged);
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: () =>
      register({
        eventId: ev.eventId,
        status: choice,
        ...(guests ? { guests } : {}),
        ...(Object.keys(answers).length ? { answers } : {}),
        ...(settings.codeOfConduct && coc ? { codeOfConductAcknowledged: settings.codeOfConduct.sha256 } : {}),
      }),
    onSuccess: () => {
      setEditing(false);
      setError(null);
      onChange();
    },
    onError: (e) => setError(refusal(e)),
  });
  const leave = useMutation({
    mutationFn: () => withdraw(ev.eventId),
    onSuccess: onChange,
    onError: (e) => setError(refusal(e)),
  });

  if (ev.status === "cancelled") {
    return (
      <div className="ev-rsvp">
        <h2>Cancelled</h2>
        {live && <p className="muted">Your registration stands in your history.</p>}
      </div>
    );
  }
  if (settings.mode === "closed" && !live) {
    return (
      <div className="ev-rsvp">
        <h2>For information</h2>
        <p className="muted">This event takes no registrations.</p>
      </div>
    );
  }
  if (live && !editing) {
    return (
      <div className="ev-rsvp">
        <h2 className="ev-rsvp-state">
          {mine!.status === "going" && <Check size={18} aria-hidden="true" />}
          {STATUS_WORDS[mine!.status]}
        </h2>
        {mine!.status === "waitlisted" && mine!.waitlistPosition && (
          <p className="muted">Number {mine!.waitlistPosition} on the waitlist. You move up when a place frees.</p>
        )}
        {mine!.guests > 0 && <p className="muted">Bringing {mine!.guests} {mine!.guests === 1 ? "guest" : "guests"}.</p>}
        {ev.sequence > mine!.eventSequence && (
          <p className="ev-changed" role="status">
            This event changed since you registered.
          </p>
        )}
        {error && <p className="error" role="alert">{error}</p>}
        <div className="ev-rsvp-actions">
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setEditing(true)}>
            Change registration
          </button>
          <button
            type="button"
            className="btn btn-danger btn-sm"
            disabled={leave.isPending}
            onClick={async () => {
              const ok = await confirm({
                title: `Withdraw from ${ev.title}?`,
                message: "Your place goes to the next person waiting. You can register again while registration is open.",
                confirmLabel: "Withdraw",
                destructive: true,
              });
              if (ok) leave.mutate();
            }}
          >
            <X size={14} aria-hidden="true" /> Withdraw
          </button>
        </div>
      </div>
    );
  }
  if (hostDecided) {
    return (
      <div className="ev-rsvp">
        <h2>{STATUS_WORDS[mine!.status]}</h2>
        {mine!.note && <p className="muted">{mine!.note}</p>}
      </div>
    );
  }
  const questions = settings.questions ?? [];
  const ready = (!settings.codeOfConduct || coc) && questions.every((q) => !q.required || answers[q.questionId] !== undefined);
  return (
    <form
      className="ev-rsvp"
      onSubmit={(e) => {
        e.preventDefault();
        if (ready) save.mutate();
      }}
    >
      <h2>{live ? "Change your registration" : "Register"}</h2>
      {settings.mode === "approval" && <p className="muted">The hosts confirm each registration.</p>}
      <div className="ev-choice" role="radiogroup" aria-label="Your answer">
        <label>
          <input type="radio" name="ev-choice" checked={choice === "going"} onChange={() => setChoice("going")} /> Going
        </label>
        {settings.mode !== "approval" && (
          <label>
            <input type="radio" name="ev-choice" checked={choice === "maybe"} onChange={() => setChoice("maybe")} /> Maybe
          </label>
        )}
      </div>
      {(settings.plusOnes ?? 0) > 0 && (
        <label className="ev-field">
          Guests
          <input
            type="number"
            min={0}
            max={settings.plusOnes}
            value={guests}
            onChange={(e) => setGuests(Math.max(0, Math.min(settings.plusOnes ?? 0, Number(e.target.value) || 0)))}
          />
        </label>
      )}
      {questions.map((q) => (
        <label key={q.questionId} className="ev-field">
          {q.label}
          {q.required ? " *" : ""}
          {q.kind === "boolean" ? (
            <input
              type="checkbox"
              checked={answers[q.questionId] === true}
              onChange={(e) => setAnswers({ ...answers, [q.questionId]: e.target.checked })}
            />
          ) : q.kind === "choice" ? (
            <select
              value={(answers[q.questionId] as string) ?? ""}
              onChange={(e) => setAnswers({ ...answers, [q.questionId]: e.target.value })}
            >
              <option value="">Choose…</option>
              {(q.choices ?? []).map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          ) : (
            <input
              type="text"
              maxLength={500}
              value={(answers[q.questionId] as string) ?? ""}
              onChange={(e) => setAnswers({ ...answers, [q.questionId]: e.target.value })}
            />
          )}
        </label>
      ))}
      {questions.length > 0 && <p className="muted">Only the hosts read your answers.</p>}
      {settings.codeOfConduct && (
        <label className="ev-coc">
          <input type="checkbox" checked={coc} onChange={(e) => setCoc(e.target.checked)} /> I've read and agree to the{" "}
          <a href={settings.codeOfConduct.url} target="_blank" rel="noreferrer noopener">
            code of conduct
          </a>
        </label>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="ev-rsvp-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={!ready || save.isPending}>
          {live ? "Save" : "Register"}
        </button>
        {live && (
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setEditing(false)}>
            Keep as it is
          </button>
        )}
      </div>
    </form>
  );
}

function ReportForm({ eventId }: { eventId: string }) {
  const [reason, setReason] = useState<ReportReason>("inappropriate");
  const [note, setNote] = useState("");
  const [done, setDone] = useState<string | null>(null);
  const send = useMutation({
    mutationFn: () => reportEvent({ eventId, reason, ...(note.trim() ? { note: note.trim() } : {}) }),
    onSuccess: () => setDone("Reported. The community's administrators will look at it; they don't see who reported it."),
    onError: (e) => setDone(refusal(e)),
  });
  return (
    <details className="ev-report">
      <summary>
        <Flag size={13} aria-hidden="true" /> Report this event
      </summary>
      {done ? (
        <p role="status">{done}</p>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            send.mutate();
          }}
        >
          <label className="ev-field">
            Why
            <select value={reason} onChange={(e) => setReason(e.target.value as ReportReason)}>
              {REPORT_REASONS.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.label}
                </option>
              ))}
            </select>
          </label>
          <label className="ev-field">
            What should the administrators know?
            <textarea maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} />
          </label>
          <button type="submit" className="btn btn-ghost btn-sm" disabled={send.isPending}>
            Send report
          </button>
        </form>
      )}
    </details>
  );
}

