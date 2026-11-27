// An event's time, as the console and the portal show it, and its `.ics` file.
//
// An event's time is JSCalendar's: a local `start` read in an IANA `timeZone`, and a
// `duration` (VTI-EVT-005). The instant it starts is worked out here with the browser's own
// zone database, so a viewer sees it in their own zone with the event's zone beside it. The
// `.ics` file is built in the browser from what the community answered; there is no route
// for it, and nothing goes in it the community did not show this viewer.

export interface EventWhen {
  start: string;
  timeZone: string;
  duration: string;
  showWithoutTime?: boolean;
}

/** Minutes in a JSCalendar duration (weeks, days, hours, minutes, seconds). */
export function durationMinutes(duration: string): number {
  const m = /^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(duration);
  if (!m) return 0;
  const n = (i: number) => (m[i] ? Number(m[i]) : 0);
  return n(1) * 10080 + n(2) * 1440 + n(3) * 60 + n(4) + Math.floor(n(5) / 60);
}

/** The offset of `zone` from UTC at `utcMs`, in milliseconds. */
function offsetAt(zone: string, utcMs: number): number {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: zone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(new Date(utcMs));
  const get = (t: string) => Number(parts.find((p) => p.type === t)?.value ?? 0);
  const asUtc = Date.UTC(get("year"), get("month") - 1, get("day"), get("hour") % 24, get("minute"), get("second"));
  return asUtc - utcMs;
}

/** The instant a local date-time in `zone` names. A time the zone skips moves forward by
 *  the gap; a repeated one takes the first, as the community resolves it. */
export function instantOf(local: string, zone: string): Date {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})$/.exec(local);
  if (!m) return new Date(NaN);
  const naive = Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!);
  try {
    // The offsets either side of any change give a candidate instant each, valid when the zone
    // reads it back as the local time. Two valid ones are a repeated hour: take the first. None
    // is a skipped hour: step forward a quarter hour at a time to the first local time that
    // exists, as the community does (`community_events::resolve_local`).
    for (let step = 0; step <= 16; step++) {
      const local = naive + step * 15 * 60_000;
      const before = local - offsetAt(zone, local - 12 * 3600_000);
      const after = local - offsetAt(zone, local + 12 * 3600_000);
      const valid = [before, after].filter((c) => c + offsetAt(zone, c) === local);
      if (valid.length) return new Date(Math.min(...valid));
    }
    return new Date(NaN);
  } catch {
    return new Date(NaN);
  }
}

export function startOf(when: EventWhen): Date {
  return instantOf(when.start, when.timeZone);
}

export function endOf(when: EventWhen): Date {
  return new Date(startOf(when).getTime() + durationMinutes(when.duration) * 60_000);
}

/** The viewer's own zone. */
export function viewerZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone;
}

/** "Mon 30 Nov, 18:30–20:00" in `zone` (the viewer's unless named); all-day events by date. */
export function formatWhen(when: EventWhen, zone: string = viewerZone()): string {
  const s = startOf(when);
  const e = endOf(when);
  if (Number.isNaN(s.getTime())) return when.start;
  const day = new Intl.DateTimeFormat(undefined, { weekday: "short", day: "numeric", month: "short", timeZone: zone });
  if (when.showWithoutTime) {
    const days = Math.round(durationMinutes(when.duration) / 1440);
    return days > 1 ? `${day.format(s)} – ${day.format(new Date(e.getTime() - 1))}` : `${day.format(s)}, all day`;
  }
  const time = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", timeZone: zone });
  const sameDay = day.format(s) === day.format(e);
  return sameDay
    ? `${day.format(s)}, ${time.format(s)}–${time.format(e)}`
    : `${day.format(s)}, ${time.format(s)} – ${day.format(e)}, ${time.format(e)}`;
}

/** The event's own zone beside the viewer's, when they differ: "18:30 Europe/London". */
export function zoneNote(when: EventWhen, zone: string = viewerZone()): string | null {
  if (when.timeZone === zone || when.showWithoutTime) return null;
  const s = startOf(when);
  if (Number.isNaN(s.getTime())) return null;
  const t = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", timeZone: when.timeZone });
  return `${t.format(s)} ${when.timeZone}`;
}

/** A date tile's month and day, in the viewer's zone. */
export function dateTile(when: EventWhen, zone: string = viewerZone()): { month: string; day: string; weekday: string } {
  const s = startOf(when);
  const f = (o: Intl.DateTimeFormatOptions) => new Intl.DateTimeFormat(undefined, { ...o, timeZone: zone }).format(s);
  return { month: f({ month: "short" }).toUpperCase(), day: f({ day: "numeric" }), weekday: f({ weekday: "short" }) };
}

// ── .ics ─────────────────────────────────────────────────────────────────

export interface IcsEvent {
  eventId: string;
  title: string;
  description?: string;
  when: EventWhen;
  /** What the viewer may see of where: the place summary, or a place they were given. */
  location?: string;
  status: "draft" | "published" | "cancelled";
  sequence: number;
  /** Minutes before the start. */
  reminders?: number[];
}

/** RFC 5545 text: backslash, semicolon, comma and newlines escaped. */
function text(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/\r?\n/g, "\\n");
}

/** Fold a content line at 75 octets (RFC 5545 §3.1). */
function fold(line: string): string {
  const bytes = new TextEncoder().encode(line);
  if (bytes.length <= 75) return line;
  const out: string[] = [];
  let cur = "";
  let len = 0;
  for (const ch of line) {
    const n = new TextEncoder().encode(ch).length;
    if (len + n > (out.length ? 74 : 75)) {
      out.push(cur);
      cur = "";
      len = 0;
    }
    cur += ch;
    len += n;
  }
  out.push(cur);
  return out.join("\r\n ");
}

const utc = (d: Date) => d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");

/** A one-event iCalendar file. The start is written as a UTC instant, so no VTIMEZONE is
 *  needed and every calendar reads the same moment; all-day events are dates. */
export function icsFor(ev: IcsEvent, community: string, now: Date = new Date()): string {
  const lines = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//OpenVTC//Verifiable Trust Community//EN",
    "CALSCALE:GREGORIAN",
    "METHOD:PUBLISH",
    "BEGIN:VEVENT",
    `UID:${ev.eventId}@${community}`,
    `DTSTAMP:${utc(now)}`,
  ];
  if (ev.when.showWithoutTime) {
    const date = ev.when.start.slice(0, 10).replace(/-/g, "");
    lines.push(`DTSTART;VALUE=DATE:${date}`);
    lines.push(`DURATION:P${Math.max(1, Math.round(durationMinutes(ev.when.duration) / 1440))}D`);
  } else {
    lines.push(`DTSTART:${utc(startOf(ev.when))}`);
    lines.push(`DURATION:${ev.when.duration}`);
  }
  lines.push(`SUMMARY:${text(ev.title)}`);
  if (ev.description) lines.push(`DESCRIPTION:${text(ev.description)}`);
  if (ev.location) lines.push(`LOCATION:${text(ev.location)}`);
  lines.push(`SEQUENCE:${ev.sequence}`);
  lines.push(`STATUS:${ev.status === "cancelled" ? "CANCELLED" : ev.status === "draft" ? "TENTATIVE" : "CONFIRMED"}`);
  for (const m of ev.reminders ?? []) {
    lines.push("BEGIN:VALARM", "ACTION:DISPLAY", `DESCRIPTION:${text(ev.title)}`, `TRIGGER:-PT${m}M`, "END:VALARM");
  }
  lines.push("END:VEVENT", "END:VCALENDAR");
  return lines.map(fold).join("\r\n") + "\r\n";
}
