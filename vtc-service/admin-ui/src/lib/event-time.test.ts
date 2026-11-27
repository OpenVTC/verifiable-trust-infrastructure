// An event's time, read as the community reads it (VTI-EVT-005), and its .ics file.

import { describe, expect, it } from "vitest";

import { durationMinutes, endOf, formatWhen, icsFor, instantOf, zoneNote } from "./event-time";

const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");

describe("an event's time", () => {
  it("reads a local start in its zone, winter and summer", () => {
    expect(iso(instantOf("2026-11-30T18:30:00", "Europe/London"))).toBe("2026-11-30T18:30:00Z");
    expect(iso(instantOf("2026-07-01T18:30:00", "Europe/London"))).toBe("2026-07-01T17:30:00Z");
    expect(iso(instantOf("2026-11-30T09:00:00", "Asia/Singapore"))).toBe("2026-11-30T01:00:00Z");
  });

  it("moves a skipped time forward and takes the first of a repeated one", () => {
    // 01:30 on 29 March 2026 does not exist in London (02:00 BST is the first that does); 01:30 on
    // 25 October happens twice. The same as the community (`community_events::resolve_local`).
    expect(iso(instantOf("2026-03-29T01:30:00", "Europe/London"))).toBe("2026-03-29T01:00:00Z");
    expect(iso(instantOf("2026-10-25T01:30:00", "Europe/London"))).toBe("2026-10-25T00:30:00Z");
  });

  it("reads JSCalendar durations", () => {
    expect(durationMinutes("PT1H30M")).toBe(90);
    expect(durationMinutes("P1D")).toBe(1440);
    expect(durationMinutes("P1W")).toBe(10080);
    expect(iso(endOf({ start: "2026-11-30T18:30:00", timeZone: "Etc/UTC", duration: "PT1H30M" }))).toBe(
      "2026-11-30T20:00:00Z",
    );
  });

  it("shows the event's own zone beside the viewer's when they differ", () => {
    const when = { start: "2026-11-30T18:30:00", timeZone: "Europe/London", duration: "PT1H" };
    expect(zoneNote(when, "Europe/London")).toBeNull();
    expect(zoneNote(when, "Asia/Singapore")).toContain("Europe/London");
    expect(formatWhen(when, "Asia/Singapore")).toMatch(/02:30/);
  });
});

describe("the .ics file", () => {
  const ev = {
    eventId: "evt_W5k2N8xRb3Qz7TpLAAAAAA",
    title: "Intro to Soldering, part 1; bring tools",
    description: "Irons provided.\nClosed shoes.",
    when: { start: "2026-11-30T18:30:00", timeZone: "Europe/London", duration: "PT1H30M" },
    location: "Central London",
    status: "published" as const,
    sequence: 2,
    reminders: [1440, 60],
  };

  it("writes one event at its UTC instant, escaped, with the reminders as alarms", () => {
    const ics = icsFor(ev, "vtc.example.com", new Date("2026-11-27T10:00:00Z"));
    expect(ics).toContain("UID:evt_W5k2N8xRb3Qz7TpLAAAAAA@vtc.example.com");
    expect(ics).toContain("DTSTART:20261130T183000Z");
    expect(ics).toContain("DURATION:PT1H30M");
    expect(ics).toContain("SUMMARY:Intro to Soldering\\, part 1\\; bring tools");
    expect(ics).toContain("DESCRIPTION:Irons provided.\\nClosed shoes.");
    expect(ics).toContain("SEQUENCE:2");
    expect(ics).toContain("STATUS:CONFIRMED");
    expect(ics.match(/BEGIN:VALARM/g)).toHaveLength(2);
    expect(ics).toContain("TRIGGER:-PT60M");
    expect(ics.endsWith("END:VCALENDAR\r\n")).toBe(true);
    // Lines are folded at 75 octets.
    for (const line of ics.split("\r\n")) expect(new TextEncoder().encode(line).length).toBeLessThanOrEqual(75);
  });

  it("marks a cancelled event cancelled and writes an all-day one as dates", () => {
    const allDay = icsFor(
      { ...ev, status: "cancelled", when: { start: "2026-12-05T00:00:00", timeZone: "Europe/London", duration: "P2D", showWithoutTime: true } },
      "vtc.example.com",
    );
    expect(allDay).toContain("STATUS:CANCELLED");
    expect(allDay).toContain("DTSTART;VALUE=DATE:20261205");
    expect(allDay).toContain("DURATION:P2D");
  });
});
