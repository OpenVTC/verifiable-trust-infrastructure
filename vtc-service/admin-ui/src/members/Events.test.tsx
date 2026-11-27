// The portal's Events pages: what's on, one event, registering and withdrawing, where it happens
// once going (and not before its time), the roster on a visible roster only, and the home tile.
// Every read and write goes through this browser's portal key (`send`, mocked per task).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ConfirmDialogProvider } from "@/components/ConfirmDialog";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const send = vi.fn();
vi.mock("./directory-api", async (orig) => ({
  ...(await orig<typeof import("./directory-api")>()),
  send: (...a: unknown[]) => send(...a),
}));

import { DirectoryError } from "./directory-api";
import { EventPage, EventsPage } from "./Events";
import {
  EVENTS_ACCESS_TASK,
  EVENTS_CALENDARS_TASK,
  EVENTS_LIST_TASK,
  EVENTS_MINE_TASK,
  EVENTS_REGISTER_TASK,
  EVENTS_ROSTER_TASK,
  EVENTS_SHOW_TASK,
  EVENTS_WITHDRAW_TASK,
  eventHref,
} from "./events-api";
import { eventsAttention, eventsStatus } from "./home-status";

const EVENT_ID = "evt_W5k2N8xRb3Qz7TpLAAAAAA";
const CAL = "cal_C0mmunityCalendarAAAA";
const ENTRY = "dir_Q7m2K9xVb4Tz8LpRAAAAAA";

function event(extra: object = {}) {
  return {
    eventId: EVENT_ID,
    calendarId: CAL,
    kind: "event",
    status: "published",
    title: "Intro to Soldering",
    description: "Irons provided.",
    when: { start: "2099-11-30T18:30:00", timeZone: "Europe/London", duration: "PT1H30M" },
    placeSummary: "Central London",
    audience: { scope: "members" },
    registration: { mode: "open", capacity: 12, plusOnes: 1 },
    roster: "hidden",
    listed: true,
    sequence: 0,
    createdAt: "2099-11-01T09:00:00Z",
    updatedAt: "2099-11-01T09:00:00Z",
    ...extra,
  };
}

function registration(extra: object = {}) {
  return {
    registrationId: "reg_R3g1stration00000AAAA",
    eventId: EVENT_ID,
    entryId: ENTRY,
    status: "going",
    guests: 0,
    roster: "hidden",
    eventSequence: 0,
    createdAt: "2099-11-02T09:00:00Z",
    updatedAt: "2099-11-02T09:00:00Z",
    ...extra,
  };
}

function answer(table: Record<string, unknown | ((payload: unknown) => unknown)>) {
  send.mockImplementation(async (type: string, payload: unknown) => {
    if (!(type in table)) throw new Error(`unexpected ${type}`);
    const a = table[type];
    return typeof a === "function" ? (a as (p: unknown) => unknown)(payload) : a;
  });
}

function sent(type: string): unknown[] {
  return send.mock.calls.filter((c) => c[0] === type).map((c) => c[1]);
}

function renderPage(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ConfirmDialogProvider look="portal">{ui}</ConfirmDialogProvider>
    </QueryClientProvider>,
  );
}

afterEach(() => send.mockReset());

describe("the portal's events page", () => {
  it("lists what's on with the roster setting and the member's own status", async () => {
    answer({
      [EVENTS_CALENDARS_TASK]: { items: [] },
      [EVENTS_LIST_TASK]: { items: [{ event: event({ showCount: true, goingCount: { fewerThan: 5 } }), myStatus: "going" }] },
      [EVENTS_MINE_TASK]: { items: [] },
    });
    renderPage(<EventsPage />);
    expect(await screen.findByText("Intro to Soldering")).toBeTruthy();
    expect(screen.getByText(/Hidden roster · Fewer than 5 going/)).toBeTruthy();
    expect(screen.getByText("You're going")).toBeTruthy();
    expect(screen.getByRole("link", { name: /Intro to Soldering/ }).getAttribute("href")).toBe(eventHref(EVENT_ID));
  });
});

describe("one event", () => {
  it("registers going with a guest and the code of conduct acknowledged", async () => {
    const SHA = "ab".repeat(32);
    answer({
      [EVENTS_SHOW_TASK]: {
        event: event({ registration: { mode: "open", plusOnes: 1, codeOfConduct: { url: "https://example.com/coc", sha256: SHA } } }),
      },
      [EVENTS_REGISTER_TASK]: { registration: registration({ guests: 1 }), event: { eventId: EVENT_ID } },
    });
    renderPage(<EventPage eventId={EVENT_ID} />);
    expect(await screen.findByRole("heading", { name: "Register" })).toBeTruthy();
    // The roster setting is said before registering (VTI-EVT-051, 052).
    expect(screen.getByText("Hidden roster")).toBeTruthy();
    const register = screen.getByRole("button", { name: "Register" });
    expect((register as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Guests"), { target: { value: "1" } });
    fireEvent.click(screen.getByLabelText(/I've read and agree/));
    fireEvent.click(register);
    await waitFor(() =>
      expect(sent(EVENTS_REGISTER_TASK)).toEqual([
        { eventId: EVENT_ID, status: "going", guests: 1, codeOfConductAcknowledged: SHA },
      ]),
    );
  });

  it("offers no maybe when the hosts confirm each registration", async () => {
    answer({ [EVENTS_SHOW_TASK]: { event: event({ registration: { mode: "approval" } }) } });
    renderPage(<EventPage eventId={EVENT_ID} />);
    expect(await screen.findByText("The hosts confirm each registration.")).toBeTruthy();
    expect(screen.queryByLabelText(/Maybe/)).toBeNull();
  });

  it("shows where it happens once going, and withdraws after confirming", async () => {
    answer({
      [EVENTS_SHOW_TASK]: { event: event(), myRegistration: registration() },
      [EVENTS_ACCESS_TASK]: { eventId: EVENT_ID, access: { places: [{ name: "The Makerspace", address: "Unit 4, Mill Lane" }] }, sequence: 0 },
      [EVENTS_WITHDRAW_TASK]: { registration: registration({ status: "withdrawn" }), event: { eventId: EVENT_ID }, changed: true },
    });
    renderPage(<EventPage eventId={EVENT_ID} />);
    expect(await screen.findByText("The Makerspace")).toBeTruthy();
    expect(screen.getByText("Unit 4, Mill Lane")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Withdraw/ }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }));
    await waitFor(() => expect(sent(EVENTS_WITHDRAW_TASK)).toEqual([{ eventId: EVENT_ID }]));
  });

  it("says when the place is released, without showing it early", async () => {
    answer({
      [EVENTS_SHOW_TASK]: { event: event(), myRegistration: registration() },
      [EVENTS_ACCESS_TASK]: () => {
        throw new DirectoryError("notYet", "Not yet.", { revealAt: "2099-11-30T12:00:00Z" });
      },
    });
    renderPage(<EventPage eventId={EVENT_ID} />);
    expect(await screen.findByText("Where it happens is shared closer to the time.")).toBeTruthy();
    expect(screen.queryByText("The Makerspace")).toBeNull();
  });

  it("asks for the roster only on a visible roster", async () => {
    answer({
      [EVENTS_SHOW_TASK]: { event: event({ roster: "visible" }), myRegistration: registration({ roster: "visible" }) },
      [EVENTS_ACCESS_TASK]: { eventId: EVENT_ID, access: {}, sequence: 0 },
      [EVENTS_ROSTER_TASK]: { eventId: EVENT_ID, view: "roster", roster: [{ entryId: ENTRY, status: "going", guests: 1 }] },
    });
    renderPage(<EventPage eventId={EVENT_ID} />);
    expect(await screen.findByText("Who's going")).toBeTruthy();
    expect(await screen.findByText(ENTRY)).toBeTruthy();
    expect(sent(EVENTS_ROSTER_TASK)).toHaveLength(1);
  });

  it("never asks for the roster on a hidden one", async () => {
    answer({
      [EVENTS_SHOW_TASK]: { event: event(), myRegistration: registration() },
      [EVENTS_ACCESS_TASK]: { eventId: EVENT_ID, access: {}, sequence: 0 },
    });
    renderPage(<EventPage eventId={EVENT_ID} />);
    expect(await screen.findByText("You're going")).toBeTruthy();
    expect(sent(EVENTS_ROSTER_TASK)).toHaveLength(0);
    expect(screen.queryByText("Who's going")).toBeNull();
  });
});

describe("the home tile", () => {
  const now = Date.parse("2099-11-25T09:00:00Z");
  const mine = (status: string, title: string, start = "2099-11-30T18:30:00") => ({
    registration: registration({ status }),
    event: { eventId: EVENT_ID, title, when: { start, timeZone: "Europe/London", duration: "PT1H" }, status: "published", sequence: 0 },
  });
  const read = <T,>(data: T) => ({ data, isPending: false, isError: false });

  it("counts upcoming events and what waits", () => {
    const q = read([mine("going", "Soldering"), mine("pending", "AGM"), mine("withdrawn", "Social")]);
    expect(eventsStatus(q as never, now)).toEqual({ text: "Going to 1 event · 1 waiting", tone: "ok" });
    const items = eventsAttention(q as never, eventHref, now);
    expect(items.map((a) => a.text)).toEqual(["AGM: waiting for the hosts to confirm", "Coming up: Soldering"]);
  });

  it("says nothing is coming up", () => {
    expect(eventsStatus(read([]) as never, now)).toEqual({ text: "Nothing coming up", tone: "muted" });
  });
});
