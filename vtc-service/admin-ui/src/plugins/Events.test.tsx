// The console's Events page: the events a calendar's runner or host sees, a new event saved as
// a draft, the roster setting offered before publishing and fixed after (VTI-EVT-051), and the
// hosts' view of registrations with a pending one approved.

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  ANNOUNCEMENTS_LIST,
  ANNOUNCEMENTS_SEND,
  CALENDARS_LIST,
  CREATE,
  INVITATIONS_LIST,
  INVITATIONS_REVOKE,
  LINKS_CREATE,
  HOSTS_LIST,
  LIST,
  REGISTRATIONS_DECIDE,
  REGISTRATIONS_LIST,
  SHOW,
} from "@/lib/events";
import { GROUPS_LIST_TASK } from "@/lib/groups";
import { ROLES_LIST_TASK } from "@/lib/roles";
import { Events } from "@/plugins/events";
import { NAME_BOOK_ROUTES, mockFetch, renderWithProviders, sentPayloads, taskRoute, whoamiWith } from "@/test/render";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
  vtcDid: async () => "did:webvh:QmCommunity:vtc.example.com",
}));

const EVENT_ID = "evt_W5k2N8xRb3Qz7TpLAAAAAA";
const CAL = "cal_C0mmunityCalendarAAAA";
const ENTRY = "dir_Q7m2K9xVb4Tz8LpRAAAAAA";
const BADGES_LIST = "https://trusttasks.org/spec/vtc/badges/list/0.1";
const ENTRIES = "https://trusttasks.org/spec/vtc/directory/entries/list/0.2";

function event(extra: object = {}) {
  return {
    eventId: EVENT_ID,
    calendarId: CAL,
    kind: "event",
    status: "draft",
    title: "Intro to Soldering",
    when: { start: "2099-11-30T18:30:00", timeZone: "Europe/London", duration: "PT1H30M" },
    audience: { scope: "members" },
    registration: { mode: "approval", capacity: 12 },
    roster: "hidden",
    listed: true,
    sequence: 0,
    goingCount: { exact: 3 },
    createdAt: "2099-11-01T09:00:00Z",
    updatedAt: "2099-11-01T09:00:00Z",
    ...extra,
  };
}

const CALENDAR = { calendarId: CAL, name: "Community", community: true, state: "active", createdAt: "2099-01-01T00:00:00Z" };

const ROUTES = [
  ...NAME_BOOK_ROUTES,
  taskRoute(CALENDARS_LIST, { items: [CALENDAR] }),
  taskRoute(GROUPS_LIST_TASK, { items: [] }),
  taskRoute(BADGES_LIST, { items: [] }),
  taskRoute(ROLES_LIST_TASK, { roles: [] }),
  taskRoute(ENTRIES, { items: [] }),
];

describe("the Events page", () => {
  it("lists the events with their calendar, going count and status", async () => {
    mockFetch([...ROUTES, taskRoute(LIST, { items: [{ event: event() }] })]);
    renderWithProviders(<Events />, { route: "/events", path: "/events/*", whoami: whoamiWith(["vtc.events.manage"]) });
    expect(await screen.findByText("Intro to Soldering")).toBeTruthy();
    expect(screen.getByText("3 / 12")).toBeTruthy();
    expect(screen.getByText("Draft")).toBeTruthy();
    expect(screen.getByRole("link", { name: /New event/ })).toBeTruthy();
  });

  it("offers no new event to a host of one event only", async () => {
    mockFetch([...ROUTES, taskRoute(LIST, { items: [] })]);
    renderWithProviders(<Events />, {
      route: "/events",
      path: "/events/*",
      whoami: whoamiWith([`vtc.events.manage:event:${EVENT_ID}`]),
    });
    expect(await screen.findByText("No events yet")).toBeTruthy();
    // A host by appointment runs that event; making one takes a calendar's authority
    // (VTI-EVT-013), unqualified or for a group.
    expect(screen.queryByRole("link", { name: /New event/ })).toBeNull();
  });

  it("saves a new event as a draft in the community's calendar", async () => {
    const requests = mockFetch([...ROUTES, taskRoute(CREATE, { event: event() }), taskRoute(SHOW, { event: event() }), taskRoute(HOSTS_LIST, { eventId: EVENT_ID, hosts: [] })]);
    renderWithProviders(<Events />, { route: "/events/new", path: "/events/*", whoami: whoamiWith(["vtc.events.manage"]) });
    await screen.findByRole("option", { name: "Community" });
    fireEvent.change(screen.getByLabelText("Title"), { target: { value: "Intro to Soldering" } });
    fireEvent.change(screen.getByLabelText("Capacity"), { target: { value: "12" } });
    fireEvent.click(screen.getByRole("button", { name: "Save draft" }));
    await waitFor(() => expect(sentPayloads(requests, CREATE)).toHaveLength(1));
    const sent = sentPayloads(requests, CREATE)[0] as Record<string, unknown>;
    expect(sent).toMatchObject({
      calendarId: CAL,
      kind: "event",
      title: "Intro to Soldering",
      roster: "hidden",
      registration: { mode: "open", capacity: 12 },
      audience: { scope: "members" },
    });
    expect((sent.when as { duration: string }).duration).toBe("PT1H30M");
  });

  it("offers the roster setting on a draft, and fixes it once published", async () => {
    mockFetch([...ROUTES, taskRoute(SHOW, { event: event() })]);
    const draft = renderWithProviders(<Events />, {
      route: `/events/${EVENT_ID}`,
      path: "/events/*",
      whoami: whoamiWith(["vtc.events.manage"]),
    });
    const roster = (await screen.findByLabelText("Roster")) as HTMLSelectElement;
    expect(roster.disabled).toBe(false);
    expect(screen.getByText(/locks when you publish/)).toBeTruthy();
    draft.unmount();

    mockFetch([...ROUTES, taskRoute(SHOW, { event: event({ status: "published", publishedAt: "2099-11-02T09:00:00Z" }) })]);
    renderWithProviders(<Events />, {
      route: `/events/${EVENT_ID}`,
      path: "/events/*",
      whoami: whoamiWith(["vtc.events.manage"]),
    });
    const fixed = (await screen.findByLabelText("Roster")) as HTMLSelectElement;
    expect(fixed.disabled).toBe(true);
    expect(screen.getByText(/was fixed when this event was published/)).toBeTruthy();
  });

  it("approves a pending registration from the hosts' view", async () => {
    const pending = {
      registrationId: "reg_R3g1stration00000AAAA",
      eventId: EVENT_ID,
      entryId: ENTRY,
      status: "pending",
      guests: 1,
      answers: { diet: "vegetarian" },
      roster: "hidden",
      eventSequence: 0,
      createdAt: "2099-11-02T09:00:00Z",
      updatedAt: "2099-11-02T09:00:00Z",
    };
    const requests = mockFetch([
      ...ROUTES,
      taskRoute(SHOW, { event: event({ status: "published" }) }),
      taskRoute(REGISTRATIONS_LIST, { eventId: EVENT_ID, view: "host", registrations: [pending] }),
      taskRoute(REGISTRATIONS_DECIDE, { decision: "approve", registration: { ...pending, status: "going" }, event: {} }),
    ]);
    renderWithProviders(<Events />, {
      route: `/events/${EVENT_ID}`,
      path: "/events/*",
      whoami: whoamiWith(["vtc.events.manage"]),
    });
    fireEvent.click(await screen.findByRole("tab", { name: "Registrations" }));
    expect(await screen.findByText("diet: vegetarian")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    await waitFor(() =>
      expect(sentPayloads(requests, REGISTRATIONS_DECIDE)).toEqual([
        { registrationId: "reg_R3g1stration00000AAAA", decision: "approve" },
      ]),
    );
  });
});

describe("the Invitations tab (VTI-EVT-103, 107, 120)", () => {
  const CODE = "k".repeat(43);
  it("lists invitations, shows a new link's code once, and posts an announcement", async () => {
    const requests = mockFetch([
      ...ROUTES,
      taskRoute(SHOW, { event: event({ status: "published", invite: "notify" }) }),
      taskRoute(INVITATIONS_LIST, {
        items: [
          {
            invitation: {
              invitationId: "inv_1nvitation00000000AAAA",
              eventId: EVENT_ID,
              entryId: ENTRY,
              invitedBy: "audience",
              replyExpected: false,
              answer: "going",
              createdAt: "2099-11-02T09:00:00Z",
            },
          },
        ],
      }),
      taskRoute(ANNOUNCEMENTS_LIST, { items: [] }),
      taskRoute(LINKS_CREATE, {
        link: { linkId: "lnk_L1nk00000000000000AAAA", eventId: EVENT_ID, label: "Flyer", maxRedemptions: 25, redemptions: 0, expiresAt: "2099-12-01T00:00:00Z", createdAt: "2099-11-02T09:00:00Z" },
        code: CODE,
      }),
      taskRoute(ANNOUNCEMENTS_SEND, {
        announcement: { announcementId: "ann_1", eventId: EVENT_ID, text: "Bring glasses.", createdAt: "2099-11-03T09:00:00Z" },
      }),
    ]);
    renderWithProviders(<Events />, {
      route: `/events/${EVENT_ID}`,
      path: "/events/*",
      whoami: whoamiWith(["vtc.events.manage"]),
    });
    fireEvent.click(await screen.findByRole("tab", { name: "Invitations" }));
    expect(await screen.findByText("Going")).toBeTruthy();
    expect(screen.getByText("The community")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Link label"), { target: { value: "Flyer" } });
    fireEvent.click(screen.getByRole("button", { name: /Make a link/ }));
    expect(await screen.findByText(new RegExp(`#/events/join/${CODE}`))).toBeTruthy();
    const made = sentPayloads(requests, LINKS_CREATE)[0] as Record<string, unknown>;
    expect(made).toMatchObject({ eventId: EVENT_ID, maxRedemptions: 25, label: "Flyer" });
    expect(String(made.expiresAt)).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);

    fireEvent.change(screen.getByLabelText("Announcement"), { target: { value: "Bring glasses." } });
    fireEvent.click(screen.getByRole("button", { name: "Post announcement" }));
    await waitFor(() =>
      expect(sentPayloads(requests, ANNOUNCEMENTS_SEND)).toEqual([{ eventId: EVENT_ID, text: "Bring glasses." }]),
    );
  });

  it("revokes an invitation that still stands, and offers no revoke on one already revoked", async () => {
    const inv = (id: string, revoked: boolean) => ({
      invitation: {
        invitationId: id,
        eventId: EVENT_ID,
        entryId: ENTRY,
        invitedBy: "host",
        replyExpected: false,
        answer: "none",
        createdAt: "2099-11-02T09:00:00Z",
        ...(revoked ? { revoked: true } : {}),
      },
    });
    const requests = mockFetch([
      ...ROUTES,
      taskRoute(SHOW, { event: event({ status: "published", invite: "notify" }) }),
      taskRoute(INVITATIONS_LIST, { items: [inv("inv_Standing000000000AAAA", false), inv("inv_Revoked0000000000AAAA", true)] }),
      taskRoute(ANNOUNCEMENTS_LIST, { items: [] }),
      taskRoute(INVITATIONS_REVOKE, { invitation: inv("inv_Standing000000000AAAA", true).invitation }),
    ]);
    renderWithProviders(<Events />, {
      route: `/events/${EVENT_ID}`,
      path: "/events/*",
      whoami: whoamiWith(["vtc.events.manage"]),
    });
    fireEvent.click(await screen.findByRole("tab", { name: "Invitations" }));
    const table = await screen.findByRole("table", { name: "Invitations" });
    const revokes = await waitFor(() => {
      const found = table.querySelectorAll("button");
      expect(found.length).toBe(1);
      return found;
    });
    fireEvent.click(revokes[0]!);
    await waitFor(() =>
      expect(sentPayloads(requests, INVITATIONS_REVOKE)).toEqual([
        { eventId: EVENT_ID, invitationId: "inv_Standing000000000AAAA" },
      ]),
    );
  });
});
