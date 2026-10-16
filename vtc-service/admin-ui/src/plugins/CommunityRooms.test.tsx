import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  COMMUNITY_ROOMS_CREATE_TASK,
  COMMUNITY_ROOMS_GET_TASK,
  COMMUNITY_ROOMS_LIST_TASK,
  COMMUNITY_ROOMS_MEMBERS_ADD_TASK,
  COMMUNITY_ROOMS_MEMBERS_LIST_TASK,
  COMMUNITY_ROOMS_MEMBERS_REMOVE_TASK,
  refusalFix,
  removalOutcome,
  removalPreview,
  validUntilIn,
} from "@/lib/community-rooms-api";
import { GestureDeclinedError } from "@/lib/signed-act";
import { DataRooms } from "@/plugins/dataRooms";
import {
  NAME_BOOK_ROUTES,
  mockFetch,
  renderWithProviders,
  sentPayloads,
  taskRoute,
  whoamiWith,
} from "@/test/render";

// Reads and writes are signed documents; the stand-in sends them unsigned so
// the tables below answer them. Every change goes through
// `postSignedWithStepUp` — the operation-bound gesture the VTC asks for — and
// the spy records that it did.
const stepUp = vi.hoisted(() => ({ calls: [] as string[] }));
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));
vi.mock("@/lib/signed-act", async (original) => {
  const { unsignedTask } = await import("@/test/signed-read");
  return {
    ...(await original<typeof import("@/lib/signed-act")>()),
    postSignedWithStepUp: (type: string, payload: unknown) => {
      stepUp.calls.push(type);
      return unsignedTask(type, payload);
    },
  };
});

const T = "https://trusttasks.org/spec";
const ROOMS_LIST = `${T}/vtc/rooms/list/0.1`;
const ROOM = "did:webvh:QmScid:vtc.example.com:room-dids:abc";
const MEMBER = "did:webvh:QmAlice:alice.example.com";
const MANAGER = whoamiWith(["vtc.rooms.manage"]);

const hosted = (visibility = "attributed") => ({
  roomId: ROOM,
  ownerDid: "did:webvh:QmVtc:vtc.example.com",
  visibility,
  retentionPolicy: "chained",
  retentionDays: 90,
  epoch: 1,
  lifecycle: "live",
  createdAt: 1_760_000_000,
  updatedAt: 1_760_000_000,
});

const communityRoom = (visibility = "attributed") => ({
  room: hosted(visibility),
  label: "Board pack",
  admitted: 1,
  offered: 1,
  ownerAuthorityValidUntil: "2099-01-01T00:00:00Z",
  createdBy: "did:key:z6MkViewer",
});

const offered = {
  member: MEMBER,
  actions: ["read", "write"],
  validUntil: "2027-01-14T00:00:00Z",
  state: "offered",
  offeredAt: "2026-10-16T10:00:00Z",
};
const admitted = {
  ...offered,
  member: "did:webvh:QmBob:bob.example.com",
  state: "admitted",
  admittedAt: "2026-10-16T11:00:00Z",
};

function Where() {
  const { pathname, search } = useLocation();
  return <output data-testid="where">{`${pathname}${search}`}</output>;
}

const mount = (route: string, whoami = MANAGER) =>
  renderWithProviders(
    <>
      <DataRooms />
      <Where />
    </>,
    { route, path: "/rooms/*", whoami },
  );

beforeEach(() => {
  stepUp.calls.length = 0;
});

describe("Community rooms tab", () => {
  it("opens on Community rooms for a viewer who only runs the community's rooms", async () => {
    const requests = mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(COMMUNITY_ROOMS_LIST_TASK, { items: [communityRoom()] }),
    ]);
    mount("/rooms");
    await waitFor(() => expect(screen.getByTestId("where").textContent).toBe("/rooms/community"));
    const link = await screen.findByRole("link", { name: "Board pack" });
    expect(link.getAttribute("href")).toBe(`/rooms/community/${encodeURIComponent(ROOM)}`);
    expect(screen.getByText("1 admitted")).toBeTruthy();
    // Never the host's reads, which this viewer cannot make.
    expect(sentPayloads(requests, ROOMS_LIST)).toEqual([]);
    expect(sentPayloads(requests, COMMUNITY_ROOMS_LIST_TASK)).toEqual([{ limit: 100 }]);
  });

  it("is not shown to a viewer who only hosts rooms", async () => {
    mockFetch([...NAME_BOOK_ROUTES, taskRoute(ROOMS_LIST, { items: [] })]);
    mount("/rooms", whoamiWith(["vtc.rooms.admin"]));
    const nav = await screen.findByRole("navigation", { name: "Data rooms sections" });
    expect([...nav.querySelectorAll("a")].map((a) => a.textContent)).toEqual([
      "Rooms",
      "Usage",
      "Storage",
    ]);
  });

  it("shows what to add when community rooms are off", async () => {
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(COMMUNITY_ROOMS_LIST_TASK, {
        items: [],
        ext: {
          "org.openvtc": {
            communityRooms: { enabled: false, configure: '[rooms.community]\ncontext = "vtc"' },
          },
        },
      }),
    ]);
    mount("/rooms/community");
    expect(await screen.findByText("Community rooms are off")).toBeTruthy();
    expect(screen.getByText(/context = "vtc"/)).toBeTruthy();
  });

  it("creates a room at the attributed tier by default, through the bound step-up", async () => {
    const requests = mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(COMMUNITY_ROOMS_LIST_TASK, { items: [] }),
      taskRoute(COMMUNITY_ROOMS_CREATE_TASK, { room: communityRoom() }),
    ]);
    mount("/rooms/community?create=1");
    fireEvent.change(await screen.findByLabelText(/^Label/), { target: { value: "Board pack" } });
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "the board's papers" } });
    expect((screen.getByRole("radio", { name: /private/ }) as HTMLInputElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Create room" }));
    expect(await screen.findByText("Created")).toBeTruthy();
    expect(sentPayloads(requests, COMMUNITY_ROOMS_CREATE_TASK)).toEqual([
      { label: "Board pack", visibility: "attributed", reason: "the board's papers" },
    ]);
    expect(stepUp.calls).toEqual([COMMUNITY_ROOMS_CREATE_TASK]);
  });

  it("says what to configure when the community has no key holder", async () => {
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(COMMUNITY_ROOMS_LIST_TASK, { items: [] }),
      taskRoute(
        COMMUNITY_ROOMS_CREATE_TASK,
        {
          code: "vtc/rooms/community/create:noKeyHolder",
          message: "this community owns no rooms until its operator turns them on",
        },
        409,
      ),
    ]);
    mount("/rooms/community?create=1");
    fireEvent.change(await screen.findByLabelText(/^Label/), { target: { value: "Board" } });
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "r" } });
    fireEvent.click(screen.getByRole("button", { name: "Create room" }));
    const card = await screen.findByRole("alert");
    expect(within(card).getByText(/operator turns them on/)).toBeTruthy();
    expect(within(card).getByText(/key-mint,credential-write,vault-write/)).toBeTruthy();
  });
});

describe("a community room's page", () => {
  const routes = (visibility = "attributed") => [
    ...NAME_BOOK_ROUTES,
    taskRoute(COMMUNITY_ROOMS_GET_TASK, { room: communityRoom(visibility) }),
    taskRoute(COMMUNITY_ROOMS_MEMBERS_LIST_TASK, { items: [offered, admitted] }),
    taskRoute(COMMUNITY_ROOMS_MEMBERS_ADD_TASK, (p) => ({
      member: { ...offered, ...(p as object), state: "offered", offeredAt: offered.offeredAt },
    })),
    taskRoute(COMMUNITY_ROOMS_MEMBERS_REMOVE_TASK, {
      member: { ...admitted, state: "removed", removedAt: "2026-10-16T12:00:00Z" },
      epoch: 3,
    }),
  ];
  const page = `/rooms/community/${encodeURIComponent(ROOM)}`;

  it("lists who was offered and who is admitted", async () => {
    const requests = mockFetch(routes());
    mount(page);
    expect(await screen.findByRole("heading", { name: "Board pack" })).toBeTruthy();
    expect(sentPayloads(requests, COMMUNITY_ROOMS_GET_TASK)).toEqual([{ roomId: ROOM }]);
    expect(await screen.findByText("offered", { selector: ".chip" })).toBeTruthy();
    expect(screen.getByText("admitted", { selector: ".chip" })).toBeTruthy();
    expect(screen.getByRole("button", { name: /Withdraw/ })).toBeTruthy();
    expect(screen.getByRole("button", { name: /Remove/ })).toBeTruthy();
  });

  it("offers a member a place with actions, an expiry and a reason", async () => {
    const requests = mockFetch(routes());
    mount(page);
    fireEvent.click(await screen.findByRole("button", { name: /Add a member/ }));
    fireEvent.change(screen.getByRole("textbox", { name: "Member" }), { target: { value: MEMBER } });
    fireEvent.click(screen.getByRole("checkbox", { name: "curate" }));
    fireEvent.change(screen.getByLabelText(/^Valid for/), { target: { value: "30" } });
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "joins the board" } });
    fireEvent.click(screen.getByRole("button", { name: "Offer a place" }));
    await waitFor(() => expect(sentPayloads(requests, COMMUNITY_ROOMS_MEMBERS_ADD_TASK)).toHaveLength(1));
    const sent = sentPayloads(requests, COMMUNITY_ROOMS_MEMBERS_ADD_TASK)[0] as Record<string, unknown>;
    expect(sent).toMatchObject({
      roomId: ROOM,
      member: MEMBER,
      actions: ["read", "write", "curate"],
      reason: "joins the board",
    });
    const days = (Date.parse(sent.validUntil as string) - Date.now()) / 86_400_000;
    expect(Math.round(days)).toBe(30);
    expect(stepUp.calls).toEqual([COMMUNITY_ROOMS_MEMBERS_ADD_TASK]);
  });

  it("says what removal does before it is signed, then what it did", async () => {
    const requests = mockFetch(routes());
    mount(page);
    fireEvent.click(await screen.findByRole("button", { name: /Remove/ }));
    const dialog = await screen.findByRole("dialog");
    // The tier's consequences and the member's validUntil, before anything is sent.
    expect(within(dialog).getByText(/sealed to everyone else/)).toBeTruthy();
    expect(within(dialog).getByText(/2027-01-14T00:00:00Z/)).toBeTruthy();
    expect(sentPayloads(requests, COMMUNITY_ROOMS_MEMBERS_REMOVE_TASK)).toEqual([]);
    fireEvent.change(within(dialog).getByRole("textbox"), { target: { value: "left the board" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));
    expect(await screen.findByText(/Epoch 3 is the first sealed without them/)).toBeTruthy();
    expect(sentPayloads(requests, COMMUNITY_ROOMS_MEMBERS_REMOVE_TASK)).toEqual([
      { roomId: ROOM, member: admitted.member, reason: "left the board" },
    ]);
  });

  it("names a room the community does not own", async () => {
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(
        COMMUNITY_ROOMS_GET_TASK,
        { code: "vtc/rooms/community/get:notFound", message: "this community owns no room" },
        404,
      ),
    ]);
    mount(page);
    expect(await screen.findByText(/A room it only hosts is on the Rooms tab/)).toBeTruthy();
  });
});

describe("community-rooms-api", () => {
  it("says what removal does on each tier", () => {
    const m = { ...admitted, actions: ["read" as const], state: "admitted" as const };
    expect(removalPreview("open", m)).toMatch(/withdraws nothing cryptographically/);
    expect(removalPreview("attributed", m)).toMatch(/sealed to everyone else/);
    expect(removalPreview("attributed", { ...m, state: "offered" })).toMatch(/offer is withdrawn/);
  });

  it("reports a removal from the answer's structured members", () => {
    const member = { ...admitted, actions: ["read" as const], state: "removed" as const };
    expect(removalOutcome({ member, epoch: 4 })).toMatch(/Epoch 4/);
    expect(removalOutcome({ member })).toMatch(/Nothing was withdrawn cryptographically/);
  });

  it("suggests a fix for the refusals an administrator can act on", () => {
    expect(refusalFix({ code: "permissionDenied" })).toMatch(/vtc\.rooms\.manage/);
    expect(refusalFix({ code: "vtc/rooms/community/members/add:notAMember" })).toMatch(/active member/);
    expect(
      refusalFix({
        code: "vtc/rooms/community/create:keyHolderUnavailable",
        details: { roomId: "did:webvh:minted" },
      }),
    ).toMatch(/did:webvh:minted/);
    expect(refusalFix({ code: "vtc/rooms/community/members/remove:keyHolderUnavailable" })).toMatch(
      /Remove them again/,
    );
    expect(refusalFix(new GestureDeclinedError())).toBeNull();
    expect(refusalFix({ code: "somethingElse" })).toBeNull();
  });

  it("writes validUntil as a whole-second RFC 3339 instant", () => {
    expect(validUntilIn(1, new Date("2026-10-16T10:00:00.123Z"))).toBe("2026-10-17T10:00:00Z");
  });
});
