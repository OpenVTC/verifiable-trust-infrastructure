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
  COMMUNITY_ROOMS_UPDATE_TASK,
  detailsUpdate,
  parseTags,
  refusalFix,
  removalOutcome,
  removalPreview,
  validUntilIn,
  vtaFixFor,
  type VtaAccess,
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
const VTC_DID = "did:webvh:QmScid:example.com:test-vtc";

// As `vtc_service::rooms::vta_access` writes it for a VTC whose DID lives in
// `vtc-test` and whose rooms context is `vtc-test/rooms`.
const VTA_ACCESS: VtaAccess = {
  vtcDid: VTC_DID,
  vtcDidContext: "vtc-test",
  roomsContext: "vtc-test/rooms",
  roomsContextInside: true,
  contexts: ["vtc-test"],
  fixes: [
    {
      id: "noEntry",
      when: [
        { refusal: "keyHolderRefused", messageContains: ["DID not in ACL", "ACL entry expired"] },
        { refusal: "noKeyHolder" },
      ],
      summary: "The VTC's DID needs an entry at its VTA.",
      commands: [
        {
          purpose: "give the VTC's DID an entry",
          command: `pnm acl create --did ${VTC_DID} --role initiator --contexts vtc-test --capabilities key-mint,credential-write,vault-write --label "community (rooms)"`,
        },
      ],
      note: "Run these with pnm as someone with admin at the community's VTA.",
      check: "pnm acl list --context vtc-test --direction any",
    },
    {
      id: "scope",
      when: [
        {
          refusal: "keyHolderRefused",
          messageContains: ["no access to context", "persona you may act as", "persona you act as"],
        },
      ],
      summary: "The VTC's entry at its VTA does not cover the context holding the VTC's own DID (vtc-test).",
      commands: [
        {
          purpose: "scope the entry to the context holding the VTC's DID",
          command: `pnm acl update ${VTC_DID} --contexts vtc-test`,
        },
      ],
      note: "Run these with pnm as someone with admin at the community's VTA.",
      check: "pnm acl list --context vtc-test --direction any",
    },
  ],
};
const PERSONA_REFUSAL = {
  code: "vtc/rooms/community/create:keyHolderRefused",
  message: `the community's VTA refused: permissionDenied \`${VTC_DID}\` is not a persona you may act as, so it cannot be the owner's leaf in room \`did:webvh:x\``,
  details: { code: "permissionDenied", message: "is not a persona you may act as" },
};

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

  it("says when the VTC cannot renew the community's own authority", async () => {
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(COMMUNITY_ROOMS_LIST_TASK, {
        items: [communityRoom()],
        ext: {
          "org.openvtc": {
            authorityRenewal: {
              renewWithinDays: 30,
              rooms: {
                [ROOM]: {
                  state: "failing",
                  attempts: 2,
                  lastError: "the community's VTA could not be reached",
                  nextAttemptAt: "2026-10-16T12:00:00Z",
                },
              },
            },
          },
        },
      }),
    ]);
    mount("/rooms/community");
    expect(await screen.findByText("renewal failing (2×)")).toBeTruthy();
    expect(screen.getByText("the community's VTA could not be reached")).toBeTruthy();
  });

  it("shows each room's description and tags, and filters by a tag", async () => {
    const LIBRARY = "did:webvh:QmScid:vtc.example.com:room-dids:lib";
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(COMMUNITY_ROOMS_LIST_TASK, {
        items: [
          {
            ...communityRoom(),
            description: "Papers for the board's meetings.",
            tags: ["board", "finance"],
          },
          { ...communityRoom(), room: { ...hosted(), roomId: LIBRARY }, label: "Library", tags: ["library"] },
        ],
      }),
    ]);
    mount("/rooms/community");
    expect(await screen.findByText("Papers for the board's meetings.")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Library" })).toBeTruthy();
    const filter = screen.getByRole("group", { name: "Filter by tag" });
    expect([...filter.querySelectorAll("button")].map((b) => b.textContent)).toEqual([
      "All",
      "board",
      "finance",
      "library",
    ]);
    fireEvent.click(within(filter).getByRole("button", { name: "library" }));
    await waitFor(() => expect(screen.queryByRole("link", { name: "Board pack" })).toBeNull());
    expect(screen.getByRole("link", { name: "Library" })).toBeTruthy();
    expect(screen.getByTestId("where").textContent).toBe("/rooms/community?tag=library");
    fireEvent.click(within(filter).getByRole("button", { name: "All" }));
    expect(await screen.findByRole("link", { name: "Board pack" })).toBeTruthy();
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

  it("creates a room with a description and tags", async () => {
    const requests = mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(COMMUNITY_ROOMS_LIST_TASK, { items: [] }),
      taskRoute(COMMUNITY_ROOMS_CREATE_TASK, { room: communityRoom() }),
    ]);
    mount("/rooms/community?create=1");
    fireEvent.change(await screen.findByLabelText(/^Label/), { target: { value: "Board pack" } });
    fireEvent.change(screen.getByLabelText(/^Description/), {
      target: { value: "Papers for the board's meetings." },
    });
    fireEvent.change(screen.getByLabelText(/^Tags/), { target: { value: "Board" } });
    expect(await screen.findByText(/is not a tag/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Create room" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText(/^Tags/), { target: { value: "board, finance board" } });
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "the board's papers" } });
    fireEvent.click(screen.getByRole("button", { name: "Create room" }));
    expect(await screen.findByText("Created")).toBeTruthy();
    expect(sentPayloads(requests, COMMUNITY_ROOMS_CREATE_TASK)).toEqual([
      {
        label: "Board pack",
        visibility: "attributed",
        reason: "the board's papers",
        description: "Papers for the board's meetings.",
        tags: ["board", "finance"],
      },
    ]);
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

describe("a refusal the community's entry at its VTA explains", () => {
  it("shows the pnm commands that fix it, filled in and copyable", async () => {
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(COMMUNITY_ROOMS_LIST_TASK, {
        items: [],
        ext: { "org.openvtc": { communityRooms: { enabled: true, vtaAccess: VTA_ACCESS } } },
      }),
      taskRoute(COMMUNITY_ROOMS_CREATE_TASK, PERSONA_REFUSAL, 409),
    ]);
    mount("/rooms/community?create=1");
    fireEvent.change(await screen.findByLabelText(/^Label/), { target: { value: "Board" } });
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "r" } });
    fireEvent.click(screen.getByRole("button", { name: "Create room" }));
    const card = await screen.findByRole("alert");
    const command = await within(card).findByText(`pnm acl update ${VTC_DID} --contexts vtc-test`);
    expect(command.tagName).toBe("PRE");
    expect(within(card).getByText("pnm acl list --context vtc-test --direction any")).toBeTruthy();
    expect(within(card).getAllByRole("button", { name: "Copy command" })).toHaveLength(2);
    expect(within(card).getByText(/admin at the community's VTA/)).toBeTruthy();
    // Never the old hint pointing at the rooms context alone.
    expect(within(card).queryByText(/in the `\[rooms.community\]` context/)).toBeNull();
  });

  it("warns on the list when the rooms context is outside the VTC DID's", async () => {
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(COMMUNITY_ROOMS_LIST_TASK, {
        items: [],
        ext: {
          "org.openvtc": {
            communityRooms: {
              enabled: true,
              vtaAccess: {
                ...VTA_ACCESS,
                roomsContext: "rooms",
                roomsContextInside: false,
                warning: "`[rooms.community] context` (`rooms`) is not inside `vtc-test`",
              },
            },
          },
        },
      }),
    ]);
    mount("/rooms/community");
    expect(await screen.findByText("Check the community’s entry at its VTA")).toBeTruthy();
    expect(screen.getByText(`pnm acl update ${VTC_DID} --contexts vtc-test`)).toBeTruthy();
  });

  it("picks the fix by the refusal's code and the VTA's words", () => {
    expect(vtaFixFor(PERSONA_REFUSAL, VTA_ACCESS)?.id).toBe("scope");
    expect(
      vtaFixFor(
        {
          code: "vtc/rooms/community/members/add:keyHolderRefused",
          message: `the community's VTA refused: permissionDenied DID not in ACL: ${VTC_DID}`,
        },
        VTA_ACCESS,
      )?.id,
    ).toBe("noEntry");
    expect(vtaFixFor({ code: "vtc/rooms/community/create:noKeyHolder", message: "x" }, VTA_ACCESS)?.id).toBe(
      "noEntry",
    );
    expect(
      vtaFixFor({ code: "vtc/rooms/community/create:keyHolderRefused", message: "malformedRequest" }, VTA_ACCESS),
    ).toBeNull();
    expect(vtaFixFor({ code: "permissionDenied", message: "DID not in ACL" }, VTA_ACCESS)).toBeNull();
    expect(vtaFixFor(PERSONA_REFUSAL, undefined)).toBeNull();
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

  it("says the VTC renews the community's authority, and when it last did", async () => {
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(COMMUNITY_ROOMS_GET_TASK, {
        room: communityRoom(),
        ext: {
          "org.openvtc": {
            authorityRenewal: { state: "ok", renewWithinDays: 30, lastRenewedAt: "2026-10-01T00:00:00Z" },
          },
        },
      }),
      taskRoute(COMMUNITY_ROOMS_MEMBERS_LIST_TASK, { items: [] }),
    ]);
    mount(page);
    expect(await screen.findByText(/The VTC renews it at/)).toBeTruthy();
    expect(screen.getByText(/from 30 days before it lapses/)).toBeTruthy();
    expect(screen.queryByText(/renewal failing/)).toBeNull();
  });

  it("says whether the room's own name is written into the room", async () => {
    for (const [roomProfile, said] of [
      [{ state: "written", writtenAt: "2026-10-16T09:00:00Z" }, /Written into the room/],
      [
        { state: "pending", attempts: 2, lastError: "the community's VTA could not be reached" },
        /Not written into the room yet/,
      ],
      [{ state: "none" }, /Never written/],
    ] as const) {
      mockFetch([
        ...NAME_BOOK_ROUTES,
        taskRoute(COMMUNITY_ROOMS_GET_TASK, {
          room: communityRoom(),
          ext: { "org.openvtc": { roomProfile } },
        }),
        taskRoute(COMMUNITY_ROOMS_MEMBERS_LIST_TASK, { items: [] }),
      ]);
      const { unmount } = mount(page);
      expect(await screen.findByText(said)).toBeTruthy();
      if (roomProfile.state === "pending") {
        expect(screen.getByText(/could not be reached/)).toBeTruthy();
      }
      unmount();
    }
  });

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

  it("shows who is being removed because they left the community", async () => {
    // First match wins: this members answer before the shared one.
    mockFetch([
      taskRoute(COMMUNITY_ROOMS_MEMBERS_LIST_TASK, {
        items: [offered, admitted],
        ext: {
          "org.openvtc": {
            departureRemovals: [
              {
                roomId: ROOM,
                member: admitted.member,
                cause: "left",
                departedAt: "2026-10-16T12:00:00Z",
                status: "retrying",
                attempts: 2,
                nextAttemptAt: "2026-10-16T12:02:00Z",
                lastError: "the community's VTA could not be reached",
              },
            ],
          },
        },
      }),
      ...routes(),
    ]);
    mount(page);
    const notice = await screen.findByRole("status", { name: "Leaving" });
    const row = within(notice).getByRole("listitem").textContent ?? "";
    expect(row).toMatch(/left the community/);
    expect(row).toMatch(/2 attempts so far/);
    expect(row).toMatch(/could not be reached/);
    expect(screen.getByText("leaving", { selector: ".chip" })).toBeTruthy();
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

  it("shows the room's details and who last changed them", async () => {
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(COMMUNITY_ROOMS_GET_TASK, {
        room: {
          ...communityRoom(),
          description: "Papers for the board's meetings.",
          tags: ["board"],
          detailsUpdatedAt: "2026-10-15T09:30:01Z",
          detailsUpdatedBy: "did:key:z6MkSecretary",
        },
      }),
      taskRoute(COMMUNITY_ROOMS_MEMBERS_LIST_TASK, { items: [] }),
    ]);
    mount(page);
    expect(await screen.findByRole("heading", { name: "Board pack" })).toBeTruthy();
    // The description is the page's lead and the room's first fact.
    expect(screen.getAllByText("Papers for the board's meetings.").length).toBeGreaterThan(0);
    expect(screen.getByText("board", { selector: ".chip" })).toBeTruthy();
    expect(screen.getByText("Details last changed")).toBeTruthy();
  });

  it("edits a room's details, sending only what changed and asking for no gesture", async () => {
    const requests = mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(COMMUNITY_ROOMS_GET_TASK, {
        room: { ...communityRoom(), description: "Old words.", tags: ["board", "finance"] },
      }),
      taskRoute(COMMUNITY_ROOMS_MEMBERS_LIST_TASK, { items: [] }),
      taskRoute(COMMUNITY_ROOMS_UPDATE_TASK, (p) => ({
        room: { ...communityRoom(), label: (p as { label?: string }).label ?? "Board pack" },
        changed: true,
      })),
    ]);
    mount(page);
    fireEvent.click(await screen.findByRole("button", { name: /Edit details/ }));
    const form = screen.getByRole("region", { name: "Edit details" });
    const save = within(form).getByRole("button", { name: "Save details" }) as HTMLButtonElement;
    fireEvent.change(within(form).getByLabelText(/^Reason/), { target: { value: "the 2027 cycle" } });
    expect(save.disabled).toBe(true);
    expect(within(form).getByText("Nothing has changed yet.")).toBeTruthy();
    fireEvent.change(within(form).getByLabelText(/^Label/), { target: { value: "Board pack — 2027" } });
    fireEvent.change(within(form).getByLabelText(/^Description/), { target: { value: "" } });
    fireEvent.change(within(form).getByLabelText(/^Tags/), { target: { value: "finance, board" } });
    fireEvent.click(save);
    await waitFor(() => expect(sentPayloads(requests, COMMUNITY_ROOMS_UPDATE_TASK)).toHaveLength(1));
    expect(sentPayloads(requests, COMMUNITY_ROOMS_UPDATE_TASK)[0]).toEqual({
      roomId: ROOM,
      reason: "the 2027 cycle",
      label: "Board pack — 2027",
      removeDescription: true,
    });
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

  it("reads tags as a set, and refuses one outside the specification", () => {
    expect(parseTags("board, finance board ,, ")).toEqual({ tags: ["board", "finance"] });
    expect(parseTags("")).toEqual({ tags: [] });
    expect("error" in parseTags("Board")).toBe(true);
    expect("error" in parseTags("-board")).toBe(true);
    expect("error" in parseTags("a b c d e f g h i")).toBe(true);
  });

  it("names only the details a form changes", () => {
    const room = { ...communityRoom(), description: "Old words.", tags: ["board"] } as Parameters<
      typeof detailsUpdate
    >[0];
    const form = { label: "Board pack", description: "Old words.", tags: ["board"], reason: " r " };
    expect(detailsUpdate(room, form)).toBeNull();
    expect(detailsUpdate(room, { ...form, tags: [] })).toEqual({ roomId: ROOM, reason: "r", tags: [] });
    expect(detailsUpdate(room, { ...form, description: "  " })).toEqual({
      roomId: ROOM,
      reason: "r",
      removeDescription: true,
    });
    expect(detailsUpdate(room, { ...form, description: "New words." })).toEqual({
      roomId: ROOM,
      reason: "r",
      description: "New words.",
    });
    // Without a description, an empty one is no change.
    expect(detailsUpdate({ ...room, description: undefined }, { ...form, description: "" })).toBeNull();
  });

  it("writes validUntil as a whole-second RFC 3339 instant", () => {
    expect(validUntilIn(1, new Date("2026-10-16T10:00:00.123Z"))).toBe("2026-10-17T10:00:00Z");
  });
});
