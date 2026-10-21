// The console's Groups page: the groups this administrator may see, a group's
// members named by their directory entry, and a request decided from it.

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { COMMUNITY_ROOMS_LIST_TASK } from "@/lib/community-rooms-api";
import {
  GROUPS_BINDINGS_LIST_TASK,
  GROUPS_LIST_TASK,
  GROUPS_MEMBERS_LIST_TASK,
  GROUPS_REQUESTS_DECIDE_TASK,
  GROUPS_REQUESTS_LIST_TASK,
  GROUPS_SHOW_TASK,
  audienceWithin,
} from "@/lib/groups";
import { Groups } from "@/plugins/groups";
import {
  NAME_BOOK_ROUTES,
  mockFetch,
  renderWithProviders,
  sentPayloads,
  taskRoute,
  whoamiWith,
} from "@/test/render";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));

const ENTRIES = "https://trusttasks.org/spec/vtc/directory/entries/list/0.1";
const GROUP_ID = "grp_W5k2N8xRb3Qz7TpLAAAAAA";
const ENTRY = "dir_Q7m2K9xVb4Tz8LpRAAAAAA";

function group(extra: object = {}) {
  return {
    groupId: GROUP_ID,
    groupDid: "did:webvh:QmScid:vtc.example.com:group-dids:abc",
    name: "Identity WG",
    description: "Where the community works on identity.",
    kind: "static",
    joinPolicy: "request",
    visibility: "members",
    showMembers: "groupMembers",
    issuesCredentials: true,
    carriesAuthority: false,
    createdAt: "2026-10-19T09:00:00Z",
    memberCount: 1,
    managers: [],
    ...extra,
  };
}

const ROUTES = [
  ...NAME_BOOK_ROUTES,
  taskRoute(ENTRIES, {
    items: [{ entryId: ENTRY, fields: { displayName: "Carol Example", did: "did:example:carol" } }],
  }),
];

describe("the Groups page", () => {
  it("lists the groups, and offers a new one to a holder of vtc.groups.manage", async () => {
    mockFetch([
      ...ROUTES,
      taskRoute(GROUPS_LIST_TASK, { items: [{ group: group(), myMembership: "none" }] }),
    ]);
    renderWithProviders(<Groups />, {
      route: "/groups",
      path: "/groups/*",
      whoami: whoamiWith(["vtc.groups.manage"]),
    });
    expect(await screen.findByText("Identity WG")).toBeTruthy();
    expect(screen.getByText("By request")).toBeTruthy();
    expect(screen.getByRole("button", { name: /New group/ })).toBeTruthy();
  });

  it("offers no new group without vtc.groups.manage", async () => {
    mockFetch([...ROUTES, taskRoute(GROUPS_LIST_TASK, { items: [] })]);
    renderWithProviders(<Groups />, { route: "/groups", path: "/groups/*", whoami: whoamiWith([]) });
    expect(await screen.findByText("No groups yet")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /New group/ })).toBeNull();
  });

  it("names members by their directory entry, and decides a request", async () => {
    const requests = mockFetch([
      ...ROUTES,
      taskRoute(GROUPS_SHOW_TASK, { group: group(), myMembership: "none" }),
      taskRoute(GROUPS_MEMBERS_LIST_TASK, {
        items: [{ entryId: ENTRY, source: "added", since: "2026-10-19T09:00:00Z", state: "active" }],
      }),
      taskRoute(GROUPS_REQUESTS_LIST_TASK, {
        items: [
          {
            request: {
              requestId: "greq_W5k2N8xRb3Qz7TpLAAAAAA",
              groupId: GROUP_ID,
              entryId: ENTRY,
              message: "I work on identity.",
              createdAt: "2026-10-19T09:00:00Z",
              state: "pending",
            },
          },
        ],
      }),
      taskRoute(GROUPS_REQUESTS_DECIDE_TASK, {
        request: {
          requestId: "greq_W5k2N8xRb3Qz7TpLAAAAAA",
          groupId: GROUP_ID,
          entryId: ENTRY,
          createdAt: "2026-10-19T09:00:00Z",
          state: "approved",
        },
      }),
    ]);
    renderWithProviders(<Groups />, {
      route: `/groups/${encodeURIComponent(GROUP_ID)}`,
      path: "/groups/*",
      whoami: whoamiWith(["vtc.groups.manage"]),
    });
    expect((await screen.findAllByText("Carol Example")).length).toBeGreaterThan(0);
    expect(screen.getByText("I work on identity.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    await waitFor(() =>
      expect(sentPayloads(requests, GROUPS_REQUESTS_DECIDE_TASK)).toEqual([
        { requestId: "greq_W5k2N8xRb3Qz7TpLAAAAAA", decision: "approve" },
      ]),
    );
  });
});

describe("a group's rooms", () => {
  const ROOM = "did:webvh:QmRoom:vtc.example.com:rooms:board";
  const routes = () => [
    ...ROUTES,
    taskRoute(GROUPS_SHOW_TASK, { group: group(), myMembership: "none" }),
    taskRoute(GROUPS_MEMBERS_LIST_TASK, { items: [] }),
    taskRoute(GROUPS_REQUESTS_LIST_TASK, { items: [] }),
    taskRoute(GROUPS_BINDINGS_LIST_TASK, {
      items: [
        {
          bindingId: "gb_P2k8W5qYc6Vd1MsKAAAAAA",
          binding: { kind: "room", roomId: ROOM, actions: ["read", "write"], validFor: "P30D" },
          state: "active",
          createdAt: "2026-10-20T09:00:00Z",
        },
      ],
    }),
    taskRoute(COMMUNITY_ROOMS_LIST_TASK, {
      items: [
        {
          room: { roomId: ROOM },
          label: "Board pack",
          admitted: 1,
          offered: 0,
          ownerAuthorityValidUntil: "2027-10-20T00:00:00Z",
          createdBy: "did:example:admin",
        },
      ],
    }),
  ];

  it("names each bound room, and lets a holder of vtc.rooms.manage bind and end", async () => {
    mockFetch(routes());
    renderWithProviders(<Groups />, {
      route: `/groups/${encodeURIComponent(GROUP_ID)}`,
      path: "/groups/*",
      whoami: whoamiWith(["vtc.groups.manage", "vtc.rooms.manage"]),
    });
    // The binding, by the room's label, and the room offered in the form.
    await waitFor(() => expect(screen.getAllByText("Board pack").length).toBe(2));
    expect(screen.getByRole("option", { name: "Board pack" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Bind room" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "End" })).toBeTruthy();
  });

  it("only lists the bindings to a manager without vtc.rooms.manage", async () => {
    mockFetch(routes());
    renderWithProviders(<Groups />, {
      route: `/groups/${encodeURIComponent(GROUP_ID)}`,
      path: "/groups/*",
      whoami: whoamiWith(["vtc.groups.manage"]),
    });
    expect(await screen.findByText(/read, write/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Bind room" })).toBeNull();
    expect(screen.queryByRole("button", { name: "End" })).toBeNull();
  });
});

describe("audiences", () => {
  it("never lets the member list reach further than the group", () => {
    expect(audienceWithin("admins", "members")).toBe(true);
    expect(audienceWithin("members", "groupMembers")).toBe(false);
  });
});
