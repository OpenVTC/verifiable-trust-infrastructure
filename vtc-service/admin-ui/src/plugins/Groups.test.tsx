// The console's Groups page: the groups this administrator may see, a group's
// members named by their directory entry, and a request decided from it.

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
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

describe("audiences", () => {
  it("never lets the member list reach further than the group", () => {
    expect(audienceWithin("admins", "members")).toBe(true);
    expect(audienceWithin("members", "groupMembers")).toBe(false);
  });
});
