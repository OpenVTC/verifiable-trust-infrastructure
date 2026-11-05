import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  NETWORKS_JOIN_TASK,
  NETWORKS_LIST_TASK,
  NETWORKS_SHOW_TASK,
  invitationOf,
  joinDraftErrors,
  joinPayload,
  unassignedRoleOf,
} from "@/lib/networks";
import { Networks } from "@/plugins/networks";
import type { NetworkMembership } from "@/lib/wire-types";
import { mockFetch, renderWithProviders, sentPayloads, taskRoute, whoamiWith } from "@/test/render";

// Signed reads and the step-up writes are sent unsigned, so the tables below
// answer them; the passkey gesture is not part of what these tests hold.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
  vtcDid: async () => "did:webvh:QmScid:community.example",
}));
vi.mock("@/lib/signed-act", async (original) => ({
  ...(await original<typeof import("@/lib/signed-act")>()),
  postSignedWithStepUp: (await import("@/test/signed-read")).unsignedTask,
}));

const GROUPS_LIST = "https://trusttasks.org/spec/vtc/groups/list/0.2";
const NETWORK_DID = "did:webvh:QmNet:vtn.example";
const NETWORK_URL = "https://vtn.example";

const group = (groupId: string, name: string, groupDid: string) => ({
  group: {
    groupId,
    name,
    groupDid,
    kind: "static",
    joinPolicy: "closed",
    visibility: "admins",
    showMembers: "admins",
    carriesAuthority: false,
    issuesCredentials: true,
    createdAt: "2026-10-01T00:00:00Z",
    updatedAt: "2026-10-01T00:00:00Z",
  },
  myMembership: "none",
});

const membership: NetworkMembership = {
  network: NETWORK_DID,
  url: NETWORK_URL,
  name: "First Network",
  state: "acknowledged",
  listing: { type: ["VerifiableCredential"] },
  groups: [],
  joinedAt: "2026-11-01T00:00:00Z",
  updatedAt: "2026-11-01T00:00:00Z",
} as unknown as NetworkMembership;

const mount = (route = "/networks") =>
  renderWithProviders(<Networks />, {
    route,
    path: "/networks/*",
    whoami: whoamiWith(["vtc.config.admin"]),
  });

describe("the join form's helpers", () => {
  it("reads an invitation link's network URL and DID", () => {
    const params = new URLSearchParams(
      `join=${encodeURIComponent(NETWORK_URL)}&network=${encodeURIComponent(NETWORK_DID)}`,
    );
    expect(invitationOf(params)).toEqual({ url: NETWORK_URL, network: NETWORK_DID });
    expect(invitationOf(new URLSearchParams(""))).toBeNull();
  });

  it("refuses what the VTC would refuse", () => {
    expect(joinDraftErrors("http://vtn.example", NETWORK_DID, []).url).toBeDefined();
    expect(joinDraftErrors(NETWORK_URL, "vtn.example", []).network).toBeDefined();
    expect(joinDraftErrors(NETWORK_URL, NETWORK_DID, [{ role: "Admins", groupId: "g" }]).roles)
      .toBeDefined();
    expect(joinDraftErrors(NETWORK_URL, NETWORK_DID, [{ role: "admins", groupId: "" }]).roles)
      .toBeDefined();
    expect(joinDraftErrors(NETWORK_URL, NETWORK_DID, [{ role: "admins", groupId: "g" }])).toEqual({});
  });

  it("builds the spec's payload, dropping blank rows and a trailing slash", () => {
    expect(
      joinPayload(`${NETWORK_URL}/`, NETWORK_DID, [
        { role: "admins", groupId: "g_1" },
        { role: "", groupId: "" },
      ]),
    ).toEqual({ url: NETWORK_URL, network: NETWORK_DID, groups: [{ role: "admins", groupId: "g_1" }] });
    expect(joinPayload(NETWORK_URL, NETWORK_DID, [])).toEqual({ url: NETWORK_URL, network: NETWORK_DID });
  });

  it("reads the role a roleUnassigned refusal names", () => {
    expect(
      unassignedRoleOf({ code: "vtc/networks/join:roleUnassigned", details: { role: "admins" } }),
    ).toBe("admins");
    expect(unassignedRoleOf({ code: "vtc/networks/join:notListed" })).toBeNull();
  });
});

describe("Networks", () => {
  it("lists the memberships and shows one with its credentials", async () => {
    mockFetch([
      taskRoute(NETWORKS_LIST_TASK, { items: [membership] }),
      taskRoute(NETWORKS_SHOW_TASK, { membership }),
    ]);
    mount();
    fireEvent.click(await screen.findByRole("button", { name: "First Network" }));
    expect(await screen.findByText("The network's listing of this community")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Leave network" })).toBeTruthy();
  });

  it("joins from an invitation link, adding the role the network requires", async () => {
    // Refused until a group serves `admins`, as a network requiring that role.
    const assigned = (body: unknown) =>
      ((body as { payload?: { groups?: unknown[] } }).payload?.groups ?? []).length > 0;
    const requests = mockFetch([
      taskRoute(NETWORKS_LIST_TASK, { items: [] }),
      taskRoute(GROUPS_LIST, {
        items: [group("g_admins", "Admins", "did:webvh:QmG:group.example"), group("g_none", "No DID", "")],
      }),
      {
        method: "POST",
        path: "/v1/trust-tasks",
        task: NETWORKS_JOIN_TASK,
        status: ({ body }) => (assigned(body) ? 200 : 422),
        body: ({ body }) =>
          assigned(body)
            ? { payload: { membership } }
            : {
                payload: {
                  code: "vtc/networks/join:roleUnassigned",
                  message: "no group is assigned to the required role admins",
                  details: { role: "admins" },
                },
              },
      },
    ]);
    mount(
      `/networks?join=${encodeURIComponent(NETWORK_URL)}&network=${encodeURIComponent(NETWORK_DID)}`,
    );

    expect((await screen.findByLabelText("Network URL") as HTMLInputElement).value).toBe(NETWORK_URL);
    expect((screen.getByLabelText("Network DID") as HTMLInputElement).value).toBe(NETWORK_DID);

    fireEvent.click(screen.getByRole("button", { name: "Join network" }));
    // The refusal names the role; the form adds a row for it.
    expect(await screen.findByText(/requires a group for the role/)).toBeTruthy();
    const select = (await screen.findByLabelText("Group")) as HTMLSelectElement;
    // Only a group with a DID of its own is offered.
    expect([...select.options].map((o) => o.textContent)).toEqual(["Pick a group…", "Admins"]);
    fireEvent.change(select, { target: { value: "g_admins" } });
    fireEvent.click(screen.getByRole("button", { name: "Join network" }));

    await waitFor(() => expect(sentPayloads(requests, NETWORKS_JOIN_TASK)).toHaveLength(2));
    expect(sentPayloads(requests, NETWORKS_JOIN_TASK)[1]).toEqual({
      url: NETWORK_URL,
      network: NETWORK_DID,
      groups: [{ role: "admins", groupId: "g_admins" }],
    });
  });
});
