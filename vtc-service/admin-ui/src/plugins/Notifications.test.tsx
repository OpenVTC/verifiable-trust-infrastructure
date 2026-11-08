// The console's Notifications page (`vtc/notifications/{list,show,relay}/0.1`):
// the notifications the community holds, one read whole, and the relay
// decision — acknowledged by the administrator's own tick where a relay
// discloses something (VTI-NTF-046), sent as exactly one selection, and
// answered with a count, never who was reached.

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { GROUPS_LIST_TASK } from "@/lib/groups";
import {
  NOTIFICATIONS_LIST_TASK,
  NOTIFICATIONS_RELAY_TASK,
  NOTIFICATIONS_SHOW_TASK,
  relayStanding,
} from "@/lib/notifications-api";
import { Notifications } from "@/plugins/notifications";
import {
  NAME_BOOK_ROUTES,
  mockFetch,
  renderWithProviders,
  sentPayloads,
  taskRoute,
  whoamiWith,
  type MockRoute,
} from "@/test/render";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));
vi.mock("@/lib/signed-act", async (original) => ({
  ...(await original<typeof import("@/lib/signed-act")>()),
  postSignedWithStepUp: (await import("@/test/signed-read")).unsignedTask,
}));

const RECORD = "rcv_7Hk2N8xRb3Qz7TpLAAAA";
const HOLDER = "did:webvh:QmHolder:holder.example";
const MEMBER_DID = "did:key:z6MkReachedMember";
const GROUP_ID = "grp_W5k2N8xRb3Qz7TpLAAAAAA";
const DISCLOSURE = "Relaying tells members this community is a member of the community holding the election.";

function received(extra: object = {}) {
  return {
    recordId: RECORD,
    originator: HOLDER,
    relayedBy: [],
    notification: {
      notificationId: "n-1",
      revision: 1,
      kind: "election",
      subject: { heldBy: HOLDER, id: "agm-2027", openWith: "https://trusttasks.org/spec/vtc/elections/show/0.6" },
      audience: "did:webvh:QmUs:us.example",
      status: "available",
      relayable: true,
      validFrom: "2026-11-08T00:00:00Z",
      validUntil: "2026-11-15T00:00:00Z",
    },
    receivedAt: "2026-11-02T10:00:00Z",
    mayRelay: true,
    relayDisclosure: DISCLOSURE,
    relayDecisions: [
      {
        decidedAt: "2026-11-02T11:00:00Z",
        decidedBy: "did:key:z6MkAdmin",
        recipients: { scope: "role", role: "moderator" },
        recipientCount: 3,
      },
    ],
    ...extra,
  };
}

const routes = (item = received(), relay?: MockRoute): MockRoute[] => [
  ...NAME_BOOK_ROUTES,
  taskRoute(NOTIFICATIONS_LIST_TASK, { items: [item] }),
  taskRoute(NOTIFICATIONS_SHOW_TASK, { item, document: { type: "https://trusttasks.org/spec/notifications/notify/0.1", issuer: HOLDER } }),
  taskRoute(GROUPS_LIST_TASK, {
    items: [{ group: { groupId: GROUP_ID, name: "Identity WG" }, myMembership: "none" }],
  }),
  ...(relay ? [relay] : []),
];

const RELAYER = whoamiWith(["vtc.notifications.read", "vtc.notifications.relay"]);

function openDetail(r: MockRoute[], whoami = RELAYER) {
  const requests = mockFetch(r);
  renderWithProviders(<Notifications />, {
    route: `/notifications/${RECORD}`,
    path: "/notifications/*",
    whoami,
  });
  return requests;
}

async function confirmRelay() {
  fireEvent.click(screen.getByRole("button", { name: "Relay to members" }));
  const dialog = await screen.findByRole("dialog");
  fireEvent.click(within(dialog).getByRole("button", { name: "Relay" }));
}

describe("the Notifications page", () => {
  it("lists the notifications held, with past decisions as selection and count", async () => {
    mockFetch(routes());
    renderWithProviders(<Notifications />, {
      route: "/notifications",
      path: "/notifications/*",
      whoami: whoamiWith(["vtc.notifications.read"]),
    });
    expect(await screen.findByRole("link", { name: "Election" })).toBeTruthy();
    expect(screen.getByText("agm-2027")).toBeTruthy();
    expect(screen.getByText("Available")).toBeTruthy();
    expect(screen.getByText("May be relayed")).toBeTruthy();
    expect(screen.getByText("Role moderator: 3")).toBeTruthy();
    expect(screen.getByText("Sent directly")).toBeTruthy();
  });

  it("asks for lapsed ones only when the filter is on, and follows nextCursor", async () => {
    const requests = mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(NOTIFICATIONS_LIST_TASK, (p) =>
        (p as { cursor?: string }).cursor
          ? { items: [received({ recordId: "rcv_second_page_000000", notification: { ...received().notification, subject: { ...received().notification.subject, id: "later" } } })] }
          : { items: [received()], nextCursor: "c2" },
      ),
    ]);
    renderWithProviders(<Notifications />, { route: "/notifications", path: "/notifications/*", whoami: RELAYER });
    await screen.findByText("agm-2027");
    fireEvent.click(screen.getByRole("button", { name: "Show more" }));
    expect(await screen.findByText("later")).toBeTruthy();
    fireEvent.click(screen.getByRole("switch", { name: /Include lapsed/ }));
    await waitFor(() =>
      expect(sentPayloads(requests, NOTIFICATIONS_LIST_TASK)).toContainEqual({ includeLapsed: true, limit: 50 }),
    );
    const sent = sentPayloads(requests, NOTIFICATIONS_LIST_TASK);
    expect(sent[0]).toEqual({ limit: 50 });
    expect(sent[1]).toEqual({ limit: 50, cursor: "c2" });
  });

  it("shows the document as received", async () => {
    openDetail(routes());
    expect(await screen.findByText("The document as received")).toBeTruthy();
    expect(screen.getByText(/notifications\/notify\/0\.1/)).toBeTruthy();
  });

  it("offers no relay without vtc.notifications.relay", async () => {
    openDetail(routes(), whoamiWith(["vtc.notifications.read"]));
    await screen.findByText("The document as received");
    expect(screen.queryByRole("button", { name: "Relay to members" })).toBeNull();
  });

  it("offers no relay for a notification the community may not relay", async () => {
    openDetail(routes(received({ mayRelay: false })));
    await screen.findByText("The document as received");
    expect(screen.queryByRole("button", { name: "Relay to members" })).toBeNull();
  });

  it("keeps the relay disabled until the disclosure is acknowledged, then sends it acknowledged", async () => {
    const requests = openDetail(
      routes(received(), taskRoute(NOTIFICATIONS_RELAY_TASK, { recordId: RECORD, revision: 1, recipientCount: 12 })),
    );
    const button = (await screen.findByRole("button", { name: "Relay to members" })) as HTMLButtonElement;
    expect(screen.getAllByText(DISCLOSURE).length).toBeGreaterThan(0);
    expect(button.disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: /I understand/ }));
    expect(button.disabled).toBe(false);
    await confirmRelay();
    await waitFor(() => expect(sentPayloads(requests, NOTIFICATIONS_RELAY_TASK)).toHaveLength(1));
    expect(sentPayloads(requests, NOTIFICATIONS_RELAY_TASK)[0]).toEqual({
      recordId: RECORD,
      recipients: { scope: "allMembers" },
      disclosureAcknowledged: true,
    });
    expect(await screen.findByText("Relayed to 12 members.")).toBeTruthy();
    expect(screen.queryByText(MEMBER_DID)).toBeNull();
  });

  it("sends groupId only with a group, and says when nobody new was reached", async () => {
    const requests = openDetail(
      routes(
        received({ relayDisclosure: undefined }),
        taskRoute(NOTIFICATIONS_RELAY_TASK, { recordId: RECORD, revision: 1, recipientCount: 0 }),
      ),
    );
    await screen.findByRole("button", { name: "Relay to members" });
    fireEvent.click(screen.getByRole("radio", { name: /One group/ }));
    const select = await screen.findByRole("combobox");
    await screen.findByRole("option", { name: "Identity WG" });
    fireEvent.change(select, { target: { value: GROUP_ID } });
    await confirmRelay();
    await waitFor(() => expect(sentPayloads(requests, NOTIFICATIONS_RELAY_TASK)).toHaveLength(1));
    expect(sentPayloads(requests, NOTIFICATIONS_RELAY_TASK)[0]).toEqual({
      recordId: RECORD,
      recipients: { scope: "group", groupId: GROUP_ID },
    });
    expect(await screen.findByText("Already relayed to everyone that selection reaches.")).toBeTruthy();
  });

  it("sends role only with a role", async () => {
    const requests = openDetail(
      routes(
        received({ relayDisclosure: undefined }),
        taskRoute(NOTIFICATIONS_RELAY_TASK, { recordId: RECORD, revision: 1, recipientCount: 1 }),
      ),
    );
    await screen.findByRole("button", { name: "Relay to members" });
    fireEvent.click(screen.getByRole("radio", { name: /One role/ }));
    fireEvent.change(screen.getByRole("combobox", { name: /Community role/ }), { target: { value: "moderator" } });
    await confirmRelay();
    await waitFor(() => expect(sentPayloads(requests, NOTIFICATIONS_RELAY_TASK)).toHaveLength(1));
    expect(sentPayloads(requests, NOTIFICATIONS_RELAY_TASK)[0]).toEqual({
      recordId: RECORD,
      recipients: { scope: "role", role: "moderator" },
    });
    expect(await screen.findByText("Relayed to 1 member.")).toBeTruthy();
  });

  it("shows the statement the community names when it refuses an unacknowledged relay", async () => {
    openDetail(
      routes(
        received({ relayDisclosure: undefined }),
        taskRoute(
          NOTIFICATIONS_RELAY_TASK,
          {
            code: "vtc/notifications/relay:disclosureNotAcknowledged",
            message: "disclosure not acknowledged",
            details: { relayDisclosure: DISCLOSURE },
          },
          403,
        ),
      ),
    );
    await screen.findByRole("button", { name: "Relay to members" });
    await confirmRelay();
    expect(await screen.findByText(/tick the acknowledgement before relaying/)).toBeTruthy();
    expect(screen.getByText(DISCLOSURE)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Relay to members" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole("checkbox", { name: /I understand/ })).toBeTruthy();
  });

  it("says plainly when the group is unknown", async () => {
    openDetail(
      routes(
        received({ relayDisclosure: undefined }),
        taskRoute(
          NOTIFICATIONS_RELAY_TASK,
          { code: "vtc/notifications/relay:groupUnknown", message: "group unknown" },
          404,
        ),
      ),
    );
    await screen.findByRole("button", { name: "Relay to members" });
    fireEvent.click(screen.getByRole("radio", { name: /One group/ }));
    await screen.findByRole("option", { name: "Identity WG" });
    fireEvent.change(screen.getByRole("combobox"), { target: { value: GROUP_ID } });
    await confirmRelay();
    expect(await screen.findByText(/That group does not exist, or you may not see it/)).toBeTruthy();
  });

  it("offers a group-qualified holder only their own group", async () => {
    openDetail(
      [
        ...routes(received({ relayDisclosure: undefined })).filter((r) => r.task !== GROUPS_LIST_TASK),
        taskRoute(GROUPS_LIST_TASK, {
          items: [
            { group: { groupId: GROUP_ID, name: "Identity WG" }, myMembership: "none" },
            { group: { groupId: "grp_other", name: "Other WG" }, myMembership: "none" },
          ],
        }),
      ],
      whoamiWith(["vtc.notifications.read", `vtc.notifications.relay@group:${GROUP_ID}`]),
    );
    await screen.findByRole("button", { name: "Relay to members" });
    expect(screen.queryByRole("radio", { name: /All members/ })).toBeNull();
    expect(screen.queryByRole("radio", { name: /One role/ })).toBeNull();
    expect(await screen.findByRole("option", { name: "Identity WG" })).toBeTruthy();
    expect(screen.queryByRole("option", { name: "Other WG" })).toBeNull();
  });
});

describe("relayStanding", () => {
  it("reads community-wide and group-qualified holdings apart", () => {
    expect(relayStanding(["vtc.notifications.relay"])).toEqual({ anywhere: true, groups: [] });
    expect(relayStanding(["vtc.notifications.relay@group:g1", "vtc.notifications.read"])).toEqual({
      anywhere: false,
      groups: ["g1"],
    });
  });
});
