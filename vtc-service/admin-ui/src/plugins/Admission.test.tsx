import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Acl } from "@/plugins/acl";
import { Members } from "@/plugins/members";
import { ACTIONS_SHOW_TASK, NEXT_STEP_TYPE } from "@/lib/parked-action";
import {
  MEMBERS_ADMIT_TASK,
  MEMBERS_MAKE_MEMBERSHIP_TASK,
  canMakeMembership,
} from "@/lib/member-admission";
import {
  MEMBERS_LIST_TASK,
  mockFetch,
  renderWithProviders,
  sentPayloads,
  taskRoute,
  type MockRoute,
} from "@/test/render";

// Every read and write is a signed document; the stand-in sends them unsigned
// so the tables below answer them without a console key.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));
vi.mock("@/lib/signed-act", async (original) => ({
  ...(await original<typeof import("@/lib/signed-act")>()),
  postSignedWithStepUp: (await import("@/test/signed-read")).unsignedTask,
}));

const ACL_LIST = "https://trusttasks.org/spec/acl/list/0.2";
const FOUNDER = "did:key:z6MkFounder";
const MEMBER = "did:key:z6MkMember";
const BRIDGE = "did:key:z6MkBridge";
const NEWCOMER = "did:key:z6MkNewcomer";

const entry = (subject: string, communityRole: string, membership: string) => ({
  subject,
  role: communityRole === "admin" ? "community-admin" : "member",
  act: { scope: communityRole === "admin" ? "all" : "none" },
  keys: { scope: "none" },
  capabilities: { scope: communityRole === "admin" ? "ceiling" : "none" },
  approve: { scope: "none" },
  ext: { "org.openvtc": { communityRole, membership } },
});

const ENTRIES = [
  entry(FOUNDER, "admin", "none"),
  entry(MEMBER, "member", "active"),
  entry(BRIDGE, "application", "none"),
];

const admitted = (subject: string, role: string) => ({
  subject,
  role,
  status: "admitted",
  returning: false,
  approval: "policyAllowed",
  statusListIndex: 3,
  vmc: { id: "urn:uuid:vmc" },
  roleVac: { id: "urn:uuid:vac" },
});

/** A `trust-task-next-step` reply: the act was parked for approval. */
const parkedRoute = (task: string): MockRoute => ({
  method: "POST",
  path: "/v1/trust-tasks",
  task,
  status: 202,
  body: () => ({
    type: NEXT_STEP_TYPE,
    payload: {
      continuation: "proceed",
      message: "Sent for approval — 1 of 1 administrator(s) must approve.",
      expects: [{ typeUri: ACTIONS_SHOW_TASK, hint: { actionId: "act-42" } }],
    },
  }),
});

const memberRoutes = (admit: MockRoute): MockRoute[] => [
  taskRoute(MEMBERS_LIST_TASK, { items: [], nextCursor: null }),
  taskRoute("https://trusttasks.org/spec/vtc/members/removed/0.1", { removed: [] }),
  taskRoute(ACL_LIST, { entries: ENTRIES, truncated: false }),
  admit,
];

describe("canMakeMembership", () => {
  it("is an entry with no member record that is not an application entry", () => {
    expect(ENTRIES.map((e) => canMakeMembership(e as never))).toEqual([true, false, false]);
    // A VTC that predates the field offers nothing.
    expect(canMakeMembership({ ...ENTRIES[0], ext: { "org.openvtc": {} } } as never)).toBe(false);
  });
});

describe("Members — Add a member", () => {
  const openForm = async () => {
    fireEvent.click(await screen.findByRole("button", { name: /add a member/i }));
    return screen.findByRole("region", { name: "Add a member" });
  };

  it("sends the DID, role and label, and says it may go to approval", async () => {
    const requests = mockFetch(
      memberRoutes(taskRoute(MEMBERS_ADMIT_TASK, admitted(NEWCOMER, "member"))),
    );
    renderWithProviders(<Members />, { route: "/members", path: "/members/*" });
    const form = await openForm();

    // The governed note names the policy that decides it.
    const policy = within(form).getByRole("link", { name: "admission policy" });
    expect(policy.getAttribute("href")).toContain("purpose=admission");
    expect(form.textContent).toMatch(/sent to another administrator for approval/);

    const submit = within(form).getByRole("button", { name: "Add member" });
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(within(form).getByLabelText(/^DID/), { target: { value: NEWCOMER } });
    fireEvent.change(within(form).getByLabelText(/^Label/), { target: { value: " Ada " } });
    expect((within(form).getByLabelText(/^Role/) as HTMLSelectElement).value).toBe("member");
    fireEvent.click(submit);

    await waitFor(() => expect(sentPayloads(requests, MEMBERS_ADMIT_TASK)).toHaveLength(1));
    // Blank optional members are omitted, never sent empty.
    expect(sentPayloads(requests, MEMBERS_ADMIT_TASK)[0]).toEqual({
      subject: NEWCOMER,
      role: "member",
      label: "Ada",
    });
    expect((await within(form).findByRole("status")).textContent).toContain(
      `${NEWCOMER} is now a member (member).`,
    );
  });

  it("offers member, moderator and issuer — never admin", async () => {
    mockFetch(memberRoutes(taskRoute(MEMBERS_ADMIT_TASK, admitted(NEWCOMER, "member"))));
    renderWithProviders(<Members />, { route: "/members", path: "/members/*" });
    const form = await openForm();
    const options = within(within(form).getByLabelText(/^Role/))
      .getAllByRole("option")
      .map((o) => (o as HTMLOptionElement).value);
    expect(options).toEqual(["member", "moderator", "issuer"]);
  });

  it("shows an add the policy referred as sent for approval, linking to the action", async () => {
    mockFetch(memberRoutes(parkedRoute(MEMBERS_ADMIT_TASK)));
    renderWithProviders(<Members />, { route: "/members", path: "/members/*" });
    const form = await openForm();
    fireEvent.change(within(form).getByLabelText(/^DID/), { target: { value: NEWCOMER } });
    fireEvent.change(within(form).getByLabelText(/^Role/), { target: { value: "moderator" } });
    fireEvent.click(within(form).getByRole("button", { name: "Add member" }));

    const notice = await within(form).findByRole("status");
    expect(notice.textContent).toContain("Sent for approval");
    expect(within(notice).getByRole("link", { name: "View the action" }).getAttribute("href")).toContain(
      "action=act-42",
    );
    // Not an error card.
    expect(within(form).queryByText("Could not add the member")).toBeNull();
  });

  it("lists access-control entries without a membership, and makes one", async () => {
    const requests = mockFetch(
      memberRoutes(taskRoute(MEMBERS_MAKE_MEMBERSHIP_TASK, admitted(FOUNDER, "admin"))),
    );
    renderWithProviders(<Members />, { route: "/members", path: "/members/*" });
    const card = await screen.findByRole("region", { name: "Access without a membership" });
    // The founder only: the member has one, the bridge is an application entry.
    const rows = within(card).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.textContent).toContain("admin");

    fireEvent.click(within(card).getByRole("button", { name: /make this a membership/i }));
    fireEvent.click(await screen.findByRole("button", { name: "Make a membership" }));
    await waitFor(() =>
      expect(sentPayloads(requests, MEMBERS_MAKE_MEMBERSHIP_TASK)).toEqual([{ subject: FOUNDER }]),
    );
  });
});

describe("Access control — Make this a membership", () => {
  it("is offered on an entry with no member record, and nowhere else", async () => {
    const requests = mockFetch([
      taskRoute(ACL_LIST, { entries: ENTRIES, truncated: false }),
      taskRoute(MEMBERS_MAKE_MEMBERSHIP_TASK, admitted(FOUNDER, "admin")),
    ]);
    renderWithProviders(<Acl />, { route: "/acl", path: "/acl" });

    const buttons = await screen.findAllByRole("button", { name: /make this a membership/i });
    expect(buttons).toHaveLength(1);
    expect(buttons[0]!.closest("tr")!.textContent).toContain(FOUNDER.slice(0, 12));
    expect(screen.getAllByTestId("no-membership")).toHaveLength(1);

    fireEvent.click(buttons[0]!);
    fireEvent.click(await screen.findByRole("button", { name: "Make a membership" }));
    await waitFor(() =>
      expect(sentPayloads(requests, MEMBERS_MAKE_MEMBERSHIP_TASK)).toEqual([{ subject: FOUNDER }]),
    );
  });

  it("shows a membership the policy referred as sent for approval", async () => {
    mockFetch([
      taskRoute(ACL_LIST, { entries: ENTRIES, truncated: false }),
      parkedRoute(MEMBERS_MAKE_MEMBERSHIP_TASK),
    ]);
    renderWithProviders(<Acl />, { route: "/acl", path: "/acl" });
    fireEvent.click(await screen.findByRole("button", { name: /make this a membership/i }));
    fireEvent.click(await screen.findByRole("button", { name: "Make a membership" }));
    expect(await screen.findByText(/Sent for approval/)).toBeTruthy();
    expect(screen.queryByText(/Make this a membership failed/)).toBeNull();
  });
});
