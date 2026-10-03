import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { WhoamiResponse } from "@/lib/api";
import { Roles } from "@/plugins/roles";
import { mockFetch, renderWithProviders, sentPayloads, taskRoute } from "@/test/render";

// The role verbs are signed documents; the stand-ins send them unsigned so the
// table below answers them without a console key.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));
vi.mock("@/lib/signed-act", async (original) => ({
  ...(await original<typeof import("@/lib/signed-act")>()),
  postSignedWithStepUp: (await import("@/test/signed-read")).unsignedTask,
}));

const LIST = "https://trusttasks.org/spec/vtc/roles/list/0.1";
const SHOW = "https://trusttasks.org/spec/vtc/roles/show/0.1";
const DEFINE = "https://trusttasks.org/spec/vtc/roles/define/0.1";

const ROLES = [
  {
    name: "auditor",
    builtIn: true,
    ceiling: [{ capability: "vtc.audit.read" }],
    approveScope: [],
  },
  {
    name: "events-team",
    builtIn: false,
    description: "Runs the public pages.",
    ceiling: [{ capability: "vtc.surface.admin" }, { capability: "vtc.invitations.manage" }],
    approveScope: [{ capability: "vtc.invitations.manage" }],
    createdAt: "2026-10-02T15:30:00Z",
    createdBy: "did:key:zCarol",
  },
];

const viewer = (capabilities: string[]): WhoamiResponse => ({
  session: {
    id: "sess_1",
    subject: "did:key:zViewer",
    issuedAt: "2026-09-01T00:00:00Z",
    expiresAt: "2026-09-01T00:05:00Z",
  },
  roles: ["admin"],
  scopes: [],
  capabilities,
});

const routes = () => [
  taskRoute(LIST, { roles: ROLES }),
  taskRoute(SHOW, { role: ROLES[1], holders: 2 }),
  taskRoute(DEFINE, { role: { ...ROLES[1], name: "pages" } }),
];

describe("Roles page", () => {
  it("lists built-in and custom roles with their ceilings", async () => {
    mockFetch(routes());
    renderWithProviders(<Roles />, {
      route: "/roles",
      path: "/roles",
      whoami: viewer(["vtc.audit.read"]),
    });
    expect(await screen.findByText("events-team")).toBeTruthy();
    expect(screen.getByText("auditor")).toBeTruthy();
    expect(screen.getByText("built-in")).toBeTruthy();
    expect(screen.getByText("custom")).toBeTruthy();
    expect(screen.getAllByText("vtc.surface.admin").length).toBeGreaterThan(0);
  });

  it("offers define and delete only to a holder of vtc.roles.assign and vtc.approvals.admin", async () => {
    mockFetch(routes());
    renderWithProviders(<Roles />, {
      route: "/roles",
      path: "/roles",
      whoami: viewer(["vtc.roles.assign"]),
    });
    await screen.findByText("events-team");
    expect(screen.queryByRole("button", { name: /define role/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /delete role/i })).toBeNull();
  });

  it("sends a definition as vtc/roles/define/0.1", async () => {
    const requests = mockFetch(routes());
    renderWithProviders(<Roles />, {
      route: "/roles",
      path: "/roles",
      whoami: viewer(["vtc.roles.assign", "vtc.approvals.admin"]),
    });
    await screen.findByText("events-team");
    // A custom role can be deleted; a built-in one cannot.
    expect(screen.getByRole("button", { name: "Delete role events-team" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Delete role auditor" })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: /define role/i }));
    fireEvent.change(screen.getByLabelText("Role name"), { target: { value: "pages" } });
    fireEvent.click(screen.getByLabelText("May hold: vtc.surface.admin"));
    fireEvent.click(screen.getByRole("button", { name: /send for approval/i }));

    await waitFor(() => expect(sentPayloads(requests, DEFINE)).toHaveLength(1));
    expect(sentPayloads(requests, DEFINE)[0]).toEqual({
      name: "pages",
      ceiling: [{ capability: "vtc.surface.admin" }],
      approveScope: [],
    });
  });
});
