// The dashboard's Members and Join requests tiles: each a count linking to its
// screen, shown only to a viewer holding what that screen needs. Then the
// redesigned layout: the greeting, "Waiting for you" and "Service health".

import { screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { WhoamiResponse } from "@/lib/api";
import { renderWithProviders } from "@/test/render";

const JOINS = "https://trusttasks.org/spec/vtc/join-requests/list/0.2";
const MEMBERS = "https://trusttasks.org/spec/vtc/members/list/0.2";

const reads = vi.hoisted(() => ({
  calls: [] as [string, Record<string, unknown>][],
  members: 7,
  pending: 2,
  failMembers: false,
  served: [] as string[],
  actions: [] as unknown[],
}));

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  fetchHealth: vi.fn(async () => ({ status: "ok" })),
  fetchBuildInfo: vi.fn(async () => ({ version: "0.0.0", mode: "test" })),
  fetchDiagnostics: vi.fn(async () => ({})),
  postSignedRead: vi.fn(async (type: string, payload: Record<string, unknown>) => {
    reads.calls.push([type, payload]);
    const rows = (n: number, status?: string) =>
      Array.from({ length: n }, (_, i) => ({ id: `x${i}`, did: `did:key:z${i}`, status }));
    if (type === MEMBERS) {
      if (reads.failMembers) throw { status: 403, message: "does not hold vtc.members.manage" };
      return { items: rows(reads.members), nextCursor: null, totalEstimate: reads.members };
    }
    if (type === JOINS)
      return { items: rows(reads.pending, "pending"), nextCursor: null, totalEstimate: reads.pending };
    if (type.includes("/vetting/show/")) return { requestId: "x", vetting: null };
    if (type.endsWith("/trust-task-discovery/0.3")) return { supportedTypes: reads.served };
    return {
      actions: reads.actions,
      counts: { waitingForMe: reads.actions.length, requestedByMe: 0 },
      ext: { "org.openvtc": {} },
      items: [],
    };
  }),
}));

import { Dashboard } from "@/plugins/dashboard";

const viewer = (capabilities: string[]): WhoamiResponse =>
  ({
    session: { id: "s", subject: "did:key:z6MkAdmin", issuedAt: "2026-10-02T10:00:00Z", expiresAt: "2099-01-01T00:00:00Z" },
    roles: ["admin"],
    scopes: [],
    capabilities,
  }) as WhoamiResponse;

const tile = (label: string) =>
  screen.queryByText(label, { selector: ".stat-tile-label" })?.closest(".stat-tile") ?? null;
/** A row of the Service health card. */
const healthRow = (label: string) =>
  document.querySelector<HTMLElement>(`.health-row[data-health="${label}"]`);
/** The tile's own count read (`limit: 1`), not the console-wide name book's
 *  page of 200, which every screen shares and swallows a refusal of. */
const tileReadOf = (task: string) => reads.calls.some(([t, p]) => t === task && p.limit === 1);

beforeEach(() => {
  reads.calls.length = 0;
  reads.members = 7;
  reads.pending = 2;
  reads.failMembers = false;
  reads.served = [];
  reads.actions = [];
});

describe("the dashboard's community tiles", () => {
  it("counts members and pending join requests, each linking to its screen", async () => {
    renderWithProviders(<Dashboard />, {
      whoami: viewer(["vtc.members.manage", "vtc.join.decide"]),
    });
    await waitFor(() => expect(tile("Members")?.textContent).toContain("7"));
    expect(tile("Members")?.getAttribute("href")).toBe("/members");
    await waitFor(() => expect(tile("Join requests")?.textContent).toContain("2"));
    expect(tile("Join requests")?.textContent).toContain("awaiting a decision");
    expect(tile("Join requests")?.getAttribute("href")).toBe("/join-requests");
    expect(reads.calls).toContainEqual([MEMBERS, { limit: 1 }]);
    expect(reads.calls).toContainEqual([JOINS, { status: "pending", limit: 1 }]);
  });

  it("says when none await a decision", async () => {
    reads.pending = 0;
    renderWithProviders(<Dashboard />, { whoami: viewer(["vtc.join.decide"]) });
    await waitFor(() =>
      expect(tile("Join requests")?.textContent).toContain("none awaiting a decision"),
    );
  });

  it("hides each tile from a viewer lacking its capability, and reads nothing for it", async () => {
    renderWithProviders(<Dashboard />, { whoami: viewer(["vtc.join.decide"]) });
    await waitFor(() => expect(tile("Join requests")).not.toBeNull());
    expect(tile("Members")).toBeNull();
    expect(tileReadOf(MEMBERS)).toBe(false);
  });

  it("hides both from a viewer holding neither", async () => {
    renderWithProviders(<Dashboard />, { whoami: viewer(["vtc.audit.read"]) });
    await screen.findByText("Daemon status");
    expect(tile("Members")).toBeNull();
    expect(tile("Join requests")).toBeNull();
    expect(tileReadOf(MEMBERS)).toBe(false);
    expect(reads.calls.some(([t, p]) => t === JOINS && p.limit === 200)).toBe(false);
  });

  it("says so when the count cannot be read", async () => {
    reads.failMembers = true;
    renderWithProviders(<Dashboard />, { whoami: viewer(["vtc.members.manage"]) });
    await waitFor(() => expect(tile("Members")?.textContent).toContain("Could not count members"));
  });
});

describe("the hidden-vetting health row", () => {
  const PUBLISH = "https://trusttasks.org/spec/vtc/vetting/hidden/publish/0.1";

  it("says a build serving hidden/publish supports PCS, and links to the criteria", async () => {
    reads.served = [PUBLISH];
    renderWithProviders(<Dashboard />, { whoami: viewer([]) });
    await waitFor(() =>
      expect(healthRow("Hidden vetting (PCS)")?.textContent).toContain("Supported"),
    );
    expect(
      healthRow("Hidden vetting (PCS)")?.querySelector("a")?.getAttribute("href"),
    ).toBe("/vetting/requirements");
    expect(reads.calls).toContainEqual([
      "https://trusttasks.org/spec/trust-task-discovery/0.3",
      { patterns: ["vtc/vetting/hidden/*"] },
    ]);
  });

  it("says a build without it is named-vetter only", async () => {
    renderWithProviders(<Dashboard />, { whoami: viewer([]) });
    await waitFor(() =>
      expect(healthRow("Hidden vetting (PCS)")?.textContent).toContain("Not in this build"),
    );
    expect(healthRow("Hidden vetting (PCS)")?.querySelector("a")).toBeNull();
  });
});

describe("the redesigned dashboard", () => {
  it("greets the operator under an Overview breadcrumb", async () => {
    renderWithProviders(<Dashboard />, { whoami: viewer([]) });
    const title = await screen.findByRole("heading", { level: 2 });
    expect(title.textContent).toMatch(/^Good (morning|afternoon|evening)/);
    expect(screen.getByRole("navigation", { name: "Breadcrumb" }).textContent).toBe("Overview");
  });

  it("offers Invite a member only to a viewer who can issue invitations", async () => {
    renderWithProviders(<Dashboard />, { whoami: viewer(["vtc.invitations.manage"]) });
    const invite = await screen.findByRole("link", { name: /Invite a member/ });
    expect(invite.getAttribute("href")).toBe("/invitations");
  });

  it("has no Invite a member without the capability", async () => {
    renderWithProviders(<Dashboard />, { whoami: viewer([]) });
    await screen.findByText("Daemon status");
    expect(screen.queryByRole("link", { name: /Invite a member/ })).toBeNull();
  });

  it("says when nothing is waiting, and counts the actions waiting in a tile", async () => {
    renderWithProviders(<Dashboard />, { whoami: viewer([]) });
    expect(await screen.findByText("Nothing is waiting for you")).toBeTruthy();
    await waitFor(() => expect(tile("Waiting for you")?.textContent).toContain("0"));
    expect(tile("Waiting for you")?.getAttribute("href")).toBe("/actions");
    expect(screen.getByRole("link", { name: /All actions/ }).getAttribute("href")).toBe(
      "/actions?tab=waitingForMe",
    );
  });

  it("lists a waiting action, never showing a summary it could not verify", async () => {
    reads.actions = [
      {
        actionId: "ack-1",
        category: "acknowledge",
        kind: "operatorWrite",
        typeUri: "https://trusttasks.org/spec/vtc/operator/offline-write/0.1",
        requester: "did:webvh:Qm1:vtc.example",
        status: "open",
        createdAt: new Date(Date.now() - 2 * 3600_000).toISOString(),
        approvals: [],
        callerRole: "acknowledger",
        payload: {},
        payloadDigest: "00",
        summary: { title: "Made-up title the VTC sent", fields: [] },
      },
    ];
    renderWithProviders(<Dashboard />, { whoami: viewer([]) });
    const link = await screen.findByRole("link", { name: /Summary refused/ });
    expect(link.getAttribute("href")).toBe("/actions?action=ack-1");
    expect(link.textContent).toContain("2 h ago");
    expect(screen.queryByText("Made-up title the VTC sent")).toBeNull();
    const row = link.closest("li")!;
    expect(row.textContent).toContain("Critical");
  });

  it("says when a cooling-off lands, not how long ago", async () => {
    reads.actions = [
      {
        actionId: "cool-1",
        category: "coolingOff",
        kind: "aclReduction",
        typeUri: "https://trusttasks.org/spec/acl/revoke/0.2",
        requester: "did:example:requester",
        status: "open",
        createdAt: new Date(Date.now() - 3600_000).toISOString(),
        landsAt: new Date(Date.now() + 26 * 3600_000).toISOString(),
        cancellableBy: "requester",
        approvals: [],
        callerRole: "observer",
        payload: {},
        payloadDigest: "00",
        summary: { title: "x", fields: [] },
      },
    ];
    renderWithProviders(<Dashboard />, { whoami: viewer([]) });
    const link = await screen.findByRole("link", { name: /Summary refused/ });
    expect(link.textContent).toMatch(/lands in 1 d/);
    expect(link.closest("li")!.textContent).toContain("Cooling off");
  });

  it("puts the daemon, agents and build in Service health, each with a word as well as a dot", async () => {
    renderWithProviders(<Dashboard />, { whoami: viewer([]) });
    await waitFor(() => expect(healthRow("Daemon status")?.textContent).toContain("ok"));
    expect(healthRow("Daemon status")?.textContent).toContain("OK");
    expect(healthRow("Build")?.textContent).toContain("0.0.0");
    expect(healthRow("VTA")?.textContent).toContain("Not set");
    expect(healthRow("VTA")?.textContent).toContain("Needs attention");
  });
});
