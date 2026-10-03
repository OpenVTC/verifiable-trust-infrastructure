// The dashboard's Members and Join requests tiles: each a count linking to its
// screen, shown only to a viewer holding what that screen needs.

import { screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { WhoamiResponse } from "@/lib/api";
import { renderWithProviders } from "@/test/render";

const JOINS = "https://trusttasks.org/spec/vtc/join-requests/list/0.1";
const MEMBERS = "https://trusttasks.org/spec/vtc/members/list/0.1";

const reads = vi.hoisted(() => ({
  calls: [] as [string, Record<string, unknown>][],
  members: 7,
  pending: 2,
  failMembers: false,
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
    return {
      actions: [],
      counts: { waitingForMe: 0, requestedByMe: 0 },
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

beforeEach(() => {
  reads.calls.length = 0;
  reads.members = 7;
  reads.pending = 2;
  reads.failMembers = false;
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
    expect(reads.calls.some(([t]) => t === MEMBERS)).toBe(false);
  });

  it("hides both from a viewer holding neither", async () => {
    renderWithProviders(<Dashboard />, { whoami: viewer(["vtc.audit.read"]) });
    await screen.findByText("Daemon status");
    expect(tile("Members")).toBeNull();
    expect(tile("Join requests")).toBeNull();
    expect(reads.calls.some(([t, p]) => t === MEMBERS || (t === JOINS && p.limit === 200))).toBe(
      false,
    );
  });

  it("says so when the count cannot be read", async () => {
    reads.failMembers = true;
    renderWithProviders(<Dashboard />, { whoami: viewer(["vtc.members.manage"]) });
    await waitFor(() => expect(tile("Members")?.textContent).toContain("Could not count members"));
  });
});
