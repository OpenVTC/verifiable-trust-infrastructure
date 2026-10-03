import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Acl } from "@/plugins/acl";
import {
  mockFetch,
  renderWithProviders,
  sentPayloads,
  taskRoute,
} from "@/test/render";

// The grant is a signed document; the stand-in sends it unsigned so the table
// below answers it without a console key.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));
vi.mock("@/lib/signed-act", async (original) => ({
  ...(await original<typeof import("@/lib/signed-act")>()),
  postSignedWithStepUp: (await import("@/test/signed-read")).unsignedTask,
}));

const GRANT = "https://trusttasks.org/spec/acl/grant/0.2";
const LIST = "https://trusttasks.org/spec/acl/list/0.2";

// The payload schema types `label` and `expiresAt` as strings, so a blank
// optional field must be absent from the request, never `null` (a 400).
describe("New ACL entry — blank optional fields", () => {
  it("omits label and expiresAt rather than sending null", async () => {
    const requests = mockFetch([
      taskRoute(LIST, { entries: [], truncated: false }),
      taskRoute(GRANT, {
        entry: {
          subject: "did:example:test",
          role: "member",
          act: { scope: "none" },
          keys: { scope: "none" },
          capabilities: { scope: "none" },
          approve: { scope: "none" },
        },
      }),
    ]);
    renderWithProviders(<Acl />, { route: "/acl", path: "/acl" });

    fireEvent.click(await screen.findByRole("button", { name: /add entry/i }));
    const did = await screen.findByPlaceholderText("did:key:z6Mk…");
    fireEvent.change(did, { target: { value: "did:example:test" } });
    fireEvent.click(screen.getByRole("button", { name: /create entry/i }));

    await waitFor(() => expect(sentPayloads(requests, GRANT)).toHaveLength(1));
    const payload = (
      sentPayloads(requests, GRANT) as { entry: Record<string, unknown> }[]
    )[0]!;
    expect(payload.entry).toEqual({
      subject: "did:example:test",
      role: "member",
      act: { scope: "none" },
      keys: { scope: "none" },
      capabilities: { scope: "none" },
      approve: { scope: "none" },
    });
    expect("label" in payload.entry).toBe(false);
    expect("expiresAt" in payload.entry).toBe(false);
  });
});


// The Access-control page names an entry's administrative role and what it
// administers — "everything" only for a community administrator with its full
// ceiling (#746) — and Add entry grants a role narrowed to the capabilities
// ticked, with a resource where one is given.
describe("Access control — roles and capabilities", () => {
  const row = (subject: string, role: string, capabilities: unknown, act = "all") => ({
    subject,
    role,
    act: { scope: act },
    keys: { scope: "none" },
    capabilities,
    approve: { scope: "none" },
    ext: { "org.openvtc": { communityRole: role === "community-admin" ? "admin" : "member" } },
  });

  it("shows everything only for a full-ceiling community administrator", async () => {
    mockFetch([
      taskRoute(LIST, {
        entries: [
          row("did:example:ca", "community-admin", { scope: "ceiling" }),
          row("did:example:mem", "member", { scope: "none" }, "none"),
          row("did:example:rm", "repo-manager", {
            scope: "listed",
            grants: [{ capability: "git.repo.manage", resource: "git-ns:github.com/acme" }],
          }),
        ],
        truncated: false,
      }),
    ]);
    renderWithProviders(<Acl />, { route: "/acl", path: "/acl" });
    const cells = await screen.findAllByTestId("administers");
    expect(cells.map((c) => c.textContent)).toEqual([
      "everything",
      "nothing",
      "git.repo.manage@git-ns:github.com/acme",
    ]);
    expect(screen.queryByText("Contexts")).toBeNull();
  });

  it("grants an administrative role narrowed to a qualified capability", async () => {
    const requests = mockFetch([
      taskRoute(LIST, { entries: [], truncated: false }),
      taskRoute(GRANT, {
        entry: row("did:example:rm", "repo-manager", {
          scope: "listed",
          grants: [{ capability: "git.repo.manage", resource: "git-ns:github.com/acme" }],
        }),
      }),
    ]);
    renderWithProviders(<Acl />, { route: "/acl", path: "/acl" });

    fireEvent.click(await screen.findByRole("button", { name: /add entry/i }));
    fireEvent.change(await screen.findByPlaceholderText("did:key:z6Mk…"), {
      target: { value: "did:example:rm" },
    });
    fireEvent.change(screen.getByLabelText("Administrative role"), {
      target: { value: "repo-manager" },
    });
    fireEvent.click(screen.getByLabelText("git.repo.manage"));
    fireEvent.change(screen.getByLabelText("git.repo.manage resource"), {
      target: { value: "git-ns:github.com/acme" },
    });
    fireEvent.click(screen.getByRole("button", { name: /create entry/i }));

    await waitFor(() => expect(sentPayloads(requests, GRANT)).toHaveLength(1));
    const payload = (sentPayloads(requests, GRANT) as { entry: Record<string, unknown> }[])[0]!;
    expect(payload.entry.role).toBe("repo-manager");
    expect(payload.entry.act).toEqual({ scope: "all" });
    expect(payload.entry.capabilities).toEqual({
      scope: "listed",
      grants: [{ capability: "git.repo.manage", resource: "git-ns:github.com/acme" }],
    });
  });
});
