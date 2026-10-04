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

  // The roles form layout: each capability's checkbox sits on the same line as
  // its text, left-aligned (no `.row-actions`, which right-aligns), and the
  // approve toggle is a checkbox label, not a column `.field`.
  it("lays each checkbox out beside its label", async () => {
    mockFetch([taskRoute(LIST, { entries: [], truncated: false })]);
    renderWithProviders(<Acl />, { route: "/acl", path: "/acl" });
    fireEvent.click(await screen.findByRole("button", { name: /add entry/i }));
    fireEvent.change(await screen.findByLabelText("Administrative role"), {
      target: { value: "community-admin" },
    });
    const box = screen.getByLabelText("vtc.roles.assign");
    const label = box.closest("label")!;
    expect(label.className).toBe("checkbox");
    expect(label.closest(".row-actions")).toBeNull();
    expect(label.querySelector(".checkbox-text .chip")?.textContent).toBe("confers authority");
    const approve = screen.getByText("May approve others' actions within this role").closest("label")!;
    expect(approve.className).toBe("checkbox");
  });
});

// VTI-ACL-052: your own entry. Its label is always yours to change (item 2);
// anything else only in single-administrator mode while the entry is
// unrestricted (item 3) — otherwise the console says why rather than letting
// the VTC answer 403. A label its subject set shows as self-set.
describe("Access control — your own entry (VTI-ACL-052)", () => {
  const ME = "did:example:me";
  const UPDATE = "https://trusttasks.org/spec/acl/update/0.2";
  const ACTIONS_LIST = "https://trusttasks.org/spec/vtc/admin/actions/list/0.2";
  const whoami = {
    session: {
      id: "s1",
      subject: ME,
      issuedAt: "2026-10-02T10:00:00Z",
      expiresAt: "2099-10-02T10:15:00Z",
    },
    roles: ["admin"],
    scopes: [],
  };
  const mine = (label?: string, selfSet = false) => ({
    subject: ME,
    role: "community-admin",
    act: { scope: "all" },
    keys: { scope: "none" },
    capabilities: { scope: "ceiling" },
    approve: { scope: "all" },
    ...(label ? { label } : {}),
    ext: {
      "org.openvtc": { communityRole: "admin", ...(selfSet ? { labelSetBySubject: true } : {}) },
    },
  });
  const render = (singleAdminMode: boolean, entry = mine()) => {
    const requests = mockFetch([
      taskRoute(LIST, { entries: [entry], truncated: false }),
      taskRoute(ACTIONS_LIST, {
        actions: [],
        counts: { waitingForMe: 0, requestedByMe: 0 },
        ext: { "org.openvtc": { singleAdminMode } },
      }),
      taskRoute(UPDATE, { entry: mine("laptop", true) }),
    ]);
    renderWithProviders(<Acl />, {
      route: "/acl",
      path: "/acl",
      whoami: whoami as never,
    });
    return requests;
  };

  it("lets you relabel your own entry", async () => {
    const requests = render(false);
    fireEvent.click(await screen.findByTitle("Click to edit label"));
    const input = await screen.findByDisplayValue("");
    fireEvent.change(input, { target: { value: "laptop" } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(sentPayloads(requests, UPDATE)).toHaveLength(1));
    expect(sentPayloads(requests, UPDATE)[0]).toMatchObject({ subject: ME, label: "laptop" });
  });

  it("does not offer other edits of your own entry outside single-administrator mode, and says why", async () => {
    render(false);
    expect(await screen.findByText("you")).toBeTruthy();
    const edit = screen.getByRole("button", { name: "Edit" }) as HTMLButtonElement;
    expect(edit.disabled).toBe(true);
    expect(edit.getAttribute("title")).toMatch(/You can change its label/);
    expect(screen.getByText(/made by another administrator \(VTI-ACL-052\)/)).toBeTruthy();
    const revoke = screen.getByRole("button", { name: "Revoke" }) as HTMLButtonElement;
    expect(revoke.disabled).toBe(true);
  });

  it("offers them in single-administrator mode while your entry is unrestricted", async () => {
    render(true);
    await screen.findByText("you");
    await waitFor(() =>
      expect((screen.getByRole("button", { name: "Edit" }) as HTMLButtonElement).disabled).toBe(
        false,
      ),
    );
    expect(screen.getByRole("button", { name: "Edit" }).getAttribute("title")).toMatch(
      /passkey gesture, bound to this change/,
    );
  });

  it("shows a label its subject set as self-set", async () => {
    render(false, mine("laptop", true));
    expect(await screen.findByText("self-set")).toBeTruthy();
  });
});
