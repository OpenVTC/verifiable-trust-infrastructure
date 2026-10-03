import { screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Members } from "@/plugins/members";
import {
  ACCOUNTS,
  BOB,
  member,
  MEMBERS,
  RIGHTS,
} from "@/plugins/repos/fixtures.test-data";
import { TASK_ACCOUNT_LIST, TASK_RIGHT_LIST } from "@/plugins/repos/api";
import {
  MEMBERS_LIST_TASK,
  mockFetch,
  renderWithProviders,
  taskRoute,
  type MockRoute,
} from "@/test/render";

// The member reads are signed documents; the stand-in sends them unsigned so
// the table below answers them without a key.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
}));

// UI-13: the Members page shows each member's git rights and linked forge
// accounts (design §7.1), from the same console projections the Repos plugin
// reads.

const NOBODY = "did:webvh:QmNobody:nobody.dev";

const routes = (
  over: { rightsStatus?: number; rights?: typeof RIGHTS } = {},
): MockRoute[] => [
  taskRoute(MEMBERS_LIST_TASK, {
    items: [...MEMBERS, member(NOBODY, "No Rights")],
    nextCursor: null,
  }),
  taskRoute("https://trusttasks.org/spec/vtc/members/removed/0.1", { removed: [] }),
  taskRoute("https://trusttasks.org/spec/vtc/members/show/0.1", { member: member(BOB, "Bob Mensah") }),
  taskRoute("https://trusttasks.org/spec/acl/list/0.2", { entries: [], truncated: false }),
  taskRoute(
    TASK_RIGHT_LIST,
    over.rightsStatus
      ? { code: "git-ns/right/list:notCommunityAdministrator", message: "forbidden" }
      : { rights: over.rights ?? RIGHTS },
    over.rightsStatus,
  ),
  taskRoute(TASK_ACCOUNT_LIST, { accounts: ACCOUNTS }),
];

const mount = (route = "/members") =>
  renderWithProviders(<Members />, { route, path: "/members/*" });

const rowOf = async (label: string) => {
  const cell = await screen.findByText(label);
  const row = cell.closest("tr");
  if (!row) throw new Error(`no row for ${label}`);
  return row;
};

describe("Members — git rights (UI-13)", () => {
  it("marks an account whose member is no longer current", async () => {
    const r = routes().map((route) =>
      route.task === TASK_ACCOUNT_LIST
        ? {
            ...route,
            body: {
              payload: {
                accounts: ACCOUNTS.map((a) =>
                  a.member === BOB ? { ...a, memberCurrent: false } : a,
                ),
              },
            },
          }
        : route,
    );
    mockFetch(r);
    mount(`/members/${encodeURIComponent(BOB)}`);
    const card = (await screen.findByRole("heading", { name: "Git rights" })).closest("section");
    await within(card!).findByText("@bobm");
    expect(card!.textContent).toContain("not current — no forge role");
  });

  it("adds a Git column with each member's strongest right and linked logins", async () => {
    mockFetch(routes());
    mount();

    expect(await screen.findByRole("columnheader", { name: "Git" })).toBeTruthy();
    // Alice: namespace admin on acme and owner of widgets; linked as @alicew.
    const alice = await rowOf("Alice Wong");
    expect(await within(alice).findByText("Namespace admin")).toBeTruthy();
    expect(alice.textContent).toContain("+1");
    expect(alice.textContent).toContain("@alicew");
    // Priya: a committer with no linked account.
    const priya = await rowOf("Priya Nair");
    expect(await within(priya).findByText("Committer")).toBeTruthy();
    expect(priya.textContent).not.toContain("@");
    // Someone with neither.
    const nobody = await rowOf("No Rights");
    expect(within(nobody).getAllByText("—").length).toBeGreaterThan(0);
  });

  it("drops the column and says why when the rights cannot be read", async () => {
    mockFetch(routes({ rightsStatus: 403 }));
    mount();

    expect(
      await screen.findByText(/Git rights are not shown: only a community administrator/),
    ).toBeTruthy();
    await rowOf("Alice Wong");
    expect(screen.queryByRole("columnheader", { name: "Git" })).toBeNull();
  });

  it("lists a member's rights and linked accounts on their page", async () => {
    mockFetch(routes());
    mount(`/members/${encodeURIComponent(BOB)}`);

    const card = (await screen.findByRole("heading", { name: "Git rights" })).closest("section");
    if (!card) throw new Error("no Git rights card");
    const c = within(card);
    // Strongest first: repo creator on the namespace, then owner of docs.
    const rows = await c.findAllByRole("row");
    expect(rows[1]?.textContent).toContain("Repo creator");
    expect(rows[1]?.textContent).toContain("acme");
    expect(rows[2]?.textContent).toContain("Owner");
    expect(c.getByRole("link", { name: "acme/docs" }).getAttribute("href")).toBe(
      `/repos/repo/${encodeURIComponent("github.com/acme/docs")}`,
    );
    // The namespace-wide right is not a repository and has no repository link.
    expect(c.queryByRole("link", { name: "acme" })).toBeNull();
    expect(c.getByText("@bobm")).toBeTruthy();
    expect(card.textContent).toContain("1002");
    // A current member's account carries no lapsed marker.
    expect(card.textContent).not.toContain("not current");
    // Unlinking is the member's own act: the console names the command.
    expect(card.textContent).toContain("cnm git unlink --forge <host>");
  });

  it("flags a right Bob granted himself by break-glass until it is ratified", async () => {
    const mark = {
      by: BOB,
      at: "2026-09-25T02:10:31Z",
      justification: "Both owners unreachable; CVE fix must ship tonight.",
    };
    const rights = RIGHTS.map((r) =>
      r.subject === BOB && r.right === "git.repo.own" ? { ...r, breakGlass: mark } : r,
    );
    mockFetch(routes({ rights }));
    mount(`/members/${encodeURIComponent(BOB)}`);

    const card = (await screen.findByRole("heading", { name: "Git rights" })).closest("section");
    if (!card) throw new Error("no Git rights card");
    const rows = await within(card).findAllByRole("row");
    const owner = rows.find((r) => r.textContent?.includes("Owner"));
    expect(owner?.textContent).toContain("Break-glass · unratified");
    // The other right carries no flag.
    expect(rows[1]?.textContent).not.toContain("Break-glass");
  });
});
