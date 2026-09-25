import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Members } from "@/plugins/members";
import {
  ACCOUNTS,
  BOB,
  member,
  MEMBERS,
  RIGHTS,
} from "@/plugins/repos/fixtures.test-data";
import { mockFetch, renderWithProviders, type MockRoute } from "@/test/render";

// UI-13: the Members page shows each member's git rights and linked forge
// accounts (design §7.1), from the same console projections the Repos plugin
// reads.

const NOBODY = "did:webvh:QmNobody:nobody.dev";

const routes = (
  over: { rightsStatus?: number; rights?: typeof RIGHTS } = {},
): MockRoute[] => [
  {
    path: "/v1/members",
    body: { items: [...MEMBERS, member(NOBODY, "No Rights")], nextCursor: null },
  },
  { path: "/v1/members/removed", body: { removed: [] } },
  { path: /^\/v1\/members\/did%3A[^/?]+(\?|$)/, body: { member: member(BOB, "Bob Mensah") } },
  { path: "/v1/acl", body: { entries: [], truncated: false } },
  {
    path: "/v1/git-ns/rights",
    status: over.rightsStatus,
    body: over.rightsStatus ? { error: "forbidden" } : { rights: over.rights ?? RIGHTS },
  },
  { path: "/v1/git-ns/accounts", body: { accounts: ACCOUNTS } },
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
