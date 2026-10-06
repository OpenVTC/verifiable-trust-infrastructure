import { fireEvent, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { RegistryRecordRow } from "@/lib/wire-types";
import { mockFetch, NAME_BOOK_ROUTES, renderWithProviders, taskRoute } from "@/test/render";

import { fetchAllRegistryRecords } from "./records";
import { TrustRecords } from "./TrustRecords";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
}));

const VTC = "did:webvh:QmVtcScidAbcdef:webvh.storm.ws:first-vtc";
const ALICE = "did:webvh:QmAliceScid123:webvh.storm.ws:glance-arrow";
const BOB = "did:webvh:QmBobScid45678:dids.firstperson.dev:stem-wall";

const membership = (entityId: string, recognized = true): RegistryRecordRow => ({
  entityId,
  authorityId: VTC,
  action: "recognise",
  resource: "trust-graph",
  recordType: "recognition",
  recognized,
});
const git = (entityId: string, action: string, resource: string): RegistryRecordRow => ({
  entityId,
  authorityId: VTC,
  action,
  resource,
  recordType: "authorization",
  authorized: true,
});

const ITEMS: RegistryRecordRow[] = [
  membership(ALICE),
  membership(BOB, false),
  git(ALICE, "git.repo.own", "github.com/acme/widgets"),
  git(ALICE, "git.commit.sign", "github.com/acme/widgets"),
  git(BOB, "git.commit.sign", "github.com/acme"),
];

const mount = () => {
  mockFetch(NAME_BOOK_ROUTES);
  renderWithProviders(<TrustRecords items={ITEMS} source="registry" />);
};
const bodyRows = () => within(screen.getByRole("table")).getAllByRole("row").slice(1);

describe("Recognition — every trust record, filterable", () => {
  it("lists memberships and git rights together, the authority stated once", () => {
    mount();
    expect(bodyRows()).toHaveLength(5);
    expect(screen.getByText(/Every record is asserted by/)).toBeTruthy();
    expect(screen.queryByRole("columnheader", { name: /^Authority/ })).toBeNull();
    expect(screen.getAllByText("member of this community")).toHaveLength(2);
    expect(screen.getByText("owner on this repository")).toBeTruthy();
    expect(screen.getByText("committer on this namespace")).toBeTruthy();
    expect(screen.getByText("not recognised")).toBeTruthy();
  });

  it("filters by type, action and assertion", () => {
    mount();
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "git" } });
    expect(bodyRows()).toHaveLength(3);
    fireEvent.change(screen.getByLabelText("Action"), { target: { value: "git.commit.sign" } });
    expect(bodyRows()).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: /Clear filters/ }));
    fireEvent.change(screen.getByLabelText("Asserts"), { target: { value: "no" } });
    expect(bodyRows()).toHaveLength(1);
    expect(bodyRows()[0]!.textContent).toContain("stem-wall");
  });

  it("searches loosely, and narrows to one DID from its row", () => {
    mount();
    fireEvent.change(screen.getByRole("searchbox", { name: "Search" }), {
      target: { value: "acme/widgets" },
    });
    expect(bodyRows()).toHaveLength(2);
    fireEvent.change(screen.getByRole("searchbox", { name: "Search" }), { target: { value: "" } });
    fireEvent.click(
      within(bodyRows().find((r) => r.textContent!.includes("stem-wall"))!).getByRole("button", {
        name: "Show only records for this DID",
      }),
    );
    expect(bodyRows()).toHaveLength(2);
    expect(screen.getByText(/2 of 5 records/)).toBeTruthy();
  });

  it("sorts by a column", () => {
    mount();
    fireEvent.click(screen.getByRole("button", { name: /^Action/ }));
    expect(bodyRows().map((r) => r.querySelector("td + td code")?.textContent)).toEqual([
      "git.commit.sign",
      "git.commit.sign",
      "git.repo.own",
      "recognise",
      "recognise",
    ]);
  });
});

describe("fetchAllRegistryRecords", () => {
  it("follows the cursor to the last page", async () => {
    const TASK = "https://trusttasks.org/spec/vtc/registry/records/list/0.1";
    mockFetch([
      taskRoute(TASK, (payload) =>
        (payload as { cursor?: string }).cursor
          ? { source: "registry", items: [ITEMS[1]], nextCursor: null }
          : { source: "registry", items: [ITEMS[0]], nextCursor: "c1" },
      ),
    ]);
    const all = await fetchAllRegistryRecords("registry");
    expect(all.items).toHaveLength(2);
    expect(all.truncated).toBe(false);
  });
});
