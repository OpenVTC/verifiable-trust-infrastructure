// The member and pending-join-request counts: a walk of every page, bounded.

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./api", async (original) => ({
  ...(await original<typeof import("./api")>()),
  postSignedRead: vi.fn(),
}));

import { postSignedRead } from "./api";
import {
  COUNT_PAGE_SIZE,
  countMembers,
  countPendingJoinRequests,
  formatTally,
  JOIN_REQUESTS_LIST_TASK,
  MAX_COUNT_PAGES,
  MEMBERS_LIST_TASK,
} from "./community-counts";
import { LIST_LIMIT_MAX } from "./list-limits";

beforeEach(() => {
  vi.mocked(postSignedRead).mockReset();
});

describe("the counts", () => {
  it("page at each listing's maximum", () => {
    expect(COUNT_PAGE_SIZE).toBeLessThanOrEqual(LIST_LIMIT_MAX[JOIN_REQUESTS_LIST_TASK]!);
    expect(COUNT_PAGE_SIZE).toBeLessThanOrEqual(LIST_LIMIT_MAX[MEMBERS_LIST_TASK]!);
  });

  it("count only pending requests, across every page", async () => {
    vi.mocked(postSignedRead)
      .mockResolvedValueOnce({ items: [{ status: "pending" }], nextCursor: "a" })
      .mockResolvedValueOnce({ items: [{ status: "approved" }, { status: "pending" }], nextCursor: null });
    expect(await countPendingJoinRequests()).toEqual({ count: 2, more: false });
    expect(vi.mocked(postSignedRead).mock.calls).toEqual([
      [JOIN_REQUESTS_LIST_TASK, { status: "pending", limit: 200 }],
      [JOIN_REQUESTS_LIST_TASK, { status: "pending", limit: 200, cursor: "a" }],
    ]);
  });

  it("stop at the bound and report a floor", async () => {
    vi.mocked(postSignedRead).mockResolvedValue({ items: [{ did: "d" }], nextCursor: "more" });
    const t = await countMembers();
    expect(t).toEqual({ count: MAX_COUNT_PAGES, more: true });
    expect(vi.mocked(postSignedRead)).toHaveBeenCalledTimes(MAX_COUNT_PAGES);
    expect(formatTally(t)).toBe(`${MAX_COUNT_PAGES}+`);
    expect(formatTally({ count: 4, more: false })).toBe("4");
  });
});
