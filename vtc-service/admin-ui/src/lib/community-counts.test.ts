// The member and pending-join-request counts: one `limit: 1` read each, the
// count being the page's `totalEstimate`.

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
  MEMBERS_LIST_TASK,
  tallyOf,
} from "./community-counts";
import { LIST_LIMIT_MAX } from "./list-limits";

beforeEach(() => {
  vi.mocked(postSignedRead).mockReset();
});

describe("the counts", () => {
  it("ask each listing for one row, within its maximum", () => {
    expect(COUNT_PAGE_SIZE).toBe(1);
    expect(COUNT_PAGE_SIZE).toBeLessThanOrEqual(LIST_LIMIT_MAX[JOIN_REQUESTS_LIST_TASK]!);
    expect(COUNT_PAGE_SIZE).toBeLessThanOrEqual(LIST_LIMIT_MAX[MEMBERS_LIST_TASK]!);
  });

  it("count pending requests in one read, from totalEstimate", async () => {
    vi.mocked(postSignedRead).mockResolvedValueOnce({
      items: [{ status: "pending" }],
      nextCursor: "a",
      totalEstimate: 312,
    });
    expect(await countPendingJoinRequests()).toEqual({ count: 312, more: false });
    expect(vi.mocked(postSignedRead).mock.calls).toEqual([
      [JOIN_REQUESTS_LIST_TASK, { status: "pending", limit: 1 }],
    ]);
  });

  it("count members in one read, from totalEstimate", async () => {
    vi.mocked(postSignedRead).mockResolvedValueOnce({ items: [], nextCursor: null, totalEstimate: 0 });
    expect(await countMembers()).toEqual({ count: 0, more: false });
    expect(vi.mocked(postSignedRead)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(postSignedRead).mock.calls[0]).toEqual([MEMBERS_LIST_TASK, { limit: 1 }]);
  });

  it("report a floor when a VTC gives no total", () => {
    const t = tallyOf({ items: [{}], nextCursor: "more" });
    expect(t).toEqual({ count: 1, more: true });
    expect(formatTally(t)).toBe("1+");
    expect(tallyOf({ items: [], nextCursor: null })).toEqual({ count: 0, more: false });
    expect(formatTally({ count: 4, more: false })).toBe("4");
  });
});
