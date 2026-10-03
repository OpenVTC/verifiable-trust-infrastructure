// The waiting count behind the Actions badge, banner and tab title.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

vi.mock("./api", async (original) => ({
  ...(await original<typeof import("./api")>()),
  postSignedRead: vi.fn(),
}));

import { postSignedRead } from "./api";
import { ACTIONS_LIST_TASK } from "./actions-api";

const listActions = postSignedRead;
import {
  BANNER_DISMISSED_KEY,
  bannerDismissed,
  dismissBanner,
  titleWithCount,
  useWaitingCount,
  waitingSentence,
} from "./action-badge";

const answer = (n: number) =>
  vi.mocked(listActions).mockResolvedValue({
    actions: [],
    counts: { waitingForMe: n, requestedByMe: 0 },
  });

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  document.title = "VTC Admin";
  sessionStorage.clear();
  vi.mocked(listActions).mockReset();
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe("the tab title", () => {
  it("prefixes the count, replaces an old one, and restores the title at zero", () => {
    expect(titleWithCount("VTC Admin", 2)).toBe("(2) VTC Admin");
    expect(titleWithCount("(2) VTC Admin", 5)).toBe("(5) VTC Admin");
    expect(titleWithCount("(5) VTC Admin", 0)).toBe("VTC Admin");
    expect(titleWithCount("VTC Admin", 0)).toBe("VTC Admin");
  });

  it("says how many wait", () => {
    expect(waitingSentence(1)).toBe("1 action waiting for your approval");
    expect(waitingSentence(3)).toBe("3 actions waiting for your approval");
  });
});

describe("useWaitingCount", () => {
  it("reads counts.waitingForMe with a limit-1 waitingForMe list", async () => {
    answer(2);
    const { result } = renderHook(() => useWaitingCount(true), { wrapper });
    await waitFor(() => expect(result.current).toBe(2));
    expect(vi.mocked(listActions)).toHaveBeenCalledWith(ACTIONS_LIST_TASK, {
      view: "waitingForMe",
      limit: 1,
    });
    expect(document.title).toBe("(2) VTC Admin");
  });

  it("refetches when the tab regains focus, and follows the count down", async () => {
    answer(2);
    const { result } = renderHook(() => useWaitingCount(true), { wrapper });
    await waitFor(() => expect(result.current).toBe(2));
    answer(0);
    act(() => {
      window.dispatchEvent(new Event("focus"));
    });
    await waitFor(() => expect(result.current).toBe(0));
    expect(document.title).toBe("VTC Admin");
  });

  it("refetches when the tab becomes visible", async () => {
    answer(1);
    renderHook(() => useWaitingCount(true), { wrapper });
    await waitFor(() => expect(vi.mocked(listActions)).toHaveBeenCalledTimes(1));
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await waitFor(() => expect(vi.mocked(listActions)).toHaveBeenCalledTimes(2));
  });

  it("asks nothing when not an admin who can sign, and counts zero", async () => {
    answer(4);
    const { result } = renderHook(() => useWaitingCount(false), { wrapper });
    expect(result.current).toBe(0);
    expect(vi.mocked(listActions)).not.toHaveBeenCalled();
    expect(document.title).toBe("VTC Admin");
  });

  it("counts zero when the read fails", async () => {
    vi.mocked(listActions).mockRejectedValue(new Error("down"));
    const { result } = renderHook(() => useWaitingCount(true), { wrapper });
    await waitFor(() => expect(vi.mocked(listActions)).toHaveBeenCalled());
    expect(result.current).toBe(0);
  });
});

describe("the banner's dismissal", () => {
  it("lasts for the session", () => {
    expect(bannerDismissed()).toBe(false);
    dismissBanner();
    expect(sessionStorage.getItem(BANNER_DISMISSED_KEY)).toBe("1");
    expect(bannerDismissed()).toBe(true);
  });

  it("survives storage that throws", () => {
    const blocked = () => {
      throw new Error("blocked");
    };
    vi.stubGlobal("sessionStorage", { getItem: blocked, setItem: blocked });
    expect(() => dismissBanner()).not.toThrow();
    expect(bannerDismissed()).toBe(false);
  });
});
