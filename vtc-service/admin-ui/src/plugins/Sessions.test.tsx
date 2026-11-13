import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Sessions } from "@/plugins/sessions";
import {
  mockFetch,
  NAME_BOOK_ROUTES,
  renderWithProviders,
  taskRoute,
  whoamiWith,
} from "@/test/render";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));

const LIST = "https://trusttasks.org/spec/auth/sessions/list/0.1";

describe("Sessions page", () => {
  it("says the list failed, with a retry, instead of 'No active sessions' (#2606)", async () => {
    let fail = true;
    mockFetch([
      ...NAME_BOOK_ROUTES,
      {
        method: "POST",
        path: "/v1/trust-tasks",
        task: LIST,
        status: () => (fail ? 403 : 200),
        body: () =>
          fail
            ? { payload: { code: "forbidden", message: "Not allowed to list sessions" } }
            : {
                payload: {
                  sessions: [
                    {
                      id: "sess_test",
                      subject: "did:key:z6MkViewer",
                      issuedAt: "2026-10-01T00:00:00Z",
                      expiresAt: "2026-10-01T00:05:00Z",
                    },
                  ],
                },
              },
      },
    ]);
    renderWithProviders(<Sessions />, { whoami: whoamiWith(["vtc.sessions.admin"]) });

    expect(await screen.findByText("Couldn't load the sessions")).toBeTruthy();
    expect(screen.getByText("Not allowed to list sessions")).toBeTruthy();
    expect(screen.queryByText("No active sessions")).toBeNull();
    expect(screen.queryByText(/active sessions$/)).toBeNull();

    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(screen.queryByText("Couldn't load the sessions")).toBeNull());
    expect(await screen.findByText("this tab")).toBeTruthy();
  });

  it("still says 'No active sessions' when the list loaded empty", async () => {
    mockFetch([...NAME_BOOK_ROUTES, taskRoute(LIST, { sessions: [] })]);
    renderWithProviders(<Sessions />, { whoami: whoamiWith([]) });
    expect(await screen.findByText("No active sessions")).toBeTruthy();
  });
});
