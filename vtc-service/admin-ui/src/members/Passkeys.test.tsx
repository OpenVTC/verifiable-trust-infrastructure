// The portal's passkey card: a failed list is not "no passkeys", and removing
// one is confirmed first (#2607).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ConfirmDialogProvider } from "@/components/ConfirmDialog";
import { mockFetch } from "@/test/render";
import { Passkeys } from "./Passkeys";

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ConfirmDialogProvider look="portal">
        <Passkeys canManage />
      </ConfirmDialogProvider>
    </QueryClientProvider>,
  );
}

const PASSKEY = {
  credentialId: "cred_0123456789abcdef",
  label: "Work laptop",
  registeredAt: "2026-10-02T09:00:00Z",
};

afterEach(() => vi.unstubAllGlobals());

describe("the portal's passkeys", () => {
  it("says the list failed, with a retry, instead of 'No passkeys yet.'", async () => {
    let fail = true;
    mockFetch([
      {
        path: "/v1/member/passkeys",
        status: () => (fail ? 500 : 200),
        body: () => (fail ? { error: "store unavailable" } : [PASSKEY]),
      },
      { method: "POST", path: "/v1/member/auth/refresh", status: 401 },
    ]);
    renderCard();
    expect(await screen.findByText("Your passkeys couldn't be loaded.")).toBeTruthy();
    expect(screen.queryByText("No passkeys yet.")).toBeNull();
    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Work laptop")).toBeTruthy();
  });

  it("removes a passkey only after the member confirms", async () => {
    const requests = mockFetch([
      { path: "/v1/member/passkeys", body: [PASSKEY] },
      { method: "DELETE", path: `/v1/member/passkeys/${PASSKEY.credentialId}`, status: 204 },
    ]);
    const deletes = () => requests.filter((r) => r.method === "DELETE");
    renderCard();
    fireEvent.click(await screen.findByRole("button", { name: "Remove Work laptop" }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(deletes()).toHaveLength(0);

    fireEvent.click(screen.getByRole("button", { name: "Remove Work laptop" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(deletes()).toHaveLength(1));
  });
});
