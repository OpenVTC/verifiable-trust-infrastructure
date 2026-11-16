// Authorizing another key from the console: the wallet signs it, the console
// hands it over, and nothing is sent.

import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";

vi.mock("@/lib/console-keys-api", async (original) => ({
  ...(await original<typeof import("@/lib/console-keys-api")>()),
  authorizeAnotherKey: vi.fn(),
}));

import { AuthorizeAnotherKey } from "@/plugins/AuthorizeKey";
import { authorizeAnotherKey } from "@/lib/console-keys-api";
import { renderWithProviders } from "@/test/render";

afterEach(() => {
  delete (window as { vtaWallet?: unknown }).vtaWallet;
  vi.mocked(authorizeAnotherKey).mockReset();
});

describe("authorize another key", () => {
  it("says the wallet signs it, and offers no form, without a wallet", () => {
    renderWithProviders(<AuthorizeAnotherKey />);
    expect(screen.getByText(/your wallet signs this/i)).toBeTruthy();
    expect(screen.getByText(/cnm access authorize-key/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /sign with my wallet/i })).toBeNull();
  });

  it("signs the terms entered and shows the authorization to hand over", async () => {
    (window as { vtaWallet?: unknown }).vtaWallet = { login: vi.fn(), signTrustTask: vi.fn() };
    vi.mocked(authorizeAnotherKey).mockResolvedValue({
      document: { type: "authorize", payload: { signingKeyDid: "did:key:z6MkBridge" } },
      usableUntil: new Date("2026-11-09T11:00:00Z"),
    });
    renderWithProviders(<AuthorizeAnotherKey />);

    fireEvent.change(screen.getByPlaceholderText("did:key:z6Mk…"), {
      target: { value: "did:key:z6MkBridge" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign with my wallet/i }));

    expect(await screen.findByText(/authorization signed/i)).toBeTruthy();
    expect(vi.mocked(authorizeAnotherKey).mock.calls[0]![0]).toEqual({
      signingKeyDid: "did:key:z6MkBridge",
      label: "vtc-mcp",
      days: 30,
    });
    const shown = screen.getByLabelText("Signed authorization") as HTMLTextAreaElement;
    expect(JSON.parse(shown.value).payload.signingKeyDid).toBe("did:key:z6MkBridge");
  });

  it("shows why the wallet refused", async () => {
    (window as { vtaWallet?: unknown }).vtaWallet = { login: vi.fn(), signTrustTask: vi.fn() };
    vi.mocked(authorizeAnotherKey).mockRejectedValue(new Error("user denied signing"));
    renderWithProviders(<AuthorizeAnotherKey />);
    fireEvent.change(screen.getByPlaceholderText("did:key:z6Mk…"), {
      target: { value: "did:key:z6MkBridge" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign with my wallet/i }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/user denied signing/);
  });
});
