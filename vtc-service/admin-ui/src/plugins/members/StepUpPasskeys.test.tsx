// A member's step-up passkeys card: the list is `auth/passkey/admin-list/0.1`,
// signed by this browser's console key — no bearer read.

import { screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { postSignedTrustTask, SigningUnavailableError } from "@/lib/api";
import { ADMIN_LIST_TASK } from "@/lib/step-up-passkeys";
import { mockFetch, renderWithProviders } from "@/test/render";

import { StepUpPasskeysCard } from "./StepUpPasskeys";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedTrustTask: vi.fn(),
}));

const CAROL = "did:webvh:QmCarol:carol.dev";

beforeEach(() => {
  vi.mocked(postSignedTrustTask).mockReset();
});

describe("StepUpPasskeysCard", () => {
  it("lists through the signed admin-list task, with the counter", async () => {
    const requests = mockFetch([]);
    vi.mocked(postSignedTrustTask).mockResolvedValue({
      subject: CAROL,
      purpose: "stepUp",
      credentials: [
        {
          credentialId: "0a0b",
          deviceLabel: "Carol's laptop",
          registeredAt: "2026-09-25T10:04:00Z",
          lastUsedAt: "2026-09-26T21:47:12Z",
          signCount: 14,
        },
      ],
    });
    renderWithProviders(<StepUpPasskeysCard did={CAROL} />);

    expect(await screen.findByText("Carol's laptop")).toBeTruthy();
    expect(screen.getByText("14")).toBeTruthy();
    expect(postSignedTrustTask).toHaveBeenCalledWith(ADMIN_LIST_TASK, {
      subject: CAROL,
      purpose: "stepUp",
    });
    expect(requests.some((r) => r.url.includes("/v1/admin/step-up-passkeys"))).toBe(false);
  });

  it("says so when this browser cannot sign", async () => {
    mockFetch([]);
    vi.mocked(postSignedTrustTask).mockRejectedValue(new SigningUnavailableError("no-key"));
    renderWithProviders(<StepUpPasskeysCard did={CAROL} />);
    await waitFor(() =>
      expect(screen.getByText(/holds no console signing key/)).toBeTruthy(),
    );
  });
});
