// `/admin/enrol-step-up`: an invite link points the member at `cnm`, which
// signs the start; the link `cnm` prints back is where the passkey is made.

import { fireEvent, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { redeemFinish, type RedeemStarted } from "@/lib/step-up-passkeys";
import { bufferToBase64url } from "@/lib/webauthn";
import { renderWithProviders } from "@/test/render";

import { EnrolStepUpPage } from "./EnrolStepUp";

vi.mock("@/lib/step-up-passkeys", async (original) => ({
  ...(await original<typeof import("@/lib/step-up-passkeys")>()),
  redeemFinish: vi.fn(),
}));

const TOKEN = "sup_0123456789abcdef0123456789abcdef";
const STARTED = {
  enrollmentId: "e-1",
  subject: "did:webvh:QmCarol:carol.dev",
  purpose: "stepUp",
  deviceLabel: "Carol's laptop",
  options: { challenge: "Y2hhbGxlbmdlLWNyZWF0ZQ" },
  expiresAt: "2026-09-25T12:05:00Z",
} as unknown as RedeemStarted;

const encode = (v: unknown) =>
  bufferToBase64url(new TextEncoder().encode(JSON.stringify(v)).buffer as ArrayBuffer);
const mount = (hash: string) =>
  renderWithProviders(<EnrolStepUpPage />, {
    route: `/enrol-step-up${hash}`,
    path: "/enrol-step-up",
  });

beforeEach(() => vi.mocked(redeemFinish).mockReset());

describe("enrol step-up page", () => {
  it("sends an invite link to cnm, which signs the start as the member", () => {
    mount(`#token=${TOKEN}`);
    const command = screen.getByLabelText("Command to run") as HTMLTextAreaElement;
    expect(command.value).toMatch(/^cnm git enrol-step-up-passkey '.*#token=sup_0123/);
    expect(screen.queryByRole("button", { name: /Create the passkey/ })).toBeNull();
  });

  it("creates the passkey for the DID the start names", async () => {
    vi.mocked(redeemFinish).mockResolvedValue({
      credentialId: "01",
      subject: STARTED.subject,
      purpose: "stepUp",
      registeredAt: "2026-09-25T12:01:00Z",
    });
    mount(`#enrollment=${encode(STARTED)}`);
    expect(screen.getByText(STARTED.subject)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Create the passkey/ }));
    await screen.findByText("Enrolled");
    expect(redeemFinish).toHaveBeenCalledWith(STARTED, undefined);
  });

  it("says so when the link carries neither", () => {
    mount("#nothing=here");
    expect(screen.getByText(/carries no invite/)).toBeTruthy();
  });
});
