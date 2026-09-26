// `/admin/step-up#request=…`: the page `cnm` hands a passkey step-up to.

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { postSignedTrustTask, type WhoamiResponse } from "@/lib/api";
import { answerStepUp, encodeStepUpRequest, type StepUpRequest } from "@/lib/bound-step-up";
import { renderWithProviders } from "@/test/render";

import { StepUpPage } from "./StepUp";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedTrustTask: vi.fn(),
}));
vi.mock("@/lib/bound-step-up", async (original) => ({
  ...(await original<typeof import("@/lib/bound-step-up")>()),
  answerStepUp: vi.fn(),
}));

const ADMIN = "did:webvh:QmAlice:alice.dev";
const REQUEST: StepUpRequest = {
  subject: ADMIN,
  challenge: "c2FtcGxlLWNoYWxsZW5nZS0xMjM0NQ",
  boundTo: "zBoundDigest",
  reason: "Break glass: git.ns.admin on github.com/acme",
  acceptableEvidence: ["webauthn"],
  webauthn: { challenge: "c2FtcGxlLWNoYWxsZW5nZS0xMjM0NQ" },
  ttl: 300,
};

const who = (subject: string): WhoamiResponse => ({
  session: { id: "s", subject, issuedAt: "2026-09-01T00:00:00Z", expiresAt: "2026-09-01T00:05:00Z" },
  roles: ["admin"],
  scopes: [],
});

const mount = (hash: string, subject = ADMIN) =>
  renderWithProviders(<StepUpPage />, { route: `/step-up${hash}`, path: "/step-up", whoami: who(subject) });

beforeEach(() => {
  vi.mocked(answerStepUp).mockReset();
  vi.mocked(postSignedTrustTask).mockReset();
});

describe("step-up page", () => {
  it("shows what the gesture authorizes, answers it, and sends the operator back to the terminal", async () => {
    vi.mocked(answerStepUp).mockResolvedValue({ status: "recorded", boundTo: "zBoundDigest" });
    mount(`#request=${encodeStepUpRequest(REQUEST)}`);
    expect(screen.getByText(REQUEST.reason)).toBeTruthy();
    expect(screen.getByText("zBoundDigest")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Confirm with passkey/ }));
    await screen.findByText("Recorded");
    expect(answerStepUp).toHaveBeenCalledWith(REQUEST);
    expect(screen.getByText(/Go back to your terminal/)).toBeTruthy();
  });

  it("warns when this session is not the DID the passkey must belong to", () => {
    mount(`#request=${encodeStepUpRequest(REQUEST)}`, "did:webvh:QmBob:bob.dev");
    expect(screen.getByText("You are signed in as someone else")).toBeTruthy();
  });

  it("can decline, which authorizes nothing", async () => {
    vi.mocked(postSignedTrustTask).mockResolvedValue({ status: "rejected" });
    mount(`#request=${encodeStepUpRequest(REQUEST)}`);
    fireEvent.click(screen.getByRole("button", { name: "Decline" }));
    await waitFor(() =>
      expect(postSignedTrustTask).toHaveBeenCalledWith(
        "https://trusttasks.org/spec/auth/step-up/approve-response/0.4",
        expect.objectContaining({ decision: "denied", challenge: REQUEST.challenge, subject: ADMIN }),
      ),
    );
    await screen.findByText("Declined");
    expect(answerStepUp).not.toHaveBeenCalled();
  });

  it("says so when the link carries no request", () => {
    mount("#request=garbage!");
    expect(screen.getByText(/carries no step-up request/)).toBeTruthy();
  });
});
