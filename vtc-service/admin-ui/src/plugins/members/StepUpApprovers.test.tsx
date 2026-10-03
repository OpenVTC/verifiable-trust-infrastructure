// The approver devices card: listed through the signed `list/0.1`, and the
// invite never offered for oneself.

import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { postSignedTrustTask, type WhoamiResponse } from "@/lib/api";
import { APPROVER_LIST_TASK } from "@/lib/step-up-approvers";
import { mockFetch, renderWithProviders } from "@/test/render";

import { ApproverDevicesCard } from "./StepUpApprovers";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedTrustTask: vi.fn(),
}));

const ADMIN = "did:webvh:QmDana:dana.dev";
const ALICE = "did:webvh:QmAlice:alice.dev";
const whoami = (did: string): WhoamiResponse => ({
  session: { id: "s", subject: did, issuedAt: "2026-10-02T09:00:00Z", expiresAt: "2026-10-02T10:00:00Z" },
  roles: ["admin"],
  scopes: [],
});

beforeEach(() => {
  vi.mocked(postSignedTrustTask).mockReset();
  mockFetch([]);
  vi.mocked(postSignedTrustTask).mockResolvedValue({
    approvers: [
      {
        approverDid: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        subject: ALICE,
        label: "Browser plugin — work laptop",
        enrolledAt: "2026-10-01T15:04:06Z",
        enrolledVia: "invite",
      },
    ],
  });
});

describe("ApproverDevicesCard", () => {
  it("lists a member's approvers and offers an administrator the invite", async () => {
    renderWithProviders(<ApproverDevicesCard did={ALICE} />, { whoami: whoami(ADMIN) });
    expect(await screen.findByText("Browser plugin — work laptop")).toBeTruthy();
    expect(screen.getByText("administrator's invite")).toBeTruthy();
    expect(postSignedTrustTask).toHaveBeenCalledWith(APPROVER_LIST_TASK, { subject: ALICE });
    expect(screen.getByText("Invite to enrol an approver")).toBeTruthy();
  });

  it("never offers an administrator an invite for themselves", async () => {
    renderWithProviders(<ApproverDevicesCard did={ADMIN} />, { whoami: whoami(ADMIN) });
    await screen.findByText("Browser plugin — work laptop");
    expect(screen.queryByText("Invite to enrol an approver")).toBeNull();
  });

  it("lists one's own with an empty payload, and says what is needed to add one", async () => {
    renderWithProviders(<ApproverDevicesCard did={ADMIN} self />, { whoami: whoami(ADMIN) });
    await screen.findByText("Browser plugin — work laptop");
    expect(postSignedTrustTask).toHaveBeenCalledWith(APPROVER_LIST_TASK, {});
    expect(screen.getByText(/needs the VTA browser plugin with approver support/)).toBeTruthy();
  });
});
