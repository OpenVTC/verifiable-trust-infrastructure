// `/admin/enrol-approver#token=…`: the invited subject's wallet signs
// `redeem/start` and `redeem/finish` as their own DID, and the plugin's
// approver proves possession over the start's challenge.

import { fireEvent, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  APPROVER_REDEEM_FINISH_TASK,
  APPROVER_REDEEM_START_TASK,
} from "@/lib/step-up-approvers";
import { mockFetch, renderWithProviders, sentPayloads, taskRoute } from "@/test/render";

import { EnrolApproverPage } from "./EnrolApprover";

const VTC_DID = "did:webvh:QmVtcScid7:acme-vtc.example";
const ALICE = "did:webvh:QmAliceScid4:wallet.example:alice";
const APPROVER = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
const TOKEN = "sua_9c2e1f7a6b3d4c8e9a1b2d3e4f5a6b7c8d9e0f1a";
const STARTED = {
  enrollmentId: "enr_5b0e3a2e6f4c4b8f9d2a1f0c2b7e4a01",
  challenge: "RW5yb2xDaGFsbGVuZ2VOb25jZTAxMjM0NTY",
  audience: VTC_DID,
  expiresAt: "2026-10-01T15:08:01Z",
};

function installWallet() {
  const signTrustTask = vi.fn(
    async ({ envelope, asDid }: { envelope: Record<string, unknown>; asDid?: string }) => ({
      signedEnvelope: {
        ...envelope,
        proof: { type: "DataIntegrityProof", verificationMethod: `${asDid}#key-1` },
      },
      holderDid: asDid!,
    }),
  );
  const attestApprover = vi.fn(async (p: Record<string, string>) => ({
    approverDid: APPROVER,
    statement: {
      id: "urn:uuid:s",
      type: "https://trusttasks.org/spec/auth/step-up/approver/attest/0.1",
      issuer: APPROVER,
      recipient: p.audience,
      issuedAt: "2026-10-01T15:04:00Z",
      payload: { ...p },
      proof: { type: "DataIntegrityProof" },
    },
  }));
  (window as unknown as { vtaWallet: unknown }).vtaWallet = {
    login: vi.fn(),
    signTrustTask,
    approverIdentity: vi.fn(async () => ({ approverDid: APPROVER })),
    attestApprover,
    walletProfile: vi.fn(async () => ({ did: ALICE, entryId: "e1", bound: false })),
  };
  return { signTrustTask, attestApprover };
}

afterEach(() => {
  delete (window as unknown as { vtaWallet?: unknown }).vtaWallet;
  vi.unstubAllGlobals();
});

const mount = (hash: string) =>
  renderWithProviders(<EnrolApproverPage />, {
    route: `/enrol-approver${hash}`,
    path: "/enrol-approver",
  });

describe("enrol approver page", () => {
  it("redeems the invite as the wallet's persona and binds the plugin's approver", async () => {
    const { signTrustTask, attestApprover } = installWallet();
    const requests = mockFetch([
      { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } },
      taskRoute(APPROVER_REDEEM_START_TASK, STARTED),
      taskRoute(APPROVER_REDEEM_FINISH_TASK, {
        approver: {
          approverDid: APPROVER,
          subject: ALICE,
          enrolledAt: "2026-10-01T15:04:06Z",
          enrolledVia: "invite",
        },
      }),
    ]);
    mount(`#token=${TOKEN}`);
    const did = (await screen.findByDisplayValue(ALICE)) as HTMLInputElement;
    expect(did.value).toBe(ALICE);
    fireEvent.change(screen.getByLabelText("Claim code"), { target: { value: " 7KQ4-MX2P-9TDA " } });
    fireEvent.click(screen.getByRole("button", { name: /Enrol the approver/ }));
    await screen.findByText("Enrolled");

    expect(sentPayloads(requests, APPROVER_REDEEM_START_TASK)).toEqual([
      { token: TOKEN, claimCode: "7KQ4-MX2P-9TDA" },
    ]);
    expect(attestApprover).toHaveBeenCalledWith({
      purpose: "enrol",
      subject: ALICE,
      audience: VTC_DID,
      challenge: STARTED.challenge,
      boundTo: STARTED.enrollmentId,
    });
    const [finish = {}] = sentPayloads(requests, APPROVER_REDEEM_FINISH_TASK) as Record<
      string,
      unknown
    >[];
    expect(finish.enrollmentId).toBe(STARTED.enrollmentId);
    expect(finish.approverDid).toBe(APPROVER);
    expect((finish.statement as { issuer: string }).issuer).toBe(APPROVER);
    // Both legs signed by the wallet as the invited subject's own DID.
    expect(signTrustTask.mock.calls.map((c) => c[0].asDid)).toEqual([ALICE, ALICE]);
    const docs = requests.filter((r) => r.url === "/v1/trust-tasks");
    expect(docs.every((r) => (r.body as { issuer: string }).issuer === ALICE)).toBe(true);
  });

  it("explains a wrong claim code", async () => {
    installWallet();
    mockFetch([
      { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } },
      {
        method: "POST",
        path: "/v1/trust-tasks",
        status: 422,
        body: {
          type: "https://trusttasks.org/spec/trust-task-error/0.5",
          payload: {
            code: "auth/step-up/approver/redeem/start:codeMismatch",
            message: "the claim code is wrong",
            details: { attemptsRemaining: 2 },
          },
        },
      },
    ]);
    mount(`#token=${TOKEN}`);
    await screen.findByDisplayValue(ALICE);
    fireEvent.change(screen.getByLabelText("Claim code"), { target: { value: "WRONG" } });
    fireEvent.click(screen.getByRole("button", { name: /Enrol the approver/ }));
    expect((await screen.findByRole("alert")).textContent).toMatch(
      /claim code is wrong\. 2 attempts left/,
    );
  });

  it("names the plugin it needs when the wallet cannot enrol an approver", () => {
    mount(`#token=${TOKEN}`);
    expect(screen.getByText(/The VTA browser plugin is needed/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Enrol the approver/ })).toBeNull();
  });

  it("says so when the link carries no invite", () => {
    installWallet();
    mount("");
    expect(screen.getByText(/carries no invite/)).toBeTruthy();
  });
});
