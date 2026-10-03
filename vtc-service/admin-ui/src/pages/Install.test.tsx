// `/admin/install?token=…` with claim 0.3: a founder who already holds a DID
// in a VTA wallet claims under it. `start/0.3` is unsigned, the plugin's
// approver signs its enrolment statement over the start's challenge bound to
// the claimId, the wallet signs `finish/0.3` as the founder's DID, and the
// same bootstrap as 0.2 follows.

import { fireEvent, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { mockFetch, renderWithProviders, sentPayloads, taskRoute } from "@/test/render";

import {
  Install,
  TRUST_TASK_BOOTSTRAP,
  TRUST_TASK_FINISH_V0_3,
  TRUST_TASK_START_V0_3,
} from "./Install";

const VTC_DID = "did:webvh:QmVtcScid7:acme-vtc.example";
const FOUNDER = "did:webvh:QmFounderScid:wallet.example:founder";
const APPROVER = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
const TOKEN = "eyJhbGciOiJFZERTQSJ9.install.token";
const STARTED = {
  claimId: "clm_00112233445566778899aabbccddeeff",
  adminDid: FOUNDER,
  challenge: "Q2xhaW1DaGFsbGVuZ2VOb25jZTAxMjM0NTY",
  audience: VTC_DID,
  expiresAt: "2026-10-03T10:15:00Z",
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
      issuedAt: "2026-10-03T10:01:00Z",
      payload: { ...p },
      proof: { type: "DataIntegrityProof" },
    },
  }));
  (window as unknown as { vtaWallet: unknown }).vtaWallet = {
    login: vi.fn(),
    signTrustTask,
    approverIdentity: vi.fn(async () => ({ approverDid: APPROVER })),
    attestApprover,
  };
  return { signTrustTask, attestApprover };
}

afterEach(() => {
  delete (window as unknown as { vtaWallet?: unknown }).vtaWallet;
  vi.unstubAllGlobals();
});

const mount = () =>
  renderWithProviders(<Install />, { route: `/install?token=${TOKEN}`, path: "/install" });

const HEALTH = { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } };

describe("install claim 0.3 with a VTA wallet", () => {
  it("claims under the founder's DID, enrols the approver and bootstraps", async () => {
    const { signTrustTask, attestApprover } = installWallet();
    const requests = mockFetch([
      HEALTH,
      taskRoute(TRUST_TASK_START_V0_3, STARTED),
      taskRoute(TRUST_TASK_FINISH_V0_3, { adminDid: FOUNDER, setupSessionToken: "sst.jwt" }),
      taskRoute(TRUST_TASK_BOOTSTRAP, { adminDid: FOUNDER, eventId: "evt" }),
    ]);
    mount();
    fireEvent.change(screen.getByLabelText("Claim code"), { target: { value: "abcd-efgh " } });
    fireEvent.click(screen.getByRole("button", { name: "Claim with my VTA wallet" }));
    await screen.findByText(/your wallet's step-up approver is bound to it/);

    // start: unsigned, the token and the code.
    expect(sentPayloads(requests, TRUST_TASK_START_V0_3)).toEqual([
      { token: TOKEN, claimCode: "ABCD-EFGH" },
    ]);
    const startDoc = requests.find(
      (r) => (r.body as { type?: string })?.type === TRUST_TASK_START_V0_3,
    )!.body as { proof?: unknown };
    expect(startDoc.proof).toBeUndefined();

    // The approver's enrolment statement, for the DID the token names.
    expect(attestApprover).toHaveBeenCalledWith({
      purpose: "enrol",
      subject: FOUNDER,
      audience: VTC_DID,
      challenge: STARTED.challenge,
      boundTo: STARTED.claimId,
    });

    // finish: signed by the wallet as the founder, carrying the statement.
    expect(signTrustTask).toHaveBeenCalledTimes(1);
    expect(signTrustTask.mock.calls[0]![0].asDid).toBe(FOUNDER);
    const finishDoc = requests.find(
      (r) => (r.body as { type?: string })?.type === TRUST_TASK_FINISH_V0_3,
    )!.body as {
      issuer: string;
      recipient: string;
      payload: Record<string, unknown>;
      proof: { verificationMethod: string };
    };
    expect(finishDoc.issuer).toBe(FOUNDER);
    expect(finishDoc.recipient).toBe(VTC_DID);
    expect(finishDoc.proof.verificationMethod).toBe(`${FOUNDER}#key-1`);
    expect(finishDoc.payload.claimId).toBe(STARTED.claimId);
    expect(finishDoc.payload.approverDid).toBe(APPROVER);
    expect((finishDoc.payload.statement as { issuer: string }).issuer).toBe(APPROVER);

    // The same bootstrap as 0.2.
    expect(sentPayloads(requests, TRUST_TASK_BOOTSTRAP)).toEqual([
      { setupSessionToken: "sst.jwt" },
    ]);
    expect(screen.getByText(FOUNDER)).toBeTruthy();
  });

  it("explains a refused start without saying which half was wrong", async () => {
    installWallet();
    mockFetch([
      HEALTH,
      {
        method: "POST",
        path: "/v1/trust-tasks",
        task: TRUST_TASK_START_V0_3,
        status: 401,
        body: {
          type: "https://trusttasks.org/spec/trust-task-error/0.5",
          payload: {
            code: "vtc/install/claim/start:invalidToken",
            message: "this install token and claim code do not open a claim",
          },
        },
      },
    ]);
    mount();
    fireEvent.change(screen.getByLabelText("Claim code"), { target: { value: "WRONG" } });
    fireEvent.click(screen.getByRole("button", { name: "Claim with my VTA wallet" }));
    expect(
      await screen.findByText("This install URL and claim code do not open a claim"),
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
  });

  it("keeps the passkey path, and offers only it without a wallet approver", () => {
    mount();
    expect(screen.queryByRole("button", { name: "Claim with my VTA wallet" })).toBeNull();
    expect(screen.getByRole("button", { name: "Continue" })).toBeTruthy();
  });

  it("offers both when the wallet can enrol an approver", () => {
    installWallet();
    mount();
    expect(screen.getByRole("button", { name: "Claim with my VTA wallet" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Register a passkey instead" })).toBeTruthy();
  });
});
