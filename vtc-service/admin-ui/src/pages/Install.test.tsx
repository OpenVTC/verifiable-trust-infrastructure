// `/admin/install?token=…`. With claim 0.3, a founder who already holds a DID
// in a VTA wallet claims under it: `start/0.3` is unsigned, the plugin's
// approver signs its enrolment statement over the start's challenge bound to
// the claimId, the wallet signs `finish/0.3` as the founder's DID, and the
// bootstrap follows. With the passkey install
// (`vtc/install/claim/passkey/{start,finish}/0.1`), the page creates a
// passkey, signs one assertion with it over the second challenge, and the
// administrator's DID is the passkey's own key.

import { fireEvent, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { mockFetch, renderWithProviders, sentPayloads, taskRoute } from "@/test/render";

import {
  Install,
  invitationKind,
  TRUST_TASK_BOOTSTRAP,
  TRUST_TASK_FINISH,
  TRUST_TASK_FINISH_V0_3,
  TRUST_TASK_START,
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

    // The bootstrap.
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
          type: "https://trusttasks.org/spec/trust-task-error/0.6",
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

/** An install token whose claims are `claims` (the signature is not checked here). */
function jwt(claims: Record<string, unknown>): string {
  const b64 = btoa(JSON.stringify(claims))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `eyJhbGciOiJFZERTQSJ9.${b64}.c2ln`;
}

const mountWith = (token: string) =>
  renderWithProviders(<Install />, { route: `/install?token=${token}`, path: "/install" });

describe("which ceremony the token is for", () => {
  it("reads a wallet invitation by the DID it names, a passkey one by naming none", () => {
    expect(invitationKind(jwt({ admin_did: FOUNDER }))).toBe("wallet");
    expect(invitationKind(jwt({ admin_did: "" }))).toBe("passkey");
    expect(invitationKind(jwt({}))).toBe("passkey");
    expect(invitationKind(TOKEN)).toBeUndefined();
  });

  it("offers only the wallet for a wallet invitation", () => {
    installWallet();
    mountWith(jwt({ admin_did: FOUNDER }));
    expect(screen.getByRole("button", { name: "Claim with my VTA wallet" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /passkey|Continue/ })).toBeNull();
  });

  // The extension adds its provider as a module script, which may run after
  // the page has rendered: the button must appear when it does.
  it("offers the wallet once a provider that arrives after the first render is there", async () => {
    mountWith(jwt({ admin_did: FOUNDER }));
    expect(screen.queryByRole("button", { name: "Claim with my VTA wallet" })).toBeNull();
    expect(screen.getByText(/This page cannot see the plugin/)).toBeTruthy();
    installWallet();
    expect(await screen.findByRole("button", { name: "Claim with my VTA wallet" })).toBeTruthy();
    expect(screen.queryByText(/This page cannot see the plugin/)).toBeNull();
  });

  it("offers only a passkey for a passkey invitation, wallet or not", () => {
    installWallet();
    mountWith(jwt({ admin_did: "" }));
    expect(screen.queryByRole("button", { name: "Claim with my VTA wallet" })).toBeNull();
    expect(screen.getByRole("button", { name: "Continue" })).toBeTruthy();
  });
});

describe("the passkey install", () => {
  const PASSKEY_DID = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
  const RAW_ID = new Uint8Array([1, 2, 3, 4]).buffer;
  const STARTED_PASSKEY = {
    registrationId: "3f2a9c1e-5b7d-4e8f-a0b1-c2d3e4f5a6b7",
    options: {
      publicKey: {
        rp: { id: "acme-vtc.example", name: "Acme" },
        challenge: "Q3JlYXRpb25DaGFsbGVuZ2U",
        user: { id: "PyqcHlt9To-gscLT5PWmtw", name: "first administrator", displayName: "first administrator" },
        pubKeyCredParams: [
          { type: "public-key", alg: -8 },
          { type: "public-key", alg: -7 },
        ],
      },
    },
    assertionOptions: {
      publicKey: {
        rpId: "acme-vtc.example",
        challenge: "UG9zc2Vzc2lvbkNoYWxsZW5nZQ",
        userVerification: "required",
      },
    },
  };

  function stubAuthenticator() {
    const bytes = (n: number) => new Uint8Array([n, n, n]).buffer;
    const create = vi.fn(async () => ({
      id: "AQIDBA",
      rawId: RAW_ID,
      type: "public-key",
      response: { attestationObject: bytes(7), clientDataJSON: bytes(8) },
    }));
    const get = vi.fn(async () => ({
      id: "AQIDBA",
      rawId: RAW_ID,
      type: "public-key",
      response: {
        authenticatorData: bytes(1),
        clientDataJSON: bytes(2),
        signature: bytes(3),
        userHandle: null,
      },
    }));
    vi.stubGlobal("navigator", { ...navigator, credentials: { create, get } });
    return { create, get };
  }

  it("registers the passkey, proves possession with it, and bootstraps", async () => {
    const { create, get } = stubAuthenticator();
    const token = jwt({ admin_did: "" });
    const requests = mockFetch([
      HEALTH,
      taskRoute(TRUST_TASK_START, STARTED_PASSKEY),
      taskRoute(TRUST_TASK_FINISH, { adminDid: PASSKEY_DID, setupSessionToken: "sst.jwt" }),
      taskRoute(TRUST_TASK_BOOTSTRAP, { adminDid: PASSKEY_DID, eventId: "evt" }),
    ]);
    mountWith(token);
    fireEvent.change(screen.getByLabelText("Claim code"), { target: { value: "abcd" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByText(PASSKEY_DID);

    expect(sentPayloads(requests, TRUST_TASK_START)).toEqual([
      { installToken: token, claimSecret: "ABCD" },
    ]);
    expect(create).toHaveBeenCalledTimes(1);
    // The assertion names only the credential just created, over start's
    // second challenge.
    expect(get).toHaveBeenCalledTimes(1);
    const request = (get.mock.calls[0] as unknown as [{ publicKey: PublicKeyCredentialRequestOptions }])[0]
      .publicKey;
    expect(request.rpId).toBe("acme-vtc.example");
    expect(request.allowCredentials).toEqual([{ type: "public-key", id: RAW_ID }]);
    expect(new Uint8Array(request.challenge as ArrayBuffer)).toEqual(
      new Uint8Array(
        [..."PossessionChallenge"].map((c) => c.charCodeAt(0)),
      ),
    );

    const [finish] = sentPayloads(requests, TRUST_TASK_FINISH) as Array<Record<string, unknown>>;
    expect(finish!.installToken).toBe(token);
    expect(finish!.registrationId).toBe(STARTED_PASSKEY.registrationId);
    expect((finish!.webauthnResponse as { rawId: string }).rawId).toBe("AQIDBA");
    expect(finish!.webauthnAssertion).toEqual({
      id: "AQIDBA",
      rawId: "AQIDBA",
      type: "public-key",
      response: {
        authenticatorData: "AQEB",
        clientDataJSON: "AgIC",
        signature: "AwMD",
        userHandle: null,
      },
    });
    expect(sentPayloads(requests, TRUST_TASK_BOOTSTRAP)).toEqual([
      { setupSessionToken: "sst.jwt" },
    ]);
  });

  it("explains an assertion that did not prove possession", async () => {
    stubAuthenticator();
    mockFetch([
      HEALTH,
      taskRoute(TRUST_TASK_START, STARTED_PASSKEY),
      {
        method: "POST",
        path: "/v1/trust-tasks",
        task: TRUST_TASK_FINISH,
        status: 422,
        body: {
          type: "https://trusttasks.org/spec/trust-task-error/0.6",
          payload: {
            code: "vtc/install/claim/passkey/finish:possessionUnproven",
            message: "the assertion does not prove possession",
          },
        },
      },
    ]);
    mountWith(jwt({ admin_did: "" }));
    fireEvent.change(screen.getByLabelText("Claim code"), { target: { value: "abcd" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText("Your passkey did not prove itself")).toBeTruthy();
  });
});
