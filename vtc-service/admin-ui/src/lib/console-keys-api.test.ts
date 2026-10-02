// Enrolment, listing and revocation as the signed documents they send.
//
// The things worth asserting: the enrolment names the key this browser can
// actually sign with and the identity the session belongs to, it goes through
// the bound step-up (`postSignedWithStepUp`), a browser with no enrolled key
// lists nothing rather than failing, and the status the shell gates on is
// `not-enrolled` only when the VTC said so.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./api", async (original) => ({
  ...(await original<typeof import("./api")>()),
  addressedDocument: vi.fn(),
  fetchWhoami: vi.fn(),
  postSignedRead: vi.fn(),
  postSignedTrustTask: vi.fn(),
}));
vi.mock("./signed-act", async (original) => ({
  ...(await original<typeof import("./signed-act")>()),
  postSignedWithStepUp: vi.fn(),
}));

import { addressedDocument, fetchWhoami, postSignedRead, postSignedTrustTask } from "./api";
import { postSignedWithStepUp } from "./signed-act";
import {
  TASK_SIGNING_KEY_AUTHORIZE,
  TASK_SIGNING_KEY_ENROLL,
  TooManyKeysError,
  TASK_SIGNING_KEY_LIST,
  TASK_SIGNING_KEY_REVOKE,
  enrolThisBrowser,
  listConsoleKeys,
  revokeConsoleKey,
  signingStatus,
} from "./console-keys-api";
import {
  forgetConsoleKey,
  generateConsoleKey,
  loadConsoleKey,
  resetConsoleKeyCacheForTests,
} from "./console-key";

const ADMIN_DID = "did:webvh:QmScid:community.example:alice";
const yes = async () => true;

function signingKey(did: string, patch: Record<string, unknown> = {}) {
  return {
    signingKeyDid: did,
    identityDid: ADMIN_DID,
    scope: "console",
    createdAt: "2026-09-23T10:00:00Z",
    expiresAt: "2026-10-23T10:00:00Z",
    active: true,
    ...patch,
  };
}

beforeEach(() => {
  vi.mocked(fetchWhoami).mockResolvedValue({
    session: { subject: ADMIN_DID },
  } as unknown as Awaited<ReturnType<typeof fetchWhoami>>);
});

afterEach(async () => {
  await forgetConsoleKey();
  resetConsoleKeyCacheForTests();
  vi.mocked(postSignedRead).mockReset();
  vi.mocked(postSignedTrustTask).mockReset();
  vi.mocked(postSignedWithStepUp).mockReset();
});

describe("enrolment", () => {
  it("names this browser's key and the session's identity, through the bound step-up", async () => {
    vi.mocked(postSignedWithStepUp).mockImplementation(async (_t, payload) => ({
      signingKey: signingKey((payload as { signingKeyDid: string }).signingKeyDid, {
        deviceLabel: "Work laptop",
      }),
    }));
    const enrolled = await enrolThisBrowser("  Work laptop  ", yes);
    const held = await loadConsoleKey();
    expect(held).not.toBeNull();
    const [task, payload, gesture] = vi.mocked(postSignedWithStepUp).mock.calls[0]!;
    expect(task).toBe(TASK_SIGNING_KEY_ENROLL);
    expect(payload).toEqual({
      signingKeyDid: held!.consoleDid,
      identityDid: ADMIN_DID,
      scope: "console",
      deviceLabel: "Work laptop",
    });
    expect(gesture).toBe(yes);
    expect(enrolled.key).toMatchObject({
      consoleDid: held!.consoleDid,
      adminDid: ADMIN_DID,
      label: "Work laptop",
      active: true,
    });
    expect(enrolled.durability).toBe("memory");
  });

  // The VTC never enrols a key twice — an expired delegation still answers
  // `alreadyEnrolled` — so reusing the held key made a lapsed browser
  // impossible to re-enrol.
  it("enrols a fresh key, never the one this browser already holds, and omits an empty label", async () => {
    const existing = await generateConsoleKey();
    vi.mocked(postSignedWithStepUp).mockImplementation(async (_t, payload) => ({
      signingKey: signingKey((payload as { signingKeyDid: string }).signingKeyDid),
    }));
    vi.mocked(postSignedTrustTask).mockResolvedValue({});
    await enrolThisBrowser("   ", yes);
    const payload = vi.mocked(postSignedWithStepUp).mock.calls[0]![1] as Record<string, unknown>;
    expect(payload.signingKeyDid).not.toBe(existing.consoleDid);
    expect("deviceLabel" in payload).toBe(false);
    // The new key is this browser's now, and the one it replaced is retired.
    expect((await loadConsoleKey())!.consoleDid).toBe(payload.signingKeyDid);
    expect(vi.mocked(postSignedTrustTask).mock.calls).toEqual([
      [TASK_SIGNING_KEY_REVOKE, { signingKeyDid: existing.consoleDid }],
    ]);
  });

  it("leaves the key this browser held in place when enrolment fails", async () => {
    const existing = await generateConsoleKey();
    vi.mocked(postSignedWithStepUp).mockRejectedValue(new Error("passkey cancelled"));
    await expect(enrolThisBrowser("x", yes)).rejects.toThrow("passkey cancelled");
    expect((await loadConsoleKey())!.consoleDid).toBe(existing.consoleDid);
    expect(postSignedTrustTask).not.toHaveBeenCalled();
  });
});

describe("enrolment authorized by the wallet (enroll/0.2)", () => {
  afterEach(() => {
    delete (window as { vtaWallet?: unknown }).vtaWallet;
  });

  it("carries the identity's wallet-signed terms as `authorization`, with no step-up", async () => {
    const signTrustTask = vi.fn(async ({ envelope }: { envelope: Record<string, unknown>; asDid?: string }) => ({
      signedEnvelope: {
        ...envelope,
        proof: { verificationMethod: `${ADMIN_DID}#key-0`, proofValue: "z1" },
      },
      holderDid: "did:key:z6MkHolder",
    }));
    (window as { vtaWallet?: unknown }).vtaWallet = { login: vi.fn(), signTrustTask };
    vi.mocked(addressedDocument).mockImplementation(async (typeUri, payload, issuer) => ({
      id: "urn:uuid:a",
      type: typeUri,
      issuer,
      recipient: "did:web:community.example",
      issuedAt: "2026-10-02T10:00:00Z",
      payload,
    }));
    vi.mocked(postSignedTrustTask).mockImplementation(async (_t, payload) => ({
      signingKey: signingKey((payload as { signingKeyDid: string }).signingKeyDid),
    }));

    await enrolThisBrowser("Wallet", yes, { evidence: "wallet" });

    expect(postSignedWithStepUp).not.toHaveBeenCalled();
    const [task, payload] = vi.mocked(postSignedTrustTask).mock.calls[0]!;
    expect(task).toBe(TASK_SIGNING_KEY_ENROLL);
    const { authorization, ...terms } = payload as Record<string, unknown>;
    const signed = authorization as Record<string, unknown>;
    expect(signed.type).toBe(TASK_SIGNING_KEY_AUTHORIZE);
    expect(signed.issuer).toBe(ADMIN_DID);
    // The identity signed exactly the terms enrolled.
    expect(signed.payload).toEqual(terms);
    expect(signTrustTask.mock.calls[0]![0].asDid).toBe(ADMIN_DID);
  });

  it("refuses a wallet signature made as somebody else, before sending anything", async () => {
    (window as { vtaWallet?: unknown }).vtaWallet = {
      login: vi.fn(),
      signTrustTask: vi.fn(async ({ envelope }: { envelope: Record<string, unknown> }) => ({
        signedEnvelope: { ...envelope, proof: { verificationMethod: "did:key:z6MkHolder#k" } },
        holderDid: "did:key:z6MkHolder",
      })),
    };
    vi.mocked(addressedDocument).mockImplementation(async (typeUri, payload, issuer) => ({
      id: "urn:uuid:a",
      type: typeUri,
      issuer,
      recipient: "did:web:community.example",
      issuedAt: "2026-10-02T10:00:00Z",
      payload,
    }));
    await expect(enrolThisBrowser("x", yes, { evidence: "wallet" })).rejects.toThrow(
      /different identity/,
    );
    expect(postSignedTrustTask).not.toHaveBeenCalled();
  });
});

describe("at the key cap", () => {
  it("turns tooManyKeys into the list to choose a key to replace from", async () => {
    vi.mocked(postSignedWithStepUp).mockRejectedValue({
      status: 422,
      code: "auth/signing-key/enroll:tooManyKeys",
      message: "full",
      details: {
        maxActiveKeys: 5,
        activeKeys: [{ signingKeyDid: "did:key:z6MkOld", createdAt: "t", expiresAt: "t" }],
      },
    });
    const err = await enrolThisBrowser("x", yes).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TooManyKeysError);
    expect((err as TooManyKeysError).activeKeys[0]!.signingKeyDid).toBe("did:key:z6MkOld");
  });

  it("names the chosen key in `replaces`", async () => {
    vi.mocked(postSignedWithStepUp).mockImplementation(async (_t, payload) => ({
      signingKey: signingKey((payload as { signingKeyDid: string }).signingKeyDid),
    }));
    await enrolThisBrowser("x", yes, { replaces: "did:key:z6MkOld" });
    const payload = vi.mocked(postSignedWithStepUp).mock.calls[0]![1] as Record<string, unknown>;
    expect(payload.replaces).toBe("did:key:z6MkOld");
  });
});

describe("signing status", () => {
  it("is no-key, and sends nothing, when this browser holds no key", async () => {
    expect(await signingStatus(ADMIN_DID)).toEqual({ state: "no-key" });
    expect(postSignedRead).not.toHaveBeenCalled();
  });

  it("is ready when the VTC lists this browser's key as active for this identity", async () => {
    const key = await generateConsoleKey();
    vi.mocked(postSignedRead).mockResolvedValue({ signingKeys: [signingKey(key.consoleDid)] });
    const status = await signingStatus(ADMIN_DID);
    expect(status).toMatchObject({ state: "ready", key: { consoleDid: key.consoleDid } });
  });

  it("is not-enrolled when the VTC does not recognise the key", async () => {
    const key = await generateConsoleKey();
    vi.mocked(postSignedRead).mockRejectedValue({ status: 403, code: "permissionDenied", message: "x" });
    expect(await signingStatus(ADMIN_DID)).toEqual({
      state: "not-enrolled",
      consoleDid: key.consoleDid,
    });
  });

  // A rate limit, an outage or a 5xx says nothing about the key; sending the
  // operator to enrol on one would be the original bug in a new place.
  it("throws, rather than answering not-enrolled, when the check itself fails", async () => {
    await generateConsoleKey();
    vi.mocked(postSignedRead).mockRejectedValue({ status: 429, code: "rateLimited", message: "slow" });
    await expect(signingStatus(ADMIN_DID)).rejects.toMatchObject({ status: 429 });
  });

  it("is other-identity when the key acts for another administrator", async () => {
    const key = await generateConsoleKey();
    vi.mocked(postSignedRead).mockResolvedValue({
      signingKeys: [signingKey(key.consoleDid, { identityDid: "did:key:z6MkBob" })],
    });
    expect(await signingStatus(ADMIN_DID)).toMatchObject({
      state: "other-identity",
      identityDid: "did:key:z6MkBob",
    });
  });

  it("asks for renewal within five days of expiry", async () => {
    const key = await generateConsoleKey();
    const soon = new Date(Date.now() + 2 * 24 * 3600 * 1000).toISOString();
    vi.mocked(postSignedRead).mockResolvedValue({
      signingKeys: [signingKey(key.consoleDid, { expiresAt: soon })],
    });
    expect(await signingStatus(ADMIN_DID)).toMatchObject({ state: "ready", renewSoon: true });
  });
});

describe("listing", () => {
  it("lists nothing, and sends nothing, from a browser with no key", async () => {
    expect(await listConsoleKeys()).toEqual([]);
    expect(postSignedRead).not.toHaveBeenCalled();
  });

  it("returns the identity's keys as the daemon computed them", async () => {
    const key = await generateConsoleKey();
    vi.mocked(postSignedRead).mockResolvedValue({
      signingKeys: [signingKey(key.consoleDid), signingKey("did:key:z6MkOld", { active: false, revokedAt: "2026-09-24T00:00:00Z" })],
    });
    const keys = await listConsoleKeys();
    expect(vi.mocked(postSignedRead).mock.calls[0]![0]).toBe(TASK_SIGNING_KEY_LIST);
    expect(keys.map((k) => [k.consoleDid, k.active])).toEqual([
      [key.consoleDid, true],
      ["did:key:z6MkOld", false],
    ]);
  });

  it("lists nothing when this browser's key speaks for nobody", async () => {
    await generateConsoleKey();
    vi.mocked(postSignedRead).mockRejectedValue({ status: 403, code: "permissionDenied", message: "x" });
    expect(await listConsoleKeys()).toEqual([]);
  });
});

describe("revocation", () => {
  it("forgets the local key when it is this browser's, and not otherwise", async () => {
    const key = await generateConsoleKey();
    vi.mocked(postSignedTrustTask).mockResolvedValue({});
    await revokeConsoleKey("did:key:z6MkAnotherBrowser");
    expect(await loadConsoleKey()).not.toBeNull();
    await revokeConsoleKey(key.consoleDid);
    expect(vi.mocked(postSignedTrustTask).mock.calls[1]).toEqual([
      TASK_SIGNING_KEY_REVOKE,
      { signingKeyDid: key.consoleDid },
    ]);
    expect(await loadConsoleKey()).toBeNull();
  });
});
