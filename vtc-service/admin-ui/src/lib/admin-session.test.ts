// The bearer → cookie bridge as the signed document it sends (#1641).
//
// What matters: the exchange is never sent unsigned or to a bearer route; the
// wallet signs it as the identity that signed in when it can, and this
// browser's console key otherwise; with neither, the operator is told which
// sign-in to use rather than shown a refusal from the VTC.

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("./api", async (original) => ({
  ...(await original<typeof import("./api")>()),
  addressedDocument: vi.fn(),
  postSignedDocument: vi.fn(),
  postSignedTrustTask: vi.fn(),
  signingAvailable: vi.fn(),
}));
vi.mock("./console-key", async (original) => ({
  ...(await original<typeof import("./console-key")>()),
  mintBrowserSessionKey: vi.fn(async () => ({ consoleDid: "did:key:z6MkBrowserSessionKey" })),
  adoptBrowserSessionKey: vi.fn(),
}));
vi.mock("./wallet", async (original) => ({
  ...(await original<typeof import("./wallet")>()),
  isWalletSigningAvailable: vi.fn(),
  signWithWallet: vi.fn(),
}));

import {
  addressedDocument,
  postSignedDocument,
  postSignedTrustTask,
  signingAvailable,
} from "./api";
import { adoptBrowserSessionKey } from "./console-key";
import { isWalletSigningAvailable, signWithWallet } from "./wallet";
import { AdminSessionSigningError, TASK_ADMIN_SESSION, openAdminSession } from "./admin-session";

const SUBJECT = "did:webvh:QmScid:community.example:alice";
const KEY_DID = "did:key:z6MkBrowserSessionKey";
const PAYLOAD = { accessToken: "t", ext: { "org.openvtc": { sessionKey: KEY_DID } } };
const SESSION = { sessionId: "sess-1", expiresAt: 1_800_000_000 };

afterEach(() => {
  vi.mocked(addressedDocument).mockReset();
  vi.mocked(postSignedDocument).mockReset();
  vi.mocked(postSignedTrustTask).mockReset();
  vi.mocked(signingAvailable).mockReset();
  vi.mocked(isWalletSigningAvailable).mockReset();
  vi.mocked(signWithWallet).mockReset();
  vi.mocked(adoptBrowserSessionKey).mockReset();
});

describe("openAdminSession", () => {
  it("has the wallet sign the exchange as the identity that signed in", async () => {
    const unsigned = { type: TASK_ADMIN_SESSION, issuer: SUBJECT, payload: PAYLOAD };
    const signed = { ...unsigned, proof: { verificationMethod: `${SUBJECT}#key-1` } };
    vi.mocked(isWalletSigningAvailable).mockReturnValue(true);
    vi.mocked(addressedDocument).mockResolvedValue(
      unsigned as unknown as Awaited<ReturnType<typeof addressedDocument>>,
    );
    vi.mocked(signWithWallet).mockResolvedValue(signed);
    vi.mocked(postSignedDocument).mockResolvedValue(SESSION);

    await expect(openAdminSession("t", SUBJECT)).resolves.toEqual(SESSION);

    expect(addressedDocument).toHaveBeenCalledWith(
      TASK_ADMIN_SESSION,
      PAYLOAD,
      SUBJECT,
    );
    expect(signWithWallet).toHaveBeenCalledWith(expect.objectContaining(unsigned), SUBJECT);
    expect(postSignedDocument).toHaveBeenCalledWith(signed);
    expect(postSignedTrustTask).not.toHaveBeenCalled();
    // The key is kept only once the VTC has bound it.
    expect(adoptBrowserSessionKey).toHaveBeenCalledWith({ consoleDid: KEY_DID });
  });

  it("signs with this browser's console key when the wallet cannot sign", async () => {
    vi.mocked(isWalletSigningAvailable).mockReturnValue(false);
    vi.mocked(signingAvailable).mockResolvedValue(true);
    vi.mocked(postSignedTrustTask).mockResolvedValue(SESSION);

    await expect(openAdminSession("t", SUBJECT)).resolves.toEqual(SESSION);
    expect(postSignedTrustTask).toHaveBeenCalledWith(TASK_ADMIN_SESSION, PAYLOAD);
    expect(postSignedDocument).not.toHaveBeenCalled();
  });

  it("says which sign-in to use when nothing here can sign", async () => {
    vi.mocked(isWalletSigningAvailable).mockReturnValue(false);
    vi.mocked(signingAvailable).mockResolvedValue(false);

    await expect(openAdminSession("t", SUBJECT)).rejects.toBeInstanceOf(
      AdminSessionSigningError,
    );
    expect(postSignedTrustTask).not.toHaveBeenCalled();
    expect(postSignedDocument).not.toHaveBeenCalled();
    expect(adoptBrowserSessionKey).not.toHaveBeenCalled();
  });
});
