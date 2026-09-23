import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  fetchHealth: vi.fn().mockResolvedValue({ vtc_did: "did:webvh:Qm:vtc.example" }),
  daemonErrorMessage: vi.fn().mockResolvedValue("principal DID not in ACL"),
}));

import { loginWithWalletProfile, SignInAsError } from "@/lib/wallet";

const PERSONA = "did:key:z6MkPersona";

function stubWallet(bound: boolean) {
  window.vtaWallet = {
    login: vi.fn(),
    vaultList: vi.fn(),
    proxyLogin: vi.fn(),
    walletProfile: vi.fn().mockResolvedValue({ did: PERSONA, entryId: "e1", bound }),
  };
}

// Keyring Q13: a refused VTA-identity sign-in has to name the DID it presented.
// It is what the ACL must admit, and nothing else on the page shows it.
describe("loginWithWalletProfile refusal", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("{}", { status: 403 })),
    );
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    delete window.vtaWallet;
  });

  it("carries the presented DID on a repeat sign-in", async () => {
    stubWallet(false);
    const err = await loginWithWalletProfile().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SignInAsError);
    expect((err as SignInAsError).presentedDid).toBe(PERSONA);
    expect((err as Error).message).toContain("403");
  });

  it("names the DID in the message on a first sign-in", async () => {
    stubWallet(true);
    const err = await loginWithWalletProfile().catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(SignInAsError);
    expect((err as Error).message).toContain(`first sign-in as ${PERSONA}`);
  });
});
