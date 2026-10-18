import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/console-key", async (orig) => ({
  ...(await orig<typeof import("@/lib/console-key")>()),
  loadMemberSessionKey: vi.fn(async () => null),
}));

import { DirectoryError, showCard } from "./directory-api";

describe("the portal's directory client", () => {
  it("asks for a wallet sign-in when this browser holds no delegated key", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const err = await showCard().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DirectoryError);
    expect((err as DirectoryError).code).toBe("noKey");
    expect((err as DirectoryError).needsWallet).toBe(true);
    // Nothing is sent unsigned.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("reads a refusal the VTC answers to a key that delegates nothing as needing the wallet", () => {
    expect(new DirectoryError("notMember", "x").needsWallet).toBe(true);
    expect(new DirectoryError("permissionDenied", "x").needsWallet).toBe(true);
    expect(new DirectoryError("superseded", "x").needsWallet).toBe(false);
  });
});
