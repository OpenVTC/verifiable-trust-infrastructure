// What the wallet-verifier screen tells an administrator: which identity is
// ready, which needs attention before wallets refuse it, and what affects all.

import { afterEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";

vi.mock("@/lib/verifier-identities", async (original) => ({
  ...(await original<typeof import("@/lib/verifier-identities")>()),
  fetchVerifierIdentities: vi.fn(),
}));

import { WalletVerifier } from "@/plugins/walletVerifier";
import {
  fetchVerifierIdentities,
  identityState,
  worstFirst,
  type VerifierIdentitiesResponse,
  type VerifierIdentity,
} from "@/lib/verifier-identities";
import { renderWithProviders } from "@/test/render";

afterEach(() => vi.mocked(fetchVerifierIdentities).mockReset());

function identity(patch: Partial<VerifierIdentity>): VerifierIdentity {
  return {
    id: "swiyu",
    kind: "swiyu",
    clientId: "decentralized_identifier:did:webvh:QmV:reg.example:3f1c",
    did: "did:webvh:QmV:reg.example:3f1c",
    keyId: "did:webvh:QmV:reg.example:3f1c#verifier-key-1",
    custody: "cached",
    usable: true,
    isDefault: true,
    attestations: [{ kind: "identityTrustStatement", expiresAt: "2027-04-01T00:00:00Z" }],
    problems: [],
    installedAt: "2026-09-20T14:02:11Z",
    ...patch,
  };
}

const answer = (r: VerifierIdentitiesResponse) =>
  vi.mocked(fetchVerifierIdentities).mockResolvedValue(r);

describe("the wallet-verifier screen", () => {
  it("shows a complete identity as ready, with its client identifier", async () => {
    answer({ identities: [identity({})], defaultIdentity: null, problems: [] });
    renderWithProviders(<WalletVerifier />);
    expect(await screen.findByText("Ready")).toBeTruthy();
    expect(screen.getByText("default")).toBeTruthy();
    expect(
      screen.getByText("decentralized_identifier:did:webvh:QmV:reg.example:3f1c"),
    ).toBeTruthy();
    expect(screen.getByText("Identity trust statement")).toBeTruthy();
  });

  it("names each problem and the fix, and community-wide ones once", async () => {
    answer({
      identities: [
        identity({
          id: "eudi",
          kind: "eudi",
          clientId: null,
          did: null,
          keyId: null,
          custody: "agent",
          usable: false,
          isDefault: false,
          attestations: [],
          problems: [
            {
              code: "certificateMissing",
              severity: "error",
              detail: "install the registrar's chain with `vtc oid4vp certificate --identity eudi`",
            },
          ],
        }),
      ],
      defaultIdentity: "gone",
      problems: [{ code: "noPublicUrl", severity: "error" }],
    });
    renderWithProviders(<WalletVerifier />);
    expect(await screen.findByText("Cannot open sessions")).toBeTruthy();
    expect(screen.getByText("No access certificate")).toBeTruthy();
    expect(screen.getByText(/vtc oid4vp certificate --identity eudi/)).toBeTruthy();
    expect(screen.getByText("Affects every identity")).toBeTruthy();
    expect(screen.getByText("No https public URL")).toBeTruthy();
    expect(screen.getByText("none yet")).toBeTruthy();
  });

  it("shows an unknown problem code as itself rather than dropping it", async () => {
    answer({
      identities: [
        identity({ problems: [{ code: "somethingNew", severity: "warning" }] }),
      ],
      problems: [],
    });
    renderWithProviders(<WalletVerifier />);
    expect(await screen.findByText("somethingNew")).toBeTruthy();
    expect(screen.getByText("Needs attention")).toBeTruthy();
  });

  it("says when there are none", async () => {
    answer({ identities: [], problems: [] });
    renderWithProviders(<WalletVerifier />);
    expect(await screen.findByText("No verifier identities")).toBeTruthy();
  });
});

describe("the summary helpers", () => {
  it("orders errors before warnings and reads state from usable + problems", () => {
    const ordered = worstFirst([
      { code: "a", severity: "warning" },
      { code: "b", severity: "error" },
    ]);
    expect(ordered.map((p) => p.code)).toEqual(["b", "a"]);
    expect(identityState(identity({}))).toBe("ready");
    expect(
      identityState(identity({ problems: [{ code: "x", severity: "warning" }] })),
    ).toBe("attention");
    expect(identityState(identity({ usable: false }))).toBe("broken");
  });
});
