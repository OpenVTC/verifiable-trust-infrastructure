// The states the signing-keys screen has to get right, because each one
// is an operator asking "why is this not working?".

import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";

import { ConsoleKeys } from "@/plugins/consoleKeys";
import {
  forgetConsoleKey,
  generateConsoleKey,
  resetConsoleKeyCacheForTests,
} from "@/lib/console-key";
import { mockFetch, renderWithProviders } from "@/test/render";

const ADMIN_DID = "did:webvh:QmScid:community.example:alice";

afterEach(async () => {
  await forgetConsoleKey();
  resetConsoleKeyCacheForTests();
});

function row(consoleDid: string, patch: Record<string, unknown> = {}) {
  return {
    consoleDid,
    adminDid: ADMIN_DID,
    createdAt: "2026-09-23T10:00:00Z",
    active: true,
    ...patch,
  };
}

describe("the signing-keys screen", () => {
  it("offers to enable signing on a browser that has never enrolled", async () => {
    mockFetch([{ path: "/v1/admin/console-keys", body: { consoleKeys: [] } }]);
    renderWithProviders(<ConsoleKeys />);

    expect(
      await screen.findByRole("button", { name: /enable signing here/i }),
    ).toBeTruthy();
    expect(await screen.findByText(/no signing keys enrolled/i)).toBeTruthy();
  });

  it("says so, and offers nothing, on a browser without WebCrypto Ed25519", async () => {
    // The degradation that matters: the console keeps working on the bearer
    // routes, and the screen explains itself rather than failing a click.
    resetConsoleKeyCacheForTests();
    const real = crypto.subtle.generateKey;
    Object.defineProperty(crypto.subtle, "generateKey", {
      configurable: true,
      value: () => Promise.reject(new DOMException("nope", "NotSupportedError")),
    });
    try {
      mockFetch([{ path: "/v1/admin/console-keys", body: { consoleKeys: [] } }]);
      renderWithProviders(<ConsoleKeys />);

      expect(await screen.findByText(/this browser cannot sign/i)).toBeTruthy();
      expect(
        screen.queryByRole("button", { name: /enable signing here/i }),
      ).toBeNull();
    } finally {
      Object.defineProperty(crypto.subtle, "generateKey", {
        configurable: true,
        value: real,
      });
      resetConsoleKeyCacheForTests();
    }
  });

  it("marks the row this browser holds, and does not re-derive `active`", async () => {
    const key = await generateConsoleKey();
    mockFetch([
      {
        path: "/v1/admin/console-keys",
        body: {
          consoleKeys: [
            row(key.consoleDid, { label: "This laptop" }),
            // Revoked, with no `expiresAt`: the daemon says `active: false`
            // and the screen reports that rather than working it out.
            row("did:key:zOther", {
              label: "Old laptop",
              active: false,
              revokedAt: "2026-09-22T09:00:00Z",
            }),
          ],
        },
      },
    ]);
    renderWithProviders(<ConsoleKeys />);

    expect(await screen.findByText(/this browser signs/i)).toBeTruthy();
    await waitFor(() => expect(screen.getByText(/\(this browser\)/i)).toBeTruthy());
    expect(screen.getByText(/^Active$/)).toBeTruthy();
    expect(screen.getByText(/^Revoked /)).toBeTruthy();
    // Only the live one can be revoked.
    expect(screen.getAllByRole("button", { name: /revoke/i })).toHaveLength(1);
  });

  it("offers a fresh enrolment when this browser's own key was revoked", async () => {
    // A revoked console DID is tombstoned server-side and can never be
    // re-enrolled, so the screen must not imply that retrying will restore it.
    const key = await generateConsoleKey();
    mockFetch([
      {
        path: "/v1/admin/console-keys",
        body: {
          consoleKeys: [
            row(key.consoleDid, { active: false, revokedAt: "2026-09-22T09:00:00Z" }),
          ],
        },
      },
    ]);
    renderWithProviders(<ConsoleKeys />);

    expect(await screen.findByText(/a revoked key can never be re-enrolled/i)).toBeTruthy();
    expect(
      screen.getByRole("button", { name: /enable signing here/i }),
    ).toBeTruthy();
  });

  it("says this browser signs as soon as enrolment succeeds, without a reload", async () => {
    // The key is generated *during* enrolment, so the "which key does this
    // browser hold" read has to happen again afterwards. Without it the
    // operator enrols successfully and the screen goes on offering to enrol,
    // which reads as a failure.
    vi.stubGlobal("navigator", {
      ...globalThis.navigator,
      credentials: {
        get: () =>
          Promise.resolve({
            id: "cred",
            rawId: new Uint8Array([1]).buffer,
            type: "public-key",
            response: {
              authenticatorData: new Uint8Array([2]).buffer,
              clientDataJSON: new Uint8Array([3]).buffer,
              signature: new Uint8Array([4]).buffer,
              userHandle: null,
            },
          }),
      },
    });
    let enrolledDid: string | null = null;
    mockFetch([
      {
        path: "/v1/admin/console-keys",
        body: () => ({
          consoleKeys: enrolledDid ? [row(enrolledDid, { label: "Here" })] : [],
        }),
      },
      {
        method: "POST",
        path: "/v1/auth/passkey-login/start",
        body: { authId: "a", options: { challenge: "AAAA", allowCredentials: [] } },
      },
      { method: "POST", path: "/v1/auth/passkey-login/finish", body: {} },
      {
        method: "POST",
        path: "/v1/admin/console-keys",
        status: 201,
        body: ({ body }) => {
          enrolledDid = (body as { consoleDid: string }).consoleDid;
          return row(enrolledDid, { label: "Here" });
        },
      },
    ]);

    renderWithProviders(<ConsoleKeys />);
    fireEvent.click(
      await screen.findByRole("button", { name: /enable signing here/i }),
    );
    expect(await screen.findByText(/this browser signs/i)).toBeTruthy();
  });

  it("shows the daemon's own message when the listing fails", async () => {
    mockFetch([
      { path: "/v1/admin/console-keys", status: 403, body: { error: "Caller is not an admin" } },
    ]);
    vi.spyOn(console, "error").mockImplementation(() => {});
    renderWithProviders(<ConsoleKeys />);

    expect(await screen.findByText(/failed to load console keys/i)).toBeTruthy();
    expect(await screen.findByText(/caller is not an admin/i)).toBeTruthy();
  });
});
