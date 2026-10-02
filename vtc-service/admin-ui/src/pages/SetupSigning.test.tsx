// The page an administrator sees between signing in and the console when this
// browser holds no key the community accepts.

import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";

vi.mock("@/lib/console-keys-api", async (original) => ({
  ...(await original<typeof import("@/lib/console-keys-api")>()),
  enrolThisBrowser: vi.fn(),
}));

import type { WhoamiResponse } from "@/lib/api";
import { enrolThisBrowser, TooManyKeysError } from "@/lib/console-keys-api";
import { SetupSigning, suggestedLabel } from "@/pages/SetupSigning";
import { renderWithProviders } from "@/test/render";

const WHOAMI = {
  session: { id: "s", subject: "did:key:z6MkAdmin", issuedAt: "", expiresAt: "" },
  roles: ["admin"],
  scopes: [],
} as WhoamiResponse;

afterEach(() => vi.mocked(enrolThisBrowser).mockReset());

describe("setting up signing", () => {
  it("explains why, and enrols with a label naming this browser", async () => {
    vi.mocked(enrolThisBrowser).mockReturnValue(new Promise(() => {}));
    renderWithProviders(
      <SetupSigning whoami={WHOAMI} status={{ state: "not-enrolled", consoleDid: "did:key:z6MkOld" }} />,
    );
    expect(screen.getByText(/no longer accepted here/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /set up signing/i }));
    expect(await screen.findByRole("button", { name: /waiting for your passkey/i })).toBeTruthy();
    expect(vi.mocked(enrolThisBrowser).mock.calls[0]![0]).toBe(suggestedLabel());
  });

  it("says what to do when the identity is at its key limit", async () => {
    vi.mocked(enrolThisBrowser).mockRejectedValue({
      status: 422,
      code: "auth/signing-key/enroll:tooManyKeys",
      message: "too many",
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    renderWithProviders(<SetupSigning whoami={WHOAMI} status={{ state: "no-key" }} />);
    fireEvent.click(screen.getByRole("button", { name: /set up signing/i }));
    expect(await screen.findByText(/maximum number of active signing keys/i)).toBeTruthy();
  });

  it("at the key cap, offers the listed keys and replaces the one chosen", async () => {
    vi.mocked(enrolThisBrowser)
      .mockRejectedValueOnce(
        new TooManyKeysError(
          [
            {
              signingKeyDid: "did:key:z6MkLeastUsed",
              deviceLabel: "Old laptop",
              createdAt: "2026-09-01T00:00:00Z",
              expiresAt: "2026-10-01T00:00:00Z",
            },
            {
              signingKeyDid: "did:key:z6MkRecent",
              deviceLabel: "Phone",
              createdAt: "2026-09-20T00:00:00Z",
              expiresAt: "2026-10-20T00:00:00Z",
            },
          ],
          5,
        ),
      )
      .mockReturnValueOnce(new Promise(() => {}));
    vi.spyOn(console, "error").mockImplementation(() => {});
    renderWithProviders(<SetupSigning whoami={WHOAMI} status={{ state: "no-key" }} />);
    fireEvent.click(screen.getByRole("button", { name: /set up signing/i }));
    fireEvent.click(
      await screen.findByRole("button", { name: /replace it and set up signing/i }),
    );
    // The least recently used is the default choice.
    await screen.findByRole("button", { name: /waiting/i });
    expect(vi.mocked(enrolThisBrowser).mock.calls[1]![2]).toMatchObject({
      replaces: "did:key:z6MkLeastUsed",
    });
  });

  it("offers nothing to click on a browser that cannot sign", () => {
    renderWithProviders(<SetupSigning whoami={WHOAMI} status={{ state: "unsupported" }} />);
    expect(screen.getByText(/this browser cannot sign/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /set up signing/i })).toBeNull();
  });
});

describe("suggestedLabel", () => {
  it("names the browser and the OS", () => {
    expect(
      suggestedLabel(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
      ),
    ).toBe("Chrome on macOS");
    expect(
      suggestedLabel(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
      ),
    ).toBe("Safari on macOS");
    expect(
      suggestedLabel("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0"),
    ).toBe("Firefox on Windows");
  });
});
