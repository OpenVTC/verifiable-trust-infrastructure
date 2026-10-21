// The member's directory card on their page: their own words, a picture shown
// only once its bytes match the card, a verified value with its issuer, and
// nothing at all when the directory has no card for them.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({
  showEntryByDid: vi.fn(),
  listFields: vi.fn(),
  getImage: vi.fn(),
}));

vi.mock("@/lib/directory", async (orig) => ({
  ...(await orig<typeof import("@/lib/directory")>()),
  ...api,
}));

import { blobRef, initials, verifiedValue } from "@/components/DirectoryAvatar";

import { MemberProfileCard, safeUrl } from "./MemberProfile";

const ENTRY = "dir_aaaaaaaaaaaaaaaa";
// "hi", and its SHA-256.
const BYTES_B64URL = "aGk";
const SHA = "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4";

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <div data-testid="host">
        <MemberProfileCard did="did:example:carol" />
      </div>
    </QueryClientProvider>,
  );
}

describe("a member's directory card in the console", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.listFields.mockResolvedValue({
      fields: [{ key: "org.example.registration", label: "Registration" }],
    });
  });

  it("shows nothing when the directory has no card for the member", async () => {
    api.showEntryByDid.mockRejectedValue(new Error("notFound"));
    renderCard();
    await vi.waitFor(() => expect(api.showEntryByDid).toHaveBeenCalled());
    expect(screen.getByTestId("host").textContent).toBe("");
  });

  it("shows the member's name, words, picture and verified values", async () => {
    api.showEntryByDid.mockResolvedValue({
      entry: {
        entryId: ENTRY,
        fields: {
          displayName: "Carol Example",
          pronouns: "she/her",
          bio: "Builds things.",
          links: ["https://carol.example", "javascript:alert(1)"],
          avatar: { sha256: SHA, mediaType: "image/png", size: 2 },
          role: "member",
          "org.example.registration": {
            value: "REG-1",
            issuer: "did:example:registry",
            credentialType: "ProfessionalRegistration",
            verifiedAt: "2026-10-19T09:00:00Z",
          },
        },
      },
    });
    api.getImage.mockResolvedValue({ image: { mediaType: "image/png" }, data: BYTES_B64URL });
    const { container } = renderCard();
    expect(await screen.findByText("Carol Example")).toBeTruthy();
    expect(screen.getByText("she/her")).toBeTruthy();
    expect(screen.getByText("Builds things.")).toBeTruthy();
    expect(screen.getByRole("link", { name: "https://carol.example" })).toBeTruthy();
    // Not a link: not http or https.
    expect(screen.queryByRole("link", { name: "javascript:alert(1)" })).toBeNull();
    expect(screen.getByText("Registration")).toBeTruthy();
    expect(screen.getByText("did:example:registry")).toBeTruthy();
    // Shown elsewhere on the page.
    expect(screen.queryByText("member")).toBeNull();
    await vi.waitFor(() => expect(container.querySelector("img.dir-avatar")).toBeTruthy());
    expect(api.getImage).toHaveBeenCalledWith(ENTRY, "avatar", SHA);
  });

  it("does not show a picture whose bytes are not the ones the card names", async () => {
    api.showEntryByDid.mockResolvedValue({
      entry: {
        entryId: ENTRY,
        fields: { displayName: "Carol Example", avatar: { sha256: "0".repeat(64), mediaType: "image/png" } },
      },
    });
    api.getImage.mockResolvedValue({ image: { mediaType: "image/png" }, data: BYTES_B64URL });
    const { container } = renderCard();
    expect(await screen.findByText("CE")).toBeTruthy();
    await vi.waitFor(() => expect(api.getImage).toHaveBeenCalled());
    expect(container.querySelector("img.dir-avatar")).toBeNull();
  });
});

describe("directory value shapes", () => {
  it("reads pictures, verified values and initials", () => {
    expect(blobRef({ sha256: SHA, mediaType: "image/png" })).not.toBeNull();
    expect(blobRef("text")).toBeNull();
    expect(verifiedValue({ value: true, issuer: "did:x", verifiedAt: "2026-10-19T00:00:00Z" })).not.toBeNull();
    expect(verifiedValue({ sha256: SHA, mediaType: "image/png" })).toBeNull();
    expect(initials("Carol Ann Example")).toBe("CE");
    expect(initials("")).toBe("?");
    expect(safeUrl("https://a.example/")).toBe("https://a.example/");
    expect(safeUrl("javascript:alert(1)")).toBeNull();
  });
});
