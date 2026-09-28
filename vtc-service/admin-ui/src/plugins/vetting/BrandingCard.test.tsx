import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { CommunityBrandingCard, readableTextOn } from "@/plugins/vetting/BrandingCard";
import { mockFetch, renderWithProviders, sentPayloads, taskRoute } from "@/test/render";

// Signed documents reach the fetch table unsigned; there is no console key here.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));

const SHOW = "https://trusttasks.org/spec/vtc/community/branding/show/0.1";
const UPDATE = "https://trusttasks.org/spec/vtc/community/branding/update/0.1";

describe("CommunityBrandingCard", () => {
  it("previews the branding and saves it with the colour in lower case", async () => {
    const requests = mockFetch([
      taskRoute(SHOW, { branding: {} }),
      taskRoute(UPDATE, (payload) => payload),
    ]);
    renderWithProviders(<CommunityBrandingCard />);

    const save = (await screen.findByRole("button", {
      name: "Save branding",
    })) as HTMLButtonElement;
    expect(save.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Linux Kernel" },
    });
    fireEvent.change(screen.getByLabelText("Pick the accent colour"), {
      target: { value: "#1a2b3c" },
    });
    const hex = screen.getByLabelText("Accent colour") as HTMLInputElement;
    expect(hex.value).toBe("#1a2b3c");
    fireEvent.change(hex, { target: { value: "#1A2B3C" } });
    fireEvent.change(screen.getByLabelText("Logo URL"), {
      target: { value: "https://kernel.example.org/logo.svg" },
    });

    const preview = screen.getByTestId("branding-preview");
    expect(within(preview).getByText("Linux Kernel")).toBeTruthy();
    expect(preview.textContent).toMatch(/kernel\.example\.org/);

    expect(save.disabled).toBe(false);
    fireEvent.click(save);
    await waitFor(() => expect(sentPayloads(requests, UPDATE).length).toBe(1));
    expect((sentPayloads(requests, UPDATE)[0] as { branding: unknown }).branding).toEqual({
      displayName: "Linux Kernel",
      accentColor: "#1a2b3c",
      logoUrl: "https://kernel.example.org/logo.svg",
    });
    expect(await screen.findByText(/^Saved the branding/)).toBeTruthy();
  });

  it("explains invalid values and will not save them", async () => {
    mockFetch([taskRoute(SHOW, { branding: { displayName: "Kernel" } })]);
    renderWithProviders(<CommunityBrandingCard />);

    await screen.findByDisplayValue("Kernel");
    fireEvent.change(screen.getByLabelText("Accent colour"), {
      target: { value: "#12345" },
    });
    fireEvent.change(screen.getByLabelText("Logo URL"), {
      target: { value: "http://kernel.example.org/logo.svg" },
    });

    expect(
      screen.getByText("Enter the colour as # and six hex digits, like #1a7f6e."),
    ).toBeTruthy();
    expect(screen.getByText(/^Use an https:\/\/ address/)).toBeTruthy();
    expect(screen.getByLabelText("Logo URL").getAttribute("aria-invalid")).toBe("true");
    expect(
      (screen.getByRole("button", { name: "Save branding" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it("picks readable text for the accent colour", () => {
    expect(readableTextOn("#ffffff")).toBe("#000000");
    expect(readableTextOn("#0d1320")).toBe("#ffffff");
  });
});
