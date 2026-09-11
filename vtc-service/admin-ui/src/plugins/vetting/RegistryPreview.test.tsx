import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RegistryPreview } from "@/plugins/vetting/RegistryPreview";
import { mockFetch, renderWithProviders } from "@/test/render";

const LIST_TASK = "https://trusttasks.org/spec/vtc/vetting/vetters/list/0.1";

const CAROL = {
  vetterDid: "did:key:z6MkCarolCarolCarolCarolCarolCarolCarol",
  displayName: "Carol M.",
  languages: ["en", "de-AT"],
  location: { country: "AT", city: "Vienna" },
  methods: ["inPerson", "video"],
  acceptsDocumentation: ["passport", "none"],
  contactHint: "Ask at the kernel-vtc table.",
  events: [
    {
      name: "Kernel Maintainers Meetup",
      startDate: "2026-10-05",
      endDate: "2026-10-07",
      url: "https://events.example.org/kmm",
    },
  ],
  grantValidUntil: "2027-01-01T00:00:00Z",
  updatedAt: "2026-09-01T00:00:00Z",
};

type ListRequest = { country?: string; cursor?: string };

describe("RegistryPreview", () => {
  it("sends the filters an applicant would, with the country in upper case", async () => {
    const requests = mockFetch([
      {
        method: "POST",
        path: "/v1/vetting/vetters/list",
        body: ({ body }) => ({
          vetters: (body as ListRequest).country === "AT" ? [CAROL] : [],
        }),
      },
    ]);
    renderWithProviders(<RegistryPreview />);

    expect(await screen.findByText("No vetter is listed")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Language"), { target: { value: "de" } });
    fireEvent.change(screen.getByLabelText("Country"), { target: { value: "at" } });
    fireEvent.change(screen.getByLabelText("Method"), { target: { value: "video" } });
    fireEvent.click(screen.getByRole("button", { name: "Show vetters" }));

    expect(await screen.findByText("Carol M.")).toBeTruthy();
    expect(screen.getByText("Ask at the kernel-vtc table.")).toBeTruthy();
    expect(screen.getByText("Vienna, AT")).toBeTruthy();
    const last = requests.at(-1)!;
    expect(last.body).toEqual({
      language: "de",
      country: "AT",
      method: "video",
      limit: 25,
    });
    expect(last.headers.get("Trust-Task")).toBe(LIST_TASK);
  });

  it("names a malformed filter and does not send it", async () => {
    const requests = mockFetch([
      { method: "POST", path: "/v1/vetting/vetters/list", body: { vetters: [] } },
    ]);
    renderWithProviders(<RegistryPreview />);
    await screen.findByText("No vetter is listed");
    const sent = requests.length;

    fireEvent.change(screen.getByLabelText("Country"), {
      target: { value: "Austria" },
    });
    fireEvent.change(screen.getByLabelText("Events from"), {
      target: { value: "2026-10-07" },
    });
    fireEvent.change(screen.getByLabelText("Events to"), {
      target: { value: "2026-10-01" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Show vetters" }));

    expect(screen.getByText("Enter a two-letter country code, like AT.")).toBeTruthy();
    expect(screen.getByText(/The end of the range is before its start/)).toBeTruthy();
    expect(screen.getByLabelText("Country").getAttribute("aria-invalid")).toBe("true");
    expect(requests.length).toBe(sent);
  });

  it("pages with the cursor the listing returned", async () => {
    const requests = mockFetch([
      {
        method: "POST",
        path: "/v1/vetting/vetters/list",
        body: ({ body }) =>
          (body as ListRequest).cursor === "page-2"
            ? { vetters: [{ ...CAROL, displayName: "Zed" }] }
            : { vetters: [CAROL], nextCursor: "page-2" },
      },
    ]);
    renderWithProviders(<RegistryPreview />);

    await screen.findByText("Carol M.");
    fireEvent.click(screen.getByRole("button", { name: /Next page/ }));
    expect(await screen.findByText("Zed")).toBeTruthy();
    expect(screen.getByText("Page 2")).toBeTruthy();
    await waitFor(() =>
      expect((requests.at(-1)!.body as ListRequest).cursor).toBe("page-2"),
    );
  });
});
