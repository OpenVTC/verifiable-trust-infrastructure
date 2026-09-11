import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { VetterGrantRow } from "@/lib/wire-types";
import { VettersPanel } from "@/plugins/vetting/VettersPanel";
import { type MockRoute, mockFetch, renderWithProviders } from "@/test/render";

const CAROL = "did:key:z6MkCarolCarolCarolCarolCarolCarolCarol";
const DAN = "did:key:z6MkDanDanDanDanDanDanDanDanDanDanDanDan";
const ERIN = "did:key:z6MkErinErinErinErinErinErinErinErin";

const GRANTS: VetterGrantRow[] = [
  {
    endorsementId: "grant-carol",
    memberDid: CAROL,
    credentialId: "urn:uuid:carol",
    validFrom: "2026-01-01T00:00:00Z",
    validUntil: "2099-01-01T00:00:00Z",
    revoked: false,
    live: true,
    origin: "manual",
    profile: {
      listed: true,
      displayName: "Carol M.",
      country: "AT",
      languages: ["en", "de-AT"],
      methods: ["inPerson"],
      eventCount: 1,
      updatedAt: "2026-02-01T00:00:00Z",
    },
  },
  {
    endorsementId: "grant-dan",
    memberDid: DAN,
    credentialId: "urn:uuid:dan",
    validFrom: "2025-01-01T00:00:00Z",
    validUntil: "2099-01-01T00:00:00Z",
    revoked: true,
    revokedAt: "2026-03-01T00:00:00Z",
    live: false,
    origin: "auto",
  },
];

const member = (did: string, label: string) => ({
  did,
  label,
  role: "member",
  joinedAt: "2025-01-01T00:00:00Z",
  personhood: false,
  publishConsent: false,
  departurePreference: "tombstone",
  extensions: {},
});

function routes(extra: MockRoute[] = []): MockRoute[] {
  return [
    { path: "/v1/vetting/vetters", body: { vetters: GRANTS } },
    {
      path: "/v1/vetting/auto-grant",
      body: { enabled: false, sweepMinutes: 60, validitySeconds: 31_536_000 },
    },
    {
      path: "/v1/members",
      body: { items: [member(CAROL, "Carol"), member(ERIN, "Erin")] },
    },
    { path: "/v1/acl", body: { entries: [], truncated: false } },
    ...extra,
  ];
}

describe("VettersPanel", () => {
  it("lists grants and filters them by status and origin", async () => {
    mockFetch(routes());
    renderWithProviders(<VettersPanel />);

    expect(await screen.findByText("Carol M.")).toBeTruthy();
    const table = screen.getByRole("table");
    expect(within(table).getByText("Live")).toBeTruthy();
    expect(within(table).getByText("Revoked")).toBeTruthy();
    expect(within(table).getByText("Automatic")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Status"), {
      target: { value: "revoked" },
    });
    expect(within(table).queryByText("Carol M.")).toBeNull();

    fireEvent.change(screen.getByLabelText("Granted by"), {
      target: { value: "manual" },
    });
    expect(within(table).getByText("No grant matches these filters")).toBeTruthy();
  });

  it("revokes only after a confirmation that says the statements stop counting", async () => {
    const requests = mockFetch(
      routes([
        {
          method: "DELETE",
          path: "/v1/credentials/endorsements/grant-carol",
          body: { revoked: true },
        },
      ]),
    );
    renderWithProviders(<VettersPanel />);

    fireEvent.click(
      await screen.findByRole("button", { name: /^Revoke vetter role for / }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toMatch(
      /stops counting toward join requests decided from now on/,
    );
    expect(requests.some((r) => r.method === "DELETE")).toBe(false);

    fireEvent.click(within(dialog).getByRole("button", { name: "Revoke vetter role" }));
    await waitFor(() =>
      expect(requests.some((r) => r.method === "DELETE")).toBe(true),
    );
    const revoke = requests.find((r) => r.method === "DELETE")!;
    expect(revoke.url).toBe("/v1/credentials/endorsements/grant-carol");
    expect(revoke.headers.get("Trust-Task")).toBe(
      "https://trusttasks.org/spec/vtc/endorsements/revoke/0.1",
    );
  });

  it("explains a resend the daemon cannot deliver", async () => {
    mockFetch(
      routes([
        {
          method: "POST",
          path: `/v1/vetting/vetters/${encodeURIComponent(CAROL)}/resend`,
          status: 404,
          body: { error: "no live vetter grant" },
        },
      ]),
    );
    renderWithProviders(<VettersPanel />);

    fireEvent.click(
      await screen.findByRole("button", { name: /^Resend vetter credential to / }),
    );
    expect(await screen.findByText("Could not resend the credential")).toBeTruthy();
    expect(
      screen.getByText(/Revoke the grant and grant the role again/),
    ).toBeTruthy();
  });

  it("refuses a validity beyond two years, then grants within the bounds", async () => {
    const requests = mockFetch(
      routes([
        {
          method: "POST",
          path: "/v1/vetting/vetters",
          status: 201,
          body: {
            endorsementId: "grant-erin",
            credentialId: "urn:uuid:erin",
            validFrom: "2026-09-12T00:00:00Z",
            validUntil: "2026-10-12T00:00:00Z",
          },
        },
      ]),
    );
    renderWithProviders(<VettersPanel />);

    await screen.findByText("Carol M.");
    const select = screen.getByLabelText("Member");
    await waitFor(() => expect(within(select).queryByText(/Erin/)).toBeTruthy());
    // Carol already holds a live grant, so she is not offered.
    expect(within(select).queryByText(/Carol/)).toBeNull();

    fireEvent.change(select, { target: { value: ERIN } });
    fireEvent.change(screen.getByLabelText("Valid for"), {
      target: { value: "custom" },
    });
    fireEvent.change(screen.getByLabelText("Days"), { target: { value: "731" } });
    expect(
      screen.getByText("Choose 1 to 730 days (two years); 731 is outside that."),
    ).toBeTruthy();
    expect(screen.getByLabelText("Days").getAttribute("aria-invalid")).toBe("true");

    fireEvent.click(screen.getByRole("button", { name: "Grant vetter role" }));
    expect(screen.queryByRole("dialog")).toBeNull();

    fireEvent.change(screen.getByLabelText("Days"), { target: { value: "30" } });
    fireEvent.click(screen.getByRole("button", { name: "Grant vetter role" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Grant vetter role" }));

    await waitFor(() =>
      expect(
        requests.some((r) => r.method === "POST" && r.url === "/v1/vetting/vetters"),
      ).toBe(true),
    );
    const grant = requests.find(
      (r) => r.method === "POST" && r.url === "/v1/vetting/vetters",
    )!;
    expect(grant.body).toEqual({ memberDid: ERIN, validitySeconds: 30 * 86_400 });
    expect(grant.headers.get("Trust-Task")).toBe(
      "https://trusttasks.org/spec/vtc/vetting/vetters/grant/0.1",
    );
  });
});
