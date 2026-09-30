import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { VetterGrantRow } from "@/lib/wire-types";
import { VettersPanel } from "@/plugins/vetting/VettersPanel";
import {
  MEMBERS_LIST_TASK,
  type MockRoute,
  mockFetch,
  renderWithProviders,
  sentPayloads,
  taskRoute,
} from "@/test/render";

// Naming a vetter is a signed document; the test browser holds no key, so it
// goes through the unsigned stand-in to the `mockFetch` table.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));

const GRANT_TASK = "https://trusttasks.org/spec/vtc/vetting/vetters/grant/0.1";

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
    taskRoute("https://trusttasks.org/spec/vtc/vetting/vetters/grants/list/0.1", {
      items: GRANTS,
    }),
    taskRoute("https://trusttasks.org/spec/vtc/vetting/auto-grant/show/0.1", {
      autoGrant: { enabled: false, sweepMinutes: 60, validitySeconds: 31_536_000 },
    }),
    taskRoute(MEMBERS_LIST_TASK, { items: [member(CAROL, "Carol"), member(ERIN, "Erin")] }),
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

  const ENDORSEMENT_REVOKE_TASK =
    "https://trusttasks.org/spec/vtc/endorsements/revoke/0.1";
  const VETTER_RESEND_0_2_TASK =
    "https://trusttasks.org/spec/vtc/vetting/vetters/resend/0.2";

  it("revokes only after a confirmation that says the statements stop counting", async () => {
    const requests = mockFetch(
      routes([taskRoute(ENDORSEMENT_REVOKE_TASK, { revoked: true })]),
    );
    renderWithProviders(<VettersPanel />);

    fireEvent.click(
      await screen.findByRole("button", { name: /^Revoke vetter role for / }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toMatch(
      /stops counting toward join requests decided from now on/,
    );
    expect(sentPayloads(requests, ENDORSEMENT_REVOKE_TASK)).toHaveLength(0);

    fireEvent.click(within(dialog).getByRole("button", { name: "Revoke vetter role" }));
    await waitFor(() =>
      expect(sentPayloads(requests, ENDORSEMENT_REVOKE_TASK)).toHaveLength(1),
    );
    expect(sentPayloads(requests, ENDORSEMENT_REVOKE_TASK)[0]).toEqual({
      endorsementId: "grant-carol",
    });
  });

  it("explains a resend the daemon cannot deliver", async () => {
    mockFetch(
      routes([
        taskRoute(
          VETTER_RESEND_0_2_TASK,
          { code: "vtc/vetting/vetters/resend:notGranted", message: "no live vetter grant" },
          404,
        ),
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
        taskRoute(GRANT_TASK, {
          endorsementId: "grant-erin",
          credentialId: "urn:uuid:erin",
          validFrom: "2026-09-12T00:00:00Z",
          validUntil: "2026-10-12T00:00:00Z",
        }),
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

    await waitFor(() => expect(sentPayloads(requests, GRANT_TASK)).toHaveLength(1));
    expect(sentPayloads(requests, GRANT_TASK)[0]).toEqual({
      memberDid: ERIN,
      validitySeconds: 30 * 86_400,
    });
  });
});
