import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { VettingRevocationRow } from "@/lib/wire-types";
import { WithdrawalsPanel } from "@/plugins/vetting/WithdrawalsPanel";
import { mockFetch, NAME_BOOK_ROUTES, renderWithProviders } from "@/test/render";

const REQUEST_ID = "5f0c2a1e-8d4b-4a51-9d7e-2b7f4c3e9a10";
const ERIN = "did:key:z6MkErinErinErinErinErinErinErinErin";

const ROWS: VettingRevocationRow[] = [
  {
    issuer: "did:key:z6MkCarolCarolCarolCarolCarolCarolCarol",
    statementId: "urn:uuid:3b5b2d7e-1c9f-4f55-8b0e-0f8c1a2b3c4d",
    statementDigestMultibase: "zQmStatementDigest",
    reason: "newInformation",
    recordedAt: "2026-09-10T12:00:00Z",
    reviewState: "needsReview",
    affectedJoinRequests: [REQUEST_ID],
    affectedMembers: [ERIN],
  },
  {
    issuer: "did:key:z6MkDanDanDanDanDanDanDanDanDanDanDanDan",
    statementId: "urn:uuid:9a9a9a9a-0000-4000-8000-000000000000",
    statementDigestMultibase: "zQmOther",
    recordedAt: "2026-09-09T12:00:00Z",
    reviewState: "noAdmission",
    affectedJoinRequests: [],
    affectedMembers: [],
  },
];

describe("WithdrawalsPanel", () => {
  it("links a withdrawal that needs review to the admission it touches", async () => {
    mockFetch([
      { path: "/v1/vetting/revocations", body: { revocations: ROWS } },
      ...NAME_BOOK_ROUTES,
    ]);
    renderWithProviders(<WithdrawalsPanel />);

    expect(
      await screen.findByText("1 withdrawal touches a current membership."),
    ).toBeTruthy();
    expect(screen.getByText("The vetter learned something new")).toBeTruthy();
    expect(screen.getByText("No reason given")).toBeTruthy();
    expect(
      screen.getByRole("link", { name: /^Join request 5f0c2a1e/ }).getAttribute("href"),
    ).toBe(`/join-requests/${REQUEST_ID}`);
    expect(
      screen.getByRole("link", { name: /^Member / }).getAttribute("href"),
    ).toBe(`/members/${encodeURIComponent(ERIN)}`);

    fireEvent.change(screen.getByLabelText("Show"), {
      target: { value: "needsReview" },
    });
    expect(screen.queryByText("No reason given")).toBeNull();
  });

  it("says when no vetter has withdrawn anything", async () => {
    mockFetch([
      { path: "/v1/vetting/revocations", body: { revocations: [] } },
      ...NAME_BOOK_ROUTES,
    ]);
    renderWithProviders(<WithdrawalsPanel />);
    expect(await screen.findByText("No vetter has withdrawn a statement")).toBeTruthy();
  });
});
