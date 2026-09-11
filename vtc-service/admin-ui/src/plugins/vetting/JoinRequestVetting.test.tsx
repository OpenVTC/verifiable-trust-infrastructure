import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { JoinRequestVetting } from "@/lib/wire-types";
import { JoinRequestVettingCard } from "@/plugins/vetting/JoinRequestVetting";
import { mockFetch, NAME_BOOK_ROUTES, renderWithProviders } from "@/test/render";

const ID = "5f0c2a1e-8d4b-4a51-9d7e-2b7f4c3e9a10";

const FACTS: JoinRequestVetting = {
  criterionId: "kernel-developer",
  requirementsDigest: "zQmRequirementsDigest",
  applicantDigestMatches: false,
  statements: [
    {
      id: "urn:uuid:counted",
      issuer: "did:key:z6MkCarol",
      method: "inPerson",
      declaredRelationship: "none",
      verified: true,
      eligible: true,
      revoked: false,
      withdrawnNow: false,
      counted: true,
      failures: [],
    },
    {
      id: "urn:uuid:refused",
      issuer: "did:key:z6MkMallory",
      method: "video",
      declaredRelationship: "family",
      verified: true,
      eligible: false,
      revoked: false,
      withdrawnNow: false,
      counted: false,
      failures: ["issuer-not-vetter"],
    },
  ],
  distinctCountedVetters: 1,
  byMethod: { inPerson: 1 },
  commitmentsConsistent: true,
  independenceOk: true,
  invitationRequired: false,
  satisfied: false,
  needs: ["vetting:statements:1"],
  recordedAt: "2026-09-01T10:00:00Z",
};

describe("JoinRequestVettingCard", () => {
  it("says what counted, what did not and why, and keeps the codes", async () => {
    mockFetch([
      { path: `/v1/join-requests/${ID}/vetting`, body: { requestId: ID, vetting: FACTS } },
      ...NAME_BOOK_ROUTES,
    ]);
    renderWithProviders(<JoinRequestVettingCard id={ID} />);

    expect(await screen.findByText("Vetting is incomplete")).toBeTruthy();
    expect(screen.getByText("Statements from 1 more eligible vetter.")).toBeTruthy();
    expect(screen.getByText("vetting:statements:1")).toBeTruthy();
    expect(screen.getByText(/^Its signer was not an eligible vetter/)).toBeTruthy();
    expect(screen.getByText("issuer-not-vetter")).toBeTruthy();
    expect(screen.getByText("Counted")).toBeTruthy();
    expect(screen.getByText("Not counted")).toBeTruthy();
    expect(screen.getByText("Family member")).toBeTruthy();
    expect(screen.getByText("In person 1")).toBeTruthy();
    expect(screen.getByText("zQmRequirementsDigest")).toBeTruthy();
    expect(
      screen.getByText(/gathered statements for different requirements/),
    ).toBeTruthy();
  });

  it("says so when no vetting criterion applied", async () => {
    mockFetch([
      { path: `/v1/join-requests/${ID}/vetting`, body: { requestId: ID } },
      ...NAME_BOOK_ROUTES,
    ]);
    renderWithProviders(<JoinRequestVettingCard id={ID} />);
    expect(await screen.findByText(/^No vetting criterion applied/)).toBeTruthy();
  });

  it("names a failed read and what to do", async () => {
    mockFetch([
      {
        path: `/v1/join-requests/${ID}/vetting`,
        status: 404,
        body: { error: "join request not found" },
      },
      ...NAME_BOOK_ROUTES,
    ]);
    renderWithProviders(<JoinRequestVettingCard id={ID} />);
    expect(await screen.findByText("Could not load the vetting facts.")).toBeTruthy();
    expect(screen.getByText(/join request not found Reload the page/)).toBeTruthy();
  });
});
