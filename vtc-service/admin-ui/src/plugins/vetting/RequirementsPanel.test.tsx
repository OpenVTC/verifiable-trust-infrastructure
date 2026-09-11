import { screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RequirementsPanel } from "@/plugins/vetting/RequirementsPanel";
import { mockFetch, renderWithProviders } from "@/test/render";

const REQUIREMENTS = {
  version: "0.1",
  statementType: "https://firstperson.network/endorsements/identity-vetting/0.1",
  minStatements: 2,
  minByMethod: { inPerson: 1 },
  acceptedMethods: ["inPerson", "video", "priorAcquaintance"],
  requiredClaims: ["name.legal"],
  maxStatementAge: "P120D",
  eligibleVetters: { role: "vetter" },
  independence: {
    maxByDeclaredRelationship: { family: 0, sameEmployer: 1 },
    requireConsistentIdentityCommitment: true,
  },
};

describe("RequirementsPanel", () => {
  it("shows each criterion's requirements in words with its digest", async () => {
    const requests = mockFetch([
      {
        path: "/v1/join-requests/manifest",
        body: {
          communityDid: "did:web:vtc.example.org",
          criteria: [
            {
              id: "kernel-developer",
              description: "Two vetters, at least one in person",
              presentationDefinition: {},
              vetting: REQUIREMENTS,
              requirementsDigest: "zQmKernelDigest",
            },
            {
              id: "legacy",
              presentationDefinition: {},
              vetting: { ...REQUIREMENTS, minStatements: 0 },
              requirementsDigest: "zQmLegacyDigest",
            },
            { id: "open-door", presentationDefinition: {} },
          ],
        },
      },
    ]);
    renderWithProviders(<RequirementsPanel />);

    expect(
      await screen.findByText("Statements from at least 2 distinct eligible vetters."),
    ).toBeTruthy();
    expect(screen.getByText("At least 1 of them made in person.")).toBeTruthy();
    expect(screen.getByText("zQmKernelDigest")).toBeTruthy();
    expect(screen.getByText(/^Require at least 1 statement/)).toBeTruthy();
    expect(screen.getByText("This criterion requires no vetting.")).toBeTruthy();

    await waitFor(() => expect(requests.length).toBeGreaterThan(0));
    expect(requests[0]!.headers.get("Trust-Task")).toBe(
      "https://trusttasks.org/spec/vtc/join-requests/manifest/0.2",
    );
  });
});
