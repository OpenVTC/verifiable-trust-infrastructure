import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { AcceptsCriterion } from "@/lib/wire-types";
import { RequirementsPanel } from "@/plugins/vetting/RequirementsPanel";
import { type MockRoute, mockFetch, renderWithProviders } from "@/test/render";

const STATEMENT_TYPE =
  "https://firstperson.network/endorsements/identity-vetting/0.1";

const REQUIREMENTS = {
  version: "0.1",
  statementType: STATEMENT_TYPE,
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

const QUERY = {
  credentials: [
    { id: "vetting", format: "ldp_vc", meta: { type_values: ["EndorsementCredential"] } },
  ],
};

const criterion = (
  id: string,
  vetting: unknown,
  description?: string,
): AcceptsCriterion =>
  ({
    id,
    query: QUERY,
    description,
    vetting,
    createdAt: "2026-01-01T00:00:00Z",
    createdByDid: "did:key:zAdmin",
  }) as unknown as AcceptsCriterion;

function routes(extra: MockRoute[] = []): MockRoute[] {
  return [
    {
      path: "/v1/schemas/accepts",
      body: [
        criterion("kernel-developer", REQUIREMENTS, "Two vetters, at least one in person"),
        criterion("legacy", { ...REQUIREMENTS, minStatements: 0 }),
        criterion("open-door", undefined),
      ],
    },
    {
      path: "/v1/join-requests/manifest",
      body: {
        communityDid: "did:web:vtc.example.org",
        criteria: [
          { id: "kernel-developer", presentationDefinition: {}, vetting: REQUIREMENTS, requirementsDigest: "zQmKernelDigest" },
          { id: "legacy", presentationDefinition: {}, requirementsDigest: "zQmLegacyDigest" },
          { id: "open-door", presentationDefinition: {} },
        ],
      },
    },
    {
      path: "/v1/endorsement-types",
      body: {
        items: [
          {
            typeUri: STATEMENT_TYPE,
            description: "A member verified this person's identity",
            createdAt: "2026-01-01T00:00:00Z",
            createdByDid: "did:key:zAdmin",
          },
        ],
      },
    },
    ...extra,
  ];
}

describe("RequirementsPanel", () => {
  it("shows each criterion's requirements in words with its digest", async () => {
    const requests = mockFetch(routes());
    renderWithProviders(<RequirementsPanel />);

    expect(
      await screen.findByText("Statements from at least 2 distinct eligible vetters."),
    ).toBeTruthy();
    expect(screen.getByText("At least 1 of them made in person.")).toBeTruthy();
    expect(screen.getByText("zQmKernelDigest")).toBeTruthy();
    expect(screen.getByText(/^Require at least 1 statement/)).toBeTruthy();
    expect(screen.getByText("This criterion requires no vetting.")).toBeTruthy();

    // The criteria are read from the schema store, and the digests from the
    // manifest the applicant receives.
    await waitFor(() =>
      expect(requests.some((r) => r.url === "/v1/schemas/accepts")).toBe(true),
    );
    const manifest = requests.find((r) => r.url === "/v1/join-requests/manifest")!;
    expect(manifest.headers.get("Trust-Task")).toBe(
      "https://trusttasks.org/spec/vtc/join-requests/manifest/0.2",
    );
  });

  it("removes a criterion once the admin confirms what it costs", async () => {
    const requests = mockFetch(
      routes([{ method: "DELETE", path: "/v1/schemas/accepts/legacy", body: { id: "legacy" } }]),
    );
    renderWithProviders(<RequirementsPanel />);

    const card = (
      await screen.findByRole("heading", { name: "Criterion legacy" })
    ).closest("section")!;
    fireEvent.click(within(card).getByRole("button", { name: "Remove" }));

    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText(/Anyone already gathering statements/),
    ).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove criterion" }));

    await waitFor(() =>
      expect(
        requests.some(
          (r) => r.method === "DELETE" && r.url === "/v1/schemas/accepts/legacy",
        ),
      ).toBe(true),
    );
  });

  it("opens the editor on a stored criterion, and on a new one", async () => {
    mockFetch(routes());
    renderWithProviders(<RequirementsPanel />);

    const card = (
      await screen.findByRole("heading", { name: "Criterion kernel-developer" })
    ).closest("section")!;
    fireEvent.click(within(card).getByRole("button", { name: "Edit" }));
    expect(
      await screen.findByRole("heading", { name: "Editing kernel-developer" }),
    ).toBeTruthy();
    // The stored values are what the form opens on.
    expect((screen.getByLabelText("Statements required") as HTMLInputElement).value).toBe("2");
    expect((screen.getByLabelText("Name") as HTMLInputElement).readOnly).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    fireEvent.click(await screen.findByRole("button", { name: "Add a criterion" }));
    expect(await screen.findByRole("heading", { name: "Add a criterion" })).toBeTruthy();
    expect((screen.getByLabelText("Name") as HTMLInputElement).readOnly).toBe(false);
  });
});
