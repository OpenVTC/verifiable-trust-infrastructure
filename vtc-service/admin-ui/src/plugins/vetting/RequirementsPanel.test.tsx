import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { AcceptsCriterion } from "@/lib/wire-types";
import { RequirementsPanel } from "@/plugins/vetting/RequirementsPanel";
import { type MockRoute, mockFetch, renderWithProviders, sentPayloads, taskRoute } from "@/test/render";

// Signed reads go through the unsigned stand-in to the `mockFetch` table: the
// test browser holds no console key.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));

const MANIFEST_TASK = "https://trusttasks.org/spec/vtc/join-requests/manifest/0.2";

const STATEMENT_TYPE =
  "https://registry.trustoverip.org/dtg/vsc/vetted/1";

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
    { id: "vetting", format: "ldp_vc", meta: { type_values: ["StatementCredential"] } },
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

const ACCEPTS_LIST_TASK = "https://trusttasks.org/spec/vtc/schemas/accepts/list/0.1";
const ACCEPTS_DELETE_TASK = "https://trusttasks.org/spec/vtc/schemas/accepts/delete/0.1";

function routes(extra: MockRoute[] = []): MockRoute[] {
  return [
    taskRoute(ACCEPTS_LIST_TASK, {
      items: [
        criterion("kernel-developer", REQUIREMENTS, "Two vetters, at least one in person"),
        criterion("legacy", { ...REQUIREMENTS, minStatements: 0 }),
        criterion("open-door", undefined),
      ],
    }),
    taskRoute(MANIFEST_TASK, {
      communityDid: "did:web:vtc.example.org",
      criteria: [
        { id: "kernel-developer", presentationDefinition: {}, vetting: REQUIREMENTS, requirementsDigest: "zQmKernelDigest" },
        { id: "legacy", presentationDefinition: {}, requirementsDigest: "zQmLegacyDigest" },
        { id: "open-door", presentationDefinition: {} },
      ],
    }),
    taskRoute("https://trusttasks.org/spec/vtc/endorsement-types/list/0.1", {
        items: [
          {
            typeUri: STATEMENT_TYPE,
            description: "A member verified this person's identity",
            createdAt: "2026-01-01T00:00:00Z",
            createdByDid: "did:key:zAdmin",
          },
        ],
      }),
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
    await waitFor(() => expect(sentPayloads(requests, ACCEPTS_LIST_TASK).length).toBe(1));
    expect(sentPayloads(requests, MANIFEST_TASK)).toContainEqual({});
  });

  it("removes a criterion once the admin confirms what it costs", async () => {
    const requests = mockFetch(
      routes([taskRoute(ACCEPTS_DELETE_TASK, { id: "legacy" })]),
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
      expect(sentPayloads(requests, ACCEPTS_DELETE_TASK)).toContainEqual({ id: "legacy" }),
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
