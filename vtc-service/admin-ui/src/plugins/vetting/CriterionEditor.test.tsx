import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DEFAULT_ACCEPTS_QUERY } from "@/lib/vetting";
import type { AcceptsCriterion, EndorsementType } from "@/lib/wire-types";
import { CriterionEditor } from "@/plugins/vetting/CriterionEditor";
import { mockFetch, renderWithProviders } from "@/test/render";

const STATEMENT_TYPE =
  "https://firstperson.network/endorsements/identity-vetting/0.1";

const TYPES: EndorsementType[] = [
  {
    typeUri: STATEMENT_TYPE,
    description: "A member verified this person's identity",
    createdAt: "2026-01-01T00:00:00Z",
    createdByDid: "did:key:zAdmin",
  } as unknown as EndorsementType,
];

const stored = (vetting: unknown): AcceptsCriterion =>
  ({
    id: "kernel-developer",
    query: DEFAULT_ACCEPTS_QUERY,
    vetting,
    createdAt: "2026-01-01T00:00:00Z",
    createdByDid: "did:key:zAdmin",
  }) as unknown as AcceptsCriterion;

const saveRoute = {
  method: "POST",
  path: "/v1/schemas/accepts",
  status: 201,
  body: (req: { body: unknown }) => req.body,
};

describe("CriterionEditor", () => {
  it("writes a criterion that admits on one vetter", async () => {
    const requests = mockFetch([saveRoute]);
    renderWithProviders(
      <CriterionEditor
        criterion={null}
        existingIds={["open-door"]}
        statementTypes={TYPES}
        onDone={() => {}}
      />,
    );

    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "vetted-member" },
    });
    fireEvent.change(screen.getByLabelText("Description"), {
      target: { value: "One vetter must confirm who you are" },
    });
    fireEvent.change(screen.getByLabelText("Statement type"), {
      target: { value: STATEMENT_TYPE },
    });

    // A new criterion starts at one vetter, in person or on video, verifying a
    // legal name — so the shortest useful policy needs no further typing.
    expect(
      screen.getByText("Statements from at least 1 distinct eligible vetter."),
    ).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Add criterion" }));

    await waitFor(() => expect(requests.length).toBe(1));
    expect(requests[0]!.body).toEqual({
      id: "vetted-member",
      description: "One vetter must confirm who you are",
      query: DEFAULT_ACCEPTS_QUERY,
      vetting: {
        version: "0.1",
        statementType: STATEMENT_TYPE,
        minStatements: 1,
        acceptedMethods: ["inPerson", "video"],
        eligibleVetters: { role: "vetter" },
        requiredClaims: ["name.legal"],
        maxStatementAge: "P120D",
        independence: { requireConsistentIdentityCommitment: true },
      },
    });
    // The schema store is one of the daemon's Trust-Task-exempt routes.
    expect(requests[0]!.headers.get("Trust-Task")).toBeNull();
  });

  it("refuses to send requirements the community would reject, and says why", async () => {
    const requests = mockFetch([saveRoute]);
    renderWithProviders(
      <CriterionEditor
        criterion={null}
        existingIds={[]}
        statementTypes={TYPES}
        onDone={() => {}}
      />,
    );

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "vetted" } });
    fireEvent.change(screen.getByLabelText("Statement type"), {
      target: { value: STATEMENT_TYPE },
    });
    fireEvent.change(screen.getByLabelText("Statements required"), {
      target: { value: "0" },
    });

    expect(screen.getByText(/^Require at least 1 statement/)).toBeTruthy();
    const save = screen.getByRole("button", { name: "Add criterion" });
    expect((save as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(save);
    expect(requests.length).toBe(0);

    // A duration the community cannot apply is caught the same way.
    fireEvent.change(screen.getByLabelText("Statements required"), {
      target: { value: "1" },
    });
    fireEvent.change(screen.getByLabelText("A statement counts for"), {
      target: { value: "P4M" },
    });
    expect(
      screen.getByText(/The maximum statement age "P4M" is not a duration/),
    ).toBeTruthy();
  });

  it("names a criterion that already exists rather than replacing it", () => {
    mockFetch([saveRoute]);
    renderWithProviders(
      <CriterionEditor
        criterion={null}
        existingIds={["vetted-member"]}
        statementTypes={TYPES}
        onDone={() => {}}
      />,
    );

    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "vetted-member" },
    });
    expect(
      screen.getByText(/A criterion called "vetted-member" already exists/),
    ).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Add criterion" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it("keeps the difference between no documentation floor and an empty one", async () => {
    const requests = mockFetch([saveRoute]);
    renderWithProviders(
      <CriterionEditor
        criterion={stored({
          version: "0.1",
          statementType: STATEMENT_TYPE,
          minStatements: 1,
          acceptedMethods: ["video"],
          eligibleVetters: { role: "vetter" },
        })}
        existingIds={["kernel-developer"]}
        statementTypes={TYPES}
        onDone={() => {}}
      />,
    );

    // Absent: each vetter decides what they accept.
    expect(
      screen.getByText("Each vetter decides which documents they accept."),
    ).toBeTruthy();

    fireEvent.click(screen.getByRole("switch", { name: /Only these documents count/ }));
    expect(screen.getByText("Vetters may rely only on: no documents.")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Save criterion" }));
    await waitFor(() => expect(requests.length).toBe(1));
    const body = requests[0]!.body as { vetting: { acceptedDocumentClasses: string[] } };
    expect(body.vetting.acceptedDocumentClasses).toEqual([]);
  });

  it("offers a minimum only for a method the criterion accepts", () => {
    mockFetch([saveRoute]);
    renderWithProviders(
      <CriterionEditor
        criterion={null}
        existingIds={[]}
        statementTypes={TYPES}
        onDone={() => {}}
      />,
    );

    // inPerson and video are accepted by default; prior acquaintance is not.
    expect(screen.getByLabelText("In person")).toBeTruthy();
    expect(screen.queryByLabelText("Prior acquaintance")).toBeTruthy();
    const counts = screen.getByText("Of those, at least").parentElement!;
    expect(counts.querySelector("#req-min-inPerson")).toBeTruthy();
    expect(counts.querySelector("#req-min-priorAcquaintance")).toBeNull();

    fireEvent.click(screen.getByRole("checkbox", { name: "Prior acquaintance" }));
    expect(counts.querySelector("#req-min-priorAcquaintance")).toBeTruthy();
  });
});
