import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DEFAULT_ACCEPTS_QUERY } from "@/lib/vetting";
import type { AcceptsCriterion, EndorsementType } from "@/lib/wire-types";
import { CriterionEditor } from "@/plugins/vetting/CriterionEditor";
import { mockFetch, renderWithProviders, taskRoute } from "@/test/render";

// Signed documents reach the fetch table unsigned; there is no console key here.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));

const STATEMENT_TYPE =
  "https://registry.trustoverip.org/dtg/vsc/vetted/1";

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
    admission: "automatic",
    vetting,
    createdAt: "2026-01-01T00:00:00Z",
    createdByDid: "did:key:zAdmin",
  }) as unknown as AcceptsCriterion;

const saveRoute = taskRoute(
  "https://trusttasks.org/spec/vtc/schemas/accepts/register/0.2",
  (payload) => ({ criterion: payload }),
);

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
    // A new criterion is reviewed unless the administrator says otherwise,
    // and asks for no credential or invitation unless they add one.
    expect((requests[0]!.body as { payload: unknown }).payload).toEqual({
      id: "vetted-member",
      admission: "review",
      description: "One vetter must confirm who you are",
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
  });

  it("writes open admission: a criterion that asks for nothing and admits", async () => {
    const requests = mockFetch([saveRoute]);
    renderWithProviders(
      <CriterionEditor
        criterion={null}
        existingIds={[]}
        statementTypes={TYPES}
        onDone={() => {}}
      />,
    );
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "open" } });
    fireEvent.click(screen.getByRole("switch", { name: /must be vetted by members/ }));
    fireEvent.click(screen.getByRole("radio", { name: "Admit them automatically" }));
    fireEvent.click(screen.getByRole("button", { name: "Add criterion" }));

    await waitFor(() => expect(requests.length).toBe(1));
    expect((requests[0]!.body as { payload: unknown }).payload).toEqual({
      id: "open",
      admission: "automatic",
    });
  });

  it("writes an invitation and a credential requirement with whose credentials count", async () => {
    const requests = mockFetch([saveRoute]);
    renderWithProviders(
      <CriterionEditor
        criterion={null}
        existingIds={[]}
        statementTypes={TYPES}
        onDone={() => {}}
      />,
    );
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "partners" } });
    fireEvent.click(screen.getByRole("switch", { name: /must be vetted by members/ }));
    fireEvent.click(screen.getByRole("switch", { name: /hold an invitation this community issued/ }));
    fireEvent.click(screen.getByRole("switch", { name: /must present credentials/ }));
    fireEvent.change(screen.getByLabelText("Whose credentials count"), {
      target: { value: "recognised" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add criterion" }));

    await waitFor(() => expect(requests.length).toBe(1));
    expect((requests[0]!.body as { payload: unknown }).payload).toEqual({
      id: "partners",
      admission: "review",
      query: DEFAULT_ACCEPTS_QUERY,
      credentialIssuers: "recognised",
      invitationRequired: true,
    });
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
    const body = (requests[0]!.body as { payload: unknown }).payload as {
      vetting: { acceptedDocumentClasses: string[] };
    };
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
