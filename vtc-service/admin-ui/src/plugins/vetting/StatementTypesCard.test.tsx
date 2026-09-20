import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { StatementTypesCard } from "@/plugins/vetting/StatementTypesCard";
import type { AcceptsCriterion } from "@/lib/wire-types";
import { type MockRoute, mockFetch, renderWithProviders } from "@/test/render";

const STATEMENT_TYPE =
  "https://firstperson.network/endorsements/identity-vetting/0.1";

const REGISTERED = {
  typeUri: STATEMENT_TYPE,
  description: "A member verified this person's identity",
  createdAt: "2026-01-01T00:00:00Z",
  createdByDid: "did:key:zAdmin",
};

const listRoute: MockRoute = {
  path: "/v1/endorsement-types",
  body: { items: [REGISTERED] },
};

/** A criterion counting statements of `statementType`. */
const criterion = (id: string, statementType: string): AcceptsCriterion =>
  ({
    id,
    query: {},
    vetting: { version: "0.1", statementType },
    createdAt: "2026-01-01T00:00:00Z",
    createdByDid: "did:key:zAdmin",
  }) as unknown as AcceptsCriterion;

const registerRoute: MockRoute = {
  method: "POST",
  path: "/v1/endorsement-types",
  status: 201,
  body: (req) => ({
    endorsementType: {
      ...(req.body as object),
      createdAt: "2026-09-01T00:00:00Z",
      createdByDid: "did:key:zAdmin",
    },
  }),
};

describe("StatementTypesCard", () => {
  it("registers the identity-vetting type when the community has none", async () => {
    const requests = mockFetch([
      { path: "/v1/endorsement-types", body: { items: [] } },
      registerRoute,
    ]);
    renderWithProviders(<StatementTypesCard criteria={[]} />);

    expect(
      await screen.findByText(/The identity-vetting statement type is not registered/),
    ).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Register it" }));

    await waitFor(() =>
      expect(requests.some((r) => r.method === "POST")).toBe(true),
    );
    const post = requests.find((r) => r.method === "POST")!;
    expect(post.body).toEqual({
      typeUri: STATEMENT_TYPE,
      description: "A member verified this person's identity",
    });
    expect(post.headers.get("Trust-Task")).toBe(
      "https://trusttasks.org/spec/vtc/endorsement-types/register/0.1",
    );
  });

  it("lists what is registered and does not offer to register it again", async () => {
    mockFetch([
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
    ]);
    renderWithProviders(<StatementTypesCard criteria={[]} />);

    expect(await screen.findByText(STATEMENT_TYPE)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Register it" })).toBeNull();
  });

  it("registers a type an admin types in", async () => {
    const requests = mockFetch([
      {
        path: "/v1/endorsement-types",
        body: {
          items: [
            {
              typeUri: STATEMENT_TYPE,
              createdAt: "2026-01-01T00:00:00Z",
              createdByDid: "did:key:zAdmin",
            },
          ],
        },
      },
      registerRoute,
    ]);
    renderWithProviders(<StatementTypesCard criteria={[]} />);

    await screen.findByText(STATEMENT_TYPE);
    fireEvent.change(screen.getByLabelText("Type URI"), {
      target: { value: "https://example.org/endorsements/affiliation/0.1" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Register type" }));

    await waitFor(() => expect(requests.some((r) => r.method === "POST")).toBe(true));
    expect(requests.find((r) => r.method === "POST")!.body).toEqual({
      typeUri: "https://example.org/endorsements/affiliation/0.1",
    });
  });

  it("offers to remove a type no criterion requires", async () => {
    const requests = mockFetch([
      listRoute,
      {
        method: "DELETE",
        path: `/v1/endorsement-types/${encodeURIComponent(STATEMENT_TYPE)}`,
        body: { typeUri: STATEMENT_TYPE },
      },
    ]);
    renderWithProviders(<StatementTypesCard criteria={[]} />);

    expect(await screen.findByText("No criterion requires it.")).toBeTruthy();
    const remove = screen.getByRole("button", { name: "Remove" });
    expect(remove.hasAttribute("disabled")).toBe(false);

    fireEvent.click(remove);
    fireEvent.click(await screen.findByRole("button", { name: "Remove type" }));

    await waitFor(() =>
      expect(requests.some((r) => r.method === "DELETE")).toBe(true),
    );
    const del = requests.find((r) => r.method === "DELETE")!;
    expect(del.url).toContain(encodeURIComponent(STATEMENT_TYPE));
    expect(del.headers.get("Trust-Task")).toBe(
      "https://trusttasks.org/spec/vtc/endorsement-types/delete/0.1",
    );
  });

  it("names the criteria that require a type, and refuses to remove it", async () => {
    const requests = mockFetch([listRoute]);
    renderWithProviders(
      <StatementTypesCard
        criteria={[
          criterion("kernel-developer", STATEMENT_TYPE),
          criterion("contributor", STATEMENT_TYPE),
          criterion("unrelated", "https://example.org/other/0.1"),
        ]}
      />,
    );

    expect(await screen.findByText("kernel-developer")).toBeTruthy();
    expect(screen.getByText("contributor")).toBeTruthy();
    expect(screen.queryByText("unrelated")).toBeNull();
    expect(
      screen.getByRole("button", { name: "Remove" }).hasAttribute("disabled"),
    ).toBe(true);
    expect(requests.some((r) => r.method === "DELETE")).toBe(false);
  });

  it("does not offer removal while the criteria are unknown", async () => {
    mockFetch([listRoute]);
    renderWithProviders(<StatementTypesCard criteria={null} />);

    expect(
      await screen.findByText("Checking which criteria require it…"),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Remove" }).hasAttribute("disabled"),
    ).toBe(true);
  });

  it("shows what the daemon says when it refuses the removal", async () => {
    mockFetch([
      listRoute,
      {
        method: "DELETE",
        path: `/v1/endorsement-types/${encodeURIComponent(STATEMENT_TYPE)}`,
        status: 409,
        // `AppError::Conflict` serialises as `{ error: "conflict: <display>" }`
        // — not `{ message }`, which only the Trust-Task variants carry.
        body: {
          error:
            "conflict: endorsement-type-in-use: '" +
            STATEMENT_TYPE +
            "' is still referenced — 2 live endorsement(s) of it exist. Revoke the endorsements before deleting the type.",
        },
      },
    ]);
    renderWithProviders(<StatementTypesCard criteria={[]} />);

    fireEvent.click(await screen.findByRole("button", { name: "Remove" }));
    fireEvent.click(await screen.findByRole("button", { name: "Remove type" }));

    expect(await screen.findByText(/Could not remove the type/)).toBeTruthy();
    expect(
      await screen.findByText(/2 live endorsement\(s\) of it exist/),
    ).toBeTruthy();
  });
});
