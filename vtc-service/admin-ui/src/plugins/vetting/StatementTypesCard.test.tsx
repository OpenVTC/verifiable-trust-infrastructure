import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { StatementTypesCard } from "@/plugins/vetting/StatementTypesCard";
import { type MockRoute, mockFetch, renderWithProviders } from "@/test/render";

const STATEMENT_TYPE =
  "https://firstperson.network/endorsements/identity-vetting/0.1";

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
    renderWithProviders(<StatementTypesCard />);

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
    renderWithProviders(<StatementTypesCard />);

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
    renderWithProviders(<StatementTypesCard />);

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
});
