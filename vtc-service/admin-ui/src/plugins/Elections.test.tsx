import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Elections } from "@/plugins/elections";
import {
  ELECTIONS_CERTIFY_TASK,
  ELECTIONS_CREATE_TASK,
  ELECTIONS_LIST_TASK,
  ELECTIONS_SHOW_TASK,
} from "@/lib/elections-api";
import { ACTIONS_SHOW_TASK, NEXT_STEP_TYPE } from "@/lib/parked-action";
import { mockFetch, renderWithProviders, sentPayloads, taskRoute, type MockRoute } from "@/test/render";

// Every read and write is a signed document; the stand-in sends them unsigned
// so the tables below answer them without a console key.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));
vi.mock("@/lib/signed-act", async (original) => ({
  ...(await original<typeof import("@/lib/signed-act")>()),
  postSignedWithStepUp: (await import("@/test/signed-read")).unsignedTask,
}));

const BOX = "did:webvh:QmBallots:votes.example.net";

const manifest = {
  electionId: "agm-2027",
  community: "did:webvh:QmCommunity:community.example",
  title: "Annual meeting",
  questions: [{ key: "chair", type: "choice", text: "Chair?" }],
  registrationOpens: "2026-11-01T00:00:00Z",
  votingOpens: "2026-11-08T00:00:00Z",
  votingCloses: "2026-11-15T00:00:00Z",
  binding: false,
  allowEarlyClose: false,
};

const head = { electionId: "agm-2027", treeSize: 7, rootHash: "zQmRoot", issuedAt: "2026-11-15T00:00:03Z" };

const shown = (state: string, extra: object = {}) => ({
  manifest,
  manifestDigest: "zQmDigest",
  state,
  parameters: { suite: "ps-ddh-bls12381", votingKey: "zKey" },
  disclosure: {
    ballotBox: BOX,
    ballotBoxOperator: "Ballots Example Ltd",
    sameOperator: true,
    boardVisibility: "public",
    auditors: [],
    revote: "replace",
    coercionResistance: false,
  },
  checkpoints: [{ head, document: {} }],
  ticketsIssued: 4,
  ...extra,
});

const routes = (extra: MockRoute[] = []): MockRoute[] => [
  taskRoute("https://trusttasks.org/spec/trust-task-discovery/0.3", {
    supportedTypes: [ELECTIONS_LIST_TASK],
  }),
  taskRoute(ELECTIONS_LIST_TASK, {
    elections: [
      {
        electionId: "agm-2027",
        title: "Annual meeting",
        state: "voting",
        votingOpens: manifest.votingOpens,
        votingCloses: manifest.votingCloses,
        binding: false,
        ticketHeld: false,
      },
    ],
  }),
  ...extra,
];

describe("Elections", () => {
  it("says so when this VTC was built without elections", async () => {
    mockFetch([
      taskRoute("https://trusttasks.org/spec/trust-task-discovery/0.3", { supportedTypes: [] }),
    ]);
    renderWithProviders(<Elections />, { route: "/elections", path: "/elections/*" });
    expect(await screen.findByText("Elections are not built into this VTC")).toBeTruthy();
  });

  it("lists the community's elections", async () => {
    mockFetch(routes());
    renderWithProviders(<Elections />, { route: "/elections", path: "/elections/*" });
    expect(await screen.findByRole("link", { name: "Annual meeting" })).toBeTruthy();
    expect(screen.getByRole("cell", { name: "Voting" })).toBeTruthy();
  });

  it("shows what members are told, and warns when one operator runs both", async () => {
    mockFetch(routes([taskRoute(ELECTIONS_SHOW_TASK, shown("voting"))]));
    renderWithProviders(<Elections />, { route: "/elections/agm-2027", path: "/elections/*" });
    expect(await screen.findByText(/Ballots Example Ltd/)).toBeTruthy();
    expect(screen.getByText(/Run by the same operator as this community/)).toBeTruthy();
    expect(screen.getByText("4")).toBeTruthy();
  });

  it("certifies a closed election and sends the attestations as given", async () => {
    const requests = mockFetch(
      routes([
        taskRoute(ELECTIONS_SHOW_TASK, shown("closed")),
        taskRoute(ELECTIONS_CERTIFY_TASK, {
          electionId: "agm-2027",
          result: { electionId: "agm-2027", manifestDigest: "zQmDigest", ballotsCounted: 3, questions: [], head },
          head,
          certifiedAt: "2026-11-16T00:00:00Z",
          auditAttestations: [],
        }),
      ]),
    );
    renderWithProviders(<Elections />, { route: "/elections/agm-2027", path: "/elections/*" });
    fireEvent.click(await screen.findByRole("button", { name: "Certify the result" }));
    await waitFor(() => expect(sentPayloads(requests, ELECTIONS_CERTIFY_TASK)).toHaveLength(1));
    expect(sentPayloads(requests, ELECTIONS_CERTIFY_TASK)[0]).toEqual({
      electionId: "agm-2027",
      auditAttestations: [],
    });
  });

  it("shows a binding creation as sent for approval", async () => {
    mockFetch(
      routes([
        {
          method: "POST",
          path: "/v1/trust-tasks",
          task: ELECTIONS_CREATE_TASK,
          status: 202,
          body: () => ({
            type: NEXT_STEP_TYPE,
            payload: {
              continuation: "proceed",
              message: "Sent for approval — 1 of 1 administrator(s) must approve.",
              expects: [{ typeUri: ACTIONS_SHOW_TASK, hint: { actionId: "act-7" } }],
            },
          }),
        },
      ]),
    );
    renderWithProviders(<Elections />, { route: "/elections/new", path: "/elections/*" });
    const text = await screen.findByLabelText(/^Manifest/);
    fireEvent.change(text, { target: { value: JSON.stringify({ ...manifest, binding: true }) } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    expect((await screen.findByRole("status")).textContent).toContain("Sent for approval");
  });
});
