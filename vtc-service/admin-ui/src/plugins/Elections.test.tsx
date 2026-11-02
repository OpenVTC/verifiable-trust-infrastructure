import { fireEvent, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Elections } from "@/plugins/elections";
import {
  ELECTIONS_BALLOT_BOXES_LIST_TASK,
  ELECTIONS_CERTIFY_TASK,
  ELECTIONS_CREATE_TASK,
  ELECTIONS_LIST_TASK,
  ELECTIONS_SHOW_TASK,
} from "@/lib/elections-api";
import { DRAFT_STORAGE_KEY } from "@/plugins/ElectionBuilder";
import { ACTIONS_SHOW_TASK, NEXT_STEP_TYPE } from "@/lib/parked-action";
import { mockFetch, renderWithProviders, sentPayloads, taskRoute, type MockRoute } from "@/test/render";

// Every read and write is a signed document; the stand-in sends them unsigned
// so the tables below answer them without a console key.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
  vtcDid: async () => "did:webvh:QmCommunity:community.example",
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
  registrationOpensAt: "2026-11-01T00:00:00Z",
  votingOpensAt: "2026-11-08T00:00:00Z",
  votingClosesAt: "2026-11-15T00:00:00Z",
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
        votingOpensAt: manifest.votingOpensAt,
        votingClosesAt: manifest.votingClosesAt,
        binding: false,
        ticketHeld: false,
      },
    ],
  }),
  ...extra,
];

beforeEach(() => sessionStorage.removeItem(DRAFT_STORAGE_KEY));

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
    expect((await screen.findAllByText(/Ballots Example Ltd/)).length).toBeGreaterThan(0);
    expect(screen.getByText(/also runs this community/)).toBeTruthy();
    expect(screen.getByText("4")).toBeTruthy();
  });

  it("tells members when written answers are released, and warns below 10 (VTI-VOT-090)", async () => {
    mockFetch(
      routes([taskRoute(ELECTIONS_SHOW_TASK, shown("voting", { manifest: { ...manifest, textReleaseThreshold: 3 } }))]),
    );
    renderWithProviders(<Elections />, { route: "/elections/agm-2027", path: "/elections/*" });
    expect(await screen.findByText("Written answers")).toBeTruthy();
    expect(screen.getByText(/Released once 3 ballots are counted/)).toBeTruthy();
    expect(screen.getByText(/a written answer may identify who wrote it/)).toBeTruthy();
  });

  it("says when written answers are released, without a warning at 10", async () => {
    mockFetch(
      routes([taskRoute(ELECTIONS_SHOW_TASK, shown("voting", { manifest: { ...manifest, textReleaseThreshold: 10 } }))]),
    );
    renderWithProviders(<Elections />, { route: "/elections/agm-2027", path: "/elections/*" });
    expect(await screen.findByText(/Released once 10 ballots are counted/)).toBeTruthy();
    expect(screen.queryByText(/may identify who wrote it/)).toBeNull();
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

  it("shows a certified result in the members' words, and says why written answers are held back", async () => {
    const m = {
      ...manifest,
      textReleaseThreshold: 10,
      questions: [
        { key: "chair", type: "choice", text: "Chair?", options: [{ key: "ana", label: "Ana Lopez" }, { key: "bo" }] },
        { key: "ideas", type: "text", text: "What should we build next?" },
      ],
    };
    mockFetch(
      routes([
        taskRoute(ELECTIONS_SHOW_TASK, {
          ...shown("tallied"),
          manifest: m,
          certified: {
            certifiedAt: "2026-11-16T00:00:00Z",
            auditAttestations: [],
            result: {
              electionId: "agm-2027",
              manifestDigest: "zQmDigest",
              ballotsCounted: 1,
              head,
              questions: [
                { question: "chair", choice: { ana: 1, bo: 0 }, abstained: 0 },
                { question: "ideas", withheld: true, abstained: 0 },
              ],
            },
          },
        }),
      ]),
    );
    renderWithProviders(<Elections />, { route: "/elections/agm-2027", path: "/elections/*" });
    expect(await screen.findByRole("heading", { name: "What should we build next?" })).toBeTruthy();
    expect(screen.getByText(/Ana Lopez/)).toBeTruthy();
    expect(screen.getByText(/at least 10\s+ballots are counted, and this election counted 1/)).toBeTruthy();
    expect(screen.getByText(/1\s+ballot counted/)).toBeTruthy();
  });

  it("lists written answers once they are released", async () => {
    const m = { ...manifest, questions: [{ key: "ideas", type: "text", text: "Ideas?" }] };
    mockFetch(
      routes([
        taskRoute(ELECTIONS_SHOW_TASK, {
          ...shown("tallied"),
          manifest: m,
          certified: {
            certifiedAt: "2026-11-16T00:00:00Z",
            auditAttestations: [],
            result: {
              electionId: "agm-2027",
              manifestDigest: "zQmDigest",
              ballotsCounted: 12,
              head,
              questions: [{ question: "ideas", text: ["Dark mode", "Offline voting"], abstained: 10 }],
            },
          },
        }),
      ]),
    );
    renderWithProviders(<Elections />, { route: "/elections/agm-2027", path: "/elections/*" });
    expect(await screen.findByText("Offline voting")).toBeTruthy();
    expect(screen.getByText(/10 ballots left this question blank/)).toBeTruthy();
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
    fireEvent.click(await screen.findByRole("tab", { name: "JSON" }));
    const text = await screen.findByLabelText(/^Manifest/);
    fireEvent.change(text, { target: { value: JSON.stringify({ ...manifest, binding: true }) } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    expect((await screen.findByRole("status")).textContent).toContain("Sent for approval");
  });

  describe("the manifest builder", () => {
    const next = () => fireEvent.click(screen.getByRole("button", { name: "Next" }));

    it("builds the manifest step by step and creates it", async () => {
      const requests = mockFetch(
        routes([
          taskRoute(ELECTIONS_CREATE_TASK, {
            electionId: "spring-poll",
            manifestDigest: "zQmDigest",
            state: "registered",
          }),
          taskRoute(ELECTIONS_SHOW_TASK, shown("registered")),
        ]),
      );
      renderWithProviders(<Elections />, { route: "/elections/new", path: "/elections/*" });
      fireEvent.change(await screen.findByLabelText("Title"), { target: { value: "Spring poll" } });
      expect((screen.getByLabelText(/^Identifier/) as HTMLInputElement).value).toBe("spring-poll");
      next();
      fireEvent.change(screen.getByLabelText("What is asked"), { target: { value: "Picnic?" } });
      fireEvent.click(screen.getByRole("button", { name: "Use Yes / No / Abstain" }));
      next();
      next();
      next();
      fireEvent.change(screen.getByLabelText(/^Ballot box DID/), { target: { value: BOX } });
      next();
      expect(screen.getByRole("heading", { name: "Review" })).toBeTruthy();
      const create = screen.getByRole("button", { name: "Create" });
      await waitFor(() => expect((create as HTMLButtonElement).disabled).toBe(false));
      fireEvent.click(create);
      await waitFor(() => expect(sentPayloads(requests, ELECTIONS_CREATE_TASK)).toHaveLength(1));
      const sent = (sentPayloads(requests, ELECTIONS_CREATE_TASK)[0] as { manifest: Record<string, unknown> }).manifest;
      expect(sent).toMatchObject({
        electionId: "spring-poll",
        community: "did:webvh:QmCommunity:community.example",
        title: "Spring poll",
        ballotBox: BOX,
        secrecy: "open",
        roll: { rule: "members" },
        binding: false,
        questions: [
          {
            key: "q1",
            type: "choice",
            text: "Picnic?",
            options: [
              { key: "yes", label: "Yes" },
              { key: "no", label: "No" },
              { key: "abstain", label: "Abstain" },
            ],
            minSelections: 1,
            maxSelections: 1,
            optional: true,
          },
        ],
      });
      // Created: the draft is gone.
      expect(sessionStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
    });

    it("takes a text release threshold below 10, and warns in Counting and in Review", async () => {
      const requests = mockFetch(
        routes([
          taskRoute(ELECTIONS_CREATE_TASK, { electionId: "small-poll", manifestDigest: "zQmDigest", state: "registered" }),
          taskRoute(ELECTIONS_SHOW_TASK, shown("registered")),
        ]),
      );
      renderWithProviders(<Elections />, { route: "/elections/new", path: "/elections/*" });
      fireEvent.change(await screen.findByLabelText("Title"), { target: { value: "Small poll" } });
      next();
      fireEvent.change(screen.getByLabelText("What is asked"), { target: { value: "Picnic?" } });
      fireEvent.click(screen.getByRole("button", { name: "Use Yes / No / Abstain" }));
      next();
      next();
      next();
      fireEvent.change(screen.getByLabelText(/^Ballot box DID/), { target: { value: BOX } });
      const threshold = screen.getByLabelText(/^Ballots counted before text answers are shown/) as HTMLInputElement;
      expect(threshold.value).toBe("10");
      expect(screen.queryByText(/may identify who wrote it/)).toBeNull();
      fireEvent.change(threshold, { target: { value: "3" } });
      expect(screen.getByText(/may identify who wrote it/)).toBeTruthy();
      next();
      expect(screen.getByRole("heading", { name: "Review" })).toBeTruthy();
      expect(screen.getByText(/may identify who wrote it/)).toBeTruthy();
      const create = screen.getByRole("button", { name: "Create" });
      await waitFor(() => expect((create as HTMLButtonElement).disabled).toBe(false));
      fireEvent.click(create);
      await waitFor(() => expect(sentPayloads(requests, ELECTIONS_CREATE_TASK)).toHaveLength(1));
      const sent = (sentPayloads(requests, ELECTIONS_CREATE_TASK)[0] as { manifest: Record<string, unknown> }).manifest;
      expect(sent.textReleaseThreshold).toBe(3);
    });

    it("holds Create until the review is clean, and says what to fix", async () => {
      mockFetch(routes());
      renderWithProviders(<Elections />, { route: "/elections/new", path: "/elections/*" });
      fireEvent.click(await screen.findByRole("button", { name: /Review/ }));
      expect(screen.getByRole("alert").textContent).toContain("Name the ballot box.");
      expect((screen.getByRole("button", { name: "Create" }) as HTMLButtonElement).disabled).toBe(true);
      fireEvent.click(screen.getByRole("button", { name: "Go to Counting" }));
      expect(screen.getByLabelText(/^Ballot box DID/)).toBeTruthy();
    });

    describe("with the trusted ballot boxes listed", () => {
      const OWN = "did:webvh:QmOwnBox:votes.community.example";
      const listing = (ballotBoxes: object[]): MockRoute[] => [
        taskRoute("https://trusttasks.org/spec/trust-task-discovery/0.3", {
          supportedTypes: [ELECTIONS_LIST_TASK, ELECTIONS_BALLOT_BOXES_LIST_TASK],
        }),
        taskRoute(ELECTIONS_BALLOT_BOXES_LIST_TASK, { ballotBoxes }),
      ];
      const boxes = [
        { did: BOX, operator: "Ballots Example Ltd", sameOperator: false },
        { did: OWN, operator: "Community Example Hosting", sameOperator: true },
      ];

      it("offers them to choose from, and says when one operator runs both", async () => {
        mockFetch([...listing(boxes), ...routes()]);
        renderWithProviders(<Elections />, { route: "/elections/new", path: "/elections/*" });
        fireEvent.click(await screen.findByRole("button", { name: /Counting/ }));
        const select = (await screen.findByLabelText(/^Ballot box/)) as HTMLSelectElement;
        expect(select.tagName).toBe("SELECT");
        fireEvent.change(select, { target: { value: OWN } });
        expect(screen.getByText(/runs both this community and this ballot box/)).toBeTruthy();
        fireEvent.change(select, { target: { value: BOX } });
        expect(screen.queryByText(/runs both this community and this ballot box/)).toBeNull();
        fireEvent.click(screen.getByRole("button", { name: /Review/ }));
        expect(screen.queryByText("Not one of this community's trusted ballot boxes.")).toBeNull();
      });

      it("still takes a typed DID, and says when it is not trusted", async () => {
        mockFetch([...listing(boxes), ...routes()]);
        renderWithProviders(<Elections />, { route: "/elections/new", path: "/elections/*" });
        fireEvent.click(await screen.findByRole("button", { name: /Counting/ }));
        const select = await screen.findByLabelText(/^Ballot box/);
        fireEvent.change(select, { target: { value: "\u0000other" } });
        fireEvent.change(screen.getByLabelText(/^Ballot box DID/), {
          target: { value: "did:web:elsewhere.example" },
        });
        expect(screen.getByText("Not one of this community's trusted ballot boxes.")).toBeTruthy();
        fireEvent.click(screen.getByRole("button", { name: "Choose from the trusted ballot boxes" }));
        expect((screen.getByLabelText(/^Ballot box/) as HTMLSelectElement).tagName).toBe("SELECT");
      });

      it("says so when the community trusts none", async () => {
        mockFetch([...listing([]), ...routes()]);
        renderWithProviders(<Elections />, { route: "/elections/new", path: "/elections/*" });
        fireEvent.click(await screen.findByRole("button", { name: /Counting/ }));
        expect(await screen.findByText(/trusts no ballot box yet/)).toBeTruthy();
      });
    });

    it("keeps the draft in this tab across a reload", async () => {
      mockFetch(routes());
      const first = renderWithProviders(<Elections />, { route: "/elections/new", path: "/elections/*" });
      fireEvent.change(await screen.findByLabelText("Title"), { target: { value: "Kept" } });
      first.unmount();
      renderWithProviders(<Elections />, { route: "/elections/new", path: "/elections/*" });
      expect(((await screen.findByLabelText("Title")) as HTMLInputElement).value).toBe("Kept");
    });

    it("keeps a manifest the form cannot represent in the JSON view", async () => {
      mockFetch(routes());
      renderWithProviders(<Elections />, { route: "/elections/new", path: "/elections/*" });
      fireEvent.click(await screen.findByRole("tab", { name: "JSON" }));
      const text = screen.getByLabelText(/^Manifest/) as HTMLTextAreaElement;
      const m = JSON.parse(text.value) as Record<string, unknown>;
      fireEvent.change(text, { target: { value: JSON.stringify({ ...m, extra: true }) } });
      fireEvent.click(screen.getByRole("tab", { name: "Guided" }));
      expect(await screen.findByText(/The form does not edit "extra"/)).toBeTruthy();
      expect(screen.getByLabelText(/^Manifest/)).toBeTruthy();
      fireEvent.change(text, { target: { value: JSON.stringify({ ...m, title: "From JSON" }) } });
      fireEvent.click(screen.getByRole("tab", { name: "Guided" }));
      expect(((await screen.findByLabelText("Title")) as HTMLInputElement).value).toBe("From JSON");
    });
  });
});
