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

  describe("grouped by the board they came from", () => {
    const BOARD = "brd_ff-8cTg0yX5EWSyHPcluzA";
    const GONE = "brd_Uc7N2qLm4Rt8Vx1ZAAAAAA";
    const row = (electionId: string, title: string, state: string) => ({
      electionId,
      title,
      state,
      votingOpensAt: manifest.votingOpensAt,
      votingClosesAt: manifest.votingClosesAt,
      binding: false,
      ticketHeld: false,
    });
    const listed = [
      row(`board.${BOARD}.ida_zgA8cE7kD8Ty8Zt_Qk1-VQ`, "Hart should buy me lunch", "registration"),
      row("agm-2027", "Annual meeting", "voting"),
      row(`board.${BOARD}.ida_Pk3Wq9Ls2Dn6Hy4BAAAAAA`, "Accessible sign-in", "voting"),
      row(`board.${GONE}.ida_Zt5Mv8Qr1Kc7Jw3EAAAAAA`, "An old idea", "tallied"),
    ];
    const grouped = (boards: MockRoute) => [
      taskRoute("https://trusttasks.org/spec/trust-task-discovery/0.3", { supportedTypes: [ELECTIONS_LIST_TASK] }),
      taskRoute(ELECTIONS_LIST_TASK, { elections: listed }),
      boards,
    ];
    const boardsList = taskRoute("https://trusttasks.org/spec/vtc/boards/list/0.1", {
      boards: [{ boardId: BOARD, title: "IIW Sessions" }],
    });

    it("puts stand-alone elections first, then each board's, without the generated identifier", async () => {
      mockFetch(grouped(boardsList));
      renderWithProviders(<Elections />, { route: "/elections", path: "/elections/*" });
      const standalone = await screen.findByRole("region", { name: "Stand-alone elections" });
      expect(standalone.textContent).toContain("Annual meeting");
      expect(standalone.textContent).not.toContain("Hart should buy me lunch");
      const iiw = (await screen.findByText("IIW Sessions", { selector: "summary strong" })).closest("details")!;
      expect(iiw.textContent).toContain("2 elections");
      expect(iiw.textContent).toContain("1 taking tickets · 1 voting");
      expect(iiw.textContent).toContain("Accessible sign-in");
      expect(iiw.textContent).not.toContain("board.brd_");
      const gone = screen.getByText("Deleted board", { selector: "summary strong" }).closest("details")!;
      expect(gone.textContent).toContain("An old idea");
      expect(gone.querySelector('a[href*="/boards/"]')).toBeNull();
    });

    it("filters to stand-alone elections or one board", async () => {
      mockFetch(grouped(boardsList));
      renderWithProviders(<Elections />, { route: "/elections", path: "/elections/*" });
      const show = await screen.findByLabelText("Show");
      await screen.findByRole("option", { name: "IIW Sessions (2)" });
      fireEvent.change(show, { target: { value: "standalone" } });
      expect(screen.queryByText("Hart should buy me lunch")).toBeNull();
      expect(screen.getByRole("link", { name: "Annual meeting" })).toBeTruthy();
      fireEvent.change(show, { target: { value: BOARD } });
      expect(screen.queryByRole("link", { name: "Annual meeting" })).toBeNull();
      expect(screen.queryByText("An old idea")).toBeNull();
      expect(screen.getByRole("link", { name: "Hart should buy me lunch" })).toBeTruthy();
    });

    it("still groups by board when the boards cannot be read", async () => {
      mockFetch(grouped(taskRoute("https://trusttasks.org/spec/vtc/boards/list/0.1", {}, 403)));
      renderWithProviders(<Elections />, { route: "/elections", path: "/elections/*" });
      expect(await screen.findByText("Board ff-8cTg0…", { selector: "summary strong" })).toBeTruthy();
      expect(screen.getByRole("link", { name: "Annual meeting" })).toBeTruthy();
    });
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

  it("tells administrators whose credential counts, and counts turnout against tickets (VTI-VOT-090, VTI-VOT-028)", async () => {
    mockFetch(
      routes([
        taskRoute(
          ELECTIONS_SHOW_TASK,
          shown("voting", {
            disclosure: {
              ...shown("voting").disclosure,
              rollCredential: {
                memberOf: "did:webvh:QmPartner:partner.example",
                memberOfKind: "memberParty",
                memberOfName: "Partner community",
                presenterDisclosed: true,
              },
            },
          }),
        ),
      ]),
    );
    renderWithProviders(<Elections />, { route: "/elections/agm-2027", path: "/elections/*" });
    expect(await screen.findByText("Whose credential counts")).toBeTruthy();
    expect(screen.getByText("Partner community")).toBeTruthy();
    expect(screen.getByText(/Claiming a ticket shows this community/)).toBeTruthy();
    expect(screen.getByText(/never appears in members/)).toBeTruthy();
    expect(screen.getByText(/there is no roll size/)).toBeTruthy();
  });

  it("shows no credential row under any other roll", async () => {
    mockFetch(routes([taskRoute(ELECTIONS_SHOW_TASK, shown("voting"))]));
    renderWithProviders(<Elections />, { route: "/elections/agm-2027", path: "/elections/*" });
    await screen.findByText("What members are told");
    expect(screen.queryByText("Whose credential counts")).toBeNull();
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

    it("builds a credential roll naming a group, from this community's parties (VTI-VOT-026)", async () => {
      const GROUP_DID = "did:webvh:QmGroup:community.example:groups:g7";
      const requests = mockFetch(
        routes([
          taskRoute("https://trusttasks.org/spec/vtc/groups/list/0.2", {
            items: [{ group: { groupId: "grp_eng", groupDid: GROUP_DID, name: "Engineering" }, myMembership: "none" }],
          }),
          taskRoute("https://trusttasks.org/spec/vtc/members/list/0.2", {
            items: [
              { did: "did:webvh:QmPartner:partner.example", label: "Partner community", currentVmcId: "urn:uuid:vmc-1" },
              { did: "did:key:z6MkNoCredential", label: "Without a credential" },
            ],
          }),
          taskRoute(ELECTIONS_CREATE_TASK, { electionId: "eng-poll", manifestDigest: "zQmDigest", state: "registered" }),
          taskRoute(ELECTIONS_SHOW_TASK, shown("registered")),
        ]),
      );
      renderWithProviders(<Elections />, { route: "/elections/new", path: "/elections/*" });
      fireEvent.change(await screen.findByLabelText("Title"), { target: { value: "Eng poll" } });
      next();
      fireEvent.change(screen.getByLabelText("What is asked"), { target: { value: "Offsite?" } });
      fireEvent.click(screen.getByRole("button", { name: "Use Yes / No / Abstain" }));
      next();
      fireEvent.click(screen.getByLabelText(/Holders of a membership credential for one DID/));
      const pick = (await screen.findByLabelText(/^Whose membership credential counts/)) as HTMLSelectElement;
      await screen.findByRole("option", { name: "Group: Engineering" });
      expect(screen.getByRole("option", { name: "This community" })).toBeTruthy();
      expect(screen.getByRole("option", { name: "Member: Partner community" })).toBeTruthy();
      // A member holding no membership credential of this community's is not offered.
      expect(screen.queryByRole("option", { name: "Member: Without a credential" })).toBeNull();
      expect(screen.getByText(/refused when the election is created/)).toBeTruthy();
      expect(screen.getByText(/someone who joins later can vote/)).toBeTruthy();
      expect(screen.getByText(/states no roll size/)).toBeTruthy();
      fireEvent.change(pick, { target: { value: GROUP_DID } });
      expect(screen.getByText(/is one of this community's groups/)).toBeTruthy();
      // A group is not a member party: the member-party visibility note is not shown.
      expect(screen.queryByText(/never appears in members' election lists/)).toBeNull();
      next();
      next();
      fireEvent.change(screen.getByLabelText(/^Ballot box DID/), { target: { value: BOX } });
      next();
      expect(screen.getByText(/turnout is counted against/)).toBeTruthy();
      const create = screen.getByRole("button", { name: "Create" });
      await waitFor(() => expect((create as HTMLButtonElement).disabled).toBe(false));
      fireEvent.click(create);
      await waitFor(() => expect(sentPayloads(requests, ELECTIONS_CREATE_TASK)).toHaveLength(1));
      const sent = (sentPayloads(requests, ELECTIONS_CREATE_TASK)[0] as { manifest: Record<string, unknown> }).manifest;
      expect(sent.roll).toEqual({ rule: "credential", memberOf: GROUP_DID });
    });

    it("explains a member party's visibility, and takes a typed DID (VTI-VOT-015)", async () => {
      mockFetch(
        routes([
          taskRoute("https://trusttasks.org/spec/vtc/groups/list/0.2", { items: [] }),
          taskRoute("https://trusttasks.org/spec/vtc/members/list/0.2", {
            items: [
              { did: "did:webvh:QmPartner:partner.example", label: "Partner community", currentVmcId: "urn:uuid:vmc-1" },
              { did: "did:key:z6MkNoCredential", label: "Without a credential" },
            ],
          }),
        ]),
      );
      renderWithProviders(<Elections />, { route: "/elections/new", path: "/elections/*" });
      fireEvent.change(await screen.findByLabelText("Title"), { target: { value: "Partner poll" } });
      next();
      next();
      fireEvent.click(screen.getByLabelText(/Holders of a membership credential for one DID/));
      await screen.findByRole("option", { name: "Member: Partner community" });
      fireEvent.change(screen.getByLabelText(/^Whose membership credential counts/), {
        target: { value: "did:webvh:QmPartner:partner.example" },
      });
      expect(screen.getByText(/never appears in members' election lists/)).toBeTruthy();
      fireEvent.click(screen.getByRole("button", { name: "Type a DID instead" }));
      fireEvent.change(screen.getByLabelText(/^Membership credential issuer DID/), { target: { value: "not-a-did" } });
      expect(screen.getByText(/A DID \(did:method:…\)/)).toBeTruthy();
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
