// Hidden vetting (PCS) on a criterion's card: shown only on a build that
// serves it, turned on and rolled with `vtc/vetting/hidden/publish/0.1`, and
// never re-published from the manifest when that would drop event approvals.

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  labelsBehind,
  periodOf,
  TASK_DISCOVERY,
  TASK_HIDDEN_PUBLISH,
  TASK_HIDDEN_SHOW,
  TASK_HIDDEN_WITHDRAW,
  type PublishedHiddenVetting,
} from "@/lib/hidden-vetting";
import { RequirementsPanel } from "@/plugins/vetting/RequirementsPanel";
import { type MockRoute, mockFetch, renderWithProviders, sentPayloads, taskRoute } from "@/test/render";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));

afterEach(() => vi.useRealTimers());

const MANIFEST_TASK = "https://trusttasks.org/spec/vtc/join-requests/manifest/0.3";
const ACCEPTS_LIST_TASK = "https://trusttasks.org/spec/vtc/schemas/accepts/list/0.2";
const STATEMENT_TYPE = "https://registry.trustoverip.org/dtg/vsc/vetted/1";

const VETTING = {
  version: "0.1",
  statementType: STATEMENT_TYPE,
  minStatements: 1,
  acceptedMethods: ["inPerson", "video"],
  eligibleVetters: { role: "vetter" },
};

const THIS_MONTH = periodOf();

function published(overrides: Partial<PublishedHiddenVetting> = {}): PublishedHiddenVetting {
  return {
    suite: "ps-ddh-bls12381",
    helperKey: "zHelper",
    tokenKey: "zToken",
    vetterLabels: [`vetter/${THIS_MONTH}`],
    tokenLabels: [`token/${THIS_MONTH}`],
    dripPerTick: 3,
    events: [],
    ...overrides,
  };
}

function routes({
  served,
  hidden,
  extra = [],
}: {
  served: string[];
  hidden: PublishedHiddenVetting | null;
  extra?: MockRoute[];
}): MockRoute[] {
  return [
    taskRoute(TASK_DISCOVERY, { supportedTypes: served }),
    taskRoute(ACCEPTS_LIST_TASK, {
      items: [
        {
          id: "vetted-member",
          admission: "automatic",
          vetting: VETTING,
          createdAt: "2026-01-01T00:00:00Z",
          createdByDid: "did:key:zAdmin",
        },
      ],
    }),
    taskRoute(MANIFEST_TASK, {
      communityDid: "did:web:vtc.example.org",
      criteria: [
        {
          id: "vetted-member",
          admission: "automatic",
          vetting: hidden
            ? { ...VETTING, ext: { "org.openvtc.hidden-vetting": hidden } }
            : VETTING,
          requirementsDigest: "zQmDigest",
        },
      ],
    }),
    taskRoute("https://trusttasks.org/spec/vtc/endorsement-types/list/0.1", { items: [] }),
    ...extra,
  ];
}

const publishAnswer = (payload: unknown) => ({
  criterionId: "vetted-member",
  stored: {},
  published: published({ dripPerTick: (payload as { dripPerTick?: number }).dripPerTick ?? 3 }),
  requirementsDigest: "zQmAfter",
});

async function card() {
  return (
    await screen.findByRole("heading", { name: "1. Criterion vetted-member" })
  ).closest("section")!;
}

describe("hidden vetting on a criterion", () => {
  it("is absent on a build that does not serve it", async () => {
    mockFetch(routes({ served: [], hidden: null }));
    renderWithProviders(<RequirementsPanel />);
    const c = await card();
    await waitFor(() => expect(within(c).queryByText("Hidden vetting (PCS)")).toBeNull());
  });

  it("turns on with a publish naming the criterion", async () => {
    const requests = mockFetch(
      routes({
        served: [TASK_HIDDEN_PUBLISH],
        hidden: null,
        extra: [taskRoute(TASK_HIDDEN_PUBLISH, publishAnswer)],
      }),
    );
    renderWithProviders(<RequirementsPanel />);
    const c = await card();
    fireEvent.click(await within(c).findByRole("button", { name: "Turn on hidden vetting" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Turn on hidden vetting" }));
    await waitFor(() =>
      expect(sentPayloads(requests, TASK_HIDDEN_PUBLISH)).toContainEqual({
        criterionId: "vetted-member",
        dripPerTick: 3,
      }),
    );
  });

  it("shows what is published and saves a new drip rate with the live labels kept", async () => {
    const requests = mockFetch(
      routes({
        served: [TASK_HIDDEN_PUBLISH],
        hidden: published(),
        extra: [taskRoute(TASK_HIDDEN_PUBLISH, publishAnswer)],
      }),
    );
    renderWithProviders(<RequirementsPanel />);
    const c = await card();
    expect(await within(c).findByText(`vetter/${THIS_MONTH}`)).toBeTruthy();
    const field = within(c).getByLabelText("Tokens a vetter may draw per tick") as HTMLInputElement;
    fireEvent.change(field, { target: { value: "5" } });
    fireEvent.click(within(c).getByRole("button", { name: "Save drip rate" }));
    await waitFor(() =>
      expect(sentPayloads(requests, TASK_HIDDEN_PUBLISH)).toContainEqual({
        criterionId: "vetted-member",
        livePeriods: [THIS_MONTH],
        liveTokenLabels: [`token/${THIS_MONTH}`],
        dripPerTick: 5,
      }),
    );
  });

  it("offers to roll labels that are behind this month", async () => {
    const requests = mockFetch(
      routes({
        served: [TASK_HIDDEN_PUBLISH],
        hidden: published({ vetterLabels: ["vetter/2020-01"], tokenLabels: ["token/2020-01"] }),
        extra: [taskRoute(TASK_HIDDEN_PUBLISH, publishAnswer)],
      }),
    );
    renderWithProviders(<RequirementsPanel />);
    const c = await card();
    expect(await within(c).findByText("The live labels are behind this month.")).toBeTruthy();
    fireEvent.click(within(c).getByRole("button", { name: `Roll labels to ${THIS_MONTH}` }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: `Roll to ${THIS_MONTH}` }));
    await waitFor(() =>
      expect(sentPayloads(requests, TASK_HIDDEN_PUBLISH)).toContainEqual({
        criterionId: "vetted-member",
        livePeriods: [THIS_MONTH],
        liveTokenLabels: [`token/${THIS_MONTH}`],
        dripPerTick: 3,
      }),
    );
  });

  it("does not re-publish a criterion with events on a build that cannot read them back", async () => {
    mockFetch(
      routes({
        served: [TASK_HIDDEN_PUBLISH],
        hidden: published({
          events: [{ eventId: "summit", startDate: "2026-10-01", endDate: "2026-10-03", tiers: [] }],
        }),
      }),
    );
    renderWithProviders(<RequirementsPanel />);
    const c = await card();
    expect(
      await within(c).findByText("This criterion runs events, so it is not edited here."),
    ).toBeTruthy();
    expect(within(c).queryByRole("button", { name: "Save drip rate" })).toBeNull();
  });
});

// ── With `show` and `withdraw` served ───────────────────────────────────

const ADMIN = "did:key:z6MkAdmin";

const SUMMIT = {
  eventId: "summit-2026",
  startDate: "2026-10-01",
  endDate: "2026-10-03",
  graceDays: 14,
  groupFloor: 3,
  tiers: [{ name: "desk", dripPerTick: 10 }],
};

function stored(events: Record<string, unknown>[] = []) {
  return {
    suite: "ps-ddh-bls12381",
    hvk: "zHelper",
    tvk: "zToken",
    livePeriods: [THIS_MONTH],
    liveTokenLabels: [`token/${THIS_MONTH}`, ...events.map((e) => `token/event/${String(e.eventId)}`)],
    dripPerTick: 3,
    events,
  };
}

function showAnswer(events: Record<string, unknown>[], groupSize = 1) {
  return {
    criterionId: "vetted-member",
    enabled: true,
    requirementsDigest: "zQmDigest",
    stored: stored(events),
    published: published(),
    enrolledVetters: { [`vetter/${THIS_MONTH}`]: 4 },
    eventStatus: events.map((e) => ({
      eventId: e.eventId,
      groupFloor: 3,
      groupSize,
      approved: Boolean(e.approvedBy),
      live: false,
    })),
  };
}

const whoami = {
  session: { id: "s", subject: ADMIN, issuedAt: "2026-10-05T10:00:00Z", expiresAt: "2099-01-01T00:00:00Z" },
  roles: ["admin"],
  scopes: [],
  capabilities: [],
} as unknown as import("@/lib/api").WhoamiResponse;

function fullRoutes(events: Record<string, unknown>[], extra: MockRoute[] = []) {
  return routes({
    served: [TASK_HIDDEN_PUBLISH, TASK_HIDDEN_WITHDRAW, TASK_HIDDEN_SHOW],
    hidden: published({ events: events.map((e) => ({ ...e, approvedBy: undefined }) as never) }),
    extra: [
      taskRoute(TASK_HIDDEN_SHOW, showAnswer(events)),
      taskRoute(TASK_HIDDEN_PUBLISH, publishAnswer),
      ...extra,
    ],
  });
}

describe("hidden vetting with its stored configuration", () => {
  it("shows enrolment and event demand as counts", async () => {
    mockFetch(fullRoutes([SUMMIT]));
    renderWithProviders(<RequirementsPanel />, { whoami });
    const c = await card();
    expect(await within(c).findByText("(4 enrolled)")).toBeTruthy();
    expect(within(c).getByText("1 of 3 needed")).toBeTruthy();
    expect(within(c).getByText("Needs approval")).toBeTruthy();
  });

  it("approves an event in the viewer's own name, keeping everything else as stored", async () => {
    const requests = mockFetch(fullRoutes([SUMMIT]));
    renderWithProviders(<RequirementsPanel />, { whoami });
    const c = await card();
    fireEvent.click(await within(c).findByRole("button", { name: "Approve" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Approve event" }));
    await waitFor(() =>
      expect(sentPayloads(requests, TASK_HIDDEN_PUBLISH)).toContainEqual({
        criterionId: "vetted-member",
        livePeriods: [THIS_MONTH],
        liveTokenLabels: [`token/${THIS_MONTH}`, "token/event/summit-2026"],
        dripPerTick: 3,
        events: [{ ...SUMMIT, approvedBy: ADMIN }],
      }),
    );
  });

  it("keeps an approval when the drip rate changes", async () => {
    const approved = { ...SUMMIT, approvedBy: "did:key:zOtherAdmin" };
    const requests = mockFetch(fullRoutes([approved]));
    renderWithProviders(<RequirementsPanel />, { whoami });
    const c = await card();
    await within(c).findByText("1 of 3 needed");
    fireEvent.change(within(c).getByLabelText("Tokens a vetter may draw per tick"), {
      target: { value: "4" },
    });
    fireEvent.click(within(c).getByRole("button", { name: "Save drip rate" }));
    await waitFor(() =>
      expect(sentPayloads(requests, TASK_HIDDEN_PUBLISH)).toContainEqual(
        expect.objectContaining({ dripPerTick: 4, events: [approved] }),
      ),
    );
  });

  it("adds an event with its label live", async () => {
    const requests = mockFetch(fullRoutes([]));
    renderWithProviders(<RequirementsPanel />, { whoami });
    const c = await card();
    fireEvent.click(await within(c).findByRole("button", { name: "Add an event" }));
    fireEvent.change(within(c).getByLabelText("Event name"), { target: { value: "summit-2026" } });
    fireEvent.change(within(c).getByLabelText("First day"), { target: { value: "2026-10-01" } });
    fireEvent.change(within(c).getByLabelText("Last day"), { target: { value: "2026-10-03" } });
    fireEvent.click(within(c).getByRole("button", { name: "Add event" }));
    await waitFor(() =>
      expect(sentPayloads(requests, TASK_HIDDEN_PUBLISH)).toContainEqual(
        expect.objectContaining({
          liveTokenLabels: [`token/${THIS_MONTH}`, "token/event/summit-2026"],
          events: [SUMMIT],
        }),
      ),
    );
  });

  it("removes an event and its label", async () => {
    const requests = mockFetch(fullRoutes([SUMMIT]));
    renderWithProviders(<RequirementsPanel />, { whoami });
    const c = await card();
    await within(c).findByText("1 of 3 needed");
    const row = within(c).getByText("summit-2026").closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Remove" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove event" }));
    await waitFor(() =>
      expect(sentPayloads(requests, TASK_HIDDEN_PUBLISH)).toContainEqual(
        expect.objectContaining({ liveTokenLabels: [`token/${THIS_MONTH}`], events: [] }),
      ),
    );
  });

  it("turns hidden vetting off", async () => {
    const requests = mockFetch(
      fullRoutes(
        [],
        [
          taskRoute(TASK_HIDDEN_WITHDRAW, {
            criterionId: "vetted-member",
            withdrawn: true,
            requirementsDigest: "zQmOff",
          }),
        ],
      ),
    );
    renderWithProviders(<RequirementsPanel />, { whoami });
    const c = await card();
    fireEvent.click(await within(c).findByRole("button", { name: "Turn off hidden vetting" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Turn off hidden vetting" }));
    await waitFor(() =>
      expect(sentPayloads(requests, TASK_HIDDEN_WITHDRAW)).toContainEqual({
        criterionId: "vetted-member",
      }),
    );
  });
});

describe("labelsBehind", () => {
  it("compares the published vetter labels with the month given", () => {
    const p = published({ vetterLabels: ["vetter/2026-09"] });
    expect(labelsBehind(p, new Date(Date.UTC(2026, 8, 30)))).toBe(false);
    expect(labelsBehind(p, new Date(Date.UTC(2026, 9, 1)))).toBe(true);
  });
});
