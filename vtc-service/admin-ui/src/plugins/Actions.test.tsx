// The Actions page: cards render from the list, a summary that does not match
// its payload is refused, an approval is signed by the approver's own DID
// through the wallet (never the console key), a browser with no wallet is
// shown the `cnm` command, and a requester can cancel.

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";

import { postSignedTrustTask, type WhoamiResponse } from "@/lib/api";
import { matchCode, payloadDigestOf, wireDigest } from "@/lib/action-summary";
import {
  ACTIONS_ACKNOWLEDGE_TASK,
  ACTIONS_CANCEL_TASK,
  ACTIONS_LIST_TASK,
  ACTIONS_SHOW_TASK,
  DECISION_TASK,
  coolingOffOf,
  type Action,
} from "@/lib/actions-api";
import { APPROVER_LIST_TASK } from "@/lib/step-up-approvers";
import vectors from "@/lib/action-summary.vectors.json";
import { Actions, landsIn, timeLeft } from "@/plugins/actions";
import {
  NAME_BOOK_ROUTES,
  mockFetch,
  renderWithProviders,
  sentPayloads,
  taskRoute,
  type RecordedRequest,
} from "@/test/render";

// Reads and cancel are console-key documents; the stand-in sends them
// unsigned. `postSignedDocument` (what a wallet-signed decision goes through)
// is left real, so the decision is seen on the wire exactly as sent.
vi.mock("@/lib/api", async (original) => {
  const signed = await import("@/test/signed-read");
  return {
    ...(await original<typeof import("@/lib/api")>()),
    postSignedRead: signed.unsignedRead,
    postSignedTrustTask: vi.fn(signed.unsignedTask),
  };
});

const ME = "did:key:z6MkApproverAliceXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const REQUESTER = "did:key:z6MkRequesterBobYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY";
const VTC = "did:webvh:QmScid:community.example:vtc";
const CHALLENGE = "Y2hhbGxlbmdlLWZvci1hY3QtMQ";

const whoami = (amr?: string[]): WhoamiResponse => ({
  session: {
    id: "s1",
    subject: ME,
    issuedAt: "2026-10-02T10:00:00Z",
    expiresAt: "2099-10-02T10:15:00Z",
    ...(amr ? { amr } : {}),
  },
  roles: ["admin"],
  scopes: [],
});

interface Vector {
  name: string;
  kind: string;
  typeUri: string;
  payload: Record<string, unknown>;
  summary: Action["summary"];
}
const GRANT = (vectors as unknown as Vector[])[0]!;

let waiting: Action;
let mine: Action;

beforeAll(async () => {
  const digest = await payloadDigestOf(GRANT.payload);
  const base = {
    category: "approval" as const,
    kind: GRANT.kind,
    typeUri: GRANT.typeUri,
    payload: GRANT.payload,
    payloadDigest: digest,
    summary: GRANT.summary,
    createdAt: "2026-10-02T09:00:00Z",
    expiresAt: new Date(Date.now() + (2 * 24 + 4) * 3600_000 + 60_000).toISOString(),
    approvals: [],
    threshold: 2,
    requesterOpenActions: 3,
    status: "open" as const,
  };
  waiting = {
    ...base,
    actionId: "act-1",
    requester: REQUESTER,
    callerRole: "approver",
    challenge: CHALLENGE,
    ext: { "org.openvtc": { approverCount: 3, requesterRecentActions: 4, burst: true } },
  };
  mine = {
    ...base,
    actionId: "act-2",
    requester: ME,
    callerRole: "requester",
  };
});

afterEach(() => {
  delete window.vtaWallet;
  vi.mocked(postSignedTrustTask).mockClear();
});

function routes(actions: Action[], extra: ReturnType<typeof taskRoute>[] = []) {
  return mockFetch([
    ...NAME_BOOK_ROUTES,
    { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC } },
    taskRoute(ACTIONS_LIST_TASK, (p) => {
      const view = (p as { view: string }).view;
      return {
        actions: actions.filter((a) =>
          view === "waitingForMe" ? a.callerRole === "approver" : a.callerRole === "requester",
        ),
        counts: { waitingForMe: 1, requestedByMe: 1 },
      };
    }),
    ...extra,
  ]);
}

/** A wallet that signs as `asDid` and records what it was asked to sign. */
function installWallet() {
  const signTrustTask = vi.fn(
    async ({ envelope, asDid }: { envelope: Record<string, unknown>; asDid?: string }) => ({
      signedEnvelope: {
        ...envelope,
        proof: {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: `${asDid}#key-1`,
          proofPurpose: "assertionMethod",
          proofValue: "zWalletSig",
        },
      },
      holderDid: asDid!,
    }),
  );
  window.vtaWallet = { login: vi.fn(), signTrustTask } as unknown as typeof window.vtaWallet;
  return signTrustTask;
}

const render = (amr?: string[], route = "/actions") =>
  renderWithProviders(<Actions />, { route, path: "/actions", whoami: whoami(amr) });

const decisions = (requests: RecordedRequest[]) =>
  requests.filter(
    (r) => r.url === "/v1/trust-tasks" && (r.body as { type?: string })?.type === DECISION_TASK,
  );

describe("the Actions page", () => {
  it("renders a verified card: summary, code, approvals, time left, burst", async () => {
    routes([waiting]);
    render();
    const card = await screen.findByRole("article", { name: "Action act-1" });
    expect(
      await within(card).findByText(/^Make did:webvh:QmScid…xample:carol an unrestricted administrator$/),
    ).toBeTruthy();
    expect(within(card).getByText(`Code: ${matchCode(waiting.payloadDigest)}`)).toBeTruthy();
    expect(within(card).getByText(/0 of 2/)).toBeTruthy();
    expect(within(card).getByText(/expires in 2 d 4 h/)).toBeTruthy();
    expect(within(card).getByText(/raised 4 actions in the last 10/)).toBeTruthy();
    expect(within(card).getByText("3")).toBeTruthy();
  });

  it("refuses a card whose summary does not match its payload, and offers no Approve", async () => {
    const tampered: Action = {
      ...waiting,
      summary: {
        ...waiting.summary,
        fields: {
          ...waiting.summary.fields,
          subject: { ...waiting.summary.fields.subject!, value: "did:key:z6MkSomeoneElse" },
        },
      },
    };
    installWallet();
    routes([tampered]);
    render();
    const card = await screen.findByRole("article", { name: "Action act-1" });
    expect(
      await within(card).findByText(
        "This action's summary does not match its payload — do not approve it.",
      ),
    ).toBeTruthy();
    expect(within(card).queryByRole("button", { name: "Approve" })).toBeNull();
    expect(within(card).queryByText(/Make .* an unrestricted administrator/)).toBeNull();
  });

  it("approves with the wallet as the admin's own DID, never the console key", async () => {
    const sign = installWallet();
    const requests = routes(
      [waiting],
      [
        taskRoute(DECISION_TASK, {
          status: "pending",
          payloadDigest: "z",
          approvals: 1,
          needed: 2,
          actionId: "act-1",
        }),
      ],
    );
    render();
    const card = await screen.findByRole("article", { name: "Action act-1" });
    fireEvent.click(await within(card).findByRole("button", { name: "Approve" }));

    await waitFor(() => expect(decisions(requests)).toHaveLength(1));
    const doc = decisions(requests)[0]!.body as {
      issuer: string;
      recipient: string;
      payload: Record<string, unknown>;
      proof: { verificationMethod: string };
    };
    expect(sign).toHaveBeenCalledTimes(1);
    expect(sign.mock.calls[0]![0].asDid).toBe(ME);
    expect(doc.issuer).toBe(ME);
    expect(doc.recipient).toBe(VTC);
    expect(doc.proof.verificationMethod.split("#")[0]).toBe(ME);
    expect(doc.payload).toEqual({
      challenge: CHALLENGE,
      payloadDigest: await wireDigest(waiting.typeUri, waiting.payload, CHALLENGE),
      decision: "approve",
      actionId: "act-1",
    });
    // The console key signed nothing for the decision.
    expect(
      vi.mocked(postSignedTrustTask).mock.calls.filter(([t]) => t === DECISION_TASK),
    ).toHaveLength(0);
    expect(await screen.findByText(/1 of 2 approvals so far/)).toBeTruthy();
  });

  it("attaches passkey evidence over the challenge when the session has a passkey", async () => {
    installWallet();
    const bytes = (s: string) => new TextEncoder().encode(s).buffer;
    const get = vi.fn(async () => ({
      id: "cred",
      rawId: bytes("cred"),
      type: "public-key",
      response: {
        authenticatorData: bytes("ad"),
        clientDataJSON: bytes("cd"),
        signature: bytes("sig"),
        userHandle: null,
      },
    }));
    Object.defineProperty(navigator, "credentials", { value: { get }, configurable: true });
    const requests = routes(
      [waiting],
      [taskRoute(DECISION_TASK, { status: "granted", payloadDigest: "z", actionId: "act-1" })],
    );
    render(["passkey"]);
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(decisions(requests)).toHaveLength(1));

    const opts = (get.mock.calls[0] as unknown as [{ publicKey: PublicKeyCredentialRequestOptions }])[0]
      .publicKey;
    expect(new TextDecoder().decode(opts.challenge as ArrayBuffer)).toBe(CHALLENGE);
    expect(opts.userVerification).toBe("required");
    const payload = (decisions(requests)[0]!.body as { payload: { evidence?: { kind: string } } })
      .payload;
    expect(payload.evidence?.kind).toBe("webauthn");
  });

  it("declines with a reason", async () => {
    installWallet();
    const requests = routes(
      [waiting],
      [taskRoute(DECISION_TASK, { status: "denied", payloadDigest: "z", actionId: "act-1" })],
    );
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Decline" }));
    const send = screen.getByRole("button", { name: "Send decline" }) as HTMLButtonElement;
    expect(send.disabled).toBe(true);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "not agreed" } });
    fireEvent.click(send);
    await waitFor(() => expect(decisions(requests)).toHaveLength(1));
    const payload = (decisions(requests)[0]!.body as { payload: Record<string, unknown> }).payload;
    expect(payload.decision).toBe("deny");
    expect(payload.reason).toBe("not agreed");
  });

  it("shows the cnm commands, and no buttons, when there is no wallet", async () => {
    routes([waiting]);
    render();
    const card = await screen.findByRole("article", { name: "Action act-1" });
    expect(await within(card).findByText(/Approving needs your own DID's signature/)).toBeTruthy();
    expect(within(card).getByText("cnm consent approve --action act-1")).toBeTruthy();
    expect(within(card).getByText(/cnm consent deny --action act-1 --reason/)).toBeTruthy();
    expect(within(card).queryByRole("button", { name: "Approve" })).toBeNull();
    expect(within(card).queryByRole("button", { name: "Decline" })).toBeNull();
  });

  it("explains a decision the VTC refused", async () => {
    installWallet();
    routes(
      [waiting],
      [
        taskRoute(
          DECISION_TASK,
          { code: "task-consent/decision:requesterExcluded", message: "excluded" },
          403,
        ),
      ],
    );
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    expect(await screen.findByText(/You raised this action, so you cannot approve it/)).toBeTruthy();
  });

  it("lets a requester cancel their own open action", async () => {
    const requests = routes(
      [mine],
      [taskRoute(ACTIONS_CANCEL_TASK, { action: { ...mine, status: "cancelled" } })],
    );
    render(undefined, "/actions?tab=requestedByMe");
    const card = await screen.findByRole("article", { name: "Action act-2" });
    fireEvent.click(within(card).getByRole("button", { name: "Cancel request" }));
    fireEvent.change(within(card).getByRole("textbox"), { target: { value: "typo" } });
    fireEvent.click(within(card).getByRole("button", { name: "Cancel this action" }));
    await waitFor(() =>
      expect(sentPayloads(requests, ACTIONS_CANCEL_TASK)).toEqual([
        { actionId: "act-2", reason: "typo" },
      ]),
    );
    // Signed with the console key (the stand-in), as cancel may be.
    expect(vi.mocked(postSignedTrustTask)).toHaveBeenCalledWith(ACTIONS_CANCEL_TASK, {
      actionId: "act-2",
      reason: "typo",
    });
  });

  it("deep-links one action, and shows a completed invite's result to its requester", async () => {
    const done: Action = {
      ...mine,
      status: "completed",
      closedReason: "thresholdMet",
      closedAt: "2026-10-02T11:00:00Z",
      ext: {
        "org.openvtc": {
          closedMessage: "Approved by 2 administrators.",
          result: { installUrl: "https://vtc.example/install#t", claimCode: "ABCD-1234" },
        },
      },
    };
    routes([], [taskRoute(ACTIONS_SHOW_TASK, { action: done })]);
    render(undefined, "/actions?action=act-2");
    const card = await screen.findByRole("article", { name: "Action act-2" });
    expect(within(card).getByText("completed")).toBeTruthy();
    expect(within(card).getByText("Enough administrators approved")).toBeTruthy();
    expect(within(card).getByText("Approved by 2 administrators.")).toBeTruthy();
    expect(within(card).getByText("https://vtc.example/install#t")).toBeTruthy();
    expect(within(card).getByText("ABCD-1234")).toBeTruthy();
  });
});

// ── Operator offline writes (VTI-VTC-023) ───────────────────────────

const OP_GRANT = (vectors as unknown as Vector[]).find(
  (v) =>
    v.kind === "operator.offlineWrite" &&
    v.typeUri === "https://trusttasks.org/spec/vtc/operator/offline-write/0.1" &&
    (v.payload as { command?: string }).command === "aclAdd",
)!;

async function operatorWrite(overrides: Partial<Action> = {}): Promise<Action> {
  return {
    actionId: "ack-1",
    category: "acknowledge",
    kind: OP_GRANT.kind,
    typeUri: OP_GRANT.typeUri,
    requester: VTC,
    status: "open",
    createdAt: "2026-10-02T08:31:00Z",
    approvals: [{ subject: REQUESTER, at: "2026-10-02T09:00:00Z" }],
    approversRemaining: 2,
    callerRole: "acknowledger",
    payload: OP_GRANT.payload,
    payloadDigest: await payloadDigestOf(OP_GRANT.payload),
    summary: OP_GRANT.summary,
    ext: { "org.openvtc": { severity: "critical", acknowledgedByMe: false } },
    ...overrides,
  };
}

/** Every view answers with `actions`. */
function anyView(actions: Action[], extra: ReturnType<typeof taskRoute>[] = []) {
  return mockFetch([
    ...NAME_BOOK_ROUTES,
    { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC } },
    taskRoute(ACTIONS_LIST_TASK, { actions, counts: { waitingForMe: actions.length, requestedByMe: 0 } }),
    ...extra,
  ]);
}

describe("an operator's offline write", () => {
  it("renders as a Critical card with who, when, the host and who has acknowledged", async () => {
    anyView([await operatorWrite()]);
    render();
    const card = await screen.findByRole("article", { name: "Action ack-1" });
    expect(within(card).getByText("Critical")).toBeTruthy();
    expect(card.className).toContain("action-critical");
    expect(
      await within(card).findByText(
        "The operator ran aclAdd on vtc-host-1, changing access for did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      ),
    ).toBeTruthy();
    expect(within(card).getByText(/^Written at .*while the service was stopped/)).toBeTruthy();
    // The command, in words an administrator recognises.
    expect(within(card).getByText("vtc acl add")).toBeTruthy();
    expect(within(card).getByText(/The operator, acting as the community/)).toBeTruthy();
    expect(within(card).getByText("2 administrators")).toBeTruthy();
    // No approval vocabulary: no threshold, no expiry, no Approve.
    expect(within(card).queryByText(/expires in/)).toBeNull();
    expect(within(card).queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("acknowledges with a console-key-signed acknowledge task", async () => {
    const before = await operatorWrite();
    const requests = anyView(
      [before],
      [
        taskRoute(ACTIONS_ACKNOWLEDGE_TASK, {
          action: { ...before, ext: { "org.openvtc": { severity: "critical", acknowledgedByMe: true } } },
        }),
      ],
    );
    render();
    const card = await screen.findByRole("article", { name: "Action ack-1" });
    fireEvent.click(await within(card).findByRole("button", { name: "Acknowledge" }));
    await waitFor(() =>
      expect(sentPayloads(requests, ACTIONS_ACKNOWLEDGE_TASK)).toEqual([{ actionId: "ack-1" }]),
    );
    expect(vi.mocked(postSignedTrustTask)).toHaveBeenCalledWith(ACTIONS_ACKNOWLEDGE_TASK, {
      actionId: "ack-1",
    });
    expect(await screen.findByText(/your acknowledgement is recorded/)).toBeTruthy();
  });

  it("treats alreadyAcknowledged as no failure", async () => {
    anyView(
      [await operatorWrite()],
      [
        taskRoute(
          ACTIONS_ACKNOWLEDGE_TASK,
          { code: "vtc/admin/actions/acknowledge:alreadyAcknowledged", message: "already" },
          409,
        ),
      ],
    );
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Acknowledge" }));
    expect(
      await screen.findByText(/already acknowledged this; your earlier acknowledgement stands/),
    ).toBeTruthy();
  });

  it("offers no button once you have acknowledged, or to an observer", async () => {
    anyView([
      await operatorWrite({
        ext: { "org.openvtc": { severity: "critical", acknowledgedByMe: true } },
      }),
      await operatorWrite({ actionId: "ack-2", callerRole: "observer" }),
    ]);
    render();
    const mineDone = await screen.findByRole("article", { name: "Action ack-1" });
    expect(await within(mineDone).findByText("You have acknowledged this.")).toBeTruthy();
    const observed = screen.getByRole("article", { name: "Action ack-2" });
    await within(observed).findByText(/The operator ran aclAdd/);
    expect(within(observed).queryByRole("button", { name: "Acknowledge" })).toBeNull();
    expect(within(mineDone).queryByRole("button", { name: "Acknowledge" })).toBeNull();
  });

  it("shows a closed acknowledgement's outcome", async () => {
    anyView([
      await operatorWrite({
        status: "completed",
        closedReason: "acknowledged",
        closedAt: "2026-10-02T12:00:00Z",
        approversRemaining: undefined,
      }),
    ]);
    render();
    const card = await screen.findByRole("article", { name: "Action ack-1" });
    expect(await within(card).findByText("Every administrator acknowledged it")).toBeTruthy();
  });
});

// ── Cooling-offs (VTI-APV-019) ──────────────────────────────────────

const REDUCE = {
  kind: "acl.reduce.authority",
  typeUri: "https://trusttasks.org/spec/acl/revoke/0.1",
};

/** A 0.2 `coolingOff` action: `landsAt` and `cancellableBy` on the action
 *  itself; no threshold, no expiry, no approvals still needed. */
async function coolingOff(overrides: Partial<Action> = {}) {
  const v = (vectors as unknown as Vector[]).find(
    (x) => x.kind === REDUCE.kind && x.typeUri === REDUCE.typeUri,
  )!;
  const action: Action = {
    actionId: "cool-1",
    category: "coolingOff",
    kind: v.kind,
    typeUri: v.typeUri,
    requester: REQUESTER,
    status: "open",
    createdAt: "2026-10-02T09:00:00Z",
    landsAt: LANDS_AT,
    cancellableBy: "requester",
    approvals: [],
    callerRole: "requester",
    payload: v.payload,
    payloadDigest: await payloadDigestOf(v.payload),
    summary: v.summary,
    requesterOpenActions: 1,
    ...overrides,
  };
  return action;
}

/** Two days, four hours and a minute from now. */
const LANDS_AT = new Date(Date.now() + (2 * 24 + 4) * 3600_000 + 60_000).toISOString();

describe("a cooling-off", () => {
  it("shows its requester when it lands, counts down to it, and offers Cancel — no threshold, no expiry", async () => {
    anyView([await coolingOff()]);
    render();
    const card = await screen.findByRole("article", { name: "Action cool-1" });
    const lands = within(card).getByText(/Lands by itself at/);
    expect(lands.textContent).toContain(new Date(LANDS_AT).toLocaleString());
    expect(lands.textContent).toMatch(/unless .* cancels it\./);
    expect(within(card).getByText("lands in 2 d 4 h")).toBeTruthy();
    expect(within(card).getByText(/None needed/)).toBeTruthy();
    expect(within(card).queryByText(/expires in/)).toBeNull();
    expect(within(card).queryByText(/ of \d/)).toBeNull();
    expect(within(card).getByRole("button", { name: "Cancel request" })).toBeTruthy();
    expect(within(card).queryByRole("button", { name: "Approve" })).toBeNull();
    expect(within(card).queryByText(/This is against you/)).toBeNull();
  });

  it("cancels through actions/cancel/0.2", async () => {
    const open = await coolingOff();
    const requests = anyView(
      [open],
      [taskRoute(ACTIONS_CANCEL_TASK, { action: { ...open, status: "cancelled" } })],
    );
    render();
    const card = await screen.findByRole("article", { name: "Action cool-1" });
    fireEvent.click(within(card).getByRole("button", { name: "Cancel request" }));
    fireEvent.click(within(card).getByRole("button", { name: "Cancel this action" }));
    await waitFor(() =>
      expect(sentPayloads(requests, ACTIONS_CANCEL_TASK)).toEqual([{ actionId: "cool-1" }]),
    );
  });

  it("tells its subject it is against them and cannot be blocked, with no buttons", async () => {
    anyView([await coolingOff({ callerRole: "subject" })]);
    render();
    const card = await screen.findByRole("article", { name: "Action cool-1" });
    expect(
      within(card).getByText(/This is against you: it reduces your own authority, and you cannot approve or block/),
    ).toBeTruthy();
    expect(within(card).getByText("lands in 2 d 4 h")).toBeTruthy();
    expect(within(card).queryByRole("button")).toBeNull();
  });

  it("offers no Cancel on a cooling-off that does not name its requester as able to", async () => {
    anyView([await coolingOff({ cancellableBy: undefined })]);
    render();
    const card = await screen.findByRole("article", { name: "Action cool-1" });
    await within(card).findByText(/Lands by itself at/);
    expect(within(card).queryByRole("button", { name: "Cancel request" })).toBeNull();
  });

  it("says a landed cooling-off landed uncancelled", async () => {
    anyView([
      await coolingOff({
        status: "completed",
        closedReason: "landedAfterCoolingOff",
        closedAt: "2026-10-05T09:00:05Z",
        cancellableBy: undefined,
      }),
    ]);
    render();
    const card = await screen.findByRole("article", { name: "Action cool-1" });
    expect(
      await within(card).findByText("It landed after its cooling-off, uncancelled"),
    ).toBeTruthy();
    expect(within(card).queryByText(/lands in/)).toBeNull();
    expect(within(card).queryByRole("button")).toBeNull();
  });
});

describe("coolingOffOf", () => {
  it("reads the 0.2 action's own landsAt and callerRole, not an ext", async () => {
    const mineOpen = await coolingOff();
    const subjectField = mineOpen.summary.fields.subject?.value;
    expect(coolingOffOf(mineOpen)).toEqual({
      landsAt: LANDS_AT,
      ...(typeof subjectField === "string" ? { subject: subjectField } : {}),
      againstYou: false,
      cancellableByMe: true,
    });
    const against = coolingOffOf(await coolingOff({ callerRole: "subject" }))!;
    expect(against.againstYou).toBe(true);
    expect(against.cancellableByMe).toBe(false);
    // An approval is never one, whatever its ext says.
    expect(
      coolingOffOf({
        ...mineOpen,
        category: "approval",
        landsAt: undefined,
        ext: { "org.openvtc": { coolingOff: { landsAt: LANDS_AT } } as never },
      }),
    ).toBeNull();
    // The 0.1 workaround is gone: a coolingOff with no top-level landsAt is not read.
    expect(coolingOffOf({ ...mineOpen, landsAt: undefined })).toBeNull();
  });
});

// ── A new administrator's approver invite ───────────────────────────

describe("the approver invite of a completed grant", () => {
  it("is shown to the requester once, with copy buttons and the separate-channel note", async () => {
    const done: Action = {
      ...mine,
      status: "completed",
      closedReason: "thresholdMet",
      closedAt: "2026-10-02T11:00:00Z",
      ext: {
        "org.openvtc": {
          approverInvite: {
            inviteId: "inv_1",
            url: "https://vtc.example/admin/enrol-approver#token=sua_abc",
            claimCode: "7KQ4-MX2P-9TDA",
            expiresAt: "2026-10-02T11:15:00Z",
          },
        },
      },
    };
    routes([], [taskRoute(ACTIONS_SHOW_TASK, { action: done })]);
    render(undefined, "/actions?action=act-2");
    const invite = await screen.findByRole("region", {
      name: "Approver invite for the new administrator",
    });
    expect(within(invite).getByText("https://vtc.example/admin/enrol-approver#token=sua_abc")).toBeTruthy();
    expect(within(invite).getByText("7KQ4-MX2P-9TDA")).toBeTruthy();
    expect(within(invite).getByText("Shown once.")).toBeTruthy();
    expect(within(invite).getByText("separate channels")).toBeTruthy();
    expect(within(invite).getByRole("button", { name: "Copy invite link" })).toBeTruthy();
    expect(within(invite).getByRole("button", { name: "Copy claim code" })).toBeTruthy();
  });

  it("is not shown to anyone but the requester", async () => {
    const done: Action = {
      ...waiting,
      challenge: undefined,
      callerRole: "observer",
      status: "completed",
      closedReason: "thresholdMet",
      closedAt: "2026-10-02T11:00:00Z",
      ext: {
        "org.openvtc": {
          approverInvite: {
            inviteId: "inv_1",
            url: "https://vtc.example/x",
            claimCode: "CODE",
            expiresAt: "2026-10-02T11:15:00Z",
          },
        },
      },
    };
    routes([], [taskRoute(ACTIONS_SHOW_TASK, { action: done })]);
    render(undefined, "/actions?action=act-1");
    await screen.findByRole("article", { name: "Action act-1" });
    expect(screen.queryByText("CODE")).toBeNull();
  });
});

describe("landsIn", () => {
  const now = Date.parse("2026-10-02T00:00:00Z");
  it("counts down to landsAt, and says when it is due", () => {
    expect(landsIn("2026-10-04T04:00:00Z", now)).toBe("lands in 2 d 4 h");
    expect(landsIn("2026-10-02T03:10:00Z", now)).toBe("lands in 3 h 10 m");
    expect(landsIn("2026-10-02T00:05:00Z", now)).toBe("lands in 5 m");
    expect(landsIn("2026-10-02T00:00:00Z", now)).toBe("landing now");
    expect(landsIn("2026-10-01T00:00:00Z", now)).toBe("landing now");
  });
});

describe("the 0.2 wire", () => {
  it("lists, shows, cancels and acknowledges at 0.2", () => {
    expect(ACTIONS_LIST_TASK).toBe("https://trusttasks.org/spec/vtc/admin/actions/list/0.2");
    expect(ACTIONS_SHOW_TASK).toBe("https://trusttasks.org/spec/vtc/admin/actions/show/0.2");
    expect(ACTIONS_CANCEL_TASK).toBe("https://trusttasks.org/spec/vtc/admin/actions/cancel/0.2");
    expect(ACTIONS_ACKNOWLEDGE_TASK).toBe(
      "https://trusttasks.org/spec/vtc/admin/actions/acknowledge/0.2",
    );
  });

  it("sends the list read as list/0.2", async () => {
    const requests = routes([waiting]);
    render();
    await screen.findByRole("article", { name: "Action act-1" });
    const types = requests
      .filter((r) => r.url === "/v1/trust-tasks")
      .map((r) => (r.body as { type?: string })?.type);
    expect(types).toContain("https://trusttasks.org/spec/vtc/admin/actions/list/0.2");
    expect(types.some((t) => t?.endsWith("/actions/list/0.1"))).toBe(false);
  });
});

// ── Approving with the step-up approver device ──────────────────────

const DEVICE = "did:key:z6MkApproverDeviceZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
const ATTEST = "https://trusttasks.org/spec/auth/step-up/approver/attest/0.1";
const STATEMENT = {
  type: ATTEST,
  issuer: DEVICE,
  payload: { purpose: "decision" },
  proof: { verificationMethod: `${DEVICE}#k`, proofValue: "zDevice" },
};

/** A wallet whose plugin also answers decisions with its approver. */
function installDeviceWallet(
  opts: { approveDecision?: () => Promise<unknown>; identity?: string } = {},
) {
  const signTrustTask = installWallet();
  const answer = opts.approveDecision ?? (async () => ({ statement: STATEMENT, approverDid: DEVICE }));
  const approveDecision = vi.fn((_params: unknown) => answer());
  const wallet = window.vtaWallet as unknown as Record<string, unknown>;
  wallet.approveDecision = approveDecision;
  if (opts.identity) wallet.approverIdentity = vi.fn(async () => ({ approverDid: opts.identity }));
  return { signTrustTask, approveDecision };
}

const approverList = (approvers: string[]) =>
  taskRoute(APPROVER_LIST_TASK, {
    approvers: approvers.map((approverDid) => ({
      approverDid,
      subject: ME,
      enrolledAt: "2026-10-01T00:00:00Z",
      enrolledVia: "invite",
    })),
  });

/** A passkey that answers, recorded. */
function installPasskey() {
  const bytes = (s: string) => new TextEncoder().encode(s).buffer;
  const get = vi.fn(async () => ({
    id: "cred",
    rawId: bytes("cred"),
    type: "public-key",
    response: {
      authenticatorData: bytes("ad"),
      clientDataJSON: bytes("cd"),
      signature: bytes("sig"),
      userHandle: null,
    },
  }));
  Object.defineProperty(navigator, "credentials", { value: { get }, configurable: true });
  return get;
}

const granted = () =>
  taskRoute(DECISION_TASK, { status: "granted", payloadDigest: "z", actionId: "act-1" });

describe("deciding with the approver device", () => {
  it("has the device sign over the salted wire digest, then the wallet signs the identical decision", async () => {
    const { signTrustTask, approveDecision } = installDeviceWallet();
    const get = installPasskey();
    const requests = routes([waiting], [approverList([DEVICE]), granted()]);
    // A passkey session too: the device still comes first.
    render(["passkey"]);
    const card = await screen.findByRole("article", { name: "Action act-1" });
    fireEvent.click(await within(card).findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(decisions(requests)).toHaveLength(1));

    const wire = await wireDigest(waiting.typeUri, waiting.payload, CHALLENGE);
    expect(wire).not.toBe(waiting.payloadDigest);
    expect(approveDecision).toHaveBeenCalledTimes(1);
    expect(approveDecision.mock.calls[0]![0]).toEqual({
      audience: VTC,
      subject: ME,
      action: {
        type: waiting.typeUri,
        payload: waiting.payload,
        actionId: "act-1",
        summary: waiting.summary,
      },
      decision: { challenge: CHALLENGE, payloadDigest: wire, decision: "approve" },
    });

    expect(signTrustTask).toHaveBeenCalledTimes(1);
    const signed = signTrustTask.mock.calls[0]![0];
    expect(signed.asDid).toBe(ME);
    expect(signed.envelope.type).toBe("https://trusttasks.org/spec/task-consent/decision/0.2");
    expect(signed.envelope.recipient).toBe(VTC);
    expect(signed.envelope.payload).toEqual({
      challenge: CHALLENGE,
      payloadDigest: wire,
      decision: "approve",
      actionId: "act-1",
      evidence: { kind: "approverSigned", statement: STATEMENT },
    });
    expect((decisions(requests)[0]!.body as { payload: unknown }).payload).toEqual(
      signed.envelope.payload,
    );
    // No passkey ceremony: the device outranks it.
    expect(get).not.toHaveBeenCalled();
  });

  it("declines through the device too, with the very same trimmed reason", async () => {
    const { signTrustTask, approveDecision } = installDeviceWallet();
    const requests = routes(
      [waiting],
      [
        approverList([DEVICE]),
        taskRoute(DECISION_TASK, { status: "denied", payloadDigest: "z", actionId: "act-1" }),
      ],
    );
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Decline" }));
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "  not agreed  " } });
    fireEvent.click(screen.getByRole("button", { name: "Send decline" }));
    await waitFor(() => expect(decisions(requests)).toHaveLength(1));

    const asked = approveDecision.mock.calls[0]![0] as { decision: Record<string, unknown> };
    expect(asked.decision).toEqual({
      challenge: CHALLENGE,
      payloadDigest: await wireDigest(waiting.typeUri, waiting.payload, CHALLENGE),
      decision: "deny",
      reason: "not agreed",
    });
    const payload = signTrustTask.mock.calls[0]![0].envelope.payload as Record<string, unknown>;
    expect(payload).toEqual({
      ...asked.decision,
      actionId: "act-1",
      evidence: { kind: "approverSigned", statement: STATEMENT },
    });
  });

  it("asks before sending without the device when it does not confirm, then falls back", async () => {
    const { signTrustTask } = installDeviceWallet({
      approveDecision: async () => {
        throw new Error("dismissed");
      },
    });
    const get = installPasskey();
    const requests = routes([waiting], [approverList([DEVICE]), granted()]);
    render(["passkey"]);
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    expect(await screen.findByText("Approver device not confirmed")).toBeTruthy();
    expect(decisions(requests)).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "Send without approver device" }));
    await waitFor(() => expect(decisions(requests)).toHaveLength(1));
    // Fell back to the next factor: the passkey.
    expect(get).toHaveBeenCalledTimes(1);
    const payload = signTrustTask.mock.calls[0]![0].envelope.payload as {
      evidence?: { kind: string };
    };
    expect(payload.evidence?.kind).toBe("webauthn");
  });

  it("sends nothing when the administrator cancels after the device did not confirm", async () => {
    installDeviceWallet({
      approveDecision: async () => {
        throw new Error("dismissed");
      },
    });
    const requests = routes([waiting], [approverList([DEVICE]), granted()]);
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await screen.findByText("Approver device not confirmed");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByText("Approver device not confirmed")).toBeNull());
    expect(decisions(requests)).toHaveLength(0);
  });
});

describe("decision evidence precedence", () => {
  it("uses the passkey when the plugin can answer but no approver is enrolled", async () => {
    const { approveDecision, signTrustTask } = installDeviceWallet();
    const get = installPasskey();
    const requests = routes([waiting], [approverList([]), granted()]);
    render(["passkey"]);
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(decisions(requests)).toHaveLength(1));
    expect(approveDecision).not.toHaveBeenCalled();
    expect(get).toHaveBeenCalledTimes(1);
    expect(
      (signTrustTask.mock.calls[0]![0].envelope.payload as { evidence?: { kind: string } })
        .evidence?.kind,
    ).toBe("webauthn");
  });

  it("does not use a device whose approver is bound from another browser", async () => {
    const { approveDecision } = installDeviceWallet({
      identity: "did:key:z6MkSomeOtherBrowsersApproverXXXXXXXXXXXXXXXXXX",
    });
    const requests = routes([waiting], [approverList([DEVICE]), granted()]);
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(decisions(requests)).toHaveLength(1));
    expect(approveDecision).not.toHaveBeenCalled();
  });

  it("uses this browser's device when the plugin names it among the enrolled", async () => {
    const { approveDecision } = installDeviceWallet({ identity: DEVICE });
    const requests = routes([waiting], [approverList([DEVICE]), granted()]);
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(decisions(requests)).toHaveLength(1));
    expect(approveDecision).toHaveBeenCalledTimes(1);
  });

  it("signs with the wallet alone when there is neither device nor passkey", async () => {
    const sign = installWallet();
    const requests = routes([waiting], [granted()]);
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(decisions(requests)).toHaveLength(1));
    expect(
      (sign.mock.calls[0]![0].envelope.payload as { evidence?: unknown }).evidence,
    ).toBeUndefined();
  });

  it("shows the cnm command when there is no wallet, device or not", async () => {
    routes([waiting], [approverList([DEVICE])]);
    render();
    const card = await screen.findByRole("article", { name: "Action act-1" });
    expect(await within(card).findByText("cnm consent approve --action act-1")).toBeTruthy();
    expect(within(card).queryByRole("button", { name: "Approve" })).toBeNull();
  });
});

describe("timeLeft", () => {
  const now = Date.parse("2026-10-02T00:00:00Z");
  it("reads as days and hours, hours and minutes, or minutes", () => {
    expect(timeLeft("2026-10-04T04:00:00Z", now)).toBe("expires in 2 d 4 h");
    expect(timeLeft("2026-10-02T03:10:00Z", now)).toBe("expires in 3 h 10 m");
    expect(timeLeft("2026-10-02T00:12:00Z", now)).toBe("expires in 12 m");
    expect(timeLeft("2026-10-01T00:00:00Z", now)).toBe("expired");
  });
});
