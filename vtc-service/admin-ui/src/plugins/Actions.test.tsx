// The Actions page: cards render from the list, a summary that does not match
// its payload is refused, an approval is signed by the approver's own DID
// through the wallet (never the console key), a browser with no wallet is
// shown the `cnm` command, and a requester can cancel.

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";

import { postSignedTrustTask, type WhoamiResponse } from "@/lib/api";
import { matchCode, payloadDigestOf, wireDigest } from "@/lib/action-summary";
import {
  ACTIONS_CANCEL_TASK,
  ACTIONS_LIST_TASK,
  ACTIONS_SHOW_TASK,
  DECISION_TASK,
  type Action,
} from "@/lib/actions-api";
import vectors from "@/lib/action-summary.vectors.json";
import { Actions, timeLeft } from "@/plugins/actions";
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

describe("timeLeft", () => {
  const now = Date.parse("2026-10-02T00:00:00Z");
  it("reads as days and hours, hours and minutes, or minutes", () => {
    expect(timeLeft("2026-10-04T04:00:00Z", now)).toBe("expires in 2 d 4 h");
    expect(timeLeft("2026-10-02T03:10:00Z", now)).toBe("expires in 3 h 10 m");
    expect(timeLeft("2026-10-02T00:12:00Z", now)).toBe("expires in 12 m");
    expect(timeLeft("2026-10-01T00:00:00Z", now)).toBe("expired");
  });
});
