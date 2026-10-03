// A parked act that waits out a cooling-off (VTI-APV-019) is not "sent for
// approval": nobody is asked, and it lands by itself unless the requester
// cancels it. The notice says that, and never "N must approve".

import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { ParkedNotice } from "./ParkedNotice";
import {
  ACTIONS_SHOW_TASK,
  NEXT_STEP_TYPE,
  ParkedAction,
  coolingOffSentence,
  parkedActionFromDocument,
} from "@/lib/parked-action";

const UNTIL = "2026-10-05T10:00:00Z";
const COOLING_MESSAGE =
  "Nobody but you and did:key:z6MkCarol can consent to this, so it waits out a cooling-off and lands by itself in 72 hours (2026-10-05T10:00:00Z) unless you cancel it. They can see it coming but cannot block it (VTI-APV-019).";

const coolingReply = (message?: string) => ({
  id: "urn:uuid:reply",
  type: NEXT_STEP_TYPE,
  payload: {
    continuation: "proceed",
    expects: [{ typeUri: ACTIONS_SHOW_TASK, hint: { actionId: "act-c" } }],
    inResponseTo: { id: "urn:uuid:req", typeUri: "https://trusttasks.org/spec/acl/revoke/0.1" },
    ...(message ? { message } : {}),
    ext: {
      "org.openvtc": {
        actionId: "act-c",
        kind: "acl.reduce.authority",
        threshold: 0,
        approvers: 0,
        approvals: 0,
        expiresAt: "2026-10-09T10:00:00Z",
        coolingOffUntil: UNTIL,
      },
    },
  },
});

const show = (action: ParkedAction) =>
  render(
    <MemoryRouter>
      <ParkedNotice action={action} />
    </MemoryRouter>,
  );

describe("a parked cooling-off", () => {
  it("reads coolingOffUntil off the next-step reply", () => {
    const parked = parkedActionFromDocument(coolingReply(COOLING_MESSAGE))!;
    expect(parked.coolingOffUntil).toBe(UNTIL);
    expect(parked.coolingOff).toBe(true);
    expect(parked.message).toBe(COOLING_MESSAGE);
  });

  it("says it lands after the cooling-off, not who must approve", () => {
    show(parkedActionFromDocument(coolingReply(COOLING_MESSAGE))!);
    expect(screen.getByText("Sent — lands after a cooling-off")).toBeTruthy();
    expect(screen.queryByText("Sent for approval")).toBeNull();
    expect(screen.getByText(/Lands by itself at/).textContent).toContain(
      new Date(UNTIL).toLocaleString(),
    );
    expect(screen.queryByText(/must approve/)).toBeNull();
    expect(screen.getByRole("link", { name: "View the action" }).getAttribute("href")).toBe(
      "/actions?action=act-c",
    );
  });

  it("falls back to its own cooling-off sentence when the VTC sent none", () => {
    const parked = parkedActionFromDocument(coolingReply())!;
    expect(parked.message).toBe(coolingOffSentence(UNTIL));
    expect(parked.message).toMatch(/lands by itself after a cooling-off/);
    expect(parked.message).not.toMatch(/must approve/);
  });

  it("an ordinary parked act still says who must approve", () => {
    const parked = new ParkedAction({ actionId: "a", threshold: 1, approvers: 2 });
    expect(parked.coolingOff).toBe(false);
    show(parked);
    expect(screen.getByText("Sent for approval")).toBeTruthy();
    expect(screen.getByText(/1 of 2 unrestricted administrator\(s\) must approve/)).toBeTruthy();
  });
});
