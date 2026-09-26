// Break-glass: the rules the console mirrors (separation of duties, who may
// ratify or revoke, which records count toward the invariants), the tasks it
// builds, and the commands it hands over — quoted so that every shell a
// console user pastes into reads the same bytes back.

import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { GitNsBreakGlassItem } from "@/lib/wire-types";
import { forgetConsoleKey, generateConsoleKey, resetConsoleKeyCacheForTests } from "@/lib/console-key";
import { mockFetch } from "@/test/render";

import {
  breakGlassTask,
  justificationError,
  ratifyTask,
  sendSigned,
  sendTask,
  StepUpNeeded,
  TASK_URI,
} from "./actions";
import {
  awaitingItems,
  breakGlassState,
  consentClass,
  countsTowardInvariant,
  isElevated,
  isSelfGrant,
  ratifyStanding,
  revokeBreakGlassStanding,
} from "./model";
import { ALICE, ALICE_BREAK_GLASS, BOB, HANA, rightRow } from "./fixtures.test-data";

const FISH_BREAKOUT = "x\\' ; echo INJECTED ; echo \\";
const HOME = mkdtempSync(join(tmpdir(), "vtc-breakglass-"));

function argvIn(shell: string, args: string): string[] {
  const out = execFileSync(shell, ["-c", `env printf '%s\\0' ${args}`], {
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME },
    stdio: ["ignore", "pipe", "pipe"],
  });
  return out.split("\0").slice(0, -1);
}

function installed(shell: string): boolean {
  try {
    execFileSync(shell, ["-c", "true"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

describe("separation of duties", () => {
  it("covers exactly namespace admin, repo creator and owner", () => {
    expect(isElevated("git.ns.admin")).toBe(true);
    expect(isElevated("git.repo.create")).toBe(true);
    expect(isElevated("git.repo.own")).toBe(true);
    expect(isElevated("git.repo.maintain")).toBe(false);
    expect(isElevated("git.commit.sign")).toBe(false);
  });

  it("is a self-grant only when the signer names themselves for an elevated right", () => {
    expect(isSelfGrant(ALICE, ALICE, "git.repo.own")).toBe(true);
    expect(isSelfGrant(ALICE, ` ${ALICE} `, "git.ns.admin")).toBe(true);
    expect(isSelfGrant(ALICE, ALICE, "git.commit.sign")).toBe(false);
    expect(isSelfGrant(ALICE, ALICE, "git.repo.maintain")).toBe(false);
    expect(isSelfGrant(ALICE, BOB, "git.repo.own")).toBe(false);
    expect(isSelfGrant(null, ALICE, "git.repo.own")).toBe(false);
  });

  it("classes break-glass as destructive and a ratification as the grant it confirms", () => {
    expect(consentClass("right.breakGlass")).toBe("destructive");
    expect(consentClass("right.ratify", "git.ns.admin")).toBe("destructive");
    expect(consentClass("right.ratify", "git.repo.own")).toBe("elevated");
  });
});

describe("break-glass state", () => {
  const at = "2026-09-25T02:10:31Z";
  const now = Date.parse("2026-09-25T03:00:00Z");

  it("reads unratified, delayed and ratified", () => {
    expect(breakGlassState(null)).toBeNull();
    expect(breakGlassState({ by: ALICE, at, justification: "j" }, now)).toBe("unratified");
    expect(
      breakGlassState({ by: ALICE, at, justification: "j", effectiveAt: "2026-09-25T04:00:00Z" }, now),
    ).toBe("pending");
    expect(
      breakGlassState({ by: ALICE, at, justification: "j", effectiveAt: "2026-09-25T02:40:00Z" }, now),
    ).toBe("unratified");
    expect(
      breakGlassState({ by: ALICE, at, justification: "j", ratifiedBy: BOB, ratifiedAt: at }, now),
    ).toBe("ratified");
  });

  it("counts toward the invariants only records with no expiry that are not unratified", () => {
    const own = { subject: ALICE, right: "git.repo.own", resource: "github.com/acme/docs" };
    expect(countsTowardInvariant(rightRow(own))).toBe(true);
    expect(countsTowardInvariant(rightRow({ ...own, expiresAt: "2099-01-01T00:00:00Z" }))).toBe(false);
    expect(
      countsTowardInvariant(rightRow({ ...own, breakGlass: { by: ALICE, at, justification: "j" } })),
    ).toBe(false);
    expect(
      countsTowardInvariant(
        rightRow({ ...own, breakGlass: { by: ALICE, at, justification: "j", ratifiedBy: BOB } }),
      ),
    ).toBe(true);
  });

  it("lists what awaits a decision, oldest first", () => {
    const later: GitNsBreakGlassItem = {
      ...ALICE_BREAK_GLASS,
      resource: "github.com/acme/widgets",
      breakGlass: { ...ALICE_BREAK_GLASS.breakGlass, at: "2026-09-25T05:00:00Z" },
      state: "pending",
    };
    const done: GitNsBreakGlassItem = { ...ALICE_BREAK_GLASS, state: "ratified" };
    expect(awaitingItems([later, done, ALICE_BREAK_GLASS])).toEqual([ALICE_BREAK_GLASS, later]);
  });
});

describe("who may ratify and revoke (ratify 0.1, revoke 0.3)", () => {
  const nsAdmin = (did: string, breakGlass?: boolean) =>
    rightRow({
      subject: did,
      right: "git.ns.admin",
      resource: "github.com/acme",
      ...(breakGlass ? { breakGlass: { by: did, at: "2026-09-24T00:00:00Z", justification: "j" } } : {}),
    });

  it("never lets the holder ratify their own break-glass, even as a community administrator", () => {
    const s = ratifyStanding(ALICE, true, ALICE_BREAK_GLASS, [nsAdmin(ALICE)]);
    expect(s.may).toBe(false);
    expect(!s.may && s.why).toMatch(/ratified by someone else/);
  });

  it("lets any community administrator ratify, git rights or not", () => {
    expect(ratifyStanding(HANA, true, ALICE_BREAK_GLASS, []).may).toBe(true);
  });

  it("lets another namespace admin ratify, but not one whose own standing is an unratified break-glass", () => {
    expect(ratifyStanding(BOB, false, ALICE_BREAK_GLASS, [nsAdmin(BOB)]).may).toBe(true);
    expect(ratifyStanding(BOB, false, ALICE_BREAK_GLASS, [nsAdmin(BOB, true)]).may).toBe(false);
    expect(ratifyStanding(HANA, false, ALICE_BREAK_GLASS, []).may).toBe(false);
  });

  it("lets an owner of the repository ratify a break-glass of owner there", () => {
    const owner = rightRow({ subject: BOB, right: "git.repo.own", resource: "github.com/acme/docs" });
    expect(ratifyStanding(BOB, false, ALICE_BREAK_GLASS, [owner]).may).toBe(true);
  });

  it("lets the holder, any community administrator, or an authority revoke", () => {
    expect(revokeBreakGlassStanding(ALICE, false, ALICE_BREAK_GLASS, []).may).toBe(true);
    expect(revokeBreakGlassStanding(HANA, true, ALICE_BREAK_GLASS, []).may).toBe(true);
    expect(revokeBreakGlassStanding(BOB, false, ALICE_BREAK_GLASS, [nsAdmin(BOB)]).may).toBe(true);
    expect(revokeBreakGlassStanding(HANA, false, ALICE_BREAK_GLASS, []).may).toBe(false);
    // Once ratified it is an ordinary grant: the community-administrator
    // capability alone no longer reaches it.
    expect(
      revokeBreakGlassStanding(HANA, true, { ...ALICE_BREAK_GLASS, state: "ratified" }, []).may,
    ).toBe(false);
  });
});

describe("break-glass and ratify tasks", () => {
  it("builds a break-glass with no subject and no expiry, as cnm will sign it", () => {
    const t = breakGlassTask("git.repo.own", "github.com/acme/docs", "  CVE fix tonight  ");
    expect(t.taskUri).toBe("https://trusttasks.org/spec/git-ns/right/break-glass/0.1");
    expect(t.payload).toEqual({
      right: "git.repo.own",
      resource: "github.com/acme/docs",
      justification: "CVE fix tonight",
    });
    expect(t.consent).toBe("destructive");
    expect(t.command).toBe(
      "cnm git break-glass --right=git.repo.own --resource=github.com/acme/docs --justification='CVE fix tonight'",
    );
    expect(t.effect).toMatch(/never expires/);
    expect(t.effect).toMatch(/notified immediately/);
    expect(t.consentNote).toMatch(/passkey/);
  });

  it("binds a ratification to the break-glass it read", () => {
    const t = ratifyTask(ALICE, "git.repo.own", "github.com/acme/docs", "2026-09-25T02:10:31Z", "ok");
    expect(t.taskUri).toBe(TASK_URI["right.ratify"]);
    expect(t.payload).toEqual({
      subject: ALICE,
      right: "git.repo.own",
      resource: "github.com/acme/docs",
      breakGlassAt: "2026-09-25T02:10:31Z",
      statement: "ok",
    });
    expect(t.command).toBe(
      `cnm git ratify --subject=${ALICE} --right=git.repo.own --resource=github.com/acme/docs --break-glass-at=2026-09-25T02:10:31Z --statement=ok`,
    );
  });

  it("requires a justification that is not blank, of at most 2048 characters", () => {
    expect(justificationError("")).toMatch(/Say why/);
    expect(justificationError(" \n\t ")).toMatch(/Say why/);
    expect(justificationError("x".repeat(2048))).toBeNull();
    expect(justificationError("x".repeat(2049))).toMatch(/At most 2048/);
  });

  it("sends grant and revoke at 0.3, where separation of duties is specified", () => {
    expect(TASK_URI["right.grant"]).toBe("https://trusttasks.org/spec/git-ns/right/grant/0.3");
    expect(TASK_URI["right.revoke"]).toBe("https://trusttasks.org/spec/git-ns/right/revoke/0.3");
  });
});

describe.each(["sh", "bash", "zsh", "fish"])("break-glass commands in %s", (shell) => {
  const present = installed(shell);
  it.skipIf(!present)("a hostile justification and statement reach cnm intact", () => {
    const bg = breakGlassTask("git.ns.admin", "github.com/acme", FISH_BREAKOUT);
    expect(argvIn(shell, bg.command.replace(/^cnm /, ""))).toEqual([
      "git",
      "break-glass",
      "--right=git.ns.admin",
      "--resource=github.com/acme",
      `--justification=${FISH_BREAKOUT}`,
    ]);
    const r = ratifyTask(ALICE, "git.ns.admin", "github.com/acme", "2026-09-25T02:10:31Z", "$(id)");
    expect(argvIn(shell, r.command.replace(/^cnm /, ""))).toEqual([
      "git",
      "ratify",
      `--subject=${ALICE}`,
      "--right=git.ns.admin",
      "--resource=github.com/acme",
      "--break-glass-at=2026-09-25T02:10:31Z",
      "--statement=$(id)",
    ]);
  });
});

// ── the operation-bound step-up, on the wire ────────────────────────────

const VTC_DID = "did:webvh:QmScid:community.example:vtc";
const STEP_UP = {
  subject: ALICE,
  challenge: "c2FtcGxlLWNoYWxsZW5nZS0xMjM0NQ",
  boundTo: "zBoundDigest",
  reason: "Break glass: git.repo.own on github.com/acme/docs",
  targetAcr: "aal2",
  acceptableEvidence: ["webauthn"],
  webauthn: { challenge: "c2FtcGxlLWNoYWxsZW5nZS0xMjM0NQ", allowCredentials: [], userVerification: "required" },
  ttl: 300,
};

describe("sendTask and a bound step-up", () => {
  afterEach(async () => {
    await forgetConsoleKey();
    resetConsoleKeyCacheForTests();
  });

  it("turns the refusal into StepUpNeeded carrying the document, and resends that same document", async () => {
    await generateConsoleKey();
    let calls = 0;
    const requests = mockFetch([
      { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } },
      {
        method: "POST",
        path: "/v1/trust-tasks",
        status: 403,
        body: () => {
          calls += 1;
          return {
            type: "https://trusttasks.org/spec/trust-task-error/0.5",
            payload: {
              code: "permissionDenied",
              message: "a passkey gesture bound to this operation is required",
              details: { stepUpRequest: STEP_UP },
            },
          };
        },
      },
    ]);
    const task = breakGlassTask("git.repo.own", "github.com/acme/docs", "CVE fix");
    const err = await sendTask(task).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(StepUpNeeded);
    const needed = err as StepUpNeeded;
    expect(needed.request.boundTo).toBe("zBoundDigest");
    expect(needed.signed.type).toBe(TASK_URI["right.breakGlass"]);
    expect(needed.signed.payload).toEqual(task.payload);

    // The re-send is byte-for-byte the document that was refused — same id,
    // same proof — not a newly signed one.
    await sendSigned(needed.signed).catch(() => undefined);
    const posts = requests.filter((r) => r.url === "/v1/trust-tasks");
    expect(calls).toBe(2);
    expect(posts[1]!.body).toEqual(posts[0]!.body);
  });
});
