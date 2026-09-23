import { describe, expect, it } from "vitest";

import {
  adoptTask,
  archiveTask,
  bindTask,
  didError,
  forgeHostError,
  grantTask,
  revokeTask,
  segmentError,
  shellQuote,
  transferTask,
  unbindTask,
} from "./actions";

const BOB = "did:webvh:QmBob:bob.dev";

describe("signed git-ns tasks", () => {
  it("builds a grant exactly as cnm will sign it", () => {
    const t = grantTask(
      {
        subject: BOB,
        right: "git.commit.sign",
        resource: "github.com/acme/widgets",
        expiresInDays: 90,
        reason: "Bob's first PR",
      },
      new Date("2026-09-23T00:00:00.000Z"),
    );
    expect(t.taskUri).toBe("https://trusttasks.org/spec/git-ns/right/grant/0.1");
    expect(t.payload).toEqual({
      subject: BOB,
      right: "git.commit.sign",
      resource: "github.com/acme/widgets",
      expiresAt: "2026-12-22T00:00:00Z",
      reason: "Bob's first PR",
    });
    expect(t.consent).toBe("normal");
    expect(t.command).toBe(
      `cnm git grant --subject ${BOB} --right git.commit.sign --resource github.com/acme/widgets --expires-in 90d --reason 'Bob'\\''s first PR'`,
    );
  });

  it("classes an owner grant elevated and an ns.admin grant destructive", () => {
    expect(grantTask({ subject: BOB, right: "git.repo.own", resource: "github.com/acme/x" }).consent).toBe(
      "elevated",
    );
    expect(grantTask({ subject: BOB, right: "git.ns.admin", resource: "github.com/acme" }).consent).toBe(
      "destructive",
    );
  });

  it("builds a revoke, bind, unbind and adopt with their cnm commands", () => {
    expect(revokeTask(BOB, "git.repo.maintain", "github.com/acme/x").command).toBe(
      `cnm git revoke --subject ${BOB} --right git.repo.maintain --resource github.com/acme/x`,
    );
    const bind = bindTask("github.com", "acme", "bridge");
    expect(bind.payload).toEqual({ forge: "github.com", owner: "acme", mode: "bridge" });
    expect(bind.command).toBe("cnm git namespace bind --forge github.com --owner acme --mode bridge");
    expect(bind.consent).toBe("destructive");
    expect(unbindTask("ns_1", "github.com/acme").payload).toEqual({ namespace: "ns_1" });
    expect(adoptTask("github.com/acme/x", [BOB]).command).toBe(
      `cnm git adopt github.com/acme/x --owner ${BOB}`,
    );
  });

  it("has no cnm command for transfer and archive, and says so with null", () => {
    expect(transferTask("github.com/acme/x", BOB)).toMatchObject({
      payload: { resource: "github.com/acme/x", to: BOB },
      command: null,
      consent: "elevated",
    });
    expect(archiveTask("github.com/acme/x")).toMatchObject({
      taskUri: "https://trusttasks.org/spec/git-ns/repo/archive/0.1",
      command: null,
    });
  });
});

describe("validation, as the specs state it", () => {
  it("wants a lowercase DNS host with no scheme", () => {
    expect(forgeHostError("github.com")).toBeNull();
    expect(forgeHostError("git.example.org")).toBeNull();
    expect(forgeHostError("GitHub.com")).toMatch(/lowercase/);
    expect(forgeHostError("https://github.com")).toMatch(/host only/);
    expect(forgeHostError("")).toMatch(/Name the forge/);
  });

  it("wants one lowercase segment without a leading dot", () => {
    expect(segmentError("acme")).toBeNull();
    expect(segmentError("Acme")).toMatch(/lowercase/);
    expect(segmentError("acme/widgets")).toMatch(/without slashes/);
    expect(segmentError(".github")).toMatch(/dot/);
  });

  it("wants a DID", () => {
    expect(didError(BOB)).toBeNull();
    expect(didError("bob")).toMatch(/Not a DID/);
  });

  it("quotes only what the shell would split", () => {
    expect(shellQuote("github.com/acme")).toBe("github.com/acme");
    expect(shellQuote("two words")).toBe("'two words'");
  });
});
