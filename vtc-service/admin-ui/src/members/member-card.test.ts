import { describe, expect, it } from "vitest";

import { hueOf, initials, nameOf, safeUrl, vcardOf } from "./member-card";

describe("drawing a member", () => {
  it("names a member by their name, else their nickname, else nothing", () => {
    expect(nameOf({ displayName: "Glenn Gore", nickname: "Glenn" })).toBe("Glenn Gore");
    expect(nameOf({ nickname: "glenn" })).toBe("glenn");
    expect(nameOf({ role: "member" })).toBeNull();
    expect(nameOf({ displayName: "   " })).toBeNull();
  });

  it("takes initials from the first and last words", () => {
    expect(initials("Glenn Gore")).toBe("GG");
    expect(initials("Carol Ann Example")).toBe("CE");
    expect(initials("cee")).toBe("C");
    expect(initials(null)).toBe("?");
  });

  it("gives an entry one colour wherever it appears", () => {
    expect(hueOf("dir_Q2xhcmFRMmxoY21GUk1t")).toBe(hueOf("dir_Q2xhcmFRMmxoY21GUk1t"));
    expect(hueOf("dir_a")).toBeGreaterThanOrEqual(0);
    expect(hueOf("dir_a")).toBeLessThan(360);
  });

  it("links only http and https", () => {
    expect(safeUrl("https://affinidi.com")).toBe("https://affinidi.com/");
    expect(safeUrl("javascript:alert(1)")).toBeNull();
    expect(safeUrl("data:text/html,x")).toBeNull();
    expect(safeUrl("not a url")).toBeNull();
  });
});

describe("saving a contact", () => {
  const labels = new Map([["org.example.team", "Team"]]);

  it("carries what the viewer sees and nothing more, escaped", () => {
    const card = vcardOf(
      "dir_x",
      {
        displayName: "Glenn Gore",
        nickname: "Glenn",
        pronouns: "He/Him",
        bio: "CEO; builds things, mostly\nopen source",
        links: ["https://affinidi.com", "javascript:alert(1)"],
        role: "admin",
        avatar: { sha256: "a".repeat(64), mediaType: "image/jpeg" },
        "org.example.team": "Platform",
      },
      labels,
      "Acme Guild",
    );
    expect(card.startsWith("BEGIN:VCARD\r\nVERSION:4.0\r\n")).toBe(true);
    expect(card).toContain("FN:Glenn Gore\r\n");
    expect(card).toContain("NICKNAME:Glenn\r\n");
    expect(card).toContain("PRONOUNS:He/Him\r\n");
    expect(card).toContain("NOTE:CEO\\; builds things\\, mostly\\nopen source\r\n");
    expect(card).toContain("URL:https://affinidi.com/\r\n");
    expect(card).not.toContain("javascript");
    expect(card).toContain("ORG:Acme Guild\r\n");
    expect(card).toContain("X-VTC-FIELD;LABEL=Team:Platform\r\n");
    expect(card).not.toContain("sha256");
    // No DID was shown, so none is saved.
    expect(card).not.toContain("IMPP");
    expect(card.endsWith("UID:urn:vtc-directory:dir_x\r\nEND:VCARD\r\n")).toBe(true);
  });
});
