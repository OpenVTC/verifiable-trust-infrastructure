import { describe, expect, it } from "vitest";

import {
  brandingBody,
  buildListBody,
  describeSeconds,
  EMPTY_LIST_DRAFT,
  explainFailure,
  explainNeed,
  factsHeadline,
  filterGrants,
  grantState,
  httpsUriProblem,
  isLanguageTag,
  parseIsoDuration,
  statementVerdict,
  summarizeRequirements,
  sweepMinutesError,
  validateBranding,
  validateRequirements,
  validityDaysError,
  type VettingRequirements,
} from "@/lib/vetting";
import type {
  JoinRequestVetting,
  JoinRequestVettingStatement,
  VetterGrantRow,
} from "@/lib/wire-types";

const REQUIREMENTS: VettingRequirements = {
  version: "0.1",
  statementType: "https://firstperson.network/endorsements/identity-vetting/0.1",
  minStatements: 2,
  minByMethod: { inPerson: 1 },
  acceptedMethods: ["inPerson", "video", "priorAcquaintance"],
  requiredClaims: ["name.legal"],
  maxStatementAge: "P120D",
  eligibleVetters: { role: "vetter" },
  independence: {
    maxByDeclaredRelationship: { family: 0, sameEmployer: 1 },
    requireConsistentIdentityCommitment: true,
  },
};

function statement(
  patch: Partial<JoinRequestVettingStatement> = {},
): JoinRequestVettingStatement {
  return {
    id: "urn:uuid:1",
    issuer: "did:key:zCarol",
    method: "inPerson",
    declaredRelationship: "none",
    verified: true,
    eligible: true,
    revoked: false,
    withdrawnNow: false,
    counted: true,
    failures: [],
    ...patch,
  };
}

function facts(patch: Partial<JoinRequestVetting> = {}): JoinRequestVetting {
  return {
    criterionId: "kernel-developer",
    requirementsDigest: "zDigest",
    applicantDigestMatches: true,
    statements: [statement()],
    distinctCountedVetters: 2,
    byMethod: { inPerson: 1, video: 1 },
    commitmentsConsistent: true,
    independenceOk: true,
    invitationRequired: false,
    satisfied: true,
    needs: [],
    recordedAt: "2026-09-01T00:00:00Z",
    ...patch,
  };
}

describe("validateRequirements mirrors VettingRequirements::validate", () => {
  it("accepts the documented example", () => {
    expect(validateRequirements(REQUIREMENTS)).toEqual([]);
  });

  it("refuses what no applicant could satisfy", () => {
    const problems = validateRequirements({
      ...REQUIREMENTS,
      minStatements: 0,
      acceptedMethods: ["video"],
      minByMethod: { inPerson: 1 },
    });
    expect(problems).toHaveLength(2);
    expect(problems[0]).toMatch(/at least 1 statement/);
    expect(problems[1]).toMatch(/in person statements, which this criterion does not accept/);
  });

  it("refuses calendar durations and malformed versions", () => {
    const problems = validateRequirements({
      ...REQUIREMENTS,
      version: "1",
      maxStatementAge: "P3M",
      decisionSla: "PT",
    });
    expect(problems.some((p) => p.includes('"1" is not'))).toBe(true);
    expect(problems.some((p) => p.includes('maximum statement age "P3M"'))).toBe(true);
    expect(problems.some((p) => p.includes('decision deadline "PT"'))).toBe(true);
  });

  it("checks the role, document classes, URL and independence members", () => {
    const problems = validateRequirements({
      ...REQUIREMENTS,
      eligibleVetters: { role: "custom:vetter" },
      acceptedDocumentClasses: ["Passport"],
      governanceFrameworkUrl: "http://example.org/gf",
      independence: { maxByDeclaredRelationship: { cousin: 1 } },
      invitation: "sometimes",
    });
    expect(problems).toHaveLength(5);
  });

  it("names an empty or missing method list", () => {
    expect(validateRequirements({ ...REQUIREMENTS, acceptedMethods: [] })).toEqual([
      "Accept at least one vetting method.",
    ]);
    expect(validateRequirements(null)).toEqual([
      "The vetting requirements must be an object.",
    ]);
  });
});

describe("parseIsoDuration mirrors parse_iso8601_duration", () => {
  it.each([
    ["P120D", 120 * 86_400],
    ["P2W", 14 * 86_400],
    ["P1DT12H", 129_600],
    ["PT90M", 5_400],
    ["PT1H30M15S", 5_415],
  ])("reads %s", (input, seconds) => {
    expect(parseIsoDuration(input)).toBe(seconds);
  });

  it.each(["P", "PT", "P1M", "P1Y", "P1D2W", "P1DT", "120D", "PD", "P1DT1H1H"])(
    "refuses %s",
    (input) => {
      expect(parseIsoDuration(input)).toBeNull();
    },
  );

  it("describes seconds in days and hours", () => {
    expect(describeSeconds(129_600)).toBe("1 day 12 hours");
    expect(describeSeconds(120 * 86_400)).toBe("120 days");
  });
});

describe("statement outcomes", () => {
  it("says a counted statement counted", () => {
    expect(statementVerdict(statement())).toEqual({
      tone: "ok",
      label: "Counted",
      reasons: [],
    });
  });

  it("flags a counted statement withdrawn after the decision", () => {
    const verdict = statementVerdict(statement({ withdrawnNow: true }));
    expect(verdict.tone).toBe("warn");
    expect(verdict.reasons[0]?.code).toBe("withdrawnNow");
  });

  it("explains every failure and keeps the code", () => {
    const verdict = statementVerdict(
      statement({ counted: false, failures: ["issuer-not-vetter", "too-old"] }),
    );
    expect(verdict.tone).toBe("bad");
    expect(verdict.reasons.map((r) => r.code)).toEqual([
      "issuer-not-vetter",
      "too-old",
    ]);
    expect(verdict.reasons[1]?.text).toBe("It is older than this criterion allows.");
  });

  it("derives reasons from the flags when facts carry none", () => {
    const verdict = statementVerdict(
      statement({ counted: false, verified: false, revoked: true }),
    );
    expect(verdict.reasons.map((r) => r.code)).toEqual(["unverified", "revoked"]);
  });

  it("does not hide an unknown failure code", () => {
    expect(explainFailure("new-reason")).toEqual({
      code: "new-reason",
      text: "It did not count, for a reason this console does not recognise.",
    });
  });
});

describe("needs", () => {
  it("reads the vetting grammar", () => {
    expect(explainNeed("vetting:statements:1").text).toBe(
      "Statements from 1 more eligible vetter.",
    );
    expect(explainNeed("vetting:method:inPerson:2").text).toBe(
      "2 more counted statements made in person.",
    );
    expect(explainNeed("vetting:invitation").text).toMatch(/^An invitation/);
  });

  it("shows anything else verbatim", () => {
    expect(explainNeed("agreed:code-of-conduct")).toEqual({
      code: "agreed:code-of-conduct",
      text: "agreed:code-of-conduct",
    });
    expect(explainNeed("vetting:method:telepathy:1").text).toBe(
      "vetting:method:telepathy:1",
    );
  });
});

describe("factsHeadline follows the default policy's order", () => {
  it("leads with different identities over a shortfall", () => {
    expect(
      factsHeadline(
        facts({
          satisfied: false,
          commitmentsConsistent: false,
          needs: ["vetting:statements:1"],
        }),
      ).title,
    ).toBe("Vetters verified different identities");
  });

  it("reports a shortfall, then an independence cap", () => {
    expect(
      factsHeadline(facts({ satisfied: false, needs: ["vetting:statements:1"] }))
        .tone,
    ).toBe("warn");
    expect(
      factsHeadline(facts({ satisfied: false, independenceOk: false })).title,
    ).toMatch(/share a relationship/);
  });

  it("confirms a satisfied request", () => {
    expect(factsHeadline(facts()).detail).toMatch(/^2 distinct vetters counted/);
  });
});

describe("requirements summary", () => {
  it("writes the example in sentences", () => {
    const lines = summarizeRequirements(REQUIREMENTS);
    expect(lines).toContain("Statements from at least 2 distinct eligible vetters.");
    expect(lines).toContain("At least 1 of them made in person.");
    expect(lines).toContain("A statement counts for 120 days after it is made.");
    expect(lines).toContain(
      'No counted statements from vetters declaring "Family member".',
    );
    expect(lines).toContain("Each vetter decides which documents they accept.");
  });
});

describe("grant bounds and states", () => {
  it("bounds validity to one day through two years", () => {
    expect(validityDaysError("365")).toBeNull();
    expect(validityDaysError("0")).toMatch(/outside/);
    expect(validityDaysError("731")).toMatch(/outside/);
    expect(validityDaysError("1.5")).toMatch(/whole number/);
    expect(validityDaysError("")).toMatch(/^Enter days/);
  });

  it("bounds the sweep to 5 through 1440 minutes", () => {
    expect(sweepMinutesError("60")).toBeNull();
    expect(sweepMinutesError("4")).toMatch(/outside/);
  });

  const row = (patch: Partial<VetterGrantRow>): VetterGrantRow => ({
    endorsementId: "e1",
    memberDid: "did:key:zCarol",
    credentialId: "urn:uuid:c1",
    validFrom: "2026-01-01T00:00:00Z",
    validUntil: "2027-01-01T00:00:00Z",
    revoked: false,
    live: true,
    origin: "manual",
    ...patch,
  });
  const now = Date.parse("2026-09-11T00:00:00Z");

  it("tells revoked, expired and departed grants apart", () => {
    expect(grantState(row({}), now)).toBe("live");
    expect(grantState(row({ live: false, revoked: true }), now)).toBe("revoked");
    expect(
      grantState(row({ live: false, validUntil: "2026-01-02T00:00:00Z" }), now),
    ).toBe("expired");
    expect(grantState(row({ live: false }), now)).toBe("inactive");
  });

  it("filters by state, origin and name", () => {
    const rows = [
      row({ endorsementId: "a" }),
      row({ endorsementId: "b", origin: "auto", live: false, revoked: true }),
      row({
        endorsementId: "c",
        memberDid: "did:key:zDan",
        profile: {
          listed: true,
          displayName: "Carol M.",
          languages: [],
          methods: [],
          eventCount: 0,
          updatedAt: "2026-01-01T00:00:00Z",
        },
      }),
    ];
    const ids = (f: Parameters<typeof filterGrants>[1]) =>
      filterGrants(rows, f, now).map((r) => r.endorsementId);
    expect(ids({ state: "live", origin: "all", search: "" })).toEqual(["a", "c"]);
    expect(ids({ state: "all", origin: "auto", search: "" })).toEqual(["b"]);
    expect(ids({ state: "all", origin: "all", search: "carol m" })).toEqual(["c"]);
  });
});

describe("listing filters mirror VetterListBody::check_shape", () => {
  it("omits empty filters and upper-cases the country", () => {
    const { body, errors } = buildListBody({
      ...EMPTY_LIST_DRAFT,
      language: " de ",
      country: "at",
      method: "video",
    });
    expect(errors).toEqual({});
    expect(body).toEqual({ language: "de", country: "AT", method: "video" });
  });

  it("refuses a bad tag, country and an inverted range", () => {
    const { errors } = buildListBody({
      ...EMPTY_LIST_DRAFT,
      language: "german!",
      country: "AUT",
      eventFrom: "2026-10-07",
      eventTo: "2026-10-05",
    });
    expect(Object.keys(errors).sort()).toEqual(["country", "eventTo", "language"]);
  });

  it("reads BCP 47 tags as the daemon does", () => {
    expect(isLanguageTag("de-AT")).toBe(true);
    expect(isLanguageTag("zh-Hant-TW")).toBe(true);
    expect(isLanguageTag("d")).toBe(false);
    expect(isLanguageTag("de_AT")).toBe(false);
  });
});

describe("branding mirrors CommunityBranding::check_shape", () => {
  it("accepts a complete branding and lower-cases the colour", () => {
    const draft = {
      displayName: "Linux Kernel",
      accentColor: "#1A2B3C",
      logoUrl: "https://kernel.example.org/logo.svg",
    };
    expect(validateBranding(draft)).toEqual({});
    expect(brandingBody(draft, { ext: { a: 1 } })).toEqual({
      displayName: "Linux Kernel",
      accentColor: "#1a2b3c",
      logoUrl: "https://kernel.example.org/logo.svg",
      ext: { a: 1 },
    });
  });

  it("clears empty members", () => {
    expect(brandingBody({ displayName: " ", accentColor: "", logoUrl: "" })).toEqual(
      {},
    );
  });

  it("explains each refusal", () => {
    const errors = validateBranding({
      displayName: "x".repeat(129),
      accentColor: "#12345",
      logoUrl: "http://kernel.example.org/logo.svg",
    });
    expect(errors.displayName).toMatch(/129 characters/);
    expect(errors.accentColor).toMatch(/six hex digits/);
    expect(errors.logoUrl).toMatch(/https:\/\//);
    expect(
      validateBranding({
        displayName: "",
        accentColor: "",
        logoUrl: "https://kernel.example.org/my logo.svg",
      }).logoUrl,
    ).toMatch(/spaces/);
    expect(
      validateBranding({
        displayName: "",
        accentColor: "",
        logoUrl: "https://kernel.example.org/logo\u0007.svg",
      }).logoUrl,
    ).toMatch(/control characters/);
    expect(
      validateBranding({
        displayName: "",
        accentColor: "",
        logoUrl: "https:///logo.svg",
      }).logoUrl,
    ).toMatch(/complete address/);
  });
});

describe("httpsUriProblem mirrors shape::https_uri", () => {
  it.each([
    "https://events.example.org",
    "https://events.example.org/kms?day=1#hall-b",
    "https://example.org/caf%C3%A9",
    "https://[2001:db8::1]:8443/logo.svg",
  ])("accepts %s", (url) => {
    expect(httpsUriProblem(url)).toBeNull();
  });

  it.each([
    ["https://events.example.org/kernel meetup", "whitespace"],
    ["https://events.example.org/\u0007", "whitespace"],
    ["https://events.example.org/\tx", "whitespace"],
    ["http://events.example.org", "notHttpsUri"],
    ["events.example.org", "notHttpsUri"],
    ["https://", "notHttpsUri"],
    ["https:///path", "notHttpsUri"],
    ["https://?q=1", "notHttpsUri"],
    ["https://example.org/%zz", "notHttpsUri"],
    ["https://example.org/café", "notHttpsUri"],
    ["https://example.org/<logo>", "notHttpsUri"],
    [`https://example.org/${"a".repeat(2048)}`, "length"],
  ])("refuses %j as %s", (url, problem) => {
    expect(httpsUriProblem(url)).toBe(problem);
  });

  it("holds the governance framework address to the same rule", () => {
    for (const governanceFrameworkUrl of [
      "https://gov.example/frame work",
      "https://gov.example/\u001b",
      "http://gov.example/gf",
    ]) {
      expect(
        validateRequirements({ ...REQUIREMENTS, governanceFrameworkUrl }),
      ).toHaveLength(1);
    }
  });
});
