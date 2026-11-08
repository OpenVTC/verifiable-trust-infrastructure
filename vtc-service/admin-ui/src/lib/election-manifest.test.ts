import { describe, expect, it } from "vitest";

import {
  MANIFEST_LIMITS,
  TEXT_RELEASE_THRESHOLD_ADVISED,
  checkDraft,
  draftFromPrevious,
  draftToManifest,
  emptyDraft,
  fromLocalInput,
  manifestDigest,
  manifestToDraft,
  newQuestion,
  retypeQuestion,
  slugKey,
  suggestElectionId,
  textReleaseWarning,
  toLocalInput,
  type ManifestDraft,
} from "./election-manifest";
import bundleJson from "../../../../vti-specs-vtc/trust-tasks/vtc/elections/create/0.5.bundle.json";

const COMMUNITY = "did:example:community";
const BOX = "did:example:box";
const NOW = Date.parse("2027-01-01T00:00:00Z");

/** The vendored bundle the community validates against. */
const bundle = bundleJson as unknown as { schema: { $defs: Record<string, any> } };
const defs = bundle.schema.$defs;

function valid(over: Partial<ManifestDraft> = {}): ManifestDraft {
  return {
    ...emptyDraft(new Date(NOW)),
    electionId: "agm-2027",
    ballotBox: BOX,
    ...over,
  };
}

const messages = (d: ManifestDraft) => checkDraft(d, COMMUNITY, NOW).map((i) => i.message);

describe("textReleaseWarning", () => {
  // VTI-VOT-065 SHOULD 10; below it members are told (VTI-VOT-090), and so is the administrator.
  it("warns from 1 to 9, and not at the advised 10 or above", () => {
    expect(emptyDraft(new Date(NOW)).textReleaseThreshold).toBe(String(TEXT_RELEASE_THRESHOLD_ADVISED));
    for (const t of [1, 5, 9]) {
      expect(textReleaseWarning(t)).toMatch(/may identify who wrote it/);
    }
    for (const t of [10, 25, undefined, null, 0, Number.NaN, 2.5]) {
      expect(textReleaseWarning(t)).toBeNull();
    }
  });
});

describe("MANIFEST_LIMITS", () => {
  // The builder's bounds are the schema's: a pinned version that moves one
  // fails here rather than as a refusal at create.
  it("matches the pinned vtc/elections/create/0.5 schema", () => {
    const m = defs.Manifest.properties;
    const [choice, ranking, score, text] = defs.Question.oneOf;
    expect(defs.ElectionId.pattern).toBe(MANIFEST_LIMITS.electionIdPattern);
    expect(defs.Key.pattern).toBe(MANIFEST_LIMITS.keyPattern);
    expect(m.title.maxLength).toBe(MANIFEST_LIMITS.titleMax);
    expect(m.description.maxLength).toBe(MANIFEST_LIMITS.descriptionMax);
    expect(m.ballotBox.maxLength).toBe(MANIFEST_LIMITS.didMax);
    expect(m.questions.minItems).toBe(MANIFEST_LIMITS.questionsMin);
    expect(m.questions.maxItems).toBe(MANIFEST_LIMITS.questionsMax);
    expect(m.textReleaseThreshold.minimum).toBe(MANIFEST_LIMITS.textReleaseThresholdMin);
    expect(defs.QuestionOption.properties.label.maxLength).toBe(MANIFEST_LIMITS.optionLabelMax);
    expect(choice.properties.text.maxLength).toBe(MANIFEST_LIMITS.questionTextMax);
    expect(choice.properties.options).toMatchObject({
      minItems: MANIFEST_LIMITS.choiceOptions.min,
      maxItems: MANIFEST_LIMITS.choiceOptions.max,
    });
    expect(ranking.properties.options).toMatchObject({
      minItems: MANIFEST_LIMITS.rankingOptions.min,
      maxItems: MANIFEST_LIMITS.rankingOptions.max,
    });
    expect(score.properties.options).toMatchObject({
      minItems: MANIFEST_LIMITS.scoreOptions.min,
      maxItems: MANIFEST_LIMITS.scoreOptions.max,
    });
    expect(text.properties.maxLength).toMatchObject({
      minimum: MANIFEST_LIMITS.textMaxLength.min,
      maximum: MANIFEST_LIMITS.textMaxLength.max,
    });
    expect(defs.Trustees.properties.dids.minItems).toBe(MANIFEST_LIMITS.trusteesMin);
    expect(defs.Trustees.properties.threshold.minimum).toBe(MANIFEST_LIMITS.thresholdMin);
    // voting/_shared/0.4: the credential roll and its one DID (VTI-VOT-025).
    const roll = defs.RollRule;
    expect(roll.properties.rule.enum).toEqual(["members", "membersAndListed", "listed", "credential"]);
    expect(roll.properties.memberOf.pattern).toBe(MANIFEST_LIMITS.memberOfPattern);
    expect(roll.properties.memberOf.minLength).toBe(MANIFEST_LIMITS.memberOfMin);
    expect(roll.properties.memberOf.maxLength).toBe(MANIFEST_LIMITS.didMax);
  });

  it("renders only members the schema declares", () => {
    const d = valid({
      title: "AGM",
      description: "Yearly",
      secrecy: "sealed",
      trustees: "did:example:t1\ndid:example:t2",
      roll: "membersAndListed",
      listed: "did:example:guest",
      questions: (["choice", "ranking", "score", "text"] as const).map((t, i) => newQuestion(i, t)),
    });
    const m = draftToManifest(d, COMMUNITY);
    const declared = Object.keys(defs.Manifest.properties);
    for (const k of Object.keys(m)) expect(declared).toContain(k);
    for (const k of defs.Manifest.required as string[]) expect(m).toHaveProperty(k);
    (m.questions as Record<string, unknown>[]).forEach((q, i) => {
      const variant = defs.Question.oneOf[i];
      for (const k of Object.keys(q)) expect(Object.keys(variant.properties)).toContain(k);
      for (const k of variant.required as string[]) expect(q).toHaveProperty(k);
    });
  });
});

describe("draft ⇄ manifest", () => {
  it("reads back every manifest the form writes", () => {
    const full = {
      electionId: "board-2027",
      community: COMMUNITY,
      title: "Board election",
      description: "Two seats.",
      questions: [
        { key: "seats", type: "choice", text: "Who?", options: [{ key: "a", label: "Alice" }, { key: "b" }, { key: "c", label: "Carol" }], minSelections: 0, maxSelections: 2, optional: false },
        { key: "order", type: "ranking", options: [{ key: "x" }, { key: "y" }], partial: true, optional: true },
        { key: "rate", type: "score", options: [{ key: "x" }], min: -2, max: 2, optional: true },
        { key: "say", type: "text", text: "Anything?", maxLength: 280, optional: true },
      ],
      secrecy: "sealed",
      trustees: { dids: ["did:example:t1", "did:example:t2", "did:example:t3"], threshold: 2 },
      roll: { rule: "listed", listed: ["did:example:p1", "did:example:p2"] },
      registrationOpensAt: "2027-01-01T00:00:00Z",
      votingOpensAt: "2027-01-02T09:30:15Z",
      votingClosesAt: "2027-01-09T00:00:00Z",
      revote: "refuse",
      board: { visibility: "private", auditors: ["did:example:aud"] },
      ballotBox: BOX,
      binding: true,
      allowEarlyClose: true,
      resultsBeforeClose: false,
      textReleaseThreshold: 25,
    };
    const r = manifestToDraft(full);
    if ("error" in r) throw new Error(r.error);
    expect(draftToManifest(r.draft, COMMUNITY)).toEqual(full);
    expect(checkDraft(r.draft, COMMUNITY, NOW)).toEqual([]);
  });

  it("refuses what the form would drop", () => {
    const m = draftToManifest(valid(), COMMUNITY);
    expect(manifestToDraft({ ...m, extra: 1 })).toEqual({ error: 'The form does not edit "extra".' });
    const q = { key: "q", type: "vote", optional: true };
    expect("error" in manifestToDraft({ ...m, questions: [q] })).toBe(true);
    const textWithOptions = { key: "q", type: "text", maxLength: 5, optional: true, options: [] };
    expect("error" in manifestToDraft({ ...m, questions: [textWithOptions] })).toBe(true);
  });

  it("omits an empty title, description and option label, and an open election's trustees", () => {
    const d = valid({ trustees: "did:example:t1\ndid:example:t2" });
    d.questions[0]!.options[1]!.label = "";
    const m = draftToManifest(d, COMMUNITY);
    expect(m).not.toHaveProperty("title");
    expect(m).not.toHaveProperty("description");
    expect(m).not.toHaveProperty("trustees");
    expect((m.questions as any)[0].options[1]).toEqual({ key: "no" });
    expect(m.roll).toEqual({ rule: "members" });
  });

  it("starts from a previous election with a fresh identifier and schedule", () => {
    const old = draftToManifest(valid({ title: "AGM 2026", electionId: "agm-2026" }), COMMUNITY);
    const later = new Date("2027-06-01T10:20:00Z");
    const r = draftFromPrevious(old, later);
    if ("error" in r) throw new Error(r.error);
    expect(r.draft.electionId).toBe("agm-2026");
    expect(r.draft.autoId).toBe(true);
    expect(r.draft.registrationOpensAt).toBe("2027-06-01T10:20:00Z");
    expect(r.draft.votingOpensAt).toBe("2027-06-02T11:00:00Z");
    expect(r.draft.questions).toHaveLength(1);
  });

  it("keeps the options when a question changes kind", () => {
    const q = { ...newQuestion(0), options: [] };
    expect(retypeQuestion(q, "ranking").options.map((o) => o.key)).toEqual(["yes", "no"]);
    const text = retypeQuestion(newQuestion(0), "text");
    expect(text.type).toBe("text");
    expect(draftToManifest(valid({ questions: [text] }), COMMUNITY).questions).toEqual([
      { key: "q1", type: "text", maxLength: 500, optional: true },
    ]);
  });
});

describe("checkDraft", () => {
  it("passes a new draft once it names a ballot box", () => {
    expect(messages(valid())).toEqual([]);
    expect(messages(valid({ ballotBox: "" }))).toEqual(["Name the ballot box."]);
  });

  // vti_voting::rules::check_manifest, rule by rule.
  it("holds the cross-field rules the community applies", () => {
    const choice = { ...newQuestion(0), minSelections: "2", maxSelections: "3" };
    expect(messages(valid({ questions: [choice] }))).toEqual([
      "Question 1: fewest ≤ most ≤ the number of options (2).",
    ]);
    const score = { ...newQuestion(0, "score"), min: "5", max: "5" };
    expect(messages(valid({ questions: [score] }))).toEqual([
      "Question 1: the lowest score is below the highest.",
    ]);
    const twice = [newQuestion(0), { ...newQuestion(1), key: "q1" }];
    expect(messages(valid({ questions: twice }))).toEqual(['The question key "q1" is used twice.']);
    const sameOption = { ...newQuestion(0), options: [...newQuestion(0).options, newQuestion(0).options[0]!] };
    expect(messages(valid({ questions: [sameOption] }))).toEqual(['Question 1: the option key "yes" is used twice.']);
    expect(messages(valid({ roll: "listed" }))).toEqual(["Name at least one party."]);
    expect(messages(valid({ auditors: BOX }))).toEqual([
      "Neither the community nor the ballot box audits its own election.",
    ]);
    expect(messages(valid({ textReleaseThreshold: "0" }))).toEqual(["A whole number, 1 or more."]);
    // VTI-VOT-065: 1 – 9 is a valid manifest; the builder warns rather than refuses.
    expect(messages(valid({ textReleaseThreshold: "1" }))).toEqual([]);
    expect(messages(valid({ textReleaseThreshold: "9" }))).toEqual([]);
  });

  it("holds the schedule in order and in the future", () => {
    const d = valid();
    expect(messages({ ...d, votingOpensAt: d.votingClosesAt })).toEqual(["Voting closes after it opens."]);
    expect(messages({ ...d, registrationOpensAt: d.votingClosesAt, votingOpensAt: d.votingClosesAt })).toContain(
      "Voting closes after it opens.",
    );
    expect(
      messages({
        ...d,
        registrationOpensAt: "2026-01-01T00:00:00Z",
        votingOpensAt: "2026-01-02T00:00:00Z",
        votingClosesAt: "2026-01-03T00:00:00Z",
      }),
    ).toEqual(["This time has already passed."]);
    expect(messages({ ...d, votingOpensAt: "" })).toContain("Not a time.");
  });

  it("holds the trustee rules of an encrypted election (VTI-VOT-060 – 064)", () => {
    const sealed = valid({ secrecy: "sealed", trustees: "did:example:t1\ndid:example:t2", threshold: "2" });
    expect(messages(sealed)).toEqual([]);
    expect(messages({ ...sealed, trustees: "did:example:t1" })).toEqual(["Name at least 2 trustees."]);
    expect(messages({ ...sealed, threshold: "3" })).toEqual(["A whole number from 2 to the number of trustees."]);
    expect(messages({ ...sealed, trustees: `did:example:t1\n${COMMUNITY}` })).toEqual([
      "Neither the community nor the ballot box is a trustee.",
    ]);
    const tallied = { ...sealed, secrecy: "talliedEncrypted" as const, questions: [newQuestion(0, "text")] };
    expect(messages(tallied)).toEqual([
      "Totals-only elections ask choice questions only. Change the other questions, or pick another secrecy.",
    ]);
    // Running totals are an open election's alone: never rendered for another level.
    expect(draftToManifest({ ...sealed, resultsBeforeClose: true }, COMMUNITY).resultsBeforeClose).toBe(false);
  });
});

describe("helpers", () => {
  it("makes keys and identifiers in the manifest's alphabet", () => {
    expect(slugKey("Café Society — 2027!")).toBe("cafe-society-2027");
    expect(suggestElectionId("Annual General Meeting")).toBe("annual-general-meeting");
    expect(suggestElectionId("!!!", new Date("2027-03-04T00:00:00Z"))).toBe("poll-2027-03-04");
  });

  it("converts between datetime-local and UTC without losing a minute", () => {
    const iso = "2027-01-02T09:30:00Z";
    expect(fromLocalInput(toLocalInput(iso))).toBe(iso);
    expect(fromLocalInput(toLocalInput("2027-01-02T09:30:15Z"))).toBe("2027-01-02T09:30:15Z");
    expect(fromLocalInput("")).toBe("");
  });

  it("computes manifestDigest as the community does", async () => {
    // Independently computed: SHA-256 multihash of the RFC 8785 bytes, base58btc.
    const m = draftToManifest(
      valid({
        registrationOpensAt: "2027-01-01T00:00:00Z",
        votingOpensAt: "2027-01-02T00:00:00Z",
        votingClosesAt: "2027-01-09T00:00:00Z",
      }),
      "did:example:c",
    );
    expect(await manifestDigest(m)).toBe("zQmSBTNwH4V2g87UjMpbRDjex6KZVeSJRCEHuJNZTUPKjHs");
  });
});

describe("the credential roll (VTI-VOT-025, VTI-VOT-026)", () => {
  const GROUP = "did:webvh:QmGroup:community.example:groups:g7";

  it("renders memberOf, and no listed, under the credential rule", () => {
    const m = draftToManifest(valid({ roll: "credential", memberOf: ` ${GROUP} `, listed: "did:example:x" }), COMMUNITY);
    expect(m.roll).toEqual({ rule: "credential", memberOf: GROUP });
    expect(messages(valid({ roll: "credential", memberOf: GROUP }))).toEqual([]);
    // Every other rule carries no memberOf.
    const other = draftToManifest(valid({ roll: "listed", listed: "did:example:x", memberOf: GROUP }), COMMUNITY);
    expect(other.roll).toEqual({ rule: "listed", listed: ["did:example:x"] });
  });

  it("asks for one DID", () => {
    expect(messages(valid({ roll: "credential", memberOf: "" }))).toEqual([
      "Name the DID whose membership credentials admit their holders.",
    ]);
    expect(messages(valid({ roll: "credential", memberOf: "group-7" }))).toEqual([
      "A DID (did:method:…), 8 – 2048 characters.",
    ]);
    expect(messages(valid({ roll: "credential", memberOf: "did:x:a b" }))).toHaveLength(1);
  });

  it("reads a credential roll back, and refuses what the rule forbids", () => {
    const m = draftToManifest(valid({ roll: "credential", memberOf: GROUP }), COMMUNITY);
    const back = manifestToDraft(m);
    if ("error" in back) throw new Error(back.error);
    expect(back.draft.roll).toBe("credential");
    expect(back.draft.memberOf).toBe(GROUP);
    expect(draftToManifest(back.draft, COMMUNITY)).toEqual(m);

    expect(manifestToDraft({ ...m, roll: { rule: "credential", memberOf: GROUP, listed: ["did:example:x"] } })).toEqual({
      error: 'A credential roll lists nobody: the form cannot carry its "listed".',
    });
    expect(manifestToDraft({ ...m, roll: { rule: "members", memberOf: GROUP } })).toEqual({
      error: 'Only a credential roll names "memberOf".',
    });
    expect("error" in manifestToDraft({ ...m, roll: { rule: "credential", memberOf: GROUP, extra: 1 } })).toBe(true);
    expect("error" in manifestToDraft({ ...m, roll: { rule: "delegates" } })).toBe(true);
  });
});
