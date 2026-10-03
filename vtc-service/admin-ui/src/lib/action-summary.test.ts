// The approver's summary (VTI-APV-011/-013): the shared template vectors from
// the Rust renderer verify and render here, and every tampering is refused.
// The decision's wire digest and the match code are checked against an
// independent node:crypto implementation.

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  KIND_OPERATOR_WRITE,
  OPERATOR_EMERGENCY_BOOTSTRAP_URI,
  PINNED_TEMPLATE_DIGESTS,
  SummaryRefusal,
  VerifiedSummary,
  digestBytesOf,
  formatDidInline,
  formatValue,
  matchCode,
  payloadDigestOf,
  resolvePointer,
  verifySummary,
  wireDigest,
  type ActionSummaryWire,
  type SummarySubject,
} from "./action-summary";
import { base58btcDecode, base58btcEncode, jcsCanonicalize } from "./jcs";
import vectors from "./action-summary.vectors.json";

interface Vector {
  name: string;
  kind: string;
  typeUri: string;
  payload: unknown;
  summary: ActionSummaryWire;
}

const VECTORS = vectors as unknown as Vector[];

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

async function verified(subject: SummarySubject): Promise<VerifiedSummary> {
  const out = await verifySummary(subject);
  if (out instanceof SummaryRefusal) throw new Error(`refused: ${out.reason} ${out.detail}`);
  return out;
}

/** Independent: multibase sha2-256 multihash via node:crypto. */
function nodeMultihash(bytes: Buffer): string {
  const d = createHash("sha256").update(bytes).digest();
  return `z${base58btcEncode(new Uint8Array(Buffer.concat([Buffer.from([0x12, 0x20]), d])))}`;
}

describe("shared template vectors", () => {
  it("has vectors to run", () => {
    expect(VECTORS.length).toBeGreaterThan(0);
  });

  for (const v of VECTORS) {
    it(`accepts and renders: ${v.name}`, async () => {
      const s = await verified({
        kind: v.kind,
        typeUri: v.typeUri,
        payload: v.payload,
        summary: v.summary,
        payloadDigest: await payloadDigestOf(v.payload),
      });
      // Every placeholder was filled from the re-derived values.
      expect(s.title).not.toMatch(/\{[A-Za-z0-9_]+\}/);
      if (v.summary.effect) expect(s.effect).not.toMatch(/\{[A-Za-z0-9_]+\}/);
      else expect(s.effect).toBeUndefined();
      for (const [name, field] of Object.entries(v.summary.fields)) {
        const inline = formatValue(field.format, field.value, "inline")!;
        if (v.summary.title.includes(`{${name}}`)) expect(s.title).toContain(inline);
        if (v.summary.effect?.includes(`{${name}}`)) expect(s.effect).toContain(inline);
        const shown = s.fields.find((f) => f.name === name)!;
        expect(shown.text).toBe(formatValue(field.format, field.value, "full"));
      }
      // The literal text around the placeholders survives.
      const literal = v.summary.title.split(/\{[A-Za-z0-9_]+\}/)[0]!;
      expect(s.title.startsWith(literal)).toBe(true);
    });
  }

  it("renders the grant vector as the sentence an approver reads", async () => {
    const v = VECTORS.find((x) => x.name === "grant an unrestricted administrator")!;
    const s = await verified({ ...v });
    expect(s.title).toBe(
      "Make did:webvh:QmScid…xample:carol an unrestricted administrator",
    );
    expect(s.fields.find((f) => f.name === "subject")!.text).toBe(
      "did:webvh:QmScidExample:community.example:carol",
    );
    expect(s.fields.find((f) => f.name === "scopes")!.text).toBe("none");
    expect(s.fields.find((f) => f.name === "expiresAt")!.text).toBe("—");
  });

  it("keeps markup in a text field as its own characters", async () => {
    const v = VECTORS.find((x) => x.kind === "admin.invite.create")!;
    const s = await verified({ ...v });
    expect(s.fields.find((f) => f.name === "label")!.text).toBe("<b>night shift</b>");
  });
});

describe("refusal", () => {
  const base = VECTORS[0]!;

  it("refuses a tampered field value", async () => {
    const summary = clone(base.summary);
    const subject = Object.keys(summary.fields).find((k) => summary.fields[k]!.format === "did")!;
    summary.fields[subject]!.value = "did:key:z6MkAttacker";
    const out = await verifySummary({ ...base, summary });
    expect(out).toBeInstanceOf(SummaryRefusal);
    expect((out as SummaryRefusal).reason).toBe("fieldMismatch");
  });

  it("refuses a payload that disagrees with the summary", async () => {
    const payload = clone(base.payload) as { entry: { subject: string } };
    payload.entry.subject = "did:key:z6MkSomeoneElse";
    const out = await verifySummary({ ...base, payload });
    expect((out as SummaryRefusal).reason).toBe("fieldMismatch");
  });

  it("refuses a pointer re-aimed at another member", async () => {
    const summary = clone(base.summary);
    summary.fields.role!.pointer = "/reason";
    const out = await verifySummary({ ...base, summary });
    expect((out as SummaryRefusal).reason).toBe("fieldMismatch");
  });

  it("refuses a templateDigest that is not pinned for (kind, typeUri)", async () => {
    const summary = { ...clone(base.summary), templateDigest: "zQmNotThePinnedTemplate" };
    expect(((await verifySummary({ ...base, summary })) as SummaryRefusal).reason).toBe(
      "unpinnedTemplate",
    );
  });

  it("refuses a pinned template under another task", async () => {
    const out = await verifySummary({
      ...base,
      typeUri: "https://trusttasks.org/spec/acl/revoke/0.1",
    });
    expect((out as SummaryRefusal).reason).toBe("unpinnedTemplate");
  });

  it("refuses a payloadDigest that does not match the payload", async () => {
    const other = await payloadDigestOf({ something: "else" });
    const out = await verifySummary({ ...base, payloadDigest: other });
    expect((out as SummaryRefusal).reason).toBe("payloadDigestMismatch");
  });

  it("refuses a title naming a field it has not got", async () => {
    const summary = { ...clone(base.summary), title: "Make {nobody} an admin" };
    expect(((await verifySummary({ ...base, summary })) as SummaryRefusal).reason).toBe(
      "unknownPlaceholder",
    );
  });

  it("refuses a field whose value is not of its format", async () => {
    const payload = { entry: { subject: 42, role: "admin", scopes: [] }, reason: "x" };
    const summary = clone(base.summary);
    summary.fields.subject!.value = 42;
    const out = await verifySummary({ ...base, payload, summary });
    expect((out as SummaryRefusal).reason).toBe("badFormat");
  });

  it("pins exactly seventeen (kind, typeUri) pairs", () => {
    expect(Object.keys(PINNED_TEMPLATE_DIGESTS)).toHaveLength(17);
  });
});

// The operator's offline writes (VTI-VTC-023): the four templates exactly as
// `vtc-service/src/admin_actions/summary.rs` declares them. Their digests are
// recomputed here, so a pin that drifted from the template text fails.
describe("operator offline-write templates", () => {
  const SPEC = "https://trusttasks.org/spec";
  const EFFECT =
    "Written with {command} on {host} at {at}, while the service was stopped. It is already in effect: acknowledging records that you have seen it, and changes nothing.";
  const f = (pointer: string, format: string) => ({ pointer, format });
  const tail = {
    command: f("/command", "text"),
    host: f("/operatorHost", "text"),
    at: f("/invokedAt", "datetime"),
  };
  const TEMPLATES: { typeUri: string; title: string; fields: Record<string, unknown> }[] = [
    {
      typeUri: `${SPEC}/acl/grant/0.1`,
      title: "The operator gave {subject} the {role} role offline",
      fields: {
        subject: f("/entry/subject", "did"),
        role: f("/entry/role", "text"),
        scopes: f("/entry/scopes", "capabilityList"),
        ...tail,
      },
    },
    {
      typeUri: `${SPEC}/acl/revoke/0.1`,
      title: "The operator removed {subject}'s access offline",
      fields: { subject: f("/entry/subject", "did"), ...tail },
    },
    {
      typeUri: `${SPEC}/auth/step-up/approver/invite/0.1`,
      title: "The operator issued a step-up approver invite for {subject} offline",
      fields: { subject: f("/entry/subject", "did"), ...tail },
    },
    {
      typeUri: OPERATOR_EMERGENCY_BOOTSTRAP_URI,
      title: "The operator ran an emergency bootstrap and replaced every administrator",
      fields: { ...tail },
    },
  ];

  for (const t of TEMPLATES) {
    it(`pins the template for ${t.typeUri}`, () => {
      const canonical = jcsCanonicalize({
        kind: KIND_OPERATOR_WRITE,
        typeUri: t.typeUri,
        title: t.title,
        effect: EFFECT,
        fields: t.fields,
      });
      expect(PINNED_TEMPLATE_DIGESTS[`${KIND_OPERATOR_WRITE}\n${t.typeUri}`]).toBe(
        nodeMultihash(Buffer.from(canonical, "utf8")),
      );
    });
  }

  it("has a shared vector for every operator template", () => {
    for (const t of TEMPLATES) {
      expect(
        VECTORS.some((v) => v.kind === KIND_OPERATOR_WRITE && v.typeUri === t.typeUri),
      ).toBe(true);
    }
  });

  it("renders the offline grant as the sentence an acknowledger reads", async () => {
    const v = VECTORS.find(
      (x) => x.kind === KIND_OPERATOR_WRITE && x.typeUri === `${SPEC}/acl/grant/0.1`,
    )!;
    const s = await verified({ ...v, payloadDigest: await payloadDigestOf(v.payload) });
    expect(s.title).toBe("The operator gave did:key:z6MkhaXg…pbnnEGta2doK the admin role offline");
    expect(s.effect).toContain("Written with vtc acl grant on vtc-host-1 at ");
    expect(s.effect).toContain("acknowledging records that you have seen it, and changes nothing.");
  });
});

describe("formats", () => {
  it("shows both ends of a long DID, never just a prefix", () => {
    const did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const shown = formatDidInline(did);
    expect(shown).toBe("did:key:z6MkhaXg…pbnnEGta2doK");
    expect(formatValue("did", did, "full")).toBe(did);
    expect(formatDidInline("did:key:z6MkShort")).toBe("did:key:z6MkShort");
  });

  it("formats capability lists and absent values", () => {
    expect(formatValue("capabilityList", ["a", "b"])).toBe("a, b");
    expect(formatValue("capabilityList", [])).toBe("none");
    expect(formatValue("capabilityList", null)).toBe("—");
    expect(formatValue("duration", "PT72H")).toBe("PT72H");
    expect(formatValue("text", 1)).toBe("1");
  });

  it("resolves RFC 6901 pointers, escapes included", () => {
    const doc = { "a/b": { "m~n": [10, 20] }, "x.y": 1 };
    expect(resolvePointer(doc, "/a~1b/m~0n/1")).toBe(20);
    expect(resolvePointer(doc, "/x.y")).toBe(1);
    expect(resolvePointer(doc, "/missing")).toBeNull();
  });
});

describe("digests", () => {
  const payload = { entry: { subject: "did:key:z6MkÅlice", role: "admin", scopes: [] } };

  it("payloadDigest matches node:crypto over JCS(payload)", async () => {
    expect(await payloadDigestOf(payload)).toBe(
      nodeMultihash(Buffer.from(jcsCanonicalize(payload), "utf8")),
    );
  });

  it("the match code is the first 6 hex of the digest", async () => {
    const digest = await payloadDigestOf(payload);
    const raw = createHash("sha256").update(jcsCanonicalize(payload), "utf8").digest("hex");
    expect(matchCode(digest)).toBe(raw.slice(0, 6));
    expect(digestBytesOf(digest)).toHaveLength(32);
    expect(matchCode("zNotADigest")).toBeNull();
    expect(matchCode("not-multibase")).toBeNull();
  });

  it("the wire digest matches an independent node:crypto construction", async () => {
    const typeUri = "https://trusttasks.org/spec/acl/grant/0.1";
    const challenge = "c2hhbGxlbmdlLWZvci10aGlzLWRlY2lzaW9u";
    const jcs = Buffer.from(jcsCanonicalize(payload), "utf8");
    const uri = Buffer.from(typeUri, "utf8");
    const len = (n: number) => {
      const b = Buffer.alloc(8);
      b.writeBigUInt64BE(BigInt(n));
      return b;
    };
    const preimage = Buffer.concat([
      Buffer.from("vta/task-consent/v1\0", "utf8"),
      len(uri.length),
      uri,
      len(jcs.length),
      jcs,
      Buffer.from(challenge, "utf8"),
    ]);
    const got = await wireDigest(typeUri, payload, challenge);
    expect(got).toBe(nodeMultihash(preimage));
    // Salted: another challenge gives another digest, and neither is the
    // unsalted payload digest.
    expect(await wireDigest(typeUri, payload, "other-challenge")).not.toBe(got);
    expect(got).not.toBe(await payloadDigestOf(payload));
    // The multihash decodes to 0x12 0x20 + 32 bytes.
    const mh = base58btcDecode(got.slice(1));
    expect([mh[0], mh[1], mh.length]).toEqual([0x12, 0x20, 34]);
  });

  it("fixed vector: empty payload, fixed challenge", async () => {
    // Computed by hand from the construction: tag, u64be(41), the URI,
    // u64be(2), "{}", "abc".
    const typeUri = "https://trusttasks.org/spec/acl/grant/0.1";
    const hex = createHash("sha256")
      .update(
        Buffer.concat([
          Buffer.from("vta/task-consent/v1\0"),
          Buffer.from([0, 0, 0, 0, 0, 0, 0, 41]),
          Buffer.from(typeUri),
          Buffer.from([0, 0, 0, 0, 0, 0, 0, 2]),
          Buffer.from("{}"),
          Buffer.from("abc"),
        ]),
      )
      .digest();
    expect(typeUri.length).toBe(41);
    const got = await wireDigest(typeUri, {}, "abc");
    expect(Array.from(digestBytesOf(got)!)).toEqual(Array.from(hex));
  });
});
