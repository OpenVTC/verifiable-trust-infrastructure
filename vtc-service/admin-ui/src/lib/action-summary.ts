// What an approver is shown about an administrator action, derived from the
// bytes that are digested (VTI-APV-011, VTI-APV-013;
// docs/05-design-notes/vtc-action-list.md §7a.2).
//
// The VTC publishes, with each action, a **summary template** — a title, an
// optional effect sentence, and named fields that are each an RFC 6901 JSON
// Pointer into the action's `payload`. The console does not trust the values
// the VTC filled in. It:
//
//  1. checks the template is the one pinned for the action's `(kind, typeUri)`
//     in this build ([`PINNED_TEMPLATE_DIGESTS`]) — a template the VTC could
//     rewrite per action could say anything;
//  2. recomputes the payload digest (multibase sha2-256 multihash of
//     JCS(payload)) and compares it with the action's `payloadDigest` — the
//     digest is what an approval is bound to, so a summary of other bytes is a
//     summary of a different act;
//  3. re-derives every field from `payload` through its pointer, and refuses
//     when any differs from the value the VTC sent;
//  4. renders the title and effect from the **re-derived** values only.
//
// Any failure refuses to render at all: the card says the summary does not
// match the payload and must not be approved. There is no partial rendering.
//
// Rendering is plain text. A `text` field is shown as its own characters —
// React text nodes, never markup — so `<b>night shift</b>` in a label is
// those eighteen characters.
//
// The same template vectors (`action-summary.vectors.json`, produced by the
// Rust renderer) are run here, in the VTC and in `cnm`, so the three agree.

import { base58btcDecode, base58btcEncode, jcsCanonicalize } from "./jcs";

const SPEC = "https://trusttasks.org/spec";

/** An operator's offline write, raised for acknowledgement (VTI-VTC-023). */
export const KIND_OPERATOR_WRITE = "operator.offlineWrite";

/**
 * The `typeUri` every operator offline write is recorded under: an embedded
 * document type (payload `{command, dids, host, at}`), never a task anybody
 * sends.
 */
export const OPERATOR_OFFLINE_WRITE_URI = "https://trusttasks.org/spec/vtc/operator/offline-write/0.1";

/** The `typeUri` the boot-time ACL migration's acknowledge item is recorded under. */
export const OPERATOR_ACL_MIGRATION_URI = "urn:openvtc:vtc:operator:acl-migration";

/** A departed granter's grants, raised for re-affirmation (`vtc-admin-roles.md`
 *  §6.3): approving re-affirms them, declining withdraws them. */
export const KIND_GRANTS_REVIEW = "acl.grants.review";

/** The record type a grants review is raised under — never a task anybody sends. */
export const GRANTS_REVIEW_URI = "urn:openvtc:vtc:acl:grants-review";

/**
 * The pinned template digest for each `(kind, typeUri)`.
 *
 * This table MUST match `vtc-service/src/admin_actions/summary.rs` `PINNED`.
 * A template whose digest is not listed here for its pair is refused, so a
 * new kind (or a changed template) needs an entry in both places.
 */
export const PINNED_TEMPLATE_DIGESTS: Readonly<Record<string, string>> = Object.freeze({
  [pinKey("acl.grant.authority", `${SPEC}/acl/grant/0.2`)]:
    "zQmNiciJtH7xnKdQUxEwp44mpbCrVt8tfBrt1XKg7VfAc71",
  [pinKey("acl.grant.authority", `${SPEC}/acl/update/0.2`)]:
    "zQmQBA6WoTVVo2wBJrmkJwTnefj6q1Hgwc2BWFTCCPpWnQT",
  [pinKey("acl.grant.authority", `${SPEC}/acl/change-role/0.2`)]:
    "zQmVAPMeYXgX9bUi5HruaPFxBLsW1ZJNkbRss6VixMz48vt",
  [pinKey("acl.reduce.authority", `${SPEC}/acl/revoke/0.2`)]:
    "zQmfJss7J6uNUdyZPUC64BoJ971CdnTfgd6BVEQd7aFjYwD",
  [pinKey("acl.reduce.authority", `${SPEC}/acl/update/0.2`)]:
    "zQmNWjHGRwDCfUsvVFxx6o6eXczqjQTepMEKwkS3qqNo1N6",
  [pinKey("acl.reduce.authority", `${SPEC}/acl/change-role/0.2`)]:
    "zQmaAjJC1L9w3pbUTEbWfhzfBdUpv8pofDZvL6mWSpU2eWk",
  [pinKey("acl.grant.authority", `${SPEC}/acl/grant/0.1`)]:
    "zQmPrXgyRpZ57y4AekuZPspEkunnEbEhxvZuqrfoxrgsvr4",
  [pinKey("acl.grant.authority", `${SPEC}/acl/update/0.1`)]:
    "zQmbvgey1akTyTq74Vhe4fuXGvpTKKTVw34mo3y4hVEKSEQ",
  [pinKey("acl.grant.authority", `${SPEC}/acl/change-role/0.1`)]:
    "zQmQX9Dx7cDqLtcoTNuDSWWo5nJTGecB9CqRLKgpd4es1c9",
  [pinKey("admin.invite.create", `${SPEC}/vtc/admin/invites/create/0.1`)]:
    "zQmSXC2GaMpizs4kKRhz4nBchZikWjqHAoeDfA5D7fVizgp",
  [pinKey("acl.reduce.authority", `${SPEC}/acl/revoke/0.1`)]:
    "zQmbvSkPZnzCqq5idfR5DKfFyiHFRCeimT48C4c6jtZfG1Z",
  [pinKey("acl.reduce.authority", `${SPEC}/acl/change-role/0.1`)]:
    "zQmfHspRZaXfEPkeAyqcFkpgqYT2RCqXjjnXVZmFhsaJQcu",
  [pinKey("acl.reduce.authority", `${SPEC}/acl/update/0.1`)]:
    "zQmXcYLQhsgDQEgDZuf2mvmkxDDKEd1c9C47tmRAGLofPgM",
  [pinKey("acl.reduce.authority", `${SPEC}/acl/grant/0.1`)]:
    "zQmVrvxot9bAts7S22CfXQgqR8vC5aZHWQz97UjfMWveT7o",
  [pinKey("acl.reduce.authority", `${SPEC}/vtc/members/admin-remove/0.1`)]:
    "zQmc2FGMz27Bqiu3CPpy5BrVBWyst3RkfWhfk322QWzu6mR",
  [pinKey("config.threshold.lower", `${SPEC}/config/patch/0.1`)]:
    "zQmeGT7ztnicC5RScp86U5Yjq1s3vhtzZof8yYy6sWi9cYP",
  [pinKey("config.threshold.lower", `${SPEC}/vtc/config/import/0.1`)]:
    "zQmQ6yxgM1HYuJkY4RvQDYiB7NyfsFeAeYzcPnh6d5rrrPc",
  [pinKey("policy.authority.change", `${SPEC}/policy/upsert/0.2`)]:
    "zQma1zFb7cvRpSH7erp14W83wYZW5vP7cke1yLwcwQZdEie",
  [pinKey("policy.authority.change", `${SPEC}/policy/activate/0.1`)]:
    "zQmTqKd5UoQZfTy7giJU9KFWFyhUbqxAtr5XWoUB9BLncBL",
  // An operator's offline write, raised for acknowledgement (VTI-VTC-023).
  [pinKey(KIND_OPERATOR_WRITE, OPERATOR_OFFLINE_WRITE_URI)]:
    "zQmQZTPg2MeWt1C8oAvoLMGJNY9DpxvB6bRjvQwJT7ns9Ah",
  [pinKey(KIND_OPERATOR_WRITE, OPERATOR_ACL_MIGRATION_URI)]:
    "zQmcx336K693LHuAKosCP9avuLZWauw1vome6VBxWBFDiqK",
  // Custom administrative roles (`vtc-admin-roles.md` §6.2).
  [pinKey("acl.role.define", `${SPEC}/vtc/roles/define/0.1`)]:
    "zQmf6erEaANYgarV9c8frmZSZ8R5XuomNdXxGNQ8FAZ2QUh",
  [pinKey("acl.role.delete", `${SPEC}/vtc/roles/delete/0.1`)]:
    "zQmNmqjjmZmPfvapiR91YcFDgXtg1xdAw3QNwaQemrEHL8U",
  // Restoring a backup replaces the ACL (§7).
  [pinKey("backup.restore", `${SPEC}/backup/finalize-import/0.1`)]:
    "zQmY89pWbScF2Mj1B1tWXJrtKPyhqcWDJDiV8eKCTchKscE",
  // A departed granter's grants, for re-affirmation (§6.3).
  [pinKey(KIND_GRANTS_REVIEW, GRANTS_REVIEW_URI)]:
    "zQmes3QBrvXfxcwu7tyU7gk58b8RrLfrQiteFRJGCwDYS4S",
});

function pinKey(kind: string, typeUri: string): string {
  return `${kind}\n${typeUri}`;
}

// ── Wire shapes ─────────────────────────────────────────────────────

/** The closed set of field formats. */
export type FieldFormat = "did" | "capabilityList" | "duration" | "datetime" | "text";

export interface SummaryField {
  /** RFC 6901 JSON Pointer into the action's payload. */
  pointer: string;
  format: FieldFormat;
  /** The value the VTC says the pointer resolves to — checked, never shown. */
  value: unknown;
}

export interface ActionSummaryWire {
  title: string;
  effect?: string;
  fields: Record<string, SummaryField>;
  templateDigest: string;
}

/** What [`verifySummary`] checks: an action's own claims about itself. */
export interface SummarySubject {
  kind: string;
  typeUri: string;
  payload: unknown;
  summary: ActionSummaryWire;
  /** The action's `payloadDigest`. Required for a live action; the shared
   *  template vectors carry none. */
  payloadDigest?: string;
}

// ── The verified form ───────────────────────────────────────────────

/** One field as shown, from the re-derived value. */
export interface RenderedField {
  name: string;
  format: FieldFormat;
  /** Display text — `"—"` for an absent value. */
  text: string;
}

/**
 * A summary that passed every check. Only [`verifySummary`] makes one, so a
 * card that takes it cannot render an unverified summary by mistake.
 */
export class VerifiedSummary {
  private constructor(
    readonly title: string,
    readonly effect: string | undefined,
    readonly fields: readonly RenderedField[],
  ) {}

  /** @internal — [`verifySummary`] only. */
  static create(title: string, effect: string | undefined, fields: RenderedField[]) {
    return new VerifiedSummary(title, effect, Object.freeze(fields));
  }
}

export type SummaryRefusalReason =
  | "unpinnedTemplate"
  | "payloadDigestMismatch"
  | "fieldMismatch"
  | "badFormat"
  | "unknownPlaceholder";

export class SummaryRefusal {
  constructor(
    readonly reason: SummaryRefusalReason,
    /** For a log or a test; never a reason to show the summary anyway. */
    readonly detail: string,
  ) {}
}

/** The single sentence a refused summary is shown as. */
export const SUMMARY_REFUSED_MESSAGE =
  "This action's summary does not match its payload — do not approve it.";

// ── Verification ────────────────────────────────────────────────────

/** Verify and render `subject`'s summary, or say why it is refused. */
export async function verifySummary(
  subject: SummarySubject,
): Promise<VerifiedSummary | SummaryRefusal> {
  const { kind, typeUri, payload, summary } = subject;
  if (!summary || typeof summary !== "object" || typeof summary.title !== "string") {
    return new SummaryRefusal("badFormat", "no summary");
  }
  const pinned = PINNED_TEMPLATE_DIGESTS[pinKey(kind, typeUri)];
  if (!pinned || summary.templateDigest !== pinned) {
    return new SummaryRefusal(
      "unpinnedTemplate",
      `template ${String(summary.templateDigest)} is not pinned for ${kind} / ${typeUri}`,
    );
  }

  if (subject.payloadDigest !== undefined) {
    let recomputed: string;
    try {
      recomputed = await payloadDigestOf(payload);
    } catch (e) {
      return new SummaryRefusal("payloadDigestMismatch", `payload cannot be digested: ${e}`);
    }
    if (recomputed !== subject.payloadDigest) {
      return new SummaryRefusal(
        "payloadDigestMismatch",
        `payload digests to ${recomputed}, the action says ${subject.payloadDigest}`,
      );
    }
  }

  const fields = summary.fields && typeof summary.fields === "object" ? summary.fields : {};
  const rendered: RenderedField[] = [];
  const inline: Record<string, string> = {};
  for (const [name, field] of Object.entries(fields)) {
    if (!field || typeof field.pointer !== "string") {
      return new SummaryRefusal("badFormat", `field ${name} has no pointer`);
    }
    const derived = resolvePointer(payload, field.pointer);
    if (derived === INVALID_POINTER) {
      return new SummaryRefusal("badFormat", `field ${name}: invalid pointer ${field.pointer}`);
    }
    if (!deepEqual(derived, field.value ?? null)) {
      return new SummaryRefusal(
        "fieldMismatch",
        `field ${name}: payload has ${JSON.stringify(derived)}, summary says ${JSON.stringify(field.value)}`,
      );
    }
    const text = formatValue(field.format, derived, "full");
    const short = formatValue(field.format, derived, "inline");
    if (text === null || short === null) {
      return new SummaryRefusal("badFormat", `field ${name}: not a ${field.format}`);
    }
    rendered.push({ name, format: field.format, text });
    inline[name] = short;
  }

  const title = fill(summary.title, inline);
  if (title === null) {
    return new SummaryRefusal("unknownPlaceholder", `title names a field it has not got`);
  }
  let effect: string | undefined;
  if (typeof summary.effect === "string") {
    const filled = fill(summary.effect, inline);
    if (filled === null) {
      return new SummaryRefusal("unknownPlaceholder", `effect names a field it has not got`);
    }
    effect = filled;
  }
  return VerifiedSummary.create(title, effect, rendered);
}

/** Replace each `{name}` with `values[name]`; `null` when one is unknown. */
function fill(template: string, values: Record<string, string>): string | null {
  let unknown = false;
  const out = template.replace(/\{([A-Za-z0-9_]+)\}/g, (_, name: string) => {
    if (!Object.prototype.hasOwnProperty.call(values, name)) {
      unknown = true;
      return "";
    }
    return values[name] as string;
  });
  return unknown ? null : out;
}

const INVALID_POINTER = Symbol("invalid-pointer");

/**
 * The value `pointer` (RFC 6901) names in `doc`, `null` when there is none —
 * an absent member and an explicit `null` read alike, as the VTC renders them.
 */
export function resolvePointer(doc: unknown, pointer: string): unknown {
  if (pointer === "") return doc ?? null;
  if (!pointer.startsWith("/")) return INVALID_POINTER;
  let at: unknown = doc;
  for (const raw of pointer.slice(1).split("/")) {
    const token = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(at)) {
      if (!/^(0|[1-9][0-9]*)$/.test(token)) return null;
      at = at[Number(token)];
    } else if (at !== null && typeof at === "object") {
      at = Object.prototype.hasOwnProperty.call(at, token)
        ? (at as Record<string, unknown>)[token]
        : undefined;
    } else {
      return null;
    }
    if (at === undefined) return null;
  }
  return at ?? null;
}

/** Structural equality over JSON values. */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    const bb = b as unknown[];
    return a.length === bb.length && a.every((v, i) => deepEqual(v, bb[i]));
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const ak = Object.keys(ao);
  if (ak.length !== Object.keys(bo).length) return false;
  return ak.every((k) => Object.prototype.hasOwnProperty.call(bo, k) && deepEqual(ao[k], bo[k]));
}

// ── Formats ─────────────────────────────────────────────────────────

/** Shown for an absent value. */
export const ABSENT = "—";

/** A DID longer than this is shown by both ends in a sentence. */
const LONG_DID = 40;

/**
 * A DID for a sentence: whole, or — when long — its first 16 and last 12
 * characters. Never just a prefix: two DIDs that share a method and an SCID
 * prefix differ at the end.
 */
export function formatDidInline(did: string): string {
  if (did.length <= LONG_DID) return did;
  return `${did.slice(0, 16)}…${did.slice(-12)}`;
}

/**
 * `value` as `format` text, or `null` when it is not of that format. `full`
 * is for the field list (a DID in full), `inline` for the title and effect.
 */
export function formatValue(
  format: FieldFormat,
  value: unknown,
  mode: "full" | "inline" = "full",
): string | null {
  if (value === null || value === undefined) return ABSENT;
  switch (format) {
    case "did":
      if (typeof value !== "string") return null;
      return mode === "inline" ? formatDidInline(value) : value;
    case "capabilityList":
      if (!Array.isArray(value)) return null;
      if (value.length === 0) return "none";
      if (!value.every((v) => typeof v === "string")) return null;
      return value.join(", ");
    case "datetime": {
      if (typeof value !== "string") return null;
      const t = Date.parse(value);
      return Number.isNaN(t) ? value : new Date(t).toLocaleString();
    }
    case "duration":
      if (typeof value !== "string" && typeof value !== "number") return null;
      return String(value);
    case "text":
      if (typeof value === "string") return value;
      if (typeof value === "number" || typeof value === "boolean") return String(value);
      return JSON.stringify(value);
    default:
      return null;
  }
}

// ── Digests ─────────────────────────────────────────────────────────

/** The sha2-256 multihash prefix: code 0x12, length 0x20. */
const SHA256_MULTIHASH = [0x12, 0x20] as const;

async function sha256Bytes(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

/** `z` + base58btc(0x12 0x20 || digest). */
function multibaseSha256(digest: Uint8Array): string {
  const mh = new Uint8Array(2 + digest.length);
  mh.set(SHA256_MULTIHASH, 0);
  mh.set(digest, 2);
  return `z${base58btcEncode(mh)}`;
}

/** An action's `payloadDigest`: multibase sha2-256 multihash of JCS(payload). */
export async function payloadDigestOf(payload: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(jcsCanonicalize(payload));
  return multibaseSha256(await sha256Bytes(bytes));
}

/** The 32-byte digest inside a multibase sha2-256 multihash, or `null`. */
export function digestBytesOf(multibase: string): Uint8Array | null {
  if (typeof multibase !== "string" || !multibase.startsWith("z")) return null;
  let bytes: Uint8Array;
  try {
    bytes = base58btcDecode(multibase.slice(1));
  } catch {
    return null;
  }
  if (bytes.length !== 34 || bytes[0] !== 0x12 || bytes[1] !== 0x20) return null;
  return bytes.slice(2);
}

/**
 * The **match code**: the first 6 lowercase hex characters of the digest in
 * `payloadDigest`. Shown on every card ("Code: abc123") and by `cnm`, so the
 * requester and each approver can say aloud that they are looking at the same
 * bytes. `null` when the digest is not a sha2-256 multihash.
 */
export function matchCode(payloadDigest: string): string | null {
  const d = digestBytesOf(payloadDigest);
  if (!d) return null;
  return Array.from(d.slice(0, 3), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The domain tag the decision's wire digest starts with. */
const WIRE_DIGEST_TAG = "vta/task-consent/v1\0";

function u64be(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}

/**
 * The `payloadDigest` a `task-consent/decision` carries — the **wire** digest,
 * salted with the decision's challenge so an approval answers one request
 * only:
 *
 * `z` base58btc multihash(sha2-256(
 *   "vta/task-consent/v1\0" || u64be(len typeUri) || typeUri ||
 *   u64be(len JCS(payload)) || JCS(payload) || challenge))`
 *
 * Lengths are UTF-8 byte lengths.
 */
export async function wireDigest(
  typeUri: string,
  payload: unknown,
  challenge: string,
): Promise<string> {
  const enc = new TextEncoder();
  const uri = enc.encode(typeUri);
  const body = enc.encode(jcsCanonicalize(payload));
  const parts = [
    enc.encode(WIRE_DIGEST_TAG),
    u64be(uri.length),
    uri,
    u64be(body.length),
    body,
    enc.encode(challenge),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return multibaseSha256(await sha256Bytes(buf));
}
