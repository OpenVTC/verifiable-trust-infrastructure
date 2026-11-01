// The election manifest builder's model (`plugins/ElectionBuilder.tsx`).
//
// A manifest (`vtc/elections/create/0.3`, voting/_shared/0.2 `Manifest`) says
// what an election asks and how it is decided, and every ticket and cast is
// bound to its digest — so nothing about it can be corrected after the ballot
// box registers it. The builder edits a **draft** (strings where the inputs
// hold strings, so a half-typed number is not lost) and renders the manifest
// from it; `manifestToDraft` reads a manifest back, so the form and the JSON
// view are two views of one value.
//
// `checkDraft` holds the rules an administrator would otherwise learn from an
// `invalidManifest` refusal: the schema's own bounds (`MANIFEST_LIMITS`,
// pinned to the vendored bundle by `election-manifest.test.ts`) and the
// cross-field rules `vti_voting::rules::check_manifest` applies. The schema is
// not evaluated here — the console's CSP (`script-src 'self'`) rules out a
// compiling validator — and none of this is authority: the community checks
// the manifest again on create, and the ballot box at registration.

import { base58btcEncode, jcsCanonicalize, sha256 } from "./jcs";

export type QuestionType = "choice" | "ranking" | "score" | "text";
export type RollRule = "members" | "membersAndListed" | "listed";
export type Secrecy = "open" | "sealed" | "talliedEncrypted";
export type BoardVisibility = "public" | "private";
export type Revote = "replace" | "refuse";

/** The builder's steps, in order. */
export const STEPS = [
  { id: "about", label: "About" },
  { id: "questions", label: "Questions" },
  { id: "voters", label: "Who votes" },
  { id: "schedule", label: "Schedule" },
  { id: "counting", label: "Counting" },
  { id: "review", label: "Review" },
] as const;
export type StepId = (typeof STEPS)[number]["id"];

/** The schema's bounds the builder enforces (vtc/elections/create/0.3). */
export const MANIFEST_LIMITS = {
  electionIdPattern: "^[A-Za-z0-9._-]{1,128}$",
  keyPattern: "^[A-Za-z0-9._-]{1,64}$",
  titleMax: 512,
  descriptionMax: 8192,
  didMax: 2048,
  questionsMin: 1,
  questionsMax: 128,
  questionTextMax: 2048,
  optionLabelMax: 512,
  choiceOptions: { min: 2, max: 256 },
  rankingOptions: { min: 2, max: 64 },
  scoreOptions: { min: 1, max: 256 },
  textMaxLength: { min: 1, max: 4096 },
  textReleaseThresholdMin: 10,
  trusteesMin: 2,
  thresholdMin: 2,
} as const;

/** `vti_voting::rules::MAX_TRUSTEES`: a rule, not a schema bound. */
export const MAX_TRUSTEES = 64;

const ELECTION_ID = new RegExp(MANIFEST_LIMITS.electionIdPattern);
const KEY = new RegExp(MANIFEST_LIMITS.keyPattern);

export interface OptionDraft {
  key: string;
  label: string;
  /** The key follows the label until the administrator edits it. */
  autoKey: boolean;
}

export interface QuestionDraft {
  /** React's key, never sent. */
  uid: string;
  key: string;
  type: QuestionType;
  text: string;
  optional: boolean;
  options: OptionDraft[];
  minSelections: string;
  maxSelections: string;
  partial: boolean;
  min: string;
  max: string;
  maxLength: string;
}

export interface ManifestDraft {
  electionId: string;
  /** The identifier follows the title until the administrator edits it. */
  autoId: boolean;
  title: string;
  description: string;
  binding: boolean;
  questions: QuestionDraft[];
  roll: RollRule;
  /** DIDs, one per line. */
  listed: string;
  /** RFC 3339, UTC, as the manifest carries them. */
  registrationOpensAt: string;
  votingOpensAt: string;
  votingClosesAt: string;
  allowEarlyClose: boolean;
  ballotBox: string;
  secrecy: Secrecy;
  /** DIDs, one per line. */
  trustees: string;
  threshold: string;
  boardVisibility: BoardVisibility;
  /** DIDs, one per line. */
  auditors: string;
  revote: Revote;
  resultsBeforeClose: boolean;
  textReleaseThreshold: string;
}

let uidSeq = 0;
function uid(): string {
  uidSeq += 1;
  return `q${uidSeq}-${Math.random().toString(36).slice(2, 8)}`;
}

/** A key in the manifest's alphabet, from a label. */
export function slugKey(label: string, max = 64): string {
  return label
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, max)
    .replace(/-+$/, "");
}

/** RFC 3339 in UTC, to the second, as the sample and the CLI write it. */
export function isoUtc(t: number | Date): string {
  return new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function option(label: string, key?: string): OptionDraft {
  return { key: key ?? slugKey(label), label, autoKey: key === undefined };
}

/** The option sets the question editor offers to start from. */
export const OPTION_PRESETS: Record<string, () => OptionDraft[]> = {
  "Yes / No": () => [option("Yes"), option("No")],
  "Yes / No / Abstain": () => [option("Yes"), option("No"), option("Abstain")],
  "For / Against": () => [option("For"), option("Against")],
};

export function newQuestion(index: number, type: QuestionType = "choice"): QuestionDraft {
  return {
    uid: uid(),
    key: `q${index + 1}`,
    type,
    text: "",
    optional: true,
    options: type === "text" ? [] : OPTION_PRESETS["Yes / No"]!(),
    minSelections: "1",
    maxSelections: "1",
    partial: false,
    min: "0",
    max: "5",
    maxLength: "500",
  };
}

/** A question changed to another type: what the new type needs, the rest kept. */
export function retypeQuestion(q: QuestionDraft, type: QuestionType): QuestionDraft {
  const options =
    type === "text"
      ? q.options
      : q.options.length > 0
        ? q.options
        : OPTION_PRESETS["Yes / No"]!();
  return { ...q, type, options };
}

/** A new draft: one yes/no question, tickets from now, voting for a week from tomorrow. */
export function emptyDraft(now = new Date()): ManifestDraft {
  const hour = 3600 * 1000;
  const startOfHour = Math.ceil(now.getTime() / hour) * hour;
  const opens = startOfHour + 24 * hour;
  return {
    electionId: `poll-${now.toISOString().slice(0, 10)}`,
    autoId: true,
    title: "",
    description: "",
    binding: false,
    questions: [newQuestion(0)],
    roll: "members",
    listed: "",
    registrationOpensAt: isoUtc(now),
    votingOpensAt: isoUtc(opens),
    votingClosesAt: isoUtc(opens + 7 * 24 * hour),
    allowEarlyClose: false,
    ballotBox: "",
    secrecy: "open",
    trustees: "",
    threshold: "2",
    boardVisibility: "public",
    auditors: "",
    revote: "replace",
    resultsBeforeClose: false,
    textReleaseThreshold: String(MANIFEST_LIMITS.textReleaseThresholdMin),
  };
}

/** The identifier a title suggests, while the administrator has not set one. */
export function suggestElectionId(title: string, now = new Date()): string {
  return slugKey(title, 128) || `poll-${now.toISOString().slice(0, 10)}`;
}

/** DIDs from a one-per-line (or comma-separated) list. */
export function didList(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** An integer from an input, or `null` when it is not one. */
function int(s: string): number | null {
  const t = s.trim();
  if (!/^-?\d+$/.test(t)) return null;
  const n = Number(t);
  return Number.isSafeInteger(n) ? n : null;
}

function questionJson(q: QuestionDraft): Record<string, unknown> {
  const out: Record<string, unknown> = { key: q.key, type: q.type };
  if (q.text.trim()) out.text = q.text;
  if (q.type !== "text") {
    out.options = q.options.map((o) => (o.label ? { key: o.key, label: o.label } : { key: o.key }));
  }
  switch (q.type) {
    case "choice":
      out.minSelections = int(q.minSelections) ?? q.minSelections;
      out.maxSelections = int(q.maxSelections) ?? q.maxSelections;
      break;
    case "ranking":
      out.partial = q.partial;
      break;
    case "score":
      out.min = int(q.min) ?? q.min;
      out.max = int(q.max) ?? q.max;
      break;
    case "text":
      out.maxLength = int(q.maxLength) ?? q.maxLength;
      break;
  }
  out.optional = q.optional;
  return out;
}

/**
 * The manifest a draft says, for `community`. An optional member left empty is
 * omitted; a number still half-typed is carried as its text, which the checks
 * (and the community) refuse rather than guess at.
 */
export function draftToManifest(d: ManifestDraft, community: string): Record<string, unknown> {
  const m: Record<string, unknown> = { electionId: d.electionId, community };
  if (d.title.trim()) m.title = d.title;
  if (d.description.trim()) m.description = d.description;
  m.questions = d.questions.map(questionJson);
  m.secrecy = d.secrecy;
  if (d.secrecy !== "open") {
    m.trustees = { dids: didList(d.trustees), threshold: int(d.threshold) ?? d.threshold };
  }
  m.roll = d.roll === "members" ? { rule: "members" } : { rule: d.roll, listed: didList(d.listed) };
  m.registrationOpensAt = d.registrationOpensAt;
  m.votingOpensAt = d.votingOpensAt;
  m.votingClosesAt = d.votingClosesAt;
  m.revote = d.revote;
  m.board = { visibility: d.boardVisibility, auditors: didList(d.auditors) };
  m.ballotBox = d.ballotBox.trim();
  m.binding = d.binding;
  m.allowEarlyClose = d.allowEarlyClose;
  m.resultsBeforeClose = d.secrecy === "open" ? d.resultsBeforeClose : false;
  m.textReleaseThreshold = int(d.textReleaseThreshold) ?? d.textReleaseThreshold;
  return m;
}

const MANIFEST_KEYS = new Set([
  "electionId",
  "community",
  "title",
  "description",
  "questions",
  "secrecy",
  "trustees",
  "roll",
  "registrationOpensAt",
  "votingOpensAt",
  "votingClosesAt",
  "revote",
  "board",
  "ballotBox",
  "binding",
  "allowEarlyClose",
  "resultsBeforeClose",
  "textReleaseThreshold",
]);

const QUESTION_KEYS: Record<QuestionType, Set<string>> = {
  choice: new Set(["key", "type", "text", "options", "minSelections", "maxSelections", "optional"]),
  ranking: new Set(["key", "type", "text", "options", "partial", "optional"]),
  score: new Set(["key", "type", "text", "options", "min", "max", "optional"]),
  text: new Set(["key", "type", "text", "maxLength", "optional"]),
};

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown, fallback = ""): string =>
  typeof v === "string" ? v : typeof v === "number" ? String(v) : fallback;
const lines = (v: unknown): string =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").join("\n") : "";

/**
 * A manifest read back into a draft, for the form. Refused — rather than
 * silently dropped — when it carries something the form does not edit, since
 * the manifest is what gets bound to every vote. `community` is not kept: the
 * draft is always rendered for this community.
 */
export function manifestToDraft(
  value: unknown,
): { draft: ManifestDraft } | { error: string } {
  if (!isObj(value)) return { error: "The manifest is a JSON object." };
  const unknown = Object.keys(value).filter((k) => !MANIFEST_KEYS.has(k));
  if (unknown.length) {
    return { error: `The form does not edit ${unknown.map((k) => `"${k}"`).join(", ")}.` };
  }
  const base = emptyDraft();
  const questions: QuestionDraft[] = [];
  const qs = Array.isArray(value.questions) ? value.questions : [];
  for (const [i, q] of qs.entries()) {
    if (!isObj(q)) return { error: `Question ${i + 1} is not an object.` };
    const type = q.type;
    if (type !== "choice" && type !== "ranking" && type !== "score" && type !== "text") {
      return { error: `Question ${i + 1} has a type the form does not know: ${JSON.stringify(type)}.` };
    }
    const extra = Object.keys(q).filter((k) => !QUESTION_KEYS[type].has(k));
    if (extra.length) {
      return { error: `Question ${i + 1} carries ${extra.map((k) => `"${k}"`).join(", ")}, which a ${type} question does not.` };
    }
    const options: OptionDraft[] = [];
    for (const o of Array.isArray(q.options) ? q.options : []) {
      if (!isObj(o) || Object.keys(o).some((k) => k !== "key" && k !== "label")) {
        return { error: `Question ${i + 1} has an option the form cannot edit.` };
      }
      options.push({ key: str(o.key), label: str(o.label), autoKey: false });
    }
    const blank = newQuestion(i, type);
    questions.push({
      ...blank,
      key: str(q.key),
      text: str(q.text),
      optional: q.optional === true,
      options,
      minSelections: str(q.minSelections, blank.minSelections),
      maxSelections: str(q.maxSelections, blank.maxSelections),
      partial: q.partial === true,
      min: str(q.min, blank.min),
      max: str(q.max, blank.max),
      maxLength: str(q.maxLength, blank.maxLength),
    });
  }
  const roll = isObj(value.roll) ? value.roll : {};
  const rule = roll.rule === "membersAndListed" || roll.rule === "listed" ? roll.rule : "members";
  const board = isObj(value.board) ? value.board : {};
  const trustees = isObj(value.trustees) ? value.trustees : {};
  const secrecy =
    value.secrecy === "sealed" || value.secrecy === "talliedEncrypted" ? value.secrecy : "open";
  return {
    draft: {
      electionId: str(value.electionId),
      autoId: false,
      title: str(value.title),
      description: str(value.description),
      binding: value.binding === true,
      questions,
      roll: rule,
      listed: lines(roll.listed),
      registrationOpensAt: str(value.registrationOpensAt, base.registrationOpensAt),
      votingOpensAt: str(value.votingOpensAt, base.votingOpensAt),
      votingClosesAt: str(value.votingClosesAt, base.votingClosesAt),
      allowEarlyClose: value.allowEarlyClose === true,
      ballotBox: str(value.ballotBox),
      secrecy,
      trustees: lines(trustees.dids),
      threshold: str(trustees.threshold, base.threshold),
      boardVisibility: board.visibility === "private" ? "private" : "public",
      auditors: lines(board.auditors),
      revote: value.revote === "refuse" ? "refuse" : "replace",
      resultsBeforeClose: value.resultsBeforeClose === true,
      textReleaseThreshold: str(value.textReleaseThreshold, base.textReleaseThreshold),
    },
  };
}

/** A previous election's manifest as the start of a new one: a fresh
 *  identifier and schedule, everything else kept. */
export function draftFromPrevious(value: unknown, now = new Date()): { draft: ManifestDraft } | { error: string } {
  const r = manifestToDraft(value);
  if ("error" in r) return r;
  const fresh = emptyDraft(now);
  return {
    draft: {
      ...r.draft,
      electionId: suggestElectionId(r.draft.title, now),
      autoId: true,
      registrationOpensAt: fresh.registrationOpensAt,
      votingOpensAt: fresh.votingOpensAt,
      votingClosesAt: fresh.votingClosesAt,
    },
  };
}

export interface Issue {
  step: StepId;
  /** The field it is about, for placing it beside its control. */
  field: string;
  message: string;
}

function dupes(xs: string[]): string[] {
  const seen = new Set<string>();
  const out = new Set<string>();
  for (const x of xs) (seen.has(x) ? out : seen).add(x);
  return [...out];
}

function parseTime(iso: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/.test(iso)) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

/**
 * Everything wrong with a draft, in step order. Empty means the manifest
 * passes every rule the console can check; the community still checks it.
 */
export function checkDraft(d: ManifestDraft, community: string, now = Date.now()): Issue[] {
  const L = MANIFEST_LIMITS;
  const out: Issue[] = [];
  const add = (step: StepId, field: string, message: string) => out.push({ step, field, message });

  // About
  if (!ELECTION_ID.test(d.electionId)) {
    add("about", "electionId", "1 – 128 characters: letters, digits, dot, dash and underscore.");
  }
  if (d.title.length > L.titleMax) add("about", "title", `At most ${L.titleMax} characters.`);
  if (d.description.length > L.descriptionMax) {
    add("about", "description", `At most ${L.descriptionMax} characters.`);
  }

  // Questions
  if (d.questions.length < L.questionsMin) add("questions", "questions", "Ask at least one question.");
  if (d.questions.length > L.questionsMax) {
    add("questions", "questions", `At most ${L.questionsMax} questions.`);
  }
  for (const k of dupes(d.questions.map((q) => q.key))) {
    add("questions", "questions", `The question key "${k}" is used twice.`);
  }
  d.questions.forEach((q, i) => {
    const at = `questions.${i}`;
    const name = `Question ${i + 1}`;
    if (!KEY.test(q.key)) add("questions", `${at}.key`, `${name}: the key is 1 – 64 letters, digits, dots, dashes or underscores.`);
    if (q.text.length > L.questionTextMax) add("questions", `${at}.text`, `${name}: at most ${L.questionTextMax} characters.`);
    if (q.type !== "text") {
      const bounds =
        q.type === "choice" ? L.choiceOptions : q.type === "ranking" ? L.rankingOptions : L.scoreOptions;
      if (q.options.length < bounds.min || q.options.length > bounds.max) {
        add("questions", `${at}.options`, `${name}: ${bounds.min} – ${bounds.max} options.`);
      }
      q.options.forEach((o, j) => {
        if (!KEY.test(o.key)) {
          add("questions", `${at}.options.${j}`, `${name}, option ${j + 1}: the key is 1 – 64 letters, digits, dots, dashes or underscores.`);
        }
        if (o.label.length > L.optionLabelMax) {
          add("questions", `${at}.options.${j}`, `${name}, option ${j + 1}: at most ${L.optionLabelMax} characters.`);
        }
      });
      for (const k of dupes(q.options.map((o) => o.key))) {
        add("questions", `${at}.options`, `${name}: the option key "${k}" is used twice.`);
      }
    }
    if (q.type === "choice") {
      const lo = int(q.minSelections);
      const hi = int(q.maxSelections);
      if (lo === null || lo < 0) add("questions", `${at}.minSelections`, `${name}: the fewest choices is a whole number, 0 or more.`);
      if (hi === null || hi < 1) add("questions", `${at}.maxSelections`, `${name}: the most choices is a whole number, 1 or more.`);
      if (lo !== null && hi !== null && (lo > hi || hi > q.options.length)) {
        add("questions", `${at}.maxSelections`, `${name}: fewest ≤ most ≤ the number of options (${q.options.length}).`);
      }
    }
    if (q.type === "score") {
      const lo = int(q.min);
      const hi = int(q.max);
      if (lo === null) add("questions", `${at}.min`, `${name}: the lowest score is a whole number.`);
      if (hi === null) add("questions", `${at}.max`, `${name}: the highest score is a whole number.`);
      if (lo !== null && hi !== null && lo >= hi) add("questions", `${at}.max`, `${name}: the lowest score is below the highest.`);
    }
    if (q.type === "text") {
      const n = int(q.maxLength);
      if (n === null || n < L.textMaxLength.min || n > L.textMaxLength.max) {
        add("questions", `${at}.maxLength`, `${name}: an answer's length limit is ${L.textMaxLength.min} – ${L.textMaxLength.max}.`);
      }
    }
  });

  // Who votes
  const listed = didList(d.listed);
  if (d.roll !== "members") {
    if (listed.length === 0) add("voters", "listed", "Name at least one party.");
    for (const x of dupes(listed)) add("voters", "listed", `${x} is listed twice.`);
    if (listed.some((x) => x.length > L.didMax)) add("voters", "listed", `A DID is at most ${L.didMax} characters.`);
  }

  // Schedule
  const reg = parseTime(d.registrationOpensAt);
  const opens = parseTime(d.votingOpensAt);
  const closes = parseTime(d.votingClosesAt);
  if (reg === null) add("schedule", "registrationOpensAt", "Not a time.");
  if (opens === null) add("schedule", "votingOpensAt", "Not a time.");
  if (closes === null) add("schedule", "votingClosesAt", "Not a time.");
  if (reg !== null && opens !== null && reg > opens) {
    add("schedule", "votingOpensAt", "Voting opens no earlier than tickets do.");
  }
  if (opens !== null && closes !== null && opens >= closes) {
    add("schedule", "votingClosesAt", "Voting closes after it opens.");
  }
  if (closes !== null && closes <= now) add("schedule", "votingClosesAt", "This time has already passed.");

  // Counting
  const box = d.ballotBox.trim();
  if (!box) add("counting", "ballotBox", "Name the ballot box.");
  else if (box.length > L.didMax) add("counting", "ballotBox", `At most ${L.didMax} characters.`);
  const auditors = didList(d.auditors);
  for (const x of dupes(auditors)) add("counting", "auditors", `${x} is named twice.`);
  if (auditors.some((a) => a === community || (box && a === box))) {
    add("counting", "auditors", "Neither the community nor the ballot box audits its own election.");
  }
  if (d.secrecy !== "open") {
    const trustees = didList(d.trustees);
    const t = int(d.threshold);
    if (trustees.length < L.trusteesMin) add("counting", "trustees", `Name at least ${L.trusteesMin} trustees.`);
    if (trustees.length > MAX_TRUSTEES) add("counting", "trustees", `At most ${MAX_TRUSTEES} trustees.`);
    for (const x of dupes(trustees)) add("counting", "trustees", `${x} is named twice.`);
    if (trustees.some((x) => x === community || (box && x === box))) {
      add("counting", "trustees", "Neither the community nor the ballot box is a trustee.");
    }
    if (t === null || t < L.thresholdMin || t > Math.max(trustees.length, L.thresholdMin)) {
      add("counting", "threshold", `A whole number from ${L.thresholdMin} to the number of trustees.`);
    }
    if (d.secrecy === "talliedEncrypted" && d.questions.some((q) => q.type !== "choice")) {
      add("counting", "secrecy", "Totals-only elections ask choice questions only. Change the other questions, or pick another secrecy.");
    }
  }
  const trt = int(d.textReleaseThreshold);
  if (trt === null || trt < L.textReleaseThresholdMin) {
    add("counting", "textReleaseThreshold", `A whole number, ${L.textReleaseThresholdMin} or more.`);
  }
  return out;
}

/** The SHA-256 multihash of the manifest's JCS canonicalization, base58btc —
 *  `manifestDigest` as the community will compute it. */
export async function manifestDigest(manifest: unknown): Promise<string> {
  const digest = await sha256(jcsCanonicalize(manifest));
  const mh = new Uint8Array(34);
  mh.set([0x12, 0x20]);
  mh.set(digest, 2);
  return `z${base58btcEncode(mh)}`;
}

/** An RFC 3339 instant as a `datetime-local` input holds it, in this browser's zone. */
export function toLocalInput(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  const base = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  return d.getSeconds() ? `${base}:${p(d.getSeconds())}` : base;
}

/** A `datetime-local` value (this browser's zone) as the manifest's UTC instant. */
export function fromLocalInput(value: string): string {
  const t = new Date(value).getTime();
  return Number.isNaN(t) ? "" : isoUtc(t);
}

/** What the secrecy levels mean, for the counting step and the review. */
export const SECRECY_TEXT: Record<Secrecy, { label: string; detail: string }> = {
  open: {
    label: "Open",
    detail: "Each ballot is recorded on the board as cast. Unlinkable to its voter, but readable by whoever can read the board.",
  },
  sealed: {
    label: "Sealed",
    detail: "Ballots are encrypted to a key the trustees generate together, and decrypted only after voting closes.",
  },
  talliedEncrypted: {
    label: "Totals only",
    detail: "Ballots stay encrypted; only the totals are ever decrypted. Choice questions only.",
  },
};

export const ROLL_TEXT: Record<RollRule, string> = {
  members: "The community's active members",
  membersAndListed: "Active members, and the parties listed",
  listed: "Only the parties listed",
};

export const QUESTION_TYPE_TEXT: Record<QuestionType, { label: string; detail: string }> = {
  choice: { label: "Choice", detail: "Pick between a fewest and most of the options. A motion is a choice of exactly one." },
  ranking: { label: "Ranking", detail: "Put the options in order." },
  score: { label: "Score", detail: "Give each option a whole-number score in a range." },
  text: { label: "Free text", detail: "A written answer, disclosed only once enough ballots are counted." },
};
