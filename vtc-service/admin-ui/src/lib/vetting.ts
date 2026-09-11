// Peer identity vetting, in the words an admin deciding a join request needs.
//
// The daemon records vetting in its own vocabulary: failure codes
// (`issuer-not-vetter`), needs in the `vetting:*` grammar
// (`vetting:method:inPerson:1`), method and relationship tokens. This module
// turns each into a sentence and keeps the code beside it, so a panel says
// what happened while an admin who needs the exact value — to search the audit
// trail, or to write a policy — can still find it.
//
// It also mirrors the checks the daemon runs on what the console sends, so a
// form can say what is wrong before a request is refused. The shapes are the
// published specifications' (`wire-types.ts`); the daemon checks each against
// its schema, plus the rules a schema cannot state
// (`vta_sdk::protocols::vetting::CheckShape`):
//
//   - `validateRequirements` is the `VettingRequirements` definition of
//     `vtc/join-requests/manifest/0.2`, plus its rule that every `minByMethod`
//     method is accepted.
//   - `validateBranding` is that manifest's `CommunityBranding` definition.
//   - `buildListBody` is `vtc/vetting/vetters/list/0.1`'s payload, plus its
//     rule that `eventTo` is not before `eventFrom`.
//   - the grant and sweep bounds are `MIN_/MAX_VETTER_GRANT_VALIDITY_SECONDS`
//     (the grant schema's own) and `MIN_/MAX_AUTO_GRANT_SWEEP_MINUTES`.
//
// The daemon stays the authority: it runs every one of these again, and makes
// the one check this module cannot — that a `statementType` is a registered
// endorsement type.

import type {
  CommunityBranding,
  JoinRequestVetting,
  JoinRequestVettingStatement,
  VetterGrantRow,
  VetterListBody,
  VettingMethod,
  VettingRelationship,
  VettingRequirements,
  VettingRevocationRow,
} from "@/lib/wire-types";

export type { VettingRequirements };

// ── Methods and relationships ───────────────────────────────────────────

export const VETTING_METHODS: readonly VettingMethod[] = [
  "inPerson",
  "video",
  "priorAcquaintance",
];

const METHOD_LABELS: Record<VettingMethod, string> = {
  inPerson: "In person",
  video: "Video call",
  priorAcquaintance: "Prior acquaintance",
};

/** How a statement was made, as it reads after "made …". */
const METHOD_PHRASES: Record<VettingMethod, string> = {
  inPerson: "in person",
  video: "over video",
  priorAcquaintance: "by a vetter who already knew the applicant",
};

export function isVettingMethod(value: unknown): value is VettingMethod {
  return (
    typeof value === "string" &&
    (VETTING_METHODS as readonly string[]).includes(value)
  );
}

/** A method's name; an unknown token is shown as it came. */
export function methodLabel(method: string): string {
  return isVettingMethod(method) ? METHOD_LABELS[method] : method;
}

/** A vetter's declared relationship to the applicant. */
export type DeclaredRelationship = VettingRelationship;

export const DECLARED_RELATIONSHIPS: readonly DeclaredRelationship[] = [
  "none",
  "communityColleague",
  "sameEmployer",
  "family",
  "otherPersonal",
];

const RELATIONSHIP_LABELS: Record<DeclaredRelationship, string> = {
  none: "No prior relationship",
  communityColleague: "Community colleague",
  sameEmployer: "Same employer",
  family: "Family member",
  otherPersonal: "Other personal relationship",
};

function isRelationship(value: string): value is DeclaredRelationship {
  return (DECLARED_RELATIONSHIPS as readonly string[]).includes(value);
}

export function relationshipLabel(value: string | null | undefined): string {
  if (!value) return "Not declared";
  return isRelationship(value) ? RELATIONSHIP_LABELS[value] : value;
}

// ── Statement outcomes ──────────────────────────────────────────────────

/** A sentence for the admin, and the daemon's own code for it. */
export interface Explained {
  text: string;
  code: string;
}

const FAILURE_TEXT: Record<string, string> = {
  unverified: "Its proof, type, validity dates or contents did not verify.",
  "subject-not-applicant":
    "It vouches for someone other than the applicant who presented it.",
  "wrong-statement-type": "It is not the kind of statement this criterion counts.",
  "issuer-not-vetter":
    "Its signer was not an eligible vetter: a current member holding an unrevoked vetter grant from before they signed.",
  revoked: "Its vetter withdrew it before the decision.",
  "wrong-community": "It was made for a different community.",
  "method-not-accepted": "This criterion does not accept the vetting method it records.",
  "documentation-not-accepted":
    "The documents its vetter checked are not ones this criterion accepts.",
  "claim-not-verified":
    "Its vetter did not verify every claim this criterion requires.",
  "too-old": "It is older than this criterion allows.",
  "same-vetter":
    "Its vetter has a more recent statement here, and each vetter counts once.",
};

export function explainFailure(code: string): Explained {
  return {
    code,
    text:
      FAILURE_TEXT[code] ??
      "It did not count, for a reason this console does not recognise.",
  };
}

export type Tone = "ok" | "warn" | "bad";

export interface StatementVerdict {
  tone: Tone;
  label: string;
  reasons: Explained[];
}

const WITHDRAWN_SINCE: Explained = {
  code: "withdrawnNow",
  text: "Its vetter has withdrawn it since the decision.",
};

/** Whether one presented statement counted, and every reason it did not. */
export function statementVerdict(
  statement: JoinRequestVettingStatement,
): StatementVerdict {
  if (statement.counted) {
    return statement.withdrawnNow
      ? {
          tone: "warn",
          label: "Counted, since withdrawn",
          reasons: [
            {
              ...WITHDRAWN_SINCE,
              text: `${WITHDRAWN_SINCE.text} An admission it helped grant may need review.`,
            },
          ],
        }
      : { tone: "ok", label: "Counted", reasons: [] };
  }
  // The daemon lists every reason; the flags are a fallback for facts recorded
  // with none, so a statement never reads "not counted" without a why.
  const codes = statement.failures.length
    ? statement.failures
    : [
        ...(statement.verified ? [] : ["unverified"]),
        ...(statement.eligible ? [] : ["issuer-not-vetter"]),
        ...(statement.revoked ? ["revoked"] : []),
      ];
  const reasons = codes.map(explainFailure);
  if (statement.withdrawnNow && !statement.revoked) reasons.push(WITHDRAWN_SINCE);
  return { tone: "bad", label: "Not counted", reasons };
}

// ── What is still needed ────────────────────────────────────────────────

const plural = (n: number, one: string, many = `${one}s`) =>
  `${n} ${n === 1 ? one : many}`;

/** One entry of a verdict's `needs`, in plain words. */
export function explainNeed(raw: string): Explained {
  const statements = /^vetting:statements:(\d+)$/.exec(raw);
  if (statements) {
    const n = Number(statements[1]);
    return {
      code: raw,
      text: `Statements from ${plural(n, "more eligible vetter")}.`,
    };
  }
  const method = /^vetting:method:([A-Za-z]+):(\d+)$/.exec(raw);
  if (method && isVettingMethod(method[1])) {
    const n = Number(method[2]);
    return {
      code: raw,
      text: `${plural(n, "more counted statement")} made ${METHOD_PHRASES[method[1]]}.`,
    };
  }
  if (raw === "vetting:invitation") {
    return {
      code: raw,
      text: "An invitation. The vetting is met, and this criterion also requires an invitation credential.",
    };
  }
  if (raw === "vetting") {
    return { code: raw, text: "More vetting, without a stated amount." };
  }
  return { code: raw, text: raw };
}

export interface FactsHeadline {
  tone: Tone;
  title: string;
  detail: string;
}

/**
 * The one line an admin reads first, in the order the default join policy
 * weighs the facts: different identities, then a shortfall, then an
 * independence cap, then an outstanding invitation.
 */
export function factsHeadline(facts: JoinRequestVetting): FactsHeadline {
  if (facts.satisfied) {
    return {
      tone: "ok",
      title: "Vetting requirements met",
      detail: `${plural(facts.distinctCountedVetters, "distinct vetter")} counted, the vetters agree on who the applicant is, and the independence rules hold.`,
    };
  }
  if (!facts.commitmentsConsistent) {
    return {
      tone: "bad",
      title: "Vetters verified different identities",
      detail:
        "The counted statements do not describe the same person. Find out why before admitting this applicant.",
    };
  }
  if (facts.needs.length > 0) {
    return {
      tone: "warn",
      title: "Vetting is incomplete",
      detail: "The applicant has not yet gathered enough counted statements.",
    };
  }
  if (!facts.independenceOk) {
    return {
      tone: "warn",
      title: "Too many vetters share a relationship with the applicant",
      detail:
        "There are enough statements, but more of them declare the same relationship than this criterion allows.",
    };
  }
  return {
    tone: "warn",
    title: "Vetting requirements not met",
    detail: facts.invitationRequired
      ? "This criterion also requires an invitation credential."
      : "The recorded facts do not satisfy the criterion.",
  };
}

// ── Durations ───────────────────────────────────────────────────────────

type Units = ReadonlyArray<readonly [string, number]>;

function accumulate(
  part: string,
  units: Units,
): { seconds: number; any: boolean } | null {
  let seconds = 0;
  let digits = "";
  let next = 0;
  let any = false;
  for (const c of part) {
    if (c >= "0" && c <= "9") {
      digits += c;
      continue;
    }
    // Each unit at most once, and only after the ones before it.
    const offset = units.slice(next).findIndex(([unit]) => unit === c);
    if (offset === -1 || digits === "") return null;
    seconds += Number(digits) * units[next + offset]![1];
    next += offset + 1;
    digits = "";
    any = true;
  }
  return digits === "" ? { seconds, any } : null;
}

/**
 * Seconds in an ISO 8601 duration, or `null` for one the daemon refuses.
 * `parse_iso8601_duration`: weeks and days, then a `T` part with hours,
 * minutes and seconds. Years and months are refused — their length depends on
 * the calendar.
 */
export function parseIsoDuration(value: string): number | null {
  if (!value.startsWith("P")) return null;
  const rest = value.slice(1);
  const t = rest.indexOf("T");
  const date = accumulate(t === -1 ? rest : rest.slice(0, t), [
    ["W", 604_800],
    ["D", 86_400],
  ]);
  if (!date) return null;
  let timeSeconds = 0;
  let timeAny = false;
  if (t !== -1) {
    const time = accumulate(rest.slice(t + 1), [
      ["H", 3_600],
      ["M", 60],
      ["S", 1],
    ]);
    if (!time || !time.any) return null;
    timeSeconds = time.seconds;
    timeAny = true;
  }
  if (!date.any && !timeAny) return null;
  const total = date.seconds + timeSeconds;
  return Number.isSafeInteger(total) ? total : null;
}

/** `10368000` → `120 days`; `129600` → `1 day 12 hours`. */
export function describeSeconds(total: number): string {
  const days = Math.floor(total / 86_400);
  const hours = Math.floor((total % 86_400) / 3_600);
  const minutes = Math.floor((total % 3_600) / 60);
  const seconds = total % 60;
  const parts = [
    days ? plural(days, "day") : "",
    hours ? plural(hours, "hour") : "",
    minutes ? plural(minutes, "minute") : "",
    seconds ? plural(seconds, "second") : "",
  ].filter(Boolean);
  return parts.length ? parts.join(" ") : "0 seconds";
}

// ── Vetting requirements (manifest 0.2) ─────────────────────────────────
//
// `VettingRequirements` is the manifest specification's own definition,
// aliased in `wire-types.ts`. `validateRequirements` still takes `unknown`: it
// reports on a criterion stored before a rule existed, which need not match.

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const chars = (s: string) => [...s].length;
const isCount = (v: unknown): v is number =>
  typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 4_294_967_295;
const isStringArray = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((s) => typeof s === "string");

const ROLE = /^[a-zA-Z][a-zA-Z0-9_-]*$/;
const TOKEN = /^[a-z][a-zA-Z0-9]*$/;

const DURATION_NAMES = {
  maxStatementAge: "The maximum statement age",
  decisionSla: "The decision deadline",
  requirementsGrace: "The requirements grace period",
} as const;

/**
 * Every problem with a `vetting` requirements object, as sentences an admin can
 * act on; empty when the daemon would accept it (bar the endorsement-type
 * registration only the daemon can check).
 */
export function validateRequirements(value: unknown): string[] {
  if (!isObject(value)) {
    return ["The vetting requirements must be an object."];
  }
  const problems: string[] = [];
  const v = value;

  if (typeof v.version !== "string" || !/^[0-9]+\.[0-9]+$/.test(v.version)) {
    problems.push(
      `Set version to MAJOR.MINOR, like "0.1"${
        typeof v.version === "string" ? `; "${v.version}" is not` : ""
      }.`,
    );
  }

  if (
    typeof v.statementType !== "string" ||
    v.statementType === "" ||
    chars(v.statementType) > 512
  ) {
    problems.push(
      "Set statementType to the endorsement type a counted statement carries, up to 512 characters.",
    );
  }

  if (!isCount(v.minStatements) || v.minStatements === 0) {
    problems.push(
      v.minStatements === 0
        ? "Require at least 1 statement. A criterion that needs no vetting should have no vetting requirements."
        : "Set minStatements to a whole number of at least 1.",
    );
  }

  const accepted: VettingMethod[] = [];
  if (!Array.isArray(v.acceptedMethods) || v.acceptedMethods.length === 0) {
    problems.push("Accept at least one vetting method.");
  } else {
    for (const m of v.acceptedMethods) {
      if (isVettingMethod(m)) accepted.push(m);
      else problems.push(unknownMethod(m));
    }
  }

  if (v.minByMethod !== undefined) {
    if (!isObject(v.minByMethod)) {
      problems.push("minByMethod must map a method to a minimum count.");
    } else {
      for (const [method, n] of Object.entries(v.minByMethod)) {
        if (!isVettingMethod(method)) {
          problems.push(unknownMethod(method));
        } else if (accepted.length > 0 && !accepted.includes(method)) {
          // With no usable method list the problem is already named above;
          // repeating it once per floor would bury it.
          problems.push(
            `A minimum is set for ${METHOD_LABELS[method].toLowerCase()} statements, which this criterion does not accept. Accept the method, or remove its minimum.`,
          );
        }
        if (!isCount(n)) {
          problems.push(`The minimum for ${method} must be a whole number.`);
        }
      }
    }
  }

  const role = isObject(v.eligibleVetters) ? v.eligibleVetters.role : undefined;
  if (typeof role !== "string" || !ROLE.test(role) || role.length > 128) {
    problems.push(
      "Set eligibleVetters.role to the role a vetter holds, like \"vetter\": a letter, then letters, digits, _ or -, up to 128 characters.",
    );
  }

  if (v.acceptedDocumentClasses !== undefined) {
    const classes = v.acceptedDocumentClasses;
    if (
      !isStringArray(classes) ||
      classes.some((c) => !TOKEN.test(c) || c.length > 64)
    ) {
      problems.push(
        "Write each accepted document class as a lowerCamelCase token, like passport or nationalId, up to 64 characters.",
      );
    }
  }

  for (const member of ["requiredClaims", "optionalClaims"] as const) {
    if (v[member] !== undefined && !isStringArray(v[member])) {
      problems.push(`${member} must be a list of claim types.`);
    }
  }

  if (v.governanceFrameworkUrl !== undefined) {
    const url = v.governanceFrameworkUrl;
    if (
      typeof url !== "string" ||
      !url.startsWith("https://") ||
      chars(url) > 2048
    ) {
      problems.push(
        "The governance framework address must be an https:// URL of at most 2048 characters.",
      );
    }
  }

  for (const [member, name] of Object.entries(DURATION_NAMES)) {
    const d = v[member];
    if (d === undefined) continue;
    if (typeof d !== "string" || d.length > 32 || parseIsoDuration(d) === null) {
      problems.push(
        `${name}${typeof d === "string" ? ` "${d}"` : ""} is not a duration the community can apply. Use weeks, days, hours, minutes or seconds, like P120D; months and years vary in length.`,
      );
    }
  }

  if (v.independence !== undefined) {
    const ind = v.independence;
    if (!isObject(ind)) {
      problems.push("independence must be an object.");
    } else {
      const caps = ind.maxByDeclaredRelationship;
      if (caps !== undefined) {
        if (!isObject(caps)) {
          problems.push(
            "maxByDeclaredRelationship must map a relationship to a maximum count.",
          );
        } else {
          for (const [rel, n] of Object.entries(caps)) {
            if (!isRelationship(rel)) {
              problems.push(
                `"${rel}" is not a declared relationship. Use ${DECLARED_RELATIONSHIPS.join(", ")}.`,
              );
            }
            if (!isCount(n)) {
              problems.push(`The cap for ${rel} must be a whole number.`);
            }
          }
        }
      }
      const consistent = ind.requireConsistentIdentityCommitment;
      if (consistent !== undefined && typeof consistent !== "boolean") {
        problems.push("requireConsistentIdentityCommitment must be true or false.");
      }
    }
  }

  if (
    v.invitation !== undefined &&
    !["required", "optional", "none"].includes(v.invitation as string)
  ) {
    problems.push('Set invitation to "required", "optional" or "none".');
  }

  return problems;
}

function unknownMethod(method: unknown): string {
  return `${JSON.stringify(method)} is not a vetting method. Use inPerson, video or priorAcquaintance.`;
}

/** Valid requirements, in sentences, in the order an applicant meets them. */
export function summarizeRequirements(r: VettingRequirements): string[] {
  const lines = [
    `Statements from at least ${plural(r.minStatements, "distinct eligible vetter")}.`,
  ];
  for (const method of VETTING_METHODS) {
    const n = r.minByMethod?.[method];
    if (n) lines.push(`At least ${n} of them made ${METHOD_PHRASES[method]}.`);
  }
  lines.push(
    `Methods that count: ${r.acceptedMethods.map(methodLabel).join(", ")}.`,
  );
  lines.push(`Vetters hold the "${r.eligibleVetters.role}" role.`);
  if (r.requiredClaims?.length) {
    lines.push(`Each vetter verifies: ${r.requiredClaims.join(", ")}.`);
  }
  lines.push(
    r.acceptedDocumentClasses
      ? `Vetters may rely only on: ${r.acceptedDocumentClasses.join(", ") || "no documents"}.`
      : "Each vetter decides which documents they accept.",
  );
  const age = r.maxStatementAge ? parseIsoDuration(r.maxStatementAge) : null;
  if (age !== null) {
    lines.push(`A statement counts for ${describeSeconds(age)} after it is made.`);
  }
  for (const rel of DECLARED_RELATIONSHIPS) {
    const cap = r.independence?.maxByDeclaredRelationship?.[rel];
    if (cap === undefined) continue;
    lines.push(
      cap === 0
        ? `No counted statements from vetters declaring "${RELATIONSHIP_LABELS[rel]}".`
        : `At most ${plural(cap, "counted statement")} from vetters declaring "${RELATIONSHIP_LABELS[rel]}".`,
    );
  }
  if (r.independence?.requireConsistentIdentityCommitment) {
    lines.push("Every vetter must have verified the same identity.");
  }
  if (r.invitation === "required") {
    lines.push("An invitation credential is required as well.");
  } else if (r.invitation === "optional") {
    lines.push("An invitation credential may be presented.");
  }
  const sla = r.decisionSla ? parseIsoDuration(r.decisionSla) : null;
  if (sla !== null) {
    lines.push(
      `A referred application is decided within ${describeSeconds(sla)}.`,
    );
  }
  const grace = r.requirementsGrace ? parseIsoDuration(r.requirementsGrace) : null;
  if (grace !== null) {
    lines.push(
      `Applications started under earlier requirements keep them for ${describeSeconds(grace)} (not yet applied by this community).`,
    );
  }
  return lines;
}

// ── Vetter grants ───────────────────────────────────────────────────────

export const DAY_SECONDS = 86_400;
/** `MIN_VETTER_GRANT_VALIDITY_SECONDS`, in days. */
export const MIN_GRANT_VALIDITY_DAYS = 1;
/** `MAX_VETTER_GRANT_VALIDITY_SECONDS` (two 365-day years), in days. */
export const MAX_GRANT_VALIDITY_DAYS = 730;
/** `MIN_/MAX_AUTO_GRANT_SWEEP_MINUTES`. */
export const MIN_SWEEP_MINUTES = 5;
export const MAX_SWEEP_MINUTES = 1440;

/** An integer field's problem, or null. */
function wholeNumberError(
  raw: string,
  min: number,
  max: number,
  what: string,
  range: string,
): string | null {
  const trimmed = raw.trim();
  if (trimmed === "") return `Enter ${what}, from ${range}.`;
  const n = Number(trimmed);
  if (!Number.isInteger(n)) return `Enter a whole number of ${what}, from ${range}.`;
  if (n < min || n > max) return `Choose ${range}; ${n} is outside that.`;
  return null;
}

export function validityDaysError(raw: string): string | null {
  return wholeNumberError(
    raw,
    MIN_GRANT_VALIDITY_DAYS,
    MAX_GRANT_VALIDITY_DAYS,
    "days",
    "1 to 730 days (two years)",
  );
}

export function sweepMinutesError(raw: string): string | null {
  return wholeNumberError(
    raw,
    MIN_SWEEP_MINUTES,
    MAX_SWEEP_MINUTES,
    "minutes",
    "5 to 1440 minutes (a day)",
  );
}

export type GrantState = "live" | "revoked" | "expired" | "inactive";

export const GRANT_STATE_LABELS: Record<GrantState, string> = {
  live: "Live",
  revoked: "Revoked",
  expired: "Expired",
  inactive: "Not in force",
};

/** Why a grant is or is not in force. `live` is the daemon's own verdict. */
export function grantState(row: VetterGrantRow, now = Date.now()): GrantState {
  if (row.live) return "live";
  if (row.revoked) return "revoked";
  if (row.validUntil && Date.parse(row.validUntil) <= now) return "expired";
  // Unrevoked and unexpired, yet not live: its holder is not a current member.
  return "inactive";
}

export interface GrantFilter {
  state: GrantState | "all";
  origin: "auto" | "manual" | "all";
  search: string;
}

export function filterGrants(
  rows: readonly VetterGrantRow[],
  filter: GrantFilter,
  now = Date.now(),
): VetterGrantRow[] {
  const needle = filter.search.trim().toLowerCase();
  return rows.filter(
    (row) =>
      (filter.state === "all" || grantState(row, now) === filter.state) &&
      (filter.origin === "all" || row.origin === filter.origin) &&
      (!needle ||
        row.memberDid.toLowerCase().includes(needle) ||
        (row.profile?.displayName ?? "").toLowerCase().includes(needle)),
  );
}

// ── Withdrawals ─────────────────────────────────────────────────────────

const REASON_LABELS: Record<string, string> = {
  mistake: "The vetter made a mistake",
  newInformation: "The vetter learned something new",
  keyCompromise: "The vetter's signing key was compromised",
  other: "Another reason",
};

export function withdrawalReason(row: VettingRevocationRow): string {
  if (!row.reason) return "No reason given";
  return REASON_LABELS[row.reason] ?? row.reason;
}

// ── Registry listing filters ────────────────────────────────────────────

export interface ListDraft {
  language: string;
  country: string;
  region: string;
  city: string;
  method: VettingMethod | "";
  eventFrom: string;
  eventTo: string;
  eventName: string;
}

export const EMPTY_LIST_DRAFT: ListDraft = {
  language: "",
  country: "",
  region: "",
  city: "",
  method: "",
  eventFrom: "",
  eventTo: "",
  eventName: "",
};

export type ListDraftErrors = Partial<Record<keyof ListDraft, string>>;

/** `shape::language_tag`: `^[A-Za-z]{2,3}(-[A-Za-z0-9]{1,8})*$`, ≤ 35. */
export function isLanguageTag(tag: string): boolean {
  return tag.length <= 35 && /^[A-Za-z]{2,3}(-[A-Za-z0-9]{1,8})*$/.test(tag);
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;

/** The listing request for a filter form, and what is wrong with it. */
export function buildListBody(draft: ListDraft): {
  body: VetterListBody;
  errors: ListDraftErrors;
} {
  const body: VetterListBody = {};
  const errors: ListDraftErrors = {};

  const language = draft.language.trim();
  if (language) {
    if (isLanguageTag(language)) body.language = language;
    else errors.language = "Enter a language tag, like de or de-AT.";
  }
  // The listing compares countries in upper case; typing `at` means `AT`.
  const country = draft.country.trim().toUpperCase();
  if (country) {
    if (/^[A-Z]{2}$/.test(country)) body.country = country;
    else errors.country = "Enter a two-letter country code, like AT.";
  }
  for (const key of ["region", "city"] as const) {
    const value = draft[key].trim();
    if (!value) continue;
    if (chars(value) > 128) {
      errors[key] = `Shorten this to 128 characters or fewer.`;
    } else {
      body[key] = value;
    }
  }
  if (draft.method) body.method = draft.method;
  for (const key of ["eventFrom", "eventTo"] as const) {
    const value = draft[key];
    if (!value) continue;
    if (DATE.test(value)) body[key] = value;
    else errors[key] = "Enter a date as YYYY-MM-DD.";
  }
  if (body.eventFrom && body.eventTo && body.eventTo < body.eventFrom) {
    errors.eventTo = "The end of the range is before its start. Change one of the dates.";
  }
  const eventName = draft.eventName.trim();
  if (eventName) {
    if (chars(eventName) > 200) {
      errors.eventName = "Shorten the event name to 200 characters or fewer.";
    } else {
      body.eventName = eventName;
    }
  }
  return { body, errors };
}

// ── Community branding ──────────────────────────────────────────────────

export interface BrandingDraft {
  displayName: string;
  accentColor: string;
  logoUrl: string;
}

export type BrandingErrors = Partial<Record<keyof BrandingDraft, string>>;

export const HEX_COLOR = /^#[0-9a-fA-F]{6}$/;

export function brandingDraft(branding: CommunityBranding): BrandingDraft {
  return {
    displayName: branding.displayName ?? "",
    accentColor: branding.accentColor ?? "",
    logoUrl: branding.logoUrl ?? "",
  };
}

export function validateBranding(draft: BrandingDraft): BrandingErrors {
  const errors: BrandingErrors = {};
  const name = draft.displayName.trim();
  if (chars(name) > 128) {
    errors.displayName = `The display name is ${chars(name)} characters. Shorten it to 128 or fewer.`;
  }
  const color = draft.accentColor.trim();
  if (color && !HEX_COLOR.test(color)) {
    errors.accentColor = "Enter the colour as # and six hex digits, like #1a7f6e.";
  }
  const url = draft.logoUrl.trim();
  if (url) {
    if (!url.startsWith("https://")) {
      errors.logoUrl =
        "Use an https:// address. Clients refuse to fetch a logo over plain http.";
    } else if (url.length <= "https://".length) {
      errors.logoUrl = "Add the rest of the address after https://.";
    } else if (/[\s\u0000-\u001f\u007f-\u009f]/.test(url)) {
      errors.logoUrl = "Remove the spaces from the logo address.";
    } else if (chars(url) > 2048) {
      errors.logoUrl = `The address is ${chars(url)} characters. Use one of 2048 or fewer.`;
    }
  }
  return errors;
}

/**
 * The `PUT /v1/community/branding` body for a draft. The PUT replaces the whole
 * branding, so an `ext` the console does not edit is carried over rather than
 * dropped; an empty member is left out, which clears it.
 */
export function brandingBody(
  draft: BrandingDraft,
  current?: CommunityBranding,
): CommunityBranding {
  const body: CommunityBranding = {};
  const name = draft.displayName.trim();
  const color = draft.accentColor.trim();
  const url = draft.logoUrl.trim();
  if (name) body.displayName = name;
  if (color) body.accentColor = color.toLowerCase();
  if (url) body.logoUrl = url;
  if (current?.ext != null) body.ext = current.ext;
  return body;
}
