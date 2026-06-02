// Rule IR + compiler — visual ceremony authoring.
//
// A decision policy is authored as a constrained JSON AST (the Rule
// IR): an ordered list of routes, each `when` (a conjunction of
// vocabulary conditions) → `then` (a four-valued effect). The compiler
// emits Rego (the `decision` else-chain + the structural default +
// the helper rules used). Rego becomes a compiled artifact; operators
// author the IR. Canonical spec: docs/05-design-notes/
// vtc-ceremony-rule-ir.md.
//
// Round-trip: the compiled Rego carries the IR as a `# @vtc-rule-ir:`
// comment header (base64 JSON) so a policy authored here can be loaded
// back into the editor. A policy without that header was hand-written
// and isn't visually editable.

export type Condition = string | Record<string, string>;

export interface Effect {
  effect: "allow" | "deny" | "refer" | "request_more";
  with: Record<string, unknown>;
}

export interface Route {
  name: string;
  when: { all: Condition[] };
  then: Effect;
}

export interface RuleIR {
  purpose: string;
  routes: Route[];
}

// ---------------------------------------------------------------------------
// Condition vocabulary (per the rule-ir spec §2). Each condition
// compiles to a Rego body expression; helper-backed ones also pull in
// a named helper rule.
// ---------------------------------------------------------------------------

/** The verified-Facts shape the local condition evaluator reads — a
 * permissive view of the daemon's `input` document. */
export interface ExplainFacts {
  actor?: { did?: string; role?: string; authenticated?: boolean };
  subject?: { did?: string };
  state?: { subject_member?: { role?: string } | null };
  evidence?: {
    invitation?: { verified?: boolean; consumed?: boolean };
    presentation?: {
      credentials?: Array<{
        type?: string;
        issuer_trusted?: boolean;
        status?: string;
      }>;
    };
    request?: {
      agreements?: Record<string, boolean>;
      disposition?: string;
      target_role?: string;
      step_up?: boolean;
    };
  };
}

const creds = (f: ExplainFacts) => f.evidence?.presentation?.credentials ?? [];

export interface ConditionDef {
  id: string;
  label: string;
  /** Argument spec, when the condition is parametrized. */
  arg?: { label: string; placeholder: string };
  /** Rego body expression for a (possibly arg'd) use. */
  expr: (arg?: string) => string;
  /** Helper-rule id pulled in when this condition is used. */
  helper?: string;
  /** Local mirror of `expr` for the decision trace — evaluates the
   * condition against the facts client-side. Kept in lock-step with
   * `expr` (both describe the same predicate). */
  test: (facts: ExplainFacts, arg?: string) => boolean;
}

const HELPERS: Record<string, string> = {
  cred_held:
    'cred_held(t) if {\n\tsome c in input.evidence.presentation.credentials\n\tc.type == t\n\tc.status == "valid"\n}',
  cred_trusted:
    'cred_trusted(t) if {\n\tsome c in input.evidence.presentation.credentials\n\tc.type == t\n\tc.issuer_trusted\n\tc.status == "valid"\n}',
  has_valid_invitation:
    "has_valid_invitation if {\n\tinput.evidence.invitation.verified\n\tnot input.evidence.invitation.consumed\n}",
  agreed:
    "agreed(tag) if {\n\tinput.evidence.request.agreements[tag] == true\n}",
  target_role: "target_role := input.evidence.request.target_role",
};

const SHARED: ConditionDef[] = [
  { id: "always", label: "always", expr: () => "true", test: () => true },
  {
    id: "actor_is_admin",
    label: "actor is admin",
    expr: () => 'input.actor.role == "admin"',
    test: (f) => f.actor?.role === "admin",
  },
  {
    id: "actor_is_self",
    label: "actor is the subject",
    expr: () => "input.actor.did == input.subject.did",
    test: (f) => !!f.actor?.did && f.actor.did === f.subject?.did,
  },
  {
    id: "subject_is_admin",
    label: "subject is admin",
    expr: () => 'input.state.subject_member.role == "admin"',
    test: (f) => f.state?.subject_member?.role === "admin",
  },
];

const JOIN: ConditionDef[] = [
  {
    id: "has_valid_invitation",
    label: "holds a valid invitation",
    expr: () => "has_valid_invitation",
    helper: "has_valid_invitation",
    test: (f) =>
      f.evidence?.invitation?.verified === true &&
      f.evidence?.invitation?.consumed !== true,
  },
  {
    id: "holds_trusted",
    label: "holds a trusted credential",
    arg: { label: "credential type", placeholder: "WitnessCredential" },
    expr: (a) => `cred_trusted(${JSON.stringify(a ?? "")})`,
    helper: "cred_trusted",
    test: (f, a) =>
      creds(f).some(
        (c) => c.type === a && c.issuer_trusted === true && c.status === "valid",
      ),
  },
  {
    id: "holds",
    label: "holds a credential",
    arg: { label: "credential type", placeholder: "EmailCredential" },
    expr: (a) => `cred_held(${JSON.stringify(a ?? "")})`,
    helper: "cred_held",
    test: (f, a) =>
      creds(f).some((c) => c.type === a && c.status === "valid"),
  },
  {
    id: "agreed",
    label: "agreed to",
    arg: { label: "agreement tag", placeholder: "code-of-conduct" },
    expr: (a) => `agreed(${JSON.stringify(a ?? "")})`,
    helper: "agreed",
    test: (f, a) => f.evidence?.request?.agreements?.[a ?? ""] === true,
  },
];

const LEAVE: ConditionDef[] = [
  {
    id: "disposition_requested",
    label: "a disposition was requested",
    expr: () => "input.evidence.request.disposition",
    test: (f) => !!f.evidence?.request?.disposition,
  },
];

const DIRECTORY: ConditionDef[] = [
  {
    id: "viewer_is_admin",
    label: "viewer is admin",
    expr: () => 'input.actor.role == "admin"',
    test: (f) => f.actor?.role === "admin",
  },
  {
    id: "viewer_is_member",
    label: "viewer is authenticated",
    expr: () => "input.actor.authenticated == true",
    test: (f) => f.actor?.authenticated === true,
  },
];

const ROLE_CHANGE: ConditionDef[] = [
  {
    id: "target_role_standard",
    label: "target role is not admin",
    expr: () => 'input.evidence.request.target_role != "admin"',
    test: (f) => f.evidence?.request?.target_role !== "admin",
  },
  {
    id: "promotes_to_admin",
    label: "promotes to admin",
    expr: () => 'input.evidence.request.target_role == "admin"',
    test: (f) => f.evidence?.request?.target_role === "admin",
  },
  {
    id: "step_up_done",
    label: "step-up verified",
    expr: () => "input.evidence.request.step_up == true",
    test: (f) => f.evidence?.request?.step_up === true,
  },
];

/// Conditions available when authoring a given policy purpose.
export function conditionsFor(purpose: string): ConditionDef[] {
  const byPurpose: Record<string, ConditionDef[]> = {
    join: JOIN,
    removal: LEAVE,
    directory: DIRECTORY,
    roleChange: ROLE_CHANGE,
  };
  return [...SHARED, ...(byPurpose[purpose] ?? [])];
}

/// The effects an operator can choose, and the `with` field each
/// carries (so the editor shows the right input).
export interface EffectDef {
  effect: Effect["effect"];
  label: string;
  /** The primary `with` field this effect carries, if any. */
  field?: { key: string; label: string; placeholder: string };
}

export function effectsFor(purpose: string): EffectDef[] {
  const allowField: EffectDef["field"] =
    purpose === "removal"
      ? { key: "disposition", label: "disposition", placeholder: "tombstone" }
      : purpose === "directory"
        ? { key: "fields", label: "fields (comma-sep)", placeholder: "did,role" }
        : { key: "role", label: "role", placeholder: "member" };
  return [
    { effect: "allow", label: "Allow", field: allowField },
    {
      effect: "deny",
      label: "Deny",
      field: { key: "code", label: "code", placeholder: "denied" },
    },
    {
      effect: "refer",
      label: "Refer",
      field: { key: "queue", label: "queue", placeholder: "moderator" },
    },
    {
      effect: "request_more",
      label: "Request more",
      field: { key: "needs", label: "needs (comma-sep)", placeholder: "agreed:code-of-conduct" },
    },
  ];
}

// ---------------------------------------------------------------------------
// Compile IR → Rego
// ---------------------------------------------------------------------------

const IR_HEADER = "# @vtc-rule-ir:";

function regoCondition(cond: Condition, purpose: string): string | null {
  const defs = conditionsFor(purpose);
  if (typeof cond === "string") {
    const d = defs.find((x) => x.id === cond);
    return d ? d.expr() : null;
  }
  const [id, arg] = Object.entries(cond)[0] ?? [];
  const d = defs.find((x) => x.id === id);
  return d ? d.expr(arg) : null;
}

/** The `then` decision object as Rego — `$target` resolves to the
 * `target_role` helper variable (unquoted). */
function regoThen(then: Effect): string {
  const json = JSON.stringify(then);
  return json.replace(/"\$target"/g, "target_role");
}

/** Compile a Rule IR to a Rego decision module. `pkg` is the full
 * package (e.g. `vtc.removal`); the IR is embedded for round-trip. */
export function compileToRego(ir: RuleIR, pkg: string): string {
  const usedHelpers = new Set<string>();
  const defs = conditionsFor(ir.purpose);

  const noteHelper = (cond: Condition) => {
    const id = typeof cond === "string" ? cond : Object.keys(cond)[0];
    const d = defs.find((x) => x.id === id);
    if (d?.helper) usedHelpers.add(d.helper);
  };

  const lines: string[] = [];
  lines.push(`package ${pkg}`, "", "import rego.v1", "");

  const irB64 =
    typeof btoa === "function"
      ? btoa(unescape(encodeURIComponent(JSON.stringify(ir))))
      : JSON.stringify(ir);
  lines.push(`${IR_HEADER} ${irB64}`, "");

  lines.push(
    "# structural totality — compiler-appended, operator cannot remove",
    'default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}',
    "",
  );

  ir.routes.forEach((route, i) => {
    const body = route.when.all
      .map((c) => {
        noteHelper(c);
        return `\t${regoCondition(c, ir.purpose) ?? "true"}`;
      })
      .join("\n");
    const head = i === 0 ? "decision :=" : "else :=";
    if (route.name) lines.push(`# ${route.name}`);
    lines.push(`${head} ${regoThen(route.then)} if {`, body, "}", "");
  });

  // `$target` pulls in the target_role helper.
  if (ir.routes.some((r) => JSON.stringify(r.then).includes("$target"))) {
    usedHelpers.add("target_role");
  }

  if (usedHelpers.size > 0) {
    lines.push("# ---- helpers ----");
    for (const h of usedHelpers) {
      if (HELPERS[h]) lines.push(HELPERS[h]!, "");
    }
  }

  return lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd() + "\n";
}

/** Recover the IR embedded in a compiled policy's `@vtc-rule-ir`
 * header, or null when the policy wasn't authored visually. */
export function parseRego(rego: string): RuleIR | null {
  const line = rego
    .split("\n")
    .find((l) => l.startsWith(IR_HEADER));
  if (!line) return null;
  const payload = line.slice(IR_HEADER.length).trim();
  try {
    const json =
      typeof atob === "function"
        ? decodeURIComponent(escape(atob(payload)))
        : payload;
    return JSON.parse(json) as RuleIR;
  } catch {
    return null;
  }
}

/** A fresh single-route IR (catch-all refer/deny) to start authoring. */
export function blankIR(purpose: string): RuleIR {
  const fallback: Effect =
    purpose === "directory"
      ? { effect: "deny", with: { code: "not-a-member" } }
      : { effect: "refer", with: { queue: "moderator" } };
  return {
    purpose,
    routes: [{ name: "Catch-all", when: { all: ["always"] }, then: fallback }],
  };
}

// ---------------------------------------------------------------------------
// Plain-English rendering — turn an IR into a readable summary so an
// operator who doesn't read Rego can confirm what the policy does.
// ---------------------------------------------------------------------------

export function condId(c: Condition): string {
  return typeof c === "string" ? c : (Object.keys(c)[0] ?? "");
}
export function condArg(c: Condition): string | undefined {
  return typeof c === "string" ? undefined : Object.values(c)[0];
}
function isCatchAll(when: { all: Condition[] }): boolean {
  return (
    when.all.length === 0 ||
    (when.all.length === 1 && condId(when.all[0] as Condition) === "always")
  );
}

/** A human phrase for a single condition, e.g. "holds a trusted
 * credential WitnessCredential". */
export function conditionToEnglish(cond: Condition, purpose: string): string {
  const defs = conditionsFor(purpose);
  const id = condId(cond);
  const arg = condArg(cond);
  const label = defs.find((x) => x.id === id)?.label ?? id;
  return arg ? `${label} ${arg}` : label;
}

/** A human phrase for an effect, e.g. "admit as member" / "refer to the
 * moderator queue". */
export function effectToEnglish(effect: Effect): string {
  const w = effect.with ?? {};
  switch (effect.effect) {
    case "allow":
      if (typeof w.role === "string") return `admit — set role to ${w.role}`;
      if (typeof w.disposition === "string")
        return `allow — remove (${w.disposition})`;
      if (Array.isArray(w.fields))
        return `allow — share ${(w.fields as unknown[]).join(", ")}`;
      return "allow";
    case "deny":
      return typeof w.code === "string" ? `deny (${w.code})` : "deny";
    case "refer":
      return typeof w.queue === "string"
        ? `refer to the ${w.queue} queue`
        : "refer for review";
    case "request_more":
      return Array.isArray(w.needs) && (w.needs as unknown[]).length
        ? `ask for ${(w.needs as unknown[]).join(", ")}`
        : "ask for more evidence";
  }
}

export interface EnglishLine {
  name: string;
  effect: Effect["effect"];
  /** A full sentence describing the route. */
  text: string;
  isCatchAll: boolean;
}

// ---------------------------------------------------------------------------
// Semantic diff — compare two IR revisions at the route level, so a
// version bump reads as "what changed" rather than a Rego text diff.
// ---------------------------------------------------------------------------

function condKey(c: Condition): string {
  const a = condArg(c);
  return a ? `${condId(c)}:${a}` : condId(c);
}

export interface RouteDiff {
  name: string;
  status: "added" | "removed" | "changed" | "unchanged";
  /** Human change lines, e.g. "when: + agreed to code-of-conduct". */
  changes: string[];
}

/** Route-level diff of two IR revisions (prev → next), matched by name. */
export function diffIR(prev: RuleIR, next: RuleIR): RouteDiff[] {
  const prevByName = new Map(prev.routes.map((r) => [r.name, r]));
  const nextByName = new Map(next.routes.map((r) => [r.name, r]));
  const order: string[] = [];
  for (const r of next.routes) order.push(r.name);
  for (const r of prev.routes) if (!nextByName.has(r.name)) order.push(r.name);

  const seen = new Set<string>();
  const diffs: RouteDiff[] = [];
  for (const name of order) {
    if (seen.has(name)) continue;
    seen.add(name);
    const a = prevByName.get(name);
    const b = nextByName.get(name);
    if (a && !b) {
      diffs.push({ name, status: "removed", changes: [] });
      continue;
    }
    if (!a && b) {
      diffs.push({ name, status: "added", changes: [] });
      continue;
    }
    if (!a || !b) continue;
    const changes: string[] = [];
    const ak = new Set(a.when.all.map(condKey));
    const bk = new Set(b.when.all.map(condKey));
    for (const c of b.when.all)
      if (!ak.has(condKey(c)))
        changes.push(`when: + ${conditionToEnglish(c, next.purpose)}`);
    for (const c of a.when.all)
      if (!bk.has(condKey(c)))
        changes.push(`when: − ${conditionToEnglish(c, prev.purpose)}`);
    if (JSON.stringify(a.then) !== JSON.stringify(b.then))
      changes.push(
        `then: ${effectToEnglish(a.then)} → ${effectToEnglish(b.then)}`,
      );
    diffs.push({
      name,
      status: changes.length ? "changed" : "unchanged",
      changes,
    });
  }
  return diffs;
}

/** Render an IR as ordered plain-English lines (first-match framing). */
export function irToEnglish(ir: RuleIR): EnglishLine[] {
  return ir.routes.map((route, i) => {
    const catchAll = isCatchAll(route.when);
    const lead = i === 0 ? "If" : "else if";
    const when = route.when.all
      .map((c) => conditionToEnglish(c, ir.purpose))
      .join(" and ");
    const then = effectToEnglish(route.then);
    const text = catchAll
      ? `Otherwise, ${then}.`
      : `${lead} ${when}, then ${then}.`;
    return {
      name: route.name,
      effect: route.then.effect,
      text,
      isCatchAll: catchAll,
    };
  });
}

// ---------------------------------------------------------------------------
// Decision trace — evaluate the routes against a facts document locally
// (mirroring the compiled Rego) to explain which route fired and why.
// Only meaningful for IR-authored policies, where the local `test`
// predicates are the same logic the Rego compiles from.
// ---------------------------------------------------------------------------

export interface ConditionTrace {
  label: string;
  passed: boolean;
}
export interface RouteTrace {
  name: string;
  effect: Effect["effect"];
  conditions: ConditionTrace[];
  /** All conditions held. */
  matched: boolean;
  /** The first matching route — the one whose effect the verdict takes. */
  fired: boolean;
  /** First-match short-circuits: routes after the fired one aren't run. */
  reached: boolean;
  isCatchAll: boolean;
}
export interface DecisionTrace {
  routes: RouteTrace[];
  fired: RouteTrace | null;
}

/** Evaluate an IR against a facts document, first-match, and report the
 * per-route / per-condition outcome. */
export function explainDecision(
  ir: RuleIR,
  facts: ExplainFacts,
): DecisionTrace {
  const defs = conditionsFor(ir.purpose);
  let firedIdx = -1;
  const routes: RouteTrace[] = ir.routes.map((route, i) => {
    const conditions = route.when.all.map((c) => {
      const def = defs.find((x) => x.id === condId(c));
      const passed = def ? def.test(facts, condArg(c)) : false;
      return { label: conditionToEnglish(c, ir.purpose), passed };
    });
    const matched = conditions.every((c) => c.passed);
    if (matched && firedIdx === -1) firedIdx = i;
    return {
      name: route.name,
      effect: route.then.effect,
      conditions,
      matched,
      fired: false,
      reached: true,
      isCatchAll: isCatchAll(route.when),
    };
  });
  routes.forEach((r, i) => {
    r.fired = i === firedIdx;
    r.reached = firedIdx === -1 || i <= firedIdx;
  });
  return { routes, fired: firedIdx >= 0 ? (routes[firedIdx] ?? null) : null };
}
