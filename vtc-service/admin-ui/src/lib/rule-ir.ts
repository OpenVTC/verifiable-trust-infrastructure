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

export interface ConditionDef {
  id: string;
  label: string;
  /** Argument spec, when the condition is parametrized. */
  arg?: { label: string; placeholder: string };
  /** Rego body expression for a (possibly arg'd) use. */
  expr: (arg?: string) => string;
  /** Helper-rule id pulled in when this condition is used. */
  helper?: string;
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
  { id: "always", label: "always", expr: () => "true" },
  {
    id: "actor_is_admin",
    label: "actor is admin",
    expr: () => 'input.actor.role == "admin"',
  },
  {
    id: "actor_is_self",
    label: "actor is the subject",
    expr: () => "input.actor.did == input.subject.did",
  },
  {
    id: "subject_is_admin",
    label: "subject is admin",
    expr: () => 'input.state.subject_member.role == "admin"',
  },
];

const JOIN: ConditionDef[] = [
  {
    id: "has_valid_invitation",
    label: "holds a valid invitation",
    expr: () => "has_valid_invitation",
    helper: "has_valid_invitation",
  },
  {
    id: "holds_trusted",
    label: "holds a trusted credential",
    arg: { label: "credential type", placeholder: "WitnessCredential" },
    expr: (a) => `cred_trusted(${JSON.stringify(a ?? "")})`,
    helper: "cred_trusted",
  },
  {
    id: "holds",
    label: "holds a credential",
    arg: { label: "credential type", placeholder: "EmailCredential" },
    expr: (a) => `cred_held(${JSON.stringify(a ?? "")})`,
    helper: "cred_held",
  },
  {
    id: "agreed",
    label: "agreed to",
    arg: { label: "agreement tag", placeholder: "code-of-conduct" },
    expr: (a) => `agreed(${JSON.stringify(a ?? "")})`,
    helper: "agreed",
  },
];

const LEAVE: ConditionDef[] = [
  {
    id: "disposition_requested",
    label: "a disposition was requested",
    expr: () => "input.evidence.request.disposition",
  },
];

const DIRECTORY: ConditionDef[] = [
  {
    id: "viewer_is_admin",
    label: "viewer is admin",
    expr: () => 'input.actor.role == "admin"',
  },
  {
    id: "viewer_is_member",
    label: "viewer is authenticated",
    expr: () => "input.actor.authenticated == true",
  },
];

const ROLE_CHANGE: ConditionDef[] = [
  {
    id: "target_role_standard",
    label: "target role is not admin",
    expr: () => 'input.evidence.request.target_role != "admin"',
  },
  {
    id: "promotes_to_admin",
    label: "promotes to admin",
    expr: () => 'input.evidence.request.target_role == "admin"',
  },
  {
    id: "step_up_done",
    label: "step-up verified",
    expr: () => "input.evidence.request.step_up == true",
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
