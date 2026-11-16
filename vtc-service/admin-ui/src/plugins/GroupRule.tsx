// A dynamic group's rule (`DynamicRule`, `vtc/groups/_shared/0.1`): every
// condition must hold, each over a verified fact — the community role, an
// administrator- or credential-sourced directory field, personhood, the join
// date. A member-written field is never offered: a rule that read one would let
// a member join by editing their card, and the community refuses it. A badge's
// rule may also count the community's own records (`counts`, VTI-BDG-015):
// kudos accepted, ideas selected, elections ticketed — never another group's.

import { useQuery } from "@tanstack/react-query";
import { Plus, X } from "lucide-react";

import { listFields } from "@/lib/directory";

export type Fact =
  | "role"
  | "field"
  | "personhood"
  | "joinedAt"
  | "kudosReceived"
  | "ideasSelected"
  | "electionTickets";
export type Op = "equals" | "oneOf" | "exists" | "before" | "after" | "atLeast";

export interface RuleCondition {
  fact: Fact;
  field?: string;
  op: Op;
  value?: string | boolean;
  values?: string[];
  /** With `atLeast`: the least a count fact must be. */
  count?: number;
}

export interface DynamicRule {
  all: RuleCondition[];
}

const FACTS: { id: Fact; label: string }[] = [
  { id: "role", label: "Community role" },
  { id: "personhood", label: "Personhood on file" },
  { id: "joinedAt", label: "Joined" },
  { id: "field", label: "A verified directory field" },
];

/** The counts only a badge's rule reads (VTI-BDG-015). */
const COUNT_FACTS: { id: Fact; label: string }[] = [
  { id: "kudosReceived", label: "Kudos accepted" },
  { id: "ideasSelected", label: "Ideas a board selected" },
  { id: "electionTickets", label: "Elections taken a ticket in" },
];

const isCount = (f: Fact) => f === "kudosReceived" || f === "ideasSelected" || f === "electionTickets";

const OPS: Record<Fact, { id: Op; label: string }[]> = {
  role: [
    { id: "equals", label: "is" },
    { id: "oneOf", label: "is one of" },
  ],
  personhood: [{ id: "exists", label: "is on file" }],
  joinedAt: [
    { id: "before", label: "before" },
    { id: "after", label: "after" },
  ],
  field: [
    { id: "equals", label: "is" },
    { id: "oneOf", label: "is one of" },
    { id: "exists", label: "is set" },
    { id: "before", label: "is before" },
    { id: "after", label: "is after" },
  ],
  kudosReceived: [{ id: "atLeast", label: "at least" }],
  ideasSelected: [{ id: "atLeast", label: "at least" }],
  electionTickets: [{ id: "atLeast", label: "at least" }],
};

/** A condition reset to its fact's first operation. */
function fresh(fact: Fact): RuleCondition {
  const op = OPS[fact][0]?.id ?? "exists";
  if (op === "atLeast") return { fact, op, count: 1 };
  return { fact, op, ...(op === "exists" ? {} : op === "oneOf" ? { values: [] } : { value: "" }) };
}

export const emptyRule = (): DynamicRule => ({ all: [fresh("role")] });

/** Whether every condition is complete enough to send. */
export function ruleReady(rule: DynamicRule): boolean {
  return (
    rule.all.length > 0 &&
    rule.all.every((c) => {
      if (c.fact === "field" && !c.field) return false;
      if (c.op === "atLeast") return Number.isInteger(c.count) && (c.count ?? 0) >= 1;
      if (c.op === "exists") return true;
      if (c.op === "oneOf") return (c.values ?? []).length > 0;
      return typeof c.value === "boolean" || (c.value ?? "").toString().trim() !== "";
    })
  );
}

/** The rule as `create` and `update` take it: only what each condition's
 *  operation reads. */
export function wireRule(rule: DynamicRule): DynamicRule {
  return {
    all: rule.all.map((c) => ({
      fact: c.fact,
      ...(c.fact === "field" ? { field: c.field } : {}),
      op: c.op,
      ...(c.op === "oneOf" ? { values: c.values } : {}),
      ...(c.op === "atLeast" ? { count: c.count } : {}),
      ...(c.op !== "oneOf" && c.op !== "exists" && c.op !== "atLeast" ? { value: c.value } : {}),
    })),
  };
}

export function RuleEditor({
  value,
  onChange,
  className,
  counts = false,
}: {
  value: DynamicRule;
  onChange: (rule: DynamicRule) => void;
  className?: string;
  /** A badge's rule: offer the counts of VTI-BDG-015 too. */
  counts?: boolean;
}) {
  const facts = counts ? [...FACTS, ...COUNT_FACTS] : FACTS;
  const fields = useQuery({ queryKey: ["directory", "fields"], queryFn: () => listFields() });
  // Only what the community vouches for (create item 2).
  const verified = (fields.data?.fields ?? []).filter((f) => {
    const source = (f as { source?: string }).source;
    return source === "admin" || source === "credential";
  });
  const set = (i: number, c: RuleCondition) =>
    onChange({ all: value.all.map((x, j) => (j === i ? c : x)) });
  return (
    <fieldset className={["field", "group-rule", className].filter(Boolean).join(" ")}>
      <legend className="field-label">Members are everyone who…</legend>
      {value.all.map((c, i) => (
        <div className="group-rule-row" key={i}>
          <span className="group-rule-and" aria-hidden={i === 0}>
            {i > 0 ? "and" : ""}
          </span>
          <select
            aria-label="Fact"
            value={c.fact}
            onChange={(e) => set(i, fresh(e.target.value as Fact))}
          >
            {facts.map((f) => (
              <option key={f.id} value={f.id}>
                {f.label}
              </option>
            ))}
          </select>
          {c.fact === "field" && (
            <select
              aria-label="Field"
              value={c.field ?? ""}
              onChange={(e) => set(i, { ...c, field: e.target.value })}
            >
              <option value="">Choose a field…</option>
              {verified.map((f) => (
                <option key={f.key} value={f.key}>
                  {f.label}
                </option>
              ))}
            </select>
          )}
          <select
            aria-label="Test"
            value={c.op}
            onChange={(e) => {
              const op = e.target.value as Op;
              if (op === "atLeast") return set(i, { fact: c.fact, op, count: c.count ?? 1 });
              set(i, {
                fact: c.fact,
                ...(c.field ? { field: c.field } : {}),
                op,
                ...(op === "exists" ? {} : op === "oneOf" ? { values: [] } : { value: "" }),
              });
            }}
          >
            {OPS[c.fact].map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </select>
          {c.op === "oneOf" && (
            <input
              aria-label="Values"
              placeholder="comma-separated"
              value={(c.values ?? []).join(", ")}
              onChange={(e) =>
                set(i, {
                  ...c,
                  values: e.target.value
                    .split(",")
                    .map((v) => v.trim())
                    .filter(Boolean),
                })
              }
            />
          )}
          {c.op === "atLeast" && isCount(c.fact) && (
            <input
              aria-label="At least"
              type="number"
              min={1}
              max={100000}
              value={c.count ?? 1}
              onChange={(e) => set(i, { ...c, count: Math.max(1, Math.floor(Number(e.target.value) || 1)) })}
            />
          )}
          {(c.op === "equals" || c.op === "before" || c.op === "after") && (
            <input
              aria-label="Value"
              type={c.op === "equals" ? "text" : "date"}
              value={String(c.value ?? "")}
              onChange={(e) => set(i, { ...c, value: e.target.value })}
            />
          )}
          {value.all.length > 1 && (
            <button
              type="button"
              className="secondary sm"
              aria-label="Remove condition"
              onClick={() => onChange({ all: value.all.filter((_, j) => j !== i) })}
            >
              <X size={14} aria-hidden="true" />
            </button>
          )}
        </div>
      ))}
      {value.all.length < 16 && (
        <button
          type="button"
          className="secondary sm group-rule-add"
          onClick={() => onChange({ all: [...value.all, fresh("role")] })}
        >
          <Plus size={14} aria-hidden="true" /> And…
        </button>
      )}
    </fieldset>
  );
}
