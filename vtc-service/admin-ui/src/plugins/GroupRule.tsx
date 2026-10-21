// A dynamic group's rule (`DynamicRule`, `vtc/groups/_shared/0.1`): every
// condition must hold, each over a verified fact — the community role, an
// administrator- or credential-sourced directory field, personhood, the join
// date. A member-written field is never offered: a rule that read one would let
// a member join by editing their card, and the community refuses it.

import { useQuery } from "@tanstack/react-query";
import { Plus, X } from "lucide-react";

import { listFields } from "@/lib/directory";

export type Fact = "role" | "field" | "personhood" | "joinedAt";
export type Op = "equals" | "oneOf" | "exists" | "before" | "after";

export interface RuleCondition {
  fact: Fact;
  field?: string;
  op: Op;
  value?: string | boolean;
  values?: string[];
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
};

/** A condition reset to its fact's first operation. */
function fresh(fact: Fact): RuleCondition {
  const op = OPS[fact][0]?.id ?? "exists";
  return { fact, op, ...(op === "exists" ? {} : op === "oneOf" ? { values: [] } : { value: "" }) };
}

export const emptyRule = (): DynamicRule => ({ all: [fresh("role")] });

/** Whether every condition is complete enough to send. */
export function ruleReady(rule: DynamicRule): boolean {
  return (
    rule.all.length > 0 &&
    rule.all.every((c) => {
      if (c.fact === "field" && !c.field) return false;
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
      ...(c.op !== "oneOf" && c.op !== "exists" ? { value: c.value } : {}),
    })),
  };
}

export function RuleEditor({
  value,
  onChange,
}: {
  value: DynamicRule;
  onChange: (rule: DynamicRule) => void;
}) {
  const fields = useQuery({ queryKey: ["directory", "fields"], queryFn: () => listFields() });
  // Only what the community vouches for (create item 2).
  const verified = (fields.data?.fields ?? []).filter((f) => {
    const source = (f as { source?: string }).source;
    return source === "admin" || source === "credential";
  });
  const set = (i: number, c: RuleCondition) =>
    onChange({ all: value.all.map((x, j) => (j === i ? c : x)) });
  return (
    <fieldset className="stack">
      <legend>Members are everyone who…</legend>
      {value.all.map((c, i) => (
        <div className="inline-form" key={i}>
          {i > 0 && <span className="muted">and</span>}
          <select
            aria-label="Fact"
            value={c.fact}
            onChange={(e) => set(i, fresh(e.target.value as Fact))}
          >
            {FACTS.map((f) => (
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
              className="icon-btn"
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
          className="secondary"
          onClick={() => onChange({ all: [...value.all, fresh("role")] })}
        >
          <Plus size={14} aria-hidden="true" /> And…
        </button>
      )}
    </fieldset>
  );
}
