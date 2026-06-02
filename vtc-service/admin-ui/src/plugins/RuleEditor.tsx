// Visual rule editor — author a ceremony's decision policy as ordered
// route cards (when → then), compile to Rego live, and save it as a
// new policy revision. The deferred "Rule IR" authoring layer, wired
// to the running daemon.

import { useMemo, useState } from "react";

import {
  type Condition,
  type Effect,
  type RuleIR,
  type Route,
  compileToRego,
  conditionsFor,
  effectsFor,
} from "@/lib/rule-ir";

function condId(c: Condition): string {
  return typeof c === "string" ? c : (Object.keys(c)[0] ?? "");
}
function condArg(c: Condition): string | undefined {
  return typeof c === "string" ? undefined : Object.values(c)[0];
}

export function RuleEditor({
  purpose,
  pkg,
  initial,
  onSave,
  onCancel,
  saving,
}: {
  purpose: string;
  pkg: string;
  initial: RuleIR;
  onSave: (rego: string) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const [ir, setIr] = useState<RuleIR>(initial);
  const vocab = useMemo(() => conditionsFor(purpose), [purpose]);
  const effects = useMemo(() => effectsFor(purpose), [purpose]);
  const rego = useMemo(() => compileToRego(ir, pkg), [ir, pkg]);

  const setRoutes = (routes: Route[]) => setIr({ ...ir, routes });
  const patchRoute = (i: number, patch: Partial<Route>) =>
    setRoutes(ir.routes.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  const move = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= ir.routes.length) return;
    const next = [...ir.routes];
    const a = next[i]!;
    next[i] = next[j]!;
    next[j] = a;
    setRoutes(next);
  };

  return (
    <div className="rule-editor">
      <div className="rule-cards">
        {ir.routes.map((route, i) => (
          <RouteCard
            key={i}
            route={route}
            index={i}
            count={ir.routes.length}
            vocab={vocab}
            effects={effects}
            onChange={(patch) => patchRoute(i, patch)}
            onMove={(dir) => move(i, dir)}
            onRemove={() =>
              setRoutes(ir.routes.filter((_, j) => j !== i))
            }
          />
        ))}
        <button
          type="button"
          className="rule-add-route"
          onClick={() =>
            setRoutes([
              ...ir.routes,
              {
                name: "New route",
                when: { all: ["always"] },
                then: { effect: "refer", with: { queue: "moderator" } },
              },
            ])
          }
        >
          + Add route
        </button>
        <p className="cer-sub" style={{ fontSize: "var(--text-xs)" }}>
          Routes are first-match, top to bottom. A structural{" "}
          <code>deny</code> is always appended as the backstop.
        </p>
      </div>

      <div className="rule-preview">
        <div className="cer-panel-title">
          Compiled Rego <span className="ln" />
        </div>
        <pre className="cer-policy" style={{ maxHeight: 360 }}>
          {rego}
        </pre>
        <div className="rule-actions">
          <button
            type="button"
            className="cer-run"
            disabled={saving}
            onClick={() => onSave(rego)}
          >
            {saving ? "Saving…" : "Save as new revision ▸"}
          </button>
          <button
            type="button"
            className="rule-cancel"
            onClick={onCancel}
            disabled={saving}
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

function RouteCard({
  route,
  index,
  count,
  vocab,
  effects,
  onChange,
  onMove,
  onRemove,
}: {
  route: Route;
  index: number;
  count: number;
  vocab: ReturnType<typeof conditionsFor>;
  effects: ReturnType<typeof effectsFor>;
  onChange: (patch: Partial<Route>) => void;
  onMove: (dir: -1 | 1) => void;
  onRemove: () => void;
}) {
  const [pendingCond, setPendingCond] = useState(vocab[0]?.id ?? "always");
  const [pendingArg, setPendingArg] = useState("");
  const pendingDef = vocab.find((v) => v.id === pendingCond);

  const eff = effects.find((e) => e.effect === route.then.effect) ?? effects[0]!;
  const effField = eff.field;
  const effValue = effField
    ? formatWithValue(route.then.with[effField.key])
    : "";

  const addCond = () => {
    if (!pendingDef) return;
    const cond: Condition = pendingDef.arg
      ? { [pendingDef.id]: pendingArg }
      : pendingDef.id;
    onChange({ when: { all: [...route.when.all, cond] } });
    setPendingArg("");
  };
  const removeCond = (i: number) =>
    onChange({ when: { all: route.when.all.filter((_, j) => j !== i) } });

  const setEffect = (effect: Effect["effect"]) => {
    const field = effects.find((e) => e.effect === effect)?.field;
    onChange({ then: { effect, with: field ? { [field.key]: "" } : {} } });
  };
  const setEffValue = (raw: string) => {
    if (!effField) return;
    const value =
      effField.key === "fields" || effField.key === "needs"
        ? raw.split(",").map((s) => s.trim()).filter(Boolean)
        : raw;
    onChange({ then: { effect: route.then.effect, with: { [effField.key]: value } } });
  };

  return (
    <div className={`rule-card eff-${route.then.effect}`}>
      <div className="rule-card-head">
        <span className="rule-pri">{index + 1}</span>
        <input
          className="rule-name"
          value={route.name}
          onChange={(e) => onChange({ name: e.target.value })}
        />
        <div className="rule-tools">
          <button
            type="button"
            disabled={index === 0}
            onClick={() => onMove(-1)}
            title="Move up"
          >
            ↑
          </button>
          <button
            type="button"
            disabled={index === count - 1}
            onClick={() => onMove(1)}
            title="Move down"
          >
            ↓
          </button>
          <button type="button" onClick={onRemove} title="Remove route">
            ×
          </button>
        </div>
      </div>

      <div className="rule-when">
        <span className="rule-kw">when all of</span>
        {route.when.all.map((c, i) => {
          const def = vocab.find((v) => v.id === condId(c));
          const arg = condArg(c);
          return (
            <span className="rule-cond" key={i}>
              {def?.label ?? condId(c)}
              {arg ? <b> {arg}</b> : null}
              <span className="rule-x" onClick={() => removeCond(i)}>
                ×
              </span>
            </span>
          );
        })}
      </div>

      <div className="rule-add-cond">
        <select
          value={pendingCond}
          onChange={(e) => setPendingCond(e.target.value)}
        >
          {vocab.map((v) => (
            <option key={v.id} value={v.id}>
              {v.label}
            </option>
          ))}
        </select>
        {pendingDef?.arg && (
          <input
            className="rule-arg"
            placeholder={pendingDef.arg.placeholder}
            value={pendingArg}
            onChange={(e) => setPendingArg(e.target.value)}
          />
        )}
        <button type="button" onClick={addCond}>
          + condition
        </button>
      </div>

      <div className="rule-then">
        <span className="rule-kw">then</span>
        <select
          value={route.then.effect}
          onChange={(e) => setEffect(e.target.value as Effect["effect"])}
        >
          {effects.map((e) => (
            <option key={e.effect} value={e.effect}>
              {e.label}
            </option>
          ))}
        </select>
        {effField && (
          <input
            className="rule-arg"
            placeholder={effField.placeholder}
            value={effValue}
            onChange={(e) => setEffValue(e.target.value)}
          />
        )}
      </div>
    </div>
  );
}

function formatWithValue(v: unknown): string {
  if (Array.isArray(v)) return v.join(",");
  if (typeof v === "string") return v;
  return "";
}
