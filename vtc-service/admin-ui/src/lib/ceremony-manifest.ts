// Ceremony manifest — the registry, now daemon-served.
//
// The daemon owns which ceremonies exist and how their decision
// surface is shaped (`GET /v1/ceremonies`). Each manifest carries the
// metadata, the simulator's input `fields` (a declarative UI schema),
// and a `factsTemplate` — a JSON skeleton of the verified-Facts `input`
// document with directives this module materializes from the field
// values. The Ceremonies surface renders entirely from this; adding a
// ceremony over an existing effect is a manifest entry on the daemon,
// not frontend code.
//
// Template directives (resolved client-side, since the dry-run builds
// the facts and POSTs them to /policies/{id}/test):
//   "$now"            → current ISO timestamp
//   "$field:<key>"    → the field value ("" / undefined ⇒ key omitted)
//   {"$if": <key>, "then": …, "else": …} → branch on the field's truthiness

import { getJson } from "@/lib/api";

export type Nature = "read-only" | "constructive" | "destructive" | "mutating";
export type Wired = "live" | "legacy" | "unwired";

/** Declarative `showWhen`: render the field only when `field`'s value
 * equals `eq`, or its truthiness matches `truthy`. */
export interface ShowWhenSpec {
  field: string;
  eq?: unknown;
  truthy?: boolean;
}

/** A single simulator input. `select` shows a dropdown; `toggle` a switch. */
export interface FieldDef {
  key: string;
  label: string;
  hint?: string;
  type: "select" | "toggle";
  options?: { value: string; label: string }[];
  default: string | boolean;
  showWhen?: ShowWhenSpec;
}

export type FieldValues = Record<string, string | boolean>;

export interface CeremonyManifest {
  purpose: string;
  pkg: string;
  nature: Nature;
  label: string;
  wired: Wired;
  blurb: string;
  fields: FieldDef[];
  /** JSON skeleton of the verified-Facts `input`, with directives. */
  factsTemplate: unknown;
}

export const natureColor: Record<Nature, string> = {
  "read-only": "var(--brand)",
  constructive: "var(--vd-allow)",
  destructive: "var(--vd-deny)",
  mutating: "var(--vd-refer)",
};

const TRUST_TASK_CEREMONIES =
  "https://trusttasks.org/openvtc/vtc/ceremonies/list/1.0";

export async function fetchCeremonies(): Promise<CeremonyManifest[]> {
  return getJson<CeremonyManifest[]>("/v1/ceremonies", {
    trustTask: TRUST_TASK_CEREMONIES,
  });
}

/** The default value map for a ceremony's simulator form. */
export function defaultValues(m: CeremonyManifest): FieldValues {
  return Object.fromEntries(m.fields.map((f) => [f.key, f.default]));
}

/** Evaluate a field's `showWhen` predicate against the current values. */
export function evalShowWhen(
  spec: ShowWhenSpec | undefined,
  values: FieldValues,
): boolean {
  if (!spec) return true;
  const v = values[spec.field];
  if (spec.eq !== undefined) return v === spec.eq;
  if (spec.truthy !== undefined) return Boolean(v) === spec.truthy;
  return true;
}

// A key dropped from its parent object (an unset optional field).
const OMIT = Symbol("omit");

function materialize(node: unknown, values: FieldValues, now: string): unknown {
  if (typeof node === "string") {
    if (node === "$now") return now;
    if (node.startsWith("$field:")) {
      const v = values[node.slice("$field:".length)];
      return v === undefined || v === "" ? OMIT : v;
    }
    return node;
  }
  if (Array.isArray(node)) {
    return node
      .map((n) => materialize(n, values, now))
      .filter((x) => x !== OMIT);
  }
  if (node && typeof node === "object") {
    const obj = node as Record<string, unknown>;
    if ("$if" in obj) {
      const cond = Boolean(values[obj.$if as string]);
      return materialize(cond ? obj.then : obj.else, values, now);
    }
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(obj)) {
      const r = materialize(val, values, now);
      if (r !== OMIT) out[k] = r;
    }
    return out;
  }
  return node;
}

/** Build the verified-Facts document for a dry-run from a manifest's
 * facts template + the operator's field values. */
export function materializeFacts(
  template: unknown,
  values: FieldValues,
): Record<string, unknown> {
  return materialize(template, values, new Date().toISOString()) as Record<
    string,
    unknown
  >;
}
