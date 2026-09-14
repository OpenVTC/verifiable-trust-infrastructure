// The Flow view — the active policy as a chart of what it decides.
//
// Drawn from [`induceFlow`], which builds the chart out of evaluations rather
// than out of the module's text, so a hand-written policy renders like an
// authored one. See `lib/policy-flow.ts` for why that is the design.
//
// The drawing is inline SVG in the console's own tokens, like the pipeline
// strip above it. A diagramming library would add a dependency, a second
// visual language, and a picture the dry-run could not point at — and the
// pointing is the half that earns its place: run the simulator and the chart
// lights the path those facts take.

import { useMemo } from "react";

import type { CeremonyManifest, FieldValues } from "@/lib/ceremony-manifest";
import {
  countEndings,
  induceFlow,
  tracePath,
  type FlowNode,
  type ProbeRow,
} from "@/lib/policy-flow";

const EFFECT_WORD: Record<string, string> = {
  allow: "admit",
  deny: "deny",
  refer: "refer",
  request_more: "ask for more",
  none: "no decision",
};

/** What an ending carries beside its effect — the part an operator acts on. */
function endingDetail(node: Extract<FlowNode, { kind: "verdict" }>): string {
  const w = node.with ?? {};
  if (typeof w.queue === "string") return `to the ${w.queue} queue`;
  if (typeof w.role === "string") return `as ${w.role}`;
  if (Array.isArray(w.needs)) return (w.needs as unknown[]).join(", ");
  if (typeof w.code === "string") return String(w.code);
  return "";
}

// Geometry. One row per ending, one column per question depth.
const COL = 250;
const ROW = 62;
const QW = 210;
const QH = 44;
const TW = 210;
const TH = 40;
const PAD = 16;

interface Placed {
  node: FlowNode;
  depth: number;
  /** Row centre, in ending-slots. */
  y: number;
  /** Index of the branch taken to get here, for the trace. */
  path: number[];
}

/** Lay the tree out: endings stack, questions centre over what they lead to. */
function place(node: FlowNode, depth: number, next: { row: number }, path: number[]): Placed[] {
  if (node.kind !== "ask") {
    const y = next.row;
    next.row += 1;
    return [{ node, depth, y, path }];
  }
  const kids = node.branches.flatMap((b, i) => place(b.node, depth + 1, next, [...path, i]));
  const own = kids.filter((k) => k.depth === depth + 1);
  const first = own[0]?.y ?? next.row;
  const last = own[own.length - 1]?.y ?? first;
  return [{ node, depth, y: (first + last) / 2, path }, ...kids];
}

export function PolicyFlow({
  ceremony,
  probes,
  values,
}: {
  ceremony: CeremonyManifest;
  probes: ProbeRow[];
  /** The simulator's current inputs, so the chart can light their path. */
  values?: FieldValues;
}) {
  const flow = useMemo(() => induceFlow(ceremony, probes), [ceremony, probes]);
  const placed = useMemo(() => place(flow, 0, { row: 0 }, []), [flow]);
  const taken = useMemo(
    () => (values ? tracePath(flow, values) : null),
    [flow, values],
  );

  const rows = countEndings(flow);
  const depth = Math.max(...placed.map((p) => p.depth));
  const width = PAD * 2 + depth * COL + TW;
  const height = PAD * 2 + rows * ROW;

  const xOf = (d: number) => PAD + d * COL;
  const yOf = (y: number) => PAD + y * ROW + ROW / 2;

  /** A node is on the traced path when every branch above it was taken. */
  const onPath = (path: number[]) =>
    taken !== null && path.every((b, i) => taken[i] === b) && path.length <= taken.length;

  const edges: React.ReactNode[] = [];
  const nodes: React.ReactNode[] = [];

  for (const p of placed) {
    const x = xOf(p.depth);
    const y = yOf(p.y);
    const lit = onPath(p.path);

    if (p.node.kind === "ask") {
      const ask = p.node;
      nodes.push(
        <g key={`q-${p.path.join("-")}`} className={lit ? "pf-lit" : "pf-dim"}>
          <rect className="pf-q" x={x} y={y - QH / 2} width={QW} height={QH} rx={8} />
          <text className="pf-q-label" x={x + 12} y={y + 4}>
            {ask.label}
          </text>
        </g>,
      );
      ask.branches.forEach((b, i) => {
        const child = placed.find(
          (c) => c.depth === p.depth + 1 && c.path.length === p.path.length + 1 &&
            c.path.every((v, j) => v === [...p.path, i][j]),
        );
        if (!child) return;
        const cy = yOf(child.y);
        const mid = x + QW + (COL - QW) / 2;
        const branchLit = onPath([...p.path, i]);
        edges.push(
          <g key={`e-${p.path.join("-")}-${i}`} className={branchLit ? "pf-lit" : "pf-dim"}>
            <path
              className="pf-edge"
              d={`M ${x + QW} ${y} H ${mid} V ${cy} H ${xOf(p.depth + 1)}`}
            />
            <text className="pf-edge-label" x={x + QW + 8} y={y === cy ? y - 7 : (y + cy) / 2 - 6}>
              {b.label}
            </text>
          </g>,
        );
      });
    } else if (p.node.kind === "verdict") {
      const v = p.node;
      const detail = endingDetail(v);
      nodes.push(
        <g key={`t-${p.path.join("-")}`} className={lit ? "pf-lit" : "pf-dim"}>
          <rect
            className={`pf-term pf-eff-${v.effect}`}
            x={x}
            y={y - TH / 2}
            width={TW}
            height={TH}
            rx={8}
          />
          <text className={`pf-term-label pf-fg-${v.effect}`} x={x + 12} y={y - 2}>
            {(EFFECT_WORD[v.effect] ?? v.effect).toUpperCase()}
          </text>
          {detail && (
            <text className="pf-term-detail" x={x + 12} y={y + 13}>
              {detail}
            </text>
          )}
        </g>,
      );
    } else {
      nodes.push(
        <g key={`v-${p.path.join("-")}`} className={lit ? "pf-lit" : "pf-dim"}>
          <rect className="pf-term pf-varies" x={x} y={y - TH / 2} width={TW} height={TH} rx={8} />
          <text className="pf-term-label pf-fg-varies" x={x + 12} y={y - 2}>
            VARIES
          </text>
          <text className="pf-term-detail" x={x + 12} y={y + 13}>
            {p.node.effects.join(" / ")} — on a fact no control varies
          </text>
        </g>,
      );
    }
  }

  return (
    <div className="pf-scroll">
      <svg
        className={`pf${taken ? " pf-traced" : ""}`}
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label={`Flow chart of the active ${ceremony.label} policy`}
      >
        {edges}
        {nodes}
      </svg>
    </div>
  );
}
