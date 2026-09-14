// The Flow view — the active policy as a chart of what it decides.
//
// Drawn from [`induceFlow`], which builds the chart out of evaluations rather
// than out of the module's text, so a hand-written policy renders like an
// authored one. See `lib/policy-flow.ts` for why that is the design.
//
// ## Why it grows downwards
//
// The first cut gave each depth its own column. That reads well on a wide
// page and not at all here: this panel is the narrow half of a two-column
// layout, a four-deep chart wanted about a thousand pixels, and the endings
// fell off the right-hand side. Depth now costs an indent rather than a
// column, so the chart's width is fixed and its depth is what grows — which is
// the direction a panel can give.
//
// Every node owns one row. That is what makes overlap impossible rather than
// unlikely: nothing is positioned relative to anything else's text, and
// `layout` is asserted against that in the tests.
//
// The drawing is inline SVG in the console's own tokens, like the pipeline
// strip above it. A diagramming library would add a dependency, a second
// visual language, and a picture the dry-run could not point at — and the
// pointing is the half that earns its place: run the simulator and the chart
// lights the path those facts take.

import { useMemo } from "react";

import type { CeremonyManifest, FieldValues } from "@/lib/ceremony-manifest";
import { induceFlow, tracePath, type FlowNode } from "@/lib/policy-flow";

const EFFECT_WORD: Record<string, string> = {
  allow: "admit",
  deny: "deny",
  refer: "refer",
  request_more: "ask for more",
  none: "no decision",
};

/** What an ending carries beside its effect — the part an operator acts on. */
export function endingDetail(node: Extract<FlowNode, { kind: "verdict" }>): string {
  const w = node.with ?? {};
  if (typeof w.queue === "string") return `to the ${w.queue} queue`;
  if (typeof w.role === "string") return `as ${w.role}`;
  if (Array.isArray(w.needs)) return (w.needs as unknown[]).join(", ");
  if (typeof w.code === "string") return String(w.code);
  return "";
}

// Geometry. One row per node; depth is an indent, not a column.
export const WIDTH = 620;
const ROW = 58;
const BOX = 40;
const PAD = 12;
const INDENT = 26;
/** Where a parent's connector runs down, relative to its own left edge. */
const GUIDE = 11;

/** Rough advance width of the label faces at their drawn sizes, in px. */
const CHAR_SANS = 6.7;
const CHAR_MONO = 5.6;

/** Cut `text` to what fits in `px`, keeping a full word where it can. */
export function fit(text: string, px: number, charWidth = CHAR_SANS): string {
  const max = Math.floor(px / charWidth);
  if (max <= 1) return "";
  if (text.length <= max) return text;
  const cut = text.slice(0, max - 1);
  const space = cut.lastIndexOf(" ");
  return `${space > max * 0.6 ? cut.slice(0, space) : cut.trimEnd()}…`;
}

export interface FlowRow {
  node: FlowNode;
  depth: number;
  /** The branch taken to reach this node, as its option reads. */
  label?: string;
  /** Branch indexes from the root, so the trace can light a path. */
  path: number[];
  /** Row index, top to bottom. */
  index: number;
}

/** Flatten the tree depth-first: one row per node, in reading order. */
export function layout(node: FlowNode): FlowRow[] {
  const rows: FlowRow[] = [];
  const walk = (n: FlowNode, depth: number, path: number[], label?: string) => {
    rows.push({ node: n, depth, label, path, index: rows.length });
    if (n.kind !== "ask") return;
    n.branches.forEach((b, i) => walk(b.node, depth + 1, [...path, i], b.label));
  };
  walk(node, 0, []);
  return rows;
}

const rowY = (index: number) => PAD + index * ROW + ROW / 2;
const rowX = (depth: number) => PAD + depth * INDENT;

export function PolicyFlow({
  ceremony,
  probes,
  values,
}: {
  ceremony: CeremonyManifest;
  probes: Parameters<typeof induceFlow>[1];
  /** The simulator's current inputs, so the chart can light their path. */
  values?: FieldValues;
}) {
  const flow = useMemo(() => induceFlow(ceremony, probes), [ceremony, probes]);
  const rows = useMemo(() => layout(flow), [flow]);
  const taken = useMemo(
    () => (values ? tracePath(flow, values) : null),
    [flow, values],
  );

  const height = PAD * 2 + rows.length * ROW;

  /** On the path when every branch above it was the one taken. */
  const onPath = (path: number[]) =>
    taken !== null && path.length <= taken.length && path.every((b, i) => taken[i] === b);

  const connectors: React.ReactNode[] = [];
  const nodes: React.ReactNode[] = [];

  for (const row of rows) {
    const x = rowX(row.depth);
    const y = rowY(row.index);
    const boxWidth = WIDTH - PAD - x;
    const lit = onPath(row.path);
    const tone = lit ? "pf-lit" : "pf-dim";
    const key = row.path.join("-") || "root";

    // The connector from this node down to each of its children.
    if (row.node.kind === "ask") {
      const kids = rows.filter(
        (r) =>
          r.depth === row.depth + 1 &&
          r.path.length === row.path.length + 1 &&
          row.path.every((v, i) => r.path[i] === v),
      );
      const last = kids[kids.length - 1];
      if (last) {
        const guideX = x + GUIDE;
        connectors.push(
          <path
            key={`guide-${key}`}
            className={`pf-edge ${onPath([...row.path, 0]) || lit ? "" : "pf-dim"}`}
            d={`M ${guideX} ${y + BOX / 2} V ${rowY(last.index)}`}
          />,
        );
        for (const kid of kids) {
          connectors.push(
            <path
              key={`stub-${kid.path.join("-")}`}
              className={`pf-edge ${onPath(kid.path) ? "pf-lit" : "pf-dim"}`}
              d={`M ${guideX} ${rowY(kid.index)} H ${rowX(kid.depth)}`}
            />,
          );
        }
      }
    }

    const label = row.label
      ? fit(row.label, boxWidth - GUIDE - 8, CHAR_MONO)
      : undefined;

    if (row.node.kind === "ask") {
      const text = row.node.label;
      nodes.push(
        <g key={`q-${key}`} className={tone}>
          {label && (
            <text className="pf-edge-label" x={x + 6} y={y - BOX / 2 - 6}>
              {label}
            </text>
          )}
          <rect className="pf-q" x={x} y={y - BOX / 2} width={boxWidth} height={BOX} rx={7} />
          <text className="pf-q-label" x={x + 12} y={y + 4}>
            {fit(text, boxWidth - 24)}
            <title>{text}</title>
          </text>
        </g>,
      );
      continue;
    }

    const effect = row.node.kind === "verdict" ? row.node.effect : "varies";
    const detail =
      row.node.kind === "verdict"
        ? endingDetail(row.node)
        : `${row.node.effects.join(" / ")} — on a fact no control varies`;
    const word = row.node.kind === "verdict" ? (EFFECT_WORD[effect] ?? effect) : "varies";

    nodes.push(
      <g key={`t-${key}`} className={tone}>
        {label && (
          <text className="pf-edge-label" x={x + 6} y={y - BOX / 2 - 6}>
            {label}
          </text>
        )}
        <rect
          className={`pf-term ${row.node.kind === "verdict" ? `pf-eff-${effect}` : "pf-varies"}`}
          x={x}
          y={y - BOX / 2}
          width={boxWidth}
          height={BOX}
          rx={7}
        />
        <text
          className={`pf-term-label ${row.node.kind === "verdict" ? `pf-fg-${effect}` : "pf-fg-varies"}`}
          x={x + 12}
          y={y - 2}
        >
          {word.toUpperCase()}
        </text>
        {detail && (
          <text className="pf-term-detail" x={x + 12} y={y + 13}>
            {fit(detail, boxWidth - 24, CHAR_MONO)}
            <title>{detail}</title>
          </text>
        )}
      </g>,
    );
  }

  return (
    <div className="pf-scroll">
      <svg
        className={`pf${taken ? " pf-traced" : ""}`}
        viewBox={`0 0 ${WIDTH} ${height}`}
        role="img"
        aria-label={`Flow chart of the active ${ceremony.label} policy`}
      >
        {connectors}
        {nodes}
      </svg>
    </div>
  );
}
