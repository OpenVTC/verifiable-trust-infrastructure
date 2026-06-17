// Relationships plugin — a connections graph of the community's member-to-member
// trust edges (Verifiable Relationship Credentials, VRCs).
//
// Unlike the recognition graph (external, query-only), member relationships are
// local + enumerable, so we can draw the whole thing. Layout is a deterministic
// circle: members are nodes, each published VRC is a directed edge issuer →
// subject. Click a node to highlight its connections and list its edges.

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Share2 } from "lucide-react";

import { fetchRelationshipsGraph, type RelationshipsGraph } from "@/lib/api";
import { shorten } from "@/lib/format";

const SIZE = 600;
const C = SIZE / 2;
const R = 240;

interface Placed {
  did: string;
  x: number;
  y: number;
}

export function Relationships() {
  const [selected, setSelected] = useState<string | null>(null);

  const query = useQuery<RelationshipsGraph>({
    queryKey: ["relationships-graph"],
    queryFn: fetchRelationshipsGraph,
  });

  const placed = useMemo<Placed[]>(() => {
    const nodes = query.data?.nodes ?? [];
    const n = nodes.length;
    return nodes.map((node, i) => {
      const a = (i / Math.max(n, 1)) * 2 * Math.PI - Math.PI / 2;
      return { did: node.did, x: C + R * Math.cos(a), y: C + R * Math.sin(a) };
    });
  }, [query.data]);

  const posByDid = useMemo(() => {
    const m = new Map<string, Placed>();
    for (const p of placed) m.set(p.did, p);
    return m;
  }, [placed]);

  const edges = query.data?.edges ?? [];
  const selectedEdges = selected
    ? edges.filter((e) => e.issuerDid === selected || e.subjectDid === selected)
    : [];
  const neighbours = new Set<string>(
    selectedEdges.flatMap((e) => [e.issuerDid, e.subjectDid]),
  );

  const isEmpty = query.data && placed.length === 0;

  return (
    <div className="page">
      <header className="page-header">
        <h2>
          <Share2 size={20} strokeWidth={1.75} /> Relationships
        </h2>
        <p className="muted">
          The community's trust graph: each node is a member, each edge a
          published Verifiable Relationship Credential (VRC), pointing from the
          asserting member to the member they vouched for. Click a node to
          highlight its connections.
        </p>
      </header>

      {query.isPending && (
        <section className="card">
          <p className="muted">Loading…</p>
        </section>
      )}
      {query.isError && (
        <section className="card">
          <p className="muted">Could not load the relationships graph.</p>
        </section>
      )}
      {isEmpty && (
        <section className="card">
          <p className="muted">
            No relationships published yet — members haven't issued any VRCs.
          </p>
        </section>
      )}

      {query.data && placed.length > 0 && (
        <section className="card" style={{ display: "flex", gap: "var(--space-4)", flexWrap: "wrap" }}>
          <svg
            viewBox={`0 0 ${SIZE} ${SIZE}`}
            style={{ width: "min(100%, 560px)", height: "auto" }}
            role="img"
            aria-label="Member relationship graph"
          >
            <defs>
              <marker
                id="rel-arrow"
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--border-strong)" />
              </marker>
            </defs>

            {/* Edges */}
            {edges.map((e) => {
              const a = posByDid.get(e.issuerDid);
              const b = posByDid.get(e.subjectDid);
              if (!a || !b) return null;
              const active =
                !selected || e.issuerDid === selected || e.subjectDid === selected;
              return (
                <line
                  key={e.id}
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke={active ? "var(--brand)" : "var(--border)"}
                  strokeWidth={active ? 1.5 : 1}
                  opacity={selected && !active ? 0.25 : 0.8}
                  markerEnd="url(#rel-arrow)"
                />
              );
            })}

            {/* Nodes */}
            {placed.map((p) => {
              const isSel = selected === p.did;
              const dim = selected && !isSel && !neighbours.has(p.did);
              return (
                <g
                  key={p.did}
                  transform={`translate(${p.x}, ${p.y})`}
                  style={{ cursor: "pointer" }}
                  opacity={dim ? 0.35 : 1}
                  onClick={() => setSelected(isSel ? null : p.did)}
                >
                  <circle
                    r={isSel ? 9 : 6}
                    fill={isSel ? "var(--brand)" : "var(--brand-tint-strong)"}
                    stroke="var(--border-strong)"
                    strokeWidth={1}
                  />
                  <text
                    x={p.x > C ? 11 : -11}
                    y={4}
                    textAnchor={p.x > C ? "start" : "end"}
                    fontSize="10"
                    fill="var(--text-muted)"
                  >
                    {shorten(p.did, 8, 4)}
                  </text>
                </g>
              );
            })}
          </svg>

          <div style={{ flex: "1 1 220px", minWidth: 220 }}>
            <h3>
              {selected ? "Connections" : "Overview"}
            </h3>
            {!selected && (
              <p className="muted">
                {placed.length} member{placed.length === 1 ? "" : "s"} ·{" "}
                {edges.length} relationship{edges.length === 1 ? "" : "s"}.
                <br />
                Select a node to see its edges.
              </p>
            )}
            {selected && (
              <>
                <p>
                  <code className="truncate">{selected}</code>
                </p>
                {selectedEdges.length === 0 ? (
                  <p className="muted">No relationships.</p>
                ) : (
                  <ul style={{ paddingLeft: "1.1em", margin: 0 }}>
                    {selectedEdges.map((e) => (
                      <li key={e.id} style={{ marginBottom: 4 }}>
                        {e.issuerDid === selected ? (
                          <>
                            → vouched for{" "}
                            <code>{shorten(e.subjectDid, 8, 4)}</code>
                          </>
                        ) : (
                          <>
                            ← vouched for by{" "}
                            <code>{shorten(e.issuerDid, 8, 4)}</code>
                          </>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
