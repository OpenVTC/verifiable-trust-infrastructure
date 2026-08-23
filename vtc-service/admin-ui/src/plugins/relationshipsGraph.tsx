// Relationships plugin — a connections graph of the community's member-to-member
// trust edges (Verifiable Relationship Credentials, VRCs).
//
// Unlike the recognition graph (external, query-only), member relationships are
// local + enumerable, so we can draw the whole thing. Layout is a deterministic
// circle: endpoints are nodes, each edge joins a pair. Click a node to highlight
// its connections and list its edges.
//
// A DTG edge is *two* VRCs, one in each direction. The two are drawn
// differently on purpose: a solid double-headed line is a complete edge, where
// both parties have published; a dashed single-headed line is a half-edge — one
// party's claim that the other has not reciprocated. These used to render
// identically, so the view could not tell a mutual relationship from a
// unilateral one (#1054).

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Share2 } from "lucide-react";

import {
  fetchRelationshipsGraph,
  type GraphEdge,
  type RelationshipsGraph,
} from "@/lib/api";
import { useNameBook } from "@/lib/names";
import { NamedDid } from "@/components/NamedDid";

const SIZE = 600;
const C = SIZE / 2;
const R = 240;

interface Placed {
  did: string;
  x: number;
  y: number;
}

/** A stable key for an edge — the pair identity the server sorted. */
const edgeKey = (e: GraphEdge) => e.endpoints.join("|");

/** The endpoint of `e` that isn't `did`. Equals `did` for a self-issued VRC. */
const otherEnd = (e: GraphEdge, did: string): string =>
  (e.endpoints[0] === did ? e.endpoints[1] : e.endpoints[0]) ?? did;

export function Relationships() {
  const nameBook = useNameBook();
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
  const completeCount = edges.filter((e) => e.complete).length;
  const halfCount = edges.length - completeCount;

  const selectedEdges = selected
    ? edges.filter((e) => e.endpoints.includes(selected))
    : [];
  const neighbours = new Set<string>(
    selectedEdges.flatMap((e) => e.endpoints),
  );

  const isEmpty = query.data && placed.length === 0;

  return (
    <div className="page">
      <header className="page-header">
        <h2>
          <Share2 size={20} strokeWidth={1.75} /> Relationships
        </h2>
        <p className="muted">
          The community's trust graph. Each node is an identifier a member
          published a Verifiable Relationship Credential (VRC) under; each edge
          joins a pair. An edge is <strong>complete</strong> when both parties
          have published a VRC naming the other — that reciprocal credential is
          how a member consents to the edge. A <strong>half-edge</strong> is one
          party's claim the other has not answered.
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
            No relationships published yet — members haven't published any VRCs.
          </p>
        </section>
      )}

      {query.data && placed.length > 0 && (
        <section className="card" style={{ display: "flex", gap: "var(--space-4)", flexWrap: "wrap" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-2)" }}>
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

              {/* Edges. Complete: solid, arrowheads both ends. Half: dashed,
                  one arrowhead, pointing at the party who hasn't answered. */}
              {edges.map((e) => {
                const [e0, e1] = e.endpoints;
                const half = e.halves[0];
                // The server guarantees two endpoints and at least one half;
                // this narrows rather than defends.
                if (!e0 || !e1 || !half) return null;
                // A self-issued VRC has both endpoints at one point — nothing
                // to draw, and the node itself already carries it.
                if (e0 === e1) return null;
                // Draw a half-edge issuer → subject; a complete edge has no
                // meaningful direction, so orient it on the sorted pair.
                const from = e.complete ? e0 : half.issuerDid;
                const to = e.complete ? e1 : half.subjectDid;
                const a = posByDid.get(from);
                const b = posByDid.get(to);
                if (!a || !b) return null;
                const active = !selected || e.endpoints.includes(selected);
                return (
                  <line
                    key={edgeKey(e)}
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                    stroke={active ? "var(--brand)" : "var(--border)"}
                    strokeWidth={e.complete ? (active ? 2 : 1.5) : active ? 1.5 : 1}
                    strokeDasharray={e.complete ? undefined : "4 3"}
                    opacity={selected && !active ? 0.25 : 0.8}
                    markerStart={e.complete ? "url(#rel-arrow)" : undefined}
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
                      {nameBook.nameOrDid(p.did)}
                    </text>
                  </g>
                );
              })}
            </svg>

            <svg
              viewBox="0 0 260 40"
              style={{ width: "min(100%, 260px)", height: "auto" }}
              role="img"
              aria-label="Legend"
            >
              {/* Its own marker: a `url(#…)` reference resolving into a
                  different inline <svg> is not something to rely on. */}
              <defs>
                <marker
                  id="rel-arrow-legend"
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
              <line
                x1={4}
                y1={12}
                x2={40}
                y2={12}
                stroke="var(--brand)"
                strokeWidth={2}
                markerStart="url(#rel-arrow-legend)"
                markerEnd="url(#rel-arrow-legend)"
              />
              <text x={48} y={16} fontSize="10" fill="var(--text-muted)">
                complete — both parties published
              </text>
              <line
                x1={4}
                y1={30}
                x2={40}
                y2={30}
                stroke="var(--brand)"
                strokeWidth={1.5}
                strokeDasharray="4 3"
                markerEnd="url(#rel-arrow-legend)"
              />
              <text x={48} y={34} fontSize="10" fill="var(--text-muted)">
                half-edge — not reciprocated
              </text>
            </svg>
          </div>

          <div style={{ flex: "1 1 220px", minWidth: 220 }}>
            <h3>{selected ? "Connections" : "Overview"}</h3>
            {!selected && (
              <p className="muted">
                {placed.length} identifier{placed.length === 1 ? "" : "s"} ·{" "}
                {completeCount} complete edge{completeCount === 1 ? "" : "s"} ·{" "}
                {halfCount} half-edge{halfCount === 1 ? "" : "s"}.
                <br />
                Select a node to see its edges.
              </p>
            )}
            {selected && (
              <>
                <p>
                  <NamedDid book={nameBook} did={selected} />
                </p>
                {selectedEdges.length === 0 ? (
                  <p className="muted">No relationships.</p>
                ) : (
                  <ul style={{ paddingLeft: "1.1em", margin: 0 }}>
                    {selectedEdges.map((e) => {
                      const other = otherEnd(e, selected);
                      const name = nameBook.nameOrDid(other);
                      const issuedBySelected = e.halves.some(
                        (h) => h.issuerDid === selected,
                      );
                      return (
                        <li key={edgeKey(e)} style={{ marginBottom: 4 }}>
                          {e.complete ? (
                            <>
                              ↔ mutual with <code>{name}</code>
                            </>
                          ) : issuedBySelected ? (
                            <>
                              → vouched for <code>{name}</code>{" "}
                              <span className="muted">
                                (not reciprocated)
                              </span>
                            </>
                          ) : (
                            <>
                              ← vouched for by <code>{name}</code>{" "}
                              <span className="muted">
                                (not reciprocated)
                              </span>
                            </>
                          )}
                        </li>
                      );
                    })}
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
