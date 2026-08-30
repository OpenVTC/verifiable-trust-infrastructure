// Relationships plugin — a connections graph of the community's trust edges.
//
// Two kinds of edge, both first-class. DTG Core Credentials makes VRCs and VMCs
// the two subtypes of *edge credential* — "in both cases, a bi-directional pair
// of credentials forms a complete DTG edge" — and the community is a node like
// any other ("DTG node types include persons, devices, AI agents, and VTCs").
//
//   relationship — a VRC pair between two members
//   membership   — the VMC pair between a member and this community
//
// This view rendered only the first, so a community whose members had published
// no VRCs saw an empty page and read it as "no trust here", when every
// membership was an edge it was not drawing.
//
// There is no `kind` on the wire: `relationships/graph/0.2` pins the response
// with `additionalProperties: false`, and none is needed — an edge with the
// community's own DID as an endpoint is the membership one, and the community
// knows its own DID.
//
// Unlike the recognition graph (external, query-only), these are local +
// enumerable, so we can draw the whole thing. Layout is a deterministic circle:
// endpoints are nodes, each edge joins a pair. Click a node to highlight its
// connections and list its edges.
//
// A complete edge is a solid double-headed line, where both parties' halves
// stand; a half-edge is dashed and single-headed — one party's claim the other
// has not answered. These used to render identically, so the view could not
// tell a mutual relationship from a unilateral one (#1054).

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Share2 } from "lucide-react";

import {
  fetchHealth,
  fetchRelationshipsGraph,
  type GraphEdge,
  type HealthResponse,
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

  // The community's own DID is what separates the two kinds of edge. Read from
  // `/health`, which the dashboard already uses for it — a graph rendered
  // before it resolves simply shows every edge as a relationship, which is what
  // this view did for its whole life and is a safe intermediate state.
  const health = useQuery<HealthResponse>({
    queryKey: ["health"],
    queryFn: fetchHealth,
  });
  const communityDid = health.data?.vtc_did;

  const isMembership = useMemo(
    () => (e: GraphEdge) =>
      communityDid !== undefined && e.endpoints.includes(communityDid),
    [communityDid],
  );

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
  const membershipCount = edges.filter(isMembership).length;
  const relationshipCount = edges.length - membershipCount;

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
          The community's trust graph. Each node is an identifier — a member, or
          this community itself — and each edge joins a pair. An edge is{" "}
          <strong>complete</strong> when both parties have issued a credential
          naming the other; that reciprocal credential is how each consents to
          the edge. A <strong>half-edge</strong> is one party's claim the other
          has not answered.
        </p>
        <p className="muted">
          <strong>Membership</strong> edges join a member to this community: the
          membership credential (VMC) this community issued, and the member's
          acknowledgement of it. An acknowledgement counts only when its{" "}
          <code>digest</code> matches the credential it names, so a member who
          has not answered — or whose answer predates that binding — shows as a
          half-edge until they re-issue. <strong>Relationship</strong> edges
          join two members by a pair of relationship credentials (VRCs).
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
            Nothing to draw yet — no memberships have been issued and no member
            has published a relationship credential.
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
                // Membership and relationship edges are both real edges, so
                // neither is drawn as the lesser: same weights and dash rules,
                // different hue. Colour alone never carries the complete /
                // half-edge distinction — that stays in the line style, which
                // survives greyscale and colour-blindness.
                const hue = isMembership(e)
                  ? "var(--accent, #7c5cff)"
                  : "var(--brand)";
                return (
                  <line
                    key={edgeKey(e)}
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                    stroke={active ? hue : "var(--border)"}
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
                    {p.did === communityDid ? (
                      // The community is a node, but it is not a peer of its
                      // members — a square says so without needing a legend
                      // entry to be read first.
                      <rect
                        x={isSel ? -9 : -6}
                        y={isSel ? -9 : -6}
                        width={isSel ? 18 : 12}
                        height={isSel ? 18 : 12}
                        fill={
                          isSel ? "var(--accent, #7c5cff)" : "var(--brand-tint-strong)"
                        }
                        stroke="var(--border-strong)"
                        strokeWidth={1}
                      />
                    ) : (
                      <circle
                        r={isSel ? 9 : 6}
                        fill={isSel ? "var(--brand)" : "var(--brand-tint-strong)"}
                        stroke="var(--border-strong)"
                        strokeWidth={1}
                      />
                    )}
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
              viewBox="0 0 260 58"
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
              <line
                x1={4}
                y1={48}
                x2={40}
                y2={48}
                stroke="var(--accent, #7c5cff)"
                strokeWidth={2}
                markerStart="url(#rel-arrow-legend)"
                markerEnd="url(#rel-arrow-legend)"
              />
              <text x={48} y={52} fontSize="10" fill="var(--text-muted)">
                membership — a VMC pair
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
                {membershipCount} membership
                {membershipCount === 1 ? "" : "s"} · {relationshipCount}{" "}
                relationship{relationshipCount === 1 ? "" : "s"}.
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
                      // Personas (VPCs) asserted on this edge. Rendered per
                      // half, and attributed, because a persona is asserted by
                      // one party about one relationship — a complete edge can
                      // carry two different ones, and picking a single
                      // `personaDid` off the edge (as this did before the
                      // graph became pair-grouped) would silently drop the
                      // other party's.
                      const personas = e.halves.flatMap((h) =>
                        h.personaDid
                          ? [{ id: h.id, by: h.issuerDid, as: h.personaDid }]
                          : [],
                      );
                      return (
                        <li key={edgeKey(e)} style={{ marginBottom: 4 }}>
                          {isMembership(e) ? (
                            // A membership edge reads in the community's
                            // vocabulary, not the peer-vouching one: "vouched
                            // for by the community" would describe a
                            // relationship the VMC pair does not assert.
                            e.complete ? (
                              <>
                                ↔ member of <code>{name}</code>
                              </>
                            ) : selected === communityDid ? (
                              <>
                                → issued membership to <code>{name}</code>{" "}
                                <span className="muted">
                                  (not acknowledged)
                                </span>
                              </>
                            ) : (
                              <>
                                ← granted membership by <code>{name}</code>{" "}
                                <span className="muted">
                                  (not acknowledged)
                                </span>
                              </>
                            )
                          ) : e.complete ? (
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
                          {personas.map((p) => (
                            <span key={p.id} className="muted">
                              {" · "}
                              <code>{nameBook.nameOrDid(p.by)}</code> as{" "}
                              <code>{nameBook.nameOrDid(p.as)}</code>
                            </span>
                          ))}
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
