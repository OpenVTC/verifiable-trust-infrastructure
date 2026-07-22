// Ceremonies — the live decision pipeline.
//
// Wires the ceremony visual guide to the running daemon. A community
// state transition (directory query, join, leave, role change) is one
// pipeline parameterized by purpose:
//
//   TRIGGER → GATHER → VERIFY → FACTS → EVALUATE(<purpose>.rego)
//           → VERDICT → EFFECTS
//
// This surface visualizes that flow and lets an operator *dry-run* a
// ceremony: it assembles a verified-Facts document and evaluates the
// active decision policy via `POST /v1/policies/{id}/test` (which
// never mutates state), then renders the real four-valued verdict —
// the same `decide()` the routes run, minus the effect.

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { getJson, postJson } from "@/lib/api";
import { useConfirm } from "@/components/ConfirmDialog";
import { formatIso } from "@/lib/format";
import {
  type PolicyRow,
  type Purpose,
  CEREMONY_PURPOSES,
  OTHER_PURPOSES,
  activatePolicy,
  fetchActivePolicy,
  fetchPolicies,
  uploadPolicy,
} from "@/lib/policies-api";
import {
  type ExplainFacts,
  type RuleIR,
  blankIR,
  diffIR,
  explainDecision,
  irToEnglish,
  parseRego,
} from "@/lib/rule-ir";
import { EnglishView, RuleEditor } from "@/plugins/RuleEditor";
import {
  type CeremonyManifest,
  type FieldDef,
  type FieldValues,
  defaultValues,
  evalShowWhen,
  fetchCeremonies,
  materializeFacts,
  natureColor,
} from "@/lib/ceremony-manifest";

const TRUST_TASK_TEST = "https://trusttasks.org/openvtc/vtc/policies/test/1.0";
const TRUST_TASK_JOIN_REQUESTS =
  "https://trusttasks.org/spec/vtc/join-requests/list/0.1";

// Queues a refer verdict can route to that map to an actionable admin
// surface. The moderator queue is the join-requests inbox.
const QUEUE_LINKS: Record<string, { label: string; to: string }> = {
  moderator: { label: "Join requests", to: "/join-requests" },
};

interface JoinRequestsPage {
  items: unknown[];
  total_estimate?: number;
}

async function fetchPendingCount(): Promise<number> {
  const page = await getJson<JoinRequestsPage>(
    "/v1/join-requests?status=pending&limit=50",
    { trustTask: TRUST_TASK_JOIN_REQUESTS },
  );
  return page.total_estimate ?? page.items.length;
}

type Effect = "allow" | "deny" | "refer" | "request_more";

// The pipeline stages, in order. The token travels along these.
const STAGES = [
  "Trigger",
  "Gather",
  "Verify",
  "Facts",
  "Evaluate",
  "Verdict",
  "Effects",
] as const;

const EFFECTS: { key: Effect; label: string; blurb: string }[] = [
  { key: "allow", label: "Allow", blurb: "the transition proceeds" },
  { key: "deny", label: "Deny", blurb: "refused" },
  { key: "refer", label: "Refer", blurb: "needs a human / quorum" },
  {
    key: "request_more",
    label: "Request more",
    blurb: "needs more evidence (threaded)",
  },
];

interface TestResponse {
  id: string;
  result: {
    result?: { expressions?: { value?: unknown }[] }[];
  };
}

interface Verdict {
  effect: Effect;
  with?: Record<string, unknown>;
}

function pluckDecision(resp: TestResponse): Verdict | null {
  const value = resp.result?.result?.[0]?.expressions?.[0]?.value;
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  if (typeof v.effect !== "string") return null;
  return { effect: v.effect as Effect, with: v.with as Record<string, unknown> };
}

// ---------------------------------------------------------------------------
// request_more loop — a verdict can ask for more evidence (`with.needs`).
// The simulator models the negotiation: satisfy a need and re-run, the
// way an applicant would supply it and re-present.
// ---------------------------------------------------------------------------

/** The `needs` array from a request_more verdict, as strings. */
function verdictNeeds(verdict: Verdict | null): string[] {
  const needs = verdict?.with?.needs;
  return Array.isArray(needs) ? needs.map(String) : [];
}

/** A need the simulator knows how to satisfy by patching the facts. */
function isSatisfiable(need: string): boolean {
  const kind = need.split(":")[0];
  return ["agreed", "cred", "credential", "trusted"].includes(kind ?? "");
}

type Facts = Record<string, unknown>;

/** Apply a satisfied need to the facts — e.g. `agreed:code-of-conduct`
 * sets the agreement flag; `trusted:WitnessCredential` adds a trusted
 * credential to the presentation. */
function satisfyNeed(facts: Facts, need: string): Facts {
  const f = structuredClone(facts) as Facts;
  const [kind, ...rest] = need.split(":");
  const arg = rest.join(":");
  const evidence = (f.evidence ??= {}) as Record<string, unknown>;
  if (kind === "agreed") {
    const request = (evidence.request ??= {}) as Record<string, unknown>;
    request.agreements = {
      ...((request.agreements as Record<string, unknown>) ?? {}),
      [arg]: true,
    };
  } else if (kind === "cred" || kind === "credential" || kind === "trusted") {
    const subject = f.subject as { did?: string } | undefined;
    const presentation = (evidence.presentation ??= {
      verified: true,
      holder: subject?.did,
      credentials: [],
    }) as Record<string, unknown>;
    presentation.credentials = [
      ...((presentation.credentials as unknown[]) ?? []),
      {
        type: arg,
        issuer: "did:example:satisfied",
        issuer_trusted: true,
        status: "valid",
        claims: {},
      },
    ];
  }
  return f;
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

export function Ceremonies() {
  // The daemon is the source of truth for the ceremony registry.
  const query = useQuery({ queryKey: ["ceremonies"], queryFn: fetchCeremonies });
  const ceremonies = query.data ?? [];
  const [active, setActive] = useState<string>("");

  // Default to the first ceremony once the registry loads.
  useEffect(() => {
    if (!active && ceremonies[0]) setActive(ceremonies[0].purpose);
  }, [ceremonies, active]);

  const ceremony = ceremonies.find((c) => c.purpose === active) ?? null;

  return (
    <div style={{ maxWidth: 1180 }}>
      <div className="cer-kicker">Verifiable Trust Community · Pipeline</div>
      <h1 className="cer-h1">
        One pipeline, every <em>ceremony</em>
      </h1>
      <p className="cer-sub">
        Joining, leaving, directory lookups, role changes — each community
        state transition is an instance of one decision pipeline. Pick a
        ceremony to see its flow, manage its decision policy, and dry-run the
        live verdict the daemon would reach.
      </p>

      {query.isLoading && <p className="cer-sub">Loading the registry…</p>}
      {query.error && (
        <p className="cer-sub" style={{ color: "var(--vd-deny)" }}>
          {(query.error as Error).message}
        </p>
      )}

      <div className="cer-tabs" role="tablist">
        {ceremonies.map((c) => (
          <button
            key={c.purpose}
            role="tab"
            aria-selected={c.purpose === active}
            className={`cer-tab${c.purpose === active ? " on" : ""}`}
            onClick={() => setActive(c.purpose)}
          >
            <span
              className="nature"
              style={{ color: natureColor[c.nature] }}
              aria-hidden
            />
            {c.label}
            <small>{c.nature}</small>
          </button>
        ))}
        <button
          role="tab"
          aria-selected={active === "other"}
          className={`cer-tab${active === "other" ? " on" : ""}`}
          onClick={() => setActive("other")}
        >
          <span
            className="nature"
            style={{ color: "var(--text-faint)" }}
            aria-hidden
          />
          Other policies
          <small>no ceremony</small>
        </button>
      </div>

      {active === "other" ? (
        <OtherPolicies />
      ) : ceremony ? (
        <CeremonyPanel key={ceremony.purpose} ceremony={ceremony} />
      ) : null}
    </div>
  );
}

function CeremonyPanel({ ceremony }: { ceremony: CeremonyManifest }) {
  const [form, setForm] = useState<FieldValues>(() => defaultValues(ceremony));
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [phase, setPhase] = useState(-1);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authoring, setAuthoring] = useState(false);
  // Needs the operator has chosen to satisfy for the request_more loop.
  const [satisfied, setSatisfied] = useState<string[]>([]);
  // The facts that produced the current verdict — fed to the trace.
  const [lastFacts, setLastFacts] = useState<ExplainFacts | null>(null);
  // Advanced: edit the verified-Facts JSON directly, overriding the
  // field-driven template (for facts the declared toggles don't cover).
  const [rawMode, setRawMode] = useState(false);
  const [rawText, setRawText] = useState("");

  const policyQuery = useQuery({
    queryKey: ["active-policy", ceremony.purpose],
    queryFn: () => fetchActivePolicy(ceremony.purpose as Purpose),
  });

  // Reset the form + verdict whenever the ceremony changes.
  useEffect(() => {
    setForm(defaultValues(ceremony));
    setVerdict(null);
    setError(null);
    setPhase(-1);
    setAuthoring(false);
    setSatisfied([]);
    setLastFacts(null);
    setRawMode(false);
  }, [ceremony]);

  const seedRaw = () =>
    JSON.stringify(materializeFacts(ceremony.factsTemplate, form), null, 2);

  // The active policy's IR, when it was authored visually — enables the
  // local decision trace.
  const activeIR = policyQuery.data
    ? parseRego(policyQuery.data.module)
    : null;

  // Editing the base evidence invalidates any satisfied needs.
  const onFieldsChange = (v: FieldValues) => {
    setForm(v);
    setSatisfied([]);
  };
  const toggleNeed = (need: string) =>
    setSatisfied((s) =>
      s.includes(need) ? s.filter((n) => n !== need) : [...s, need],
    );

  const canSimulate = ceremony.wired === "live";

  async function run() {
    const policy = policyQuery.data;
    if (!policy) return;

    // Build the facts up front so a raw-JSON parse error fails fast,
    // before the animation starts.
    let facts: Record<string, unknown>;
    if (rawMode) {
      try {
        facts = JSON.parse(rawText) as Record<string, unknown>;
      } catch {
        setError("Raw facts are not valid JSON.");
        return;
      }
    } else {
      facts = materializeFacts(ceremony.factsTemplate, form);
    }
    for (const need of satisfied) facts = satisfyNeed(facts, need);

    setRunning(true);
    setVerdict(null);
    setError(null);
    setLastFacts(facts as ExplainFacts);

    // Animate the token across the stages while the request is in flight.
    for (let i = 0; i < STAGES.length; i++) {
      setTimeout(() => setPhase(i), i * 110);
    }

    try {
      const resp = await postJson<TestResponse>(
        `/v1/policies/${policy.id}/test`,
        { query: `data.${ceremony.pkg}.decision`, input: facts },
        { trustTask: TRUST_TASK_TEST },
      );
      const v = pluckDecision(resp);
      // Land the verdict as the token reaches the Verdict stage.
      window.setTimeout(
        () => {
          if (v) setVerdict(v);
          else
            setError(
              "The active policy produced no decision — it may still be the legacy boolean shape rather than a decision spine.",
            );
          setPhase(-1);
          setRunning(false);
        },
        STAGES.length * 110 + 120,
      );
    } catch (e) {
      const err = e as { message?: string };
      setError(err.message ?? "policy test failed");
      setPhase(-1);
      setRunning(false);
    }
  }

  return (
    <>
      <p className="cer-sub" style={{ marginTop: "var(--space-5)" }}>
        {ceremony.blurb}
      </p>

      <div className="cer-meta-row">
        <span className="cer-chip">
          purpose <b>{ceremony.purpose}</b>
        </span>
        <span className="cer-chip">
          package <b>{ceremony.pkg}</b>
        </span>
        <span className="cer-chip">
          status{" "}
          <b
            style={{
              color:
                ceremony.wired === "live"
                  ? "var(--vd-allow)"
                  : ceremony.wired === "legacy"
                    ? "var(--vd-refer)"
                    : "var(--text-faint)",
            }}
          >
            {ceremony.wired === "live"
              ? "decision pipeline"
              : ceremony.wired === "legacy"
                ? "legacy boolean policy"
                : "not yet wired"}
          </b>
        </span>
      </div>

      <div className="card" style={{ marginTop: "var(--space-5)", padding: 0 }}>
        <div style={{ padding: "var(--space-4) var(--space-4) 0" }}>
          <FlowDiagram phase={phase} verdict={verdict} />
        </div>
        <div style={{ padding: "0 var(--space-4) var(--space-4)" }}>
          <div className="cer-outcomes">
            {EFFECTS.map((e) => (
              <div
                key={e.key}
                className={`cer-oc ${e.key}${
                  verdict?.effect === e.key ? " lit" : ""
                }`}
              >
                <div className="oc-h">
                  <span className="dot" />
                  {e.label}
                </div>
                <div className="oc-d">{e.blurb}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className={`cer-work${authoring ? " authoring" : ""}`}>
        {/* Simulator */}
        <div className="card">
          <div className="cer-panel-title">
            Simulate <span className="ln" />
          </div>

          {!canSimulate ? (
            <p className="cer-sub">
              {ceremony.wired === "legacy"
                ? "This ceremony still runs the legacy boolean policy — dry-run lands with its decision-pipeline migration."
                : "This ceremony isn't wired into the executor yet, so there's no decision policy to dry-run."}
            </p>
          ) : (
            <>
              {rawMode ? (
                <RawFactsEditor
                  value={rawText}
                  onChange={setRawText}
                  onReset={() => setRawText(seedRaw())}
                  onUseFields={() => setRawMode(false)}
                />
              ) : (
                <>
                  <SimFields
                    fields={ceremony.fields}
                    values={form}
                    onChange={onFieldsChange}
                  />
                  <button
                    type="button"
                    className="cer-raw-toggle"
                    onClick={() => {
                      setRawText(seedRaw());
                      setRawMode(true);
                    }}
                  >
                    Advanced: edit raw facts ▸
                  </button>
                </>
              )}

              <button
                className="cer-run"
                onClick={run}
                disabled={running || policyQuery.isLoading || !policyQuery.data}
              >
                {running ? "Evaluating…" : "Run decision ▸"}
              </button>

              {error && (
                <div
                  className="cer-verdict"
                  style={{ borderColor: "var(--vd-deny)" }}
                >
                  <span className="cer-vbadge deny">error</span>
                  <div className="cer-vwith">{error}</div>
                </div>
              )}

              {verdict && !error && (
                <>
                  <div className="cer-verdict">
                    <span className={`cer-vbadge ${verdict.effect}`}>
                      {verdict.effect}
                    </span>
                    <div className="cer-vwith">
                      {verdict.with
                        ? JSON.stringify(verdict.with, null, 2)
                        : "{}"}
                    </div>
                  </div>
                  {verdict.effect === "request_more" && (
                    <NeedsLoop
                      needs={verdictNeeds(verdict)}
                      satisfied={satisfied}
                      onToggle={toggleNeed}
                      onRerun={run}
                      running={running}
                    />
                  )}
                  {verdict.effect === "refer" &&
                    typeof verdict.with?.queue === "string" && (
                      <ReferQueue queue={verdict.with.queue as string} />
                    )}
                  {activeIR && lastFacts && (
                    <DecisionTrace
                      ir={activeIR}
                      facts={lastFacts}
                      verdictEffect={verdict.effect}
                    />
                  )}
                </>
              )}
            </>
          )}
        </div>

        {/* Decision policy — source + versions + activate + upload */}
        <div className="card cer-policy-panel">
          <div className="cer-panel-title">
            Decision policy <span className="ln" />
          </div>
          <PolicyManager
            key={ceremony.purpose}
            purpose={ceremony.purpose as Purpose}
            onEditingChange={setAuthoring}
          />
        </div>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Policy management — source + version history + activate + upload. Used
// per-ceremony (the right panel) and for the non-ceremony purposes.
// ---------------------------------------------------------------------------

/** Rego package for a ceremony purpose (role-change → role_change). */
function pkgFor(purpose: Purpose): string {
  return `vtc.${purpose === "roleChange" ? "role_change" : purpose}`;
}

// Active policy source — a plain-English summary when it was authored
// visually (carries the IR header), with a toggle to the raw Rego. A
// hand-written policy shows only the Rego.
function ActivePolicyView({ source }: { source: string }) {
  const ir = parseRego(source);
  const [view, setView] = useState<"english" | "rego">(
    ir ? "english" : "rego",
  );
  if (!ir) return <pre className="cer-policy">{source}</pre>;
  return (
    <>
      <div className="rule-view-tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={view === "english"}
          className={view === "english" ? "on" : ""}
          onClick={() => setView("english")}
        >
          Plain English
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={view === "rego"}
          className={view === "rego" ? "on" : ""}
          onClick={() => setView("rego")}
        >
          Rego
        </button>
      </div>
      {view === "english" ? (
        <EnglishView lines={irToEnglish(ir)} />
      ) : (
        <pre className="cer-policy">{source}</pre>
      )}
    </>
  );
}

function PolicyManager({
  purpose,
  onEditingChange,
}: {
  purpose: Purpose;
  /** Notifies the parent so it can widen the layout for the editor. */
  onEditingChange?: (editing: boolean) => void;
}) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [showUpload, setShowUpload] = useState(false);
  const [editing, setEditingState] = useState(false);
  const setEditing = (v: boolean) => {
    setEditingState(v);
    onEditingChange?.(v);
  };

  const query = useQuery({
    queryKey: ["policies", purpose],
    queryFn: () => fetchPolicies(purpose),
  });

  // Which revision is live is now a separate canonical task
  // (policy/active) rather than an isActive flag on each module.
  const activeQuery = useQuery({
    queryKey: ["active-policy", purpose],
    queryFn: () => fetchActivePolicy(purpose),
  });

  const activate = useMutation({
    mutationFn: activatePolicy,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["policies", purpose] });
      void qc.invalidateQueries({ queryKey: ["active-policy", purpose] });
    },
  });

  const saveVisual = useMutation({
    mutationFn: (rego: string) => uploadPolicy({ purpose, regoSource: rego }),
    onSuccess: () => {
      setEditing(false);
      void qc.invalidateQueries({ queryKey: ["policies", purpose] });
    },
  });

  // Fail-forward rollback: never rewind the chain — copy the chosen
  // revision's source into a NEW revision and activate that. History
  // only ever grows; the active pointer always moves forward.
  const rollback = useMutation({
    mutationFn: async (row: PolicyRow) => {
      const created = await uploadPolicy({
        purpose,
        regoSource: row.module,
      });
      await activatePolicy(created.id);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["policies", purpose] });
      void qc.invalidateQueries({ queryKey: ["active-policy", purpose] });
    },
  });

  const items: PolicyRow[] = query.data?.policies ?? [];
  // Activeness is no longer a flag on the module: the active binding
  // comes from its own query (policy/active).
  const active = activeQuery.data ?? null;
  const canAuthor = CEREMONY_PURPOSES.includes(purpose);

  if (editing) {
    return (
      <RuleEditor
        purpose={purpose}
        pkg={pkgFor(purpose)}
        initial={
          (active && parseRego(active.module)) || blankIR(purpose)
        }
        saving={saveVisual.isPending}
        onSave={(rego) => saveVisual.mutate(rego)}
        onCancel={() => setEditing(false)}
      />
    );
  }

  return (
    <>
      {query.isLoading && <p className="cer-sub">Loading…</p>}
      {query.error && (
        <p className="cer-sub" style={{ color: "var(--vd-deny)" }}>
          {(query.error as Error).message}
        </p>
      )}

      {active && (
        <>
          <div
            className="cer-meta-row"
            style={{ marginTop: 0, marginBottom: "var(--space-3)" }}
          >
            <span className="cer-chip">
              active <b>v{active.version}</b>
            </span>
            {active.ext?.["org.openvtc.sha256"] && (
              <span className="cer-chip">
                sha <b>{active.ext["org.openvtc.sha256"].slice(0, 12)}…</b>
              </span>
            )}
          </div>
          <ActivePolicyView source={active.module} />
        </>
      )}
      {!query.isLoading && !active && (
        <p className="cer-sub">No active policy for this purpose.</p>
      )}

      {/* Version history */}
      {items.length > 0 && (
        <>
          <div
            className="cer-panel-title"
            style={{ marginTop: "var(--space-4)" }}
          >
            Versions <span className="ln" />
          </div>
          <div className="cer-versions">
            {items.map((p) => (
              <VersionRow
                key={p.id}
                row={p}
                active={active}
                purpose={purpose}
                busy={activate.isPending || rollback.isPending}
                onActivate={async () => {
                  const ok = await confirm({
                    title: `Activate ${purpose} v${p.version}?`,
                    message: `The current active policy for "${purpose}" becomes archived.`,
                    confirmLabel: "Activate",
                  });
                  if (ok) activate.mutate(p.id);
                }}
                onRollback={async () => {
                  const ok = await confirm({
                    title: `Roll back ${purpose} to v${p.version}?`,
                    message: `Fail-forward: v${p.version}'s content is copied into a new revision and activated. The chain isn't rewound.`,
                    confirmLabel: "Roll back",
                  });
                  if (ok) rollback.mutate(p);
                }}
              />
            ))}
          </div>
        </>
      )}

      {canAuthor && (
        <>
          <button
            type="button"
            className="cer-run"
            style={{ marginTop: "var(--space-4)" }}
            onClick={() => setEditing(true)}
          >
            Author visually ▸
          </button>
          {active && !parseRego(active.module) && (
            <p className="cer-sub" style={{ fontSize: "var(--text-xs)" }}>
              The active policy was hand-written — opening the editor starts
              from a blank route set.
            </p>
          )}
        </>
      )}

      <button
        type="button"
        className="rule-cancel"
        style={{ marginTop: "var(--space-3)" }}
        onClick={() => setShowUpload((v) => !v)}
      >
        {showUpload ? "Cancel" : "Upload raw Rego"}
      </button>
      {showUpload && (
        <UploadPolicyForm
          purpose={purpose}
          onDone={() => {
            setShowUpload(false);
            void qc.invalidateQueries({ queryKey: ["policies", purpose] });
          }}
        />
      )}
    </>
  );
}

// One row in the version history. A non-active row can be compared to
// the live policy (route-level diff) and either activated (a newer
// draft) or rolled back to (an older revision, fail-forward).
function VersionRow({
  row,
  active,
  purpose,
  busy,
  onActivate,
  onRollback,
}: {
  row: PolicyRow;
  active: PolicyRow | null;
  purpose: Purpose;
  busy: boolean;
  onActivate: () => void;
  onRollback: () => void;
}) {
  const [comparing, setComparing] = useState(false);
  const isOlder = active ? row.version < active.version : false;
  const isActive = active?.id === row.id;

  return (
    <div className={`cer-ver${isActive ? " active" : ""}`}>
      <div className="cer-ver-head">
        <span className="cer-ver-v">v{row.version}</span>
        <span className="cer-ver-meta">{formatIso(row.createdAt)}</span>
        {isActive ? (
          <span className="cer-chip" style={{ color: "var(--vd-allow)" }}>
            active
          </span>
        ) : (
          <>
            {active && !isActive && (
              <button
                type="button"
                className="cer-ver-compare"
                aria-expanded={comparing}
                onClick={() => setComparing((v) => !v)}
              >
                {comparing ? "Hide diff" : "Compare ▾"}
              </button>
            )}
            <button
              type="button"
              className="cer-ver-activate"
              disabled={busy}
              onClick={isOlder ? onRollback : onActivate}
            >
              {isOlder ? "Roll back" : "Activate"}
            </button>
          </>
        )}
      </div>
      {comparing && active && (
        <VersionDiff purpose={purpose} from={active} to={row} />
      )}
    </div>
  );
}

// The route-level diff between the live policy and another revision —
// "what changes if this becomes active". Falls back to a note when
// either side wasn't authored visually (no IR to compare).
function VersionDiff({
  purpose,
  from,
  to,
}: {
  purpose: Purpose;
  from: PolicyRow;
  to: PolicyRow;
}) {
  const fromIr = parseRego(from.module);
  const toIr = parseRego(to.module);
  if (!fromIr || !toIr) {
    return (
      <p className="cer-sub" style={{ fontSize: "var(--text-xs)" }}>
        A structured diff needs both revisions authored visually — one here
        is hand-written Rego.
      </p>
    );
  }
  const diffs = diffIR(fromIr, toIr);
  const changed = diffs.filter((d) => d.status !== "unchanged");
  return (
    <div className="cer-diff">
      <div className="cer-diff-head">
        v{from.version} <span aria-hidden>→</span> v{to.version}
      </div>
      {changed.length === 0 ? (
        <p className="cer-sub" style={{ fontSize: "var(--text-xs)" }}>
          No route-level changes — the decision is identical.
        </p>
      ) : (
        changed.map((d) => (
          <div key={`${purpose}-${d.name}`} className={`diff-route ${d.status}`}>
            <span className="diff-mark" aria-hidden>
              {d.status === "added" ? "+" : d.status === "removed" ? "−" : "~"}
            </span>
            <div className="diff-body">
              <span className="diff-name">{d.name}</span>
              {d.status === "added" && <em> route added</em>}
              {d.status === "removed" && <em> route removed</em>}
              {d.changes.map((c, i) => (
                <span key={i} className="diff-change">
                  {c}
                </span>
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

function UploadPolicyForm({
  purpose,
  onDone,
}: {
  purpose: Purpose;
  onDone: () => void;
}) {
  const [source, setSource] = useState("");
  const mutation = useMutation({
    mutationFn: () => uploadPolicy({ purpose, regoSource: source }),
    onSuccess: onDone,
  });

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        mutation.mutate();
      }}
      style={{ marginTop: "var(--space-3)" }}
    >
      <p className="cer-sub" style={{ marginBottom: "var(--space-2)" }}>
        Uploading does not activate — the revision is archived until you
        activate it above.
      </p>
      <textarea
        rows={10}
        spellCheck={false}
        className="cer-rego-input"
        placeholder={`package vtc.${purpose}\n\nimport rego.v1\n\ndefault decision := {"effect": "deny", "with": {"code": "no-matching-route"}}`}
        value={source}
        onChange={(e) => setSource(e.target.value)}
      />
      {mutation.error && (
        <p className="cer-sub" style={{ color: "var(--vd-deny)" }}>
          {(mutation.error as Error).message}
        </p>
      )}
      <button
        type="submit"
        className="cer-run"
        disabled={mutation.isPending || source.trim().length === 0}
      >
        {mutation.isPending ? "Compiling…" : "Upload"}
      </button>
    </form>
  );
}

function OtherPolicies() {
  const [purpose, setPurpose] = useState<Purpose>(OTHER_PURPOSES[0]!);
  return (
    <>
      <p className="cer-sub" style={{ marginTop: "var(--space-5)" }}>
        Policy purposes that aren't (yet) first-class ceremonies — managed
        the same way, without a flow or simulator.
      </p>
      <div className="cer-tabs" style={{ marginTop: "var(--space-4)" }}>
        {OTHER_PURPOSES.map((p) => (
          <button
            key={p}
            className={`cer-tab${p === purpose ? " on" : ""}`}
            onClick={() => setPurpose(p)}
          >
            {p}
          </button>
        ))}
      </div>
      <div className="card" style={{ marginTop: "var(--space-4)" }}>
        <div className="cer-panel-title">
          {purpose} <span className="ln" />
        </div>
        <PolicyManager purpose={purpose} />
      </div>
    </>
  );
}

// Generic simulator form — renders a ceremony's declared fields. A
// `select` becomes a dropdown, a `toggle` a switch; a field with a
// `showWhen` predicate only renders when it holds (dependent fields).
function SimFields({
  fields,
  values,
  onChange,
}: {
  fields: FieldDef[];
  values: FieldValues;
  onChange: (v: FieldValues) => void;
}) {
  return (
    <>
      {fields
        .filter((f) => evalShowWhen(f.showWhen, values))
        .map((f) => (
          <div className="cer-field" key={f.key}>
            <label>
              {f.label}
              {f.hint && <small>{f.hint}</small>}
            </label>
            {f.type === "toggle" ? (
              <Toggle
                on={values[f.key] === true}
                onClick={() =>
                  onChange({ ...values, [f.key]: values[f.key] !== true })
                }
              />
            ) : (
              <select
                className="input"
                value={String(values[f.key] ?? "")}
                onChange={(e) =>
                  onChange({ ...values, [f.key]: e.target.value })
                }
              >
                {f.options?.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            )}
          </div>
        ))}
    </>
  );
}

// A refer verdict routes to a queue. When that queue maps to an admin
// surface (the moderator queue → the join-requests inbox), link to it
// and show how many items are waiting — closing the loop from "this
// would be referred" to "go act on it".
function ReferQueue({ queue }: { queue: string }) {
  const link = QUEUE_LINKS[queue];
  const pending = useQuery({
    queryKey: ["pending-count", queue],
    queryFn: fetchPendingCount,
    enabled: !!link,
  });
  return (
    <div className="cer-refer">
      <span className="cer-refer-q">
        → routes to the <b>{queue}</b> queue
      </span>
      {link && (
        <Link to={link.to} className="cer-refer-link">
          {link.label}
          {pending.data !== undefined ? ` · ${pending.data} pending` : ""} ▸
        </Link>
      )}
    </div>
  );
}

// The request_more negotiation, in miniature: the verdict listed what
// it needs; the operator satisfies the ones the simulator understands
// and re-runs, modelling the applicant supplying the evidence.
function NeedsLoop({
  needs,
  satisfied,
  onToggle,
  onRerun,
  running,
}: {
  needs: string[];
  satisfied: string[];
  onToggle: (need: string) => void;
  onRerun: () => void;
  running: boolean;
}) {
  const anySelected = needs.some(
    (n) => isSatisfiable(n) && satisfied.includes(n),
  );
  return (
    <div className="cer-needs">
      <div className="cer-needs-title">Satisfy to continue</div>
      {needs.map((n) => {
        const ok = isSatisfiable(n);
        return (
          <label
            key={n}
            className={`cer-need${ok ? "" : " unsupported"}`}
            title={ok ? undefined : "The simulator can't auto-satisfy this need"}
          >
            <input
              type="checkbox"
              disabled={!ok}
              checked={ok && satisfied.includes(n)}
              onChange={() => onToggle(n)}
            />
            <code>{n}</code>
            {!ok && <span className="cer-need-note">manual</span>}
          </label>
        );
      })}
      <button
        type="button"
        className="cer-run"
        style={{ marginTop: "var(--space-2)" }}
        onClick={onRerun}
        disabled={running || !anySelected}
      >
        {running ? "Evaluating…" : "Re-run with satisfied evidence ▸"}
      </button>
    </div>
  );
}

// "Why this verdict" — the local first-match trace over the active
// policy's routes: which conditions held, which route fired. Derived
// from the IR, so it explains visually-authored policies; a note flags
// the rare case where the live Rego was hand-edited away from its IR.
function DecisionTrace({
  ir,
  facts,
  verdictEffect,
}: {
  ir: RuleIR;
  facts: ExplainFacts;
  verdictEffect: Effect;
}) {
  const trace = explainDecision(ir, facts);
  const drift = trace.fired ? trace.fired.effect !== verdictEffect : true;
  return (
    <div className="cer-trace">
      <div className="cer-trace-title">Why this verdict</div>
      {trace.routes.map((r, i) => (
        <div
          key={i}
          className={`trace-route eff-${r.effect}${r.fired ? " fired" : ""}${
            !r.reached ? " skipped" : ""
          }`}
        >
          <div className="trace-head">
            <span className="trace-mark" aria-hidden>
              {r.fired ? "▶" : r.reached ? "·" : "⌀"}
            </span>
            <span className="trace-name">{r.name}</span>
            {r.fired && <span className="trace-fired">fired</span>}
            {!r.reached && <span className="trace-note">not reached</span>}
          </div>
          {r.reached && !r.isCatchAll && (
            <ul className="trace-conds">
              {r.conditions.map((c, j) => (
                <li key={j} className={c.passed ? "pass" : "fail"}>
                  <span aria-hidden>{c.passed ? "✓" : "✗"}</span> {c.label}
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}
      {drift && (
        <p className="cer-trace-drift">
          The live verdict differs from this trace — the active policy may
          have been hand-edited away from its visual form.
        </p>
      )}
    </div>
  );
}

// Advanced simulator input: the verified-Facts JSON, edited directly.
// Overrides the field-driven template, for evidence the declared
// toggles don't model (extra credentials, custom claims, edge shapes).
function RawFactsEditor({
  value,
  onChange,
  onReset,
  onUseFields,
}: {
  value: string;
  onChange: (v: string) => void;
  onReset: () => void;
  onUseFields: () => void;
}) {
  let invalid = false;
  try {
    JSON.parse(value);
  } catch {
    invalid = true;
  }
  return (
    <div className="cer-raw">
      <p className="cer-sub" style={{ fontSize: "var(--text-xs)" }}>
        This JSON is sent to the policy verbatim — the field toggles are
        ignored. Seeded from the current fields.
      </p>
      <textarea
        className="cer-rego-input"
        rows={14}
        spellCheck={false}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-invalid={invalid}
      />
      {invalid && (
        <p className="cer-sub" style={{ color: "var(--vd-deny)" }}>
          Not valid JSON.
        </p>
      )}
      <div className="rule-actions">
        <button type="button" className="rule-cancel" onClick={onReset}>
          Reset to fields
        </button>
        <button type="button" className="rule-cancel" onClick={onUseFields}>
          Use fields ▸
        </button>
      </div>
    </div>
  );
}

function Toggle({ on, onClick }: { on: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      onClick={onClick}
      className="cer-toggle"
      style={{
        width: 42,
        height: 23,
        borderRadius: 999,
        border: `1px solid ${on ? "var(--brand)" : "var(--border-strong)"}`,
        background: on ? "var(--brand-tint-strong)" : "var(--bg-subtle)",
        position: "relative",
        cursor: "pointer",
        transition: "all var(--motion-fast)",
        flex: "none",
      }}
    >
      <span
        style={{
          position: "absolute",
          top: 2,
          left: on ? 21 : 2,
          width: 17,
          height: 17,
          borderRadius: "50%",
          background: on ? "var(--brand)" : "var(--text-faint)",
          transition: "all var(--motion-fast)",
        }}
      />
    </button>
  );
}

// Inline SVG pipeline flow. Seven stage nodes, an edge between each,
// and a token that lights nodes as it travels. The Evaluate node goes
// hot while the policy runs; the matching outcome lights below.
function FlowDiagram({
  phase,
  verdict,
}: {
  phase: number;
  verdict: Verdict | null;
}) {
  const n = STAGES.length;
  const W = 1080;
  const H = 120;
  const padX = 20;
  const boxW = 124;
  const boxH = 48;
  const gap = (W - padX * 2 - boxW * n) / (n - 1);
  const y = 36;

  const xOf = (i: number) => padX + i * (boxW + gap);
  const tokenIdx = phase >= 0 ? phase : -1;
  const effClass = verdict
    ? `vd-${verdict.effect === "request_more" ? "more" : verdict.effect}`
    : "";

  return (
    <svg
      className="cer-flow"
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label="Decision pipeline flow"
    >
      <defs>
        <marker
          id="cer-arrow"
          viewBox="0 0 8 8"
          refX="6"
          refY="4"
          markerWidth="6"
          markerHeight="6"
          orient="auto-start-reverse"
        >
          <path d="M0,0 L8,4 L0,8 z" />
        </marker>
      </defs>
      {/* edges */}
      {STAGES.slice(0, -1).map((_, i) => {
        const x1 = xOf(i) + boxW;
        const x2 = xOf(i + 1);
        return (
          <line
            key={`e${i}`}
            className="edge"
            x1={x1}
            y1={y + boxH / 2}
            x2={x2 - 3}
            y2={y + boxH / 2}
            markerEnd="url(#cer-arrow)"
          />
        );
      })}
      {/* nodes */}
      {STAGES.map((s, i) => {
        const x = xOf(i);
        // During the run the token heats each node; once a verdict
        // lands, Evaluate stays hot and the Verdict node (and Effects,
        // for an allow) take the verdict's colour.
        let cls = "node-box";
        if (tokenIdx === i) cls += " hot";
        if (verdict) {
          if (i === 4) cls += " hot";
          if (i === 5) cls += ` ${effClass}`;
          if (i === 6 && verdict.effect === "allow") cls += ` ${effClass}`;
        }
        return (
          <g key={s}>
            <rect
              className={cls}
              x={x}
              y={y}
              width={boxW}
              height={boxH}
              rx={11}
            />
            <text
              className="node-t"
              x={x + boxW / 2}
              y={y + boxH / 2 + 1}
              textAnchor="middle"
              dominantBaseline="middle"
            >
              {s}
            </text>
            <text
              className="stage-label"
              x={x + boxW / 2}
              y={y + boxH + 14}
              textAnchor="middle"
            >
              {i === 0
                ? "actor"
                : i === 2
                  ? "host crypto"
                  : i === 4
                    ? `${"<purpose>"}.rego`
                    : i === 6
                      ? "issue / revoke"
                      : ""}
            </text>
          </g>
        );
      })}
      {/* token */}
      {tokenIdx >= 0 && (
        <circle
          className="token"
          r={6}
          cx={xOf(tokenIdx) + boxW / 2}
          cy={y + boxH / 2}
        />
      )}
    </svg>
  );
}
