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

import { postJson } from "@/lib/api";
import { useConfirm } from "@/components/ConfirmDialog";
import { formatIso } from "@/lib/format";
import {
  type Purpose,
  CEREMONY_PURPOSES,
  OTHER_PURPOSES,
  activatePolicy,
  fetchActivePolicy,
  fetchPolicies,
  uploadPolicy,
} from "@/lib/policies-api";
import { blankIR, parseRego } from "@/lib/rule-ir";
import { RuleEditor } from "@/plugins/RuleEditor";

const TRUST_TASK_TEST = "https://trusttasks.org/openvtc/vtc/policies/test/1.0";

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

type CeremonyKey = "directory" | "join" | "leave" | "role-change";
type Wired = "live" | "legacy" | "unwired";

interface Ceremony {
  key: CeremonyKey;
  label: string;
  nature: string;
  /** API policy purpose key, or null when the ceremony has no policy. */
  purpose: string | null;
  /** Rego package whose `decision` rule the host evaluates. */
  pkg: string;
  wired: Wired;
  blurb: string;
}

const CEREMONIES: Ceremony[] = [
  {
    key: "directory",
    label: "Directory",
    nature: "read-only",
    purpose: "directory",
    pkg: "vtc.directory",
    wired: "live",
    blurb:
      "A member views another member's record. Read-only — the verdict's allow carries a field projection, capped by the PII boundary.",
  },
  {
    key: "join",
    label: "Join",
    nature: "constructive",
    purpose: "join",
    pkg: "vtc.join",
    wired: "live",
    blurb:
      "A DID joins the community. A trusted presented credential auto-admits (allow → issue the membership credential); everything else is referred to the moderator queue for review.",
  },
  {
    key: "leave",
    label: "Leave",
    nature: "destructive",
    purpose: "removal",
    pkg: "vtc.removal",
    wired: "live",
    blurb:
      "A member departs or is removed. Self-leave is unconditional; an admin may remove a non-admin. The no-last-admin invariant + revocation are host-enforced in the effect.",
  },
  {
    key: "role-change",
    label: "Role change",
    nature: "mutating",
    purpose: "roleChange",
    pkg: "vtc.role_change",
    wired: "live",
    blurb:
      "A member's role changes in place (the DID + VMC are unchanged; the role VEC is re-minted). The one ceremony whose allow may grant admin — gated by a verified step-up; demotions are guarded by no-last-admin.",
  },
];

const natureColor: Record<string, string> = {
  "read-only": "var(--brand)",
  constructive: "var(--vd-allow)",
  destructive: "var(--vd-deny)",
  mutating: "var(--vd-refer)",
};

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
// Facts assembly — a compact, ceremony-specific editor produces the
// verified-Facts document the policy decides over.
// ---------------------------------------------------------------------------

interface FormState {
  // directory
  viewerRole: string;
  subjectIsMember: boolean;
  subjectRole: string;
  // leave
  selfLeave: boolean;
  // role-change
  targetRole: string;
  stepUp: boolean;
  // join
  joinTrusted: boolean;
}

const DEFAULT_FORM: FormState = {
  viewerRole: "member",
  subjectIsMember: true,
  subjectRole: "member",
  selfLeave: false,
  targetRole: "moderator",
  stepUp: false,
  joinTrusted: false,
};

function buildFacts(c: Ceremony, f: FormState): Record<string, unknown> {
  const now = new Date().toISOString();
  const context = {
    community_did: "did:webvh:demo.example",
    channel: "rest",
    member_count: 42,
  };

  if (c.key === "directory") {
    return {
      purpose: "directory",
      now,
      actor: {
        did: "did:key:zViewer",
        role: f.viewerRole || undefined,
        authenticated: true,
      },
      subject: { did: "did:key:zTarget" },
      context,
      evidence: {
        request: { fields_requested: ["did", "role", "joined_at", "status"] },
      },
      state: {
        subject_member: f.subjectIsMember
          ? {
              role: f.subjectRole,
              status: "active",
              joined_at: "2026-01-02T00:00:00Z",
            }
          : null,
      },
    };
  }

  if (c.key === "join") {
    return {
      purpose: "join",
      now,
      actor: { did: "did:key:zApplicant", authenticated: true },
      subject: { did: "did:key:zApplicant" },
      context,
      evidence: {
        presentation: {
          verified: true,
          holder: "did:key:zApplicant",
          credentials: [
            {
              type: "WitnessCredential",
              issuer: "did:webvh:notary.example",
              issuer_trusted: f.joinTrusted,
              status: "valid",
              claims: {},
            },
          ],
        },
      },
      state: { subject_member: null },
    };
  }

  if (c.key === "role-change") {
    return {
      purpose: "role-change",
      now,
      actor: { did: "did:key:zAdmin", role: "admin", authenticated: true },
      subject: { did: "did:key:zTarget" },
      context,
      evidence: {
        request: { target_role: f.targetRole, step_up: f.stepUp },
      },
      state: {
        subject_member: {
          role: "member",
          status: "active",
          joined_at: "2026-01-02T00:00:00Z",
        },
      },
    };
  }

  // leave
  const actorDid = "did:key:zActor";
  const subjectDid = f.selfLeave ? actorDid : "did:key:zTarget";
  return {
    purpose: "leave",
    now,
    actor: { did: actorDid, role: "admin", authenticated: true },
    subject: { did: subjectDid },
    context,
    evidence: { request: { disposition: "tombstone" } },
    state: {
      subject_member: {
        role: f.subjectRole,
        status: "active",
        joined_at: "2026-01-02T00:00:00Z",
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

export function Ceremonies() {
  const [active, setActive] = useState<CeremonyKey | "other">("directory");
  const ceremony = CEREMONIES.find((c) => c.key === active);

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

      <div className="cer-tabs" role="tablist">
        {CEREMONIES.map((c) => (
          <button
            key={c.key}
            role="tab"
            aria-selected={c.key === active}
            className={`cer-tab${c.key === active ? " on" : ""}`}
            onClick={() => setActive(c.key)}
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

      {ceremony ? <CeremonyPanel ceremony={ceremony} /> : <OtherPolicies />}
    </div>
  );
}

function CeremonyPanel({ ceremony }: { ceremony: Ceremony }) {
  const [form, setForm] = useState<FormState>(DEFAULT_FORM);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [phase, setPhase] = useState(-1);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const policyQuery = useQuery({
    queryKey: ["active-policy", ceremony.purpose],
    queryFn: () => fetchActivePolicy(ceremony.purpose as Purpose),
    enabled: ceremony.purpose !== null,
  });

  // Reset the verdict whenever the ceremony changes.
  useEffect(() => {
    setVerdict(null);
    setError(null);
    setPhase(-1);
  }, [ceremony.key]);

  const canSimulate = ceremony.wired === "live";

  async function run() {
    const policy = policyQuery.data;
    if (!policy) return;
    setRunning(true);
    setVerdict(null);
    setError(null);

    // Animate the token across the stages while the request is in flight.
    for (let i = 0; i < STAGES.length; i++) {
      setTimeout(() => setPhase(i), i * 110);
    }

    try {
      const facts = buildFacts(ceremony, form);
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
          purpose <b>{ceremony.purpose ?? "—"}</b>
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

      <div className="cer-work">
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
              {ceremony.key === "join" && (
                <JoinForm form={form} setForm={setForm} />
              )}
              {ceremony.key === "directory" && (
                <DirectoryForm form={form} setForm={setForm} />
              )}
              {ceremony.key === "leave" && (
                <LeaveForm form={form} setForm={setForm} />
              )}
              {ceremony.key === "role-change" && (
                <RoleChangeForm form={form} setForm={setForm} />
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
              )}
            </>
          )}
        </div>

        {/* Decision policy — source + versions + activate + upload */}
        <div className="card">
          <div className="cer-panel-title">
            Decision policy <span className="ln" />
          </div>
          {ceremony.purpose === null ? (
            <p className="cer-sub">No policy purpose for this ceremony yet.</p>
          ) : (
            <PolicyManager purpose={ceremony.purpose as Purpose} />
          )}
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

function PolicyManager({ purpose }: { purpose: Purpose }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [showUpload, setShowUpload] = useState(false);
  const [editing, setEditing] = useState(false);

  const query = useQuery({
    queryKey: ["policies", purpose],
    queryFn: () => fetchPolicies(purpose),
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

  const items = query.data?.items ?? [];
  const active = items.find((p) => p.isActive) ?? null;
  const canAuthor = CEREMONY_PURPOSES.includes(purpose);

  if (editing) {
    return (
      <RuleEditor
        purpose={purpose}
        pkg={pkgFor(purpose)}
        initial={
          (active && parseRego(active.regoSource)) || blankIR(purpose)
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
            <span className="cer-chip">
              sha <b>{active.sha256.slice(0, 12)}…</b>
            </span>
          </div>
          <pre className="cer-policy">{active.regoSource}</pre>
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
              <div
                key={p.id}
                className={`cer-ver${p.isActive ? " active" : ""}`}
              >
                <span className="cer-ver-v">v{p.version}</span>
                <span className="cer-ver-meta">{formatIso(p.createdAt)}</span>
                {p.isActive ? (
                  <span className="cer-chip" style={{ color: "var(--vd-allow)" }}>
                    active
                  </span>
                ) : (
                  <button
                    type="button"
                    className="cer-ver-activate"
                    disabled={activate.isPending}
                    onClick={async () => {
                      const ok = await confirm({
                        title: `Activate ${purpose} v${p.version}?`,
                        message: `The current active policy for "${purpose}" becomes archived.`,
                        confirmLabel: "Activate",
                      });
                      if (ok) activate.mutate(p.id);
                    }}
                  >
                    Activate
                  </button>
                )}
              </div>
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
          {active && !parseRego(active.regoSource) && (
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

function DirectoryForm({
  form,
  setForm,
}: {
  form: FormState;
  setForm: (f: FormState) => void;
}) {
  return (
    <>
      <div className="cer-field">
        <label>
          Viewer's community role
          <small>actor.role — admin sees the fuller record</small>
        </label>
        <select
          className="input"
          value={form.viewerRole}
          onChange={(e) => setForm({ ...form, viewerRole: e.target.value })}
        >
          <option value="admin">admin</option>
          <option value="member">member</option>
          <option value="">none (authenticated)</option>
        </select>
      </div>
      <div className="cer-field">
        <label>
          Subject is a member
          <small>state.subject_member present</small>
        </label>
        <Toggle
          on={form.subjectIsMember}
          onClick={() =>
            setForm({ ...form, subjectIsMember: !form.subjectIsMember })
          }
        />
      </div>
      {form.subjectIsMember && (
        <div className="cer-field">
          <label>
            Subject's role
            <small>state.subject_member.role</small>
          </label>
          <select
            className="input"
            value={form.subjectRole}
            onChange={(e) => setForm({ ...form, subjectRole: e.target.value })}
          >
            <option value="member">member</option>
            <option value="moderator">moderator</option>
            <option value="admin">admin</option>
          </select>
        </div>
      )}
    </>
  );
}

function LeaveForm({
  form,
  setForm,
}: {
  form: FormState;
  setForm: (f: FormState) => void;
}) {
  return (
    <>
      <div className="cer-field">
        <label>
          Self-leave
          <small>actor.did == subject.did — always allowed</small>
        </label>
        <Toggle
          on={form.selfLeave}
          onClick={() => setForm({ ...form, selfLeave: !form.selfLeave })}
        />
      </div>
      {!form.selfLeave && (
        <div className="cer-field">
          <label>
            Subject's role
            <small>an admin may remove a non-admin only</small>
          </label>
          <select
            className="input"
            value={form.subjectRole}
            onChange={(e) => setForm({ ...form, subjectRole: e.target.value })}
          >
            <option value="member">member</option>
            <option value="moderator">moderator</option>
            <option value="admin">admin</option>
          </select>
        </div>
      )}
    </>
  );
}

function JoinForm({
  form,
  setForm,
}: {
  form: FormState;
  setForm: (f: FormState) => void;
}) {
  return (
    <div className="cer-field">
      <label>
        Presented credential is trusted
        <small>evidence.presentation.credentials[].issuer_trusted</small>
      </label>
      <Toggle
        on={form.joinTrusted}
        onClick={() => setForm({ ...form, joinTrusted: !form.joinTrusted })}
      />
    </div>
  );
}

function RoleChangeForm({
  form,
  setForm,
}: {
  form: FormState;
  setForm: (f: FormState) => void;
}) {
  return (
    <>
      <div className="cer-field">
        <label>
          Target role
          <small>evidence.request.target_role</small>
        </label>
        <select
          className="input"
          value={form.targetRole}
          onChange={(e) => setForm({ ...form, targetRole: e.target.value })}
        >
          <option value="member">member</option>
          <option value="moderator">moderator</option>
          <option value="admin">admin (promotion)</option>
        </select>
      </div>
      {form.targetRole === "admin" && (
        <div className="cer-field">
          <label>
            Step-up verified
            <small>admin needs step-up — else the verdict refers</small>
          </label>
          <Toggle
            on={form.stepUp}
            onClick={() => setForm({ ...form, stepUp: !form.stepUp })}
          />
        </div>
      )}
    </>
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
