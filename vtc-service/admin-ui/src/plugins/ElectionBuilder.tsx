// New election: the manifest builder (`lib/election-manifest.ts`).
//
// A guided form, one step per part of the manifest — about, questions, who
// votes, schedule, counting — and a review that shows the manifest and its
// digest before the one thing that gets signed. The JSON view is the same
// value: switching to it renders the draft, switching back reads it, and a
// manifest the form cannot represent stays in the JSON view rather than being
// trimmed to fit.
//
// What is checked here is a convenience, never the authority: the community
// checks the manifest on create (`vtc/elections/create/0.3`) and the ballot box
// at registration. The draft is kept in this tab (sessionStorage) until it is created or
// discarded, because a manifest is long to write and a reload should not lose
// it.

import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useConfirm } from "@/components/ConfirmDialog";
import { Field } from "@/components/Field";
import { Switch } from "@/components/Switch";
import { Tabs } from "@/components/Tabs";
import { vtcDid } from "@/lib/api";
import {
  ELECTIONS_KEY,
  createElection,
  fetchElection,
  fetchElections,
  fetchTrustedBallotBoxes,
  type TrustedBallotBox,
} from "@/lib/elections-api";
import {
  OPTION_PRESETS,
  QUESTION_TYPE_TEXT,
  ROLL_TEXT,
  SECRECY_TEXT,
  STEPS,
  checkDraft,
  didList,
  draftFromPrevious,
  draftToManifest,
  emptyDraft,
  fromLocalInput,
  manifestDigest,
  manifestToDraft,
  newQuestion,
  option,
  retypeQuestion,
  slugKey,
  suggestElectionId,
  toLocalInput,
  type Issue,
  type ManifestDraft,
  type QuestionDraft,
  type QuestionType,
  type RollRule,
  type Secrecy,
  type StepId,
} from "@/lib/election-manifest";
import { formatDuration, formatIso } from "@/lib/format";
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";
import { Refusal } from "@/plugins/ElectionRefusal";

/** Where the unfinished draft is kept: this tab only. */
export const DRAFT_STORAGE_KEY = "vtc-admin.election-draft.v1";

function loadDraft(): ManifestDraft | null {
  try {
    const raw = sessionStorage.getItem(DRAFT_STORAGE_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw) as ManifestDraft;
    return v && Array.isArray(v.questions) ? v : null;
  } catch {
    return null;
  }
}

function saveDraft(d: ManifestDraft | null) {
  try {
    if (d) sessionStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(d));
    else sessionStorage.removeItem(DRAFT_STORAGE_KEY);
  } catch {
    // Storage blocked: the draft lives only as long as the page.
  }
}

type Mode = "guided" | "json";

export function NewElection() {
  const confirm = useConfirm();
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const community = useQuery({ queryKey: ["vtc-did"], queryFn: vtcDid, staleTime: Infinity });
  const communityDid = community.data ?? "";

  const [draft, setDraftState] = useState<ManifestDraft>(() => loadDraft() ?? emptyDraft());
  const [step, setStep] = useState<StepId>("about");
  const [visited, setVisited] = useState<Set<StepId>>(() => new Set(["about"]));
  const [mode, setMode] = useState<Mode>("guided");
  const [jsonText, setJsonText] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);

  const setDraft = (next: ManifestDraft) => {
    setDraftState(next);
    saveDraft(next);
  };
  const patch = (p: Partial<ManifestDraft>) => setDraft({ ...draft, ...p });

  const manifest = useMemo(() => draftToManifest(draft, communityDid), [draft, communityDid]);
  // The trusted ballot boxes, read live: `null` from a VTC that cannot list them (the field is
  // then a typed DID), `undefined` while loading or after a failed read.
  const trustedQuery = useQuery({
    queryKey: [...ELECTIONS_KEY, "ballot-boxes"],
    queryFn: fetchTrustedBallotBoxes,
    retry: false,
  });
  const trusted = trustedQuery.data;
  const issues = useMemo(() => {
    const out = checkDraft(draft, communityDid);
    const box = draft.ballotBox.trim();
    // The list is exactly the one create checks against, so naming another is a certain refusal.
    if (trusted && box && !out.some((i) => i.field === "ballotBox") && !trusted.some((b) => b.did === box)) {
      out.push({
        step: "counting",
        field: "ballotBox",
        message: "Not one of this community's trusted ballot boxes.",
      });
    }
    return out;
  }, [draft, communityDid, trusted]);

  // In the JSON view the text is what is sent; it may be anything.
  let jsonParsed: Record<string, unknown> | null = null;
  let jsonParseError: string | undefined;
  if (mode === "json" && jsonText.trim()) {
    try {
      const v: unknown = JSON.parse(jsonText);
      if (v && typeof v === "object" && !Array.isArray(v)) jsonParsed = v as Record<string, unknown>;
      else jsonParseError = "The manifest is a JSON object.";
    } catch (e) {
      jsonParseError = `Not JSON: ${(e as Error).message}`;
    }
  }

  const goto = (s: StepId) => {
    setStep(s);
    setVisited((v) => new Set(v).add(s));
  };
  const stepIndex = STEPS.findIndex((s) => s.id === step);

  const switchMode = (next: Mode) => {
    if (next === mode) return;
    if (next === "json") {
      setJsonText(JSON.stringify(manifest, null, 2));
      setJsonError(null);
      setMode("json");
      return;
    }
    if (!jsonParsed) {
      setJsonError(jsonParseError ?? "Write a manifest first.");
      return;
    }
    const r = manifestToDraft(jsonParsed);
    if ("error" in r) {
      setJsonError(`${r.error} Keep editing it as JSON, or remove it to use the form.`);
      return;
    }
    setDraft(r.draft);
    setJsonError(null);
    setVisited(new Set(STEPS.map((s) => s.id)));
    setMode("guided");
  };

  const create = useMutation({
    mutationFn: () =>
      createElection(mode === "json" ? (jsonParsed ?? {}) : manifest, gestureFromConfirm(confirm)),
    onSuccess: (r) => {
      saveDraft(null);
      toast.push(
        "success",
        r.state === "registered"
          ? `Created ${r.electionId}; the ballot box registered it.`
          : `Created ${r.electionId}; the community keeps delivering it to the ballot box.`,
      );
      void queryClient.invalidateQueries({ queryKey: ELECTIONS_KEY });
      navigate(`../${encodeURIComponent(r.electionId)}`);
    },
  });

  const discard = async () => {
    const ok = await confirm({
      title: "Discard this draft?",
      message: "The form starts again from a blank election.",
      confirmLabel: "Discard",
      destructive: true,
    });
    if (!ok) return;
    saveDraft(null);
    setDraftState(emptyDraft());
    setVisited(new Set(["about"]));
    setStep("about");
    create.reset();
  };

  return (
    <div className="page election-builder">
      <header className="page-header">
        <h1>New election</h1>
        <Link to="..">All elections</Link>
      </header>
      <p className="muted">
        The manifest says what is asked, who may vote, when, and which ballot box counts. Every
        ticket and every vote is bound to its digest, so it cannot be changed once the ballot box
        registers it — check the review before you create it.
      </p>
      <Tabs
        variant="segmented"
        label="How to write the manifest"
        value={mode}
        onChange={switchMode}
        items={[
          { id: "guided", label: "Guided" },
          { id: "json", label: "JSON" },
        ]}
        end={
          <button type="button" className="link" onClick={() => void discard()}>
            Discard draft
          </button>
        }
      />
      {mode === "json" ? (
        <section className="card form-stack">
          <p className="muted">
            Sent exactly as written. Switch back to Guided to edit it in the form.
          </p>
          <Field label="Manifest" error={jsonParseError}>
            <textarea
              rows={28}
              spellCheck={false}
              className="mono"
              value={jsonText}
              onChange={(e) => {
                setJsonText(e.target.value);
                setJsonError(null);
              }}
            />
          </Field>
          {jsonError && <p className="field-error">{jsonError}</p>}
          <div className="election-builder-nav">
            <button type="button" disabled={!jsonParsed || create.isPending} onClick={() => create.mutate()}>
              Create
            </button>
          </div>
        </section>
      ) : (
        <>
          <Stepper current={step} visited={visited} issues={issues} onPick={goto} />
          <section className="card form-stack">
            {step === "about" && <AboutStep draft={draft} patch={patch} setDraft={setDraft} issues={issues} />}
            {step === "questions" && <QuestionsStep draft={draft} patch={patch} issues={issues} />}
            {step === "voters" && <VotersStep draft={draft} patch={patch} issues={issues} />}
            {step === "schedule" && <ScheduleStep draft={draft} patch={patch} issues={issues} />}
            {step === "counting" && (
              <CountingStep draft={draft} patch={patch} issues={issues} trusted={trusted} />
            )}
            {step === "review" && (
              <ReviewStep draft={draft} manifest={manifest} issues={issues} onFix={goto} />
            )}
            <div className="election-builder-nav">
              {stepIndex > 0 && (
                <button type="button" className="secondary" onClick={() => goto(STEPS[stepIndex - 1]!.id)}>
                  Back
                </button>
              )}
              {step !== "review" ? (
                <button type="button" onClick={() => goto(STEPS[stepIndex + 1]!.id)}>
                  Next
                </button>
              ) : (
                <button
                  type="button"
                  disabled={issues.length > 0 || !communityDid || create.isPending}
                  onClick={() => create.mutate()}
                >
                  {draft.binding ? "Create and send for approval" : "Create"}
                </button>
              )}
            </div>
          </section>
        </>
      )}
      <Refusal title="The election was not created" error={create.error} />
      {community.isError && <Refusal title="Could not read this community's DID" error={community.error} />}
    </div>
  );
}

function Stepper({
  current,
  visited,
  issues,
  onPick,
}: {
  current: StepId;
  visited: Set<StepId>;
  issues: Issue[];
  onPick: (s: StepId) => void;
}) {
  return (
    <ol className="election-stepper" aria-label="Steps">
      {STEPS.map((s, i) => {
        const wrong = s.id !== "review" && visited.has(s.id) && s.id !== current && issues.some((x) => x.step === s.id);
        const state = s.id === current ? "current" : wrong ? "wrong" : visited.has(s.id) ? "done" : "todo";
        return (
          <li key={s.id} className={state}>
            <button
              type="button"
              className="link"
              aria-current={s.id === current ? "step" : undefined}
              onClick={() => onPick(s.id)}
            >
              <span className="election-step-mark" aria-hidden="true">
                {wrong ? "!" : i + 1}
              </span>
              {s.label}
              {wrong && <span className="visually-hidden"> (needs attention)</span>}
            </button>
          </li>
        );
      })}
    </ol>
  );
}

/** The first issue about `field`, for a Field's error slot. */
function errorFor(issues: Issue[], field: string): string | undefined {
  return issues.find((i) => i.field === field)?.message;
}

function errorsUnder(issues: Issue[], prefix: string): Issue[] {
  return issues.filter((i) => i.field === prefix || i.field.startsWith(`${prefix}.`));
}

interface StepProps {
  draft: ManifestDraft;
  patch: (p: Partial<ManifestDraft>) => void;
  issues: Issue[];
}

function StepIntro({ title, children }: { title: string; children: ReactNode }) {
  return (
    <>
      <h2>{title}</h2>
      <p className="muted">{children}</p>
    </>
  );
}

function AboutStep({
  draft,
  patch,
  setDraft,
  issues,
}: StepProps & { setDraft: (d: ManifestDraft) => void }) {
  const confirm = useConfirm();
  const [from, setFrom] = useState("");
  const [fromError, setFromError] = useState<string | null>(null);
  const previous = useQuery({ queryKey: [...ELECTIONS_KEY, "list"], queryFn: fetchElections });

  const copyFrom = async (electionId: string) => {
    setFrom(electionId);
    setFromError(null);
    if (!electionId) return;
    const ok = await confirm({
      title: `Start from ${electionId}?`,
      message: "Its questions, voters and counting replace this draft's. The identifier and schedule start fresh.",
      confirmLabel: "Replace the draft",
    });
    if (!ok) {
      setFrom("");
      return;
    }
    try {
      const e = await fetchElection(electionId);
      const r = draftFromPrevious(e.manifest);
      if ("error" in r) setFromError(r.error);
      else setDraft(r.draft);
    } catch (err) {
      setFromError((err as Error).message);
    }
    setFrom("");
  };

  return (
    <>
      <StepIntro title="About this election">
        What members see first. The identifier is part of every ticket and vote, so it is fixed
        once created.
      </StepIntro>
      {previous.data && previous.data.length > 0 && (
        <Field label="Start from a previous election" hint="Optional." error={fromError ?? undefined}>
          <select value={from} onChange={(e) => void copyFrom(e.target.value)}>
            <option value="">—</option>
            {previous.data.map((e) => (
              <option key={e.electionId} value={e.electionId}>
                {e.title || e.electionId}
              </option>
            ))}
          </select>
        </Field>
      )}
      <Field label="Title" error={errorFor(issues, "title")}>
        <input
          type="text"
          value={draft.title}
          placeholder="Annual general meeting 2027"
          onChange={(e) =>
            patch({
              title: e.target.value,
              ...(draft.autoId ? { electionId: suggestElectionId(e.target.value) } : {}),
            })
          }
        />
      </Field>
      <Field
        label="Identifier"
        hint="Letters, digits, dot, dash and underscore. Unique in this community."
        error={errorFor(issues, "electionId")}
      >
        <input
          type="text"
          className="mono"
          value={draft.electionId}
          onChange={(e) => patch({ electionId: e.target.value, autoId: false })}
        />
      </Field>
      <Field label="Description" hint="Optional. Shown to members with the election." error={errorFor(issues, "description")}>
        <textarea rows={4} value={draft.description} onChange={(e) => patch({ description: e.target.value })} />
      </Field>
      <Switch
        label="Binding"
        checked={draft.binding}
        onChange={(e) => patch({ binding: e.target.checked })}
        description={
          draft.binding
            ? "The result decides something in the community's name. Another administrator approves it before it is created."
            : "A poll or survey: the result decides nothing by itself."
        }
      />
    </>
  );
}

function QuestionsStep({ draft, patch, issues }: StepProps) {
  const setQ = (i: number, q: QuestionDraft) =>
    patch({ questions: draft.questions.map((x, j) => (j === i ? q : x)) });
  const move = (i: number, by: number) => {
    const qs = [...draft.questions];
    const [q] = qs.splice(i, 1);
    qs.splice(i + by, 0, q!);
    patch({ questions: qs });
  };
  const listIssues = issues.filter((i) => i.field === "questions");
  return (
    <>
      <StepIntro title="Questions">
        Each question has a key that ballots and results name it by. Option keys work the same way
        and follow their labels until you change them.
      </StepIntro>
      {listIssues.map((x) => (
        <p key={x.message} className="field-error">
          {x.message}
        </p>
      ))}
      {draft.questions.map((q, i) => (
        <QuestionEditor
          key={q.uid}
          index={i}
          count={draft.questions.length}
          q={q}
          issues={errorsUnder(issues, `questions.${i}`)}
          onChange={(next) => setQ(i, next)}
          onMove={(by) => move(i, by)}
          onRemove={() => patch({ questions: draft.questions.filter((_, j) => j !== i) })}
        />
      ))}
      <div>
        <button
          type="button"
          className="secondary"
          onClick={() => patch({ questions: [...draft.questions, newQuestion(draft.questions.length)] })}
        >
          Add a question
        </button>
      </div>
    </>
  );
}

function QuestionEditor({
  index,
  count,
  q,
  issues,
  onChange,
  onMove,
  onRemove,
}: {
  index: number;
  count: number;
  q: QuestionDraft;
  issues: Issue[];
  onChange: (q: QuestionDraft) => void;
  onMove: (by: number) => void;
  onRemove: () => void;
}) {
  const at = `questions.${index}`;
  const set = (p: Partial<QuestionDraft>) => onChange({ ...q, ...p });
  const setOption = (j: number, label: string, key?: string) =>
    set({
      options: q.options.map((o, k) =>
        k !== j
          ? o
          : key !== undefined
            ? { ...o, key, autoKey: false }
            : { ...o, label, key: o.autoKey ? slugKey(label) : o.key },
      ),
    });
  const optionIssues = issues.filter((x) => x.field.startsWith(`${at}.options`));
  const exactlyOne = q.type === "choice" && q.minSelections.trim() === "1" && q.maxSelections.trim() === "1";
  return (
    <fieldset className="election-question">
      <legend>Question {index + 1}</legend>
      <div className="election-question-tools">
        <button type="button" className="link" disabled={index === 0} onClick={() => onMove(-1)}>
          Move up
        </button>
        <button type="button" className="link" disabled={index === count - 1} onClick={() => onMove(1)}>
          Move down
        </button>
        <button type="button" className="link" disabled={count === 1} onClick={onRemove}>
          Remove
        </button>
      </div>
      <Field label="What is asked" error={errorFor(issues, `${at}.text`)}>
        <textarea rows={2} value={q.text} onChange={(e) => set({ text: e.target.value })} />
      </Field>
      <div className="election-row">
        <Field label="Kind" hint={QUESTION_TYPE_TEXT[q.type].detail}>
          <select value={q.type} onChange={(e) => onChange(retypeQuestion(q, e.target.value as QuestionType))}>
            {(Object.keys(QUESTION_TYPE_TEXT) as QuestionType[]).map((t) => (
              <option key={t} value={t}>
                {QUESTION_TYPE_TEXT[t].label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Key" error={errorFor(issues, `${at}.key`)}>
          <input type="text" className="mono" value={q.key} onChange={(e) => set({ key: e.target.value })} />
        </Field>
      </div>
      {q.type !== "text" && (
        <div className="election-options">
          <span className="field-label">Options</span>
          {q.options.map((o, j) => (
            <div key={j} className="election-option">
              <input
                type="text"
                aria-label={`Option ${j + 1} label`}
                placeholder="Label"
                value={o.label}
                onChange={(e) => setOption(j, e.target.value)}
              />
              <input
                type="text"
                className="mono"
                aria-label={`Option ${j + 1} key`}
                placeholder="key"
                value={o.key}
                onChange={(e) => setOption(j, o.label, e.target.value)}
              />
              <button
                type="button"
                className="link"
                aria-label={`Remove option ${j + 1}`}
                onClick={() => set({ options: q.options.filter((_, k) => k !== j) })}
              >
                Remove
              </button>
            </div>
          ))}
          {optionIssues.map((x) => (
            <span key={x.message} className="field-error">
              {x.message}
            </span>
          ))}
          <div className="election-option-tools">
            <button
              type="button"
              className="secondary"
              onClick={() => set({ options: [...q.options, option(`Option ${q.options.length + 1}`)] })}
            >
              Add an option
            </button>
            {Object.entries(OPTION_PRESETS).map(([name, make]) => (
              <button key={name} type="button" className="link" onClick={() => set({ options: make() })}>
                Use {name}
              </button>
            ))}
          </div>
        </div>
      )}
      {q.type === "choice" && (
        <div className="election-row">
          <Field label="Fewest choices" error={errorFor(issues, `${at}.minSelections`)}>
            <input type="number" min={0} value={q.minSelections} onChange={(e) => set({ minSelections: e.target.value })} />
          </Field>
          <Field
            label="Most choices"
            hint={exactlyOne ? "A voter picks exactly one." : undefined}
            error={errorFor(issues, `${at}.maxSelections`)}
          >
            <input type="number" min={1} value={q.maxSelections} onChange={(e) => set({ maxSelections: e.target.value })} />
          </Field>
        </div>
      )}
      {q.type === "ranking" && (
        <Switch
          label="Partial rankings"
          checked={q.partial}
          onChange={(e) => set({ partial: e.target.checked })}
          description={q.partial ? "A voter may rank only their top options." : "A voter ranks every option."}
        />
      )}
      {q.type === "score" && (
        <div className="election-row">
          <Field label="Lowest score" error={errorFor(issues, `${at}.min`)}>
            <input type="number" value={q.min} onChange={(e) => set({ min: e.target.value })} />
          </Field>
          <Field label="Highest score" error={errorFor(issues, `${at}.max`)}>
            <input type="number" value={q.max} onChange={(e) => set({ max: e.target.value })} />
          </Field>
        </div>
      )}
      {q.type === "text" && (
        <Field label="Longest answer, in characters" error={errorFor(issues, `${at}.maxLength`)}>
          <input type="number" min={1} max={4096} value={q.maxLength} onChange={(e) => set({ maxLength: e.target.value })} />
        </Field>
      )}
      <Switch
        label="Optional"
        checked={q.optional}
        onChange={(e) => set({ optional: e.target.checked })}
        description={q.optional ? "A voter may leave it unanswered." : "Every ballot answers it."}
      />
    </fieldset>
  );
}

function Radios<T extends string>({
  name,
  legend,
  value,
  onChange,
  options,
}: {
  name: string;
  legend: string;
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: string; detail?: string }[];
}) {
  return (
    <fieldset className="election-radios">
      <legend className="field-label">{legend}</legend>
      {options.map((o) => (
        <label key={o.value}>
          <input type="radio" name={name} value={o.value} checked={value === o.value} onChange={() => onChange(o.value)} />{" "}
          <strong>{o.label}</strong>
          {o.detail && <span className="muted"> — {o.detail}</span>}
        </label>
      ))}
    </fieldset>
  );
}

function VotersStep({ draft, patch, issues }: StepProps) {
  return (
    <>
      <StepIntro title="Who votes">
        The community issues each party the roll admits one ticket, blind. It never learns which
        ballot is whose.
      </StepIntro>
      <Radios<RollRule>
        name="roll"
        legend="Eligible"
        value={draft.roll}
        onChange={(roll) => patch({ roll })}
        options={(Object.keys(ROLL_TEXT) as RollRule[]).map((r) => ({ value: r, label: ROLL_TEXT[r] }))}
      />
      {draft.roll !== "members" && (
        <Field label="Listed parties" hint="DIDs, one per line." error={errorFor(issues, "listed")}>
          <textarea rows={5} className="mono" spellCheck={false} value={draft.listed} onChange={(e) => patch({ listed: e.target.value })} />
        </Field>
      )}
    </>
  );
}

function zoneName(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return "your local time";
  }
}

function ScheduleStep({ draft, patch, issues }: StepProps) {
  const opens = Date.parse(draft.votingOpensAt);
  const closes = Date.parse(draft.votingClosesAt);
  const span = !Number.isNaN(opens) && !Number.isNaN(closes) && closes > opens ? (closes - opens) / 1000 : null;
  const time = (field: "registrationOpensAt" | "votingOpensAt" | "votingClosesAt", label: string, hint: string) => (
    <Field label={label} hint={hint} error={errorFor(issues, field)}>
      <input
        type="datetime-local"
        value={toLocalInput(draft[field])}
        onChange={(e) => patch({ [field]: fromLocalInput(e.target.value) })}
      />
    </Field>
  );
  return (
    <>
      <StepIntro title="Schedule">Times are in {zoneName()} and stored in UTC.</StepIntro>
      {time("registrationOpensAt", "Tickets from", "Members can take a ticket from this time.")}
      {time("votingOpensAt", "Voting opens", "No earlier than tickets.")}
      {time("votingClosesAt", "Voting closes", span ? `Voting runs for ${formatDuration(span)}.` : "After voting opens.")}
      <Switch
        label="Allow closing early"
        checked={draft.allowEarlyClose}
        onChange={(e) => patch({ allowEarlyClose: e.target.checked })}
        description={
          draft.allowEarlyClose
            ? "An administrator may close voting before the time above."
            : "Voting runs until the time above (it can still be cancelled)."
        }
      />
    </>
  );
}

/** The `<select>` value for a DID typed rather than chosen. */
const OTHER_BOX = "\u0000other";

function CountingStep({
  draft,
  patch,
  issues,
  trusted,
}: StepProps & { trusted: TrustedBallotBox[] | null | undefined }) {
  const hasText = draft.questions.some((q) => q.type === "text");
  const box = draft.ballotBox.trim();
  const listed = trusted?.find((b) => b.did === box);
  // Typing is the fallback: a VTC that cannot list them, a failed read, or a DID not listed.
  const [typing, setTyping] = useState(() => !!box && !listed);
  const choosing = !!trusted && trusted.length > 0 && !typing && (!box || !!listed);
  return (
    <>
      <StepIntro title="Counting">
        The ballot box is a voting service, never this community: it admits the votes, keeps the
        board and counts.
      </StepIntro>
      {choosing ? (
        <Field
          label="Ballot box"
          hint="This community's trusted voting services. Members are told who operates the one you choose before they take a ticket."
          error={errorFor(issues, "ballotBox")}
        >
          <select
            value={box}
            onChange={(e) => {
              if (e.target.value === OTHER_BOX) {
                setTyping(true);
                patch({ ballotBox: "" });
              } else patch({ ballotBox: e.target.value });
            }}
          >
            <option value="" disabled>
              Choose a ballot box…
            </option>
            {trusted.map((b) => (
              <option key={b.did} value={b.did}>
                {b.operator}
                {b.sameOperator ? " (also runs this community)" : ""} — {b.did}
              </option>
            ))}
            <option value={OTHER_BOX}>Another DID…</option>
          </select>
        </Field>
      ) : (
        <Field
          label="Ballot box DID"
          hint={
            trusted && trusted.length === 0
              ? "This community trusts no ballot box yet, so it cannot create an election. The host operator adds one under [voting] trusted_ballot_boxes in its configuration."
              : "One of this community's trusted voting services ([voting] trusted_ballot_boxes in its configuration)."
          }
          error={errorFor(issues, "ballotBox")}
        >
          <input
            type="text"
            className="mono"
            placeholder="did:webvh:…"
            value={draft.ballotBox}
            onChange={(e) => patch({ ballotBox: e.target.value })}
          />
        </Field>
      )}
      {choosing && listed?.sameOperator && (
        <p className="field-hint">
          {listed.operator} runs both this community and this ballot box, so its members are told
          that one party could link a ballot to its voter.
        </p>
      )}
      {!choosing && trusted && trusted.length > 0 && (
        <button type="button" className="link" onClick={() => {
          setTyping(false);
          if (!listed) patch({ ballotBox: "" });
        }}>
          Choose from the trusted ballot boxes
        </button>
      )}
      <Radios<Secrecy>
        name="secrecy"
        legend="Secrecy"
        value={draft.secrecy}
        onChange={(secrecy) => patch({ secrecy, ...(secrecy !== "open" ? { resultsBeforeClose: false } : {}) })}
        options={(Object.keys(SECRECY_TEXT) as Secrecy[]).map((s) => ({
          value: s,
          label: SECRECY_TEXT[s].label,
          detail: SECRECY_TEXT[s].detail,
        }))}
      />
      {errorFor(issues, "secrecy") && <p className="field-error">{errorFor(issues, "secrecy")}</p>}
      {draft.secrecy !== "open" && (
        <div className="election-row">
          <Field
            label="Trustees"
            hint="DIDs, one per line: at least two, neither this community nor the ballot box. Each runs the key ceremony from their own VTA."
            error={errorFor(issues, "trustees")}
          >
            <textarea rows={4} className="mono" spellCheck={false} value={draft.trustees} onChange={(e) => patch({ trustees: e.target.value })} />
          </Field>
          <Field
            label="Trustees needed to decrypt"
            hint={`Of ${didList(draft.trustees).length} named.`}
            error={errorFor(issues, "threshold")}
          >
            <input type="number" min={2} value={draft.threshold} onChange={(e) => patch({ threshold: e.target.value })} />
          </Field>
        </div>
      )}
      <Radios
        name="board"
        legend="Who reads the board"
        value={draft.boardVisibility}
        onChange={(boardVisibility) => patch({ boardVisibility })}
        options={[
          { value: "public", label: "Anyone" },
          { value: "private", label: "The community and its auditors", detail: "and each voter, for their own vote" },
        ]}
      />
      <Field label="Auditors" hint="Optional. DIDs, one per line, whose attestations certification keeps." error={errorFor(issues, "auditors")}>
        <textarea rows={3} className="mono" spellCheck={false} value={draft.auditors} onChange={(e) => patch({ auditors: e.target.value })} />
      </Field>
      <Radios
        name="revote"
        legend="A second vote on one ticket"
        value={draft.revote}
        onChange={(revote) => patch({ revote })}
        options={[
          { value: "replace", label: "Replaces the first" },
          { value: "refuse", label: "Is refused", detail: "the first vote stands" },
        ]}
      />
      {draft.secrecy === "open" && (
        <Switch
          label="Running totals"
          checked={draft.resultsBeforeClose}
          onChange={(e) => patch({ resultsBeforeClose: e.target.checked })}
          description={
            draft.resultsBeforeClose ? "Totals can be read while voting is open." : "Totals only after voting closes."
          }
        />
      )}
      <Field
        label="Ballots counted before text answers are shown"
        hint={hasText ? "At least 10, so a written answer is harder to tie to its writer." : "Only matters for free-text questions. At least 10."}
        error={errorFor(issues, "textReleaseThreshold")}
      >
        <input
          type="number"
          min={10}
          value={draft.textReleaseThreshold}
          onChange={(e) => patch({ textReleaseThreshold: e.target.value })}
        />
      </Field>
    </>
  );
}

function ReviewStep({
  draft,
  manifest,
  issues,
  onFix,
}: {
  draft: ManifestDraft;
  manifest: Record<string, unknown>;
  issues: Issue[];
  onFix: (s: StepId) => void;
}) {
  const [digest, setDigest] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    manifestDigest(manifest).then(
      (d) => live && setDigest(d),
      () => live && setDigest(null),
    );
    return () => {
      live = false;
    };
  }, [manifest]);
  const label = (s: StepId) => STEPS.find((x) => x.id === s)?.label ?? s;
  return (
    <>
      <StepIntro title="Review">
        This is what will be registered. Nothing in it can be changed afterwards: a mistake means
        cancelling the election and creating another.
      </StepIntro>
      {issues.length > 0 && (
        <div className="election-issues" role="alert">
          <strong>Fix these first</strong>
          <ul>
            {issues.map((x, i) => (
              <li key={i}>
                {x.message}{" "}
                <button type="button" className="link" onClick={() => onFix(x.step)}>
                  Go to {label(x.step)}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
      <dl className="detail-list">
        <dt>Election</dt>
        <dd>
          {draft.title || <span className="muted">(no title)</span>} — <code>{draft.electionId}</code>
        </dd>
        <dt>Binding</dt>
        <dd>{draft.binding ? "Yes — another administrator approves it before it is created" : "No"}</dd>
        <dt>Questions</dt>
        <dd>
          <ol className="election-review-questions">
            {draft.questions.map((q) => (
              <li key={q.uid}>
                {q.text || <code>{q.key}</code>}{" "}
                <span className="muted">
                  ({QUESTION_TYPE_TEXT[q.type].label.toLowerCase()}
                  {q.type !== "text" && `: ${q.options.map((o) => o.label || o.key).join(", ")}`}
                  {q.optional ? ", optional" : ""})
                </span>
              </li>
            ))}
          </ol>
        </dd>
        <dt>Who votes</dt>
        <dd>
          {ROLL_TEXT[draft.roll]}
          {draft.roll !== "members" && ` (${didList(draft.listed).length} listed)`}
        </dd>
        <dt>Tickets from</dt>
        <dd>{formatIso(draft.registrationOpensAt)}</dd>
        <dt>Voting</dt>
        <dd>
          {formatIso(draft.votingOpensAt)} to {formatIso(draft.votingClosesAt)}
          {draft.allowEarlyClose && ", may close early"}
        </dd>
        <dt>Secrecy</dt>
        <dd>
          {SECRECY_TEXT[draft.secrecy].label}
          {draft.secrecy !== "open" && `, ${draft.threshold} of ${didList(draft.trustees).length} trustees to decrypt`}
        </dd>
        <dt>Ballot box</dt>
        <dd>
          <code>{draft.ballotBox || "—"}</code>
        </dd>
        <dt>Board</dt>
        <dd>
          {draft.boardVisibility === "public" ? "Public" : "Private"}
          {didList(draft.auditors).length > 0 && `, ${didList(draft.auditors).length} auditor(s)`}
        </dd>
        <dt>Changing a vote</dt>
        <dd>{draft.revote === "replace" ? "A later vote replaces the earlier one" : "The first vote stands"}</dd>
        <dt>Manifest digest</dt>
        <dd>
          <code>{digest ?? "…"}</code>
          <div className="muted">Computed here; the community computes it again on create.</div>
        </dd>
      </dl>
      <details>
        <summary>The manifest as JSON</summary>
        <pre className="mono election-json">{JSON.stringify(manifest, null, 2)}</pre>
      </details>
    </>
  );
}
