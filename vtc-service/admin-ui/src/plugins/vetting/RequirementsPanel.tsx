// Requirements — what this community asks of an applicant, and the vetting each
// route requires.
//
// This is where admission criteria are written. It used to be a reading of the
// join manifest, with the criteria themselves registered by hand over REST: the
// two calls that turn vetting on had no interface at all, so the first thing an
// operator had to do was the one thing the console could not help with.
//
// It reads both surfaces, because they answer different questions. The criteria
// (`vtc/schemas/accepts/list/0.2`) are the records being edited. The manifest
// (`vtc/join-requests/manifest/0.3`) is what applicants receive, and it alone
// carries two things: each criterion's `requirementsDigest` — the value an
// applicant cites, so a change made here is visible to them rather than silent
// — and the order the community decides by, which is the order shown here.
//
// The checks shown are `validateRequirements`, the same rules the daemon
// applies — so a criterion stored before a rule existed says what would be
// refused if it were saved again, and a draft says it before it is sent.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import { useConfirm } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { useToast } from "@/lib/toast";
import {
  admissionSentence,
  criterionRequirementLines,
  summarizeRequirements,
  validateRequirements,
  type VettingRequirements,
} from "@/lib/vetting";
import type { AcceptsCriterion } from "@/lib/wire-types";

import {
  deleteCriterion,
  fetchCriteria,
  fetchEndorsementTypes,
  fetchManifest,
  vettingKeys,
} from "./api";
import { publishedHiddenVetting, type PublishedHiddenVetting } from "@/lib/hidden-vetting";

import { CriterionEditor } from "./CriterionEditor";
import { HiddenVettingCard } from "./HiddenVettingCard";
import { StatementTypesCard } from "./StatementTypesCard";
import { errorMessage, LoadError } from "./ui";

/** Which criterion the editor is open on: none, a new one, or a stored id. */
type Editing = { kind: "none" } | { kind: "new" } | { kind: "edit"; id: string };

export function RequirementsPanel() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const criteria = useQuery({ queryKey: vettingKeys.criteria, queryFn: fetchCriteria });
  const manifest = useQuery({ queryKey: vettingKeys.manifest, queryFn: fetchManifest });
  const statementTypes = useQuery({
    queryKey: vettingKeys.endorsementTypes,
    queryFn: fetchEndorsementTypes,
  });
  const [editing, setEditing] = useState<Editing>({ kind: "none" });

  // In the order the community decides by: the manifest's. A criterion the
  // manifest does not list yet (it was just saved) goes last, as it will.
  const published = (manifest.data?.criteria ?? []).map((c) => c.id);
  const rank = (id: string) => {
    const at = published.indexOf(id);
    return at < 0 ? published.length : at;
  };
  const rows = [...(criteria.data ?? [])].sort((a, b) => rank(a.id) - rank(b.id));
  const digests = new Map(
    (manifest.data?.criteria ?? []).map((c) => [c.id, c.requirementsDigest]),
  );
  const hidden = new Map(
    (manifest.data?.criteria ?? []).map((c) => [c.id, publishedHiddenVetting(c)]),
  );
  // Vetters enrol and draw under the first criterion with hidden vetting on
  // (`pcs_tasks::config_for`), so turning it on for a second is worth a word.
  const firstHidden = (manifest.data?.criteria ?? []).find((c) => publishedHiddenVetting(c))?.id;

  const remove = useMutation({
    mutationFn: deleteCriterion,
    onSuccess: (_res, id) => {
      void queryClient.invalidateQueries({ queryKey: vettingKeys.criteria });
      void queryClient.invalidateQueries({ queryKey: vettingKeys.manifest });
      toast.push(
        "success",
        `Removed "${id}". Applicants can no longer join by that route; members admitted through it keep their membership.`,
      );
      setEditing({ kind: "none" });
    },
  });

  const onRemove = async (criterion: AcceptsCriterion) => {
    const ok = await confirm({
      title: `Remove the criterion "${criterion.id}"?`,
      message:
        "Applicants stop being offered this route as soon as they next read the join manifest. Anyone already gathering statements against it will have nothing to submit them under. Members admitted through it are unaffected.",
      confirmLabel: "Remove criterion",
      destructive: true,
    });
    if (ok) remove.mutate(criterion.id);
  };

  const editingCriterion =
    editing.kind === "edit"
      ? (rows.find((c) => c.id === editing.id) ?? null)
      : null;

  return (
    <>
      <section className="card" aria-labelledby="requirements-title">
        <h3 id="requirements-title">Admission criteria</h3>
        <p className="lead">
          Each criterion is one way into this community: what it asks for, and
          whether an applicant who meets it is admitted automatically or
          referred to an administrator. Nobody is admitted other than through
          one of them. An applicant who names no criterion is decided under the
          first one they meet, in the order below — so a criterion that asks for
          nothing, listed first, would decide every application. Every rule here
          is this community's policy; the protocol has no defaults.
        </p>
        {criteria.isPending && <p className="muted">Loading the criteria…</p>}
        {criteria.data && rows.length === 0 && (
          <EmptyState
            compact
            title="No criteria are registered, so this community is not accepting applications. Add one to open it — a criterion that asks for nothing lets anyone apply."
          />
        )}
        {editing.kind === "none" && (
          <div className="form-actions">
            <button
              type="button"
              className="primary"
              disabled={!criteria.data}
              onClick={() => setEditing({ kind: "new" })}
            >
              Add a criterion
            </button>
          </div>
        )}
        {remove.error && (
          <div className="finding error" role="alert">
            <strong>Could not remove the criterion</strong>
            <p>{errorMessage(remove.error)}</p>
          </div>
        )}
      </section>

      {criteria.error && <LoadError what="the admission criteria" error={criteria.error} />}
      {manifest.error && <LoadError what="the join manifest" error={manifest.error} />}

      <StatementTypesCard criteria={criteria.data ?? null} />

      {editing.kind !== "none" && (
        <CriterionEditor
          criterion={editingCriterion}
          existingIds={rows.map((c) => c.id)}
          statementTypes={statementTypes.data ?? []}
          onDone={() => setEditing({ kind: "none" })}
        />
      )}

      {rows.map((criterion, index) => (
        <CriterionCard
          key={criterion.id}
          position={index + 1}
          criterion={criterion}
          digest={digests.get(criterion.id)}
          hidden={hidden.get(criterion.id) ?? null}
          otherHiddenCriterion={firstHidden !== criterion.id ? firstHidden : undefined}
          busy={remove.isPending || editing.kind !== "none"}
          onEdit={() => setEditing({ kind: "edit", id: criterion.id })}
          onRemove={() => void onRemove(criterion)}
        />
      ))}
    </>
  );
}

function CriterionCard({
  position,
  criterion,
  digest,
  hidden,
  otherHiddenCriterion,
  busy,
  onEdit,
  onRemove,
}: {
  position: number;
  criterion: AcceptsCriterion;
  digest: string | null | undefined;
  hidden: PublishedHiddenVetting | null;
  otherHiddenCriterion?: string;
  busy: boolean;
  onEdit: () => void;
  onRemove: () => void;
}) {
  const titleId = `criterion-${criterion.id}`;
  const vetting = criterion.vetting ?? null;
  const problems = vetting ? validateRequirements(vetting) : [];
  const requirements: VettingRequirements | null =
    vetting && problems.length === 0 ? vetting : null;

  return (
    <section className="card" aria-labelledby={titleId}>
      <h3 id={titleId}>
        {position}. Criterion <code>{criterion.id}</code>
      </h3>
      {criterion.description && <p>{criterion.description}</p>}
      <p>
        <strong>{admissionSentence(criterion.admission)}</strong>
      </p>
      <ul className="vet-list" aria-label="What it asks for">
        {criterionRequirementLines(criterion).map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
      {digest && !vetting && (
        <dl>
          <dt>Requirements digest</dt>
          <dd>
            <code>{digest}</code>
            <CopyButton
              value={digest}
              label="Copy requirements digest"
              successMessage="Requirements digest copied"
            />
          </dd>
        </dl>
      )}

      {vetting && (
        <>
          {problems.length > 0 && (
            <div className="finding error" role="alert">
              <strong>
                The daemon would refuse these requirements if they were saved
                today.
              </strong>
              <ul className="vet-list">
                {problems.map((problem) => (
                  <li key={problem}>{problem}</li>
                ))}
              </ul>
              <span className="muted">Edit the criterion to correct them.</span>
            </div>
          )}
          {requirements && (
            <ul className="vet-list">
              {summarizeRequirements(requirements).map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          )}
          <dl>
            <dt>Requirements digest</dt>
            <dd>
              {digest ? (
                <>
                  <code>{digest}</code>
                  <CopyButton
                    value={digest}
                    label="Copy requirements digest"
                    successMessage="Requirements digest copied"
                  />
                </>
              ) : (
                <span className="muted">Not published</span>
              )}
            </dd>
            <dt>Statement type</dt>
            <dd>
              <code>{vetting.statementType}</code>
            </dd>
            {vetting.governanceFrameworkUrl && (
              <>
                <dt>Governance framework</dt>
                <dd>
                  <a
                    href={vetting.governanceFrameworkUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {vetting.governanceFrameworkUrl}{" "}
                    <ExternalLink size={12} aria-hidden="true" />
                  </a>
                </dd>
              </>
            )}
          </dl>
          <details>
            <summary>Requirements as published</summary>
            <pre>{JSON.stringify(vetting, null, 2)}</pre>
          </details>
        </>
      )}

      <HiddenVettingCard
        criterionId={criterion.id}
        asksForVetting={Boolean(vetting)}
        published={hidden}
        otherHiddenCriterion={otherHiddenCriterion}
      />

      <div className="form-actions">
        <button type="button" className="secondary" disabled={busy} onClick={onEdit}>
          Edit
        </button>
        <button
          type="button"
          className="secondary destructive"
          disabled={busy}
          onClick={onRemove}
        >
          Remove
        </button>
      </div>
    </section>
  );
}
