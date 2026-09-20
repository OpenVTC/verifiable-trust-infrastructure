// Requirements — what this community asks of an applicant, and the vetting each
// route requires.
//
// This is where admission criteria are written. It used to be a reading of the
// join manifest, with the criteria themselves registered by hand over REST: the
// two calls that turn vetting on had no interface at all, so the first thing an
// operator had to do was the one thing the console could not help with.
//
// It reads both surfaces, because they answer different questions. The criteria
// (`GET /v1/schemas/accepts`) are the records being edited — the DCQL query
// included, which the manifest does not carry. The manifest is what applicants
// receive, and it alone carries each criterion's `requirementsDigest`: the
// value an applicant records when they start gathering statements, so a change
// made here is visible to them rather than silent.
//
// The checks shown are `validateRequirements`, the same rules the daemon
// applies — so a criterion stored before a rule existed says what would be
// refused if it were saved again, and a draft says it before it is sent.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import { useConfirm } from "@/components/ConfirmDialog";
import { useToast } from "@/lib/toast";
import {
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
import { CriterionEditor } from "./CriterionEditor";
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

  const rows = criteria.data ?? [];
  const digests = new Map(
    (manifest.data?.criteria ?? []).map((c) => [c.id, c.requirementsDigest]),
  );

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
          Each criterion is one way into this community — an applicant satisfies
          any one of them. A criterion that requires vetting says how many
          statements it counts and from whom; every number is this community's
          policy, and the protocol has no defaults.
        </p>
        {criteria.isPending && <p className="muted">Loading the criteria…</p>}
        {criteria.data && rows.length === 0 && (
          <p className="muted">
            No criteria are registered, so applicants are asked for no evidence.
          </p>
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

      {rows.map((criterion) => (
        <CriterionCard
          key={criterion.id}
          criterion={criterion}
          digest={digests.get(criterion.id)}
          busy={remove.isPending || editing.kind !== "none"}
          onEdit={() => setEditing({ kind: "edit", id: criterion.id })}
          onRemove={() => void onRemove(criterion)}
        />
      ))}
    </>
  );
}

function CriterionCard({
  criterion,
  digest,
  busy,
  onEdit,
  onRemove,
}: {
  criterion: AcceptsCriterion;
  digest: string | null | undefined;
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
        Criterion <code>{criterion.id}</code>
      </h3>
      {criterion.description && <p>{criterion.description}</p>}

      {!vetting ? (
        <p className="muted">This criterion requires no vetting.</p>
      ) : (
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
