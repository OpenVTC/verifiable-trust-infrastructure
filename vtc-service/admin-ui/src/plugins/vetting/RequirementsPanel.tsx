// Requirements — the vetting each join criterion asks of an applicant, and its
// requirements digest, as the join manifest publishes them.
//
// Read-only on purpose: this console has no criteria editor. Criteria are
// registered through `POST /v1/schemas/accepts`, where the daemon checks the
// requirements before storing them. The panel still runs the same checks
// (`validateRequirements`), so a criterion stored before a rule existed shows
// what would be refused if it were saved again.

import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import {
  summarizeRequirements,
  validateRequirements,
  type VettingRequirements,
} from "@/lib/vetting";

import { fetchManifest, type ManifestCriterion, vettingKeys } from "./api";
import { LoadError } from "./ui";

export function RequirementsPanel() {
  const query = useQuery({ queryKey: vettingKeys.manifest, queryFn: fetchManifest });
  const criteria = query.data?.criteria ?? [];

  return (
    <>
      <section className="card" aria-labelledby="requirements-title">
        <h3 id="requirements-title">Published vetting requirements</h3>
        <p className="lead">
          Applicants read these from the join manifest. This console does not
          edit criteria: register or change one with{" "}
          <code>POST /v1/schemas/accepts</code>, and the daemon checks its vetting
          requirements before storing them. A criterion's requirements digest
          changes whenever its requirements do; an applicant records it when they
          start gathering statements, so a change mid-application is visible.
        </p>
        {query.isPending && <p className="muted">Loading the join manifest…</p>}
        {query.data && criteria.length === 0 && (
          <p className="muted">
            No criteria are registered, so applicants are asked for no evidence.
          </p>
        )}
      </section>
      {query.error && <LoadError what="the join manifest" error={query.error} />}
      {criteria.map((criterion) => (
        <CriterionCard key={criterion.id} criterion={criterion} />
      ))}
    </>
  );
}

function CriterionCard({ criterion }: { criterion: ManifestCriterion }) {
  const titleId = `criterion-${criterion.id}`;
  const hasVetting = criterion.vetting !== undefined && criterion.vetting !== null;
  const problems = hasVetting ? validateRequirements(criterion.vetting) : [];
  const requirements =
    hasVetting && problems.length === 0
      ? // The OpenAPI document types `vetting` as an opaque object; the
        // validator above is what establishes this shape.
        (criterion.vetting as unknown as VettingRequirements)
      : null;

  return (
    <section className="card" aria-labelledby={titleId}>
      <h3 id={titleId}>
        Criterion <code>{criterion.id}</code>
      </h3>
      {criterion.description && <p>{criterion.description}</p>}

      {!hasVetting ? (
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
              <span className="muted">
                Register the criterion again with corrected requirements.
              </span>
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
              {criterion.requirementsDigest ? (
                <>
                  <code>{criterion.requirementsDigest}</code>
                  <CopyButton
                    value={criterion.requirementsDigest}
                    label="Copy requirements digest"
                    successMessage="Requirements digest copied"
                  />
                </>
              ) : (
                <span className="muted">Not published</span>
              )}
            </dd>
            {requirements && (
              <>
                <dt>Statement type</dt>
                <dd>
                  <code>{requirements.statementType}</code>
                </dd>
              </>
            )}
            {requirements?.governanceFrameworkUrl && (
              <>
                <dt>Governance framework</dt>
                <dd>
                  <a
                    href={requirements.governanceFrameworkUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {requirements.governanceFrameworkUrl}{" "}
                    <ExternalLink size={12} aria-hidden="true" />
                  </a>
                </dd>
              </>
            )}
          </dl>
          <details>
            <summary>Requirements as published</summary>
            <pre>{JSON.stringify(criterion.vetting, null, 2)}</pre>
          </details>
        </>
      )}
    </section>
  );
}
