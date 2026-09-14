// The admission criterion editor — what a community asks of an applicant, and
// the vetting it requires.
//
// Every control here writes one member of the criterion the daemon stores
// (`POST /v1/schemas/accepts`). Two things the form does that a JSON body
// cannot:
//
//   - it only offers a per-method minimum for a method the criterion accepts,
//     so the commonest refusal ("a minimum is set for a method this criterion
//     does not accept") cannot be written in the first place;
//   - it separates "each vetter decides what documents they accept" from "the
//     community allows these documents and no others" — the same distinction
//     the wire draws between an absent `acceptedDocumentClasses` and an empty
//     one, which is invisible in JSON and decisive for a vetter (D16).
//
// What is *not* here: the rules. `criterionProblems` answers with
// `validateRequirements`' sentences, which mirror the daemon's own checks, and
// the daemon runs all of them again on save.

import { type FormEvent, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { useToast } from "@/lib/toast";
import {
  criterionBody,
  criterionDraft,
  criterionProblems,
  criterionSavable,
  DECLARED_RELATIONSHIPS,
  describeSeconds,
  draftToRequirements,
  IDENTITY_VETTING_STATEMENT_TYPE,
  methodLabel,
  parseIsoDuration,
  relationshipLabel,
  summarizeRequirements,
  VETTING_METHODS,
  type CriterionDraft,
  type RequirementsDraft,
} from "@/lib/vetting";
import type { AcceptsCriterion, EndorsementType } from "@/lib/wire-types";

import { saveCriterion, vettingKeys } from "./api";
import { describedBy, errorMessage, FormField, VETTING_PATH } from "./ui";

export function CriterionEditor({
  criterion,
  existingIds,
  statementTypes,
  onDone,
}: {
  /** The criterion being changed, or `null` to add one. */
  criterion: AcceptsCriterion | null;
  /** Ids already taken, so a new criterion does not silently replace one. */
  existingIds: readonly string[];
  statementTypes: readonly EndorsementType[];
  onDone: () => void;
}) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const isNew = criterion === null;
  const [draft, setDraft] = useState<CriterionDraft>(() => criterionDraft(criterion));

  const save = useMutation({
    mutationFn: saveCriterion,
    onSuccess: (stored) => {
      void queryClient.invalidateQueries({ queryKey: vettingKeys.criteria });
      void queryClient.invalidateQueries({ queryKey: vettingKeys.manifest });
      toast.push(
        "success",
        stored.vetting
          ? `Saved "${stored.id}". Applicants read the new requirements the next time they ask for the join manifest; an application already gathering statements keeps the requirements it started under.`
          : `Saved "${stored.id}". It asks for no vetting.`,
      );
      onDone();
    },
  });

  const problems = criterionProblems(draft, isNew ? existingIds : []);
  const savable = criterionSavable(problems);
  const requirements = draft.vets ? draftToRequirements(draft.requirements) : null;

  const set = (patch: Partial<CriterionDraft>) => setDraft({ ...draft, ...patch });
  const setReq = (patch: Partial<RequirementsDraft>) =>
    setDraft({ ...draft, requirements: { ...draft.requirements, ...patch } });

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!savable) return;
    save.mutate(criterionBody(draft));
  };

  return (
    <form className="card" onSubmit={onSubmit} aria-labelledby="editor-title" noValidate>
      <h3 id="editor-title">
        {isNew ? "Add a criterion" : `Editing ${criterion.id}`}
      </h3>
      <p className="lead">
        A criterion is one way into this community. An applicant satisfies any
        one of them; what it asks for is this community's decision, and every
        number below is yours to set.
      </p>

      <div className="form-stack">
        <FormField
          id="criterion-id"
          label="Name"
          hint={
            isNew
              ? "How the manifest and the decision cite this criterion, like vetted-member."
              : "A criterion is stored under its name, so this one cannot be renamed. Add a criterion and remove this one instead."
          }
          error={problems.id}
        >
          <input
            id="criterion-id"
            type="text"
            value={draft.id}
            readOnly={!isNew}
            spellCheck={false}
            autoComplete="off"
            placeholder="vetted-member"
            onChange={(e) => set({ id: e.target.value })}
            aria-invalid={Boolean(problems.id)}
            aria-describedby={describedBy("criterion-id", true, problems.id)}
          />
        </FormField>

        <FormField
          id="criterion-description"
          label="Description"
          hint="One sentence, shown to applicants in the join manifest."
        >
          <input
            id="criterion-description"
            type="text"
            value={draft.description}
            placeholder="One vetter must confirm who you are"
            onChange={(e) => set({ description: e.target.value })}
            aria-describedby={describedBy("criterion-description", true)}
          />
        </FormField>

        <label className="switch-field" htmlFor="criterion-vets">
          <input
            id="criterion-vets"
            type="checkbox"
            role="switch"
            checked={draft.vets}
            onChange={(e) => set({ vets: e.target.checked })}
          />
          <span className="switch-text">
            <strong>Applicants taking this route must be vetted by members</strong>
            <span className="muted">
              Off, the criterion asks only for the credentials its query names.
            </span>
          </span>
        </label>

        {draft.vets && (
          <VettingFields
            draft={draft.requirements}
            statementTypes={statementTypes}
            onChange={setReq}
          />
        )}

        <details className="vet-details">
          <summary>DCQL query</summary>
          <FormField
            id="criterion-query"
            label="Credentials this criterion asks for"
            hint="The community checks the query and every credential type it names when it stores the criterion."
            error={problems.query}
          >
            <textarea
              id="criterion-query"
              rows={10}
              spellCheck={false}
              className="code-input"
              value={draft.query}
              onChange={(e) => set({ query: e.target.value })}
              aria-invalid={Boolean(problems.query)}
              aria-describedby={describedBy("criterion-query", true, problems.query)}
            />
          </FormField>
        </details>
      </div>

      {problems.requirements.length > 0 && (
        <div className="finding error" role="alert">
          <strong>This community would refuse these requirements.</strong>
          <ul className="vet-list">
            {problems.requirements.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        </div>
      )}

      {requirements && problems.requirements.length === 0 && (
        <div className="finding ok">
          <strong>What applicants will be told</strong>
          <ul className="vet-list">
            {summarizeRequirements(requirements).map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      )}

      {save.error && (
        <div className="finding error" role="alert">
          <strong>Could not save the criterion</strong>
          <p>{errorMessage(save.error)}</p>
          <p className="muted">
            Applicants still read the criterion saved before. Correct it and
            save again.
          </p>
        </div>
      )}

      <div className="form-actions">
        <button type="submit" className="primary" disabled={!savable || save.isPending}>
          {save.isPending ? "Saving…" : isNew ? "Add criterion" : "Save criterion"}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={save.isPending}
          onClick={onDone}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

// ── The vetting half ────────────────────────────────────────────────────

function VettingFields({
  draft,
  statementTypes,
  onChange,
}: {
  draft: RequirementsDraft;
  statementTypes: readonly EndorsementType[];
  onChange: (patch: Partial<RequirementsDraft>) => void;
}) {
  const accepted = VETTING_METHODS.filter((m) => draft.acceptedMethods[m]);
  const known = statementTypes.map((t) => t.typeUri);
  // A stored criterion can name a type that has since been removed from the
  // registry; keep it selectable rather than silently switching the criterion
  // to another type on save.
  const options = draft.statementType && !known.includes(draft.statementType)
    ? [draft.statementType, ...known]
    : known;

  return (
    <>
      <FormField
        id="req-statement-type"
        label="Statement type"
        hint={
          options.length === 0
            ? "No endorsement type is registered yet. Register one above first."
            : "What a counted statement carries. Peer identity vetting uses the identity-vetting type."
        }
      >
        <select
          id="req-statement-type"
          value={draft.statementType}
          onChange={(e) => onChange({ statementType: e.target.value })}
          aria-describedby={describedBy("req-statement-type", true)}
        >
          <option value="">Choose a type…</option>
          {options.map((uri) => (
            <option key={uri} value={uri}>
              {uri === IDENTITY_VETTING_STATEMENT_TYPE
                ? `Identity vetting — ${uri}`
                : uri}
            </option>
          ))}
        </select>
      </FormField>

      <FormField
        id="req-min-statements"
        label="Statements required"
        hint="Distinct eligible vetters, counted by member record. One vetter holding two DIDs still counts once."
      >
        <input
          id="req-min-statements"
          type="text"
          inputMode="numeric"
          value={draft.minStatements}
          onChange={(e) => onChange({ minStatements: e.target.value })}
          aria-describedby={describedBy("req-min-statements", true)}
        />
      </FormField>

      <fieldset className="vet-fieldset">
        <legend>Methods that count</legend>
        <div className="vet-method-checks">
          {VETTING_METHODS.map((method) => (
            <label key={method} className="switch-field">
              <input
                type="checkbox"
                checked={draft.acceptedMethods[method]}
                onChange={(e) =>
                  onChange({
                    acceptedMethods: {
                      ...draft.acceptedMethods,
                      [method]: e.target.checked,
                    },
                  })
                }
              />
              <span className="switch-text">{methodLabel(method)}</span>
            </label>
          ))}
        </div>
        {accepted.length > 0 && (
          <div className="vet-counts">
            <span className="field-label">Of those, at least</span>
            {accepted.map((method) => (
              <FormField
                key={method}
                id={`req-min-${method}`}
                label={`${methodLabel(method)} statements`}
                className="field inline"
              >
                <input
                  id={`req-min-${method}`}
                  type="text"
                  inputMode="numeric"
                  placeholder="no minimum"
                  value={draft.minByMethod[method]}
                  onChange={(e) =>
                    onChange({
                      minByMethod: { ...draft.minByMethod, [method]: e.target.value },
                    })
                  }
                />
              </FormField>
            ))}
          </div>
        )}
      </fieldset>

      <FormField
        id="req-role"
        label="Vetters hold this role"
        hint="The role the community's vetter credential carries — a bare token such as vetter, not an ACL role name."
      >
        <input
          id="req-role"
          type="text"
          value={draft.role}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => onChange({ role: e.target.value })}
          aria-describedby={describedBy("req-role", true)}
        />
      </FormField>

      <FormField
        id="req-required-claims"
        label="Claims each vetter verifies"
        hint="Claim types from the VTA registry, separated by commas. The applicant's card must carry each one with a value a vetter can read."
      >
        <input
          id="req-required-claims"
          type="text"
          value={draft.requiredClaims}
          spellCheck={false}
          placeholder="name.legal"
          onChange={(e) => onChange({ requiredClaims: e.target.value })}
          aria-describedby={describedBy("req-required-claims", true)}
        />
      </FormField>

      <FormField
        id="req-optional-claims"
        label="Claims a vetter may also verify"
        hint="Offered to the applicant, never required. Optional."
      >
        <input
          id="req-optional-claims"
          type="text"
          value={draft.optionalClaims}
          spellCheck={false}
          placeholder="account.handle, url.homepage"
          onChange={(e) => onChange({ optionalClaims: e.target.value })}
          aria-describedby={describedBy("req-optional-claims", true)}
        />
      </FormField>

      <DurationField
        id="req-max-age"
        label="A statement counts for"
        hint="An ISO 8601 duration in weeks, days, hours, minutes or seconds — months and years vary in length, so the community refuses them. Leave empty for no limit."
        value={draft.maxStatementAge}
        placeholder="P120D"
        onChange={(maxStatementAge) => onChange({ maxStatementAge })}
      />

      <fieldset className="vet-fieldset">
        <legend>Documentation</legend>
        <label className="switch-field" htmlFor="req-document-floor">
          <input
            id="req-document-floor"
            type="checkbox"
            role="switch"
            checked={draft.documentFloor}
            onChange={(e) => onChange({ documentFloor: e.target.checked })}
          />
          <span className="switch-text">
            <strong>Only these documents count</strong>
            <span className="muted">
              Off, each vetter decides what documentation they accept, including
              none for prior acquaintance. On, a statement resting on anything
              else does not count.
            </span>
          </span>
        </label>
        {draft.documentFloor && (
          <FormField
            id="req-documents"
            label="Accepted documents"
            hint="lowerCamelCase tokens, separated by commas: passport, nationalId, drivingLicence. An empty list means vetters may rely on no document at all."
          >
            <input
              id="req-documents"
              type="text"
              value={draft.acceptedDocumentClasses}
              spellCheck={false}
              placeholder="passport, nationalId"
              onChange={(e) => onChange({ acceptedDocumentClasses: e.target.value })}
              aria-describedby={describedBy("req-documents", true)}
            />
          </FormField>
        )}
      </fieldset>

      <fieldset className="vet-fieldset">
        <legend>Independence</legend>
        <label className="switch-field" htmlFor="req-consistent">
          <input
            id="req-consistent"
            type="checkbox"
            role="switch"
            checked={draft.requireConsistentIdentityCommitment}
            onChange={(e) =>
              onChange({ requireConsistentIdentityCommitment: e.target.checked })
            }
          />
          <span className="switch-text">
            <strong>Every vetter must have verified the same identity</strong>
            <span className="muted">
              Vetters who verified different identities send the application to
              moderators rather than denying it.
            </span>
          </span>
        </label>
        <div className="vet-counts">
          <span className="field-label">At most, from vetters declaring</span>
          {DECLARED_RELATIONSHIPS.map((rel) => (
            <FormField
              key={rel}
              id={`req-cap-${rel}`}
              label={relationshipLabel(rel)}
              className="field inline"
            >
              <input
                id={`req-cap-${rel}`}
                type="text"
                inputMode="numeric"
                placeholder="no cap"
                value={draft.relationshipCaps[rel]}
                onChange={(e) =>
                  onChange({
                    relationshipCaps: {
                      ...draft.relationshipCaps,
                      [rel]: e.target.value,
                    },
                  })
                }
              />
            </FormField>
          ))}
        </div>
      </fieldset>

      <FormField
        id="req-invitation"
        label="Invitation credential"
        hint="Whether a vetted applicant must also hold an invitation."
      >
        <select
          id="req-invitation"
          value={draft.invitation}
          onChange={(e) =>
            onChange({ invitation: e.target.value as RequirementsDraft["invitation"] })
          }
          aria-describedby={describedBy("req-invitation", true)}
        >
          <option value="">Not stated</option>
          <option value="none">Not accepted</option>
          <option value="optional">May be presented</option>
          <option value="required">Required as well</option>
        </select>
      </FormField>

      <details className="vet-details">
        <summary>Deadlines, governance and version</summary>
        <div className="form-stack">
          <DurationField
            id="req-sla"
            label="A referred application is decided within"
            hint="What an applicant's client shows instead of its own pending timeout. Optional."
            value={draft.decisionSla}
            placeholder="P14D"
            onChange={(decisionSla) => onChange({ decisionSla })}
          />
          <DurationField
            id="req-grace"
            label="Earlier requirements keep counting for"
            hint="How long an application started under older requirements is judged by them. Published for applicants; this community does not apply it yet. Optional."
            value={draft.requirementsGrace}
            placeholder="P30D"
            onChange={(requirementsGrace) => onChange({ requirementsGrace })}
          />
          <FormField
            id="req-governance"
            label="Governance framework"
            hint="An https:// address where the community's vetting rules are written. Optional."
          >
            <input
              id="req-governance"
              type="url"
              value={draft.governanceFrameworkUrl}
              spellCheck={false}
              placeholder="https://example.org/governance#vetting"
              onChange={(e) => onChange({ governanceFrameworkUrl: e.target.value })}
              aria-describedby={describedBy("req-governance", true)}
            />
          </FormField>
          <FormField
            id="req-version"
            label="Requirements version"
            hint="The vetting requirements vocabulary this criterion is written in. Leave it at 0.1 unless the specification moves."
          >
            <input
              id="req-version"
              type="text"
              value={draft.version}
              spellCheck={false}
              onChange={(e) => onChange({ version: e.target.value })}
              aria-describedby={describedBy("req-version", true)}
            />
          </FormField>
        </div>
      </details>

      <p className="muted">
        A vetter is a member you have named one. Do that on the{" "}
        <Link to={VETTING_PATH}>Vetters</Link> page.
      </p>
    </>
  );
}

/** A duration field that reads its value back in words as it is typed. */
function DurationField({
  id,
  label,
  hint,
  value,
  placeholder,
  onChange,
}: {
  id: string;
  label: string;
  hint: string;
  value: string;
  placeholder: string;
  onChange: (value: string) => void;
}) {
  const seconds = value.trim() ? parseIsoDuration(value.trim()) : null;
  return (
    <FormField
      id={id}
      label={label}
      hint={
        seconds === null ? (
          hint
        ) : (
          <>
            <strong>{describeSeconds(seconds)}.</strong> {hint}
          </>
        )
      }
    >
      <input
        id={id}
        type="text"
        value={value}
        spellCheck={false}
        autoComplete="off"
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        aria-describedby={describedBy(id, true)}
      />
    </FormField>
  );
}
