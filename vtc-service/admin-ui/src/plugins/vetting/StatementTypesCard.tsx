// Statement types — the endorsement types this community recognises, and the
// one peer identity vetting needs.
//
// It sits on the Requirements page because it is a prerequisite of the thing
// that page exists for: `POST /v1/schemas/accepts` refuses a criterion whose
// `statementType` is not registered, so an admin who starts with the criterion
// meets that refusal before they have any way to act on it. Registering the
// type is one button here, and the criterion editor links back to it.
//
// Removal used to be withheld, on the grounds that the daemon refuses to delete
// a type anything still references and the console could not see what did. The
// half it can see is the half that blocks an operator in practice: peer-vetting
// statements are signed by vetters' own wallets, so they are not in this
// community's endorsement store at all, and what actually depends on a type is
// a criterion naming it. The criteria are already loaded one component up, so
// each type says who uses it and Remove is disabled while anyone does.
//
// The other half — live endorsements of the type, which would mean paging the
// whole endorsement store to count — is left to the daemon. Its 409 carries the
// count, and the error block below renders it.

import { type FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useConfirm } from "@/components/ConfirmDialog";
import { useToast } from "@/lib/toast";
import { IDENTITY_VETTING_STATEMENT_TYPE } from "@/lib/vetting";
import type { AcceptsCriterion, EndorsementType } from "@/lib/wire-types";

import {
  deleteEndorsementType,
  fetchEndorsementTypes,
  registerEndorsementType,
  vettingKeys,
} from "./api";
import { describedBy, errorMessage, FormField, LoadError } from "./ui";

const IDENTITY_VETTING_DESCRIPTION = "A member verified this person's identity";

/**
 * `criteria` is `null` until the page has them — while the criteria query is
 * pending or has failed. Removal stays disabled until then rather than
 * defaulting to "nothing uses this", which would be a guess the operator would
 * read as a fact.
 */
export function StatementTypesCard({
  criteria,
}: {
  criteria: AcceptsCriterion[] | null;
}) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const query = useQuery({
    queryKey: vettingKeys.endorsementTypes,
    queryFn: fetchEndorsementTypes,
  });
  const [typeUri, setTypeUri] = useState("");
  const [description, setDescription] = useState("");
  const [attempted, setAttempted] = useState(false);

  const types = query.data ?? [];
  const hasIdentityVetting = types.some(
    (t) => t.typeUri === IDENTITY_VETTING_STATEMENT_TYPE,
  );

  const register = useMutation({
    mutationFn: registerEndorsementType,
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: vettingKeys.endorsementTypes });
      setTypeUri("");
      setDescription("");
      setAttempted(false);
      toast.push(
        "success",
        `Registered ${res.endorsementType.typeUri}. A criterion can now count statements of this type.`,
      );
    },
  });

  const remove = useMutation({
    mutationFn: deleteEndorsementType,
    onSuccess: (_res, uri) => {
      void queryClient.invalidateQueries({ queryKey: vettingKeys.endorsementTypes });
      toast.push(
        "success",
        `Removed ${uri}. No criterion can name it until it is registered again; statements already issued of that type are untouched.`,
      );
    },
  });

  const onRemove = async (type: EndorsementType) => {
    const ok = await confirm({
      title: `Remove the statement type "${type.typeUri}"?`,
      message:
        "No criterion will be able to name it until it is registered again. Statements already issued of this type are not touched, and the daemon still refuses the removal if any of them are live.",
      confirmLabel: "Remove type",
      destructive: true,
    });
    if (ok) remove.mutate(type.typeUri);
  };

  const uriError = typeUri.trim() ? null : "Give the type URI a statement carries.";
  const shownUriError = attempted ? uriError : null;

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setAttempted(true);
    if (uriError) return;
    register.mutate({
      typeUri: typeUri.trim(),
      ...(description.trim() ? { description: description.trim() } : {}),
    });
  };

  if (query.error) {
    return <LoadError what="the registered statement types" error={query.error} />;
  }

  return (
    <section className="card" aria-labelledby="statement-types-title">
      <h3 id="statement-types-title">Statement types</h3>
      <p className="lead">
        A criterion can only count statements of a type this community
        recognises. Peer identity vetting uses one type; register it once, and
        every vetting criterion names it.
      </p>

      {query.isPending ? (
        <p className="muted">Loading the registered types…</p>
      ) : types.length === 0 ? (
        <p className="muted">No endorsement types are registered yet.</p>
      ) : (
        <ul className="vet-list">
          {types.map((t, i) => (
            <StatementTypeRow
              key={t.typeUri}
              type={t}
              usedBy={
                criteria === null
                  ? null
                  : criteria
                      .filter((c) => c.vetting?.statementType === t.typeUri)
                      .map((c) => c.id)
              }
              noteId={`statement-type-usage-${i}`}
              busy={remove.isPending}
              onRemove={() => void onRemove(t)}
            />
          ))}
        </ul>
      )}

      {query.data && !hasIdentityVetting && (
        <div className="finding warn">
          <strong>
            The identity-vetting statement type is not registered, so no
            criterion can ask for vetting yet.
          </strong>
          <p className="muted">
            <code>{IDENTITY_VETTING_STATEMENT_TYPE}</code>
          </p>
          <button
            type="button"
            className="primary"
            disabled={register.isPending}
            onClick={() =>
              register.mutate({
                typeUri: IDENTITY_VETTING_STATEMENT_TYPE,
                description: IDENTITY_VETTING_DESCRIPTION,
              })
            }
          >
            {register.isPending ? "Registering…" : "Register it"}
          </button>
        </div>
      )}

      <details className="vet-details">
        <summary>Register another type</summary>
        <form className="form-stack" onSubmit={onSubmit} noValidate>
          <FormField
            id="statement-type-uri"
            label="Type URI"
            hint="The value a statement carries as its endorsement type."
            error={shownUriError}
          >
            <input
              id="statement-type-uri"
              type="text"
              value={typeUri}
              spellCheck={false}
              autoComplete="off"
              placeholder="https://example.org/endorsements/…"
              onChange={(e) => setTypeUri(e.target.value)}
              aria-invalid={Boolean(shownUriError)}
              aria-describedby={describedBy("statement-type-uri", true, shownUriError)}
            />
          </FormField>
          <FormField
            id="statement-type-description"
            label="Description"
            hint="Shown in this console. Optional."
          >
            <input
              id="statement-type-description"
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              aria-describedby={describedBy("statement-type-description", true)}
            />
          </FormField>
          <div className="form-actions">
            <button type="submit" className="primary" disabled={register.isPending}>
              {register.isPending ? "Registering…" : "Register type"}
            </button>
          </div>
        </form>
      </details>

      {register.error && (
        <div className="finding error" role="alert">
          <strong>Could not register the type</strong>
          <p>{errorMessage(register.error)}</p>
        </div>
      )}

      {remove.error && (
        <div className="finding error" role="alert">
          <strong>Could not remove the type</strong>
          <p>{errorMessage(remove.error)}</p>
        </div>
      )}
    </section>
  );
}

/**
 * One registered type, what depends on it, and its Remove.
 *
 * `usedBy` is the ids of the criteria naming this type, or `null` when the
 * criteria are not known. Remove is disabled in both the "used" and the "not
 * known" case, and the note says which — a disabled control whose reason is
 * only in a tooltip is no reason at all, so the note is the button's
 * `aria-describedby` too.
 */
function StatementTypeRow({
  type,
  usedBy,
  noteId,
  busy,
  onRemove,
}: {
  type: EndorsementType;
  usedBy: string[] | null;
  noteId: string;
  busy: boolean;
  onRemove: () => void;
}) {
  const inUse = usedBy !== null && usedBy.length > 0;
  const blocked = usedBy === null || inUse;

  return (
    <li className="vet-type">
      <div>
        <code>{type.typeUri}</code>
        {type.description ? ` — ${type.description}` : ""}
        {type.typeUri === IDENTITY_VETTING_STATEMENT_TYPE && (
          <> — the identity-vetting statement</>
        )}
        <span className={inUse ? "vet-note warn" : "vet-note"} id={noteId}>
          {usedBy === null ? (
            "Checking which criteria require it…"
          ) : usedBy.length === 0 ? (
            "No criterion requires it."
          ) : (
            <>
              Required by {usedBy.length === 1 ? "criterion" : "criteria"}{" "}
              {usedBy.map((id, i) => (
                <span key={id}>
                  {i > 0 && ", "}
                  <code>{id}</code>
                </span>
              ))}
              . Remove or re-point {usedBy.length === 1 ? "it" : "them"} first.
            </>
          )}
        </span>
      </div>
      <div className="row-actions">
        <button
          type="button"
          className="secondary destructive"
          disabled={blocked || busy}
          aria-describedby={noteId}
          onClick={onRemove}
        >
          Remove
        </button>
      </div>
    </li>
  );
}
