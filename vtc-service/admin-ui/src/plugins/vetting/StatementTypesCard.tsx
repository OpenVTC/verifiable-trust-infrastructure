// Statement types — the endorsement types this community recognises, and the
// one peer identity vetting needs.
//
// It sits on the Requirements page because it is a prerequisite of the thing
// that page exists for: `POST /v1/schemas/accepts` refuses a criterion whose
// `statementType` is not registered, so an admin who starts with the criterion
// meets that refusal before they have any way to act on it. Registering the
// type is one button here, and the criterion editor links back to it.
//
// Registration is additive and cheap; removal is not offered, because the
// daemon refuses to delete a type while a live endorsement references it and
// the console has no view of which do.

import { type FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useToast } from "@/lib/toast";
import { IDENTITY_VETTING_STATEMENT_TYPE } from "@/lib/vetting";

import { fetchEndorsementTypes, registerEndorsementType, vettingKeys } from "./api";
import { describedBy, errorMessage, FormField, LoadError } from "./ui";

const IDENTITY_VETTING_DESCRIPTION = "A member verified this person's identity";

export function StatementTypesCard() {
  const queryClient = useQueryClient();
  const toast = useToast();
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
          {types.map((t) => (
            <li key={t.typeUri}>
              <code>{t.typeUri}</code>
              {t.description ? ` — ${t.description}` : ""}
              {t.typeUri === IDENTITY_VETTING_STATEMENT_TYPE && (
                <> — the identity-vetting statement</>
              )}
            </li>
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
    </section>
  );
}
