// The forms that build a change: grant a right, adopt, create or transfer a
// repository. Each ends by handing its `SignedTask` to the caller, which shows
// it in `SignTaskDialog` to sign and send — the forms themselves send nothing
// (see `actions.ts`).
//
// The person picker lists current members and also takes a pasted DID,
// because whether a non-member may hold a repository right is the
// community's `gitNamespace` policy to decide, not the console's. The one
// floor the daemon enforces regardless — namespace rights go to current
// members only — is enforced here too, so the form never builds a grant the
// fixed rules will refuse.

import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";

import { useNameBook } from "@/lib/names";
import { shortenDid } from "@/lib/format";
import type { GitNsRight } from "@/lib/wire-types";

import {
  adoptTask,
  createTask,
  didError,
  grantTask,
  segmentError,
  type SignedTask,
  transferTask,
} from "./actions";
import { fetchMembers, gitNsKeys } from "./api";
import { consentClass, RIGHT_LABEL, shortName } from "./model";

const OTHER = "__other__";

/** A modal form with the confirmation dialog's keyboard contract. */
function FormDialog({
  title,
  onClose,
  onSubmit,
  submitLabel,
  children,
}: {
  title: string;
  onClose: () => void;
  onSubmit: () => void;
  submitLabel: string;
  children: ReactNode;
}) {
  const titleId = useId();
  const surfaceRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    surfaceRef.current
      ?.querySelector<HTMLElement>("select, input, textarea, button")
      ?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="confirm-scrim"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <form
        ref={surfaceRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="confirm-dialog gitns-form"
        noValidate
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          onSubmit();
        }}
      >
        <h3 id={titleId}>{title}</h3>
        {children}
        <div className="form-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary">
            {submitLabel}
          </button>
        </div>
      </form>
    </div>
  );
}

function FieldError({ id, error }: { id: string; error: string | null }) {
  if (!error) return null;
  return (
    <span id={id} className="field-error" role="alert">
      {error}
    </span>
  );
}

/**
 * Pick a member, or paste a DID. `membersOnly` hides the paste option — for
 * namespace rights, which the fixed rules give to current members only.
 */
function PersonField({
  label,
  value,
  onChange,
  membersOnly,
  error,
  exclude = [],
}: {
  label: string;
  value: string;
  onChange: (did: string) => void;
  membersOnly?: boolean;
  error: string | null;
  exclude?: string[];
}) {
  const id = useId();
  const errId = useId();
  const book = useNameBook();
  const facts = useQuery({ queryKey: gitNsKeys.members, queryFn: fetchMembers });
  const [mode, setMode] = useState<"member" | "other">("member");
  const members = (facts.data ?? []).filter((m) => !exclude.includes(m.did));

  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        value={mode === "other" ? OTHER : value}
        aria-describedby={error ? errId : undefined}
        onChange={(e) => {
          if (e.target.value === OTHER) {
            setMode("other");
            onChange("");
          } else {
            setMode("member");
            onChange(e.target.value);
          }
        }}
      >
        <option value="">
          {facts.isPending ? "Loading members…" : "Choose a member"}
        </option>
        {members.map((m) => (
          <option key={m.did} value={m.did}>
            {book.nameOf(m.did) ?? m.label ?? shortenDid(m.did)} — {shortenDid(m.did)}
          </option>
        ))}
        {!membersOnly && <option value={OTHER}>Someone else — paste a DID</option>}
      </select>
      {facts.isError && (
        <span className="field-hint">
          The member list could not be read; paste the DID instead.
        </span>
      )}
      {mode === "other" && (
        <input
          aria-label={`${label} DID`}
          placeholder="did:webvh:…"
          value={value}
          onChange={(e) => onChange(e.target.value.trim())}
        />
      )}
      {mode === "other" && (
        <span className="field-hint">
          A non-member holds a repository right only if the community's git
          namespace policy allows external signers.
        </span>
      )}
      <FieldError id={errId} error={error} />
    </div>
  );
}

export function GrantDialog({
  resource,
  rights,
  initialRight,
  title,
  onClose,
  onBuilt,
}: {
  resource: string;
  /** The rights this form may offer on `resource`. */
  rights: readonly GitNsRight[];
  initialRight?: GitNsRight;
  title?: string;
  onClose: () => void;
  onBuilt: (task: SignedTask) => void;
}) {
  const rightId = useId();
  const expiryId = useId();
  const reasonId = useId();
  const [subject, setSubject] = useState("");
  const [right, setRight] = useState<GitNsRight>(initialRight ?? rights[0]!);
  const [days, setDays] = useState("");
  const [reason, setReason] = useState("");
  const [errors, setErrors] = useState<{ subject: string | null; days: string | null }>({
    subject: null,
    days: null,
  });
  const namespaceRight = right === "git.ns.admin" || right === "git.repo.create";
  const consent = consentClass("right.grant", right);

  const submit = () => {
    const n = days.trim() ? Number(days) : undefined;
    const next = {
      subject: didError(subject),
      days:
        n !== undefined && (!Number.isInteger(n) || n < 1)
          ? "Whole days, 1 or more — or leave it empty for no expiry."
          : null,
    };
    setErrors(next);
    if (next.subject || next.days) return;
    onBuilt(grantTask({ subject, right, resource, expiresInDays: n, reason }));
  };

  return (
    <FormDialog
      title={title ?? `Add a person to ${shortName(resource)}`}
      onClose={onClose}
      onSubmit={submit}
      submitLabel="Build the grant"
    >
      <PersonField
        label="Person"
        value={subject}
        onChange={setSubject}
        membersOnly={namespaceRight}
        error={errors.subject}
      />
      {rights.length > 1 ? (
        <div className="field">
          <label className="field-label" htmlFor={rightId}>
            Right
          </label>
          <select
            id={rightId}
            value={right}
            onChange={(e) => setRight(e.target.value as GitNsRight)}
          >
            {rights.map((r) => (
              <option key={r} value={r}>
                {RIGHT_LABEL[r]} ({r})
              </option>
            ))}
          </select>
        </div>
      ) : (
        <p>
          Right: <b>{RIGHT_LABEL[right]}</b> <code>{right}</code>
        </p>
      )}
      {consent !== "normal" && (
        <p className="muted">
          Granting {RIGHT_LABEL[right].toLowerCase()} is{" "}
          {consent === "destructive" ? "destructive-class" : "elevated-class"}: it
          needs a step-up (design §6).
        </p>
      )}
      <div className="field">
        <label className="field-label" htmlFor={expiryId}>
          Expires after (days)
        </label>
        <input
          id={expiryId}
          inputMode="numeric"
          placeholder="No expiry"
          value={days}
          aria-describedby={errors.days ? `${expiryId}-err` : undefined}
          onChange={(e) => setDays(e.target.value)}
        />
        <FieldError id={`${expiryId}-err`} error={errors.days} />
      </div>
      <div className="field">
        <label className="field-label" htmlFor={reasonId}>
          Reason
        </label>
        <input
          id={reasonId}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Optional"
        />
        <span className="field-hint">
          Shown to the resource's owners and admins. Never published.
        </span>
      </div>
    </FormDialog>
  );
}

export function AdoptDialog({
  resource: fixed,
  namespaceResource,
  onClose,
  onBuilt,
}: {
  /** Adopt this repository; omitted, the form asks for its name. */
  resource?: string;
  /** The namespace a typed name goes under (`github.com/acme`). */
  namespaceResource?: string;
  onClose: () => void;
  onBuilt: (task: SignedTask) => void;
}) {
  const nameId = useId();
  const [name, setName] = useState("");
  const [owner, setOwner] = useState("");
  const [errors, setErrors] = useState<{ name: string | null; owner: string | null }>({
    name: null,
    owner: null,
  });

  const submit = () => {
    const resource = fixed ?? (namespaceResource ? `${namespaceResource}/${name}` : name);
    const next = {
      name:
        fixed || /^[a-z0-9.-]+\/[a-z0-9._-]+\/[a-z0-9._-]+$/.test(resource)
          ? null
          : "A lowercase repository name in this namespace.",
      owner: didError(owner),
    };
    setErrors(next);
    if (next.name || next.owner) return;
    onBuilt(adoptTask(resource, [owner]));
  };

  return (
    <FormDialog
      title={fixed ? `Adopt ${shortName(fixed)}` : "Adopt an existing repository"}
      onClose={onClose}
      onSubmit={submit}
      submitLabel="Build the adoption"
    >
      <p className="muted">
        Brings a repository that already exists on the forge under the community's
        governance, names its first owner, and has the bridge bootstrap commit trust
        on it.
      </p>
      {!fixed && (
        <div className="field">
          <label className="field-label" htmlFor={nameId}>
            Repository {namespaceResource ? `in ${namespaceResource}` : ""}
          </label>
          <input
            id={nameId}
            value={name}
            placeholder={namespaceResource ? "widgets" : "github.com/acme/widgets"}
            onChange={(e) => setName(e.target.value.trim())}
          />
          <FieldError id={`${nameId}-err`} error={errors.name} />
        </div>
      )}
      <PersonField
        label="First owner"
        value={owner}
        onChange={setOwner}
        error={errors.owner}
      />
    </FormDialog>
  );
}

export function TransferDialog({
  resource,
  owners,
  onClose,
  onBuilt,
}: {
  resource: string;
  owners: string[];
  onClose: () => void;
  onBuilt: (task: SignedTask) => void;
}) {
  const [to, setTo] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = () => {
    const e = didError(to) ?? (owners.includes(to) ? "Already an owner." : null);
    setError(e);
    if (!e) onBuilt(transferTask(resource, to));
  };
  return (
    <FormDialog
      title={`Transfer ownership of ${shortName(resource)}`}
      onClose={onClose}
      onSubmit={submit}
      submitLabel="Build the transfer"
    >
      <p className="muted">
        Signed by an owner who is leaving: the recipient becomes an owner and the
        signer stops being one. To add an owner without leaving, grant{" "}
        <code>git.repo.own</code> instead.
      </p>
      <PersonField
        label="New owner"
        value={to}
        onChange={setTo}
        error={error}
        exclude={owners}
      />
    </FormDialog>
  );
}

export function CreateDialog({
  namespaceId,
  namespaceResource,
  personal,
  onClose,
  onBuilt,
}: {
  namespaceId: string;
  namespaceResource: string;
  personal: boolean;
  onClose: () => void;
  onBuilt: (task: SignedTask) => void;
}) {
  const nameId = useId();
  const descId = useId();
  const [name, setName] = useState("");
  const [visibility, setVisibility] = useState<"public" | "private">("public");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);

  const submit = () => {
    const e = segmentError(name, "repository");
    setError(e);
    if (!e) {
      onBuilt(
        createTask({ namespaceId, namespaceResource, name, visibility, description, personal }),
      );
    }
  };

  return (
    <FormDialog
      title={`New repository in ${namespaceResource}`}
      onClose={onClose}
      onSubmit={submit}
      submitLabel="Build the repository"
    >
      <p className="muted">
        {personal
          ? "On a personal account no bot can create a repository: the VTC reserves the name and answers with the commands the account holder runs."
          : "The bridge creates it and bootstraps commit trust. Whoever signs becomes its owner, and needs git.repo.create here."}
      </p>
      <div className="field">
        <label className="field-label" htmlFor={nameId}>
          Name
        </label>
        <input
          id={nameId}
          value={name}
          placeholder="widgets"
          aria-describedby={error ? `${nameId}-err` : undefined}
          onChange={(e) => setName(e.target.value.trim())}
        />
        <FieldError id={`${nameId}-err`} error={error} />
      </div>
      <fieldset className="gitns-fieldset">
        <legend>Visibility</legend>
        {(["public", "private"] as const).map((v) => (
          <label key={v} className="gitns-radio">
            <input
              type="radio"
              name="gitns-visibility"
              checked={visibility === v}
              onChange={() => setVisibility(v)}
            />
            <span>{v === "public" ? "Public" : "Private"}</span>
          </label>
        ))}
        <span className="field-hint">
          Either way, who owns it and who may commit is published to the Trust Registry.
        </span>
      </fieldset>
      <div className="field">
        <label className="field-label" htmlFor={descId}>
          Description
        </label>
        <input
          id={descId}
          value={description}
          placeholder="Optional"
          onChange={(e) => setDescription(e.target.value)}
        />
        <span className="field-hint">Shown by the forge. Nothing you would not publish.</span>
      </div>
    </FormDialog>
  );
}
