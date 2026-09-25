// The forms that build a change: grant or revoke a right, adopt, create or
// transfer a repository. Each ends by handing its `SignedTask` to the caller,
// which shows it in `SignTaskDialog` to sign and send — the forms themselves
// send nothing (see `actions.ts`).
//
// The person picker lists current members and also takes a pasted DID,
// because whether a non-member may hold a repository right is the
// community's `gitNamespace` policy to decide, not the console's. The one
// floor the daemon enforces regardless — namespace rights go to current
// members only — is enforced here too, so the form never builds a grant the
// fixed rules will refuse.
//
// Members are read a page at a time (the listing clamps a page to 200), with
// a filter over what has been read and a button for the next page: a
// community with more members than one page must still be able to find the
// one it means, and a silently truncated list would not say it was.

import { useId, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";

import { useNameBook } from "@/lib/names";
import { shortenDid } from "@/lib/format";
import type { GitNsRight } from "@/lib/wire-types";

import {
  adoptTask,
  createTask,
  didError,
  expiryDaysError,
  grantTask,
  MAX_REASON,
  reasonError,
  reseatTask,
  revokeTask,
  segmentError,
  type SignedTask,
  statementError,
  transferTask,
} from "./actions";
import { fetchMembersPage, gitNsKeys } from "./api";
import { consentClass, RIGHT_LABEL, rightLabel, shortName } from "./model";
import { useModal } from "./ui";

const OTHER = "__other__";

/** A modal form, with the Repos dialogs' keyboard contract (`useModal`). */
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
  const dismiss = useModal(surfaceRef, onClose);

  return (
    <div
      className="confirm-scrim"
      onClick={(e) => {
        if (e.target === e.currentTarget) dismiss();
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

/** A labelled text input whose error, when there is one, describes it. */
function TextField({
  label,
  value,
  onChange,
  error,
  hint,
  placeholder,
  inputMode,
  maxLength,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  error?: string | null;
  hint?: string;
  placeholder?: string;
  inputMode?: "numeric";
  maxLength?: number;
}) {
  const id = useId();
  const errId = `${id}-err`;
  const hintId = `${id}-hint`;
  const describedBy = [error ? errId : null, hint ? hintId : null].filter(Boolean).join(" ");
  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        value={value}
        placeholder={placeholder}
        inputMode={inputMode}
        maxLength={maxLength}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy || undefined}
        onChange={(e) => onChange(e.target.value)}
      />
      {hint && (
        <span id={hintId} className="field-hint">
          {hint}
        </span>
      )}
      <FieldError id={errId} error={error ?? null} />
    </div>
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
  const errId = `${id}-err`;
  const book = useNameBook();
  const pages = useInfiniteQuery({
    queryKey: gitNsKeys.members,
    queryFn: ({ pageParam }) => fetchMembersPage(pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.nextCursor ?? null,
  });
  const [mode, setMode] = useState<"member" | "other">("member");
  const [filter, setFilter] = useState("");
  const members = useMemo(() => {
    const all = (pages.data?.pages ?? []).flatMap((p) => p.members);
    const f = filter.trim().toLowerCase();
    return all
      .filter((m) => !exclude.includes(m.did))
      .filter(
        (m) =>
          !f ||
          m.did.toLowerCase().includes(f) ||
          (book.nameOf(m.did) ?? m.label ?? "").toLowerCase().includes(f),
      );
  }, [pages.data, filter, exclude, book]);

  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <input
        type="search"
        aria-label={`Filter members for ${label}`}
        placeholder="Filter by name or DID"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      <select
        id={id}
        value={mode === "other" ? OTHER : value}
        aria-invalid={error && mode === "member" ? true : undefined}
        aria-describedby={error && mode === "member" ? errId : undefined}
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
          {pages.isPending ? "Loading members…" : "Choose a member"}
        </option>
        {members.map((m) => (
          <option key={m.did} value={m.did}>
            {book.nameOf(m.did) ?? m.label ?? shortenDid(m.did)} — {m.did}
          </option>
        ))}
        {!membersOnly && <option value={OTHER}>Someone else — paste a DID</option>}
      </select>
      {pages.hasNextPage && (
        <button
          type="button"
          className="link"
          disabled={pages.isFetchingNextPage}
          onClick={() => void pages.fetchNextPage()}
        >
          {pages.isFetchingNextPage ? "Loading more members…" : "Load more members"}
        </button>
      )}
      {pages.isError && (
        <span className="field-hint">
          The member list could not be read
          {membersOnly ? "." : "; paste the DID instead."}
        </span>
      )}
      {mode === "other" && (
        <>
          <input
            aria-label={`${label} DID`}
            placeholder="did:webvh:…"
            value={value}
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? errId : undefined}
            onChange={(e) => onChange(e.target.value.trim())}
          />
          <span className="field-hint">
            A non-member holds a repository right only if the community's git
            namespace policy allows external signers.
          </span>
        </>
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
  const [subject, setSubject] = useState("");
  const [right, setRight] = useState<GitNsRight>(initialRight ?? rights[0]!);
  const [days, setDays] = useState("");
  const [reason, setReason] = useState("");
  const [errors, setErrors] = useState<{
    subject: string | null;
    days: string | null;
    reason: string | null;
  }>({ subject: null, days: null, reason: null });
  const namespaceRight = right === "git.ns.admin" || right === "git.repo.create";
  const consent = consentClass("right.grant", right);

  const submit = () => {
    const next = {
      subject: didError(subject),
      days: expiryDaysError(days),
      reason: reasonError(reason),
    };
    setErrors(next);
    if (next.subject || next.days || next.reason) return;
    onBuilt(
      grantTask({
        subject: subject.trim(),
        right,
        resource,
        expiresInDays: days.trim() ? Number(days) : undefined,
        reason,
      }),
    );
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
      <TextField
        label="Expires after (days)"
        value={days}
        onChange={setDays}
        inputMode="numeric"
        placeholder="No expiry"
        error={errors.days}
      />
      <TextField
        label="Reason"
        value={reason}
        onChange={setReason}
        placeholder="Optional"
        hint={`Shown to the resource's owners and admins. Never published. At most ${MAX_REASON} characters.`}
        error={errors.reason}
      />
    </FormDialog>
  );
}

export function RevokeDialog({
  subject,
  subjectName,
  right,
  resource,
  initialReason = "",
  onClose,
  onBuilt,
}: {
  subject: string;
  subjectName?: string;
  right: GitNsRight;
  resource: string;
  initialReason?: string;
  onClose: () => void;
  onBuilt: (task: SignedTask) => void;
}) {
  const [reason, setReason] = useState(initialReason);
  const [error, setError] = useState<string | null>(null);
  const submit = () => {
    const e = reasonError(reason);
    setError(e);
    if (!e) onBuilt(revokeTask(subject, right, resource, reason));
  };
  return (
    <FormDialog
      title={`Revoke ${rightLabel(right).toLowerCase()} on ${shortName(resource)}`}
      onClose={onClose}
      onSubmit={submit}
      submitLabel="Build the revocation"
    >
      <p>
        From <b>{subjectName ?? shortenDid(subject)}</b> <code className="gitns-party-did">{subject}</code>
      </p>
      <TextField
        label="Reason"
        value={reason}
        onChange={setReason}
        placeholder="Optional"
        hint={`Recorded with the revocation for the resource's owners and admins. Never published. At most ${MAX_REASON} characters.`}
        error={error}
      />
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
  const [name, setName] = useState("");
  const [owner, setOwner] = useState("");
  const [errors, setErrors] = useState<{ name: string | null; owner: string | null }>({
    name: null,
    owner: null,
  });

  const submit = () => {
    const nameErr = fixed ? null : segmentError(name.trim(), "repository");
    const resource = fixed ?? `${namespaceResource}/${name.trim()}`;
    const next = { name: nameErr, owner: didError(owner) };
    setErrors(next);
    if (next.name || next.owner) return;
    onBuilt(adoptTask(resource, [owner.trim()]));
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
        <TextField
          label={`Repository in ${namespaceResource}`}
          value={name}
          onChange={(v) => setName(v.trim())}
          placeholder="widgets"
          error={errors.name}
        />
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
    const e = didError(to) ?? (owners.includes(to.trim()) ? "Already an owner." : null);
    setError(e);
    if (!e) onBuilt(transferTask(resource, to.trim()));
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
      <TextField
        label="Name"
        value={name}
        onChange={(v) => setName(v.trim())}
        placeholder="widgets"
        error={error}
      />
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
      <TextField
        label="Description"
        value={description}
        onChange={setDescription}
        placeholder="Optional"
        hint="Shown by the forge. Nothing you would not publish."
      />
    </FormDialog>
  );
}

/**
 * Reseat a headless namespace (`git-ns/namespace/reseat` 0.1). Offered only
 * where the daemon reports the namespace headless; the VTC checks it again
 * when it runs the task. The subject is picked from current members only —
 * the fixed rules give `git.ns.admin` to no one else — and the statement is
 * required.
 */
export function ReseatDialog({
  namespaceId,
  namespaceResource,
  onClose,
  onBuilt,
}: {
  namespaceId: string;
  namespaceResource: string;
  onClose: () => void;
  onBuilt: (task: SignedTask) => void;
}) {
  const [subject, setSubject] = useState("");
  const [statement, setStatement] = useState("");
  const [errors, setErrors] = useState<{ subject: string | null; statement: string | null }>({
    subject: null,
    statement: null,
  });

  const submit = () => {
    const next = { subject: didError(subject), statement: statementError(statement) };
    setErrors(next);
    if (next.subject || next.statement) return;
    onBuilt(reseatTask(namespaceId, namespaceResource, subject.trim(), statement));
  };

  return (
    <FormDialog
      title={`Reseat ${namespaceResource}`}
      onClose={onClose}
      onSubmit={submit}
      submitLabel="Build the reseat"
    >
      <p className="muted">
        Seats a new namespace admin where none is left. Only a community administrator
        (an admin not limited to some contexts) can do this, and only while no
        current member holds a live <code>git.ns.admin</code> there: the VTC refuses it
        otherwise.
        The admin it seats has no expiry.
      </p>
      <PersonField
        label="New namespace admin"
        value={subject}
        onChange={setSubject}
        membersOnly
        error={errors.subject}
      />
      <TextField
        label="Statement"
        value={statement}
        onChange={setStatement}
        placeholder="Why the namespace is headless, and why this member"
        hint={`Required. Recorded as the right's reason, kept in the audit record, and shown to the namespace's repository owners. Never published. At most ${MAX_REASON} characters.`}
        error={errors.statement}
      />
    </FormDialog>
  );
}
