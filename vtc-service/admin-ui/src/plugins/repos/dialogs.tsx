// The forms that build a change: grant or revoke a right, adopt, create or
// transfer a repository, revert drift. Each ends by handing its `SignedTask` to the caller,
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
import { useViewerDid } from "@/lib/viewer";
import { shortenDid } from "@/lib/format";
import type {
  GitNsDriftItem,
  GitNsRight,
  GitNsRoleMap,
} from "@/lib/wire-types";

import {
  adoptTask,
  breakGlassTask,
  createTask,
  didError,
  driftAdoptTask,
  driftRevertTask,
  expiryDaysError,
  grantTask,
  justificationError,
  MAX_JUSTIFICATION,
  MAX_REASON,
  ratifyTask,
  reasonError,
  reseatTask,
  revokeTask,
  segmentError,
  type SignedTask,
  statementError,
  transferTask,
} from "./actions";
import { fetchMembersPage, gitNsKeys } from "./api";
import {
  consentClass,
  driftRevertEffect,
  isSelfGrant,
  RIGHT_LABEL,
  rightLabel,
  shortName,
} from "./model";
import { useModal } from "./ui";

const OTHER = "__other__";

/** A modal form, with the Repos dialogs' keyboard contract (`useModal`). */
function FormDialog({
  title,
  onClose,
  onSubmit,
  submitLabel,
  children,
  submitClass = "primary",
}: {
  title: string;
  onClose: () => void;
  onSubmit: () => void;
  submitLabel: string;
  children: ReactNode;
  /** `destructive` for the one form whose submit builds a destructive act. */
  submitClass?: string;
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
          <button type="submit" className={submitClass}>
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
  const viewer = useViewerDid();
  const selfGrant = isSelfGrant(viewer, subject, right);
  const [breakGlass, setBreakGlass] = useState(false);

  if (breakGlass) {
    return (
      <BreakGlassDialog right={right} resource={resource} onClose={onClose} onBuilt={onBuilt} />
    );
  }

  const submit = () => {
    const next = {
      subject: selfGrant ? SELF_GRANT_ERROR : didError(subject),
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
      {selfGrant && (
        <SelfGrantNotice right={right} onBreakGlass={() => setBreakGlass(true)} />
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
  const [owner, setOwner] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [ownerError, setOwnerError] = useState<string | null>(null);

  const submit = () => {
    const e = segmentError(name, "repository");
    const oe = owner.trim() ? didError(owner) : null;
    setError(e);
    setOwnerError(oe);
    if (!e && !oe) {
      onBuilt(
        createTask({
          namespaceId,
          namespaceResource,
          name,
          visibility,
          description,
          owners: owner.trim() ? [owner.trim()] : undefined,
          personal,
        }),
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
          : "The bridge creates it and bootstraps commit trust. Whoever signs needs git.repo.create here."}
      </p>
      <TextField
        label="Owner (DID)"
        value={owner}
        onChange={setOwner}
        placeholder="Optional — you, if empty"
        error={ownerError}
        hint="Empty makes you the owner, which the VTC accepts only if someone else granted you git.repo.create here (or you broke the glass for it). A namespace admin's create right is implied and makes nobody an owner on its own: name another member."
      />
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
 * Reseat a headless namespace (`git-ns/namespace/reseat` 0.3). Offered only
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
  const viewer = useViewerDid();
  // A community administrator reseating a headless namespace to themselves is
  // a self-grant of `git.ns.admin`, which `git-ns/right/grant` 0.3 routes to
  // break-glass.
  const selfGrant = isSelfGrant(viewer, subject, "git.ns.admin");
  const [breakGlass, setBreakGlass] = useState(false);

  if (breakGlass) {
    return (
      <BreakGlassDialog
        right="git.ns.admin"
        resource={namespaceResource}
        onClose={onClose}
        onBuilt={onBuilt}
      />
    );
  }

  const submit = () => {
    const next = {
      subject: selfGrant ? SELF_GRANT_ERROR : didError(subject),
      statement: statementError(statement),
    };
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
      {selfGrant && (
        <SelfGrantNotice right="git.ns.admin" onBreakGlass={() => setBreakGlass(true)} />
      )}
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

/**
 * Resolve one drift item (`git-ns/drift/resolve` 0.1): `revert` has the
 * bridge re-apply the VTC-authoritative state; `adopt` records the forge role
 * as the right it projects, for the member who linked the account. Offered
 * only where the console reads the signer as able to (`revertStanding`,
 * `adoptStanding`); the VTC checks again. The reason is optional — kept in the
 * audit record, and for an adopt as the right's reason too.
 */
export function DriftResolveDialog({
  resource,
  roleMap,
  item,
  label,
  adopt,
  onClose,
  onBuilt,
}: {
  resource: string;
  /** The repository's role map (`GitNsRepoRow.roleMap`); absent while the
   *  bridge has not reported it. */
  roleMap?: GitNsRoleMap | null;
  item: GitNsDriftItem;
  /** The item as the drift list names it. */
  label: string;
  /** Adopt, granting `right` to `member`; revert when absent. */
  adopt?: { member: string; right: GitNsRight };
  onClose: () => void;
  onBuilt: (task: SignedTask) => void;
}) {
  const book = useNameBook();
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = () => {
    const e = reasonError(reason);
    setError(e);
    if (e) return;
    onBuilt(
      adopt
        ? driftAdoptTask(resource, item, adopt.member, adopt.right, reason)
        : driftRevertTask(resource, item, reason, roleMap),
    );
  };
  const verb = adopt ? "Adopt" : "Revert";
  return (
    <FormDialog
      title={`${verb} drift on ${shortName(resource)}`}
      onClose={onClose}
      onSubmit={submit}
      submitLabel={`Build the ${verb.toLowerCase()}`}
    >
      <p>
        <b>{label}</b>
        {item.account && <> · @{item.account.login}</>}
        {" · "}
        {item.observed ? `forge shows ${item.observed}` : "forge shows nothing"}
        {" · "}
        {item.expected ? `projection calls for ${item.expected}` : "projection calls for nothing"}
      </p>
      {adopt ? (
        <p className="muted">
          Grants <b>{rightLabel(adopt.right).toLowerCase()}</b> to{" "}
          {book.nameOf(adopt.member) && <b>{book.nameOf(adopt.member)} </b>}
          <code className="gitns-party-did">{adopt.member}</code>, who linked this account,
          as a grant from you would. The forge keeps the role.
        </p>
      ) : (
        <p className="muted">{driftRevertEffect(item)}</p>
      )}
      <TextField
        label="Reason"
        value={reason}
        onChange={setReason}
        placeholder="Optional"
        hint={
          adopt
            ? `Recorded as the right's reason and in the audit record, for the repository's owners and the namespace's admins. Never published. At most ${MAX_REASON} characters.`
            : `Kept in the audit record for the repository's owners and the namespace's admins. Never published. At most ${MAX_REASON} characters.`
        }
        error={error}
      />
    </FormDialog>
  );
}

// ── break-glass ─────────────────────────────────────────────────────────

const SELF_GRANT_ERROR =
  "You cannot grant yourself this right: separation of duties. Choose someone else, or break the glass.";

/**
 * Shown where a form would build an elevated self-grant, which the VTC
 * refuses (`git-ns:selfGrantNotAllowed`) — so the form does not build it, and
 * says what to do instead.
 */
function SelfGrantNotice({
  right,
  onBreakGlass,
}: {
  right: GitNsRight;
  onBreakGlass: () => void;
}) {
  return (
    <div className="finding error" role="alert">
      <strong>You cannot grant yourself {RIGHT_LABEL[right].toLowerCase()}</strong>
      <span>
        Namespace admin, repo creator and owner carry authority over other people's
        rights, so separation of duties requires someone else to grant them to you.
        Ask another owner or administrator. If nobody else can — they are gone, or
        unreachable and this cannot wait — you can break the glass.
      </span>
      <span>
        <button type="button" className="secondary sm destructive" onClick={onBreakGlass}>
          Break glass…
        </button>
      </span>
    </div>
  );
}

/** What breaking the glass does, said before the justification is typed. */
export function BreakGlassConsequences() {
  return (
    <ul className="gitns-consequences">
      <li>
        <b>Takes effect immediately</b> and is published to the Trust Registry like any
        other right.
      </li>
      <li>
        <b>Never expires on its own.</b> It lasts until another administrator revokes it,
        or ratifies it into an ordinary grant.
      </li>
      <li>
        <b>Every community administrator and every namespace admin is notified now</b>,
        with your justification, and it is recorded at the audit log's highest severity.
      </li>
      <li>
        <b>It stays flagged</b> on every administrator's console until another
        administrator ratifies or revokes it. Any of them may revoke it at any time.
      </li>
      <li>
        The VTC asks for your <b>passkey</b> before it records it, bound to this one
        request.
      </li>
    </ul>
  );
}

/**
 * `git-ns/right/break-glass` 0.1: record an elevated right for yourself, with a
 * justification every administrator will read. The right is fixed by where it
 * was opened from; the signer is always the subject.
 */
export function BreakGlassDialog({
  right,
  resource,
  onClose,
  onBuilt,
}: {
  right: GitNsRight;
  resource: string;
  onClose: () => void;
  onBuilt: (task: SignedTask) => void;
}) {
  const [justification, setJustification] = useState("");
  const [error, setError] = useState<string | null>(null);
  const id = useId();
  const submit = () => {
    const e = justificationError(justification);
    setError(e);
    if (!e) onBuilt(breakGlassTask(right, resource, justification));
  };
  return (
    <FormDialog
      title={`Break glass: ${RIGHT_LABEL[right].toLowerCase()} on ${shortName(resource)}`}
      onClose={onClose}
      onSubmit={submit}
      submitLabel="Build the break-glass"
      submitClass="secondary destructive"
    >
      <p>
        You are about to give yourself <b>{RIGHT_LABEL[right]}</b> <code>{right}</code> on{" "}
        <code>{resource}</code> — a right your own rights let you grant to others, but
        that separation of duties stops you granting to yourself.
      </p>
      <BreakGlassConsequences />
      <div className="field">
        <label className="field-label" htmlFor={id}>
          Justification
        </label>
        <textarea
          id={id}
          rows={4}
          value={justification}
          maxLength={MAX_JUSTIFICATION + 200}
          placeholder="Why nobody else could grant this now — who you tried, what cannot wait"
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? `${id}-err` : `${id}-hint`}
          onChange={(e) => setJustification(e.target.value)}
        />
        <span id={`${id}-hint`} className="field-hint">
          Required. Shown to every administrator and every owner of the resource, sent in
          every notice and kept in the audit record. Never published. At most{" "}
          {MAX_JUSTIFICATION} characters.
        </span>
        <FieldError id={`${id}-err`} error={error} />
      </div>
    </FormDialog>
  );
}

/**
 * `git-ns/right/ratify` 0.1: confirm someone else's break-glass. The
 * justification is shown in full before anything is built — a ratifier
 * should read it, and what was done since, first.
 */
export function RatifyDialog({
  subject,
  subjectName,
  right,
  resource,
  breakGlassAt,
  justification,
  onClose,
  onBuilt,
}: {
  subject: string;
  subjectName?: string;
  right: GitNsRight;
  resource: string;
  breakGlassAt: string;
  justification: string;
  onClose: () => void;
  onBuilt: (task: SignedTask) => void;
}) {
  const [statement, setStatement] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = () => {
    const e = reasonError(statement);
    setError(e);
    if (!e) onBuilt(ratifyTask(subject, right, resource, breakGlassAt, statement));
  };
  return (
    <FormDialog
      title={`Ratify ${rightLabel(right).toLowerCase()} on ${shortName(resource)}`}
      onClose={onClose}
      onSubmit={submit}
      submitLabel="Build the ratification"
    >
      <p>
        <b>{subjectName ?? shortenDid(subject)}</b>{" "}
        <code className="gitns-party-did">{subject}</code> gave themselves this right on{" "}
        {new Date(breakGlassAt).toLocaleString()}, saying:
      </p>
      <blockquote className="gitns-justification">{justification}</blockquote>
      <p className="muted">
        Ratifying confirms they should keep it: the flag clears and it becomes an
        ordinary grant. If they should not keep it, revoke it instead.
      </p>
      <TextField
        label="Statement"
        value={statement}
        onChange={setStatement}
        placeholder="Optional"
        hint={`Kept in the audit record and sent to the other administrators. At most ${MAX_REASON} characters.`}
        error={error}
      />
    </FormDialog>
  );
}
