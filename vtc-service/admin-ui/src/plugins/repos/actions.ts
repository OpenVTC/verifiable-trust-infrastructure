// The changes the Repos screens offer, as the signed Trust Tasks they are.
//
// ## Two ways to send one
//
// Every change to a git right is a `git-ns/*` Trust Task whose proof is
// REQUIRED, authorized by *the signer's own git rights* resolved from the
// VTC's records — not by an admin session. The daemon mounts no bearer door
// for any of them (`routes/git_ns.rs`), so there is nothing to fall back to
// the way `signedOrBearer` falls back for the admin member verbs.
//
// **From this browser**, where it has an enrolled console signing key
// (#1684/#1692/#1695): `sendTask` signs the document with that key and posts
// it to `/v1/trust-tasks`. The daemon resolves the key's delegation to the
// operator's admin DID at execution time (`git_ns::tasks::acting_as`) and
// authorizes the task by *that* DID's git rights — a delegation confers no
// right of its own, so a console key is exactly as able as the operator.
//
// **Handed over**, where it has none (no WebCrypto Ed25519, or signing never
// enabled here): the same task, as the `cnm git …` command that signs it with
// the operator's community profile, and as the document itself. The dialog
// always shows both, so an operator who would rather sign from their terminal
// can.
//
// Nothing retries across the two: a signed task the VTC *refuses* is shown as
// refused, because it would be refused from the terminal too.
//
// ## Step-up
//
// Design §6 classes grants of `own` and `repo.create`, transfer, archive and
// adopt as *elevated* (step-up), and bind, unbind and `ns.admin` as
// *destructive* (step-up and confirm). A passkey step-up elevates a console
// **session**, and a signed document has none, so running one before sending
// would be ceremony that authorizes nothing. The console key was itself
// enrolled behind a step-up; beyond that, the daemon's stand-in is
// `[git_ns] elevated_requires_admin` (default on): an elevated or destructive
// task is accepted only from a community administrator, in addition to the
// rights model's own entitlement. The dialog says which class a task is and
// asks for an explicit confirmation of destructive ones before sending.

import {
  consentClass,
  type ConsentClass,
  driftRevertEffect,
  driftRevertImpact,
  type GitNsAction,
  isRoleDrift,
  rightLabel,
  shortName,
} from "./model";
import { postSignedTrustTask } from "@/lib/api";
import type { GitNsDriftItem, GitNsRight, GitNsRoleMap } from "@/lib/wire-types";

// Document `type`s, not `Trust-Task` headers: each is dispatched by
// `POST /v1/trust-tasks` from the document itself, and no REST route binds
// one — there is no bearer door to bind it to. `trust_task_manifest` pairs
// every header the console sends with a route that enforces it, and checks
// these against the dispatcher's own registry (`git_ns::tasks::served_uris`)
// instead, from its document-type allowlist.
export const TASK_URI: Record<GitNsAction, string> = {
  "namespace.bind": "https://trusttasks.org/spec/git-ns/namespace/bind/0.1",
  "namespace.unbind": "https://trusttasks.org/spec/git-ns/namespace/unbind/0.1",
  "namespace.reseat": "https://trusttasks.org/spec/git-ns/namespace/reseat/0.1",
  "right.grant": "https://trusttasks.org/spec/git-ns/right/grant/0.1",
  "right.revoke": "https://trusttasks.org/spec/git-ns/right/revoke/0.1",
  "repo.adopt": "https://trusttasks.org/spec/git-ns/repo/adopt/0.1",
  "repo.transfer": "https://trusttasks.org/spec/git-ns/repo/transfer/0.1",
  "repo.archive": "https://trusttasks.org/spec/git-ns/repo/archive/0.1",
  "repo.create": "https://trusttasks.org/spec/git-ns/repo/create/0.1",
  "drift.resolve": "https://trusttasks.org/spec/git-ns/drift/resolve/0.1",
  "roles.reproject": "https://trusttasks.org/spec/git-ns/roles/reproject/0.1",
};

/** Someone a change is about, named in the dialog before it is signed. */
export interface Party {
  /** `Recipient`, `New owner`, `Revoked from`, … */
  role: string;
  did: string;
}

/** A change, ready to sign. */
export interface SignedTask {
  action: GitNsAction;
  /** What the dialog is titled — the change in the operator's words. */
  title: string;
  /** What happens once it is accepted. */
  effect: string;
  taskUri: string;
  payload: Record<string, unknown>;
  consent: ConsentClass;
  /** What authorizes it, where that is not the class's usual account (the
   *  signer's own git rights) — a reseat is authorized by the
   *  community-administrator capability instead. */
  consentNote?: string;
  /** The resource it acts on, shown in full in the dialog. */
  resource: string;
  /** Who it is about, shown with name and full DID in the dialog. */
  parties: Party[];
  /** The `cnm git …` command that signs and sends it. */
  command: string;
}

/**
 * Shell quoting for one argument, safe in sh, bash, zsh and fish alike.
 *
 * Every argument of every command goes through this — DIDs, resources, ids,
 * names, free text alike — because the command is meant to be pasted into a
 * shell, and a value that validated as a DID is not thereby safe to run: a
 * DID's method-specific id is not a shell word.
 *
 * A value is left bare only when it is made of characters no shell treats
 * specially and its first character cannot start an expansion or an option:
 * not `-` (an option), `=` (zsh's `=cmd` path expansion) or `%` (fish's
 * `%self`). Everything else is quoted so that sh, bash, zsh and fish all read
 * the same bytes back. POSIX's `'…'\''…'` is not enough: fish reads `\'` and
 * `\\` as escapes even inside single quotes, so a value such as
 * `x\' ; echo INJECTED ; echo \` closes the quote early there. So runs of
 * characters other than `'` and `\` go inside single quotes (where nothing
 * else — `$`, backticks, newlines — is special in any of these shells), and
 * each `'` is written `"'"` and each `\` is written `"\\"`, which mean the
 * same single character inside double quotes in POSIX shells and in fish.
 */
export function shellQuote(value: string): string {
  if (value !== "" && /^[A-Za-z0-9_@%+=:,./-]+$/.test(value) && !/^[-=%]/.test(value)) {
    return value;
  }
  const parts = value.match(/[^'\\]+|'|\\/g) ?? [];
  if (parts.length === 0) return "''";
  return parts
    .map((part) => (part === "'" ? `"'"` : part === "\\" ? `"\\\\"` : `'${part}'`))
    .join("");
}

/** A subcommand word or an option, spelled by this module — never a value. */
type Word = { word: string };
const w = (word: string): Word => ({ word });
/** `--flag=value`: the value is quoted and bound to its flag, so even a value
 *  that begins with `-` cannot be read as another option. */
const opt = (flag: string, value: string): string => `--${flag}=${shellQuote(value)}`;

/**
 * `cnm git …`. Words are this module's own literals; every other argument is
 * a value and is quoted — positionals through `shellQuote`, options through
 * `opt`, which binds the value to its flag.
 */
function cnm(...parts: (Word | string | { opt: string })[]): string {
  const out = ["cnm", "git"];
  for (const p of parts) {
    if (typeof p === "string") out.push(shellQuote(p));
    else if ("word" in p) out.push(p.word);
    else out.push(p.opt);
  }
  return out.join(" ");
}
const o = (flag: string, value: string) => ({ opt: opt(flag, value) });

// ── validation, as the specs state it ───────────────────────────────────

/** A forge host: lowercase DNS, no scheme, no port, no path. */
export function forgeHostError(value: string): string | null {
  if (!value) return "Name the forge host, such as github.com.";
  if (/[A-Z]/.test(value)) return "Forge hosts are lowercase.";
  if (/^[a-z]+:\/\//.test(value)) return "The host only — no https://.";
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(value)) {
    return "Not a DNS host name.";
  }
  return null;
}

/** An owner or repository segment: lowercase, one segment, no leading dot. */
export function segmentError(value: string, what = "owner"): string | null {
  if (!value) return `Name the ${what}.`;
  if (/[A-Z]/.test(value)) return "Forges compare names case-insensitively, so they are sent lowercase.";
  if (value.includes("/")) return `One ${what} name, without slashes.`;
  if (value.startsWith(".")) return "A name cannot start with a dot.";
  if (!/^[a-z0-9._-]+$/.test(value)) return "Letters, digits, dots, dashes and underscores only.";
  return null;
}

// DID Core §3.1: `did:` method-name `:` method-specific-id, where
// method-name = 1*method-char (a-z, 0-9) and method-specific-id =
// *( *idchar ":" ) 1*idchar, idchar = ALPHA / DIGIT / "." / "-" / "_" /
// pct-encoded. A DID, not a DID URL: no path, query or `#fragment` — every
// field this checks names a party (a subject, an owner, a recipient), and the
// VTC checks it the same way (`vta_sdk::identifier::validate_did_core`),
// including its 1024-byte bound.
const IDCHAR = "(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})";
const DID_RE = new RegExp(`^did:[a-z0-9]+:(?:${IDCHAR}*:)*${IDCHAR}+$`);
const MAX_DID = 1024;

export function didError(value: string): string | null {
  const v = value.trim();
  if (!v) return "Name the DID.";
  if (v.includes("#")) return "A DID, not a DID URL — drop the #fragment.";
  if (new TextEncoder().encode(v).length > MAX_DID) return `At most ${MAX_DID} bytes.`;
  if (!DID_RE.test(v)) return "Not a DID (did:method:id, DID Core syntax).";
  return null;
}

/** The longest reason the specs accept (`git-ns/right/{grant,revoke}`). */
export const MAX_REASON = 1024;

export function reasonError(value: string): string | null {
  return value.trim().length > MAX_REASON
    ? `At most ${MAX_REASON} characters — it is ${value.trim().length}.`
    : null;
}

/** A reseat's statement: REQUIRED, 1–1024 characters
 *  (`git-ns/namespace/reseat/0.1`). */
export function statementError(value: string): string | null {
  const v = value.trim();
  if (!v) return "Say why the namespace is headless and why this member.";
  return v.length > MAX_REASON ? `At most ${MAX_REASON} characters — it is ${v.length}.` : null;
}

/** The longest expiry the form offers: ten years. A right meant to outlive
 *  that is one meant to have no expiry. */
export const MAX_EXPIRY_DAYS = 3650;

export function expiryDaysError(value: string): string | null {
  if (!value.trim()) return null;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) {
    return "Whole days, 1 or more — or leave it empty for no expiry.";
  }
  if (n > MAX_EXPIRY_DAYS) {
    return `At most ${MAX_EXPIRY_DAYS} days — leave it empty for no expiry.`;
  }
  return null;
}

// ── builders ────────────────────────────────────────────────────────────

export function bindTask(forge: string, owner: string, mode: "bridge" | "manual"): SignedTask {
  return {
    action: "namespace.bind",
    title: `Bind ${forge}/${owner}`,
    effect:
      mode === "bridge"
        ? "The VTC asks the community's bridge where to send you, records the namespace as pending, and answers with that URL. Install the App there; the namespace is bound when the bridge reports the install, and you become its first admin."
        : "The namespace is bound at once and you become its first admin. No bridge acts on the forge: people with access carry out the steps the VTC names.",
    taskUri: TASK_URI["namespace.bind"],
    payload: { forge, owner, mode },
    consent: consentClass("namespace.bind"),
    resource: `${forge}/${owner}`,
    parties: [],
    command: cnm(w("namespace"), w("bind"), o("forge", forge), o("owner", owner), o("mode", mode)),
  };
}

export function unbindTask(namespaceId: string, resource: string): SignedTask {
  return {
    action: "namespace.unbind",
    title: `Unbind ${resource}`,
    effect:
      "Every right in the namespace is revoked and withdrawn from the Trust Registry, and its repositories become detached.",
    taskUri: TASK_URI["namespace.unbind"],
    payload: { namespace: namespaceId },
    consent: consentClass("namespace.unbind"),
    resource,
    parties: [],
    command: cnm(w("namespace"), w("unbind"), namespaceId),
  };
}

/**
 * `git-ns/namespace/reseat` 0.1: a community administrator seats `subject` —
 * a current member — as the permanent `git.ns.admin` of a headless namespace.
 */
export function reseatTask(
  namespaceId: string,
  resource: string,
  subject: string,
  statement: string,
): SignedTask {
  const s = statement.trim();
  return {
    action: "namespace.reseat",
    title: `Reseat ${resource}`,
    effect:
      "The member receives namespace admin (git.ns.admin) with no expiry, published to the Trust Registry and projected onto the forge by the bridge. The statement becomes the right's reason, is kept in the audit record with how each earlier admin record ended, and is shown to the namespace's repository owners. Refused while a current member holds a live git.ns.admin there.",
    taskUri: TASK_URI["namespace.reseat"],
    payload: { namespace: namespaceId, subject, statement: s },
    consent: consentClass("namespace.reseat"),
    consentNote:
      "Authorized by the community-administrator capability, not by a git right: a headless namespace has nobody holding one. Only a community administrator (an admin not limited to some contexts) can sign it, and only while the namespace is headless.",
    resource,
    parties: [{ role: "Becomes namespace admin", did: subject }],
    command: cnm(w("reseat"), namespaceId, o("subject", subject), o("statement", s)),
  };
}

export interface GrantInput {
  subject: string;
  right: GitNsRight;
  resource: string;
  /** Whole days from signing; omitted for no expiry. */
  expiresInDays?: number;
  reason?: string;
}

export function grantTask(g: GrantInput, now = new Date()): SignedTask {
  const payload: Record<string, unknown> = {
    subject: g.subject,
    right: g.right,
    resource: g.resource,
  };
  const args = [w("grant"), o("subject", g.subject), o("right", g.right), o("resource", g.resource)];
  if (g.expiresInDays) {
    // `cnm` computes the instant when it signs; the preview uses now, so the
    // two differ by however long the operator takes to run it.
    const at = new Date(now.getTime() + g.expiresInDays * 86_400_000);
    payload.expiresAt = at.toISOString().replace(/\.\d{3}Z$/, "Z");
    args.push(o("expires-in", `${g.expiresInDays}d`));
  }
  const reason = g.reason?.trim();
  if (reason) {
    payload.reason = reason;
    args.push(o("reason", reason));
  }
  return {
    action: "right.grant",
    title: `Grant ${rightLabel(g.right).toLowerCase()} on ${shortName(g.resource)}`,
    effect:
      "The right is recorded, published to the Trust Registry (with its implied commit right where it has one), and projected onto the forge by the bridge.",
    taskUri: TASK_URI["right.grant"],
    payload,
    consent: consentClass("right.grant", g.right),
    resource: g.resource,
    parties: [{ role: "Receives the right", did: g.subject }],
    command: cnm(...args),
  };
}

export function revokeTask(
  subject: string,
  right: GitNsRight,
  resource: string,
  reason?: string,
): SignedTask {
  const payload: Record<string, unknown> = { subject, right, resource };
  const args = [w("revoke"), o("subject", subject), o("right", right), o("resource", resource)];
  const r = reason?.trim();
  if (r) {
    payload.reason = r;
    args.push(o("reason", r));
  }
  return {
    action: "right.revoke",
    title: `Revoke ${rightLabel(right).toLowerCase()} on ${shortName(resource)}`,
    effect:
      "The record is removed and withdrawn from the Trust Registry; the bridge removes the forge role it projected. A repository's last owner cannot be revoked — name another first.",
    taskUri: TASK_URI["right.revoke"],
    payload,
    consent: consentClass("right.revoke", right),
    resource,
    parties: [{ role: "Loses the right", did: subject }],
    command: cnm(...args),
  };
}

export function adoptTask(resource: string, owners: string[]): SignedTask {
  return {
    action: "repo.adopt",
    title: `Adopt ${shortName(resource)}`,
    effect:
      "The repository comes under governance with these owners, and the bridge bootstraps commit trust on it: workflow, keyring, variables and the required check.",
    taskUri: TASK_URI["repo.adopt"],
    payload: { resource, owners },
    consent: consentClass("repo.adopt"),
    resource,
    parties: owners.map((did) => ({ role: "First owner", did })),
    command: cnm(w("adopt"), resource, ...owners.map((did) => o("owner", did))),
  };
}

export function transferTask(resource: string, to: string): SignedTask {
  return {
    action: "repo.transfer",
    title: `Transfer ownership of ${shortName(resource)}`,
    effect:
      "The recipient becomes an owner and the signer stops being one. Only an owner can transfer their own ownership; a namespace admin names an owner with a grant instead.",
    taskUri: TASK_URI["repo.transfer"],
    payload: { resource, to },
    consent: consentClass("repo.transfer"),
    resource,
    parties: [{ role: "New owner", did: to }],
    command: cnm(w("transfer"), resource, o("to", to)),
  };
}

export function archiveTask(resource: string): SignedTask {
  return {
    action: "repo.archive",
    title: `Archive ${shortName(resource)}`,
    effect:
      "The bridge archives the repository on the forge and every commit right on it is withdrawn from the Trust Registry. Ownership records stay.",
    taskUri: TASK_URI["repo.archive"],
    payload: { resource },
    consent: consentClass("repo.archive"),
    resource,
    parties: [],
    command: cnm(w("archive"), resource),
  };
}

export interface CreateInput {
  namespaceId: string;
  /** `github.com/acme`, for the title and the resource it will have. */
  namespaceResource: string;
  name: string;
  visibility: "public" | "private";
  description?: string;
  /** A personal account: no bot can create there, so the VTC reserves the
   *  name and returns the steps for the account holder. */
  personal: boolean;
}

export function createTask(c: CreateInput): SignedTask {
  const payload: Record<string, unknown> = {
    namespace: c.namespaceId,
    name: c.name,
    visibility: c.visibility,
  };
  const args = [w("create"), o("namespace", c.namespaceId), c.name, o("visibility", c.visibility)];
  const d = c.description?.trim();
  if (d) {
    payload.description = d;
    args.push(o("description", d));
  }
  return {
    action: "repo.create",
    title: `Create ${shortName(`${c.namespaceResource}/${c.name}`)}`,
    effect: c.personal
      ? "The VTC reserves the name and answers with the commands the account holder runs to create it; it becomes active when adopted. The signer becomes its owner."
      : "The bridge creates the repository and bootstraps commit trust on it — workflow, keyring, variables, required check. The signer becomes its owner. Needs git.repo.create on the namespace.",
    taskUri: TASK_URI["repo.create"],
    payload,
    consent: consentClass("repo.create"),
    resource: `${c.namespaceResource}/${c.name}`,
    parties: [],
    command: cnm(...args),
  };
}

/**
 * `git-ns/drift/resolve` 0.1, `revert`: the bridge makes the forge match the
 * VTC's projection again for one reported drift item, and no right changes.
 *
 * The item is selected as the spec selects it — by `type`, by account for
 * the role types — and by the `observed` value read here, so a revert decided
 * about one forge state is refused (`driftNotFound`) rather than applied to
 * another. The account's `login` is display only; its `forge` and `id` pick
 * it out.
 */
export function driftRevertTask(
  resource: string,
  item: GitNsDriftItem,
  reason?: string,
  /** The repository's role map (`GitNsRepoRow.roleMap`); absent while the
   *  bridge has not reported it, when every role revert weighs as revoking
   *  own. */
  roleMap?: GitNsRoleMap | null,
): SignedTask {
  const drift: Record<string, unknown> = { type: item.type };
  const impact = driftRevertImpact(item, roleMap);
  const args: (Word | string | { opt: string })[] = [
    w("drift"),
    w("resolve"),
    resource,
    w("revert"),
    o("type", item.type),
  ];
  if (isRoleDrift(item) && item.account) {
    drift.account = { forge: item.account.forge, id: item.account.id, login: item.account.login };
    args.push(o("account-id", item.account.id), o("account-login", item.account.login));
  }
  if (item.observed !== undefined) {
    drift.observed = item.observed;
    args.push(o("observed", item.observed));
  }
  const payload: Record<string, unknown> = { resource, drift, action: "revert" };
  const r = reason?.trim();
  if (r) {
    payload.reason = r;
    args.push(o("reason", r));
  }
  return {
    action: "drift.resolve",
    title: `Revert drift on ${shortName(resource)}`,
    effect: `${driftRevertEffect(item)} The item leaves the outstanding drift and the bridge inspects the repository again to confirm it; refused if the forge no longer shows what was read here.`,
    taskUri: TASK_URI["drift.resolve"],
    payload,
    consent: consentClass("drift.resolve", impact),
    consentNote:
      impact === "git.repo.own"
        ? "Taking an admin role off the forge weighs as revoking ownership, so this VTC gates it as that revocation: an elevated action it accepts only from a community administrator (`elevated_requires_admin`) who also holds git.repo.own here."
        : "Gated as the revocation it amounts to, which is normal-class: authorized by the signer's git.repo.own on the repository, explicit or implied by git.ns.admin.",
    resource,
    parties: [],
    command: cnm(...args),
  };
}

/**
 * Sign `task` with this browser's console key and send it.
 *
 * Throws `SigningUnavailableError` when this browser cannot sign — the dialog
 * then offers only the hand-over — and an `ApiError` carrying the VTC's own
 * refusal (`git-ns:lastOwner`, `permissionDenied`, …) otherwise.
 */
export function sendTask<T = Record<string, unknown>>(task: SignedTask): Promise<T> {
  return postSignedTrustTask<T>(task.taskUri, task.payload);
}

/** The document body the signer wraps — URI and payload, as the dispatch
 *  spine reads them. The signer adds `id`, `issuedAt` and the proof. */
export function documentPreview(task: SignedTask): string {
  return JSON.stringify({ type: task.taskUri, payload: task.payload }, null, 2);
}

/** The URL a bridge-mode bind answers with (`next.url`), if it is https. */
export function nextUrlOf(response: unknown): string | null {
  const url = (response as { next?: { url?: unknown } } | null)?.next?.url;
  return typeof url === "string" && /^https:\/\//.test(url) ? url : null;
}

/** Whether `url` is on `forge` — the only case the page may call it
 *  "continue on {forge}". A bridge that answered with somewhere else is shown
 *  as that, not as the forge. */
export function urlIsOnForge(url: string, forge: string): boolean {
  try {
    return new URL(url).hostname === forge;
  } catch {
    return false;
  }
}

export const CONSENT_LABEL: Record<ConsentClass, string> = {
  normal: "Normal",
  elevated: "Elevated — step-up",
  destructive: "Destructive — step-up and confirmation",
};

/**
 * `git-ns/roles/reproject/0.1` — have the bridge re-apply the forge roles of
 * every active or orphaned repository in a namespace, or of one repository,
 * from the VTC's rights under the bridge's current role map. No right
 * changes. Signed by a community administrator or a namespace admin, or —
 * for one repository — its owner.
 */
export function reprojectTask(resource: string, reason?: string): SignedTask {
  const payload: Record<string, unknown> = { resource };
  const args: (Word | string | { opt: string })[] = [w("reproject"), resource];
  const r = reason?.trim();
  if (r) {
    payload.reason = r;
    args.push(o("reason", r));
  }
  const whole = resource.split("/").length === 2;
  return {
    action: "roles.reproject",
    title: `Re-project roles on ${whole ? resource : shortName(resource)}`,
    effect: `The VTC sends the bridge the complete forge roles of ${whole ? "every active or orphaned repository in the namespace" : "the repository"} again, and the bridge applies them under its current role map: roles are raised or lowered to what each person's rights call for, and a role it projected that no right calls for is taken off. No right changes and nothing is published.`,
    taskUri: TASK_URI["roles.reproject"],
    payload,
    consent: consentClass("roles.reproject"),
    consentNote:
      whole
        ? "Authorized by the community-administrator capability, or by git.ns.admin on the namespace by explicit record; owning some of its repositories is not enough."
        : "Authorized by git.repo.own on the repository (explicit, or implied by git.ns.admin), git.ns.admin on its namespace, or the community-administrator capability.",
    resource,
    parties: [],
    command: cnm(...args),
  };
}
