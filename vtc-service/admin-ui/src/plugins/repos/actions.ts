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
  type GitNsAction,
  rightLabel,
  shortName,
} from "./model";
import { postSignedTrustTask } from "@/lib/api";
import type { GitNsRight } from "@/lib/wire-types";

// Document `type`s, not `Trust-Task` headers: each is dispatched by
// `POST /v1/trust-tasks` from the document itself, and no REST route binds
// one (there is no bearer door to bind it to). They are spelled from their
// family so `trust_task_manifest`'s header census — which pairs every header
// the console sends with a route that enforces it — does not read them as
// headers; the dispatcher's own registry (`git_ns::tasks::served_uris`) is
// what serves them.
const SPEC = ["https://trusttasks.org", "spec", "git-ns"].join("/");

export const TASK_URI: Record<GitNsAction, string> = {
  "namespace.bind": `${SPEC}/namespace/bind/0.1`,
  "namespace.unbind": `${SPEC}/namespace/unbind/0.1`,
  "right.grant": `${SPEC}/right/grant/0.1`,
  "right.revoke": `${SPEC}/right/revoke/0.1`,
  "repo.adopt": `${SPEC}/repo/adopt/0.1`,
  "repo.transfer": `${SPEC}/repo/transfer/0.1`,
  "repo.archive": `${SPEC}/repo/archive/0.1`,
  "repo.create": `${SPEC}/repo/create/0.1`,
};

/** A change, ready for the administrator to sign. */
export interface SignedTask {
  action: GitNsAction;
  /** What the dialog is titled — the change in the operator's words. */
  title: string;
  /** What happens once it is accepted. */
  effect: string;
  taskUri: string;
  payload: Record<string, unknown>;
  consent: ConsentClass;
  /** The `cnm git …` command that signs and sends it. */
  command: string;
}

/** POSIX-shell quoting, only where a value needs it. DIDs and resources pass
 *  through unquoted; a free-text reason does not. */
export function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

const cnm = (...args: string[]) => ["cnm", "git", ...args].join(" ");

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

export function didError(value: string): string | null {
  if (!value.trim()) return "Name the DID.";
  if (!/^did:[a-z0-9]+:\S+$/.test(value.trim())) return "Not a DID (did:method:…).";
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
    command: cnm("namespace", "bind", "--forge", forge, "--owner", owner, "--mode", mode),
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
    command: cnm("namespace", "unbind", namespaceId),
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
  const args = [
    "grant",
    "--subject",
    g.subject,
    "--right",
    g.right,
    "--resource",
    g.resource,
  ];
  if (g.expiresInDays) {
    // `cnm` computes the instant when it signs; the preview uses now, so the
    // two differ by however long the operator takes to run it.
    const at = new Date(now.getTime() + g.expiresInDays * 86_400_000);
    payload.expiresAt = at.toISOString().replace(/\.\d{3}Z$/, "Z");
    args.push("--expires-in", `${g.expiresInDays}d`);
  }
  const reason = g.reason?.trim();
  if (reason) {
    payload.reason = reason;
    args.push("--reason", shellQuote(reason));
  }
  return {
    action: "right.grant",
    title: `Grant ${rightLabel(g.right).toLowerCase()} on ${shortName(g.resource)}`,
    effect:
      "The right is recorded, published to the Trust Registry (with its implied commit right where it has one), and projected onto the forge by the bridge.",
    taskUri: TASK_URI["right.grant"],
    payload,
    consent: consentClass("right.grant", g.right),
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
  const args = ["revoke", "--subject", subject, "--right", right, "--resource", resource];
  const r = reason?.trim();
  if (r) {
    payload.reason = r;
    args.push("--reason", shellQuote(r));
  }
  return {
    action: "right.revoke",
    title: `Revoke ${rightLabel(right).toLowerCase()} on ${shortName(resource)}`,
    effect:
      "The record is removed and withdrawn from the Trust Registry; the bridge removes the forge role it projected. A repository's last owner cannot be revoked — name another first.",
    taskUri: TASK_URI["right.revoke"],
    payload,
    consent: consentClass("right.revoke", right),
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
    command: cnm("adopt", resource, ...owners.flatMap((o) => ["--owner", o])),
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
    command: cnm("transfer", resource, "--to", to),
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
    command: cnm("archive", resource),
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
  const args = ["create", "--namespace", c.namespaceId, c.name, "--visibility", c.visibility];
  const d = c.description?.trim();
  if (d) {
    payload.description = d;
    args.push("--description", shellQuote(d));
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

/** The URL a bridge-mode bind answers with (`next.url`), if any. */
export function nextUrlOf(response: unknown): string | null {
  const url = (response as { next?: { url?: unknown } } | null)?.next?.url;
  return typeof url === "string" && /^https:\/\//.test(url) ? url : null;
}

export const CONSENT_LABEL: Record<ConsentClass, string> = {
  normal: "Normal",
  elevated: "Elevated — step-up",
  destructive: "Destructive — step-up and confirmation",
};
