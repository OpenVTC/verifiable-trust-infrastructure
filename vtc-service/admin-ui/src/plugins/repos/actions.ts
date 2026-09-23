// The changes the Repos screens offer, as the signed Trust Tasks they are.
//
// ## Why the console hands these over rather than sending them
//
// Every change to a git right is a `git-ns/*` Trust Task whose proof is
// REQUIRED, authorized by *the signer's own git rights* resolved from the
// VTC's records — not by an admin session. A bearer token carries no proof,
// so the daemon deliberately mounts no REST door for any of them
// (`routes/git_ns.rs`), and the console cannot yet sign a document (#1641).
//
// So each action here is built exactly as it will be sent — the task URI and
// the payload, validated the way the spec validates it — and handed to the
// administrator to sign: as the `cnm git …` command that signs it with their
// community profile's key where one exists, and as the document itself where
// `cnm` has no command yet (transfer, archive). When the console gains a
// signer, this module is where it plugs in, and nothing the screens build
// has to change.
//
// ## Step-up
//
// Design §6 classes grants of `own` and `repo.create`, transfer, archive and
// adopt as *elevated* (step-up), and bind, unbind and `ns.admin` as
// *destructive* (step-up and confirm). A passkey step-up elevates a console
// **session**, and a signed document has none, so running one here would be
// ceremony that authorizes nothing. The daemon's stand-in is
// `[git_ns] elevated_requires_admin` (default on): an elevated or destructive
// task is accepted only from a community administrator, in addition to the
// rights model's own entitlement. The dialog says which class a task is and
// what that means on this VTC; it does not pretend to have stepped anything up.

import {
  consentClass,
  type ConsentClass,
  type GitNsAction,
  rightLabel,
  shortName,
} from "./model";
import type { GitNsRight } from "@/lib/wire-types";

const SPEC = "https://trusttasks.org/spec/git-ns";

export const TASK_URI: Record<GitNsAction, string> = {
  "namespace.bind": `${SPEC}/namespace/bind/0.1`,
  "namespace.unbind": `${SPEC}/namespace/unbind/0.1`,
  "right.grant": `${SPEC}/right/grant/0.1`,
  "right.revoke": `${SPEC}/right/revoke/0.1`,
  "repo.adopt": `${SPEC}/repo/adopt/0.1`,
  "repo.transfer": `${SPEC}/repo/transfer/0.1`,
  "repo.archive": `${SPEC}/repo/archive/0.1`,
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
  /** The `cnm git …` command that signs and sends it, or `null` where `cnm`
   *  has no command for this task yet. */
  command: string | null;
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
        ? "The VTC asks the community's bridge where to send you, records the namespace as pending, and prints that URL. Install the App there; the namespace is bound when the bridge reports the install, and you become its first admin."
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
      "The recipient becomes an owner and the signer stops being one. Signed by an owner of the repository.",
    taskUri: TASK_URI["repo.transfer"],
    payload: { resource, to },
    consent: consentClass("repo.transfer"),
    command: null,
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
    command: null,
  };
}

/** The document body the signer wraps — URI and payload, as the dispatch
 *  spine reads them. The signer adds `id`, `issuedAt` and the proof. */
export function documentPreview(task: SignedTask): string {
  return JSON.stringify({ type: task.taskUri, payload: task.payload }, null, 2);
}

export const CONSENT_LABEL: Record<ConsentClass, string> = {
  normal: "Normal",
  elevated: "Elevated — step-up",
  destructive: "Destructive — step-up and confirmation",
};
