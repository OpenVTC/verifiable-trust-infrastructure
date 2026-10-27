// The community's repositories, as a member sees them (`git-ns/view/0.4`), and
// the member's own forge accounts.
//
// Reads are signed by this browser's portal key for the member, which the
// member delegated `git-ns/view` and `git-ns/account/link-status` to at
// sign-in, as the directory pages are. Nothing else under `git-ns` is: linking
// or unlinking an account binds what the forge then relies on as the member's,
// and every right change confers or withdraws authority, so the portal key may
// sign neither (`auth/oob/grant/0.2` consumer item 6). Linking and unlinking go
// through the member's wallet (`window.vtaWallet.git`), which signs as the
// member after asking them, and shows the forge's authorisation page and code
// in its own window — the page never sees the code. A member without it is
// shown the `cnm git link` command instead.

import type {
  GitNsForgeAccount,
  GitNsRepoSummary,
  GitNsRightRecord,
  GitNsViewNamespace,
} from "@/lib/wire-types";

import { send } from "./directory-api";

export const VIEW_TASK = "https://trusttasks.org/spec/git-ns/view/0.4";
export const LINK_STATUS_TASK = "https://trusttasks.org/spec/git-ns/account/link-status/0.1";

/** A recorded right, as 0.4 marks one its holder gave themselves. */
export type MemberRight = GitNsRightRecord & {
  breakGlass?: { by: string; at: string; justification: string; ratifiedBy?: string; ratifiedAt?: string };
};

export interface LinkedAccount {
  account: GitNsForgeAccount;
  linkedAt: string;
}

/** `git-ns/view/0.4#response`: 0.1's members, every record's `breakGlass`,
 *  each namespace's `kind` once known, and the member's linked accounts. */
export interface MemberGitView {
  namespaces: (GitNsViewNamespace & { kind?: "organization" | "user" })[];
  repos: GitNsRepoSummary[];
  rights: MemberRight[];
  accounts: LinkedAccount[];
}

export type LinkState = "pending" | "linked" | "expired" | "failed";

export interface LinkStatus {
  state: LinkState;
  account?: GitNsForgeAccount;
}

export const viewRepos = () => send<MemberGitView>(VIEW_TASK, {});
export const linkStatus = (linkId: string) => send<LinkStatus>(LINK_STATUS_TASK, { linkId });

// ── The wallet's git channel ─────────────────────────────────────────────

/** A link the wallet began: where to follow it. The authorisation page and
 *  any device code stay in the wallet's window. */
export interface WalletLinkStarted {
  linkId: string;
  expiresAt: string;
}

export interface WalletUnlinked {
  unlinked: GitNsForgeAccount;
  unlinkedAt: string;
}

/** `window.vtaWallet.git`, where the member's wallet offers it. */
export interface WalletGit {
  linkAccount(p: { hostDid: string; forge: string; member?: string }): Promise<WalletLinkStarted>;
  unlinkAccount(p: {
    hostDid: string;
    forge: string;
    accountId?: string;
    member?: string;
  }): Promise<WalletUnlinked>;
}

export function walletGit(): WalletGit | null {
  const w = (window as { vtaWallet?: { git?: Partial<WalletGit> } }).vtaWallet;
  const g = w?.git;
  return g && typeof g.linkAccount === "function" && typeof g.unlinkAccount === "function"
    ? (g as WalletGit)
    : null;
}

// ── Reading the view ─────────────────────────────────────────────────────

/** The five rights, strongest first, in the member's words. */
export const RIGHTS: readonly { right: GitNsRightRecord["right"]; label: string; on: string }[] = [
  { right: "git.ns.admin", label: "Administrator", on: "namespace" },
  { right: "git.repo.own", label: "Owner", on: "repository" },
  { right: "git.repo.maintain", label: "Maintainer", on: "repository" },
  { right: "git.repo.create", label: "Can create repositories", on: "namespace" },
  { right: "git.commit.sign", label: "Can sign commits", on: "either" },
];

export function rightLabel(right: string): string {
  return RIGHTS.find((r) => r.right === right)?.label ?? right;
}

function rank(right: string): number {
  const i = RIGHTS.findIndex((r) => r.right === right);
  return i < 0 ? RIGHTS.length : i;
}

/** Whether `outer` contains `inner`, by whole segment. */
export function contains(outer: string, inner: string): boolean {
  return inner === outer || inner.startsWith(`${outer}/`);
}

/** One resource the member holds something on, strongest right first. */
export interface Holding {
  resource: string;
  rights: MemberRight[];
}

/** The member's own rights, grouped by resource, strongest first. */
export function holdingsOf(view: MemberGitView, did: string): Holding[] {
  const by = new Map<string, MemberRight[]>();
  for (const r of view.rights) {
    if (r.subject !== did) continue;
    by.set(r.resource, [...(by.get(r.resource) ?? []), r]);
  }
  return [...by.entries()]
    .map(([resource, rights]) => ({
      resource,
      rights: rights.sort((a, b) => rank(a.right) - rank(b.right)),
    }))
    .sort(
      (a, b) =>
        rank(a.rights[0]!.right) - rank(b.rights[0]!.right) || a.resource.localeCompare(b.resource),
    );
}

/** The repositories the member owns or administers, with what others hold on
 *  each — the view lists every right on a resource its holder governs. */
export function governedOf(
  view: MemberGitView,
  did: string,
): { repo: GitNsRepoSummary; others: MemberRight[] }[] {
  const admins = view.rights
    .filter((r) => r.subject === did && r.right === "git.ns.admin")
    .map((r) => r.resource);
  return view.repos
    .filter((repo) => repo.owners.includes(did) || admins.some((ns) => contains(ns, repo.resource)))
    .map((repo) => ({
      repo,
      others: view.rights
        .filter((r) => r.subject !== did && contains(r.resource, repo.resource))
        .sort((a, b) => rank(a.right) - rank(b.right)),
    }));
}

/** Forges the member can link an account on: those with a bound namespace run
 *  by a bridge — the bridge is what gives the account its forge roles. */
export function linkableForges(view: MemberGitView): string[] {
  return [
    ...new Set(
      view.namespaces.filter((n) => n.mode === "bridge" && n.state === "bound").map((n) => n.forge),
    ),
  ].sort();
}

/** The resource's display name: `owner/repo` on the forge it names. */
export function shortResource(resource: string): { forge: string; path: string } {
  const i = resource.indexOf("/");
  return i < 0 ? { forge: resource, path: "" } : { forge: resource.slice(0, i), path: resource.slice(i + 1) };
}
