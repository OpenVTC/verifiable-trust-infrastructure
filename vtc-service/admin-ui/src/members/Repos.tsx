// The community's repositories in the member portal (`git-ns/view/0.4`):
//
//   #/repos   What you may do on the community's repositories, what others
//             hold on the ones you own, every repository the community
//             governs, and the forge accounts linked to you.
//
// Read with this browser's portal key for the member, as the directory is.
// Granting and revoking stay where they are signed by your own key (`cnm git`,
// the console). Linking or unlinking a forge account goes through your wallet,
// which asks you first and shows the forge's page and code in its own window.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { GitBranch, KeyRound, Link2, Unlink } from "lucide-react";

import { DirectoryError } from "./directory-api";
import {
  governedOf,
  holdingsOf,
  linkableForges,
  linkStatus,
  rightLabel,
  shortResource,
  viewRepos,
  walletGit,
  type LinkedAccount,
  type MemberRight,
  type WalletLinkStarted,
} from "./git-api";
import { Crumbs } from "./member-card";

const POLL_MS = 5000;

function shortDid(did: string): string {
  return did.length > 34 ? `${did.slice(0, 20)}…${did.slice(-8)}` : did;
}

function Who({ did, me }: { did: string; me: string }) {
  return did === me ? <strong>you</strong> : <code title={did}>{shortDid(did)}</code>;
}

function Resource({ resource }: { resource: string }) {
  const { forge, path } = shortResource(resource);
  return (
    <span className="repo-name">
      <GitBranch size={16} aria-hidden="true" /> <strong>{path}</strong>{" "}
      <span className="muted">on {forge}</span>
    </span>
  );
}

function day(iso: string): string {
  return new Date(iso).toLocaleDateString();
}

function RightPills({ rights }: { rights: MemberRight[] }) {
  return (
    <span className="pills">
      {rights.map((r) => (
        <span key={r.right} className={r.breakGlass && !r.breakGlass.ratifiedBy ? "pill pill-warn" : "pill pill-ok"}>
          {rightLabel(r.right)}
          {r.expiresAt ? ` · until ${day(r.expiresAt)}` : ""}
          {r.breakGlass && !r.breakGlass.ratifiedBy ? " · break-glass, not yet ratified" : ""}
        </span>
      ))}
    </span>
  );
}

function Unavailable({ error }: { error: unknown }) {
  const e = error instanceof DirectoryError ? error : null;
  return (
    <div className="alert" role="status">
      {e?.needsWallet ? (
        <>
          <p className="alert-title">Sign in with your wallet to see the repositories.</p>
          <p>
            Your wallet lets this browser read what you may do here for this session. Sign out,
            then sign in again with &ldquo;Sign in with your wallet&rdquo;.
          </p>
        </>
      ) : (
        <>
          <p className="alert-title">The repositories aren&rsquo;t available right now.</p>
          <p>{(error as Error)?.message}</p>
        </>
      )}
    </div>
  );
}

export function ReposPage({ hostDid, member }: { hostDid: string; member: string }) {
  const view = useQuery({ queryKey: ["git", "view"], queryFn: viewRepos, retry: false });
  const v = view.data;
  const holdings = v ? holdingsOf(v, member) : [];
  const governed = v ? governedOf(v, member) : [];
  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Repositories" }]} />
      <section className="welcome">
        <p className="eyebrow">Repositories</p>
        <h1>Repositories</h1>
        <p className="lead">
          The community decides who may create, own and sign commits for its repositories. Here
          is what it has given you.
        </p>
      </section>
      {view.isPending && <p className="muted">Loading…</p>}
      {view.isError && <Unavailable error={view.error} />}
      {v && (
        <>
          <section aria-labelledby="access-heading">
            <h2 id="access-heading">Your access</h2>
            {holdings.length === 0 ? (
              <p className="muted">You hold no rights on the community&rsquo;s repositories yet.</p>
            ) : (
              <ul className="repo-list">
                {holdings.map((h) => (
                  <li key={h.resource} className="card repo-row">
                    <Resource resource={h.resource} />
                    <RightPills rights={h.rights} />
                    <span className="muted">
                      Given by <Who did={h.rights[0]!.grantedBy} me={member} /> on{" "}
                      {day(h.rights[0]!.grantedAt)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {governed.length > 0 && (
            <section aria-labelledby="governed-heading">
              <h2 id="governed-heading">Shared on repositories you look after</h2>
              <ul className="repo-list">
                {governed.map(({ repo, others }) => (
                  <li key={repo.resource} className="card repo-row">
                    <Resource resource={repo.resource} />
                    {others.length === 0 ? (
                      <span className="muted">Nobody else holds a right on it.</span>
                    ) : (
                      <ul className="repo-grants">
                        {others.map((r) => (
                          <li key={`${r.subject}-${r.right}-${r.resource}`}>
                            <Who did={r.subject} me={member} />: {rightLabel(r.right)}
                            {r.resource !== repo.resource && (
                              <span className="muted"> (on {shortResource(r.resource).path})</span>
                            )}
                            {r.reason && <span className="muted"> — {r.reason}</span>}
                          </li>
                        ))}
                      </ul>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}

          <ForgeAccounts
            hostDid={hostDid}
            member={member}
            accounts={v.accounts}
            forges={linkableForges(v)}
          />

          <section aria-labelledby="all-heading">
            <h2 id="all-heading">In the community</h2>
            {v.repos.length === 0 ? (
              <p className="muted">The community governs no repositories yet.</p>
            ) : (
              <ul className="repo-list">
                {v.repos.map((repo) => (
                  <li key={repo.resource} className="card repo-row">
                    <Resource resource={repo.resource} />
                    <span className="pills">
                      <span className="pill">{repo.visibility}</span>
                      {repo.state !== "active" && <span className="pill">{repo.state}</span>}
                    </span>
                    <span className="muted">
                      {repo.owners.length === 0 ? (
                        "Looked after by its namespace's administrators"
                      ) : (
                        <>
                          Owned by{" "}
                          {repo.owners.map((o, i) => (
                            <span key={o}>
                              {i > 0 && ", "}
                              <Who did={o} me={member} />
                            </span>
                          ))}
                        </>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </main>
  );
}

type Pending = WalletLinkStarted & { forge: string };

/** The forge accounts linked to the member, and linking or unlinking one
 *  through the wallet. The link's state is followed here with the portal key
 *  (`git-ns/account/link-status`). */
function ForgeAccounts({
  hostDid,
  member,
  accounts,
  forges,
}: {
  hostDid: string;
  member: string;
  accounts: LinkedAccount[];
  forges: string[];
}) {
  const qc = useQueryClient();
  const wallet = walletGit();
  const [pending, setPending] = useState<Pending | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const linked = new Map(accounts.map((a) => [a.account.forge, a]));
  const unlinkedForges = forges.filter((f) => !linked.has(f));

  const status = useQuery({
    queryKey: ["git", "link", pending?.linkId],
    queryFn: async () => {
      const s = await linkStatus(pending!.linkId);
      if (s.state !== "pending") {
        setPending(null);
        setNote(
          s.state === "linked"
            ? `Linked ${s.account?.login ?? "your account"} on ${s.account?.forge ?? "the forge"}. The community gives it the forge roles your rights call for.`
            : s.state === "expired"
              ? "The link was not authorised in time. Start it again when you are ready."
              : "The forge refused the link, or that account is already linked to another member.",
        );
        void qc.invalidateQueries({ queryKey: ["git", "view"] });
      }
      return s;
    },
    enabled: Boolean(pending),
    refetchInterval: POLL_MS,
    retry: false,
  });

  const link = useMutation({
    mutationFn: (forge: string) => wallet!.linkAccount({ hostDid, forge, member }),
    onSuccess: (started, forge) => {
      setNote(null);
      setPending({ ...started, forge });
    },
    onError: (e) => setNote((e as Error).message),
  });
  const unlink = useMutation({
    mutationFn: (a: LinkedAccount) =>
      wallet!.unlinkAccount({
        hostDid,
        forge: a.account.forge,
        accountId: a.account.id,
        member,
      }),
    onSuccess: (u) => {
      setNote(`Unlinked ${u.unlinked.login} on ${u.unlinked.forge}. Its forge roles are withdrawn.`);
      void qc.invalidateQueries({ queryKey: ["git", "view"] });
    },
    onError: (e) => setNote((e as Error).message),
  });

  if (accounts.length === 0 && forges.length === 0) return null;
  return (
    <section className="card" aria-labelledby="accounts-heading">
      <div className="card-head">
        <KeyRound size={18} aria-hidden="true" />
        <h2 id="accounts-heading">Your forge accounts</h2>
      </div>
      <p className="muted">
        The community gives your account on a forge the roles your rights call for once it knows
        which account is yours.
      </p>
      {note && (
        <p className="note" role="status">
          {note}
        </p>
      )}
      {pending && (
        <p className="note" role="status">
          Finish linking on {pending.forge} in your wallet&rsquo;s window, before{" "}
          {new Date(pending.expiresAt).toLocaleTimeString()}.
          {status.isError ? ` ${(status.error as Error).message}` : " Waiting for the forge…"}
        </p>
      )}
      <ul className="repo-list">
        {[...linked.values()].map((a) => (
          <li key={a.account.forge} className="repo-row">
            <span>
              <strong>{a.account.login}</strong> <span className="muted">on {a.account.forge}</span>
            </span>
            <span className="muted">Linked {day(a.linkedAt)}</span>
            {wallet && (
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                disabled={unlink.isPending}
                onClick={() => unlink.mutate(a)}
              >
                <Unlink size={14} aria-hidden="true" /> Unlink
              </button>
            )}
          </li>
        ))}
        {unlinkedForges.map((forge) => (
          <li key={forge} className="repo-row">
            <span>
              No account linked <span className="muted">on {forge}</span>
            </span>
            {wallet ? (
              <button
                type="button"
                className="btn btn-primary btn-sm"
                disabled={link.isPending || Boolean(pending)}
                onClick={() => link.mutate(forge)}
              >
                <Link2 size={14} aria-hidden="true" /> Link your {forge} account
              </button>
            ) : (
              <span className="muted">
                Link it with your wallet, or run <code>cnm git link --forge {forge}</code>.
              </span>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
