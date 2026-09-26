// One repository: who holds what on it, whether commit trust is switched on,
// what that puts in the public Trust Registry, where the forge has drifted, and
// what happened to it lately.

import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Check, Plus, X } from "lucide-react";

import { NamedDid } from "@/components/NamedDid";
import { useNameBook } from "@/lib/names";
import { useIsSuperAdmin, useViewerDid } from "@/lib/viewer";
import type {
  GitNsDriftItem,
  GitNsNamespaceRow,
  GitNsRepoRow,
  GitNsRight,
  GitNsRightRow,
} from "@/lib/wire-types";

import { archiveTask, driftAdoptTask, driftRevertTask, type SignedTask } from "./actions";
import {
  fetchAccounts,
  fetchActivity,
  fetchDrift,
  fetchNamespaces,
  fetchProjection,
  fetchRepos,
  fetchRights,
  type ForgeAccounts,
  gitNsKeys,
  indexAccounts,
  memberForAccount,
} from "./api";
import {
  AdoptDialog,
  GrantDialog,
  DriftResolveDialog,
  RevokeDialog,
  TransferDialog,
} from "./dialogs";
import {
  activityVerb,
  bootstrapSteps,
  desiredTuples,
  expiresWithin,
  guardFor,
  inheritedRights,
  isRight,
  isServiceGrant,
  lastCheckOf,
  REPO_RIGHTS,
  repoRights,
  type AdoptStanding,
  adoptStanding,
  projectedRepoRank,
  isAdoptableKind,
  repoStatus,
  revertStanding,
  rightLabel,
  shortName,
} from "./model";
import {
  errorMessage,
  readErrorMessage,
  errorStatus,
  formatDay,
  memberPath,
  namespacePath,
  REPOS_PATH,
  SignTaskDialog,
  ToneChip,
} from "./ui";

type Dialog =
  | { kind: "grant"; initialRight?: "git.repo.own"; title?: string }
  | { kind: "transfer" }
  | { kind: "revoke"; row: GitNsRightRow }
  | { kind: "adopt" }
  | { kind: "drift"; item: GitNsDriftItem; adopt?: { member: string; right: GitNsRight } }
  | { kind: "sign"; task: SignedTask };

const RIGHT_TONE: Record<string, "accent" | "success" | "neutral" | "danger"> = {
  "git.ns.admin": "danger",
  "git.repo.own": "accent",
  "git.repo.maintain": "success",
  "git.commit.sign": "neutral",
};

function ForgeAccountCell({
  did,
  forge,
  forges,
  right,
}: {
  did: string;
  forge: string;
  forges: ForgeAccounts | undefined;
  right: string;
}) {
  const acct = forges?.get(did)?.get(forge);
  if (!acct) {
    return (
      <span className="muted">
        Not linked{right === "git.commit.sign" ? " · fork pull requests" : ""}
      </span>
    );
  }
  return <span title={`${forge} id ${acct.id}`}>@{acct.login}</span>;
}

function GrantedBy({
  row,
  vtcDid,
}: {
  row: GitNsRightRow;
  vtcDid: string | undefined;
}) {
  const book = useNameBook();
  if (row.origin === "roleDerived") {
    return <span className="muted">Role-derived · configuration</span>;
  }
  if (!row.grantedBy) return <span className="muted">—</span>;
  return (
    <span className={row.granterDeparted ? "gitns-warn" : undefined}>
      {row.grantedBy === vtcDid ? (
        "The community"
      ) : (
        <NamedDid did={row.grantedBy} book={book} />
      )}
      {row.granterDeparted && " · departed"}
    </span>
  );
}

function PeopleTable({
  rows,
  forge,
  forges,
  onRevoke,
  readOnlyNote,
  vtcDid,
}: {
  rows: GitNsRightRow[];
  vtcDid: string | undefined;
  forge: string;
  forges: ForgeAccounts | undefined;
  onRevoke?: (row: GitNsRightRow) => void;
  readOnlyNote?: (row: GitNsRightRow) => string | null;
}) {
  const book = useNameBook();
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">Person</th>
            <th scope="col">Right</th>
            <th scope="col">{forge}</th>
            <th scope="col">Granted by</th>
            <th scope="col">
              <span className="visually-hidden">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const note = readOnlyNote?.(r) ?? null;
            const name = book.nameOf(r.subject) ?? r.subject;
            return (
              <tr key={`${r.subject}|${r.right}|${r.origin}`}>
                <td>
                  <Link to={memberPath(r.subject)}>
                    <NamedDid did={r.subject} book={book} />
                  </Link>
                  {!r.subjectMember && (
                    <div>
                      <ToneChip tone="warning" title="Not a member of this community">
                        External signer
                      </ToneChip>
                    </div>
                  )}
                </td>
                <td>
                  <ToneChip tone={RIGHT_TONE[r.right] ?? "neutral"} title={r.right}>
                    {rightLabel(r.right)}
                  </ToneChip>
                </td>
                <td>
                  <ForgeAccountCell did={r.subject} forge={forge} forges={forges} right={r.right} />
                </td>
                <td>
                  <GrantedBy row={r} vtcDid={vtcDid} />
                  <div className="muted gitns-small">
                    {r.grantedAt ? formatDay(r.grantedAt) : ""}
                    {r.expiresAt && (
                      <span className={expiresWithin(r, 14) ? "gitns-warn" : undefined}>
                        {r.grantedAt ? " · " : ""}expires {formatDay(r.expiresAt)}
                      </span>
                    )}
                    {r.granterDeparted && " · review"}
                  </div>
                  {r.reason && <div className="muted gitns-small">“{r.reason}”</div>}
                </td>
                <td>
                  {note ? (
                    <span className="muted gitns-small">{note}</span>
                  ) : (
                    onRevoke && (
                      <button
                        type="button"
                        className="secondary sm destructive"
                        aria-label={`Revoke ${rightLabel(r.right)} from ${name}`}
                        onClick={() => onRevoke(r)}
                      >
                        Revoke
                      </button>
                    )
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

const DRIFT_LABEL: Record<GitNsDriftItem["type"], string> = {
  roleAdded: "Role added on the forge",
  roleRemoved: "Projected role missing",
  roleChanged: "Role changed on the forge",
  requiredCheckMissing: "Required check no longer required",
  protectionWeakened: "Protection weakened",
  bootstrapMissing: "Bootstrap file or variable gone",
};

function DriftList({
  items,
  forges,
  ns,
  repo,
  rights,
  onAdopt,
  onRevert,
}: {
  items: GitNsDriftItem[];
  forges: ForgeAccounts | undefined;
  ns: GitNsNamespaceRow;
  repo: GitNsRepoRow;
  /** `null` until the rights listing has answered: adopting a `roleChanged`
   *  depends on what the member already holds, so nothing is offered until
   *  that is known. */
  rights: GitNsRightRow[] | null;
  onAdopt: (item: GitNsDriftItem, member: string, right: GitNsRight) => void;
  onRevert: (item: GitNsDriftItem) => void;
}) {
  const book = useNameBook();
  const viewer = useViewerDid();
  const superAdmin = useIsSuperAdmin();
  return (
    <ul className="finding-list">
      {items.map((d, i) => {
        const member =
          d.account && forges ? memberForAccount(forges, d.account.forge, d.account.id) : undefined;
        const adopt: AdoptStanding | null = !isAdoptableKind(d)
          ? null
          : rights === null
            ? {
                may: false,
                handOver: false,
                why: "Reading who holds what here before offering to adopt…",
              }
            : adoptStanding(
                viewer,
                superAdmin,
                ns,
                repo,
                d,
                member,
                member ? projectedRepoRank(rights, member, repo, ns) : 0,
              );
        const protection = d.type === "requiredCheckMissing" || d.type === "protectionWeakened";
        const standing = revertStanding(viewer, superAdmin, ns, repo, d);
        const label = DRIFT_LABEL[d.type] ?? d.type;
        return (
          <li key={i} className={`finding ${protection ? "error" : "warn"}`}>
            <strong>{label}</strong>
            <span>
              {d.account && (
                <>
                  @{d.account.login}
                  {member ? (
                    <>
                      {" — linked by "}
                      {book.nameOf(member) && <b>{book.nameOf(member)} </b>}
                      <code className="gitns-party-did">{member}</code>
                    </>
                  ) : (
                    " — linked by no member"
                  )}
                  {" · "}
                </>
              )}
              {d.observed ? `forge shows ${d.observed}` : "forge shows nothing"}
              {" · "}
              {d.expected ? `projection calls for ${d.expected}` : "projection calls for nothing"}
            </span>
            {protection && (
              <span className="muted">
                A weakened ruleset silently removes the guarantee, so the bridge
                re-applies it by default (rulesets enforce).
              </span>
            )}
            <span className="gitns-drift-actions">
              {standing.may ? (
                <button
                  type="button"
                  className="secondary sm"
                  aria-label={`Revert: ${label}${d.account ? ` @${d.account.login}` : ""}`}
                  onClick={() => onRevert(d)}
                >
                  Revert to the VTC's state
                </button>
              ) : (
                <span className="muted">
                  {standing.why}
                  {ns.mode === "bridge" && (
                    <>
                      {" "}
                      <code aria-label="Revert command">
                        {driftRevertTask(repo.resource, ns, d).command}
                      </code>
                    </>
                  )}
                </span>
              )}
              {adopt?.may && (
                <button
                  type="button"
                  className="secondary sm"
                  aria-label={`Adopt: ${label}${d.account ? ` @${d.account.login}` : ""}`}
                  onClick={() => onAdopt(d, adopt.member, adopt.right)}
                >
                  Adopt into VTC as {rightLabel(adopt.right).toLowerCase()}
                </button>
              )}
              {adopt && !adopt.may && (
                <span className="muted">
                  {adopt.why}
                  {adopt.handOver && (
                    <>
                      {" "}
                      <code aria-label="Adopt command">
                        {driftAdoptTask(repo.resource, d, adopt.member, adopt.right).command}
                      </code>
                    </>
                  )}
                </span>
              )}
              {d.type === "roleAdded" && ns.roleDrift !== "enforce" && (
                <span className="muted">
                  Or set <code>role_drift = "enforce"</code> in the git namespace policy and
                  the bridge re-projects roles itself.
                </span>
              )}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

/** The repository's history, from the namespace's activity feed. */
function Activity({ ns, resource }: { ns: GitNsNamespaceRow; resource: string }) {
  const book = useNameBook();
  const q = useQuery({
    queryKey: gitNsKeys.activity(ns.id),
    queryFn: () => fetchActivity(ns.id),
  });
  const items = (q.data?.items ?? []).filter((i) => i.resource === resource).slice(0, 10);
  const who = (did: string | null | undefined) =>
    did ? <NamedDid did={did} book={book} nameOnly={!!book.nameOf(did)} /> : null;

  return (
    <section className="card" aria-labelledby="gitns-activity">
      <h3 id="gitns-activity">Recent activity</h3>
      {q.isPending && <p>Loading activity…</p>}
      {q.isError &&
        (errorStatus(q.error) === 403 ? (
          <p className="muted">
            Activity is shown to this namespace's admins, and this session's DID does
            not hold <code>git.ns.admin</code> on {ns.resource}.
          </p>
        ) : (
          <p className="muted">Activity could not be read: {errorMessage(q.error)}.</p>
        ))}
      {q.isSuccess && items.length === 0 && (
        <p className="muted">Nothing recorded for this repository yet.</p>
      )}
      {items.length > 0 && (
        <ul className="gitns-activity">
          {items.map((it, i) => (
            <li key={i}>
              <time dateTime={it.at} className="muted">
                {formatDay(it.at)}
              </time>{" "}
              · {who(it.actor)}
              {it.actor && " "}
              {activityVerb(it.action)}
              {it.right && (
                <>
                  {" "}
                  <b>{rightLabel(it.right).toLowerCase()}</b>
                </>
              )}
              {it.subject && it.subject !== it.actor && <> — {who(it.subject)}</>}
              {it.detail && <span className="muted"> ({it.detail})</span>}
            </li>
          ))}
        </ul>
      )}
      <p className="muted gitns-small">
        Rights changes, drift and bridge jobs. The full record is in the Audit trail.
      </p>
    </section>
  );
}

const OUTCOME_TONE: Record<string, "success" | "neutral" | "danger" | "accent"> = {
  applied: "success",
  unchanged: "neutral",
  failed: "danger",
  skipped: "accent",
};

function CommitTrust({ ns, repo }: { ns: GitNsNamespaceRow; repo: GitNsRepoRow }) {
  const guard = guardFor(ns, repo);
  const check = lastCheckOf(repo);
  return (
    <section className="card" aria-labelledby="gitns-trust">
      <h3 id="gitns-trust">Commit trust on {ns.forge}</h3>
      <ul className="gitns-checklist">
        {bootstrapSteps(repo.bootstrap).map((s) => (
          <li key={s.key} className={s.done ? "done" : "missing"}>
            {s.done ? (
              <Check aria-hidden="true" size={16} />
            ) : (
              <X aria-hidden="true" size={16} />
            )}
            <span>
              <b>{s.label}</b>{" "}
              <span className="visually-hidden">{s.done ? "in place" : "missing"}</span>
              <span className="muted gitns-small gitns-block">{s.detail}</span>
            </span>
          </li>
        ))}
      </ul>
      {repo.failedStep && (
        <div className="finding error">
          <strong>Failed at: {repo.failedStep}</strong>
          {repo.lastError && <span>{repo.lastError}</span>}
          <span className="muted">Every step is check-then-apply, so a retry is safe.</span>
        </div>
      )}
      {repo.steps.length > 0 && (
        <div>
          <span className="field-label">Last create, bootstrap or inspect</span>
          <ol className="gitns-step-outcomes">
            {repo.steps.map((s, i) => (
              <li key={`${s.step}-${i}`}>
                <span className="gitns-mono">{s.step}</span>{" "}
                <ToneChip tone={OUTCOME_TONE[s.outcome] ?? "neutral"}>{s.outcome}</ToneChip>
                {s.detail && <span className="muted gitns-small"> {s.detail}</span>}
              </li>
            ))}
          </ol>
        </div>
      )}
      <div
        className={`finding ${guard.tone === "danger" ? "error" : guard.tone === "warning" ? "warn" : guard.tone === "success" ? "ok" : ""}`}
      >
        <strong>Guard: {guard.label}</strong>
        <span>{guard.detail}</span>
        <span className="muted gitns-small">
          {guard.source === "reported"
            ? "As the bridge last reported it."
            : `Expected for a ${ns.mode}-mode ${ns.kind ?? "namespace"} (design §9); the bridge has not reported the guard in force.`}
        </span>
      </div>
      <p className="gitns-small">
        Last check:{" "}
        {check ? (
          <>
            <ToneChip tone={check.conclusion === "success" ? "success" : check.conclusion === "failure" ? "danger" : "neutral"}>
              {check.conclusion}
            </ToneChip>
            {check.at && <> {formatDay(check.at)}</>}
            {check.sha && <> on <code>{check.sha.slice(0, 12)}</code></>}
          </>
        ) : (
          <span className="muted">none reported</span>
        )}
      </p>
    </section>
  );
}

function RegistryPreview({
  resource,
  ns,
  repos,
  namespaces,
  rights,
  rightsError,
}: {
  resource: string;
  ns: GitNsNamespaceRow;
  repos: GitNsRepoRow[];
  namespaces: GitNsNamespaceRow[];
  /** `null` until the rights are read; the preview is built from them, so
   *  without them it says nothing about what is or is not published. */
  rights: GitNsRightRow[] | null;
  rightsError: unknown;
}) {
  const book = useNameBook();
  const proj = useQuery({ queryKey: gitNsKeys.projection, queryFn: fetchProjection });
  const tuples = useMemo(
    () =>
      desiredTuples(rights ?? [], namespaces, repos, proj.data?.published ?? []).filter(
        (t) => t.resource === resource || (t.resource === ns.resource && t.action === "git.commit.sign"),
      ),
    [rights, namespaces, repos, proj.data, resource, ns.resource],
  );
  const pending = tuples.filter((t) => !t.published).length;

  return (
    <section className="card" aria-labelledby="gitns-registry">
      <div className="gitns-section-head">
        <h3 id="gitns-registry">Published to the Trust Registry</h3>
        <ToneChip tone="warning">Public</ToneChip>
      </div>
      {proj.isError && (
        <p className="muted">
          What is published could not be read ({readErrorMessage(proj.error)}); the list
          below is what the records call for.
        </p>
      )}
      {proj.data && !proj.data.registryConfigured && (
        <p className="muted">
          No Trust Registry is configured, so nothing is being published. These are the
          records that would be.
        </p>
      )}
      {rights === null ? (
        rightsError ? (
          <p className="muted">
            The rights could not be read ({readErrorMessage(rightsError)}), so what they
            publish cannot be shown.
          </p>
        ) : (
          <p>Loading…</p>
        )
      ) : tuples.length === 0 ? (
        <p className="muted">Nothing on this repository is published.</p>
      ) : (
        <table className="data-table gitns-tuples">
          <caption className="visually-hidden">Registry records for {resource}</caption>
          <thead>
            <tr>
              <th scope="col">Entity</th>
              <th scope="col">Action</th>
              <th scope="col">Resource</th>
              <th scope="col">State</th>
            </tr>
          </thead>
          <tbody>
            {tuples.map((t) => (
              <tr key={`${t.entity}|${t.action}|${t.resource}`}>
                <td>
                  <NamedDid did={t.entity} book={book} />
                </td>
                <td>
                  <code>{t.action}</code>
                  {t.impliedBy && (
                    <div className="muted gitns-small">implied by {t.impliedBy}</div>
                  )}
                </td>
                <td>
                  <code>{t.resource}</code>
                </td>
                <td>
                  {proj.data ? (
                    <ToneChip tone={t.published ? "success" : "accent"}>
                      {t.published ? "Published" : "Pending"}
                    </ToneChip>
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="muted gitns-small">
        The CI check reads only <code>git.commit.sign</code>; the projector writes each
        owner's and maintainer's implied commit right explicitly. Anyone can query who
        owns or commits to this repository. Reasons are never published.
        {pending > 0 && proj.data?.registryConfigured && ` ${pending} not yet published.`}
      </p>
    </section>
  );
}

export function RepoDetail() {
  const params = useParams();
  const resource = decodeURIComponent(params.resource ?? "");
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const book = useNameBook();

  const nsQ = useQuery({ queryKey: gitNsKeys.namespaces, queryFn: fetchNamespaces });
  const reposQ = useQuery({ queryKey: gitNsKeys.repos, queryFn: fetchRepos });
  const rightsQ = useQuery({ queryKey: gitNsKeys.rights, queryFn: fetchRights });
  const driftQ = useQuery({ queryKey: gitNsKeys.drift, queryFn: fetchDrift });
  const accountsQ = useQuery({ queryKey: gitNsKeys.accounts, queryFn: fetchAccounts });
  const forges = useMemo(() => indexAccounts(accountsQ.data), [accountsQ.data]);

  const repos = reposQ.data?.repos ?? [];
  const namespaces = nsQ.data?.namespaces ?? [];
  const allRights = rightsQ.data?.rights ?? [];
  const repo = repos.find((r) => r.resource === resource);
  const ns = repo ? namespaces.find((n) => n.id === repo.namespace) : undefined;

  const breadcrumb = (
    <nav aria-label="Breadcrumb" className="gitns-crumbs">
      <Link to={REPOS_PATH}>Repos</Link>
      <span aria-hidden="true">/</span>
      {ns ? <Link to={namespacePath(ns.id)}>{ns.resource}</Link> : <span>{resource.split("/").slice(0, 2).join("/")}</span>}
      <span aria-hidden="true">/</span>
      <span aria-current="page">{resource.split("/").pop()}</span>
    </nav>
  );

  if (reposQ.isPending || nsQ.isPending) {
    return (
      <>
        {breadcrumb}
        <section className="card">
          <p>Loading {resource}…</p>
        </section>
      </>
    );
  }
  if (reposQ.isError || nsQ.isError) {
    return (
      <>
        {breadcrumb}
        <section className="card error">
          <h3>{resource} could not be read</h3>
          <p>{errorMessage(reposQ.error ?? nsQ.error)}</p>
        </section>
      </>
    );
  }
  if (!repo) {
    return (
      <>
        {breadcrumb}
        <section className="card">
          <p className="muted">
            The VTC records no repository at <code>{resource}</code>. It may have been
            renamed, or never adopted.
          </p>
        </section>
      </>
    );
  }
  if (!ns || repo.state === "detached") {
    // Detached: its namespace was unbound (and may be gone from the list), or
    // it moved outside it. The record stays, for history; nothing is governed
    // or published, so none of the governed panels apply.
    return (
      <>
        {breadcrumb}
        <header className="gitns-head">
          <div>
            <h2 className="gitns-mono">{repo.resource}</h2>
            <div className="gitns-chips">
              <ToneChip tone="neutral">Detached</ToneChip>
              <span className="muted gitns-small">
                {repo.forgeId && `forge id ${repo.forgeId} · `}recorded {formatDay(repo.createdAt)}
              </span>
            </div>
          </div>
        </header>
        <section className="card">
          <p>
            No longer governed: {ns ? "it moved outside its namespace" : "its namespace was unbound"}.
            Its rights were revoked and withdrawn from the Trust Registry, and nothing
            about it is published. To govern it again, bind the namespace it is in now
            and adopt it there.
          </p>
        </section>
      </>
    );
  }

  const status = repoStatus(repo);
  const people = repoRights(allRights, repo.resource);
  const inherited = inheritedRights(allRights, ns);
  const drift = driftQ.data?.repos.find((d) => d.resource === repo.resource)?.drift ?? [];
  const owners = repo.owners;
  // The service grant is the one record the community issues as itself, so its
  // granter is this VTC's DID — which lets "granted by" say so in words.
  const vtcDid = inherited.find((r) => isServiceGrant(r, ns))?.grantedBy ?? undefined;
  const governed = repo.state !== "unmanaged" && repo.state !== "detached";
  const archived = repo.state === "archived";
  const lastOwner = (r: GitNsRightRow) =>
    r.right === "git.repo.own" && owners.length === 1 && owners[0] === r.subject
      ? "Last owner — name another first"
      : null;

  return (
    <>
      {breadcrumb}
      <header className="gitns-head">
        <div>
          <h2 className="gitns-mono">{shortName(repo.resource)}</h2>
          <div className="gitns-chips">
            <ToneChip tone="neutral">{repo.visibility}</ToneChip>
            <ToneChip tone={status.tone}>{status.label}</ToneChip>
            {repo.bootstrap.requiredCheck && (
              <ToneChip tone="accent">“Verify commit trust” required</ToneChip>
            )}
            <span className="muted gitns-small">
              {repo.forgeId && `${ns.forge} id ${repo.forgeId} · `}
              recorded {formatDay(repo.createdAt)}
            </span>
          </div>
        </div>
        <div className="gitns-head-actions">
          {repo.state === "unmanaged" ? (
            <button type="button" className="primary" onClick={() => setDialog({ kind: "adopt" })}>
              Adopt
            </button>
          ) : (
            <>
              <button
                type="button"
                className="secondary"
                disabled={!governed || archived}
                onClick={() => setDialog({ kind: "transfer" })}
              >
                Transfer ownership
              </button>
              <button
                type="button"
                className="secondary destructive"
                disabled={!governed || archived}
                onClick={() => setDialog({ kind: "sign", task: archiveTask(repo.resource) })}
              >
                Archive
              </button>
            </>
          )}
        </div>
      </header>

      {repo.state === "orphaned" && (
        <div className="finding error">
          <strong>Orphaned</strong>
          <span>
            Its last owner left the community, so ownership passed to the namespace
            admins. Name a new owner.
          </span>
          <span>
            <button
              type="button"
              className="primary sm"
              onClick={() =>
                setDialog({
                  kind: "grant",
                  initialRight: "git.repo.own",
                  title: `Assign an owner to ${shortName(repo.resource)}`,
                })
              }
            >
              Assign owner
            </button>
          </span>
        </div>
      )}

      <div className="gitns-detail">
        <div className="gitns-col">
          <section className="card" aria-labelledby="gitns-people">
            <div className="gitns-section-head">
              <h3 id="gitns-people">People and rights</h3>
              <button
                type="button"
                className="primary sm"
                disabled={!governed || archived}
                onClick={() => setDialog({ kind: "grant" })}
              >
                <Plus aria-hidden="true" size={14} /> Add person
              </button>
            </div>
            {rightsQ.isPending && <p>Loading rights…</p>}
            {rightsQ.isError && (
              <p className="muted">Rights could not be read: {readErrorMessage(rightsQ.error)}.</p>
            )}
            {rightsQ.isSuccess && people.length === 0 && (
              <p className="muted">
                {repo.state === "unmanaged"
                  ? "Nobody holds a right here: adopt it to name an owner."
                  : "No right is recorded on this repository itself."}
              </p>
            )}
            {people.length > 0 && (
              <PeopleTable
                rows={people}
                forge={ns.forge}
                forges={forges}
                vtcDid={vtcDid}
                readOnlyNote={(r) =>
                  r.origin === "roleDerived"
                    ? "Managed in configuration"
                    : !isRight(r.right)
                      ? "Unknown right"
                      : lastOwner(r)
                }
                onRevoke={(r) => setDialog({ kind: "revoke", row: r })}
              />
            )}
            <p className="muted gitns-small">
              Owners can grant owner, maintainer and committer on this repository.
              Committers need no forge access; they contribute through fork pull
              requests.
            </p>
          </section>

          {inherited.length > 0 && (
            <section className="card" aria-labelledby="gitns-inherited">
              <h3 id="gitns-inherited">Through the namespace</h3>
              <p className="muted gitns-small">
                Rights on {ns.resource} that reach this repository. Change them from the
                namespace. <code>git.ns.admin</code> gives no role on the forge; a
                namespace-level <code>git.commit.sign</code> is projected here as a committer
                right on this repository would be.
              </p>
              <PeopleTable
                rows={inherited}
                forge={ns.forge}
                forges={forges}
                vtcDid={vtcDid}
                readOnlyNote={(r) =>
                  isServiceGrant(r, ns)
                    ? "Bridge service grant · Dependabot re-sign"
                    : "On the namespace"
                }
              />
            </section>
          )}

          {(drift.length > 0 || repo.syncState === "drift") && (
            <section className="card" id="drift" aria-labelledby="gitns-drift">
              <h3 id="gitns-drift">Drift</h3>
              {driftQ.isError && (
                <p className="muted">Drift could not be read: {readErrorMessage(driftQ.error)}.</p>
              )}
              <DriftList
                items={drift}
                forges={forges}
                ns={ns}
                repo={repo}
                rights={rightsQ.isSuccess ? allRights : null}
                onRevert={(item) => setDialog({ kind: "drift", item })}
                onAdopt={(item, member, right) =>
                  setDialog({ kind: "drift", item, adopt: { member, right } })
                }
              />
            </section>
          )}
        </div>

        <div className="gitns-col">
          <CommitTrust ns={ns} repo={repo} />
          <RegistryPreview
            resource={repo.resource}
            ns={ns}
            repos={repos}
            namespaces={namespaces}
            rights={rightsQ.isSuccess ? allRights : null}
            rightsError={rightsQ.error}
          />
          <Activity ns={ns} resource={repo.resource} />
        </div>
      </div>

      {dialog?.kind === "grant" && (
        <GrantDialog
          resource={repo.resource}
          rights={dialog.initialRight ? [dialog.initialRight] : REPO_RIGHTS}
          initialRight={dialog.initialRight}
          title={dialog.title}
          onClose={() => setDialog(null)}
          onBuilt={(task) => setDialog({ kind: "sign", task })}
        />
      )}
      {dialog?.kind === "revoke" && (
        <RevokeDialog
          subject={dialog.row.subject}
          subjectName={book.nameOf(dialog.row.subject) ?? undefined}
          right={dialog.row.right as GitNsRight}
          resource={dialog.row.resource}
          onClose={() => setDialog(null)}
          onBuilt={(task) => setDialog({ kind: "sign", task })}
        />
      )}
      {dialog?.kind === "transfer" && (
        <TransferDialog
          resource={repo.resource}
          owners={owners}
          onClose={() => setDialog(null)}
          onBuilt={(task) => setDialog({ kind: "sign", task })}
        />
      )}
      {dialog?.kind === "adopt" && (
        <AdoptDialog
          resource={repo.resource}
          onClose={() => setDialog(null)}
          onBuilt={(task) => setDialog({ kind: "sign", task })}
        />
      )}
      {dialog?.kind === "drift" && (
        <DriftResolveDialog
          resource={repo.resource}
          ns={ns}
          item={dialog.item}
          adopt={dialog.adopt}
          label={DRIFT_LABEL[dialog.item.type] ?? dialog.item.type}
          onClose={() => setDialog(null)}
          onBuilt={(task) => setDialog({ kind: "sign", task })}
        />
      )}
      {dialog?.kind === "sign" && (
        <SignTaskDialog task={dialog.task} onClose={() => setDialog(null)} />
      )}
    </>
  );
}
