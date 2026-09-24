// The Repos landing page: the namespaces this community governs, the
// repositories in the one selected, who holds its namespace rights, and the
// grants departed members left behind.

import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { FolderGit2, Plus } from "lucide-react";

import { NamedDid } from "@/components/NamedDid";
import { fetchActivePolicy } from "@/lib/policies-api";
import { useNameBook } from "@/lib/names";
import type {
  GitNsNamespaceRow,
  GitNsRepoRow,
  GitNsRightRow,
} from "@/lib/wire-types";

import type { SignedTask } from "./actions";
import {
  fetchIssuedByDeparted,
  fetchNamespaces,
  fetchRepos,
  fetchRights,
  gitNsKeys,
} from "./api";
import { AdoptDialog, CreateDialog, GrantDialog } from "./dialogs";
import {
  isPersonal,
  isServiceGrant,
  kindLabel,
  modeLabel,
  namespaceFindings,
  repoStatus,
  shortName,
} from "./model";
import {
  BIND_PATH,
  BootstrapDots,
  DEPARTED_PATH,
  errorMessage,
  readErrorMessage,
  namespacePath,
  POLICY_PATH,
  repoPath,
  SignTaskDialog,
  ToneChip,
} from "./ui";

type Dialog =
  | { kind: "grant"; resource: string; right: "git.ns.admin" | "git.repo.create" | "git.repo.own"; title?: string }
  | { kind: "adopt"; resource?: string; namespaceResource?: string }
  | { kind: "create"; ns: GitNsNamespaceRow }
  | { kind: "sign"; task: SignedTask };

function PersonalAccountHint({ ns }: { ns: GitNsNamespaceRow }) {
  return (
    <div className="finding warn">
      <strong>Forge roles collapse to write on a personal account</strong>
      <span>
        Only the account holder can be admin there, and only they can create a
        repository, so creation is theirs alone. Ownership in the VTC still decides
        who may grant commit rights.
      </span>
      <details>
        <summary>Move to an organisation</summary>
        <ol className="gitns-steps-list">
          <li>Create an organisation on {ns.forge} and make the account holder an owner.</li>
          <li>Bind the organisation here and install the community's App on it.</li>
          <li>
            Transfer each repository from {ns.owner} to the organisation in its forge
            settings.
          </li>
          <li>
            The bridge reports each transfer as drift and the VTC moves its rights
            and Trust Registry records to the new name.
          </li>
        </ol>
      </details>
    </div>
  );
}

/** What the bridge last reported about its standing on the owner. Every
 *  member is optional: only what was reported is shown. */
function ForgeStatusLine({ ns }: { ns: GitNsNamespaceRow }) {
  const fs = ns.forgeStatus!;
  const parts: string[] = [];
  if (fs.appName || fs.appSlug) parts.push(`App ${fs.appName ?? fs.appSlug}`);
  if (fs.installationId) parts.push(`installation #${fs.installationId}`);
  if (fs.appRegistration) parts.push(`registration: ${fs.appRegistration}`);
  if (fs.requiredWorkflow != null)
    parts.push(fs.requiredWorkflow ? "required workflow in force" : "required workflow not in force");
  if (fs.bridgePostedCheck != null)
    parts.push(fs.bridgePostedCheck ? "bridge-posted check ready" : "bridge-posted check not ready");
  if (fs.missingPermissions.length === 0 && fs.installationId) parts.push("all permissions granted");
  if (parts.length === 0) return null;
  return (
    <p className="muted gitns-small">
      {parts.join(" · ")}
      {fs.reportedAt && <> · reported {new Date(fs.reportedAt).toLocaleDateString()}</>}
    </p>
  );
}

function NamespaceCard({
  ns,
  repos,
  rights,
  selected,
  policyVersion,
}: {
  ns: GitNsNamespaceRow;
  repos: GitNsRepoRow[];
  rights: GitNsRightRow[];
  selected: boolean;
  policyVersion: number | null | undefined;
}) {
  const book = useNameBook();
  const managed = repos.filter((r) => r.state !== "unmanaged").length;
  const unmanaged = repos.length - managed;
  const creators = rights.filter(
    (r) => r.resource === ns.resource && r.right === "git.repo.create",
  ).length;
  const service = rights.find((r) => isServiceGrant(r, ns));
  const findings = namespaceFindings(ns);
  const headingId = `gitns-ns-${ns.id}`;

  return (
    <article
      className={selected ? "card gitns-ns selected" : "card gitns-ns"}
      aria-labelledby={headingId}
      aria-current={selected ? "true" : undefined}
    >
      <div className="gitns-ns-head">
        <h3 id={headingId} className="gitns-ns-name">
          <Link to={namespacePath(ns.id)}>{ns.resource}</Link>
        </h3>
        <ToneChip tone={ns.kind === "organization" ? "accent" : "neutral"}>
          {kindLabel(ns)}
        </ToneChip>
        <span
          className={`gitns-mode ${ns.installationRemoved ? "bad" : ns.mode === "bridge" && ns.state === "bound" ? "ok" : ""}`}
        >
          {modeLabel(ns)}
        </span>
      </div>

      <div className="gitns-stats">
        <span>
          <b>{managed}</b> managed {managed === 1 ? "repo" : "repos"}
        </span>
        {unmanaged > 0 && (
          <span>
            <b>{unmanaged}</b> unmanaged
          </span>
        )}
        <span>
          <b>{ns.admins.length}</b> namespace {ns.admins.length === 1 ? "admin" : "admins"}
        </span>
        {isPersonal(ns) ? (
          <span>
            Repo creation: <b>account holder only</b>
          </span>
        ) : (
          <span>
            <b>{creators}</b> repo {creators === 1 ? "creator" : "creators"}
          </span>
        )}
      </div>

      <p className="muted gitns-small">
        Policy:{" "}
        <Link to={POLICY_PATH}>
          {policyVersion ? `git namespace policy v${policyVersion}` : "git namespace policy"}
        </Link>
        {policyVersion === null && " (none active: every change is refused)"}
        {ns.boundAt && <> · bound {new Date(ns.boundAt).toLocaleDateString()}</>}
        {" · by "}
        <NamedDid did={ns.boundBy} book={book} nameOnly={!!book.nameOf(ns.boundBy)} />
      </p>

      <p className="muted gitns-small">
        Drift: rulesets <b>enforce</b> · roles <b>{ns.roleDrift}</b>
        {" · "}grants of departed members{" "}
        <b>{ns.cascadeOnDeparture ? "revoked with them" : "kept for review"}</b>
      </p>

      {ns.forgeStatus && <ForgeStatusLine ns={ns} />}

      {ns.bridgeDid && (
        <p className="muted gitns-small">
          Bridge <NamedDid did={ns.bridgeDid} book={book} />
          {service ? (
            <>
              {" "}
              holds <code>git.commit.sign</code> on {ns.resource} as a service grant
              from the community, to re-sign Dependabot pull requests (never ones
              that touch workflows). Read-only: it ends with the binding.
            </>
          ) : (
            ns.state === "bound" && (
              <>
                {" "}
                holds no service grant: the policy refused it, so Dependabot pull
                requests will not pass the check until someone re-signs them.
              </>
            )
          )}
        </p>
      )}

      {findings.map((f) => (
        <div key={f.title} className={`finding ${f.tone === "danger" ? "error" : "warn"}`}>
          <strong>{f.title}</strong>
          <span>{f.detail}</span>
        </div>
      ))}
      {isPersonal(ns) && <PersonalAccountHint ns={ns} />}
    </article>
  );
}

function ReposTable({
  ns,
  repos,
  onAdopt,
  onAssignOwner,
}: {
  ns: GitNsNamespaceRow;
  repos: GitNsRepoRow[];
  onAdopt: (resource: string) => void;
  onAssignOwner: (resource: string) => void;
}) {
  const book = useNameBook();
  if (repos.length === 0) {
    return (
      <div className="empty-state">
        <span className="empty-icon" aria-hidden="true">
          <FolderGit2 />
        </span>
        <h4>No repositories in {ns.resource} yet</h4>
        <p>
          {ns.mode === "bridge"
            ? "Repositories appear as they are created or adopted, and ones the bridge finds on the forge are listed here as unmanaged."
            : "In manual mode the VTC knows only repositories adopted through it. Adopt one to bring it under governance."}
        </p>
      </div>
    );
  }
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">Repository</th>
            <th scope="col">Owners</th>
            <th scope="col">Maintainers</th>
            <th scope="col">Committers</th>
            <th scope="col">VGI</th>
            <th scope="col">Forge sync</th>
          </tr>
        </thead>
        <tbody>
          {repos.map((r) => {
            const status = repoStatus(r);
            const unmanaged = r.state === "unmanaged";
            return (
              <tr key={r.id}>
                <td>
                  <Link to={repoPath(r.resource)} className="gitns-mono">
                    {shortName(r.resource)}
                  </Link>
                  <div className="muted gitns-small">
                    {r.visibility}
                    {r.createdBy && (
                      <>
                        {" · created by "}
                        <NamedDid did={r.createdBy} book={book} nameOnly={!!book.nameOf(r.createdBy)} />
                      </>
                    )}
                  </div>
                </td>
                <td>
                  {r.state === "orphaned" ? (
                    <span className="gitns-bad">Orphaned · reassigned to admins</span>
                  ) : unmanaged || r.owners.length === 0 ? (
                    "—"
                  ) : (
                    r.owners.map((o) => (
                      <div key={o}>
                        <NamedDid did={o} book={book} />
                      </div>
                    ))
                  )}
                </td>
                <td className="tabular">{unmanaged ? "—" : r.maintainers}</td>
                <td className="tabular">{unmanaged ? "—" : r.committers}</td>
                <td>
                  <BootstrapDots bootstrap={r.bootstrap} />
                </td>
                <td>
                  <div className="gitns-sync">
                    <ToneChip tone={status.tone} title={r.lastError ?? undefined}>
                      {status.label}
                    </ToneChip>
                    {status.action === "adopt" && (
                      <button
                        type="button"
                        className="link"
                        onClick={() => onAdopt(r.resource)}
                        aria-label={`Adopt ${shortName(r.resource)}`}
                      >
                        Adopt
                      </button>
                    )}
                    {status.action === "assignOwner" && (
                      <button
                        type="button"
                        className="link"
                        onClick={() => onAssignOwner(r.resource)}
                        aria-label={`Assign an owner to ${shortName(r.resource)}`}
                      >
                        Assign owner
                      </button>
                    )}
                    {(status.action === "resolve" || status.action === "view") && (
                      <Link
                        to={`${repoPath(r.resource)}${status.action === "resolve" ? "#drift" : ""}`}
                        aria-label={`${status.actionLabel} ${shortName(r.resource)}`}
                      >
                        {status.actionLabel}
                      </Link>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function NamespaceRights({
  ns,
  rights,
  onGrant,
}: {
  ns: GitNsNamespaceRow;
  rights: GitNsRightRow[];
  onGrant: (right: "git.ns.admin" | "git.repo.create") => void;
}) {
  const book = useNameBook();
  const holders = (right: string) =>
    rights.filter((r) => r.resource === ns.resource && r.right === right);
  const admins = holders("git.ns.admin");
  const creators = holders("git.repo.create");
  const bound = ns.state === "bound";

  const list = (rows: GitNsRightRow[]) =>
    rows.length === 0 ? (
      <span className="muted">Nobody</span>
    ) : (
      rows.map((r) => (
        <span key={r.subject} className="gitns-holder">
          <NamedDid did={r.subject} book={book} />
          {r.expiresAt && (
            <span className="muted gitns-small"> until {new Date(r.expiresAt).toLocaleDateString()}</span>
          )}
        </span>
      ))
    );

  return (
    <section className="card" aria-labelledby={`gitns-nsr-${ns.id}`}>
      <h3 id={`gitns-nsr-${ns.id}`}>Namespace rights in {ns.owner}</h3>
      <div className="gitns-nsr">
        <code className="gitns-right-admin">git.ns.admin</code>
        <div className="gitns-holders">{list(admins)}</div>
        <button
          type="button"
          className="secondary sm"
          disabled={!bound}
          onClick={() => onGrant("git.ns.admin")}
        >
          Grant
        </button>

        <code className="gitns-right-create">git.repo.create</code>
        <div className="gitns-holders">
          {isPersonal(ns) ? (
            <span>
              The account holder only — a personal account cannot let anyone else
              create a repository.
            </span>
          ) : (
            list(creators)
          )}
        </div>
        {isPersonal(ns) ? (
          <span />
        ) : (
          <button
            type="button"
            className="secondary sm"
            disabled={!bound}
            onClick={() => onGrant("git.repo.create")}
          >
            Grant
          </button>
        )}
      </div>
      <p className="muted gitns-small">
        A namespace admin can grant anything in the namespace — treat it like org
        owner. Granting it is destructive-class and needs a step-up; repo creators
        cannot pass their right on. Both go to current members only.
        {!bound && " Nothing can be granted until the binding finishes."}
      </p>
    </section>
  );
}

function DepartedCard() {
  const q = useQuery({ queryKey: gitNsKeys.departed, queryFn: fetchIssuedByDeparted });
  const count = (q.data?.granters ?? []).reduce((n, g) => n + g.rights.length, 0);
  const people = q.data?.granters.length ?? 0;

  return (
    <section
      className={count > 0 ? "card gitns-departed warn" : "card gitns-departed"}
      aria-labelledby="gitns-departed-title"
    >
      <h3 id="gitns-departed-title">Issued by departed members</h3>
      {q.isPending && <p>Reading grants…</p>}
      {q.isError && (
        <p className="muted">
          Could not be read: {readErrorMessage(q.error)}. This is a failure to ask, not
          an empty list.
        </p>
      )}
      {q.data && count === 0 && (
        <p className="muted">
          No live grant was issued by someone who has since left.
        </p>
      )}
      {q.data && count > 0 && (
        <>
          <p>
            {count} {count === 1 ? "grant" : "grants"} issued by {people}{" "}
            {people === 1 ? "person" : "people"} who left.{" "}
            {q.data.cascadeOnDeparture
              ? "The active policy revokes these (cascade_on_departure); they are listed until the revocation lands."
              : "They stay valid — they were issued under the community's authority — so review whether to keep them."}
          </p>
          <p>
            <Link to={DEPARTED_PATH} className="button secondary">
              Review {count} {count === 1 ? "grant" : "grants"}
            </Link>
          </p>
        </>
      )}
    </section>
  );
}

export function Overview() {
  const [params] = useSearchParams();
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const nsQ = useQuery({ queryKey: gitNsKeys.namespaces, queryFn: fetchNamespaces });
  const reposQ = useQuery({ queryKey: gitNsKeys.repos, queryFn: fetchRepos });
  const rightsQ = useQuery({ queryKey: gitNsKeys.rights, queryFn: fetchRights });
  const policyQ = useQuery({
    queryKey: ["policies", "active", "gitNamespace"],
    queryFn: () => fetchActivePolicy("gitNamespace"),
  });

  const namespaces = nsQ.data?.namespaces ?? [];
  const repos = reposQ.data?.repos ?? [];
  const rights = rightsQ.data?.rights ?? [];
  const selected =
    namespaces.find((n) => n.id === params.get("namespace")) ?? namespaces[0];
  const selectedRepos = useMemo(
    () => (selected ? repos.filter((r) => r.namespace === selected.id) : []),
    [repos, selected],
  );
  const roleDerived = rights.filter((r) => r.origin === "roleDerived").length;
  const policyVersion = policyQ.isSuccess ? (policyQ.data?.version ?? null) : undefined;

  return (
    <>
      <header className="gitns-head">
        <div>
          <h2>Repos</h2>
          <p className="lead">
            Git namespaces this community governs. Rights are held here, published to
            the Trust Registry, and applied on the forge by the community's bridge.
          </p>
        </div>
        <div className="gitns-head-actions">
          <button
            type="button"
            className="secondary"
            disabled={!selected || selected.state !== "bound"}
            onClick={() => selected && setDialog({ kind: "create", ns: selected })}
          >
            New repo
          </button>
          <button
            type="button"
            className="secondary"
            disabled={!selected || selected.state !== "bound"}
            onClick={() =>
              setDialog({ kind: "adopt", namespaceResource: selected?.resource })
            }
          >
            Adopt existing repo
          </button>
          <Link to={BIND_PATH} className="button primary">
            <Plus aria-hidden="true" size={16} /> Bind namespace
          </Link>
        </div>
      </header>

      {nsQ.isPending && (
        <section className="card">
          <p>Loading namespaces…</p>
        </section>
      )}
      {nsQ.isError && (
        <section className="card error">
          <h3>Namespaces could not be read</h3>
          <p>
            {errorMessage(nsQ.error)}. This is a failure to ask — not a community with
            no namespaces.
          </p>
        </section>
      )}

      {nsQ.isSuccess && namespaces.length === 0 && (
        <section className="card">
          <div className="empty-state">
            <span className="empty-icon" aria-hidden="true">
              <FolderGit2 />
            </span>
            <h4>No namespace bound</h4>
            <p>
              Bind a forge organisation or account to govern its repositories: who
              owns each, and who may commit.
            </p>
            <Link to={BIND_PATH} className="button primary">
              Bind namespace
            </Link>
          </div>
        </section>
      )}

      {namespaces.length > 0 && (
        <section aria-label="Namespaces" className="gitns-ns-grid">
          {namespaces.map((ns) => (
            <NamespaceCard
              key={ns.id}
              ns={ns}
              repos={repos.filter((r) => r.namespace === ns.id)}
              rights={rights}
              selected={ns.id === selected?.id}
              policyVersion={policyVersion}
            />
          ))}
        </section>
      )}

      {selected && (
        <section className="card" aria-labelledby="gitns-repos-title">
          <div className="gitns-section-head">
            <h3 id="gitns-repos-title">{selected.resource} · repositories</h3>
            <span className="muted gitns-small">
              VGI bootstrap: workflow · keyring · variables · required check
            </span>
          </div>
          {reposQ.isPending && <p>Loading repositories…</p>}
          {reposQ.isError && (
            <p className="muted">Repositories could not be read: {errorMessage(reposQ.error)}.</p>
          )}
          {reposQ.isSuccess && (
            <ReposTable
              ns={selected}
              repos={selectedRepos}
              onAdopt={(resource) => setDialog({ kind: "adopt", resource })}
              onAssignOwner={(resource) =>
                setDialog({
                  kind: "grant",
                  resource,
                  right: "git.repo.own",
                  title: `Assign an owner to ${shortName(resource)}`,
                })
              }
            />
          )}
        </section>
      )}

      {selected && (
        <div className="gitns-two">
          {rightsQ.isError ? (
            <section className="card">
              <h3>Namespace rights</h3>
              <p className="muted">Rights could not be read: {readErrorMessage(rightsQ.error)}.</p>
            </section>
          ) : (
            <NamespaceRights
              ns={selected}
              rights={rights}
              onGrant={(right) =>
                setDialog({
                  kind: "grant",
                  resource: selected.resource,
                  right,
                  title: `Grant ${right} on ${selected.resource}`,
                })
              }
            />
          )}
          <DepartedCard />
        </div>
      )}

      {roleDerived > 0 && (
        <p className="muted gitns-small">
          {roleDerived} commit {roleDerived === 1 ? "right comes" : "rights come"} from{" "}
          <code>[hooks.git-trust] grant_on_role</code>. They are role-derived and
          managed only through configuration; inside a bound namespace the git
          namespace projection publishes them.
        </p>
      )}

      {dialog?.kind === "grant" && (
        <GrantDialog
          resource={dialog.resource}
          rights={[dialog.right]}
          initialRight={dialog.right}
          title={dialog.title}
          onClose={() => setDialog(null)}
          onBuilt={(task) => setDialog({ kind: "sign", task })}
        />
      )}
      {dialog?.kind === "adopt" && (
        <AdoptDialog
          resource={dialog.resource}
          namespaceResource={dialog.namespaceResource}
          onClose={() => setDialog(null)}
          onBuilt={(task) => setDialog({ kind: "sign", task })}
        />
      )}
      {dialog?.kind === "create" && (
        <CreateDialog
          namespaceId={dialog.ns.id}
          namespaceResource={dialog.ns.resource}
          personal={isPersonal(dialog.ns)}
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
