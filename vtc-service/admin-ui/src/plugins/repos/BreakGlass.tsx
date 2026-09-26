// Break-glass grants (`git-ns/right/break-glass`): elevated rights their
// holders gave themselves because nobody else could, and what became of each.
//
// Separation of duties (`git-ns/right/grant` 0.3, fixed rule 7) stops anyone
// granting themselves namespace admin, repo creator or owner. Break-glass is
// the escape hatch, and its safety is that it cannot be missed: every one
// that no other administrator has yet ratified or revoked is listed first
// here, counted in the banner on every page of the console, and flagged next
// to the right wherever the right is shown.
//
// Two decisions, both ordinary signed tasks:
//
// - **Ratify** (`git-ns/right/ratify`) — another administrator confirms the
//   right should stand. Never the person who broke the glass.
// - **Revoke** (`git-ns/right/revoke` 0.3) — any community administrator, a
//   namespace admin of the namespace, an owner for `own`, or the holder
//   themselves. An unratified break-glass counts toward neither the last-owner
//   nor the last-admin invariant, so revoking one is never refused by them.
//
// Where the viewer cannot sign one, the page says why and shows the `cnm`
// command for someone who can.

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Siren } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import { NamedDid } from "@/components/NamedDid";
import { useNameBook } from "@/lib/names";
import { useIsSuperAdmin, useViewerDid } from "@/lib/viewer";
import type { GitNsBreakGlassItem, GitNsRight } from "@/lib/wire-types";

import { ratifyTask, revokeTask, type SignedTask } from "./actions";
import { fetchBreakGlass, fetchRepos, fetchRights, gitNsKeys } from "./api";
import { RatifyDialog, RevokeDialog } from "./dialogs";
import {
  awaitingItems,
  BREAK_GLASS_STATE_LABEL,
  type BreakGlassState,
  isRight,
  ratifyStanding,
  revokeBreakGlassStanding,
  rightLabel,
  shortName,
} from "./model";
import { formatDay, readErrorMessage, REPOS_PATH, repoPath, SignTaskDialog, ToneChip } from "./ui";

type Dialog =
  | { kind: "ratify"; item: GitNsBreakGlassItem }
  | { kind: "revoke"; item: GitNsBreakGlassItem }
  | { kind: "sign"; task: SignedTask };

const STATE_TONE: Record<BreakGlassState, "danger" | "warning" | "neutral"> = {
  unratified: "danger",
  pending: "warning",
  ratified: "neutral",
};

function stateOf(item: GitNsBreakGlassItem): BreakGlassState {
  return item.state === "pending" || item.state === "ratified" ? item.state : "unratified";
}

function HandOver({ why, command }: { why: string; command: string }) {
  return (
    <div className="gitns-small">
      <p className="muted">{why}</p>
      <div className="gitns-command-row">
        <pre aria-label="Command">{command}</pre>
        <CopyButton value={command} label="Copy command" />
      </div>
    </div>
  );
}

export function BreakGlassList() {
  const book = useNameBook();
  const viewer = useViewerDid();
  const superAdmin = useIsSuperAdmin();
  const q = useQuery({ queryKey: gitNsKeys.breakGlass, queryFn: fetchBreakGlass });
  // The viewer's own standing, to tell a namespace admin from one whose only
  // standing is an unconfirmed break-glass. A scoped administrator cannot
  // read every right; the page then offers the hand-over where it is unsure.
  const rightsQ = useQuery({ queryKey: gitNsKeys.rights, queryFn: fetchRights, retry: false });
  const reposQ = useQuery({ queryKey: gitNsKeys.repos, queryFn: fetchRepos });
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const rights = rightsQ.data?.rights ?? [];
  const isRepo = (resource: string) =>
    (reposQ.data?.repos ?? []).some((r) => r.resource === resource);

  const items = q.data?.items ?? [];
  const awaiting = awaitingItems(items);
  const settled = items
    .filter((i) => !awaiting.includes(i))
    .sort((a, b) => b.breakGlass.at.localeCompare(a.breakGlass.at));

  const row = (item: GitNsBreakGlassItem) => {
    const state = stateOf(item);
    const name = book.nameOf(item.subject) ?? item.subject;
    const right = item.right as GitNsRight;
    const ratify = ratifyStanding(viewer, superAdmin, item, rights);
    const revoke = revokeBreakGlassStanding(viewer, superAdmin, item, rights);
    const known = isRight(item.right);
    return (
      <tr key={`${item.subject}|${item.right}|${item.resource}|${item.breakGlass.at}`}>
        <td>
          <NamedDid did={item.subject} book={book} />
          {item.subject === viewer && <div className="muted gitns-small">You</div>}
        </td>
        <td>
          <ToneChip tone="accent" title={item.right}>
            {rightLabel(item.right)}
          </ToneChip>
        </td>
        <td>
          {isRepo(item.resource) ? (
            <Link to={repoPath(item.resource)} className="gitns-mono">
              {shortName(item.resource)}
            </Link>
          ) : (
            <code>{item.resource}</code>
          )}
        </td>
        <td className="gitns-justification">“{item.breakGlass.justification}”</td>
        <td>
          {new Date(item.breakGlass.at).toLocaleString()}
          {item.breakGlass.effectiveAt && state === "pending" && (
            <div className="muted gitns-small">
              takes effect {new Date(item.breakGlass.effectiveAt).toLocaleString()}
            </div>
          )}
        </td>
        <td>
          <ToneChip tone={STATE_TONE[state]}>{BREAK_GLASS_STATE_LABEL[state]}</ToneChip>
          {item.breakGlass.ratifiedBy && (
            <div className="muted gitns-small">
              by <NamedDid did={item.breakGlass.ratifiedBy} book={book} />,{" "}
              {formatDay(item.breakGlass.ratifiedAt)}
            </div>
          )}
        </td>
        <td>
          {known && state !== "ratified" && (
            <div className="gitns-card-actions">
              {ratify.may ? (
                <button
                  type="button"
                  className="primary sm"
                  aria-label={`Ratify ${rightLabel(item.right)} on ${shortName(item.resource)} for ${name}`}
                  onClick={() => setDialog({ kind: "ratify", item })}
                >
                  Ratify
                </button>
              ) : null}
              {revoke.may ? (
                <button
                  type="button"
                  className="secondary sm destructive"
                  aria-label={`Revoke ${rightLabel(item.right)} on ${shortName(item.resource)} from ${name}`}
                  onClick={() => setDialog({ kind: "revoke", item })}
                >
                  Revoke
                </button>
              ) : null}
            </div>
          )}
          {known && state !== "ratified" && !ratify.may && (
            <HandOver
              why={ratify.why}
              command={
                ratifyTask(item.subject, right, item.resource, item.breakGlass.at).command
              }
            />
          )}
          {known && !revoke.may && (
            <HandOver
              why={revoke.why}
              command={revokeTask(item.subject, right, item.resource).command}
            />
          )}
        </td>
      </tr>
    );
  };

  const table = (rows: GitNsBreakGlassItem[], label: string) => (
    <div className="table-scroll">
      <table className="data-table" aria-label={label}>
        <thead>
          <tr>
            <th scope="col">Holder</th>
            <th scope="col">Right</th>
            <th scope="col">Resource</th>
            <th scope="col">Justification</th>
            <th scope="col">When</th>
            <th scope="col">State</th>
            <th scope="col">
              <span className="visually-hidden">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>{rows.map(row)}</tbody>
      </table>
    </div>
  );

  return (
    <>
      <nav aria-label="Breadcrumb" className="gitns-crumbs">
        <Link to={REPOS_PATH}>Repos</Link>
        <span aria-hidden="true">/</span>
        <span aria-current="page">Break-glass grants</span>
      </nav>
      <h2>Break-glass grants</h2>
      <p className="lead">
        Namespace admin, repo creator and owner are never granted to oneself. When nobody
        else could, an administrator broke the glass: the right took effect at once, does
        not expire, and stays here — and in the banner on every page — until another
        administrator ratifies it or revokes it.
      </p>

      {q.isPending && (
        <section className="card">
          <p>Reading break-glass grants…</p>
        </section>
      )}
      {q.isError && (
        <section className="card error">
          <h3>Break-glass grants could not be read</h3>
          <p>{readErrorMessage(q.error)}. This is a failure to ask, not an empty list.</p>
        </section>
      )}

      {q.data && (
        <section className="card" aria-labelledby="bg-awaiting">
          <h3 id="bg-awaiting">
            <Siren aria-hidden="true" size={16} /> Awaiting another administrator ·{" "}
            {awaiting.length}
          </h3>
          {awaiting.length === 0 ? (
            <p className="muted">None. Every break-glass has been ratified or revoked.</p>
          ) : (
            table(awaiting, "Break-glass grants awaiting a decision")
          )}
        </section>
      )}

      {q.data && settled.length > 0 && (
        <section className="card" aria-labelledby="bg-settled">
          <h3 id="bg-settled">Ratified</h3>
          <p className="muted gitns-small">
            Ordinary grants now, kept here as their history. Revoke one like any other
            right.
          </p>
          {table(settled, "Ratified break-glass grants")}
        </section>
      )}

      {dialog?.kind === "ratify" && isRight(dialog.item.right) && (
        <RatifyDialog
          subject={dialog.item.subject}
          subjectName={book.nameOf(dialog.item.subject) ?? undefined}
          right={dialog.item.right}
          resource={dialog.item.resource}
          breakGlassAt={dialog.item.breakGlass.at}
          justification={dialog.item.breakGlass.justification}
          onClose={() => setDialog(null)}
          onBuilt={(task) => setDialog({ kind: "sign", task })}
        />
      )}
      {dialog?.kind === "revoke" && isRight(dialog.item.right) && (
        <RevokeDialog
          subject={dialog.item.subject}
          subjectName={book.nameOf(dialog.item.subject) ?? undefined}
          right={dialog.item.right}
          resource={dialog.item.resource}
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
