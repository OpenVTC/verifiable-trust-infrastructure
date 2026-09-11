// The vetting facts a join request was decided on, for the admin deciding it.
//
// `GET /v1/join-requests/{id}/vetting` returns what the daemon counted at the
// decision — the policy's `input.evidence.vetting` — plus whether each
// statement has been withdrawn since. Every verdict is shown in words, with
// the daemon's code beside it for the admin who needs to search for it.

import { useQuery } from "@tanstack/react-query";
import { Check, X } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import { NamedDid } from "@/components/NamedDid";
import { formatIso, shorten } from "@/lib/format";
import { type NameBook, useNameBook } from "@/lib/names";
import {
  explainNeed,
  factsHeadline,
  methodLabel,
  relationshipLabel,
  statementVerdict,
} from "@/lib/vetting";
import type {
  JoinRequestVetting,
  JoinRequestVettingStatement,
} from "@/lib/wire-types";

import { fetchJoinRequestVetting, vettingKeys } from "./api";
import { errorMessage, ExplainedText, FINDING_CLASS, ToneChip } from "./ui";

export function useJoinRequestVetting(id: string) {
  return useQuery({
    queryKey: vettingKeys.joinRequest(id),
    queryFn: () => fetchJoinRequestVetting(id),
    enabled: id.length > 0,
  });
}

export function JoinRequestVettingCard({ id }: { id: string }) {
  const query = useJoinRequestVetting(id);
  return (
    <section className="card" aria-labelledby="join-vetting-title">
      <h3 id="join-vetting-title">Vetting</h3>
      {query.isPending && <p className="muted">Loading the vetting facts…</p>}
      {query.error && (
        <p className="finding error" role="alert">
          <strong>Could not load the vetting facts.</strong>
          <span className="muted">
            {errorMessage(query.error)} Reload the page to try again.
          </span>
        </p>
      )}
      {query.data && !query.data.vetting && (
        <p className="muted">
          No vetting criterion applied to this request, so no vetting statements
          were counted.
        </p>
      )}
      {query.data?.vetting && <VettingFacts facts={query.data.vetting} />}
    </section>
  );
}

export function VettingFacts({ facts }: { facts: JoinRequestVetting }) {
  const book = useNameBook();
  const headline = factsHeadline(facts);
  const byMethod = Object.entries(facts.byMethod)
    .filter(([, n]) => n > 0)
    .map(([method, n]) => `${methodLabel(method)} ${n}`);
  const needs = facts.needs.map(explainNeed);

  return (
    <>
      <p className={FINDING_CLASS[headline.tone]}>
        <strong>{headline.title}</strong>
        <span className="muted">{headline.detail}</span>
      </p>

      <dl>
        <dt>Criterion</dt>
        <dd>
          <code>{facts.criterionId}</code>
        </dd>
        <dt>Requirements digest</dt>
        <dd>
          <code>{facts.requirementsDigest}</code>
          <CopyButton
            value={facts.requirementsDigest}
            label="Copy requirements digest"
            successMessage="Requirements digest copied"
          />
          {!facts.applicantDigestMatches && (
            <span className="vet-note warn" title="applicantDigestMatches: false">
              The applicant gathered statements for different requirements than
              these. The request was evaluated under the requirements above.
            </span>
          )}
        </dd>
        <dt>Counted vetters</dt>
        <dd>
          {facts.distinctCountedVetters} distinct{" "}
          {facts.distinctCountedVetters === 1 ? "vetter" : "vetters"}
        </dd>
        <dt>By method</dt>
        <dd>{byMethod.length ? byMethod.join(" · ") : "None counted"}</dd>
        <dt>Same identity</dt>
        <dd title="commitmentsConsistent">
          {facts.commitmentsConsistent
            ? "Yes: the vetters verified the same identity"
            : "No: the vetters verified different identities"}
        </dd>
        <dt>Independence</dt>
        <dd title="independenceOk">
          {facts.independenceOk
            ? "Holds: no relationship limit is exceeded"
            : "Exceeded: too many statements declare the same relationship"}
        </dd>
        <dt>Invitation</dt>
        <dd title="invitationRequired">
          {facts.invitationRequired ? "Required by this criterion" : "Not required"}
        </dd>
        <dt>Recorded</dt>
        <dd>{formatIso(facts.recordedAt)}</dd>
      </dl>

      <div>
        <h4 className="vet-subhead">Still needed</h4>
        {needs.length === 0 ? (
          <p className="muted">Nothing is missing.</p>
        ) : (
          <ul className="vet-list">
            {needs.map((need) => (
              <li key={need.code}>
                <ExplainedText item={need} />
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <h4 className="vet-subhead">
          Statements presented ({facts.statements.length})
        </h4>
        {facts.statements.length === 0 ? (
          <p className="muted">
            The presentation carried no identity-vetting statements.
          </p>
        ) : (
          <div className="table-scroll">
            <table className="data-table vet-statements">
              <thead>
                <tr>
                  <th>Vetter</th>
                  <th>Method</th>
                  <th>Relationship to applicant</th>
                  <th>Checks</th>
                  <th>Outcome</th>
                </tr>
              </thead>
              <tbody>
                {facts.statements.map((statement, i) => (
                  <StatementRow
                    key={statement.id ?? `statement-${i}`}
                    statement={statement}
                    book={book}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

function StatementRow({
  statement,
  book,
}: {
  statement: JoinRequestVettingStatement;
  book: NameBook;
}) {
  const verdict = statementVerdict(statement);
  return (
    <tr>
      <td>
        {statement.issuer ? (
          <NamedDid book={book} did={statement.issuer} />
        ) : (
          <span className="muted">Signer unknown</span>
        )}
        {statement.id && (
          <div className="muted">
            <code title={statement.id}>{shorten(statement.id, 16, 6)}</code>
          </div>
        )}
      </td>
      <td>
        {statement.method ? (
          <span title={statement.method}>{methodLabel(statement.method)}</span>
        ) : (
          <span className="muted">Not stated</span>
        )}
      </td>
      <td>
        <span title={statement.declaredRelationship ?? undefined}>
          {relationshipLabel(statement.declaredRelationship)}
        </span>
      </td>
      <td>
        <ul className="vet-checks">
          <CheckItem
            ok={statement.verified}
            yes="Verified"
            no="Did not verify"
            code="verified"
          />
          <CheckItem
            ok={statement.eligible}
            yes="Eligible vetter"
            no="Not an eligible vetter"
            code="eligible"
          />
          <CheckItem
            ok={!statement.revoked && !statement.withdrawnNow}
            yes="Not withdrawn"
            no={
              statement.revoked
                ? "Withdrawn before the decision"
                : "Withdrawn since the decision"
            }
            code={statement.revoked ? "revoked" : "withdrawnNow"}
          />
        </ul>
      </td>
      <td>
        <ToneChip tone={verdict.tone}>{verdict.label}</ToneChip>
        {verdict.reasons.length > 0 && (
          <ul className="vet-list">
            {verdict.reasons.map((reason) => (
              <li key={reason.code}>
                <ExplainedText item={reason} />
              </li>
            ))}
          </ul>
        )}
      </td>
    </tr>
  );
}

function CheckItem({
  ok,
  yes,
  no,
  code,
}: {
  ok: boolean;
  yes: string;
  no: string;
  code: string;
}) {
  return (
    <li className={ok ? "vet-check ok" : "vet-check bad"} title={code}>
      {ok ? (
        <Check size={14} aria-hidden="true" />
      ) : (
        <X size={14} aria-hidden="true" />
      )}{" "}
      {ok ? yes : no}
    </li>
  );
}
