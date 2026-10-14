// Wallet verifier — the identities this community presents to swiyu and EUDI
// wallets as an OpenID4VP verifier, and what stops each from serving one.
//
// A signed `vtc/oid4vp/identities/list/0.1` read, for holders of
// `vtc.config.admin`. Identities are installed with the `vtc oid4vp …`
// commands, not here: this page is where an administrator sees an access
// certificate or trust statement nearing expiry before wallets start refusing
// the community's requests, and why a wallet session cannot be opened when it
// cannot. Each problem's detail names the command that fixes it.

import { useQuery } from "@tanstack/react-query";
import { ScanLine } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { formatIso } from "@/lib/format";
import {
  attestationLabel,
  fetchVerifierIdentities,
  identityState,
  problemTitle,
  verifierKeys,
  worstFirst,
  type VerifierIdentity,
  type VerifierProblem,
} from "@/lib/verifier-identities";

const CUSTODY: Record<string, string> = {
  cached: "Cached by this VTC",
  agent: "Kept by the VTA (signs every request)",
  invalid: "Invalid record",
};

const KIND: Record<string, string> = { swiyu: "swiyu", eudi: "EUDI" };

function ProblemList({ problems }: { problems: VerifierProblem[] }) {
  if (problems.length === 0) return null;
  return (
    <ul className="verifier-problems">
      {worstFirst(problems).map((p, i) => (
        <li key={`${p.code}-${i}`}>
          <span className={`chip ${p.severity === "error" ? "danger" : "warning"}`}>
            {problemTitle(p.code)}
          </span>{" "}
          {p.detail && <span className="muted">{p.detail}</span>}
        </li>
      ))}
    </ul>
  );
}

function IdentityCard({ identity }: { identity: VerifierIdentity }) {
  const state = identityState(identity);
  return (
    <section className="card" aria-label={`Verifier identity ${identity.id}`}>
      <h3>
        {identity.id}{" "}
        <span className="chip">{KIND[identity.kind] ?? identity.kind}</span>{" "}
        {state === "ready" && <span className="chip success">Ready</span>}
        {state === "attention" && <span className="chip warning">Needs attention</span>}
        {state === "broken" && <span className="chip danger">Cannot open sessions</span>}{" "}
        {identity.isDefault && (
          <span
            className="chip accent"
            title="Used when a session names no client identifier prefix"
          >
            default
          </span>
        )}
      </h3>
      <ProblemList problems={identity.problems} />
      <dl className="verifier-fields">
        <dt>Client identifier</dt>
        <dd>
          {identity.clientId ? (
            <>
              <code className="truncate" title={identity.clientId}>
                {identity.clientId}
              </code>{" "}
              <CopyButton value={identity.clientId} />
            </>
          ) : (
            <span className="muted">none yet</span>
          )}
        </dd>
        {identity.keyId && (
          <>
            <dt>Signing key</dt>
            <dd>
              <code className="truncate" title={identity.keyId}>
                {identity.keyId}
              </code>
            </dd>
          </>
        )}
        <dt>Key custody</dt>
        <dd>{CUSTODY[identity.custody] ?? identity.custody}</dd>
        {identity.certificate && (
          <>
            <dt>Access certificate</dt>
            <dd>
              {identity.certificate.subject && <code>{identity.certificate.subject}</code>}
              <div className="muted">
                {identity.certificate.issuer && <>issued by {identity.certificate.issuer} · </>}
                valid {formatIso(identity.certificate.notBefore)} –{" "}
                {formatIso(identity.certificate.notAfter)} · chain of{" "}
                {identity.certificate.chainLength}
              </div>
            </dd>
          </>
        )}
        <dt>verifier_info</dt>
        <dd>
          {identity.attestations.length === 0 ? (
            <span className="muted">none</span>
          ) : (
            <ul>
              {identity.attestations.map((a, i) => (
                <li key={`${a.kind}-${i}`}>
                  {attestationLabel(a.kind)}
                  {a.expiresAt ? (
                    <span className="muted"> · expires {formatIso(a.expiresAt)}</span>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </dd>
        <dt>Installed</dt>
        <dd>{formatIso(identity.installedAt)}</dd>
      </dl>
    </section>
  );
}

export function WalletVerifier() {
  const query = useQuery({
    queryKey: verifierKeys.list,
    queryFn: fetchVerifierIdentities,
    // Expiry moves on its own; a page left open should notice.
    refetchInterval: 5 * 60_000,
  });
  const data = query.data;
  const identities = data?.identities ?? [];

  return (
    <section className="page">
      <PageHeader
        count={query.isPending ? undefined : identities.length}
        countLabel={`${identities.length} verifier identities`}
        lead={
          <>
            The identities this community presents to swiyu and EUDI wallets when an applicant
            proves something from a wallet. They are installed with <code>vtc oid4vp</code>; this
            page shows whether each can serve a wallet now and what will stop it.
          </>
        }
      />

      {query.isPending && (
        <section className="card">
          <p>Loading…</p>
        </section>
      )}
      {query.isError && (
        <section className="card">
          <p className="error">Could not read the verifier identities: {String(query.error)}</p>
        </section>
      )}

      {data && data.problems.length > 0 && (
        <section className="card" aria-label="Verifier problems">
          <h3>Affects every identity</h3>
          <ProblemList problems={data.problems} />
        </section>
      )}

      {data && identities.length === 0 && (
        <section className="card">
          <EmptyState icon={ScanLine} title="No verifier identities">
            Wallet presentations need one. See <code>docs/03-vtc/oid4vp-verifier.md</code> for{" "}
            <code>vtc oid4vp request</code> / <code>attach</code>.
          </EmptyState>
        </section>
      )}

      {identities.map((identity) => (
        <IdentityCard key={identity.id} identity={identity} />
      ))}
    </section>
  );
}
