// Binding a namespace: the four steps of design §4.1, as this VTC runs them.
//
// ## The order is the daemon's, not the mockup's
//
// The design sketches *register the App → install it → confirm → adopt*, with
// the confirmation after GitHub has redirected back. On this VTC the binding
// is one signed `git-ns/namespace/bind` task, and it has to come **first**:
// it is what asks the community's bridge where to send the administrator
// (`next.url` — the App manifest registration the first time, the install
// page after), and it is what records the namespace as pending, so the bridge
// can prove the install it later reports was one this VTC started. There is no
// second confirmation to sign: the specification binds on the bridge's
// `bindCompleted` for the job the signed bind created.
//
// So everything a confirmation is for — the public-visibility consequence,
// the policy that will govern the namespace, and the step-up class — is shown
// *before* the one thing that gets signed, and step 3 is the administrator
// checking what the VTC recorded against what they meant to bind.
//
// Sent from this browser, the bind's answer carries `next.url` and the page
// links it. Handed to `cnm`, cnm prints it. Either way steps 1 and 2 happen on
// the forge, which the console cannot see: it watches the namespace list until
// the namespace appears pending and then turns bound. A manual-mode bind has
// no App and skips straight to step 3.

import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { TriangleAlert, Lock } from "lucide-react";

import { NamedDid } from "@/components/NamedDid";
import { fetchActivePolicy } from "@/lib/policies-api";
import { useNameBook } from "@/lib/names";

import {
  bindTask,
  forgeHostError,
  nextUrlOf,
  segmentError,
  type SignedTask,
  urlIsOnForge,
} from "./actions";
import { fetchNamespaces, fetchRepos, fetchRights, gitNsKeys } from "./api";
import { AdoptDialog } from "./dialogs";
import { isServiceGrant, kindLabel, shortName } from "./model";
import {
  errorMessage,
  namespacePath,
  POLICY_PATH,
  REPOS_PATH,
  repoPath,
  SignTaskDialog,
} from "./ui";

const steps = (owner: string) => [
  "Register your GitHub App",
  `Install on ${owner || "the owner"}`,
  "Confirm binding",
  "Adopt existing repos",
];

type Mode = "bridge" | "manual";

function Stepper({
  owner,
  current,
  done,
  skipped,
}: {
  owner: string;
  current: number;
  done: number[];
  skipped: number[];
}) {
  return (
    <ol className="gitns-stepper" aria-label="Binding steps">
      {steps(owner).map((label, i) => {
        const isDone = done.includes(i);
        const isSkipped = skipped.includes(i);
        const state = i === current ? "current" : isDone ? "done" : isSkipped ? "skipped" : "todo";
        return (
          <li key={label} className={state} aria-current={i === current ? "step" : undefined}>
            <span className="gitns-step-mark" aria-hidden="true">
              {isDone ? "✓" : i + 1}
            </span>
            {label}
            {isDone && <span className="visually-hidden"> (done)</span>}
            {isSkipped && <span className="muted gitns-small"> · not needed</span>}
          </li>
        );
      })}
    </ol>
  );
}

export function BindFlow() {
  const book = useNameBook();
  const [params, setParams] = useSearchParams();
  const forge = params.get("forge") ?? "github.com";
  const owner = params.get("owner") ?? "";
  const mode: Mode = params.get("mode") === "manual" ? "manual" : "bridge";
  const sent = params.get("sent") === "1";
  const [adopting, setAdopting] = useState(false);

  const [form, setForm] = useState({ forge, owner, mode });
  const [errors, setErrors] = useState<{ forge: string | null; owner: string | null }>({
    forge: null,
    owner: null,
  });
  const [task, setTask] = useState<SignedTask | null>(null);
  const [nextUrl, setNextUrl] = useState<string | null>(null);
  const [adoptResource, setAdoptResource] = useState<string | null>(null);
  const [adoptTaskState, setAdoptTaskState] = useState<SignedTask | null>(null);

  const nsQ = useQuery({
    queryKey: gitNsKeys.namespaces,
    queryFn: fetchNamespaces,
    // Only while waiting on the forge: the bridge's report is what moves
    // the flow on, and nothing else here changes without the operator.
    refetchInterval: (q) => {
      if (!sent) return false;
      const ns = q.state.data?.namespaces.find((n) => n.forge === forge && n.owner === owner);
      return !ns || ns.state === "pending" ? 5000 : false;
    },
  });
  const policyQ = useQuery({
    queryKey: ["policies", "active", "gitNamespace"],
    queryFn: () => fetchActivePolicy("gitNamespace"),
  });

  const ns = sent
    ? nsQ.data?.namespaces.find((n) => n.forge === forge && n.owner === owner)
    : undefined;
  const bound = ns?.state === "bound";
  const reposQ = useQuery({
    queryKey: gitNsKeys.repos,
    queryFn: fetchRepos,
    enabled: bound,
  });
  const rightsQ = useQuery({ queryKey: gitNsKeys.rights, queryFn: fetchRights, enabled: bound });
  const unmanaged = useMemo(
    () =>
      (reposQ.data?.repos ?? []).filter((r) => r.namespace === ns?.id && r.state === "unmanaged"),
    [reposQ.data, ns?.id],
  );

  const current = !sent ? 0 : !ns || ns.state === "pending" ? (mode === "manual" ? 2 : 1) : adopting ? 3 : 2;
  const skipped = mode === "manual" ? [0, 1] : [];
  const done = [...Array(current).keys()].filter((i) => !skipped.includes(i));

  const build = () => {
    const next = {
      forge: forgeHostError(form.forge),
      owner: segmentError(form.owner),
    };
    setErrors(next);
    if (next.forge || next.owner) return;
    setTask(bindTask(form.forge, form.owner, form.mode));
  };

  const startWatching = () => {
    setParams({ forge: form.forge, owner: form.owner, mode: form.mode, sent: "1" });
    setTask(null);
  };

  const policyVersion = policyQ.data?.version;

  return (
    <section className="card gitns-bind" aria-labelledby="gitns-bind-title">
      <Stepper owner={sent ? owner : form.owner} current={current} done={done} skipped={skipped} />
      <h2 id="gitns-bind-title" className="gitns-bind-title">
        {sent ? `Bind ${forge}/${owner}` : "Bind a namespace"}
      </h2>

      {!sent && (
        <form
          className="form-stack"
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            build();
          }}
        >
          <div className="gitns-form-row">
            <div className="field">
              <label className="field-label" htmlFor="gitns-forge">
                Forge
              </label>
              <input
                id="gitns-forge"
                value={form.forge}
                aria-describedby={errors.forge ? "gitns-forge-err" : undefined}
                onChange={(e) => setForm({ ...form, forge: e.target.value.trim() })}
              />
              {errors.forge && (
                <span id="gitns-forge-err" className="field-error" role="alert">
                  {errors.forge}
                </span>
              )}
            </div>
            <div className="field">
              <label className="field-label" htmlFor="gitns-owner">
                Organisation or account
              </label>
              <input
                id="gitns-owner"
                value={form.owner}
                placeholder="acme"
                aria-describedby={errors.owner ? "gitns-owner-err" : undefined}
                onChange={(e) => setForm({ ...form, owner: e.target.value.trim() })}
              />
              {errors.owner && (
                <span id="gitns-owner-err" className="field-error" role="alert">
                  {errors.owner}
                </span>
              )}
            </div>
          </div>

          <fieldset className="gitns-fieldset">
            <legend>How the VTC acts on the forge</legend>
            <label className="gitns-radio">
              <input
                type="radio"
                name="gitns-mode"
                checked={form.mode === "bridge"}
                onChange={() => setForm({ ...form, mode: "bridge" })}
              />
              <span>
                <b>Through the community's GitHub App</b>
                <span className="muted gitns-block">
                  The bridge registers the App the first time, then creates, adopts,
                  projects roles and watches for drift. Needs a bridge configured for
                  this forge.
                </span>
              </span>
            </label>
            <label className="gitns-radio">
              <input
                type="radio"
                name="gitns-mode"
                checked={form.mode === "manual"}
                onChange={() => setForm({ ...form, mode: "manual" })}
              />
              <span>
                <b>Manually</b>
                <span className="muted gitns-block">
                  No App. The VTC governs the rights; people with forge access carry
                  out the steps it names, and nothing checks the forge for drift.
                </span>
              </span>
            </label>
          </fieldset>

          <div className="finding warn" role="note">
            <strong>
              <TriangleAlert aria-hidden="true" size={14} /> Rights in this namespace are
              public
            </strong>
            <span>
              Who owns each repository and who may commit is published to your Trust
              Registry, which anyone can query. That is what lets CI verify commits
              without credentials.
            </span>
          </div>

          <div className="finding">
            <strong>Who may hold rights here</strong>
            <span>
              Your community decides in its git namespace policy: who may create
              repositories, and whether non-members may sign.{" "}
              {policyQ.isSuccess && policyQ.data === null
                ? "No git namespace policy is active, so every change would be refused until one is."
                : "The shipped policy is members only, with no external signers."}{" "}
              <Link to={POLICY_PATH}>
                {policyVersion ? `Edit policy (v${policyVersion} active)` : "Edit policy"}
              </Link>
            </span>
            <span className="muted">
              Drift: a weakened ruleset is re-applied; a role changed on the forge is
              reported for an owner to adopt or revert, unless the policy sets{" "}
              <code>role_drift = "enforce"</code>.
            </span>
          </div>

          <div className="finding">
            <strong>
              <Lock aria-hidden="true" size={14} /> Binding makes you its admin
            </strong>
            <span>
              It is destructive-class: design §6 asks for a step-up and a confirmation.
              You confirm by signing it as a community administrator, which this VTC
              requires for it.
            </span>
          </div>

          <div className="form-actions">
            <Link to={REPOS_PATH} className="button secondary">
              Cancel
            </Link>
            <button type="submit" className="primary">
              Build the binding
            </button>
          </div>
        </form>
      )}

      {sent && !bound && (
        <p>
          <button
            type="button"
            className="link"
            onClick={() => {
              setNextUrl(null);
              setParams({});
            }}
          >
            Back to the form
          </button>{" "}
          <span className="muted gitns-small">
            — to change what you bind. A bind already sent stays pending until it
            completes or expires.
          </span>
        </p>
      )}

      {sent && nsQ.isError && (
        <p className="muted">
          The namespace list could not be read: {errorMessage(nsQ.error)}. Retrying.
        </p>
      )}

      {sent && !ns && nsQ.isSuccess && (
        <div className="finding" role="status">
          <strong>Waiting for the VTC to record {forge}/{owner}</strong>
          <span>
            Run the signed bind if you have not yet. Once it is accepted the namespace
            appears here{mode === "bridge" ? " as pending, and cnm prints where to go next" : ", bound"}.
          </span>
          <span>
            <button
              type="button"
              className="link"
              onClick={() => setTask(bindTask(forge, owner, mode))}
            >
              Show the command again
            </button>
          </span>
        </div>
      )}

      {ns?.state === "pending" && (
        <div className="finding" role="status">
          <strong>Pending: install the App on {owner}</strong>
          <span>
            {nextUrl && urlIsOnForge(nextUrl, forge) ? (
              <>
                <a href={nextUrl} target="_blank" rel="noopener noreferrer">
                  Continue on {forge}
                </a>
                .
              </>
            ) : nextUrl ? (
              <>
                The bridge answered with a URL that is not on {forge}:{" "}
                <code className="gitns-party-did">{nextUrl}</code>. Check it is your
                bridge's before opening it.
              </>
            ) : (
              <>
                Open the URL the bind answered with (<code>cnm git namespace bind</code>{" "}
                prints it).
              </>
            )}{" "}
            The first time, it registers the community's App from its manifest; then
            install it on {owner}, which needs owner rights there. This page moves on
            by itself when the bridge reports the install.
          </span>
        </div>
      )}

      {bound && ns && !adopting && (
        <>
          <div className="gitns-facts">
            <div>
              <span className="field-label">Account type</span>
              <b>{kindLabel(ns)}</b>
            </div>
            <div>
              <span className="field-label">{ns.mode === "bridge" ? "Bridge" : "Mode"}</span>
              {ns.bridgeDid ? <NamedDid did={ns.bridgeDid} book={book} /> : <b>Manual</b>}
              {ns.ownerId && (
                <span className="muted gitns-small gitns-block">owner id {ns.ownerId}</span>
              )}
            </div>
            <div>
              <span className="field-label">Existing repos</span>
              <b>
                {reposQ.isSuccess
                  ? `${unmanaged.length} · unmanaged until adopted`
                  : "…"}
              </b>
            </div>
          </div>
          <p>
            The VTC recorded <code>{ns.resource}</code> as bound, with{" "}
            {ns.admins.length === 1 ? "one admin" : `${ns.admins.length} admins`}:{" "}
            {ns.admins.map((a) => (
              <NamedDid key={a} did={a} book={book} />
            ))}
            .{" "}
            {ns.bridgeDid &&
              (rightsQ.data?.rights.some((r) => isServiceGrant(r, ns))
                ? "The bridge holds its service grant to re-sign Dependabot pull requests."
                : rightsQ.isSuccess
                  ? "The bridge holds no service grant: the policy refused it."
                  : "")}
          </p>
          {ns.kind === "user" && (
            <p className="muted">
              A personal account: GitHub roles collapse to write and only the account
              holder can create repositories. Consider moving to an organisation.
            </p>
          )}
          <div className="form-actions">
            <Link to={namespacePath(ns.id)} className="button secondary">
              Done
            </Link>
            <button type="button" className="primary" onClick={() => setAdopting(true)}>
              Continue to adopt
            </button>
          </div>
        </>
      )}

      {bound && ns && adopting && (
        <>
          {unmanaged.length === 0 ? (
            <p className="muted">
              {ns.mode === "bridge"
                ? "The bridge has reported no unmanaged repositories in this namespace."
                : "In manual mode the VTC does not list the forge's repositories. Adopt one by name from the Repos page."}
            </p>
          ) : (
            <ul className="gitns-adopt-list">
              {unmanaged.map((r) => (
                <li key={r.id}>
                  <Link to={repoPath(r.resource)} className="gitns-mono">
                    {shortName(r.resource)}
                  </Link>
                  <span className="muted gitns-small">{r.visibility}</span>
                  <button
                    type="button"
                    className="secondary sm"
                    aria-label={`Adopt ${shortName(r.resource)}`}
                    onClick={() => setAdoptResource(r.resource)}
                  >
                    Adopt
                  </button>
                </li>
              ))}
            </ul>
          )}
          <div className="form-actions">
            <Link to={namespacePath(ns.id)} className="button primary">
              Finish
            </Link>
          </div>
        </>
      )}

      {task && (
        <SignTaskDialog
          task={task}
          onClose={() => setTask(null)}
          onSent={(response) => {
            setNextUrl(nextUrlOf(response));
            startWatching();
          }}
          onHandedOff={startWatching}
        >
          {task.payload.mode === "bridge" && (
            <p className="muted">
              Once accepted, the bind answers with where to go on the forge. Close this
              and the page waits for the binding.
            </p>
          )}
        </SignTaskDialog>
      )}
      {adoptResource && (
        <AdoptDialog
          resource={adoptResource}
          onClose={() => setAdoptResource(null)}
          onBuilt={(t) => {
            setAdoptResource(null);
            setAdoptTaskState(t);
          }}
        />
      )}
      {adoptTaskState && (
        <SignTaskDialog task={adoptTaskState} onClose={() => setAdoptTaskState(null)} />
      )}
    </section>
  );
}
