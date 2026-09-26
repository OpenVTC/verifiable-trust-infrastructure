// Repos plugin — the git namespaces this community governs, the repositories
// in them, and who may own, maintain and commit to each.
//
// ## What the community actually holds here
//
// A namespace binds this VTC to one owner on one forge (`github.com/acme`).
// Inside it, rights are held by DIDs on forge-qualified resources — the
// community's records, not the forge's roles. They go three places: the VTC's
// own store, which is the authority; the Trust Registry, where
// `did-git-sign verify-trust` reads `git.commit.sign` in CI; and the forge,
// where the community's bridge projects them onto roles. The last is a
// convenience and the first two are the guarantee, which is why a role added
// by hand on the forge is *drift* here rather than a new fact.
//
// ## Everything here is public, and the screens say so where it matters
//
// TRQP reads are anonymous, so who owns and who may commit to every governed
// repository is readable by anyone. That is intended — it is what lets CI
// verify a commit without a credential — but an administrator must be told
// before binding, not discover it afterwards, so the bind flow leads with it
// and the repository page shows the exact records it puts there.
//
// ## How a change is made
//
// Every change is a signed `git-ns/*` Trust Task, authorized by the **signer's
// own git rights** read from the VTC's records at execution time. An
// administrator's role binds namespaces and nothing more: to grant on a
// repository, the signer must hold a right that carries that authority. There
// is no bearer route for any of these tasks, so a console session alone can
// change nothing here.
//
// Where this browser holds a console signing key (#1695), a change is signed
// with it and sent; the VTC resolves the key's delegation to the operator's
// admin DID and authorizes the task by that DID's git rights (#1692 — the key
// confers nothing of its own). Where it does not, the same task is handed over
// as the `cnm git …` command that signs it with the operator's community
// profile, and as the document itself. `repos/actions.ts` has the detail.
//
// Step-up: design §6 puts grants of `own` and `repo.create`, transfer, archive
// and adopt behind a step-up, and binding and `ns.admin` behind a step-up and
// confirmation. A passkey step-up elevates a session; a signed document has
// none. The daemon's stand-in is `elevated_requires_admin` — those tasks are
// accepted only from a community administrator who also holds the right — and
// the dialog says which class each task is and makes a destructive one be
// confirmed before it is signed.
//
// ## Reported, and what is shown when it is not
//
// The daemon reports each repository's bootstrap, sync state, drift, the
// guard the bridge last saw in force, per-step outcomes of the last create or
// bootstrap, and the last verify-trust check; and for each namespace, what the
// bridge reported of its App (installation, missing permissions, a pending
// permission upgrade, org-ruleset availability). All of the bridge's reports
// are optional. Where the guard is unreported the page shows the one design §9
// assigns, labelled *expected*; where the App's permissions are unreported
// nothing is claimed about them either way.
//
// Section links are absolute: the shell mounts plugins on `path/*`, where a
// relative link outside the descendant `<Routes>` would resolve against the
// current section rather than the plugin root.

import { Route, Routes } from "react-router-dom";

import { BindFlow } from "./repos/BindFlow";
import { BreakGlassList } from "./repos/BreakGlass";
import { DepartedReview } from "./repos/DepartedReview";
import { Overview } from "./repos/Overview";
import { RepoDetail } from "./repos/RepoDetail";

export function Repos() {
  return (
    <section className="page gitns">
      <Routes>
        <Route index element={<Overview />} />
        <Route path="repo/:resource" element={<RepoDetail />} />
        <Route path="bind" element={<BindFlow />} />
        <Route path="departed" element={<DepartedReview />} />
        <Route path="break-glass" element={<BreakGlassList />} />
        <Route
          path="*"
          element={
            <p className="muted">
              There is no such Repos page. Go back to the list of namespaces.
            </p>
          }
        />
      </Routes>
    </section>
  );
}
