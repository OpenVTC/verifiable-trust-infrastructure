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
// ## Why no button here changes anything by itself
//
// Every change is a signed `git-ns/*` Trust Task, authorized by the **signer's
// own git rights** read from the VTC's records at execution time. An
// administrator's role binds namespaces and nothing more: to grant on a
// repository, the signer must hold a right that carries that authority. A
// console session carries no proof, so the daemon mounts no REST door for any
// of these tasks, and the console cannot yet sign a document (#1641: #1692 is
// the server side of a console signing key, the browser side #1684 has not
// landed, and `git_ns` would still have to resolve that key's delegation to
// the administrator's DID before their git rights applied to it). So each
// action builds its task exactly as it will be sent and hands it over — as the
// `cnm git …` command that signs it with the administrator's community
// profile, and as the document itself. `repos/actions.ts` has the detail, and
// is where a console signer plugs in when there is one.
//
// The same reason explains the step-up. Design §6 puts grants of `own` and
// `repo.create`, transfer, archive and adopt behind a step-up, and binding and
// `ns.admin` behind a step-up and confirmation. A passkey step-up elevates a
// session; a signed document has none. The daemon's stand-in is
// `elevated_requires_admin` — those tasks are accepted only from a community
// administrator who also holds the right — and the hand-over dialog says which
// class each task is rather than running a ceremony that authorizes nothing.
//
// ## Expected is not observed
//
// The daemon reports each repository's bootstrap (workflow, keyring,
// variables, required check), its sync state and its drift. It does not
// report which guard keeps a pull request from satisfying its own check
// (design §9: a required workflow on an organisation, a bridge-posted check
// and code-owner review elsewhere), nor what the App was granted on the
// forge. The repository page shows the guard §9 assigns as *expected*, and the
// namespace cards claim nothing about App permissions at all.
//
// Section links are absolute: the shell mounts plugins on `path/*`, where a
// relative link outside the descendant `<Routes>` would resolve against the
// current section rather than the plugin root.

import { Route, Routes } from "react-router-dom";

import { BindFlow } from "./repos/BindFlow";
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
