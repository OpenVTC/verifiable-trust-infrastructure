import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { postSignedTrustTask, signingAvailable, type WhoamiResponse } from "@/lib/api";

import { Repos } from "@/plugins/repos";
import { mockFetch, renderWithProviders } from "@/test/render";

import {
  ACME,
  ALICE,
  BOB,
  DOCS,
  gitNsRoutes,
  HANA,
  JUN,
  PERSONAL,
  RIGHTS,
  WIDGETS,
} from "./fixtures.test-data";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  signingAvailable: vi.fn(async () => false),
  postSignedTrustTask: vi.fn(),
}));

beforeEach(() => {
  vi.mocked(signingAvailable).mockResolvedValue(false);
  vi.mocked(postSignedTrustTask).mockReset();
});

const mount = (resource: string, whoami?: WhoamiResponse) =>
  renderWithProviders(<Repos />, {
    route: `/repos/repo/${encodeURIComponent(resource)}`,
    path: "/repos/*",
    whoami,
  });

const signedInAs = (subject: string, roles: string[] = ["initiator"]): WhoamiResponse => ({
  session: {
    id: "sess_1",
    subject,
    issuedAt: "2026-09-01T00:00:00Z",
    expiresAt: "2026-09-01T00:05:00Z",
  },
  roles,
  scopes: [],
});

describe("Repo detail", () => {
  it("shows people × rights with forge account, granter, expiry and departed flags", async () => {
    mockFetch(gitNsRoutes());
    mount(WIDGETS.resource);

    const people = await screen.findByRole("region", { name: "People and rights" });
    const table = await within(people).findByRole("table");
    await within(table).findAllByText("Hana Sato");
    // The person is the row's first cell; the same name can recur as granter.
    const row = (name: string) =>
      within(table)
        .getAllByRole("row")
        .find((r) => r.querySelector("td")?.textContent?.includes(name))!;

    expect(within(row("Alice Wong")).getByText("Owner")).toBeTruthy();
    expect(within(row("Alice Wong")).getByText("@alicew")).toBeTruthy();
    // The last owner cannot be revoked; the row says why instead.
    expect(within(row("Alice Wong")).getByText("Last owner — name another first")).toBeTruthy();
    expect(within(row("Hana Sato")).getByText("Maintainer")).toBeTruthy();
    expect(within(row("Hana Sato")).getByText("@hsato")).toBeTruthy();

    const jun = within(table).getByText(/QmJun/).closest("tr")!;
    expect(within(jun).getByText("External signer")).toBeTruthy();
    expect(within(jun).getByText(/Not linked · fork pull requests/)).toBeTruthy();
    expect(jun.textContent).toMatch(/expires/);
    expect(jun.textContent).toMatch(/OSS contributor/);

    const priya = row("Priya Nair");
    expect(priya.textContent).toMatch(/departed/);
    expect(priya.textContent).toMatch(/review/);
  });

  it("shows namespace rights that reach the repository read-only, the bridge's among them", async () => {
    mockFetch(gitNsRoutes());
    mount(WIDGETS.resource);

    const inherited = await screen.findByRole("region", { name: "Through the namespace" });
    expect(
      await within(inherited).findByText("Bridge service grant · Dependabot re-sign"),
    ).toBeTruthy();
    expect(within(inherited).getByText("The community")).toBeTruthy();
    expect(within(inherited).queryByRole("button", { name: /Revoke/ })).toBeNull();
  });

  it("revokes a maintainer as a normal-class task and sends nothing itself", async () => {
    const requests = mockFetch(gitNsRoutes());
    mount(WIDGETS.resource);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke Maintainer from Hana Sato" }));
    const form = await screen.findByRole("dialog", { name: /Revoke maintainer on acme\/widgets/ });
    fireEvent.click(within(form).getByRole("button", { name: "Build the revocation" }));
    const sign = await screen.findByRole("dialog", { name: /Revoke maintainer on acme\/widgets/ });
    expect(sign.textContent).toMatch(/Consent class: Normal/);
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      `cnm git revoke --subject=${HANA} --right=git.repo.maintain --resource=${WIDGETS.resource}`,
    );
    const doc = JSON.parse(within(sign).getByLabelText("Document").textContent!);
    expect(doc).toEqual({
      type: "https://trusttasks.org/spec/git-ns/right/revoke/0.3",
      payload: { subject: HANA, right: "git.repo.maintain", resource: WIDGETS.resource },
    });
    fireEvent.click(within(sign).getByRole("button", { name: "Close" }));
    expect(requests.some((r) => r.method !== "GET")).toBe(false);
    expect(postSignedTrustTask).not.toHaveBeenCalled();
  });

  it("adds a person, and an owner grant carries the step-up class", async () => {
    mockFetch(gitNsRoutes());
    mount(WIDGETS.resource);

    fireEvent.click(await screen.findByRole("button", { name: "Add person" }));
    const form = await screen.findByRole("dialog", { name: "Add a person to acme/widgets" });
    await within(form).findByRole("option", { name: /Bob Mensah/ });
    fireEvent.change(within(form).getByLabelText("Person"), { target: { value: BOB } });
    fireEvent.change(within(form).getByLabelText("Right"), { target: { value: "git.repo.own" } });
    expect(form.textContent).toMatch(/elevated-class: it needs a step-up/);
    fireEvent.change(within(form).getByLabelText("Expires after (days)"), {
      target: { value: "0" },
    });
    fireEvent.click(within(form).getByRole("button", { name: "Build the grant" }));
    expect(within(form).getByRole("alert").textContent).toMatch(/Whole days/);

    fireEvent.change(within(form).getByLabelText("Expires after (days)"), {
      target: { value: "30" },
    });
    fireEvent.click(within(form).getByRole("button", { name: "Build the grant" }));
    const sign = await screen.findByRole("dialog", { name: "Grant owner on acme/widgets" });
    expect(sign.textContent).toMatch(/Elevated — step-up/);
    expect(within(sign).getByLabelText("Command").textContent).toContain("--expires-in=30d");
  });

  it("offers a pasted DID for an external signer on a repository right", async () => {
    mockFetch(gitNsRoutes());
    mount(WIDGETS.resource);

    fireEvent.click(await screen.findByRole("button", { name: "Add person" }));
    const form = await screen.findByRole("dialog", { name: "Add a person to acme/widgets" });
    await within(form).findByRole("option", { name: /Bob Mensah/ });
    fireEvent.change(within(form).getByLabelText("Person"), { target: { value: "__other__" } });
    fireEvent.change(within(form).getByLabelText("Person DID"), {
      target: { value: "did:key:z6MkOutsider" },
    });
    expect(form.textContent).toMatch(/policy allows external signers/);
    fireEvent.click(within(form).getByRole("button", { name: "Build the grant" }));
    const sign = await screen.findByRole("dialog", { name: /Grant owner|Grant committer/ });
    expect(within(sign).getByLabelText("Command").textContent).toContain(
      "--subject=did:key:z6MkOutsider",
    );
  });

  it("shows the bootstrap checklist and the guard design §9 expects", async () => {
    mockFetch(gitNsRoutes());
    mount(WIDGETS.resource);

    const trust = await screen.findByRole("region", { name: "Commit trust on github.com" });
    expect(within(trust).getAllByText("in place")).toHaveLength(4);
    expect(trust.textContent).toMatch(/Guard: Required workflow/);
    expect(trust.textContent).toMatch(/Expected for a bridge-mode organization \(design §9\)/);
  });

  it("names a solo owner's unreviewed workflow changes on a personal account", async () => {
    const repo = { ...WIDGETS, namespace: PERSONAL.id, resource: "github.com/glenn-g/tool" };
    mockFetch(gitNsRoutes({ repos: [repo] }));
    mount(repo.resource);

    const trust = await screen.findByRole("region", { name: "Commit trust on github.com" });
    expect(trust.textContent).toMatch(/Solo owner — workflow changes unreviewed/);
  });

  it("previews the public registry records, implied commit rights included", async () => {
    mockFetch(gitNsRoutes());
    mount(WIDGETS.resource);

    const reg = await screen.findByRole("region", { name: "Published to the Trust Registry" });
    const table = await within(reg).findByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);
    const text = rows.map((r) => r.textContent);
    expect(text.some((t) => /Alice Wong.*git\.repo\.own.*Published/.test(t!))).toBe(true);
    expect(
      text.some((t) => /Alice Wong.*git\.commit\.signimplied by git\.repo\.own.*Published/.test(t!)),
    ).toBe(true);
    expect(text.some((t) => /Hana Sato.*git\.commit\.signimplied by git\.repo\.maintain.*Pending/.test(t!))).toBe(
      true,
    );
    // An external signer's commit right is published like anyone else's.
    expect(text.some((t) => t!.includes(JUN.slice(-12)) && t!.includes("git.commit.sign"))).toBe(true);
    // The namespace-wide commit rights that also cover this repository.
    expect(text.some((t) => /git\.commit\.signgithub\.com\/acme(?!\/)/.test(t!))).toBe(true);
  });

  it("adopts a forge role through git-ns/drift/resolve, carrying the item's selector", async () => {
    const requests = mockFetch(gitNsRoutes());
    // Bob owns acme/docs; the maintain role was added for Hana's account.
    mount(DOCS.resource, signedInAs(BOB));

    const drift = await screen.findByRole("region", { name: "Drift" });
    expect(within(drift).getByText("Role added on the forge")).toBeTruthy();
    // The member the account resolves to, by full DID beside the login.
    await waitFor(() => expect(drift.textContent).toContain(`@hsato — linked by Hana Sato ${HANA}`));
    const button = await within(drift).findByRole("button", {
      name: "Adopt: Role added on the forge @hsato",
    });
    expect(button.textContent).toBe("Adopt into VTC as maintainer");
    fireEvent.click(button);
    const form = await screen.findByRole("dialog", { name: "Adopt drift on acme/docs" });
    expect(form.textContent).toMatch(/Grants maintainer to/);
    fireEvent.change(within(form).getByLabelText("Reason"), { target: { value: "Hana's role" } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the adopt" }));

    const sign = await screen.findByRole("dialog", { name: "Adopt drift on acme/docs" });
    expect(sign.textContent).toMatch(/Consent class: Normal/);
    expect(sign.textContent).toContain(HANA);
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      `cnm git drift resolve ${DOCS.resource} adopt --type=roleAdded --account-id=1003 --account-login=hsato --observed=maintain --reason='Hana'"'"'s role'`,
    );
    expect(JSON.parse(within(sign).getByLabelText("Document").textContent!)).toEqual({
      type: "https://trusttasks.org/spec/git-ns/drift/resolve/0.1",
      payload: {
        resource: DOCS.resource,
        action: "adopt",
        drift: {
          type: "roleAdded",
          account: { forge: "github.com", id: "1003", login: "hsato" },
          observed: "maintain",
        },
        reason: "Hana's role",
      },
    });
    fireEvent.click(within(sign).getByRole("button", { name: "Close" }));
    expect(requests.some((r) => r.method !== "GET")).toBe(false);
    expect(postSignedTrustTask).not.toHaveBeenCalled();
  });

  const driftRoute = (items: object[]) => ({
    path: "/v1/git-ns/drift",
    body: { repos: [{ resource: DOCS.resource, state: "drift", drift: items }] },
  });
  const hsato = { forge: "github.com", id: "1003", login: "hsato" };

  it("adopts write on a personal account as maintainer, where the server projects it", async () => {
    const routes = gitNsRoutes({
      namespaces: [{ ...ACME, kind: "user" }],
      extra: [driftRoute([{ type: "roleAdded", resource: DOCS.resource, observed: "write", account: hsato }])],
    });
    mockFetch(routes);
    mount(DOCS.resource, signedInAs(BOB));
    const drift = await screen.findByRole("region", { name: "Drift" });
    const button = await within(drift).findByRole("button", { name: /^Adopt/ });
    expect(button.textContent).toBe("Adopt into VTC as maintainer");
    expect(drift.textContent).not.toMatch(/No git right/);
  });

  it("says write projects nothing on an organisation, and offers no adopt", async () => {
    mockFetch(
      gitNsRoutes({
        extra: [driftRoute([{ type: "roleAdded", resource: DOCS.resource, observed: "write", account: hsato }])],
      }),
    );
    mount(DOCS.resource, signedInAs(BOB));
    const drift = await screen.findByRole("region", { name: "Drift" });
    await within(drift).findByText("Role added on the forge");
    await waitFor(() => expect(drift.textContent).toMatch(/No git right projects to the forge role "write"/));
    expect(within(drift).queryByRole("button", { name: /^Adopt/ })).toBeNull();
  });

  it("refuses to adopt a lowering, which is accepted by revoking", async () => {
    // Hana holds maintain on docs; the forge shows her at maintain too.
    mockFetch(
      gitNsRoutes({
        rights: [
          ...RIGHTS,
          { ...RIGHTS[4]!, resource: DOCS.resource },
        ],
        extra: [driftRoute([{ type: "roleChanged", resource: DOCS.resource, observed: "maintain", expected: "admin", account: hsato }])],
      }),
    );
    mount(DOCS.resource, signedInAs(BOB, ["admin"]));
    const drift = await screen.findByRole("region", { name: "Drift" });
    await waitFor(() => expect(drift.textContent).toMatch(/lowering, accepted by revoking/));
    expect(within(drift).queryByRole("button", { name: /^Adopt/ })).toBeNull();
    // Revert stays on offer.
    expect(within(drift).getByRole("button", { name: /^Revert/ })).toBeTruthy();
  });

  it("offers no adopt until the rights listing has answered", async () => {
    // The listing never settles: a lowering must not be offered on no data.
    let release: (v: unknown) => void = () => {};
    const held = new Promise((r) => (release = r));
    const routes = gitNsRoutes({
      rights: [...RIGHTS, { ...RIGHTS[4]!, resource: DOCS.resource }],
      extra: [
        driftRoute([{ type: "roleChanged", resource: DOCS.resource, observed: "maintain", expected: "admin", account: hsato }]),
      ],
    });
    const rightsRoute = routes.find((r) => r.path === "/v1/git-ns/rights")!;
    const body = rightsRoute.body;
    const realFetch = globalThis.fetch;
    mockFetch(routes);
    const mocked = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (new URL(url, "http://x").pathname === "/v1/git-ns/rights") await held;
      return mocked(input, init);
    }) as typeof fetch;
    try {
      mount(DOCS.resource, signedInAs(BOB, ["admin"]));
      const drift = await screen.findByRole("region", { name: "Drift" });
      await waitFor(() => expect(drift.textContent).toMatch(/before offering to adopt/));
      expect(within(drift).queryByRole("button", { name: /^Adopt/ })).toBeNull();
      release(body);
      // Once read, the lowering is recognised and still not offered.
      await waitFor(() => expect(drift.textContent).toMatch(/lowering, accepted by revoking/));
      expect(within(drift).queryByRole("button", { name: /^Adopt/ })).toBeNull();
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it.each([
    ["a DID that holds no right there", signedInAs(HANA, ["admin"])],
    ["a viewer without a session probe", undefined],
  ])("does not offer adopt to %s, and hands over the command", async (_, whoami) => {
    mockFetch(gitNsRoutes());
    mount(DOCS.resource, whoami);
    const drift = await screen.findByRole("region", { name: "Drift" });
    await waitFor(() => expect(within(drift).getByLabelText("Adopt command")).toBeTruthy());
    expect(within(drift).queryByRole("button", { name: /^Adopt/ })).toBeNull();
    expect(within(drift).getByLabelText("Adopt command").textContent).toBe(
      `cnm git drift resolve ${DOCS.resource} adopt --type=roleAdded --account-id=1003 --account-login=hsato --observed=maintain`,
    );
  });

  it("offers an elevated adopt only to a community administrator", async () => {
    const extra = [driftRoute([{ type: "roleAdded", resource: DOCS.resource, observed: "admin", account: hsato }])];
    mockFetch(gitNsRoutes({ extra }));
    const view = mount(DOCS.resource, signedInAs(BOB));
    const drift = await screen.findByRole("region", { name: "Drift" });
    await waitFor(() => expect(drift.textContent).toMatch(/elevated grant/));
    expect(within(drift).queryByRole("button", { name: /^Adopt/ })).toBeNull();
    view.unmount();

    mockFetch(gitNsRoutes({ extra }));
    mount(DOCS.resource, signedInAs(BOB, ["admin"]));
    const again = await screen.findByRole("region", { name: "Drift" });
    fireEvent.click(await within(again).findByRole("button", { name: /^Adopt/ }));
    fireEvent.click(
      within(await screen.findByRole("dialog", { name: "Adopt drift on acme/docs" })).getByRole(
        "button",
        { name: "Build the adopt" },
      ),
    );
    const sign = await screen.findByRole("dialog", { name: "Adopt drift on acme/docs" });
    expect(sign.textContent).toMatch(/Consent class: Elevated/);
  });

  it("reverts drift for the repository's owner as git-ns/drift/resolve", async () => {
    const requests = mockFetch(gitNsRoutes());
    // Bob owns acme/docs; he is not a community administrator.
    mount(DOCS.resource, signedInAs(BOB));

    const drift = await screen.findByRole("region", { name: "Drift" });
    fireEvent.click(
      await within(drift).findByRole("button", { name: "Revert: Role added on the forge @hsato" }),
    );
    const form = await screen.findByRole("dialog", { name: "Revert drift on acme/docs" });
    expect(form.textContent).toMatch(/takes the forge role off the account/);
    fireEvent.change(within(form).getByLabelText("Reason"), { target: { value: "Not granted here" } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the revert" }));

    const sign = await screen.findByRole("dialog", { name: "Revert drift on acme/docs" });
    expect(sign.textContent).toMatch(/Consent class: Normal/);
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      `cnm git drift resolve ${DOCS.resource} revert --type=roleAdded --account-id=1003 --account-login=hsato --observed=maintain --reason='Not granted here'`,
    );
    const doc = JSON.parse(within(sign).getByLabelText("Document").textContent!);
    expect(doc).toEqual({
      type: "https://trusttasks.org/spec/git-ns/drift/resolve/0.1",
      payload: {
        resource: DOCS.resource,
        action: "revert",
        drift: {
          type: "roleAdded",
          account: { forge: "github.com", id: "1003", login: "hsato" },
          observed: "maintain",
        },
        reason: "Not granted here",
      },
    });
    fireEvent.click(within(sign).getByRole("button", { name: "Close" }));
    expect(requests.some((r) => r.method !== "GET")).toBe(false);
    expect(postSignedTrustTask).not.toHaveBeenCalled();
  });

  it.each([
    ["a DID that holds no right there", signedInAs(HANA, ["admin"])],
    ["a viewer without a session probe", undefined],
  ])("does not offer revert to %s, and hands over the command", async (_, whoami) => {
    mockFetch(gitNsRoutes());
    mount(DOCS.resource, whoami);

    const drift = await screen.findByRole("region", { name: "Drift" });
    await within(drift).findByText("Role added on the forge");
    expect(within(drift).queryByRole("button", { name: /^Revert/ })).toBeNull();
    expect(drift.textContent).toMatch(/an owner's decision/);
    expect(within(drift).getByLabelText("Revert command").textContent).toBe(
      `cnm git drift resolve ${DOCS.resource} revert --type=roleAdded --account-id=1003 --account-login=hsato --observed=maintain`,
    );
  });

  it("offers an elevated revert only to a community administrator who owns the repository", async () => {
    const routes = gitNsRoutes().map((r) =>
      r.path === "/v1/git-ns/drift"
        ? {
            ...r,
            body: {
              repos: [
                {
                  resource: DOCS.resource,
                  state: "drift",
                  drift: [
                    {
                      type: "roleAdded",
                      resource: DOCS.resource,
                      observed: "admin",
                      account: { forge: "github.com", id: "1003", login: "hsato" },
                    },
                  ],
                },
              ],
            },
          }
        : r,
    );
    mockFetch(routes);
    const view = mount(DOCS.resource, signedInAs(BOB));
    const drift = await screen.findByRole("region", { name: "Drift" });
    await within(drift).findByText("Role added on the forge");
    expect(within(drift).queryByRole("button", { name: /^Revert/ })).toBeNull();
    expect(drift.textContent).toMatch(/only from a community administrator/);
    view.unmount();

    mockFetch(routes);
    mount(DOCS.resource, signedInAs(BOB, ["admin"]));
    const again = await screen.findByRole("region", { name: "Drift" });
    fireEvent.click(await within(again).findByRole("button", { name: /^Revert/ }));
    fireEvent.click(
      within(await screen.findByRole("dialog", { name: "Revert drift on acme/docs" })).getByRole(
        "button",
        { name: "Build the revert" },
      ),
    );
    const sign = await screen.findByRole("dialog", { name: "Revert drift on acme/docs" });
    expect(sign.textContent).toMatch(/Consent class: Elevated/);
  });

  it("transfers ownership with cnm git transfer, excluding current owners", async () => {
    mockFetch(gitNsRoutes());
    mount(WIDGETS.resource);

    fireEvent.click(await screen.findByRole("button", { name: "Transfer ownership" }));
    const form = await screen.findByRole("dialog", { name: "Transfer ownership of acme/widgets" });
    await within(form).findByRole("option", { name: /Bob Mensah/ });
    expect(within(form).queryByRole("option", { name: /Alice Wong/ })).toBeNull();
    fireEvent.change(within(form).getByLabelText("New owner"), { target: { value: BOB } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the transfer" }));

    const sign = await screen.findByRole("dialog", { name: "Transfer ownership of acme/widgets" });
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      `cnm git transfer ${WIDGETS.resource} --to=${BOB}`,
    );
    expect(JSON.parse(within(sign).getByLabelText("Document").textContent!).payload).toEqual({
      resource: WIDGETS.resource,
      to: BOB,
    });
  });

  it("archives with cnm git archive, or sends it signed from this browser", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    vi.mocked(postSignedTrustTask).mockResolvedValue({ repo: {} });
    mockFetch(gitNsRoutes());
    mount(WIDGETS.resource);

    fireEvent.click(await screen.findByRole("button", { name: "Archive" }));
    const sign = await screen.findByRole("dialog", { name: "Archive acme/widgets" });
    expect(sign.textContent).toMatch(/Elevated — step-up/);
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      `cnm git archive ${WIDGETS.resource}`,
    );
    fireEvent.click(await within(sign).findByRole("button", { name: "Sign and send" }));
    await waitFor(() =>
      expect(postSignedTrustTask).toHaveBeenCalledWith(
        "https://trusttasks.org/spec/git-ns/repo/archive/0.1",
        { resource: WIDGETS.resource },
      ),
    );
  });

  it("shows the guard the bridge reports, step outcomes and the last check", async () => {
    mockFetch(
      gitNsRoutes({
        repos: [
          {
            ...WIDGETS,
            owners: [ALICE, BOB],
            guard: "bridgePostedCheck",
            steps: [
              { step: "workflow", outcome: "unchanged" },
              { step: "ruleset", outcome: "failed", detail: "422 from the forge" },
            ],
            lastCheck: { conclusion: "success", at: "2026-09-20T00:00:00Z", sha: "abcdef0123456789" } as never,
          },
        ],
      }),
    );
    mount(WIDGETS.resource);

    const trust = await screen.findByRole("region", { name: "Commit trust on github.com" });
    expect(trust.textContent).toMatch(/Guard: Bridge-posted check/);
    expect(trust.textContent).toMatch(/As the bridge last reported it/);
    expect(trust.textContent).toMatch(/ruleset\s*failed\s*422 from the forge/);
    expect(trust.textContent).toMatch(/Last check:\s*success/);
    expect(trust.textContent).toMatch(/abcdef012345/);
  });

  it("reads a reported code-owner review with one owner as unreviewed", async () => {
    mockFetch(gitNsRoutes({ repos: [{ ...WIDGETS, guard: "codeOwnerReview" }] }));
    mount(WIDGETS.resource);

    const trust = await screen.findByRole("region", { name: "Commit trust on github.com" });
    expect(trust.textContent).toMatch(/Solo owner — workflow changes unreviewed/);
    expect(trust.textContent).toMatch(/Last check:\s*none reported/);
  });

  it("shows the repository's activity from the namespace feed", async () => {
    const requests = mockFetch(gitNsRoutes());
    mount(WIDGETS.resource);

    const act = await screen.findByRole("region", { name: "Recent activity" });
    await within(act).findByText(/bridge job bootstrap/);
    expect(act.textContent).toMatch(/granted\s*committer/);
    // Only this repository's items, not the namespace's.
    expect(act.textContent).not.toMatch(/owner/);
    expect(requests.some((r) => r.url === "/v1/git-ns/activity?namespace=ns_acme&limit=100")).toBe(
      true,
    );
  });

  it("says activity is for namespace admins when the feed refuses", async () => {
    mockFetch(gitNsRoutes({ activityStatus: 403 }));
    mount(WIDGETS.resource);

    const act = await screen.findByRole("region", { name: "Recent activity" });
    expect(await within(act).findByText(/does\s+not hold/)).toBeTruthy();
  });

  it("says a scoped admin cannot read the community-wide records", async () => {
    mockFetch([
      { path: "/v1/git-ns/rights", status: 403, body: { error: "super admin required" } },
      ...gitNsRoutes(),
    ]);
    mount(WIDGETS.resource);

    const people = await screen.findByRole("region", { name: "People and rights" });
    expect(
      (await within(people).findByText(/Rights could not be read/)).textContent,
    ).toMatch(/only a community administrator/);
  });

  it("shows a detached repository of an unbound namespace as detached", async () => {
    const detached = {
      ...WIDGETS,
      id: "repo_old",
      namespace: "ns_gone",
      resource: "github.com/oldorg/tool",
      state: "detached",
    };
    mockFetch(gitNsRoutes({ repos: [detached] }));
    mount(detached.resource);

    expect(await screen.findByText("Detached")).toBeTruthy();
    expect(screen.getByText(/its namespace was unbound/)).toBeTruthy();
    expect(screen.queryByText(/records no repository/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Archive" })).toBeNull();
  });

  it("does not say nothing is published while the rights are unreadable", async () => {
    mockFetch([
      { path: "/v1/git-ns/rights", status: 403, body: { error: "super admin required" } },
      ...gitNsRoutes(),
    ]);
    mount(WIDGETS.resource);

    const reg = await screen.findByRole("region", { name: "Published to the Trust Registry" });
    await within(reg).findByText(/could not be read/);
    expect(reg.textContent).not.toMatch(/Nothing on this repository is published/);
    expect(reg.textContent).toMatch(/only a community administrator/);
  });

  it("revokes with an optional reason, bounded like a grant's", async () => {
    mockFetch(gitNsRoutes());
    mount(WIDGETS.resource);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke Maintainer from Hana Sato" }));
    const form = await screen.findByRole("dialog", { name: /Revoke maintainer on acme\/widgets/ });
    expect(form.textContent).toContain(HANA);
    fireEvent.change(within(form).getByLabelText("Reason"), { target: { value: "x".repeat(1025) } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the revocation" }));
    expect(within(form).getByRole("alert").textContent).toMatch(/At most 1024/);
    fireEvent.change(within(form).getByLabelText("Reason"), { target: { value: "left the team" } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the revocation" }));
    const sign = await screen.findByRole("dialog", { name: /Revoke maintainer on acme\/widgets/ });
    expect(within(sign).getByLabelText("Command").textContent).toContain("--reason='left the team'");
  });

  it("says when the VTC records no such repository", async () => {
    mockFetch(gitNsRoutes());
    mount("github.com/acme/nope");

    expect(await screen.findByText(/records no repository at/)).toBeTruthy();
  });

  it("shows a read failure as an error, not an empty repository", async () => {
    mockFetch([
      { path: "/v1/git-ns/namespaces", body: { namespaces: [ACME] } },
      { path: "/v1/git-ns/repos", status: 403, body: { error: "not an admin" } },
      { path: "/v1/members", body: { items: [] } },
      { path: "/v1/acl", body: { entries: [], truncated: false } },
    ]);
    mount(WIDGETS.resource);

    expect(await screen.findByText(`${WIDGETS.resource} could not be read`)).toBeTruthy();
    expect(screen.getByText("not an admin")).toBeTruthy();
  });
});
