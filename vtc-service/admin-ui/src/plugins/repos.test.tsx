import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { postSignedTrustTask, signingAvailable, type WhoamiResponse } from "@/lib/api";

import { Repos } from "@/plugins/repos";
import {
  ACME,
  BOB,
  gitNsRoutes,
  PERSONAL,
  PRIYA,
  SANDBOX,
  WIDGETS,
} from "@/plugins/repos/fixtures.test-data";
import { mockFetch, renderWithProviders } from "@/test/render";

// The browser's signing door, controlled per test: jsdom has no IndexedDB to
// hold a console key, and whether the key exists is exactly what these tests
// vary. Everything else in `@/lib/api` is the real module over mocked fetch.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  signingAvailable: vi.fn(async () => false),
  postSignedTrustTask: vi.fn(),
}));

beforeEach(() => {
  vi.mocked(signingAvailable).mockResolvedValue(false);
  vi.mocked(postSignedTrustTask).mockReset();
});
const mount = (route = "/repos", whoami?: WhoamiResponse) =>
  renderWithProviders(<Repos />, { route, path: "/repos/*", whoami });

const signedInAs = (roles: string[], scopes: string[]): WhoamiResponse => ({
  session: {
    id: "sess_1",
    subject: "did:webvh:QmAdmin:admin.example",
    issuedAt: "2026-09-01T00:00:00Z",
    expiresAt: "2026-09-01T00:05:00Z",
  },
  roles,
  scopes,
});
/** The admin role with no context restriction: the community administrator
 *  that reseat is signed as. */
const COMMUNITY_ADMIN = signedInAs(["admin"], []);
const CONTEXT_ADMIN = signedInAs(["admin"], ["ctx-a"]);

describe("Repos plugin — overview", () => {
  it("reads the console projections with no Trust-Task header, and sends nothing", async () => {
    const requests = mockFetch(gitNsRoutes());
    mount();

    expect(await screen.findByRole("link", { name: "github.com/acme" })).toBeTruthy();
    await screen.findByText("acme/widgets");
    const gitNs = requests.filter((r) => r.url.startsWith("/v1/git-ns/"));
    expect(gitNs.length).toBeGreaterThan(0);
    // Only `/v1/git-ns/view` answers a specification's read; the projections
    // are mounted with no binding, and sending one would claim a contract.
    for (const r of gitNs) {
      expect(r.method).toBe("GET");
      expect(r.headers.get("Trust-Task")).toBeNull();
    }
    expect(requests.every((r) => r.method === "GET")).toBe(true);
  });

  it("shows each namespace card with its kind, mode, counts and policy", async () => {
    mockFetch(gitNsRoutes());
    mount();

    const acme = await screen.findByRole("article", { name: "github.com/acme" });
    expect(within(acme).getByText("Organization")).toBeTruthy();
    expect(within(acme).getByText("App installed")).toBeTruthy();
    expect(acme.textContent).toMatch(/3\s*managed repos/);
    expect(acme.textContent).toMatch(/1\s*unmanaged/);
    expect(acme.textContent).toMatch(/1\s*repo creator/);
    expect(
      (await within(acme).findByRole("link", { name: "git namespace policy v3" })).getAttribute("href"),
    ).toBe("/ceremonies?purpose=gitNamespace");
    // The bridge's service grant, read-only.
    expect(acme.textContent).toMatch(/service grant from the community/);
    expect(acme.textContent).toMatch(/never ones\s+that touch workflows/);
  });

  it("tells a personal account that creation is the holder's alone, and how to move", async () => {
    mockFetch(gitNsRoutes());
    mount();

    const personal = await screen.findByRole("article", { name: "github.com/glenn-g" });
    expect(within(personal).getByText("Personal account")).toBeTruthy();
    expect(within(personal).getByText("Manual mode")).toBeTruthy();
    expect(within(personal).getByText("account holder only")).toBeTruthy();
    expect(within(personal).getByText("Move to an organisation")).toBeTruthy();
  });

  it("warns on a lost installation and a headless namespace", async () => {
    mockFetch(
      gitNsRoutes({ namespaces: [{ ...ACME, installationRemoved: true, headless: true }] }),
    );
    mount();

    expect(await screen.findByText("The App lost access")).toBeTruthy();
    expect(screen.getByText("No namespace admin")).toBeTruthy();
    expect(screen.getByText("App uninstalled")).toBeTruthy();
  });

  it("shows the bridge's role map, flags an unknown one, and offers a namespace re-projection", async () => {
    mockFetch(gitNsRoutes({ namespaces: [ACME, PERSONAL] }));
    const first = mount();
    expect((await screen.findByLabelText("Forge role map")).textContent).toMatch(/namespace admin no role/);
    expect(screen.queryByText("Role map unknown")).toBeNull();
    first.unmount();

    // Unreported: no map is shown or assumed, the default included.
    mockFetch(
      gitNsRoutes({ namespaces: [{ ...ACME, roleMap: undefined, roleMapSource: "unknown" }, PERSONAL] }),
    );
    mount();
    expect(await screen.findByText("Role map unknown")).toBeTruthy();
    expect(screen.queryByLabelText("Forge role map")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Re-project roles on github.com/acme" }));
    const sign = await screen.findByRole("dialog", { name: /Re-project roles on github\.com\/acme/ });
    expect(sign.textContent).toMatch(/owning some of its repositories is not enough/);
  });

  it("warns on missing App permissions and a pending upgrade, and shows the drift settings", async () => {
    mockFetch(
      gitNsRoutes({
        namespaces: [
          {
            ...ACME,
            roleDrift: "enforce",
            cascadeOnDeparture: true,
            forgeStatus: {
              appName: "acme-builders-vgi",
              installationId: "55120033",
              missingPermissions: ["organization_administration:write"],
              permissionUpgradePending: true,
              orgRulesets: false,
            },
          },
        ],
      }),
    );
    mount();

    const acme = await screen.findByRole("article", { name: "github.com/acme" });
    expect(within(acme).getByText("The App is missing a permission")).toBeTruthy();
    expect(acme.textContent).toMatch(/organization_administration:write/);
    expect(within(acme).getByText("Permission upgrade awaiting approval")).toBeTruthy();
    expect(within(acme).getByText("No org rulesets on this plan")).toBeTruthy();
    expect(acme.textContent).toMatch(/App acme-builders-vgi · installation #55120033/);
    expect(acme.textContent).toMatch(/roles\s*enforce/);
    expect(acme.textContent).toMatch(/revoked with them/);
  });

  it("claims nothing about App permissions the bridge has not reported", async () => {
    mockFetch(gitNsRoutes());
    mount();

    const acme = await screen.findByRole("article", { name: "github.com/acme" });
    expect(acme.textContent).not.toMatch(/permission/i);
    expect(acme.textContent).toMatch(/roles\s*report/);
  });

  it("claims nothing that rests on the rights while they cannot be read", async () => {
    mockFetch([
      { path: "/v1/git-ns/rights", status: 403, body: { error: "super admin required" } },
      ...gitNsRoutes(),
    ]);
    mount();

    const acme = await screen.findByRole("article", { name: "github.com/acme" });
    await waitFor(() => expect(acme.textContent).toMatch(/Repo creators: not readable/));
    expect(acme.textContent).not.toMatch(/\d+\s*repo creators?/);
    expect(acme.textContent).not.toMatch(/holds no service grant/);
    expect(acme.textContent).not.toMatch(/holds git\.commit\.sign/);
    expect(acme.textContent).toMatch(/only a community administrator/);
    expect(
      (await screen.findByText(/Rights could not be read/)).textContent,
    ).toMatch(/only a community administrator/);
  });

  it("lists detached repositories of an unbound namespace, not as never adopted", async () => {
    const orphanRecord = {
      ...WIDGETS,
      id: "repo_old",
      namespace: "ns_gone",
      resource: "github.com/oldorg/tool",
      state: "detached",
    };
    mockFetch(gitNsRoutes({ repos: [WIDGETS, orphanRecord] }));
    mount();

    const section = await screen.findByRole("region", { name: "Detached repositories" });
    expect(
      within(section).getByRole("link", { name: "github.com/oldorg/tool" }).getAttribute("href"),
    ).toBe(`/repos/repo/${encodeURIComponent("github.com/oldorg/tool")}`);
    const table = screen.getByRole("table");
    expect(within(table).queryByText("oldorg/tool")).toBeNull();
  });

  it("unbinds a namespace as a destructive task", async () => {
    mockFetch(gitNsRoutes());
    mount();

    fireEvent.click(await screen.findByRole("button", { name: "Unbind github.com/acme" }));
    const sign = await screen.findByRole("dialog", { name: "Unbind github.com/acme" });
    expect(sign.textContent).toMatch(/Destructive — step-up and confirmation/);
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      "cnm git namespace unbind ns_acme",
    );
    expect(postSignedTrustTask).not.toHaveBeenCalled();
  });

  it("offers reseat only on a headless namespace, and says it needs a community administrator", async () => {
    mockFetch(gitNsRoutes());
    mount("/repos", COMMUNITY_ADMIN);
    const acme = await screen.findByRole("article", { name: "github.com/acme" });
    expect(within(acme).queryByRole("button", { name: "Reseat github.com/acme" })).toBeNull();
    expect(acme.textContent).not.toMatch(/Needs a community administrator/);
  });

  it("shows the reseat action on a headless namespace card to a community administrator", async () => {
    mockFetch(gitNsRoutes({ namespaces: [{ ...ACME, headless: true, admins: [] }, PERSONAL] }));
    mount("/repos", COMMUNITY_ADMIN);
    const acme = await screen.findByRole("article", { name: "github.com/acme" });
    expect(within(acme).getByRole("button", { name: "Reseat github.com/acme" })).toBeTruthy();
    expect(acme.textContent).toMatch(/Needs a community administrator/);
    const personal = screen.getByRole("article", { name: "github.com/glenn-g" });
    expect(within(personal).queryByRole("button", { name: /Reseat/ })).toBeNull();
  });

  it.each([
    ["an admin limited to some contexts", CONTEXT_ADMIN],
    ["a viewer without a session probe", undefined],
  ])("does not offer reseat to %s, who can still unbind", async (_, whoami) => {
    mockFetch(gitNsRoutes({ namespaces: [{ ...ACME, headless: true, admins: [] }, PERSONAL] }));
    mount("/repos", whoami);
    const acme = await screen.findByRole("article", { name: "github.com/acme" });
    expect(within(acme).getByRole("button", { name: "Unbind github.com/acme" })).toBeTruthy();
    expect(within(acme).queryByRole("button", { name: /Reseat/ })).toBeNull();
    expect(acme.textContent).not.toMatch(/Needs a community administrator/);
  });

  it("reseats with a member and a required statement, handed over when this browser cannot sign", async () => {
    const requests = mockFetch(
      gitNsRoutes({ namespaces: [{ ...ACME, headless: true, admins: [] }] }),
    );
    mount("/repos", COMMUNITY_ADMIN);

    fireEvent.click(await screen.findByRole("button", { name: "Reseat github.com/acme" }));
    const form = await screen.findByRole("dialog", { name: "Reseat github.com/acme" });
    expect(form.textContent).toMatch(/Only a community administrator/);
    // Members only: git.ns.admin goes to no one else.
    await within(form).findByRole("option", { name: /Bob Mensah/ });
    expect(within(form).queryByRole("option", { name: /paste a DID/ })).toBeNull();
    fireEvent.change(within(form).getByLabelText("New namespace admin"), { target: { value: BOB } });

    // The statement is required.
    fireEvent.click(within(form).getByRole("button", { name: "Build the reseat" }));
    expect(within(form).getByLabelText("Statement").getAttribute("aria-invalid")).toBe("true");
    expect(form.textContent).toMatch(/Say why the namespace is headless/);

    fireEvent.change(within(form).getByLabelText("Statement"), {
      target: { value: "Alice left; Bob owns most repos" },
    });
    fireEvent.click(within(form).getByRole("button", { name: "Build the reseat" }));

    const sign = await screen.findByRole("dialog", { name: "Reseat github.com/acme" });
    const body = sign.querySelector(".gitns-parties")!;
    await waitFor(() => expect(body.textContent).toMatch(/Becomes namespace admin/));
    expect(body.textContent).toMatch(/Bob Mensah/);
    expect(body.textContent).toContain(BOB);
    expect(body.textContent).toContain("github.com/acme");
    expect(sign.textContent).toMatch(/Destructive — step-up and confirmation/);
    expect(sign.textContent).toMatch(/community-administrator capability/);
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      `cnm git reseat ns_acme --subject=${BOB} --statement='Alice left; Bob owns most repos'`,
    );
    expect(JSON.parse(within(sign).getByLabelText("Document").textContent!)).toEqual({
      type: "https://trusttasks.org/spec/git-ns/namespace/reseat/0.3",
      payload: { namespace: "ns_acme", subject: BOB, statement: "Alice left; Bob owns most repos" },
    });
    // No console key: nothing to sign with, so nothing is sent.
    await within(sign).findByRole("button", { name: "I have sent it — refresh" });
    expect(within(sign).queryByRole("button", { name: "Sign and send" })).toBeNull();
    expect(within(sign).queryByLabelText(/destructive and want to sign it/)).toBeNull();
    expect(postSignedTrustTask).not.toHaveBeenCalled();
    expect(requests.every((r) => r.method === "GET")).toBe(true);
  });

  it("does not build a reseat to the viewer themselves (separation of duties)", async () => {
    const requests = mockFetch(
      gitNsRoutes({ namespaces: [{ ...ACME, headless: true, admins: [] }] }),
    );
    // Bob is a member and a community administrator, reseating to himself.
    mount("/repos", { ...COMMUNITY_ADMIN, session: { ...COMMUNITY_ADMIN.session, subject: BOB } });

    fireEvent.click(await screen.findByRole("button", { name: "Reseat github.com/acme" }));
    const form = await screen.findByRole("dialog", { name: "Reseat github.com/acme" });
    await within(form).findByRole("option", { name: /Bob Mensah/ });
    fireEvent.change(within(form).getByLabelText("New namespace admin"), { target: { value: BOB } });
    fireEvent.change(within(form).getByLabelText("Statement"), { target: { value: "Alice left" } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the reseat" }));

    expect(form.textContent).toMatch(/cannot reseat a namespace to yourself/);
    expect(within(form).queryByLabelText("Document")).toBeNull();
    expect(postSignedTrustTask).not.toHaveBeenCalled();
    expect(requests.every((r) => r.method === "GET")).toBe(true);
  });

  it("makes a reseat be confirmed before this browser signs and sends it", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    vi.mocked(postSignedTrustTask).mockResolvedValue({ right: {} });
    mockFetch(gitNsRoutes({ namespaces: [{ ...ACME, headless: true, admins: [] }] }));
    mount("/repos", COMMUNITY_ADMIN);

    fireEvent.click(await screen.findByRole("button", { name: "Reseat github.com/acme" }));
    const form = await screen.findByRole("dialog", { name: "Reseat github.com/acme" });
    await within(form).findByRole("option", { name: /Bob Mensah/ });
    fireEvent.change(within(form).getByLabelText("New namespace admin"), { target: { value: BOB } });
    fireEvent.change(within(form).getByLabelText("Statement"), { target: { value: "Alice left" } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the reseat" }));

    const sign = await screen.findByRole("dialog", { name: "Reseat github.com/acme" });
    const send = await within(sign).findByRole("button", { name: "Sign and send" });
    expect((send as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(send);
    expect(postSignedTrustTask).not.toHaveBeenCalled();
    fireEvent.click(within(sign).getByLabelText(/destructive and want to sign it/));
    expect((send as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(send);
    await waitFor(() =>
      expect(postSignedTrustTask).toHaveBeenCalledWith(
        "https://trusttasks.org/spec/git-ns/namespace/reseat/0.3",
        { namespace: "ns_acme", subject: BOB, statement: "Alice left" },
      ),
    );
  });

  it("lists repositories with their bootstrap dots, sync state and the action each needs", async () => {
    mockFetch(gitNsRoutes());
    mount();

    const table = await screen.findByRole("table");
    const row = (name: string) => within(table).getByText(name).closest("tr")!;
    await within(table).findByText("acme/widgets");

    expect(within(row("acme/widgets")).getByText("In sync")).toBeTruthy();
    expect(within(row("acme/widgets")).getByRole("img", { name: "All four in place" })).toBeTruthy();
    expect(within(row("acme/docs")).getByText("Drift · 1 item")).toBeTruthy();
    expect(
      within(row("acme/docs")).getByRole("link", { name: "Resolve acme/docs" }).getAttribute("href"),
    ).toBe(`/repos/repo/${encodeURIComponent("github.com/acme/docs")}#drift`);
    expect(within(row("acme/legacy-cli")).getByText("Orphaned · reassigned to admins")).toBeTruthy();
    expect(
      within(row("acme/legacy-cli")).getByRole("img", {
        name: "Workflow, Keyring, Variables in place; required check missing",
      }),
    ).toBeTruthy();
    expect(within(row("acme/sandbox")).getByText("Unmanaged")).toBeTruthy();
    expect(within(row("acme/sandbox")).getByRole("img", { name: "Not bootstrapped" })).toBeTruthy();
  });

  it("adopts an unmanaged repository by building the signed task — and sends nothing", async () => {
    const requests = mockFetch(gitNsRoutes());
    mount();

    fireEvent.click(await screen.findByRole("button", { name: "Adopt acme/sandbox" }));
    const form = await screen.findByRole("dialog", { name: "Adopt acme/sandbox" });
    fireEvent.click(within(form).getByRole("button", { name: "Build the adoption" }));
    expect(within(form).getByRole("alert").textContent).toMatch(/Name the DID/);

    await within(form).findByRole("option", { name: /Bob Mensah/ });
    fireEvent.change(within(form).getByLabelText("First owner"), { target: { value: BOB } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the adoption" }));

    const sign = await screen.findByRole("dialog", { name: "Adopt acme/sandbox" });
    expect(within(sign).getByText(/Elevated — step-up/)).toBeTruthy();
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      `cnm git adopt ${SANDBOX.resource} --owner=${BOB}`,
    );
    // Who and what, in the body, named and in full — not only in the command.
    expect(sign.querySelector(".gitns-parties")!.textContent).toMatch(
      new RegExp(`Resource${SANDBOX.resource.replace(/\./g, "\\.")}First ownerBob Mensah${BOB}`),
    );
    expect(requests.some((r) => r.method !== "GET")).toBe(false);
    expect(postSignedTrustTask).not.toHaveBeenCalled();
  });

  it("signs and sends from this browser when it holds a console key", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    vi.mocked(postSignedTrustTask).mockResolvedValue({ repo: {} });
    mockFetch(gitNsRoutes());
    mount();

    fireEvent.click(await screen.findByRole("button", { name: "Adopt acme/sandbox" }));
    const form = await screen.findByRole("dialog", { name: "Adopt acme/sandbox" });
    await within(form).findByRole("option", { name: /Bob Mensah/ });
    fireEvent.change(within(form).getByLabelText("First owner"), { target: { value: BOB } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the adoption" }));

    const sign = await screen.findByRole("dialog", { name: "Adopt acme/sandbox" });
    fireEvent.click(await within(sign).findByRole("button", { name: "Sign and send" }));
    await waitFor(() =>
      expect(postSignedTrustTask).toHaveBeenCalledWith(
        "https://trusttasks.org/spec/git-ns/repo/adopt/0.1",
        { resource: SANDBOX.resource, owners: [BOB] },
      ),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("shows the VTC's refusal of a signed task in the dialog", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    vi.mocked(postSignedTrustTask).mockRejectedValue({
      status: 403,
      message: "git-ns:escalation: the signer holds no right here",
    });
    mockFetch(gitNsRoutes());
    mount();

    fireEvent.click(await screen.findByRole("button", { name: "Assign an owner to acme/legacy-cli" }));
    const form = await screen.findByRole("dialog", { name: "Assign an owner to acme/legacy-cli" });
    await within(form).findByRole("option", { name: /Bob Mensah/ });
    fireEvent.change(within(form).getByLabelText("Person"), { target: { value: BOB } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the grant" }));
    const sign = await screen.findByRole("dialog", { name: /Grant owner on acme\/legacy-cli/ });
    fireEvent.click(await within(sign).findByRole("button", { name: "Sign and send" }));

    expect((await within(sign).findByRole("alert")).textContent).toMatch(
      /refused it.*git-ns:escalation/,
    );
    // Refused is final: never retried, from here or over any other door.
    expect(postSignedTrustTask).toHaveBeenCalledTimes(1);
    expect(within(sign).getByRole("button", { name: "Sign and send" })).toBeTruthy();
  });

  it("makes a destructive task be confirmed before it is signed", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    vi.mocked(postSignedTrustTask).mockResolvedValue({});
    mockFetch(gitNsRoutes());
    mount();

    const card = await screen.findByRole("region", { name: "Namespace rights in acme" });
    fireEvent.click(within(card).getAllByRole("button", { name: "Grant" })[0]!);
    const form = await screen.findByRole("dialog", { name: "Grant git.ns.admin on github.com/acme" });
    await within(form).findByRole("option", { name: /Bob Mensah/ });
    fireEvent.change(within(form).getByLabelText("Person"), { target: { value: BOB } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the grant" }));

    const sign = await screen.findByRole("dialog", { name: /Grant namespace admin/ });
    const send = await within(sign).findByRole("button", { name: "Sign and send" });
    expect((send as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(sign).getByLabelText(/destructive and want to sign it/));
    expect((send as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(send);
    await waitFor(() => expect(postSignedTrustTask).toHaveBeenCalledTimes(1));
  });

  it("creates a repository, and on a personal account shows the holder's steps", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    vi.mocked(postSignedTrustTask).mockResolvedValue({
      repo: {},
      manualSteps: ["gh repo create glenn-g/tool --public", "vgi repo init"],
    });
    mockFetch(gitNsRoutes());
    mount("/repos?namespace=ns_glenn");

    await screen.findByText("github.com/glenn-g · repositories");
    fireEvent.click(screen.getByRole("button", { name: "New repo" }));
    const form = await screen.findByRole("dialog", { name: "New repository in github.com/glenn-g" });
    expect(form.textContent).toMatch(/no bot can create a repository/);
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "Tool" } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the repository" }));
    expect(within(form).getByRole("alert").textContent).toMatch(/lowercase/);
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "tool" } });
    fireEvent.click(within(form).getByLabelText("Private"));
    fireEvent.click(within(form).getByRole("button", { name: "Build the repository" }));

    const sign = await screen.findByRole("dialog", { name: "Create glenn-g/tool" });
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      "cnm git create --namespace=ns_glenn tool --visibility=private",
    );
    fireEvent.click(await within(sign).findByRole("button", { name: "Sign and send" }));
    expect(await within(sign).findByText("gh repo create glenn-g/tool --public")).toBeTruthy();
    expect(postSignedTrustTask).toHaveBeenCalledWith(
      "https://trusttasks.org/spec/git-ns/repo/create/0.1",
      { namespace: "ns_glenn", name: "tool", visibility: "private" },
    );
  });

  it("points a browser that cannot sign at enabling it", async () => {
    mockFetch(gitNsRoutes());
    mount();

    fireEvent.click(await screen.findByRole("button", { name: "Adopt acme/sandbox" }));
    const form = await screen.findByRole("dialog", { name: "Adopt acme/sandbox" });
    await within(form).findByRole("option", { name: /Bob Mensah/ });
    fireEvent.change(within(form).getByLabelText("First owner"), { target: { value: BOB } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the adoption" }));
    const sign = await screen.findByRole("dialog", { name: "Adopt acme/sandbox" });
    expect(
      (await within(sign).findByRole("link", { name: "enable signing in this browser" })).getAttribute("href"),
    ).toBe("/console-keys");
    expect(within(sign).queryByRole("button", { name: "Sign and send" })).toBeNull();
  });

  it("assigns an owner to an orphaned repository as an elevated own grant", async () => {
    mockFetch(gitNsRoutes());
    mount();

    fireEvent.click(await screen.findByRole("button", { name: "Assign an owner to acme/legacy-cli" }));
    const form = await screen.findByRole("dialog", { name: "Assign an owner to acme/legacy-cli" });
    expect(form.textContent).toMatch(/Owner/);
    await within(form).findByRole("option", { name: /Bob Mensah/ });
    fireEvent.change(within(form).getByLabelText("Person"), { target: { value: BOB } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the grant" }));

    const sign = await screen.findByRole("dialog", { name: /Grant owner on acme\/legacy-cli/ });
    expect(within(sign).getByLabelText("Command").textContent).toContain(
      "--right=git.repo.own --resource=github.com/acme/legacy-cli",
    );
  });

  it("grants namespace admin to members only, as a destructive task", async () => {
    mockFetch(gitNsRoutes());
    mount();

    const card = await screen.findByRole("region", { name: "Namespace rights in acme" });
    fireEvent.click(within(card).getAllByRole("button", { name: "Grant" })[0]!);
    const form = await screen.findByRole("dialog", { name: "Grant git.ns.admin on github.com/acme" });
    // No paste-a-DID option: namespace rights go to current members only.
    await within(form).findByRole("option", { name: /Bob Mensah/ });
    expect(within(form).queryByRole("option", { name: /paste a DID/ })).toBeNull();
    fireEvent.change(within(form).getByLabelText("Person"), { target: { value: BOB } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the grant" }));

    const sign = await screen.findByRole("dialog", { name: /Grant namespace admin/ });
    expect(within(sign).getByText(/Destructive — step-up and confirmation/)).toBeTruthy();
    expect(within(sign).getByText(/elevated_requires_admin/)).toBeTruthy();
  });

  it("counts grants issued by departed members and links to the review", async () => {
    mockFetch(gitNsRoutes());
    mount();

    const card = await screen.findByRole("region", { name: "Issued by departed members" });
    const link = await within(card).findByRole("link", { name: "Review 1 grant" });
    expect(link.getAttribute("href")).toBe("/repos/departed");
  });

  it("says a failed read is a failure to ask, not an empty community", async () => {
    mockFetch([{ path: "/v1/git-ns/namespaces", status: 500, body: { error: "store unavailable" } }]);
    mount();

    expect(await screen.findByText("Namespaces could not be read")).toBeTruthy();
    expect(screen.getByText(/store unavailable/).textContent).toMatch(/not a community/);
  });

  it("offers binding when nothing is bound", async () => {
    mockFetch(gitNsRoutes({ namespaces: [], repos: [], rights: [] }));
    mount();

    expect(await screen.findByText("No namespace bound")).toBeTruthy();
    expect(
      screen.getAllByRole("link", { name: /Bind namespace/ })[0]!.getAttribute("href"),
    ).toBe("/repos/bind");
  });
});

describe("Repos plugin — issued by departed members", () => {
  it("lists each departed granter's grants and revokes one as a signed task", async () => {
    const requests = mockFetch(gitNsRoutes());
    mount("/repos/departed");

    const section = await screen.findByRole("region", { name: /Grants issued by/ });
    expect(section.textContent).toMatch(/1\s*grant/);
    expect(within(section).getByRole("link", { name: "acme/widgets" }).getAttribute("href")).toBe(
      `/repos/repo/${encodeURIComponent(WIDGETS.resource)}`,
    );
    fireEvent.click(within(section).getByRole("button", { name: /^Revoke Committer on acme\/widgets/ }));
    const form = await screen.findByRole("dialog", { name: /Revoke committer on acme\/widgets/ });
    fireEvent.click(within(form).getByRole("button", { name: "Build the revocation" }));

    const sign = await screen.findByRole("dialog", { name: /Revoke committer on acme\/widgets/ });
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      `cnm git revoke --subject=${PRIYA} --right=git.commit.sign --resource=${WIDGETS.resource} --reason='Issued by a departed member'`,
    );
    expect(sign.textContent).toMatch(/Consent class: Normal/);
    expect(sign.querySelector(".gitns-parties")!.textContent).toContain(PRIYA);
    expect(requests.every((r) => r.method === "GET")).toBe(true);
    expect(postSignedTrustTask).not.toHaveBeenCalled();
  });
});
