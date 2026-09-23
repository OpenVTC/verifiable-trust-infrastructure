import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Repos } from "@/plugins/repos";
import {
  ACME,
  BOB,
  gitNsRoutes,
  GUS,
  PRIYA,
  SANDBOX,
  WIDGETS,
} from "@/plugins/repos/fixtures.test-data";
import { mockFetch, renderWithProviders } from "@/test/render";

const VIEW = "https://trusttasks.org/spec/git-ns/view/0.1";
const mount = (route = "/repos") =>
  renderWithProviders(<Repos />, { route, path: "/repos/*" });

describe("Repos plugin — overview", () => {
  it("reads every git-ns route under git-ns/view and sends nothing else", async () => {
    const requests = mockFetch(gitNsRoutes());
    mount();

    expect(await screen.findByRole("link", { name: "github.com/acme" })).toBeTruthy();
    await screen.findByText("acme/widgets");
    const gitNs = requests.filter((r) => r.url.startsWith("/v1/git-ns/"));
    expect(gitNs.length).toBeGreaterThan(0);
    for (const r of gitNs) {
      expect(r.method).toBe("GET");
      expect(r.headers.get("Trust-Task")).toBe(VIEW);
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
      `cnm git adopt ${SANDBOX.resource} --owner ${BOB}`,
    );
    expect(requests.some((r) => r.method !== "GET")).toBe(false);
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
      "--right git.repo.own --resource github.com/acme/legacy-cli",
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

    const sign = await screen.findByRole("dialog", { name: /Revoke committer on acme\/widgets/ });
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      `cnm git revoke --subject ${PRIYA} --right git.commit.sign --resource ${WIDGETS.resource} --reason 'Issued by a departed member'`,
    );
    expect(sign.textContent).toMatch(/Consent class: Normal/);
    await waitFor(() => expect(requests.some((r) => r.url.includes(GUS))).toBe(false));
  });
});
