// Break-glass in the console: the banner every administrator sees, the list
// with its Ratify / Revoke decisions, the flag next to a right, the grant form
// that refuses a self-grant and offers the glass instead, and the passkey
// step-up the VTC asks for before it records one.

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  postSignedDocument,
  postSignedTrustTask,
  signingAvailable,
  type WhoamiResponse,
} from "@/lib/api";
import { answerStepUp } from "@/lib/bound-step-up";
import { BreakGlassBanner } from "@/components/BreakGlassBanner";
import { Repos } from "@/plugins/repos";
import { mockFetch, renderWithProviders } from "@/test/render";

import {
  ALICE,
  ALICE_BREAK_GLASS,
  BOB,
  DOCS,
  gitNsRoutes,
  HANA,
  RIGHTS,
  rightRow,
} from "./fixtures.test-data";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  signingAvailable: vi.fn(async () => false),
  postSignedTrustTask: vi.fn(),
  postSignedDocument: vi.fn(),
}));
vi.mock("@/lib/bound-step-up", async (original) => ({
  ...(await original<typeof import("@/lib/bound-step-up")>()),
  answerStepUp: vi.fn(),
}));

beforeEach(() => {
  vi.mocked(signingAvailable).mockResolvedValue(false);
  vi.mocked(postSignedTrustTask).mockReset();
  vi.mocked(postSignedDocument).mockReset();
  vi.mocked(answerStepUp).mockReset();
});

const signedInAs = (subject: string, roles: string[] = ["admin"], scopes: string[] = []): WhoamiResponse => ({
  session: {
    id: "sess_1",
    subject,
    issuedAt: "2026-09-01T00:00:00Z",
    expiresAt: "2026-09-01T00:05:00Z",
  },
  roles,
  scopes,
});

const DOCS_BREAK_GLASS_RIGHT = rightRow({
  subject: ALICE,
  right: "git.repo.own",
  resource: DOCS.resource,
  grantedBy: ALICE,
  breakGlass: ALICE_BREAK_GLASS.breakGlass,
});

describe("break-glass banner", () => {
  it("shows every administrator what awaits a decision, and cannot be dismissed", async () => {
    mockFetch(gitNsRoutes({ breakGlass: [ALICE_BREAK_GLASS] }));
    renderWithProviders(<BreakGlassBanner />, { whoami: signedInAs(HANA) });
    const banner = await screen.findByRole("alert");
    expect(banner.textContent).toMatch(/1 break-glass grant awaits another administrator/);
    expect(banner.textContent).toMatch(/Alice Wong gave themselves git\.repo\.own on github\.com\/acme\/docs/);
    expect(banner.textContent).toMatch(/does not expire/);
    expect(within(banner).getByRole("link", { name: "Review break-glass grants" }).getAttribute("href")).toBe(
      "/repos/break-glass",
    );
    expect(within(banner).queryByRole("button")).toBeNull();
  });

  it("is absent when nothing awaits, and for a viewer the list is not for", async () => {
    mockFetch(gitNsRoutes({ breakGlass: [{ ...ALICE_BREAK_GLASS, state: "ratified" }] }));
    const { unmount } = renderWithProviders(<BreakGlassBanner />);
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalled());
    expect(screen.queryByRole("alert")).toBeNull();
    unmount();

    mockFetch(gitNsRoutes({ breakGlassStatus: 403 }));
    renderWithProviders(<BreakGlassBanner />);
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalled());
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("break-glass grants list", () => {
  const mount = (whoami: WhoamiResponse) =>
    renderWithProviders(<Repos />, { route: "/repos/break-glass", path: "/repos/*", whoami });

  it("never offers the holder Ratify, and says why, but lets them revoke", async () => {
    mockFetch(gitNsRoutes({ breakGlass: [ALICE_BREAK_GLASS] }));
    mount(signedInAs(ALICE));
    const table = await screen.findByRole("table", { name: "Break-glass grants awaiting a decision" });
    expect(table.textContent).toMatch(/CVE fix must ship tonight/);
    expect(within(table).queryByRole("button", { name: /^Ratify/ })).toBeNull();
    expect(table.textContent).toMatch(/ratified by someone else or not at all/);
    expect(within(table).getByLabelText("Command").textContent).toContain("cnm git ratify");
    expect(within(table).getByRole("button", { name: /^Revoke Owner on acme\/docs/ })).toBeTruthy();
  });

  it("lets another community administrator ratify it, with the justification in front of them", async () => {
    mockFetch(gitNsRoutes({ breakGlass: [ALICE_BREAK_GLASS] }));
    mount(signedInAs(HANA));
    fireEvent.click(await screen.findByRole("button", { name: /^Ratify Owner on acme\/docs/ }));
    const form = await screen.findByRole("dialog", { name: "Ratify owner on acme/docs" });
    expect(form.textContent).toMatch(/CVE fix must ship tonight/);
    fireEvent.change(within(form).getByLabelText("Statement"), { target: { value: "Confirmed with Bob" } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the ratification" }));
    const sign = await screen.findByRole("dialog", { name: "Ratify break-glass: owner on acme/docs" });
    const doc = JSON.parse(within(sign).getByLabelText("Document").textContent ?? "{}");
    expect(doc).toEqual({
      type: "https://trusttasks.org/spec/git-ns/right/ratify/0.1",
      payload: {
        subject: ALICE,
        right: "git.repo.own",
        resource: DOCS.resource,
        breakGlassAt: ALICE_BREAK_GLASS.breakGlass.at,
        statement: "Confirmed with Bob",
      },
    });
  });

  it("lists ratified ones as history, without decisions", async () => {
    mockFetch(
      gitNsRoutes({
        breakGlass: [
          {
            ...ALICE_BREAK_GLASS,
            state: "ratified",
            breakGlass: { ...ALICE_BREAK_GLASS.breakGlass, ratifiedBy: BOB, ratifiedAt: "2026-09-25T09:00:00Z" },
          },
        ],
      }),
    );
    mount(signedInAs(HANA));
    const table = await screen.findByRole("table", { name: "Ratified break-glass grants" });
    expect(table.textContent).toMatch(/Bob Mensah/);
    expect(within(table).queryByRole("button", { name: /^Ratify/ })).toBeNull();
    expect(screen.getByText(/None\. Every break-glass has been ratified or revoked/)).toBeTruthy();
  });
});

describe("the flag and the self-grant", () => {
  const mount = (resource: string, whoami: WhoamiResponse) =>
    renderWithProviders(<Repos />, {
      route: `/repos/repo/${encodeURIComponent(resource)}`,
      path: "/repos/*",
      whoami,
    });

  it("flags a self-granted right next to it, with its justification, and never as the last owner", async () => {
    mockFetch(gitNsRoutes({ rights: [...RIGHTS, DOCS_BREAK_GLASS_RIGHT] }));
    mount(DOCS.resource, signedInAs(HANA));
    const people = await screen.findByRole("region", { name: "People and rights" });
    const table = await within(people).findByRole("table");
    await within(table).findAllByText("Alice Wong");
    expect(within(table).getByText(/Break-glass · unratified/)).toBeTruthy();
    expect(table.textContent).toMatch(/Break-glass: “CVE fix must ship tonight/);
    // Bob is the only owner that counts toward the invariant; Alice's
    // unratified break-glass does not, so hers is revocable and his is not.
    const row = (name: string) =>
      within(table)
        .getAllByRole("row")
        .find((r) => r.querySelector("td")?.textContent?.includes(name))!;
    expect(row("Bob Mensah").textContent).toMatch(/Last owner/);
    expect(within(row("Alice Wong")).getByRole("button", { name: /Revoke Owner from Alice Wong/ })).toBeTruthy();
  });

  it("refuses to build an elevated self-grant and offers break-glass, which asks for a passkey and resends the same document", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    const signed = { id: "urn:uuid:doc-1", type: "x", payload: {} };
    const stepUpRequest = {
      subject: ALICE,
      challenge: "c2FtcGxlLWNoYWxsZW5nZS0xMjM0NQ",
      boundTo: "zBoundDigest",
      reason: "Break glass: git.repo.own on github.com/acme/docs",
      acceptableEvidence: ["webauthn"],
      webauthn: { challenge: "c2FtcGxlLWNoYWxsZW5nZS0xMjM0NQ" },
    };
    vi.mocked(postSignedTrustTask).mockRejectedValue({
      status: 403,
      code: "permissionDenied",
      message: "a passkey gesture bound to this operation is required",
      details: { stepUpRequest },
      document: signed,
    });
    vi.mocked(answerStepUp).mockResolvedValue({ status: "recorded", boundTo: "zBoundDigest" });
    vi.mocked(postSignedDocument).mockResolvedValue({ right: {} });
    mockFetch(gitNsRoutes());
    mount(DOCS.resource, signedInAs(ALICE));

    fireEvent.click(await screen.findByRole("button", { name: "Add person" }));
    const form = await screen.findByRole("dialog", { name: "Add a person to acme/docs" });
    await within(form).findByRole("option", { name: /Alice Wong/ });
    fireEvent.change(within(form).getByLabelText("Person"), { target: { value: ALICE } });
    fireEvent.change(within(form).getByLabelText("Right"), { target: { value: "git.repo.own" } });
    expect(form.textContent).toMatch(/You cannot grant yourself owner/);
    fireEvent.click(within(form).getByRole("button", { name: "Build the grant" }));
    expect(screen.queryByRole("dialog", { name: /^Grant owner/ })).toBeNull();

    fireEvent.click(within(form).getByRole("button", { name: "Break glass…" }));
    const bg = await screen.findByRole("dialog", { name: "Break glass: owner on acme/docs" });
    expect(bg.textContent).toMatch(/Takes effect immediately/);
    expect(bg.textContent).toMatch(/Never expires on its own/);
    expect(bg.textContent).toMatch(/Every community administrator and every namespace admin is notified now/);
    fireEvent.click(within(bg).getByRole("button", { name: "Build the break-glass" }));
    expect(within(bg).getByRole("alert").textContent).toMatch(/Say why/);
    fireEvent.change(within(bg).getByLabelText("Justification"), {
      target: { value: "Bob unreachable; fix must ship" },
    });
    fireEvent.click(within(bg).getByRole("button", { name: "Build the break-glass" }));

    const sign = await screen.findByRole("dialog", { name: "Break glass: owner on acme/docs" });
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      "cnm git break-glass --right=git.repo.own --resource=github.com/acme/docs --justification='Bob unreachable; fix must ship'",
    );
    fireEvent.click(await within(sign).findByRole("checkbox"));
    fireEvent.click(within(sign).getByRole("button", { name: "Sign and send" }));

    const confirm = await within(sign).findByRole("button", { name: "Confirm with passkey and send" });
    expect(sign.textContent).toMatch(/Confirm with your passkey/);
    expect(sign.textContent).toMatch(/zBoundDigest/);
    expect(within(sign).queryByText("The VTC refused it")).toBeNull();
    fireEvent.click(confirm);
    await waitFor(() => expect(postSignedDocument).toHaveBeenCalledWith(signed));
    expect(answerStepUp).toHaveBeenCalledWith(stepUpRequest);
    expect(postSignedTrustTask).toHaveBeenCalledTimes(1);
  });

  it("explains a selfGrantNotAllowed refusal", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    vi.mocked(postSignedTrustTask).mockRejectedValue({
      status: 403,
      code: "git-ns:selfGrantNotAllowed",
      message: "git.repo.own is an elevated right, and you cannot grant it to yourself",
    });
    mockFetch(gitNsRoutes());
    // Signed in as Bob, but granting to Alice — the console lets it through;
    // the VTC's refusal (as if resolved to Alice) is explained.
    mount(DOCS.resource, signedInAs(BOB));
    fireEvent.click(await screen.findByRole("button", { name: "Add person" }));
    const form = await screen.findByRole("dialog", { name: "Add a person to acme/docs" });
    await within(form).findByRole("option", { name: /Alice Wong/ });
    fireEvent.change(within(form).getByLabelText("Person"), { target: { value: ALICE } });
    fireEvent.click(within(form).getByRole("button", { name: "Build the grant" }));
    const sign = await screen.findByRole("dialog", { name: /^Grant/ });
    fireEvent.click(await within(sign).findByRole("button", { name: "Sign and send" }));
    const alert = await within(sign).findByRole("alert");
    expect(alert.textContent).toMatch(/Separation of duties/);
    expect(alert.textContent).toMatch(/break the glass/);
  });
});
