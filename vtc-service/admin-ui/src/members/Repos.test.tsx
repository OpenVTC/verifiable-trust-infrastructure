// The portal's Repos page: the member's own rights, what is shared on what they
// own, and linking a forge account — through the wallet, never the portal key.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({ viewRepos: vi.fn(), linkStatus: vi.fn() }));

vi.mock("./git-api", async (orig) => ({
  ...(await orig<typeof import("./git-api")>()),
  ...api,
}));

import { DirectoryError } from "./directory-api";
import { governedOf, holdingsOf, linkableForges, type MemberGitView } from "./git-api";
import { ReposPage } from "./Repos";

const ME = "did:key:z6MkMember";
const BOB = "did:key:z6MkBobBobBobBobBobBobBobBobBob";
const HOST = "did:webvh:QmHost:acme.example";
const ADMIN = "did:key:z6MkAdminAdminAdminAdminAdmin";

const repo = (resource: string, owners: string[]) => ({
  resource,
  owners,
  visibility: "private" as const,
  state: "active" as const,
  bootstrap: { state: "done" },
  sync: { state: "inSync", drift: [] },
});

const right = (subject: string, r: string, resource: string, extra = {}) => ({
  subject,
  right: r,
  resource,
  grantedBy: ADMIN,
  grantedAt: "2026-10-01T09:00:00Z",
  ...extra,
});

function view(over: Partial<MemberGitView> = {}): MemberGitView {
  return {
    namespaces: [
      { id: "ns_1", forge: "github.com", owner: "acme", mode: "bridge", state: "bound" },
      { id: "ns_2", forge: "codeberg.org", owner: "acme", mode: "manual", state: "bound" },
    ],
    repos: [repo("github.com/acme/widgets", [ME]), repo("github.com/acme/gadgets", [BOB])],
    rights: [
      right(ME, "git.repo.own", "github.com/acme/widgets"),
      right(ME, "git.commit.sign", "github.com/acme"),
      right(BOB, "git.repo.maintain", "github.com/acme/widgets", { reason: "release lead" }),
    ],
    accounts: [],
    ...over,
  } as MemberGitView;
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ReposPage hostDid={HOST} member={ME} />
    </QueryClientProvider>,
  );
}

type W = { vtaWallet?: unknown };

beforeEach(() => {
  api.viewRepos.mockReset();
  api.linkStatus.mockReset();
});
afterEach(() => {
  delete (window as unknown as W).vtaWallet;
});

describe("reading the view", () => {
  it("groups the member's own rights, strongest first", () => {
    const h = holdingsOf(view(), ME);
    expect(h.map((x) => [x.resource, x.rights.map((r) => r.right)])).toEqual([
      ["github.com/acme/widgets", ["git.repo.own"]],
      ["github.com/acme", ["git.commit.sign"]],
    ]);
  });

  it("lists what others hold on a repository the member owns, and only those", () => {
    const g = governedOf(view(), ME);
    expect(g.map((x) => x.repo.resource)).toEqual(["github.com/acme/widgets"]);
    expect(g[0]!.others.map((r) => r.subject)).toEqual([BOB]);
  });

  it("offers a link only on forges a bridge runs", () => {
    expect(linkableForges(view())).toEqual(["github.com"]);
  });
});

describe("the Repos page", () => {
  it("shows the member's access, what is shared on what they own, and every repository", async () => {
    api.viewRepos.mockResolvedValue(view());
    renderPage();
    expect(await screen.findByText("Owner")).toBeTruthy();
    expect(screen.getByText("Can sign commits")).toBeTruthy();
    expect(screen.getByText(/release lead/)).toBeTruthy();
    expect(screen.getAllByText("gadgets", { exact: false }).length).toBeGreaterThan(0);
  });

  it("says to sign in with the wallet when the portal key may not read", async () => {
    api.viewRepos.mockRejectedValue(new DirectoryError("permissionDenied", "no"));
    renderPage();
    expect(await screen.findByText(/Sign in with your wallet to see the repositories/)).toBeTruthy();
  });

  it("without a wallet git channel, shows the cnm command instead of a button", async () => {
    api.viewRepos.mockResolvedValue(view());
    renderPage();
    expect(await screen.findByText("cnm git link --forge github.com")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Link your/ })).toBeNull();
  });

  it("links through the wallet, then follows the link with the portal key", async () => {
    const linkAccount = vi.fn(async () => ({
      linkId: "lnk_4Tq9Xw2P",
      expiresAt: "2026-10-21T12:00:00Z",
    }));
    (window as unknown as W).vtaWallet = { git: { linkAccount, unlinkAccount: vi.fn() } };
    api.viewRepos.mockResolvedValue(view());
    api.linkStatus.mockResolvedValue({
      state: "linked",
      account: { forge: "github.com", id: "5550123", login: "member-dev" },
    });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /Link your github.com account/ }));
    await waitFor(() =>
      expect(linkAccount).toHaveBeenCalledWith({ hostDid: HOST, forge: "github.com", member: ME }),
    );
    await waitFor(() => expect(api.linkStatus).toHaveBeenCalledWith("lnk_4Tq9Xw2P"));
    expect(await screen.findByText(/Linked member-dev on github.com/)).toBeTruthy();
  });

  it("unlinks the account as last read, through the wallet", async () => {
    const unlinkAccount = vi.fn(async () => ({
      unlinked: { forge: "github.com", id: "5550123", login: "member-dev" },
      unlinkedAt: "2026-10-21T12:00:00Z",
    }));
    (window as unknown as W).vtaWallet = { git: { linkAccount: vi.fn(), unlinkAccount } };
    api.viewRepos.mockResolvedValue(
      view({
        accounts: [
          {
            account: { forge: "github.com", id: "5550123", login: "member-dev" },
            linkedAt: "2026-10-02T09:00:00Z",
          },
        ],
      }),
    );
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /Unlink/ }));
    await waitFor(() =>
      expect(unlinkAccount).toHaveBeenCalledWith({
        hostDid: HOST,
        forge: "github.com",
        accountId: "5550123",
        member: ME,
      }),
    );
    expect(await screen.findByText(/Unlinked member-dev on github.com/)).toBeTruthy();
  });
});
