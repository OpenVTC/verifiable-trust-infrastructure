import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { postSignedTrustTask, signingAvailable } from "@/lib/api";

import { Repos } from "@/plugins/repos";
import { mockFetch, renderWithProviders } from "@/test/render";

import { ACME, gitNsRoutes } from "./fixtures.test-data";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  signingAvailable: vi.fn(async () => false),
  postSignedTrustTask: vi.fn(),
}));

beforeEach(() => {
  vi.mocked(signingAvailable).mockResolvedValue(false);
  vi.mocked(postSignedTrustTask).mockReset();
});

const mount = (route = "/repos/bind") =>
  renderWithProviders(<Repos />, { route, path: "/repos/*" });

const stepState = (name: RegExp) => {
  const li = within(screen.getByRole("list", { name: "Binding steps" }))
    .getAllByRole("listitem")
    .find((l) => name.test(l.textContent ?? ""))!;
  return li.getAttribute("aria-current") === "step" ? "current" : li.className;
};

describe("Bind namespace", () => {
  it("leads with the public-visibility consequence, the policy and the step-up", async () => {
    mockFetch(gitNsRoutes());
    mount();

    expect(await screen.findByText("Rights in this namespace are public")).toBeTruthy();
    expect(
      (await screen.findByRole("link", { name: "Edit policy (v3 active)" })).getAttribute("href"),
    ).toBe("/ceremonies?purpose=gitNamespace");
    expect(screen.getByText("Binding makes you its admin")).toBeTruthy();
    expect(stepState(/Register your GitHub App/)).toBe("current");
  });

  it("validates the forge and owner the way the spec does", async () => {
    mockFetch(gitNsRoutes());
    mount();

    fireEvent.change(await screen.findByLabelText("Forge"), {
      target: { value: "https://github.com" },
    });
    fireEvent.change(screen.getByLabelText("Organisation or account"), {
      target: { value: "Acme" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Build the binding" }));
    const alerts = screen.getAllByRole("alert").map((a) => a.textContent);
    expect(alerts).toEqual([
      "The host only — no https://.",
      "Forges compare names case-insensitively, so they are sent lowercase.",
    ]);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("builds the destructive bind, then waits for the VTC to record it", async () => {
    const requests = mockFetch(gitNsRoutes({ namespaces: [] }));
    mount();

    fireEvent.change(await screen.findByLabelText("Organisation or account"), {
      target: { value: "acme" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Build the binding" }));

    const sign = await screen.findByRole("dialog", { name: "Bind github.com/acme" });
    expect(sign.textContent).toMatch(/Destructive — step-up and confirmation/);
    expect(within(sign).getByLabelText("Command").textContent).toBe(
      "cnm git namespace bind --forge=github.com --owner=acme --mode=bridge",
    );
    expect(sign.textContent).toMatch(/the bind answers with where to go on the forge/);
    fireEvent.click(within(sign).getByRole("button", { name: "I have sent it — refresh" }));

    expect(await screen.findByText("Waiting for the VTC to record github.com/acme")).toBeTruthy();
    expect(stepState(/Install on acme/)).toBe("current");
    expect(requests.some((r) => r.method !== "GET")).toBe(false);
    expect(postSignedTrustTask).not.toHaveBeenCalled();
  });

  it("signed from this browser, links the forge URL the bind answered with", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    vi.mocked(postSignedTrustTask).mockResolvedValue({
      namespace: { id: "ns_acme", state: "pending" },
      next: { url: "https://github.com/apps/acme-builders-vgi/installations/new?state=n1" },
    });
    mockFetch(
      gitNsRoutes({ namespaces: [{ ...ACME, state: "pending", kind: null, boundAt: null }] }),
    );
    mount();

    fireEvent.change(await screen.findByLabelText("Organisation or account"), {
      target: { value: "acme" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Build the binding" }));
    const sign = await screen.findByRole("dialog", { name: "Bind github.com/acme" });
    const send = await within(sign).findByRole("button", { name: "Sign and send" });
    fireEvent.click(within(sign).getByLabelText(/destructive and want to sign it/));
    fireEvent.click(send);

    await waitFor(() =>
      expect(postSignedTrustTask).toHaveBeenCalledWith(
        "https://trusttasks.org/spec/git-ns/namespace/bind/0.1",
        { forge: "github.com", owner: "acme", mode: "bridge" },
      ),
    );
    const link = await screen.findByRole("link", { name: "Continue on github.com" });
    expect(link.getAttribute("href")).toBe(
      "https://github.com/apps/acme-builders-vgi/installations/new?state=n1",
    );
    expect(stepState(/Install on acme/)).toBe("current");
  });

  it("closing or escaping the dialog returns to the form without watching", async () => {
    mockFetch(gitNsRoutes({ namespaces: [] }));
    mount();

    fireEvent.change(await screen.findByLabelText("Organisation or account"), {
      target: { value: "acme" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Build the binding" }));
    await screen.findByRole("dialog", { name: "Bind github.com/acme" });
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.queryByText(/Waiting for the VTC/)).toBeNull();
    expect((screen.getByLabelText("Organisation or account") as HTMLInputElement).value).toBe("acme");

    fireEvent.click(screen.getByRole("button", { name: "Build the binding" }));
    const sign = await screen.findByRole("dialog", { name: "Bind github.com/acme" });
    fireEvent.click(within(sign).getByRole("button", { name: "Close" }));
    expect(screen.queryByText(/Waiting for the VTC/)).toBeNull();
    expect(stepState(/Register your GitHub App/)).toBe("current");
  });

  it("a refused signed bind stays on the dialog and does not start watching", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    vi.mocked(postSignedTrustTask).mockRejectedValue({ status: 409, message: "alreadyBound" });
    mockFetch(gitNsRoutes({ namespaces: [] }));
    mount();

    fireEvent.change(await screen.findByLabelText("Organisation or account"), {
      target: { value: "acme" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Build the binding" }));
    const sign = await screen.findByRole("dialog", { name: "Bind github.com/acme" });
    fireEvent.click(await within(sign).findByLabelText(/destructive and want to sign it/));
    fireEvent.click(within(sign).getByRole("button", { name: "Sign and send" }));
    await within(sign).findByText(/alreadyBound/);
    expect(postSignedTrustTask).toHaveBeenCalledTimes(1);
    fireEvent.click(within(sign).getByRole("button", { name: "Close" }));
    expect(screen.queryByText(/Waiting for the VTC/)).toBeNull();
  });

  it("goes back to the form from the waiting step", async () => {
    mockFetch(gitNsRoutes({ namespaces: [] }));
    mount("/repos/bind?forge=github.com&owner=acme&mode=bridge&sent=1");

    await screen.findByText("Waiting for the VTC to record github.com/acme");
    fireEvent.click(screen.getByRole("button", { name: "Back to the form" }));
    expect(await screen.findByLabelText("Organisation or account")).toBeTruthy();
    expect(stepState(/Register your GitHub App/)).toBe("current");
  });

  it("does not call a URL off the forge a way to continue on it", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    vi.mocked(postSignedTrustTask).mockResolvedValue({
      namespace: {},
      next: { url: "https://github.com.evil.example/install" },
    });
    mockFetch(
      gitNsRoutes({ namespaces: [{ ...ACME, state: "pending", kind: null, boundAt: null }] }),
    );
    mount();

    fireEvent.change(await screen.findByLabelText("Organisation or account"), {
      target: { value: "acme" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Build the binding" }));
    const sign = await screen.findByRole("dialog", { name: "Bind github.com/acme" });
    fireEvent.click(await within(sign).findByLabelText(/destructive and want to sign it/));
    fireEvent.click(within(sign).getByRole("button", { name: "Sign and send" }));

    expect(await screen.findByText(/is not on github.com/)).toBeTruthy();
    expect(screen.queryByRole("link", { name: /Continue on/ })).toBeNull();
  });

  it("a manual bind skips the App steps", async () => {
    mockFetch(gitNsRoutes({ namespaces: [] }));
    mount();

    fireEvent.change(await screen.findByLabelText("Organisation or account"), {
      target: { value: "acme" },
    });
    fireEvent.click(screen.getByLabelText(/Manually/));
    fireEvent.click(screen.getByRole("button", { name: "Build the binding" }));
    const sign = await screen.findByRole("dialog", { name: "Bind github.com/acme" });
    expect(within(sign).getByLabelText("Command").textContent).toContain("--mode=manual");
    fireEvent.click(within(sign).getByRole("button", { name: "I have sent it — refresh" }));

    await screen.findByText("Waiting for the VTC to record github.com/acme");
    expect(stepState(/Register your GitHub App/)).toBe("skipped");
    expect(stepState(/Confirm binding/)).toBe("current");
  });

  it("shows a pending namespace as waiting on the install", async () => {
    mockFetch(gitNsRoutes({ namespaces: [{ ...ACME, state: "pending", kind: null, boundAt: null }] }));
    mount("/repos/bind?forge=github.com&owner=acme&mode=bridge&sent=1");

    expect(await screen.findByText("Pending: install the App on acme")).toBeTruthy();
    expect(stepState(/Install on acme/)).toBe("current");
  });

  it("confirms what the VTC recorded once bound, then offers the unmanaged repos to adopt", async () => {
    mockFetch(gitNsRoutes());
    mount("/repos/bind?forge=github.com&owner=acme&mode=bridge&sent=1");

    expect(await screen.findByText("Organization")).toBeTruthy();
    expect(stepState(/Confirm binding/)).toBe("current");
    expect(await screen.findByText("1 · unmanaged until adopted")).toBeTruthy();
    expect(
      await screen.findByText(/holds its service grant to re-sign Dependabot/),
    ).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Continue to adopt" }));
    expect(stepState(/Adopt existing repos/)).toBe("current");
    fireEvent.click(screen.getByRole("button", { name: "Adopt acme/sandbox" }));
    expect(await screen.findByRole("dialog", { name: "Adopt acme/sandbox" })).toBeTruthy();
  });
});
