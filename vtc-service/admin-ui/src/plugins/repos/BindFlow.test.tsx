import { fireEvent, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Repos } from "@/plugins/repos";
import { mockFetch, renderWithProviders } from "@/test/render";

import { ACME, gitNsRoutes } from "./fixtures.test-data";

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
      "cnm git namespace bind --forge github.com --owner acme --mode bridge",
    );
    expect(sign.textContent).toMatch(/cnm prints the URL the bridge returned/);
    fireEvent.click(within(sign).getByRole("button", { name: "Close" }));

    expect(await screen.findByText("Waiting for the VTC to record github.com/acme")).toBeTruthy();
    expect(stepState(/Install on acme/)).toBe("current");
    expect(requests.some((r) => r.method !== "GET")).toBe(false);
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
    expect(within(sign).getByLabelText("Command").textContent).toContain("--mode manual");
    fireEvent.click(within(sign).getByRole("button", { name: "Close" }));

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
