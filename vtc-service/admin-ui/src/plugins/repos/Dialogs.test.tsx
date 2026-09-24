import { useState } from "react";
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { postSignedTrustTask, signingAvailable, SigningUnavailableError } from "@/lib/api";
import { mockFetch, renderWithProviders } from "@/test/render";

import { grantTask } from "./actions";
import { GrantDialog } from "./dialogs";
import { ALICE, BOB, gitNsRoutes, member, WIDGETS } from "./fixtures.test-data";
import { SignTaskDialog } from "./ui";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  signingAvailable: vi.fn(async () => false),
  postSignedTrustTask: vi.fn(),
}));

beforeEach(() => {
  vi.mocked(signingAvailable).mockResolvedValue(false);
  vi.mocked(postSignedTrustTask).mockReset();
});

/** A button that opens `dialog`, so focus has an opener to return to. */
function Opener({ dialog }: { dialog: (close: () => void) => React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Open
      </button>
      {open && dialog(() => setOpen(false))}
    </>
  );
}

const grant = () =>
  grantTask({ subject: BOB, right: "git.commit.sign", resource: WIDGETS.resource });

describe("Repos dialogs — keyboard and focus", () => {
  it("traps Tab inside a form dialog and returns focus to the opener on Escape", async () => {
    mockFetch(gitNsRoutes());
    renderWithProviders(
      <Opener
        dialog={(close) => (
          <GrantDialog
            resource={WIDGETS.resource}
            rights={["git.commit.sign"]}
            onClose={close}
            onBuilt={() => {}}
          />
        )}
      />,
    );
    const opener = screen.getByRole("button", { name: "Open" });
    opener.focus();
    fireEvent.click(opener);
    const dialog = await screen.findByRole("dialog");
    expect(dialog.contains(document.activeElement)).toBe(true);

    const submit = within(dialog).getByRole("button", { name: "Build the grant" });
    submit.focus();
    fireEvent.keyDown(window, { key: "Tab" });
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(document.activeElement).not.toBe(submit);

    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.activeElement).toBe(opener);
  });

  it("ties each field's error to it with aria-describedby", async () => {
    mockFetch(gitNsRoutes());
    renderWithProviders(
      <GrantDialog
        resource={WIDGETS.resource}
        rights={["git.commit.sign"]}
        onClose={() => {}}
        onBuilt={() => {}}
      />,
    );
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Expires after (days)"), {
      target: { value: "5000" },
    });
    fireEvent.change(within(dialog).getByLabelText("Reason"), {
      target: { value: "x".repeat(1025) },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Build the grant" }));

    for (const [label, message] of [
      ["Person", /Name the DID/],
      ["Expires after (days)", /At most 3650 days/],
      ["Reason", /At most 1024 characters/],
    ] as const) {
      const field = within(dialog).getByLabelText(label);
      expect(field.getAttribute("aria-invalid")).toBe("true");
      const ids = field.getAttribute("aria-describedby")!.split(" ");
      expect(ids.map((id) => document.getElementById(id)?.textContent).join(" ")).toMatch(message);
    }
  });

  it("cannot be dismissed while a signed send is in flight", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    let finish: (v: unknown) => void = () => {};
    vi.mocked(postSignedTrustTask).mockReturnValue(new Promise((r) => (finish = r)));
    const onClose = vi.fn();
    mockFetch(gitNsRoutes());
    renderWithProviders(<SignTaskDialog task={grant()} onClose={onClose} />);

    fireEvent.click(await screen.findByRole("button", { name: "Sign and send" }));
    await screen.findByRole("button", { name: "Sending…" });
    fireEvent.keyDown(window, { key: "Escape" });
    fireEvent.click(document.querySelector(".confirm-scrim")!);
    expect(onClose).not.toHaveBeenCalled();
    expect(
      (screen.getByRole("button", { name: "Close" }) as HTMLButtonElement).disabled,
    ).toBe(true);

    await act(async () => finish({}));
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
  });
});

describe("Repos dialogs — what is signed", () => {
  it("names who the change is about, in full, in the body", async () => {
    mockFetch(gitNsRoutes());
    renderWithProviders(<SignTaskDialog task={grant()} onClose={() => {}} />);

    const body = (await screen.findByRole("dialog")).querySelector(".gitns-parties")!;
    await waitFor(() => expect(body.textContent).toMatch(/Bob Mensah/));
    expect(body.textContent).toContain(BOB);
    expect(body.textContent).toContain(WIDGETS.resource);
    // Visible without opening the terminal hand-over.
    expect(body.closest("details")).toBeNull();
  });

  it("says when this browser can no longer sign, and offers the terminal instead", async () => {
    vi.mocked(signingAvailable).mockResolvedValue(true);
    vi.mocked(postSignedTrustTask).mockRejectedValue(new SigningUnavailableError("no-key"));
    mockFetch(gitNsRoutes());
    renderWithProviders(<SignTaskDialog task={grant()} onClose={() => {}} />);

    fireEvent.click(await screen.findByRole("button", { name: "Sign and send" }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/This browser can no longer sign/);
    expect(alert.textContent).toMatch(/Nothing was sent/);
    expect(alert.textContent).not.toMatch(/refused/);
    expect(screen.queryByRole("button", { name: "Sign and send" })).toBeNull();
    expect(screen.getByRole("button", { name: "I have sent it — refresh" })).toBeTruthy();
    expect(document.querySelector<HTMLDetailsElement>("details.gitns-doc")!.open).toBe(true);
  });
});

describe("Repos dialogs — the member picker", () => {
  it("reads members a page at a time, and filters what it has read", async () => {
    const page1 = Array.from({ length: 3 }, (_, i) => member(`did:key:z6MkPage1n${i}`, `First ${i}`));
    const requests = mockFetch([
      {
        path: "/v1/members",
        body: ({ url }) =>
          url.includes("cursor=c2")
            ? { items: [member(ALICE, "Alice Wong")] }
            : { items: page1, nextCursor: "c2" },
      },
      { path: "/v1/acl", body: { entries: [], truncated: false } },
    ]);
    renderWithProviders(
      <GrantDialog
        resource={WIDGETS.resource}
        rights={["git.commit.sign"]}
        onClose={() => {}}
        onBuilt={() => {}}
      />,
    );
    const dialog = await screen.findByRole("dialog");
    await within(dialog).findByRole("option", { name: /First 0/ });
    expect(within(dialog).queryByRole("option", { name: /Alice Wong/ })).toBeNull();
    // The listing clamps a page to 200; asking for more would be silently cut.
    // (The name book reads its own listing; this is the picker's.)
    expect(requests.some((r) => r.url === "/v1/members?limit=200")).toBe(true);

    fireEvent.click(within(dialog).getByRole("button", { name: "Load more members" }));
    await within(dialog).findByRole("option", { name: /Alice Wong/ });
    expect(within(dialog).queryByRole("button", { name: "Load more members" })).toBeNull();

    fireEvent.change(within(dialog).getByLabelText("Filter members for Person"), {
      target: { value: "alice" },
    });
    expect(within(dialog).queryByRole("option", { name: /First 0/ })).toBeNull();
    expect(within(dialog).getByRole("option", { name: /Alice Wong/ })).toBeTruthy();
  });
});
