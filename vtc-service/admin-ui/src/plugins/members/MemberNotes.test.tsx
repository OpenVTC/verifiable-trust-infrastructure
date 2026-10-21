// The console's notes card: shown only to a notes holder, a withdrawn note
// shown without its text, and the export behind the operator's gesture.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({
  showEntryByDid: vi.fn(),
  listNotes: vi.fn(),
  appendNote: vi.fn(),
  redactNote: vi.fn(),
  exportNotes: vi.fn(),
  saveJson: vi.fn(),
}));

vi.mock("@/lib/directory", async (orig) => ({
  ...(await orig<typeof import("@/lib/directory")>()),
  ...api,
}));

import { ConfirmDialogProvider } from "@/components/ConfirmDialog";
import { ToastProvider } from "@/lib/toast";

import { MemberNotesCard } from "./MemberNotes";

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ToastProvider>
        <ConfirmDialogProvider>
          <div data-testid="host">
            <MemberNotesCard did="did:example:carol" />
          </div>
        </ConfirmDialogProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

describe("administrators' notes on a member's page", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.showEntryByDid.mockResolvedValue({ entry: { entryId: "dir_aaaaaaaaaaaaaaaa", fields: {} } });
  });

  it("shows nothing to an administrator who does not hold the notes capability", async () => {
    api.listNotes.mockRejectedValue(new Error("permissionDenied"));
    renderCard();
    await vi.waitFor(() => expect(api.listNotes).toHaveBeenCalled());
    expect(screen.getByTestId("host").textContent).toBe("");
  });

  it("lists notes, a withdrawn one without its text", async () => {
    api.listNotes.mockResolvedValue({
      items: [
        {
          noteId: "note_bbbbbbbbbbbbbbbb",
          entryId: "dir_aaaaaaaaaaaaaaaa",
          author: "did:example:admin",
          createdAt: "2026-10-19T10:00:00Z",
          redacts: "note_aaaaaaaaaaaaaaaa",
        },
        {
          noteId: "note_aaaaaaaaaaaaaaaa",
          entryId: "dir_aaaaaaaaaaaaaaaa",
          author: "did:example:admin",
          createdAt: "2026-10-19T09:00:00Z",
          redactedBy: "note_bbbbbbbbbbbbbbbb",
        },
      ],
    });
    renderCard();
    expect(await screen.findByText("Withdrawn.")).toBeTruthy();
    expect(screen.getByText("Withdrew an earlier note.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Withdraw" })).toBeNull();
    expect(screen.getByText(/Export these notes/)).toBeTruthy();
  });
});
