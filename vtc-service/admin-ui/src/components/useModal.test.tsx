import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it } from "vitest";

import { ConfirmDialogProvider, useConfirm } from "@/components/ConfirmDialog";
import { TypedConfirmDialog } from "@/components/TypedConfirmDialog";

// The shared modal contract (#2610): focus in, Tab trapped, Escape closes,
// focus back to the opener.

function ConfirmOpener() {
  const confirm = useConfirm();
  const [answer, setAnswer] = useState<string>("");
  return (
    <>
      <button type="button" onClick={async () => setAnswer(String(await confirm({ title: "Remove it?" })))}>
        Open confirm
      </button>
      <button type="button">Behind the scrim</button>
      <output>{answer}</output>
    </>
  );
}

/** The focused element, through the dialog's shadow root. */
function focused(): Element | null {
  let el: Element | null = document.activeElement;
  while (el?.shadowRoot?.activeElement) el = el.shadowRoot.activeElement;
  return el;
}

describe("useModal, through the dialogs that use it (#2610)", () => {
  it("ConfirmDialog starts on Cancel, keeps Tab inside and returns focus to its opener", async () => {
    render(
      <ConfirmDialogProvider>
        <ConfirmOpener />
      </ConfirmDialogProvider>,
    );
    const opener = screen.getByRole("button", { name: "Open confirm" });
    opener.focus();
    fireEvent.click(opener);

    await waitFor(() => expect(focused()?.textContent).toBe("Cancel"));
    const cancel = focused() as HTMLElement;
    // Shift-Tab from the first control wraps to the last, not into the page.
    fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
    expect(focused()?.textContent).toBe("Confirm");
    fireEvent.keyDown(window, { key: "Tab" });
    expect(focused()).toBe(cancel);

    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.getByRole("status").textContent).toBe("false"));
    expect(document.activeElement).toBe(opener);
  });

  it("TypedConfirmDialog traps Tab and ignores Escape while busy", async () => {
    let cancelled = 0;
    function Host({ busy }: { busy: boolean }) {
      return (
        <TypedConfirmDialog
          title="Remove now?"
          message="Type it"
          prompt="Type the DID"
          matches={(t) => t === "did:key:z"}
          confirmLabel="Remove"
          busy={busy}
          onConfirm={() => {}}
          onCancel={() => (cancelled += 1)}
        />
      );
    }
    const { rerender } = render(<Host busy={false} />);
    await waitFor(() => expect(focused()?.getAttribute("aria-label")).toBe("Type the DID"));
    const input = focused() as HTMLElement;
    // The confirm button is disabled until the DID is typed, so Cancel is last.
    fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
    expect(focused()?.textContent).toBe("Cancel");
    fireEvent.keyDown(window, { key: "Tab" });
    expect(focused()).toBe(input);

    rerender(<Host busy />);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(cancelled).toBe(0);
    rerender(<Host busy={false} />);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(cancelled).toBe(1);
  });
});
