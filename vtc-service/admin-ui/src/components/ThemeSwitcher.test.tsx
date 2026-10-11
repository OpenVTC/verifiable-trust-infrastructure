// The colour-theme switcher: Match system / Light / Dark, persisted under the
// key the member portal and the home page share, and an ARIA radio group.

import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ThemeSwitcher } from "@/components/ThemeSwitcher";
import {
  THEME_STORAGE_KEY,
  applyStoredTheme,
  effectiveTheme,
  getStoredTheme,
  setTheme,
} from "@/lib/theme";

/** A plain in-memory Storage, so the tests do not depend on the runtime's. */
function memoryStorage(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k) => m.get(k) ?? null,
    key: (i) => [...m.keys()][i] ?? null,
    removeItem: (k) => void m.delete(k),
    setItem: (k, v) => void m.set(k, String(v)),
  };
}

let storage: Storage;
beforeEach(() => {
  storage = memoryStorage();
  vi.stubGlobal("localStorage", storage);
  Object.defineProperty(window, "localStorage", { value: storage, configurable: true });
  document.documentElement.removeAttribute("data-theme");
});
afterEach(() => {
  document.documentElement.removeAttribute("data-theme");
});

const radio = (name: string) => screen.getByRole("radio", { name }) as HTMLButtonElement;

describe("theme preference (lib/theme)", () => {
  it("defaults to following the system, storing nothing", () => {
    expect(getStoredTheme()).toBe("auto");
    setTheme("auto");
    expect(storage.getItem(THEME_STORAGE_KEY)).toBeNull();
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
  });

  it("pins light or dark on <html> and persists it under the shared key", () => {
    expect(THEME_STORAGE_KEY).toBe("vtc-admin-theme");
    setTheme("dark");
    expect(storage.getItem("vtc-admin-theme")).toBe("dark");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    setTheme("auto");
    expect(storage.getItem("vtc-admin-theme")).toBeNull();
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
  });

  it("re-applies a stored choice on load, and ignores a value it does not know", () => {
    storage.setItem(THEME_STORAGE_KEY, "light");
    applyStoredTheme();
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    storage.setItem(THEME_STORAGE_KEY, "sepia");
    expect(getStoredTheme()).toBe("auto");
  });

  it("resolves Match system from prefers-color-scheme", () => {
    const mm = vi.fn((q: string) => ({ matches: q.includes("dark") }) as MediaQueryList);
    vi.stubGlobal("matchMedia", mm);
    Object.defineProperty(window, "matchMedia", { value: mm, configurable: true });
    expect(effectiveTheme("auto")).toBe("dark");
    expect(effectiveTheme("light")).toBe("light");
  });

  it("follows a choice made in another tab", () => {
    applyStoredTheme();
    storage.setItem(THEME_STORAGE_KEY, "dark");
    act(() => {
      window.dispatchEvent(new StorageEvent("storage", { key: THEME_STORAGE_KEY }));
    });
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });
});

describe("ThemeSwitcher", () => {
  it("is a radio group with the stored choice checked", () => {
    storage.setItem(THEME_STORAGE_KEY, "dark");
    render(<ThemeSwitcher />);
    expect(screen.getByRole("radiogroup", { name: "Colour theme" })).toBeTruthy();
    expect(radio("Dark").getAttribute("aria-checked")).toBe("true");
    expect(radio("Light").getAttribute("aria-checked")).toBe("false");
    expect(radio("Match system").getAttribute("aria-checked")).toBe("false");
  });

  it("applies and persists a click", () => {
    render(<ThemeSwitcher />);
    fireEvent.click(radio("Light"));
    expect(radio("Light").getAttribute("aria-checked")).toBe("true");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(storage.getItem(THEME_STORAGE_KEY)).toBe("light");
  });

  it("keeps only the chosen option in the Tab order, and moves with the arrow keys", () => {
    render(<ThemeSwitcher />);
    expect(radio("Match system").tabIndex).toBe(0);
    expect(radio("Light").tabIndex).toBe(-1);
    expect(radio("Dark").tabIndex).toBe(-1);

    radio("Match system").focus();
    fireEvent.keyDown(radio("Match system"), { key: "ArrowRight" });
    expect(radio("Light").getAttribute("aria-checked")).toBe("true");
    expect(document.activeElement).toBe(radio("Light"));
    expect(radio("Light").tabIndex).toBe(0);

    fireEvent.keyDown(radio("Light"), { key: "End" });
    expect(radio("Dark").getAttribute("aria-checked")).toBe("true");
    // Wraps from the last to the first.
    fireEvent.keyDown(radio("Dark"), { key: "ArrowRight" });
    expect(radio("Match system").getAttribute("aria-checked")).toBe("true");
    fireEvent.keyDown(radio("Match system"), { key: "ArrowLeft" });
    expect(radio("Dark").getAttribute("aria-checked")).toBe("true");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  it("stays in step with a change made elsewhere on the page", () => {
    render(
      <>
        <ThemeSwitcher label="First" />
        <ThemeSwitcher label="Second" />
      </>,
    );
    const second = screen.getByRole("radiogroup", { name: "Second" });
    fireEvent.click(screen.getAllByRole("radio", { name: "Dark" })[0]!);
    expect(
      second.querySelector('[aria-label="Dark"]')!.getAttribute("aria-checked"),
    ).toBe("true");
  });
});
