// Theme preview: built-in themes are in the profile, and a preview tab sends
// reads only — at both of the console's seams and the portal's.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BUILTIN_THEMES, applyCommunityTheme } from "./community-theme";
import { checkThemeStylesheet } from "./theme-profile";
import {
  PREVIEW_NOOP_EVENT,
  PreviewNoopError,
  guardPreviewDocument,
  guardPreviewRequest,
  isReadTask,
  isThemePreview,
  resetThemePreviewForTests,
} from "./theme-preview";

describe("built-in themes", () => {
  for (const t of BUILTIN_THEMES) {
    it(`${t.name} is within the theme profile`, () => {
      // Only Default is the empty stylesheet; an empty built-in otherwise means
      // its `?raw` import arrived empty, and would pass the check vacuously.
      expect(t.stylesheet === "").toBe(t.id === "default");
      expect(checkThemeStylesheet(t.stylesheet)).toMatchObject({ ok: true });
    });
  }

  it("draws a theme last in <head> and removes it for one outside the profile", () => {
    applyCommunityTheme(BUILTIN_THEMES[1]!.stylesheet);
    const style = document.getElementById("vtc-community-theme");
    expect(style?.parentElement).toBe(document.head);
    expect(document.head.lastElementChild).toBe(style);
    expect(document.documentElement.hasAttribute("data-community-theme")).toBe(true);

    applyCommunityTheme(".a { display: none; }");
    expect(document.getElementById("vtc-community-theme")).toBeNull();
    expect(document.documentElement.hasAttribute("data-community-theme")).toBe(false);
  });
});

describe("read classification", () => {
  it.each([
    "https://trusttasks.org/spec/vtc/community/profile/show/0.1",
    "https://trusttasks.org/spec/vtc/members/list/0.2#request",
    "https://trusttasks.org/spec/trust-task-discovery/0.1",
  ])("%s is a read", (uri) => expect(isReadTask(uri)).toBe(true));

  it.each([
    "https://trusttasks.org/spec/vtc/community/profile/update/0.1",
    "https://trusttasks.org/spec/acl/grant/0.2",
    "https://trusttasks.org/spec/vtc/admin/actions/approve/0.1",
    "https://trusttasks.org/spec/auth/step-up/approve-response/0.4",
    "https://example.org/spec/vtc/community/profile/show/0.1",
    "not a uri",
  ])("%s is not", (uri) => expect(isReadTask(uri)).toBe(false));
});

describe("in a preview tab", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    resetThemePreviewForTests();
    window.history.replaceState(null, "", "/admin/profile?theme-preview=1#x");
  });
  afterEach(() => {
    window.sessionStorage.clear();
    resetThemePreviewForTests();
    window.history.replaceState(null, "", "/");
  });

  it("enters from the query parameter, keeps it for the tab and tidies the address", () => {
    expect(isThemePreview()).toBe(true);
    expect(window.location.search).toBe("");
    expect(window.location.hash).toBe("#x");
    resetThemePreviewForTests();
    expect(isThemePreview()).toBe(true);
  });

  it("refuses writes and announces each refusal", () => {
    const seen = vi.fn();
    window.addEventListener(PREVIEW_NOOP_EVENT, seen);
    expect(isThemePreview()).toBe(true);
    expect(() =>
      guardPreviewDocument("https://trusttasks.org/spec/vtc/community/profile/update/0.1"),
    ).toThrow(PreviewNoopError);
    expect(() => guardPreviewRequest("POST", "/v1/member/sign-out")).toThrow(PreviewNoopError);
    expect(seen).toHaveBeenCalledTimes(2);
    window.removeEventListener(PREVIEW_NOOP_EVENT, seen);
  });

  it("lets reads through", () => {
    expect(isThemePreview()).toBe(true);
    expect(() =>
      guardPreviewDocument("https://trusttasks.org/spec/vtc/community/profile/show/0.1"),
    ).not.toThrow();
    expect(() => guardPreviewRequest("GET", "/v1/member/me")).not.toThrow();
  });
});

describe("outside a preview", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    resetThemePreviewForTests();
  });

  it("refuses nothing", () => {
    expect(isThemePreview()).toBe(false);
    expect(() =>
      guardPreviewDocument("https://trusttasks.org/spec/vtc/community/profile/update/0.1"),
    ).not.toThrow();
    expect(() => guardPreviewRequest("DELETE", "/v1/member/passkeys/x")).not.toThrow();
  });
});
