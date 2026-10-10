import { afterEach, describe, expect, it } from "vitest";

import {
  accentForeground,
  applyCommunityAccent,
  displayableLogo,
} from "@/lib/community-identity";

describe("the community accent", () => {
  afterEach(() => applyCommunityAccent(null));

  it("picks a label colour that reads on the accent", () => {
    expect(accentForeground("#1a2b3c")).toBe("#ffffff");
    expect(accentForeground("#5b5bd6")).toBe("#ffffff");
    expect(accentForeground("#ffd400")).toBe("#0b0b1a");
    expect(accentForeground("red")).toBeNull();
    expect(accentForeground("#12345g")).toBeNull();
  });

  it("is set on <html> and taken off again", () => {
    const root = document.documentElement;
    applyCommunityAccent("#1A2B3C");
    expect(root.hasAttribute("data-community-accent")).toBe(true);
    expect(root.style.getPropertyValue("--community-accent")).toBe("#1a2b3c");
    expect(root.style.getPropertyValue("--community-accent-fg")).toBe("#ffffff");

    applyCommunityAccent(null);
    expect(root.hasAttribute("data-community-accent")).toBe(false);
    expect(root.style.getPropertyValue("--community-accent")).toBe("");
  });

  it("ignores a value that is not #rrggbb, leaving indigo", () => {
    applyCommunityAccent("url(javascript:alert(1))");
    expect(document.documentElement.hasAttribute("data-community-accent")).toBe(false);
  });
});

describe("the community logo", () => {
  const ORIGIN = "https://vtc.example.org";

  it("shows only what the console's img-src 'self' admits", () => {
    expect(displayableLogo("/logo.svg", ORIGIN)).toBe("/logo.svg");
    expect(displayableLogo("https://vtc.example.org/logo.png", ORIGIN)).toBe(
      "https://vtc.example.org/logo.png",
    );
    expect(displayableLogo("https://cdn.example.com/logo.png", ORIGIN)).toBeNull();
    expect(displayableLogo("//cdn.example.com/logo.png", ORIGIN)).toBeNull();
    expect(displayableLogo("", ORIGIN)).toBeNull();
    expect(displayableLogo(null, ORIGIN)).toBeNull();
  });
});
