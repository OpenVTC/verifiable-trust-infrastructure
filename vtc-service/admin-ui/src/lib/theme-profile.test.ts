// The theme profile checker against the shared vectors — the cases the
// community's own checker must answer the same way.

import { describe, expect, it } from "vitest";

import { MAX_STYLESHEET_BYTES, checkThemeStylesheet } from "./theme-profile";
import vectors from "./theme-profile.vectors.json";

describe("theme profile", () => {
  for (const v of vectors.accept) {
    it(`accepts ${v.name}`, () => {
      expect(checkThemeStylesheet(v.css)).toEqual({ ok: true, stylesheet: v.stored });
    });
  }

  for (const v of vectors.refuse) {
    it(`refuses ${v.name} (${v.rule})`, () => {
      const got = checkThemeStylesheet(v.css);
      expect(got.ok).toBe(false);
      if (got.ok) return;
      expect({ rule: got.rule, line: got.line, column: got.column }).toEqual({
        rule: v.rule,
        line: v.line,
        column: v.column,
      });
    });
  }

  it("counts the bound in bytes, not characters", () => {
    // Fewer characters than the bound, more bytes: a comment of two-byte é.
    const css = `/*${"é".repeat(MAX_STYLESHEET_BYTES / 2)}*/`;
    expect(Array.from(css).length).toBeLessThan(MAX_STYLESHEET_BYTES);
    const got = checkThemeStylesheet(css);
    expect(got).toMatchObject({ ok: false, rule: "P1" });
  });
});
