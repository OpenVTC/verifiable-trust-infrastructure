// The theme profile (`vtc/community/theme/update/0.1`, "The theme profile",
// items P1–P8): the only CSS a community theme may contain.
//
// The page checks a theme itself before applying it (`theme/show` client
// item 1), so this runs on every stylesheet the console or portal draws — a
// built-in, an upload, a preview candidate, and later the stored one. The
// community runs its own check before storing; `theme-profile.vectors.json`
// holds the cases both must agree on.
//
// Dependency-free on purpose: the member portal imports it too, and must not
// pull in the console's client.

/** A stylesheet's byte bound (update item 2). */
export const MAX_STYLESHEET_BYTES = 32768;

/** The profile item a refusal names (`outsideProfile` `details.rule`). */
export type ProfileRule = "P1" | "P2" | "P3" | "P4" | "P5" | "P6" | "P7" | "P8";

export type ProfileCheck =
  | { ok: true; stylesheet: string }
  | { ok: false; rule: ProfileRule; line: number; column: number; message: string };

class Refusal {
  constructor(
    readonly rule: ProfileRule,
    readonly at: number,
    readonly message: string,
  ) {}
}

/**
 * Check `css` against the theme profile. On success, the stylesheet with its
 * comments removed — the only normalisation (update item 4), and what the
 * community stores.
 */
export function checkThemeStylesheet(css: string): ProfileCheck {
  if (new TextEncoder().encode(css).length > MAX_STYLESHEET_BYTES) {
    return { ok: false, rule: "P1", line: 1, column: 1, message: `longer than ${MAX_STYLESHEET_BYTES} bytes` };
  }
  try {
    const { text, kept } = stripComments(css);
    new Parser(text, kept).sheet();
    return { ok: true, stylesheet: text };
  } catch (e) {
    if (!(e instanceof Refusal)) throw e;
    const { line, column } = position(css, e.at);
    return { ok: false, rule: e.rule, line, column, message: e.message };
  }
}

// ── Comments ─────────────────────────────────────────────────────────

/**
 * Remove `/* … *\/` comments outside strings. `kept[i]` is the index in the
 * original of `text[i]`, so a refusal points at what the author wrote.
 */
function stripComments(css: string): { text: string; kept: number[] } {
  let text = "";
  const kept: number[] = [];
  let i = 0;
  let quote: string | null = null;
  while (i < css.length) {
    const c = css[i]!;
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === "/" && css[i + 1] === "*") {
      const end = css.indexOf("*/", i + 2);
      if (end < 0) throw new Refusal("P1", i, "unterminated comment");
      i = end + 2;
      continue;
    }
    text += c;
    kept.push(i);
    i++;
  }
  if (quote) throw new Refusal("P1", kept[kept.length - 1] ?? 0, "unterminated string");
  return { text, kept };
}

function position(css: string, at: number): { line: number; column: number } {
  const before = css.slice(0, at);
  const lines = before.split("\n");
  return { line: lines.length, column: Array.from(lines[lines.length - 1]!).length + 1 };
}

// ── Grammar ──────────────────────────────────────────────────────────

const MEDIA_PRELUDES = new Set(["(prefers-color-scheme: light)", "(prefers-color-scheme: dark)"]);

const TOKEN_SELECTORS = new Set([':root', ':root[data-theme="light"]', ':root[data-theme="dark"]']);

const CUSTOM_PROPERTY = /^--[a-z][a-z0-9-]*$/;

const BANNED_FUNCTIONS = /(?:^|[^a-z0-9-])(url|src|image|image-set|cross-fade|element|attr|paint|env)\s*\(/i;

/** P8, the properties whose value is free (subject to P2/P4/P5). */
const FREE_PROPERTIES = new Set([
  "color",
  "background-color",
  "accent-color",
  "caret-color",
  "outline-color",
  "text-decoration-color",
  "font-family",
  "font-weight",
  "font-style",
  "text-decoration-line",
  "text-transform",
  "border-style",
  "border-top-style",
  "border-right-style",
  "border-bottom-style",
  "border-left-style",
  "border-color",
  "border-top-color",
  "border-right-color",
  "border-bottom-color",
  "border-left-color",
]);

const BORDER_WIDTHS = new Set([
  "border-width",
  "border-top-width",
  "border-right-width",
  "border-bottom-width",
  "border-left-width",
]);

const BORDER_RADII = new Set([
  "border-radius",
  "border-top-left-radius",
  "border-top-right-radius",
  "border-bottom-right-radius",
  "border-bottom-left-radius",
]);

const PSEUDO_CLASSES = new Set([
  "hover",
  "focus",
  "focus-visible",
  "focus-within",
  "active",
  "disabled",
  "checked",
  "first-child",
  "last-child",
]);

const PSEUDO_ELEMENTS = new Set(["placeholder", "selection"]);

const GRADIENT = /^(repeating-)?(linear|radial|conic)-gradient\(/i;

class Parser {
  private i = 0;

  constructor(
    private readonly s: string,
    private readonly kept: number[],
  ) {}

  /** An original index for position `i` of the comment-free text. */
  private at(i = this.i): number {
    return this.kept[Math.min(i, this.kept.length - 1)] ?? 0;
  }

  private refuse(rule: ProfileRule, message: string, i = this.i): never {
    throw new Refusal(rule, this.at(i), message);
  }

  sheet(): void {
    // P2 over the whole text first: an escape or `<` anywhere outside comments.
    for (let j = 0; j < this.s.length; j++) {
      const c = this.s[j];
      if (c === "\\") this.refuse("P2", "escapes are not allowed", j);
      if (c === "<") this.refuse("P2", "`<` is not allowed", j);
    }
    this.ws();
    while (this.i < this.s.length) {
      if (this.s[this.i] === "@") this.atRule();
      else this.styleRule();
      this.ws();
    }
  }

  private ws(): void {
    while (this.i < this.s.length && /\s/.test(this.s[this.i]!)) this.i++;
  }

  /** Text up to (not including) the next `stop` outside strings and parens. */
  private until(stops: string): { text: string; start: number } {
    const start = this.i;
    let depth = 0;
    let quote: string | null = null;
    while (this.i < this.s.length) {
      const c = this.s[this.i]!;
      if (quote) {
        if (c === quote) quote = null;
      } else if (c === '"' || c === "'") {
        quote = c;
      } else if (c === "(" || c === "[") {
        depth++;
      } else if (c === ")" || c === "]") {
        depth--;
      } else if (depth === 0 && stops.includes(c)) {
        break;
      }
      this.i++;
    }
    return { text: this.s.slice(start, this.i), start };
  }

  private expect(c: string, rule: ProfileRule = "P1"): void {
    if (this.s[this.i] !== c) this.refuse(rule, `expected \`${c}\``);
    this.i++;
  }

  private atRule(): void {
    const start = this.i;
    const { text } = this.until("{;");
    const m = /^@([a-z-]+)\s*([\s\S]*)$/i.exec(text.trim());
    const name = m?.[1]?.toLowerCase();
    if (name !== "media") this.refuse("P3", `@${m?.[1] ?? ""} is not allowed`, start);
    const prelude = m![2]!.trim().replace(/\s+/g, " ").replace(/\(\s*/g, "(").replace(/\s*\)/g, ")").replace(/\s*:\s*/g, ": ").toLowerCase();
    if (!MEDIA_PRELUDES.has(prelude)) {
      this.refuse("P3", "only @media (prefers-color-scheme: light|dark) is allowed", start);
    }
    this.expect("{", "P3");
    this.ws();
    while (this.i < this.s.length && this.s[this.i] !== "}") {
      if (this.s[this.i] === "@") this.refuse("P3", "an at-rule may not be nested");
      this.styleRule();
      this.ws();
    }
    this.expect("}");
  }

  private styleRule(): void {
    const { text: selector, start } = this.until("{};");
    if (this.s[this.i] !== "{") this.refuse("P1", "expected a style rule");
    const normalised = selector.trim().replace(/\s+/g, " ");
    if (!normalised) this.refuse("P1", "empty selector", start);
    const token = TOKEN_SELECTORS.has(normalised);
    if (!token) this.selectorList(selector, start);
    this.i++; // `{`
    this.declarations(token);
    this.expect("}");
  }

  private declarations(token: boolean): void {
    for (;;) {
      this.ws();
      if (this.i >= this.s.length || this.s[this.i] === "}") return;
      if (this.s[this.i] === ";") {
        this.i++;
        continue;
      }
      const { text, start } = this.until(";}");
      this.declaration(text, start, token);
    }
  }

  private declaration(text: string, start: number, token: boolean): void {
    const colon = text.indexOf(":");
    if (colon < 0) this.refuse("P1", "expected `property: value`", start);
    const rawName = text.slice(0, colon).trim();
    const value = text.slice(colon + 1).trim();
    const valueAt = start + colon + 1 + (text.slice(colon + 1).length - text.slice(colon + 1).trimStart().length);
    if (!value) this.refuse("P1", `${rawName} has no value`, valueAt);
    if (stripStrings(value).includes("!")) this.refuse("P5", "!important is not allowed", valueAt);
    const banned = BANNED_FUNCTIONS.exec(value);
    if (banned) this.refuse("P4", `${banned[1]}() is not allowed`, valueAt);

    if (rawName.startsWith("--")) {
      if (!CUSTOM_PROPERTY.test(rawName)) this.refuse(token ? "P6" : "P8", `${rawName} is not a valid token name`, start);
      if (rawName.startsWith("--protected-")) this.refuse(token ? "P6" : "P8", "--protected-* tokens are reserved", start);
      if (Array.from(value).length > 512) this.refuse(token ? "P6" : "P8", `${rawName} is longer than 512 characters`, valueAt);
      return;
    }
    if (token) this.refuse("P6", `a :root rule declares tokens only, not ${rawName}`, start);

    const name = rawName.toLowerCase();
    if (FREE_PROPERTIES.has(name)) return;
    if (name === "background-image") {
      if (!gradientsOrNone(value)) this.refuse("P8", "background-image takes gradients or none", valueAt);
      return;
    }
    if (BORDER_WIDTHS.has(name)) {
      if (!boundedLengths(value, 4, ["thin", "medium"])) this.refuse("P8", `${name} is at most 4px`, valueAt);
      return;
    }
    if (BORDER_RADII.has(name)) {
      if (!boundedLengths(value.replace("/", " "), 32, [])) this.refuse("P8", `${name} is at most 32px`, valueAt);
      return;
    }
    if (name === "letter-spacing") {
      if (!/^(normal|0|-?(\d*\.)?\d+em)$/i.test(value) || Math.abs(parseFloat(value) || 0) > 0.2) {
        this.refuse("P8", "letter-spacing is at most 0.2em either way", valueAt);
      }
      return;
    }
    this.refuse("P8", `${rawName} is not a theme property`, start);
  }

  // ── Selectors (P7) ────────────────────────────────────────────────

  private selectorList(selector: string, start: number): void {
    for (const { text, offset } of splitTopLevel(selector, ",")) {
      const lead = text.length - text.trimStart().length;
      const trimmed = text.trim();
      if (!trimmed) this.refuse("P7", "empty selector", start + offset);
      this.compound(trimmed, start + offset + lead);
    }
  }

  /** A complex selector: compounds joined by combinators. */
  private compound(sel: string, base: number): void {
    let j = 0;
    let wantSimple = true;
    while (j < sel.length) {
      const c = sel[j]!;
      if (/\s/.test(c)) {
        j++;
        wantSimple = true;
        continue;
      }
      if (c === ">" || c === "+" || c === "~") {
        j++;
        wantSimple = true;
        continue;
      }
      j = this.simple(sel, j, base);
      wantSimple = false;
    }
    if (wantSimple && /[>+~]\s*$/.test(sel)) this.refuse("P7", "a combinator needs a selector after it", base + sel.length - 1);
  }

  /** One simple selector at `j`; returns the index after it. */
  private simple(sel: string, j: number, base: number): number {
    const ident = /^-?[a-zA-Z_][a-zA-Z0-9_-]*/;
    const c = sel[j]!;
    if (c === "." || c === "#") {
      const m = ident.exec(sel.slice(j + 1));
      if (!m) this.refuse("P7", `expected a name after \`${c}\``, base + j);
      return j + 1 + m[0].length;
    }
    if (c === "[") {
      const end = matching(sel, j, "[", "]");
      if (end < 0) this.refuse("P7", "unterminated attribute selector", base + j);
      const inner = sel.slice(j + 1, end).trim();
      if (!/^[a-zA-Z_][a-zA-Z0-9_-]*\s*(([~|^$*]?=)\s*("[^"]*"|'[^']*'|-?[a-zA-Z_][a-zA-Z0-9_-]*)(\s+[is])?)?$/.test(inner)) {
        this.refuse("P7", "not an attribute selector the profile allows", base + j);
      }
      return end + 1;
    }
    if (c === ":") {
      if (sel[j + 1] === ":") {
        const m = ident.exec(sel.slice(j + 2));
        if (!m || !PSEUDO_ELEMENTS.has(m[0].toLowerCase())) {
          this.refuse("P7", `::${m?.[0] ?? ""} is not allowed`, base + j);
        }
        return j + 2 + m[0].length;
      }
      const m = ident.exec(sel.slice(j + 1));
      if (!m) this.refuse("P7", "expected a pseudo-class", base + j);
      const name = m[0].toLowerCase();
      const after = j + 1 + m[0].length;
      if (sel[after] === "(") {
        const end = matching(sel, after, "(", ")");
        if (end < 0) this.refuse("P7", "unterminated pseudo-class", base + j);
        const arg = sel.slice(after + 1, end).trim();
        if (name === "nth-child") {
          if (!/^(odd|even|[+-]?\d*n(\s*[+-]\s*\d+)?|[+-]?\d+)$/i.test(arg)) {
            this.refuse("P7", "not an :nth-child() argument the profile allows", base + j);
          }
        } else if (name === "not") {
          if (!arg) this.refuse("P7", ":not() needs a selector", base + j);
          for (const part of splitTopLevel(arg, ",")) {
            this.compound(part.text.trim(), base + after + 1);
          }
        } else {
          this.refuse("P7", `:${name}() is not allowed`, base + j);
        }
        return end + 1;
      }
      if (!PSEUDO_CLASSES.has(name)) this.refuse("P7", `:${name} is not allowed`, base + j);
      return after;
    }
    const m = ident.exec(sel.slice(j));
    if (!m) this.refuse("P7", `\`${c}\` is not allowed in a selector`, base + j);
    return j + m[0].length;
  }
}

// ── Helpers ──────────────────────────────────────────────────────────

function stripStrings(v: string): string {
  return v.replace(/"[^"]*"|'[^']*'/g, '""');
}

function matching(s: string, open: number, o: string, c: string): number {
  let depth = 0;
  let quote: string | null = null;
  for (let k = open; k < s.length; k++) {
    const ch = s[k]!;
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === o) {
      depth++;
    } else if (ch === c) {
      depth--;
      if (depth === 0) return k;
    }
  }
  return -1;
}

function splitTopLevel(s: string, sep: string): { text: string; offset: number }[] {
  const out: { text: string; offset: number }[] = [];
  let depth = 0;
  let quote: string | null = null;
  let from = 0;
  for (let k = 0; k < s.length; k++) {
    const ch = s[k]!;
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === "(" || ch === "[") {
      depth++;
    } else if (ch === ")" || ch === "]") {
      depth--;
    } else if (depth === 0 && ch === sep) {
      out.push({ text: s.slice(from, k), offset: from });
      from = k + 1;
    }
  }
  out.push({ text: s.slice(from), offset: from });
  return out;
}

function gradientsOrNone(value: string): boolean {
  if (value.toLowerCase() === "none") return true;
  return splitTopLevel(value, ",").every(({ text }) => {
    const t = text.trim();
    return GRADIENT.test(t) && matching(t, t.indexOf("("), "(", ")") === t.length - 1;
  });
}

/** Space-separated lengths, each `0` or `Npx` with N ≤ `max`, or a keyword. */
function boundedLengths(value: string, max: number, keywords: string[]): boolean {
  const parts = value.trim().split(/\s+/);
  if (parts.length === 0 || parts.length > 8) return false;
  return parts.every((p) => {
    const lower = p.toLowerCase();
    if (keywords.includes(lower) || lower === "0") return true;
    const m = /^(\d+(?:\.\d+)?|\.\d+)px$/.exec(lower);
    return m !== null && parseFloat(m[1]!) <= max;
  });
}
