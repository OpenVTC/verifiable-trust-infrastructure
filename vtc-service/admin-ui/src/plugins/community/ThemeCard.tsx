// Community theme — the stylesheet the console and member portal are drawn
// with (`vtc/community/theme/*`, spec PR trustoverip/dtgwg-trust-tasks-tf#811).
//
// Rendered on the Community profile page. An administrator starts from a
// built-in theme or an uploaded `.css`, edits it, and sees it checked against
// the theme profile as they type. Preview opens the console or the member
// portal in a new tab drawn with the draft, with every write switched off
// (`lib/theme-preview.ts`); the preview follows the draft live.
//
// Storing a theme for the community waits on `vtc/community/theme/update`
// reaching the daemon. Until then the draft lives in this browser only.

import { useEffect, useRef, useState, type ChangeEvent } from "react";
import { Download, Eye, Upload } from "lucide-react";

import { BUILTIN_THEMES, downloadStylesheet } from "@/lib/community-theme";
import { previewStylesheet, setPreviewStylesheet } from "@/lib/theme-preview";
import { MAX_STYLESHEET_BYTES, checkThemeStylesheet } from "@/lib/theme-profile";

/** Which built-in a draft is, if it is one unchanged. */
function builtinOf(css: string): string | null {
  return BUILTIN_THEMES.find((t) => t.stylesheet === css)?.id ?? null;
}

function openPreview(path: string): void {
  window.open(`${path}?theme-preview=1`, "_blank", "noopener");
}

export function CommunityThemeCard() {
  const [draft, setDraft] = useState<string>(() => previewStylesheet());
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const check = checkThemeStylesheet(draft);
  const bytes = new TextEncoder().encode(draft).length;
  const selected = builtinOf(draft);

  // Every valid draft is handed to the open preview tabs at once; an invalid
  // one is not, so a preview keeps the last theme that could be drawn.
  useEffect(() => {
    if (check.ok) setPreviewStylesheet(check.stylesheet);
  }, [check.ok, check.ok ? check.stylesheet : null]);

  const onUpload = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (file.size > MAX_STYLESHEET_BYTES) {
      setUploadError(`${file.name} is ${file.size} bytes; a theme is at most ${MAX_STYLESHEET_BYTES}.`);
      return;
    }
    setUploadError(null);
    setDraft(await file.text());
  };

  return (
    <section className="card" aria-labelledby="theme-title">
      <h3 id="theme-title">Theme</h3>
      <p className="lead">
        The colours, fonts and corners of this console and the member portal. Start from a built-in
        theme or upload a stylesheet, then preview it: the preview opens the console or the portal in
        a new tab drawn with your draft, and nothing you do there is saved.
      </p>

      <div className="theme-presets" role="radiogroup" aria-label="Built-in themes">
        {BUILTIN_THEMES.map((t) => (
          <button
            key={t.id}
            type="button"
            role="radio"
            aria-checked={selected === t.id}
            className="theme-preset"
            onClick={() => setDraft(t.stylesheet)}
          >
            <span className="theme-swatches" aria-hidden="true">
              {t.swatches.map((c) => (
                <span key={c} className="theme-swatch" style={{ backgroundColor: c }} />
              ))}
            </span>
            {t.name}
          </button>
        ))}
      </div>

      <label className="field-label" htmlFor="theme-css">
        Stylesheet
      </label>
      <textarea
        id="theme-css"
        className="theme-editor"
        spellCheck={false}
        rows={14}
        value={draft}
        placeholder="/* No theme: the built-in look. */"
        onChange={(e) => setDraft(e.target.value)}
        aria-invalid={!check.ok}
        aria-describedby="theme-check theme-hint"
      />
      <p id="theme-hint" className="field-hint">
        {bytes} of {MAX_STYLESHEET_BYTES} bytes. Design tokens on <code>:root</code> (light and dark), and
        colours, gradients, borders and fonts on elements. Nothing that loads a file, adds content, or
        moves or hides an element.
      </p>
      <div id="theme-check" aria-live="polite">
        {check.ok ? (
          <p className="finding ok">Within the theme profile.</p>
        ) : (
          <p className="finding error">
            Line {check.line}, column {check.column}: {check.message} ({check.rule}).
          </p>
        )}
        {uploadError && <p className="finding error">{uploadError}</p>}
      </div>

      <div className="form-actions">
        <button
          type="button"
          className="primary"
          disabled={!check.ok}
          onClick={() => openPreview("/admin/")}
        >
          <Eye size={14} aria-hidden="true" /> Preview console
        </button>
        <button
          type="button"
          className="secondary"
          disabled={!check.ok}
          onClick={() => openPreview("/members/")}
        >
          <Eye size={14} aria-hidden="true" /> Preview member portal
        </button>
        <button type="button" className="secondary" onClick={() => fileInput.current?.click()}>
          <Upload size={14} aria-hidden="true" /> Upload .css
        </button>
        <button
          type="button"
          className="secondary"
          disabled={draft === ""}
          onClick={() => downloadStylesheet(draft, selected ? `${selected}.css` : "community-theme.css")}
        >
          <Download size={14} aria-hidden="true" /> Download
        </button>
        <input
          ref={fileInput}
          type="file"
          accept=".css,text/css"
          className="visually-hidden"
          tabIndex={-1}
          aria-hidden="true"
          onChange={(e) => void onUpload(e)}
        />
      </div>
      <p className="muted">
        Saving a theme for the whole community arrives with the theme Trust Tasks. Until then your draft
        stays in this browser.
      </p>
    </section>
  );
}
