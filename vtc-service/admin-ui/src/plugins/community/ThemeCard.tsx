// Community theme — the stylesheet the console and member portal are drawn
// with (`vtc/community/theme/{show,update}/0.1`).
//
// Rendered on the Community profile page. An administrator starts from the
// stored theme, a built-in or an uploaded `.css`, edits it, and sees it checked
// against the theme profile as they type. Preview first asks the community to
// check the draft without storing it (`dryRun`), then opens the console or the
// member portal in a new tab drawn with exactly what would be stored, with
// every write switched off (`lib/theme-preview.ts`); the preview follows the
// draft live. Save stores it for everyone.

import { useEffect, useRef, useState, type ChangeEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Eye, Save, Trash2, Upload } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { postSignedTrustTask, type ApiError } from "@/lib/api";
import {
  BUILTIN_THEMES,
  THEME_UPDATE_TYPE,
  applyCommunityTheme,
  downloadStylesheet,
  fetchStoredTheme,
} from "@/lib/community-theme";
import { setPreviewStylesheet } from "@/lib/theme-preview";
import { MAX_STYLESHEET_BYTES, checkThemeStylesheet } from "@/lib/theme-profile";
import { useToast } from "@/lib/toast";

const THEME_KEY = ["community-theme"] as const;
const OUTSIDE_PROFILE = "vtc/community/theme/update:outsideProfile";

interface UpdateAnswer {
  stylesheet: string;
  stored: boolean;
  updatedAt?: string;
}

function update(stylesheet: string, dryRun: boolean): Promise<UpdateAnswer> {
  return postSignedTrustTask<UpdateAnswer>(THEME_UPDATE_TYPE, dryRun ? { stylesheet, dryRun } : { stylesheet });
}

/** The community's refusal, in the editor's words. */
function refusal(e: unknown): string {
  const err = e as ApiError;
  if (err?.code === OUTSIDE_PROFILE && err.details) {
    const d = err.details as { line?: number; column?: number; rule?: string };
    return `The community refused it — line ${d.line}, column ${d.column}: ${err.message} (${d.rule}).`;
  }
  return err?.message ?? String(e);
}

/** Which built-in a draft is, if it is one unchanged. */
function builtinOf(css: string): string | null {
  return BUILTIN_THEMES.find((t) => t.stylesheet === css)?.id ?? null;
}

export function CommunityThemeCard() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const stored = useQuery({ queryKey: THEME_KEY, queryFn: fetchStoredTheme });
  const [draft, setDraft] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (stored.data && draft === null) setDraft(stored.data.stylesheet);
  }, [stored.data, draft]);

  const text = draft ?? "";
  const check = checkThemeStylesheet(text);
  const bytes = new TextEncoder().encode(text).length;
  const selected = builtinOf(text);
  const current = stored.data?.stylesheet ?? "";
  const dirty = check.ok ? check.stylesheet !== current : true;

  // Every valid draft goes to the open preview tabs at once; an invalid one
  // does not, so a preview keeps the last theme that could be drawn.
  useEffect(() => {
    if (check.ok) setPreviewStylesheet(check.stylesheet);
  }, [check.ok, check.ok ? check.stylesheet : null]);

  const preview = useMutation({
    mutationFn: async (path: string) => {
      const answer = await update(text, true);
      setPreviewStylesheet(answer.stylesheet);
      return path;
    },
    onSuccess: (path) => {
      setNotice(null);
      window.open(`${path}?theme-preview=1`, "_blank", "noopener");
    },
    onError: (e) => setNotice(refusal(e)),
  });

  const save = useMutation({
    mutationFn: (stylesheet: string) => update(stylesheet, false),
    onSuccess: (answer) => {
      setNotice(null);
      queryClient.setQueryData(THEME_KEY, { stylesheet: answer.stylesheet, updatedAt: answer.updatedAt });
      setDraft(answer.stylesheet);
      applyCommunityTheme(answer.stylesheet);
      toast.push(
        "success",
        answer.stylesheet === ""
          ? "Removed the theme. Pages use the standard look again."
          : answer.stored
            ? "Saved the theme. The console and the member portal use it from their next load."
            : "That is already the community's theme.",
      );
    },
    onError: (e) => setNotice(refusal(e)),
  });

  const onUpload = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (file.size > MAX_STYLESHEET_BYTES) {
      setNotice(`${file.name} is ${file.size} bytes; a theme is at most ${MAX_STYLESHEET_BYTES}.`);
      return;
    }
    setNotice(null);
    setDraft(await file.text());
  };

  const onRemove = async () => {
    const ok = await confirm({
      title: "Remove the theme?",
      message: "The console and the member portal go back to the standard look for everyone.",
      confirmLabel: "Remove theme",
      destructive: true,
    });
    if (ok) save.mutate("");
  };

  const busy = preview.isPending || save.isPending;

  return (
    <section className="card" aria-labelledby="theme-title">
      <h3 id="theme-title">Theme</h3>
      <p className="lead">
        The colours, fonts and corners of this console and the member portal. Start from a built-in
        theme or upload a stylesheet, then preview it: the preview opens the console or the portal in
        a new tab drawn with your draft, and nothing you do there is saved. Approvals, confirmations
        and warnings always keep the standard look.
      </p>

      {stored.error && (
        <p className="finding warn">
          Could not read the community's current theme, so the editor starts empty.
        </p>
      )}

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
        value={text}
        placeholder="/* No theme: the standard look. */"
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
          <p className="finding ok">
            Within the theme profile{dirty ? "" : " — this is the community's current theme"}.
          </p>
        ) : (
          <p className="finding error">
            Line {check.line}, column {check.column}: {check.message} ({check.rule}).
          </p>
        )}
        {notice && <p className="finding error">{notice}</p>}
      </div>

      <div className="form-actions">
        <button
          type="button"
          className="primary"
          disabled={!check.ok || !dirty || busy}
          onClick={() => save.mutate(text)}
        >
          <Save size={14} aria-hidden="true" /> {save.isPending ? "Saving…" : "Save theme"}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={!check.ok || busy}
          onClick={() => preview.mutate("/admin/")}
        >
          <Eye size={14} aria-hidden="true" /> Preview console
        </button>
        <button
          type="button"
          className="secondary"
          disabled={!check.ok || busy}
          onClick={() => preview.mutate("/members/")}
        >
          <Eye size={14} aria-hidden="true" /> Preview member portal
        </button>
        <button type="button" className="secondary" onClick={() => fileInput.current?.click()}>
          <Upload size={14} aria-hidden="true" /> Upload .css
        </button>
        <button
          type="button"
          className="secondary"
          disabled={text === ""}
          onClick={() => downloadStylesheet(text, selected ? `${selected}.css` : "community-theme.css")}
        >
          <Download size={14} aria-hidden="true" /> Download
        </button>
        {current !== "" && (
          <button type="button" className="secondary destructive" disabled={busy} onClick={() => void onRemove()}>
            <Trash2 size={14} aria-hidden="true" /> Remove theme
          </button>
        )}
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
    </section>
  );
}
