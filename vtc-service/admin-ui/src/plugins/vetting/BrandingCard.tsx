// Community branding — the name, accent colour and logo an applicant's client
// shows for this community (`join-requests/manifest/0.2`'s `branding`).
//
// Rendered on the Community profile page. Presentation only: clients identify
// the community by its DID. The preview sketches the result without fetching
// the logo, because this console's content security policy only loads images
// from the daemon itself — and because fetching it is exactly what reveals a
// visitor to the logo's host, which the form warns about.

import { type FormEvent, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useToast } from "@/lib/toast";
import {
  brandingBody,
  brandingDraft,
  HEX_COLOR,
  validateBranding,
  type BrandingDraft,
  type BrandingErrors,
} from "@/lib/vetting";

import { fetchBranding, saveBranding, vettingKeys } from "./api";
import { describedBy, errorMessage, FormField, LoadError } from "./ui";

/** What the colour picker shows before a valid colour is entered. */
const PICKER_FALLBACK = "#0d9488";

/** Black or white, whichever reads better on `hex` (WCAG relative luminance). */
export function readableTextOn(hex: string): "#000000" | "#ffffff" {
  const n = Number.parseInt(hex.slice(1), 16);
  const channel = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  const luminance =
    0.2126 * channel((n >> 16) & 255) +
    0.7152 * channel((n >> 8) & 255) +
    0.0722 * channel(n & 255);
  return luminance > 0.179 ? "#000000" : "#ffffff";
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

export function CommunityBrandingCard() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const query = useQuery({ queryKey: vettingKeys.branding, queryFn: fetchBranding });
  const [draft, setDraft] = useState<BrandingDraft | null>(null);

  useEffect(() => {
    if (query.data && draft === null) setDraft(brandingDraft(query.data));
  }, [query.data, draft]);

  const save = useMutation({
    mutationFn: saveBranding,
    onSuccess: (stored) => {
      queryClient.setQueryData(vettingKeys.branding, stored);
      setDraft(brandingDraft(stored));
      toast.push(
        "success",
        "Saved the branding. Applicants' clients show it the next time they read the join manifest.",
      );
    },
  });

  if (query.error) {
    return <LoadError what="the community branding" error={query.error} />;
  }
  if (!query.data || !draft) {
    return (
      <section className="card">
        <h3>Branding for applicants</h3>
        <p className="muted">Loading…</p>
      </section>
    );
  }

  const current = query.data;
  const errors = validateBranding(draft);
  const invalid = Object.keys(errors).length > 0;
  const dirty =
    JSON.stringify(brandingBody(draft)) !==
    JSON.stringify(brandingBody(brandingDraft(current)));
  const color = draft.accentColor.trim();
  const nameLength = [...draft.displayName.trim()].length;

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!dirty || invalid) return;
    save.mutate(brandingBody(draft, current));
  };

  return (
    <form
      className="card"
      onSubmit={onSubmit}
      aria-labelledby="branding-title"
      noValidate
    >
      <h3 id="branding-title">Branding for applicants</h3>
      <p className="lead">
        How applicants' clients show this community when someone considers
        joining. It is presentation only: clients identify the community by its
        DID, never by its name or logo. Leave a field empty to publish none.
      </p>

      <div className="branding-layout">
        <div className="form-stack">
          <FormField
            id="branding-name"
            label="Display name"
            hint={`${nameLength} of 128 characters.`}
            error={errors.displayName}
          >
            <input
              id="branding-name"
              type="text"
              value={draft.displayName}
              placeholder="Linux Kernel"
              onChange={(e) => setDraft({ ...draft, displayName: e.target.value })}
              aria-invalid={Boolean(errors.displayName)}
              aria-describedby={describedBy("branding-name", true, errors.displayName)}
            />
          </FormField>

          <FormField
            id="branding-color"
            label="Accent colour"
            hint="# and six hex digits. Pick one, or type it."
            error={errors.accentColor}
          >
            <div className="color-row">
              <input
                type="color"
                aria-label="Pick the accent colour"
                value={HEX_COLOR.test(color) ? color.toLowerCase() : PICKER_FALLBACK}
                onChange={(e) => setDraft({ ...draft, accentColor: e.target.value })}
              />
              <input
                id="branding-color"
                type="text"
                value={draft.accentColor}
                placeholder="#1a7f6e"
                spellCheck={false}
                autoComplete="off"
                onChange={(e) => setDraft({ ...draft, accentColor: e.target.value })}
                aria-invalid={Boolean(errors.accentColor)}
                aria-describedby={describedBy("branding-color", true, errors.accentColor)}
              />
            </div>
          </FormField>

          <FormField
            id="branding-logo"
            label="Logo URL"
            hint="An https:// address. Applicants' clients load the logo from its host, so that host can see when, and from which network address, each applicant looked."
            error={errors.logoUrl}
          >
            <input
              id="branding-logo"
              type="url"
              value={draft.logoUrl}
              placeholder="https://community.example.org/logo.svg"
              spellCheck={false}
              onChange={(e) => setDraft({ ...draft, logoUrl: e.target.value })}
              aria-invalid={Boolean(errors.logoUrl)}
              aria-describedby={describedBy("branding-logo", true, errors.logoUrl)}
            />
          </FormField>
        </div>

        <BrandingPreview draft={draft} errors={errors} />
      </div>

      {save.error && (
        <section className="card error" role="alert">
          <h3>Could not save the branding</h3>
          <p>{errorMessage(save.error)}</p>
          <p className="muted">
            Applicants still see the branding saved before. Correct the fields
            and save again.
          </p>
        </section>
      )}

      <div className="form-actions">
        <button
          type="submit"
          className="primary"
          disabled={!dirty || invalid || save.isPending}
        >
          {save.isPending ? "Saving…" : "Save branding"}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={!dirty || save.isPending}
          onClick={() => {
            setDraft(brandingDraft(current));
            save.reset();
          }}
        >
          Discard changes
        </button>
      </div>
    </form>
  );
}

function BrandingPreview({
  draft,
  errors,
}: {
  draft: BrandingDraft;
  errors: BrandingErrors;
}) {
  const color = draft.accentColor.trim();
  const accent = color && !errors.accentColor ? color.toLowerCase() : null;
  const name = draft.displayName.trim();
  const logoUrl = draft.logoUrl.trim();
  const logoHost = logoUrl && !errors.logoUrl ? hostOf(logoUrl) : null;

  return (
    <figure className="branding-preview">
      <div
        className="branding-preview-card"
        style={accent ? { borderTopColor: accent } : undefined}
        data-testid="branding-preview"
      >
        <div className="branding-preview-logo">
          {logoHost ? (
            <span>
              Logo from
              <br />
              {logoHost}
            </span>
          ) : (
            <span>No logo</span>
          )}
        </div>
        <div>
          <div className="branding-preview-name">{name || "No display name"}</div>
          <div className="muted">Asks to vet you before you join</div>
        </div>
        <span
          className="branding-preview-cta"
          style={
            accent
              ? { background: accent, borderColor: accent, color: readableTextOn(accent) }
              : undefined
          }
        >
          Request to join
        </span>
      </div>
      <figcaption className="muted">
        A sketch of an applicant's client. The logo is not loaded here: this
        console only loads images from its own daemon.
      </figcaption>
    </figure>
  );
}
