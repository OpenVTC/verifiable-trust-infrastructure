// Community logo — the image the community stores and serves from its own
// origin (`vtc/community/logo/update/0.1`, read at `GET /v1/community/logo`).
//
// Rendered on the Community profile page. An administrator chooses a PNG,
// JPEG, WebP or SVG; the console draws it as a PNG at most 512 pixels across
// (`lib/logo-upload.ts`, which rasterizes an SVG so none is ever sent), shows
// it, and Save sends it. The community re-encodes what arrives and answers what
// it stored. Every page then draws it in place of the profile's Logo URL.

import { useRef, useState, type ChangeEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Save, Trash2, Upload } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { postSignedTrustTask, type ApiError } from "@/lib/api";
import { PUBLIC_PROFILE_KEY, fetchPublicProfile } from "@/lib/community-identity";
import { LogoError, prepareLogo } from "@/lib/logo-upload";
import { messageOf } from "@/lib/messages";
import { useToast } from "@/lib/toast";
import { pictureUrl, toBase64Url } from "@/members/picture";

export const LOGO_UPDATE_TYPE = "https://trusttasks.org/spec/vtc/community/logo/update/0.1";

const TOO_LARGE = "vtc/community/logo/update:tooLarge";
const NOT_AN_IMAGE = "vtc/community/logo/update:notAnImage";
const RATE_LIMITED = "vtc/community/logo/update:rateLimited";

interface UpdateAnswer {
  logo: { sha256: string; mediaType: string; size: number; width: number; height: number; url?: string } | null;
  stored: boolean;
  updatedAt?: string;
}

/** The community's refusal, in the administrator's words. */
function refusal(e: unknown): string {
  const code = (e as ApiError)?.code;
  if (code === TOO_LARGE) return "The community refused it: the image is larger than it decodes.";
  if (code === NOT_AN_IMAGE) return "The community could not read that image.";
  if (code === RATE_LIMITED) return "Too many logo changes in the last hour. Try again later.";
  return messageOf(e);
}

export function CommunityLogoCard() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  // The same read as the top bar's, so one fetch serves both and one
  // invalidation refreshes both.
  const stored = useQuery({ queryKey: PUBLIC_PROFILE_KEY, queryFn: fetchPublicProfile });
  const [draft, setDraft] = useState<{ data: string; preview: string; width: number; height: number } | null>(
    null,
  );
  const [notice, setNotice] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const save = useMutation({
    // Removal is `remove: true`, never `image: null` (update item 6).
    mutationFn: (data: string | null) =>
      postSignedTrustTask<UpdateAnswer>(
        LOGO_UPDATE_TYPE,
        data === null ? { remove: true } : { image: { mediaType: "image/png", data } },
      ),
    onSuccess: (answer) => {
      setNotice(null);
      setDraft(null);
      void queryClient.invalidateQueries({ queryKey: PUBLIC_PROFILE_KEY });
      toast.push(
        "success",
        answer.logo === null
          ? answer.stored
            ? "Removed the logo. Pages use the Logo URL, or the standard mark, again."
            : "The community has no logo to remove."
          : answer.stored
            ? "Saved the logo. Every page shows it from its next load."
            : "That is already the community's logo.",
      );
    },
    onError: (e) => setNotice(refusal(e)),
  });

  const onChoose = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setNotice(null);
    try {
      const { bytes, width, height } = await prepareLogo(file);
      const data = toBase64Url(bytes);
      setDraft({ data, preview: pictureUrl("image/png", data), width, height });
    } catch (err) {
      setDraft(null);
      setNotice(err instanceof LogoError ? err.message : messageOf(err));
    }
  };

  const onRemove = async () => {
    const ok = await confirm({
      title: "Remove the logo?",
      message: "Every page goes back to the profile's Logo URL, or the standard mark if it has none.",
      confirmLabel: "Remove logo",
      destructive: true,
    });
    if (ok) save.mutate(null);
  };

  const current = stored.data?.storedLogo ?? null;
  const shown = draft?.preview ?? current?.url ?? null;

  return (
    <section className="card" aria-labelledby="logo-title">
      <h3 id="logo-title">Logo</h3>
      <p className="lead">
        The mark shown in the top bar of this console, the member portal, the sign-in pages and the
        home page. The community stores it and serves it itself, so it shows wherever those pages do.
        An SVG is turned into a PNG in this browser before it is sent.
      </p>

      {stored.error && <p className="finding warn">Could not read the community's current logo.</p>}

      <div className="logo-preview" aria-live="polite">
        {shown ? (
          <img src={shown} alt={draft ? "The logo you chose" : "The community's logo"} className="brand-logo" />
        ) : (
          <p className="muted">No logo uploaded. Pages use the Logo URL above, or the standard mark.</p>
        )}
        {draft && (
          <p className="field-hint">
            {draft.width} × {draft.height} pixels, not saved yet.
          </p>
        )}
        {notice && <p className="finding error">{notice}</p>}
      </div>

      <div className="form-actions">
        <button type="button" className="secondary" onClick={() => fileInput.current?.click()}>
          <Upload size={14} aria-hidden="true" /> Choose image
        </button>
        <button
          type="button"
          className="primary"
          disabled={!draft || save.isPending}
          onClick={() => draft && save.mutate(draft.data)}
        >
          <Save size={14} aria-hidden="true" /> {save.isPending ? "Saving…" : "Save logo"}
        </button>
        {current && !draft && (
          <button
            type="button"
            className="secondary destructive"
            disabled={save.isPending}
            onClick={() => void onRemove()}
          >
            <Trash2 size={14} aria-hidden="true" /> Remove logo
          </button>
        )}
        {draft && (
          <button type="button" className="secondary" onClick={() => setDraft(null)}>
            Cancel
          </button>
        )}
        <input
          ref={fileInput}
          type="file"
          accept=".png,.jpg,.jpeg,.webp,.svg,image/png,image/jpeg,image/webp,image/svg+xml"
          className="visually-hidden"
          tabIndex={-1}
          aria-hidden="true"
          onChange={(e) => void onChoose(e)}
        />
      </div>
    </section>
  );
}
