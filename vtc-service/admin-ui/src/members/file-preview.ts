// What a verified room file may be shown as in the member portal, decided by
// its bytes.
//
// A file's media type is its author's claim — another member's word, which the
// portal cannot check and the wallet does not vouch for. The download keeps
// that rule by saving the bytes under a safe name and opening nothing; a
// preview keeps it too: it is chosen from the **verified bytes** the wallet
// handed over (`wallet.getFile`, which matches every byte against the digest
// the author signed before this page sees one), never from the record, and
// only from a short list of forms that cannot do anything when drawn.
//
// - **Raster images** (PNG, JPEG, GIF, WebP), recognised by their signature and
//   drawn in an `<img>`, which runs nothing. SVG is deliberately not one: it is
//   markup, and the check that would make it safe is the kind that goes wrong.
// - **Plain text** that decodes as UTF-8 with no control characters, drawn as
//   a text node.
//
// Nothing else is previewed — PDF, HTML and office documents included, and
// nothing is ever framed. This page's origin is the community's own site, the
// one its member sessions and the console's cookies belong to: an author's
// markup drawn here would run with all of that, which is worse than in the
// wallet's own pages. A download is the honest way to open anything else.
//
// The rules are the browser wallet's own (`manager/file-preview.ts` in
// OpenVTC/vta-browser-plugin), restated here: the portal imports nothing from
// the extension (`docs/05-design-notes/data-rooms-files.md` §8.5).

export type PreviewKind = "png" | "jpeg" | "gif" | "webp" | "text";

/** The largest file a thumbnail is fetched for without being asked. */
export const AUTO_PREVIEW_MAX_BYTES = 2 * 1024 * 1024;

/** The most text a preview shows; the rest is the download. */
export const TEXT_PREVIEW_MAX_CHARS = 20_000;

const IMAGE_TYPE: Record<Exclude<PreviewKind, "text">, string> = {
  png: "image/png",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
};

const starts = (b: Uint8Array, sig: readonly number[], at = 0) => sig.every((x, i) => b[at + i] === x);
const ascii = (s: string) => [...s].map((ch) => ch.charCodeAt(0));

/** What these bytes may be drawn as, or `null` for download only. */
export function previewKind(bytes: Uint8Array): PreviewKind | null {
  if (starts(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "png";
  if (starts(bytes, [0xff, 0xd8, 0xff])) return "jpeg";
  if (starts(bytes, ascii("GIF87a")) || starts(bytes, ascii("GIF89a"))) return "gif";
  if (starts(bytes, ascii("RIFF")) && starts(bytes, ascii("WEBP"), 8)) return "webp";
  return textOf(bytes) === null ? null : "text";
}

/** The bytes as text, if they are plain text: UTF-8, no control characters but tab and newlines. */
export function textOf(bytes: Uint8Array): string | null {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text) ? null : text;
}

/**
 * A `data:` URL of `bytes`, typed by what they were recognised as — never by
 * the author's claim. A `data:` URL rather than a `blob:` one because the
 * portal's CSP (`img-src 'self' data:`) already allows it, so drawing a
 * preview widens nothing, and there is no object URL to revoke.
 */
export function imageDataUrl(bytes: Uint8Array, kind: Exclude<PreviewKind, "text">): string {
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return `data:${IMAGE_TYPE[kind]};base64,${btoa(binary)}`;
}

/** What a verified file is shown as: a picture, its text, or nothing but a download. */
export type Shown =
  | { kind: "image"; url: string }
  | { kind: "text"; text: string; cut: boolean }
  | { kind: "none" };

/** Decide what verified `bytes` are shown as. */
export function showBytes(bytes: Uint8Array): Shown {
  const kind = previewKind(bytes);
  if (kind === null) return { kind: "none" };
  if (kind === "text") {
    const text = textOf(bytes) ?? "";
    return { kind: "text", text: text.slice(0, TEXT_PREVIEW_MAX_CHARS), cut: text.length > TEXT_PREVIEW_MAX_CHARS };
  }
  return { kind: "image", url: imageDataUrl(bytes, kind) };
}

/** A blob's bytes. */
export async function blobBytes(blob: Blob): Promise<Uint8Array> {
  if (typeof blob.arrayBuffer === "function") return new Uint8Array(await blob.arrayBuffer());
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(new Uint8Array(r.result as ArrayBuffer));
    r.onerror = () => reject(r.error ?? new Error("could not read the file"));
    r.readAsArrayBuffer(blob);
  });
}

/**
 * Whether the record's own account makes a preview worth fetching unasked.
 * Only a hint for *whether to fetch*: what is drawn is still decided by the
 * bytes, so a record that lies here gets a download button, not a rendering.
 */
export function worthAutoPreview(claim: { size: number; mediaType?: string; name: string }): boolean {
  if (claim.size > AUTO_PREVIEW_MAX_BYTES) return false;
  const type = claim.mediaType?.toLowerCase() ?? "";
  return /^image\/(png|jpeg|gif|webp)$/.test(type) || /\.(png|jpe?g|gif|webp)$/i.test(claim.name);
}

/** Whether a Preview button is worth offering at all, from the record's account. */
export function mayPreview(claim: { mediaType?: string; name: string }): boolean {
  const type = claim.mediaType?.toLowerCase() ?? "";
  return (
    /^image\/(png|jpeg|gif|webp)$/.test(type) ||
    type.startsWith("text/") ||
    type === "application/json" ||
    /\.(png|jpe?g|gif|webp|txt|md|csv|json|log)$/i.test(claim.name)
  );
}

// ── The queue thumbnails go through ─────────────────────────────────────────
//
// A room's thumbnails are fetched without being asked, and each is a read
// through the member's wallet and their VTA. Started together, a big room would
// fire dozens of reads at the member's agent at once, and the one the member
// *did* ask for would wait behind them all. A limiter runs a few at a time, in
// the order asked, so the top of the list fills in first. What a member clicks
// does not go through one.

export interface Limiter {
  run<T>(task: () => Promise<T>): Promise<T>;
}

export function createLimiter(concurrency: number): Limiter {
  let active = 0;
  const waiting: (() => void)[] = [];
  const next = () => {
    if (active >= concurrency) return;
    const start = waiting.shift();
    if (start) start();
  };
  return {
    run<T>(task: () => Promise<T>): Promise<T> {
      return new Promise<T>((resolve, reject) => {
        waiting.push(() => {
          active++;
          let started: Promise<T>;
          try {
            started = task();
          } catch (e) {
            started = Promise.reject(e);
          }
          started.then(resolve, reject).finally(() => {
            active--;
            next();
          });
        });
        next();
      });
    },
  };
}
