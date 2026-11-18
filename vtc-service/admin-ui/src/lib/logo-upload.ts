// Preparing a community logo in the browser for `vtc/community/logo/update/0.1`.
//
// Everything is drawn onto a canvas and sent as PNG, at most 512 pixels on the
// longer side: what the community keeps (update item 4), and lossless, which a
// logo's flat color and sharp edges need. The community re-encodes whatever
// arrives anyway; scaling here only keeps the document small.
//
// An SVG is rasterized here, never sent (client item 2): the community stores
// raster images only, because an SVG served from its origin is a document that
// can run script there. It is drawn from a `data:` URL into an `<img>`, where an
// SVG runs no script and loads nothing, then onto the canvas. A `data:` URL
// rather than a `blob:` one because the console's CSP is `img-src 'self' data:`.

/** The most the community accepts or stores (`LogoImage.data`, decoded). */
export const MAX_LOGO_BYTES = 262_144;

/** The longer side a logo is drawn at. */
export const LOGO_DIMENSION = 512;

/** The largest file the console reads at all. */
export const MAX_LOGO_FILE_BYTES = 1_048_576;

/** The sizes tried, longest side first, until the PNG fits. */
const SIZES = [LOGO_DIMENSION, 384, 256, 192, 128] as const;

/** The square an SVG with no intrinsic size is drawn into. */
const DEFAULT_SVG_BOX = LOGO_DIMENSION;

const RASTER_TYPES = ["image/png", "image/jpeg", "image/webp"];

/** Why a logo cannot be sent, in the administrator's words. */
export class LogoError extends Error {}

/** A drawable image and its size in pixels. */
export interface Drawable {
  readonly source: CanvasImageSource;
  readonly width: number;
  readonly height: number;
  close?(): void;
}

/** The browser calls this module needs, injectable for tests. */
export interface LogoDeps {
  /** Decode a raster file. */
  decodeRaster(file: Blob): Promise<Drawable>;
  /** Decode an SVG from a `data:` URL, inside an `<img>`. */
  decodeSvg(dataUrl: string): Promise<Drawable>;
  /** Draw `image` at `width`×`height` and encode it as PNG. */
  encodePng(image: Drawable, width: number, height: number): Promise<Uint8Array>;
}

/** Whether `file` is an SVG, by type or name. */
export function isSvg(file: Blob & { name?: string }): boolean {
  return file.type === "image/svg+xml" || /\.svg$/i.test(file.name ?? "");
}

/** `text` as a `data:image/svg+xml;base64,…` URL. */
export function svgDataUrl(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return `data:image/svg+xml;base64,${btoa(bin)}`;
}

/** `width`×`height` scaled to at most `size` on the longer side; never up. */
export function fitWithin(width: number, height: number, size: number): [number, number] {
  const scale = Math.min(1, size / Math.max(width, height));
  return [Math.max(1, Math.round(width * scale)), Math.max(1, Math.round(height * scale))];
}

/**
 * The PNG to send for `file`: drawn at most {@link LOGO_DIMENSION} on its
 * longer side, then smaller until it fits {@link MAX_LOGO_BYTES}.
 */
export async function prepareLogo(
  file: Blob & { name?: string },
  deps: LogoDeps = browserDeps,
): Promise<{ mediaType: "image/png"; bytes: Uint8Array; width: number; height: number }> {
  if (file.size > MAX_LOGO_FILE_BYTES) {
    throw new LogoError("That file is larger than 1 MB. Choose a smaller logo.");
  }
  const svg = isSvg(file);
  if (!svg && !RASTER_TYPES.includes(file.type)) {
    throw new LogoError("Choose a logo: a PNG, JPEG, WebP or SVG image.");
  }
  let image: Drawable;
  try {
    image = svg ? await deps.decodeSvg(svgDataUrl(await file.text())) : await deps.decodeRaster(file);
  } catch {
    throw new LogoError("This browser can't read that image. Try a PNG.");
  }
  try {
    if (!(image.width > 0 && image.height > 0)) {
      throw new LogoError("That image has no size to draw.");
    }
    for (const size of SIZES) {
      const [width, height] = fitWithin(image.width, image.height, size);
      const bytes = await deps.encodePng(image, width, height);
      if (bytes.length <= MAX_LOGO_BYTES) return { mediaType: "image/png", bytes, width, height };
    }
    throw new LogoError("That logo is too detailed to send, even made smaller.");
  } finally {
    image.close?.();
  }
}

const browserDeps: LogoDeps = {
  async decodeRaster(file) {
    const bitmap = await createImageBitmap(file);
    return { source: bitmap, width: bitmap.width, height: bitmap.height, close: () => bitmap.close() };
  },
  async decodeSvg(dataUrl) {
    const img = new Image();
    img.decoding = "async";
    img.src = dataUrl;
    await img.decode();
    // An SVG without width/height reports no intrinsic size: draw it into a
    // square box, keeping its aspect ratio where the browser knows it.
    const w = img.naturalWidth || DEFAULT_SVG_BOX;
    const h = img.naturalHeight || (img.naturalWidth ? img.naturalWidth : DEFAULT_SVG_BOX);
    return { source: img, width: w, height: h };
  },
  async encodePng(image, width, height) {
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new LogoError("This browser can't draw the logo.");
    ctx.drawImage(image.source, 0, 0, width, height);
    const blob = await new Promise<Blob | null>((r) => canvas.toBlob(r, "image/png"));
    if (!blob) throw new LogoError("This browser can't encode the logo as PNG.");
    return new Uint8Array(await blob.arrayBuffer());
  },
};
