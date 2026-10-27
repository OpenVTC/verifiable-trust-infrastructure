// Directory pictures in the browser: making one small enough to send, and
// showing one the community answered.
//
// A community keeps no more of a picture than it shows, and refuses one over
// 256 KiB (`vtc/directory/images/upload`). So the portal scales a picture down
// before it leaves the browser — what the specification asks of a producer —
// and the community re-encodes whatever arrives, stripping every metadata
// block. A picture is read only through `vtc/directory/images/get`, which
// answers where the member's choice lets this reader see it; it is shown as a
// `data:` URL, never fetched from anywhere else.

/** The most a picture may be, sent or stored. */
export const MAX_PICTURE_BYTES = 262_144;

/** The longer side a picture is scaled to before it is sent. */
export const SEND_DIMENSION = 1024;

export const PICTURE_TYPES = ["image/png", "image/jpeg", "image/webp"] as const;
export type PictureType = (typeof PICTURE_TYPES)[number];

/** Base64url without padding (RFC 4648 §5), as `images/upload` takes it. */
export function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A `data:` URL for base64url picture bytes. */
export function pictureUrl(mediaType: string, base64url: string): string {
  const b64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return `data:${mediaType};base64,${padded}`;
}

async function bytesOf(blob: Blob): Promise<Uint8Array> {
  if (typeof blob.arrayBuffer === "function") return new Uint8Array(await blob.arrayBuffer());
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(blob);
  });
}

/** Why a picture cannot be sent, in the member's words. */
export class PictureError extends Error {}

/**
 * The bytes to send for `file`: as chosen when it is already a small picture
 * of a type the community reads, otherwise drawn onto a canvas no larger than
 * {@link SEND_DIMENSION} and encoded as JPEG, lowering the quality until it
 * fits.
 */
export async function prepare(file: Blob): Promise<{ mediaType: PictureType; bytes: Uint8Array }> {
  const type = file.type as PictureType;
  if (PICTURE_TYPES.includes(type) && file.size <= MAX_PICTURE_BYTES) {
    return { mediaType: type, bytes: await bytesOf(file) };
  }
  if (!file.type.startsWith("image/")) {
    throw new PictureError("Choose a picture: a PNG, JPEG or WebP image.");
  }
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    throw new PictureError("This browser can't read that picture. Try a PNG or JPEG.");
  }
  const scale = Math.min(1, SEND_DIMENSION / Math.max(bitmap.width, bitmap.height));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(bitmap.width * scale));
  canvas.height = Math.max(1, Math.round(bitmap.height * scale));
  canvas.getContext("2d")?.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close();
  for (const quality of [0.85, 0.75, 0.6, 0.45]) {
    const blob = await new Promise<Blob | null>((r) => canvas.toBlob(r, "image/jpeg", quality));
    if (blob && blob.size <= MAX_PICTURE_BYTES) {
      return { mediaType: "image/jpeg", bytes: await bytesOf(blob) };
    }
  }
  throw new PictureError("That picture is too large to send, even made smaller.");
}
