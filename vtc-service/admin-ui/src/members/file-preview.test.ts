// What a verified room file may be shown as in the portal — decided by its
// bytes, never by the type its author claimed — and the queue thumbnails go
// through. Mirrors the browser wallet's own tests of the same rules.

import { describe, expect, it } from "vitest";

import {
  AUTO_PREVIEW_MAX_BYTES,
  TEXT_PREVIEW_MAX_CHARS,
  createLimiter,
  imageDataUrl,
  mayPreview,
  previewKind,
  showBytes,
  textOf,
  worthAutoPreview,
} from "./file-preview";

const bytes = (...xs: (number | string)[]) =>
  new Uint8Array(xs.flatMap((x) => (typeof x === "string" ? [...x].map((ch) => ch.charCodeAt(0)) : [x])));

describe("file previews", () => {
  it("raster images are recognised by their signature", () => {
    expect(previewKind(bytes(0x89, "PNG", 0x0d, 0x0a, 0x1a, 0x0a, 0))).toBe("png");
    expect(previewKind(bytes(0xff, 0xd8, 0xff, 0xe0))).toBe("jpeg");
    expect(previewKind(bytes("GIF87a", 1))).toBe("gif");
    expect(previewKind(bytes("GIF89a", 1))).toBe("gif");
    expect(previewKind(bytes("RIFF", 0, 0, 0, 0, "WEBPVP8 "))).toBe("webp");
    expect(previewKind(bytes("RIFF", 0, 0, 0, 0, "WAVEfmt ", 0))).toBeNull();
  });

  // The ones a preview must never draw, whatever a record says they are.
  it("markup and documents are never drawn", () => {
    const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
    expect(previewKind(svg)).toBe("text"); // shown as its text, never drawn
    const html = new TextEncoder().encode("<html><body><script>alert(1)</script></body></html>");
    expect(previewKind(html)).toBe("text");
    expect(previewKind(bytes("%PDF-1.7", 0, 1, 2))).toBeNull();
    expect(previewKind(bytes("PK", 3, 4, 0, 0))).toBeNull(); // a .docx is a zip
  });

  it("text is UTF-8 with no control characters", () => {
    expect(textOf(new TextEncoder().encode('Settled on "Trustie"\n\tdone\r\n'))).toBe('Settled on "Trustie"\n\tdone\r\n');
    expect(textOf(bytes(0xc3, 0x28))).toBeNull(); // not UTF-8
    expect(textOf(bytes("a", 0x1b, "[31m"))).toBeNull(); // an escape sequence is not plain text
    expect(textOf(bytes("a", 0, "b"))).toBeNull();
    expect(textOf(bytes("a", 0x7f))).toBeNull();
  });

  it("an image is drawn from a data: URL typed by its bytes", () => {
    const png = bytes(0x89, "PNG", 0x0d, 0x0a, 0x1a, 0x0a, 0);
    expect(imageDataUrl(png, "png")).toBe(`data:image/png;base64,${btoa(String.fromCharCode(...png))}`);
    const shown = showBytes(png);
    expect(shown.kind).toBe("image");
    expect(shown.kind === "image" && shown.url.startsWith("data:image/png;base64,")).toBe(true);
  });

  it("a large image encodes whole", () => {
    const big = new Uint8Array(200_000);
    big.set([0xff, 0xd8, 0xff]);
    const url = imageDataUrl(big, "jpeg");
    expect(url.startsWith("data:image/jpeg;base64,/9j/")).toBe(true);
    expect(atob(url.slice(url.indexOf(",") + 1)).length).toBe(big.length);
  });

  it("text is cut at the bound; anything else is download only", () => {
    const long = new TextEncoder().encode("x".repeat(TEXT_PREVIEW_MAX_CHARS + 5));
    expect(showBytes(long)).toEqual({ kind: "text", text: "x".repeat(TEXT_PREVIEW_MAX_CHARS), cut: true });
    expect(showBytes(bytes("%PDF-1.7", 0))).toEqual({ kind: "none" });
  });

  it("only small pictures are fetched unasked; the claim only decides whether to fetch", () => {
    expect(worthAutoPreview({ name: "a.png", size: 1000, mediaType: "image/png" })).toBe(true);
    expect(worthAutoPreview({ name: "a.jpg", size: 1000 })).toBe(true);
    expect(worthAutoPreview({ name: "a.png", size: AUTO_PREVIEW_MAX_BYTES + 1, mediaType: "image/png" })).toBe(false);
    expect(worthAutoPreview({ name: "a.svg", size: 1000, mediaType: "image/svg+xml" })).toBe(false);
    expect(worthAutoPreview({ name: "a.pdf", size: 1000, mediaType: "application/pdf" })).toBe(false);
    expect(mayPreview({ name: "notes.md" })).toBe(true);
    expect(mayPreview({ name: "x", mediaType: "text/plain" })).toBe(true);
    expect(mayPreview({ name: "deck.pptx" })).toBe(false);
    expect(mayPreview({ name: "terms.pdf", mediaType: "application/pdf" })).toBe(false);
  });
});

describe("the thumbnail queue", () => {
  it("runs a few at a time, in the order asked", async () => {
    const limit = createLimiter(2);
    let running = 0;
    let most = 0;
    const order: number[] = [];
    const task = (n: number) => () =>
      new Promise<number>((resolve) => {
        running++;
        most = Math.max(most, running);
        order.push(n);
        setTimeout(() => {
          running--;
          resolve(n);
        }, 5);
      });
    const results = await Promise.all([1, 2, 3, 4, 5].map((n) => limit.run(task(n))));
    expect(results).toEqual([1, 2, 3, 4, 5]);
    expect(order).toEqual([1, 2, 3, 4, 5]);
    expect(most).toBe(2);
  });

  it("a failed task does not stall the queue", async () => {
    const limit = createLimiter(1);
    await expect(limit.run(() => Promise.reject(new Error("host refused")))).rejects.toThrow("host refused");
    await expect(
      limit.run(() => {
        throw new Error("thrown before a promise");
      }),
    ).rejects.toThrow("thrown before");
    expect(await limit.run(async () => "next")).toBe("next");
  });
});
