import { describe, expect, it, vi } from "vitest";

import {
  LOGO_DIMENSION,
  LogoError,
  MAX_LOGO_BYTES,
  MAX_LOGO_FILE_BYTES,
  fitWithin,
  isSvg,
  prepareLogo,
  svgDataUrl,
  type Drawable,
  type LogoDeps,
} from "./logo-upload";

function deps(over: Partial<LogoDeps> = {}, image: Partial<Drawable> = {}): LogoDeps {
  const drawable: Drawable = { source: {} as CanvasImageSource, width: 1000, height: 500, ...image };
  return {
    decodeRaster: vi.fn(async () => drawable),
    decodeSvg: vi.fn(async () => drawable),
    encodePng: vi.fn(async (_i: Drawable, w: number, h: number) => new Uint8Array(w + h)),
    ...over,
  };
}

function file(type: string, size = 10, name?: string): Blob & { name?: string } {
  const blob = new Blob([new Uint8Array(size)], { type }) as Blob & { name?: string };
  if (name) Object.defineProperty(blob, "name", { value: name });
  return blob;
}

describe("preparing a community logo", () => {
  it("draws a raster image as PNG at most 512 pixels on the longer side", async () => {
    const d = deps();
    const sent = await prepareLogo(file("image/jpeg"), d);
    expect(sent.mediaType).toBe("image/png");
    expect([sent.width, sent.height]).toEqual([LOGO_DIMENSION, 256]);
    expect(d.decodeSvg).not.toHaveBeenCalled();
  });

  it("never scales a small logo up", () => {
    expect(fitWithin(40, 20, LOGO_DIMENSION)).toEqual([40, 20]);
    expect(fitWithin(2048, 1024, LOGO_DIMENSION)).toEqual([512, 256]);
  });

  it("rasterizes an SVG from a data: URL, never a blob: one, and never sends the SVG", async () => {
    const d = deps();
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>';
    const blob = new Blob([svg], { type: "image/svg+xml" });
    const sent = await prepareLogo(blob, d);
    const url = (d.decodeSvg as ReturnType<typeof vi.fn>).mock.calls[0]![0] as string;
    expect(url.startsWith("data:image/svg+xml;base64,")).toBe(true);
    expect(atob(url.slice(url.indexOf(",") + 1))).toBe(svg);
    expect(sent.mediaType).toBe("image/png");
    expect(d.decodeRaster).not.toHaveBeenCalled();
  });

  it("recognizes an SVG by its name when the browser gives it no type", () => {
    expect(isSvg(file("", 10, "logo.SVG"))).toBe(true);
    expect(isSvg(file("image/png", 10, "logo.png"))).toBe(false);
    expect(svgDataUrl("é")).toBe("data:image/svg+xml;base64,w6k=");
  });

  it("steps down in size until the PNG fits", async () => {
    const encodePng = vi.fn(async (_i: Drawable, w: number) =>
      new Uint8Array(w > 256 ? MAX_LOGO_BYTES + 1 : 100),
    );
    const sent = await prepareLogo(file("image/png"), deps({ encodePng }));
    expect(sent.width).toBe(256);
    expect(encodePng).toHaveBeenCalledTimes(3);
  });

  it("refuses what it will not send before drawing anything", async () => {
    const d = deps();
    await expect(prepareLogo(file("application/pdf"), d)).rejects.toBeInstanceOf(LogoError);
    await expect(prepareLogo(file("image/gif"), d)).rejects.toBeInstanceOf(LogoError);
    await expect(prepareLogo(file("image/png", MAX_LOGO_FILE_BYTES + 1), d)).rejects.toBeInstanceOf(
      LogoError,
    );
    expect(d.decodeRaster).not.toHaveBeenCalled();
    expect(d.decodeSvg).not.toHaveBeenCalled();
  });

  it("says so when the browser cannot read the image", async () => {
    const d = deps({ decodeRaster: vi.fn(async () => Promise.reject(new Error("bad"))) });
    await expect(prepareLogo(file("image/png"), d)).rejects.toBeInstanceOf(LogoError);
  });
});
