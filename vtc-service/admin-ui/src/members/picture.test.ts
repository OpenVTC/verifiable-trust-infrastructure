import { describe, expect, it } from "vitest";

import { MAX_PICTURE_BYTES, PictureError, pictureUrl, prepare, toBase64Url } from "./picture";

describe("directory pictures in the browser", () => {
  it("encodes base64url without padding, and reads it back as a data URL", () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf, 0x01]);
    const b64u = toBase64Url(bytes);
    expect(b64u).toBe("-_-_AQ");
    expect(pictureUrl("image/png", b64u)).toBe("data:image/png;base64,+/+/AQ==");
  });

  it("sends a small picture of a type the community reads as chosen", async () => {
    const file = new Blob([new Uint8Array([1, 2, 3])], { type: "image/png" });
    const sent = await prepare(file);
    expect(sent.mediaType).toBe("image/png");
    expect(Array.from(sent.bytes)).toEqual([1, 2, 3]);
  });

  it("refuses what is not a picture before sending anything", async () => {
    const file = new Blob([new Uint8Array(MAX_PICTURE_BYTES + 1)], { type: "application/pdf" });
    await expect(prepare(file)).rejects.toBeInstanceOf(PictureError);
  });
});
