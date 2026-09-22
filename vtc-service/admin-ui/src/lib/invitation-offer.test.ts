import { describe, expect, it } from "vitest";

import { offerDeepLink } from "./invitation-offer";

const OFFER = {
  credential_issuer: "did:webvh:QmScid:community.example",
  credential_configuration_ids: ["VIC"],
  grants: {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "pac_3f9d2c1a7b6e4d5c8a0b1e2f3a4b5c6d",
    },
  },
};

describe("offerDeepLink", () => {
  it("carries the offer by value under the OID4VCI scheme", () => {
    const link = offerDeepLink(OFFER);
    expect(link.startsWith("openid-credential-offer://?credential_offer=")).toBe(true);
    const encoded = link.slice("openid-credential-offer://?credential_offer=".length);
    expect(JSON.parse(decodeURIComponent(encoded))).toEqual(OFFER);
  });

  it("fits comfortably in a QR code, which the signed invitation did not", () => {
    // A version-40 QR at level L holds ~2,953 bytes; an offer is a few hundred.
    expect(offerDeepLink(OFFER).length).toBeLessThan(600);
  });
});
