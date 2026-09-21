import { describe, expect, it } from "vitest";

import {
  claimedDigest,
  credentialDocuments,
  credentialId,
  unboundReason,
} from "./member-credentials";
import type { MemberCredentials } from "./wire-types";

const DID = "did:key:z6MkMember";

// The wire type describes the opaque bodies as `Record<string, never>`; a
// fixture has to say what a real one carries, so it goes through `unknown`.
function creds(v: Record<string, unknown>): MemberCredentials {
  return { did: DID, memberVmcBound: false, ...v } as unknown as MemberCredentials;
}

const grant = { id: "urn:uuid:grant", credentialSubject: { id: DID } };

describe("claimedDigest", () => {
  it("reads the WD02 spelling first", () => {
    expect(
      claimedDigest({
        credentialSubject: { digestMultibase: "zQm1", digest: "sha256:ab" },
      }),
    ).toEqual({ property: "credentialSubject.digestMultibase", value: "zQm1" });
  });

  it("falls back to the WD01 spelling", () => {
    expect(claimedDigest({ credentialSubject: { digest: "sha256:ab" } })).toEqual({
      property: "credentialSubject.digest",
      value: "sha256:ab",
    });
  });

  it("is absent when the acknowledgement names none", () => {
    expect(claimedDigest({ credentialSubject: { id: "did:web:c" } })).toBeUndefined();
    expect(claimedDigest(undefined)).toBeUndefined();
  });
});

describe("unboundReason", () => {
  it("is undefined for a bound edge", () => {
    expect(unboundReason(creds({ memberVmcBound: true }))).toBeUndefined();
  });

  it("names a missing acknowledgement first", () => {
    expect(unboundReason(creds({ membershipCredential: grant }))).toBe(
      "no-acknowledgement",
    );
  });

  it("names an acknowledgement without a digest", () => {
    expect(
      unboundReason(
        creds({ membershipCredential: grant, memberVmc: { credentialSubject: {} } }),
      ),
    ).toBe("no-digest");
  });

  it("names a missing grant when the acknowledgement has a digest", () => {
    expect(
      unboundReason(
        creds({ memberVmc: { credentialSubject: { digestMultibase: "zQm1" } } }),
      ),
    ).toBe("no-grant");
  });

  it("falls through to an unchecked row when both are present", () => {
    expect(
      unboundReason(
        creds({
          membershipCredential: grant,
          memberVmc: { credentialSubject: { digestMultibase: "zQm1" } },
        }),
      ),
    ).toBe("unchecked");
  });
});

describe("credentialDocuments", () => {
  it("lists only what is present, grant before acknowledgement", () => {
    const docs = credentialDocuments(
      creds({ roleCredential: { id: "urn:uuid:role" }, membershipCredential: grant }),
    );
    expect(docs.map((d) => d.key)).toEqual(["membershipCredential", "roleCredential"]);
    expect(credentialId(docs[0]?.doc)).toBe("urn:uuid:grant");
  });
});
