// Reading `vtc/members/credentials/0.1` for the member-detail page (#1215).
//
// The credential bodies are opaque to the schema — `type: object` and nothing
// else — so the generated wire type describes them as `Record<string, never>`.
// Everything this console needs to *say* about them is read here, in one
// place, rather than by casting at each use.
//
// Nothing here verifies anything. `memberVmcBound` is the daemon's answer,
// recorded when the acknowledgement arrived; this module only lays out the
// evidence behind it so an operator can see why an edge is incomplete.

import type { MemberCredentials } from "@/lib/wire-types";

type Doc = Record<string, unknown>;

function asDoc(v: unknown): Doc | undefined {
  return v && typeof v === "object" && !Array.isArray(v)
    ? (v as Doc)
    : undefined;
}

/** A credential's top-level `id`, when it has a string one. */
export function credentialId(doc: unknown): string | undefined {
  const id = asDoc(doc)?.["id"];
  return typeof id === "string" ? id : undefined;
}

/** The digest an acknowledgement claims for the grant it acknowledges. */
export interface ClaimedDigest {
  /** Where it was found — the two Working Drafts spell it differently. */
  property: "credentialSubject.digestMultibase" | "credentialSubject.digest";
  value: string;
}

/**
 * The digest a member-issued VMC names, in whichever spelling it used.
 *
 * Mirrors the daemon's reading order (`members/inbound_vmc.rs`): the WD02
 * `digestMultibase` first, then the WD01 `digest`. Both are shown as sent —
 * the console does not recompute the grant's digest, so it never claims the
 * two match or differ; the daemon's `memberVmcBound` is the only verdict.
 */
export function claimedDigest(memberVmc: unknown): ClaimedDigest | undefined {
  const subject = asDoc(asDoc(memberVmc)?.["credentialSubject"]);
  const multibase = subject?.["digestMultibase"];
  if (typeof multibase === "string") {
    return { property: "credentialSubject.digestMultibase", value: multibase };
  }
  const legacy = subject?.["digest"];
  if (typeof legacy === "string") {
    return { property: "credentialSubject.digest", value: legacy };
  }
  return undefined;
}

/** Why an edge is not bound — the cases the daemon's binding check can land in. */
export type UnboundReason =
  /** No acknowledgement has arrived: the member has not sent their half. */
  | "no-acknowledgement"
  /** The acknowledgement names no digest, so there was nothing to check. */
  | "no-digest"
  /** No grant body was held to check against (issued before bodies were kept). */
  | "no-grant"
  /**
   * Both a digest and a grant are present and the daemon still did not bind
   * them. A mismatch is refused at receipt, so this is a row older than the
   * check — the acknowledgement arrived before the grant it would bind to was
   * kept.
   */
  | "unchecked";

/**
 * Why `memberVmcBound` is false, from the documents the daemon returned.
 * `undefined` when the edge is bound.
 */
export function unboundReason(c: MemberCredentials): UnboundReason | undefined {
  if (c.memberVmcBound) return undefined;
  if (!c.memberVmc) return "no-acknowledgement";
  if (!claimedDigest(c.memberVmc)) return "no-digest";
  if (!c.membershipCredential) return "no-grant";
  return "unchecked";
}

/** One stored document, labelled for display. */
export interface CredentialDocument {
  key: "membershipCredential" | "roleCredential" | "memberVmc";
  label: string;
  doc: Doc;
}

/** The documents present in a response, in the order an operator reads the pair. */
export function credentialDocuments(c: MemberCredentials): CredentialDocument[] {
  const out: CredentialDocument[] = [];
  const push = (key: CredentialDocument["key"], label: string, v: unknown) => {
    const doc = asDoc(v);
    if (doc) out.push({ key, label, doc });
  };
  push("membershipCredential", "Membership credential (VTC → member) — the grant", c.membershipCredential);
  push("memberVmc", "Member VMC (member → VTC) — the acknowledgement", c.memberVmc);
  push("roleCredential", "Role credential (VEC)", c.roleCredential);
  return out;
}
