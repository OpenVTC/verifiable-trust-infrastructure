// The community's OpenID4VP verifier identities, as administrators see them
// (`vtc/oid4vp/identities/list/0.1`, #1988).
//
// The response is a generated spec type with no OpenAPI schema to alias, so
// its shape is written out here, member for member, from
// `specs/vtc/oid4vp/identities/list/0.1/payload.schema.json`. Every enum is
// open (`| string`): a newer daemon may report a problem this console does not
// know, and it is shown by its code rather than dropped.

import { postSignedRead } from "@/lib/api";

export const TASK_IDENTITIES_LIST =
  "https://trusttasks.org/spec/vtc/oid4vp/identities/list/0.1";

export type ProblemSeverity = "error" | "warning";

export interface VerifierProblem {
  code: string;
  severity: ProblemSeverity | string;
  /** Prose for the administrator, often naming the command that fixes it. */
  detail?: string;
}

export interface VerifierCertificate {
  subject?: string;
  issuer?: string;
  notBefore: string;
  notAfter: string;
  chainLength: number;
}

export interface VerifierAttestation {
  kind:
    | "identityTrustStatement"
    | "protectedVerificationAuthorization"
    | "registrationCertificate"
    | "other"
    | string;
  expiresAt?: string | null;
}

export interface VerifierIdentity {
  id: string;
  kind: "swiyu" | "eudi" | string;
  clientId?: string | null;
  did?: string | null;
  keyId?: string | null;
  custody: "cached" | "agent" | "invalid" | string;
  usable: boolean;
  isDefault: boolean;
  certificate?: VerifierCertificate;
  attestations: VerifierAttestation[];
  problems: VerifierProblem[];
  installedAt: string;
}

export interface VerifierIdentitiesResponse {
  identities: VerifierIdentity[];
  defaultIdentity?: string | null;
  problems: VerifierProblem[];
}

export const verifierKeys = {
  list: ["oid4vp", "identities"] as const,
};

export const fetchVerifierIdentities = (): Promise<VerifierIdentitiesResponse> =>
  postSignedRead<VerifierIdentitiesResponse>(TASK_IDENTITIES_LIST, {});

const PROBLEM_TITLES: Record<string, string> = {
  keyCustodyInvalid: "Key record is invalid",
  signerNotLoaded: "Not loaded — restart needed",
  agentLinkMissing: "No link to the VTA",
  certificateMissing: "No access certificate",
  certificateNotYetValid: "Certificate not yet valid",
  certificateExpired: "Certificate expired",
  certificateExpiresSoon: "Certificate expires soon",
  identityStatementMissing: "No identity trust statement",
  statementExpired: "Statement expired",
  statementExpiresSoon: "Statement expires soon",
  defaultIdentityNotInstalled: "Default identity not installed",
  noPublicUrl: "No https public URL",
};

/** A short title for a problem code; an unknown code is shown as itself. */
export function problemTitle(code: string): string {
  return PROBLEM_TITLES[code] ?? code;
}

const ATTESTATION_LABELS: Record<string, string> = {
  identityTrustStatement: "Identity trust statement",
  protectedVerificationAuthorization: "Protected verification authorization",
  registrationCertificate: "Registration certificate",
  other: "Other",
};

export function attestationLabel(kind: string): string {
  return ATTESTATION_LABELS[kind] ?? kind;
}

/** Errors first, then warnings, each in the order the daemon gave them. */
export function worstFirst(problems: VerifierProblem[]): VerifierProblem[] {
  const rank = (p: VerifierProblem) => (p.severity === "error" ? 0 : 1);
  return [...problems].sort((a, b) => rank(a) - rank(b));
}

/** How the identity's row is summarised: what an administrator reads first. */
export function identityState(
  identity: VerifierIdentity,
): "ready" | "attention" | "broken" {
  if (!identity.usable) return "broken";
  return identity.problems.length > 0 ? "attention" : "ready";
}
