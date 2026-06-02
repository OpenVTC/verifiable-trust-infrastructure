// Ceremony manifest — the thin registry.
//
// A ceremony is one instance of the decision pipeline (TRIGGER → GATHER
// → VERIFY → FACTS → EVALUATE(<purpose>.rego) → VERDICT → EFFECTS). The
// pipeline is generic; what differs per ceremony is *declarative*: its
// metadata (purpose, package, nature), the simulator form fields, and
// how those fields assemble into a verified-Facts document.
//
// This module is that declaration. The Ceremonies surface renders every
// ceremony from it — no per-ceremony components — so adding a ceremony
// over an existing effect is a manifest entry, not new UI code.
//
// Deliberately thin: `buildFacts` stays a hand-written function per
// ceremony (the one piece that isn't yet pure data). A later step can
// derive it from a facts-schema served by the daemon. The *effects* a
// ceremony triggers remain reviewed Rust — this registry only describes
// the decision surface, never mutates state.

export type CeremonyKey = "directory" | "join" | "leave" | "role-change";
export type Nature = "read-only" | "constructive" | "destructive" | "mutating";
export type Wired = "live" | "legacy" | "unwired";

/** A single simulator input. `select` shows a dropdown; `toggle` a switch. */
export interface FieldDef {
  key: string;
  label: string;
  hint?: string;
  type: "select" | "toggle";
  /** Options for a `select` field. */
  options?: { value: string; label: string }[];
  default: string | boolean;
  /** Render this field only when the predicate holds (e.g. dependent fields). */
  showWhen?: (v: FieldValues) => boolean;
}

export type FieldValues = Record<string, string | boolean>;

export interface CeremonyManifest {
  key: CeremonyKey;
  label: string;
  nature: Nature;
  /** API policy purpose key, or null when the ceremony has no policy. */
  purpose: string | null;
  /** Rego package whose `decision` rule the host evaluates. */
  pkg: string;
  wired: Wired;
  blurb: string;
  /** Declarative simulator form. */
  fields: FieldDef[];
  /** Assemble the verified-Facts document the policy decides over. */
  buildFacts: (v: FieldValues) => Record<string, unknown>;
}

export const natureColor: Record<Nature, string> = {
  "read-only": "var(--brand)",
  constructive: "var(--vd-allow)",
  destructive: "var(--vd-deny)",
  mutating: "var(--vd-refer)",
};

/** The default value map for a ceremony's simulator form. */
export function defaultValues(m: CeremonyManifest): FieldValues {
  return Object.fromEntries(m.fields.map((f) => [f.key, f.default]));
}

// Shared scaffolding every ceremony's Facts doc carries.
function baseContext() {
  return {
    community_did: "did:webvh:demo.example",
    channel: "rest",
    member_count: 42,
  };
}
function memberRow(role: string) {
  return { role, status: "active", joined_at: "2026-01-02T00:00:00Z" };
}
const ROLE_OPTIONS = [
  { value: "member", label: "member" },
  { value: "moderator", label: "moderator" },
  { value: "admin", label: "admin" },
];

export const CEREMONIES: CeremonyManifest[] = [
  {
    key: "directory",
    label: "Directory",
    nature: "read-only",
    purpose: "directory",
    pkg: "vtc.directory",
    wired: "live",
    blurb:
      "A member views another member's record. Read-only — the verdict's allow carries a field projection, capped by the PII boundary.",
    fields: [
      {
        key: "viewerRole",
        label: "Viewer's community role",
        hint: "actor.role — admin sees the fuller record",
        type: "select",
        options: [
          { value: "admin", label: "admin" },
          { value: "member", label: "member" },
          { value: "", label: "none (authenticated)" },
        ],
        default: "member",
      },
      {
        key: "subjectIsMember",
        label: "Subject is a member",
        hint: "state.subject_member present",
        type: "toggle",
        default: true,
      },
      {
        key: "subjectRole",
        label: "Subject's role",
        hint: "state.subject_member.role",
        type: "select",
        options: ROLE_OPTIONS,
        default: "member",
        showWhen: (v) => v.subjectIsMember === true,
      },
    ],
    buildFacts: (v) => ({
      purpose: "directory",
      now: new Date().toISOString(),
      actor: {
        did: "did:key:zViewer",
        role: (v.viewerRole as string) || undefined,
        authenticated: true,
      },
      subject: { did: "did:key:zTarget" },
      context: baseContext(),
      evidence: {
        request: { fields_requested: ["did", "role", "joined_at", "status"] },
      },
      state: {
        subject_member: v.subjectIsMember
          ? memberRow(v.subjectRole as string)
          : null,
      },
    }),
  },
  {
    key: "join",
    label: "Join",
    nature: "constructive",
    purpose: "join",
    pkg: "vtc.join",
    wired: "live",
    blurb:
      "A DID joins the community. A trusted presented credential auto-admits (allow → issue the membership credential); everything else is referred to the moderator queue for review.",
    fields: [
      {
        key: "joinTrusted",
        label: "Presented credential is trusted",
        hint: "evidence.presentation.credentials[].issuer_trusted",
        type: "toggle",
        default: false,
      },
    ],
    buildFacts: (v) => ({
      purpose: "join",
      now: new Date().toISOString(),
      actor: { did: "did:key:zApplicant", authenticated: true },
      subject: { did: "did:key:zApplicant" },
      context: baseContext(),
      evidence: {
        presentation: {
          verified: true,
          holder: "did:key:zApplicant",
          credentials: [
            {
              type: "WitnessCredential",
              issuer: "did:webvh:notary.example",
              issuer_trusted: v.joinTrusted === true,
              status: "valid",
              claims: {},
            },
          ],
        },
      },
      state: { subject_member: null },
    }),
  },
  {
    key: "leave",
    label: "Leave",
    nature: "destructive",
    purpose: "removal",
    pkg: "vtc.removal",
    wired: "live",
    blurb:
      "A member departs or is removed. Self-leave is unconditional; an admin may remove a non-admin. The no-last-admin invariant + revocation are host-enforced in the effect.",
    fields: [
      {
        key: "selfLeave",
        label: "Self-leave",
        hint: "actor.did == subject.did — always allowed",
        type: "toggle",
        default: false,
      },
      {
        key: "subjectRole",
        label: "Subject's role",
        hint: "an admin may remove a non-admin only",
        type: "select",
        options: ROLE_OPTIONS,
        default: "member",
        showWhen: (v) => v.selfLeave !== true,
      },
    ],
    buildFacts: (v) => {
      const actorDid = "did:key:zActor";
      const subjectDid = v.selfLeave ? actorDid : "did:key:zTarget";
      return {
        purpose: "leave",
        now: new Date().toISOString(),
        actor: { did: actorDid, role: "admin", authenticated: true },
        subject: { did: subjectDid },
        context: baseContext(),
        evidence: { request: { disposition: "tombstone" } },
        state: { subject_member: memberRow(v.subjectRole as string) },
      };
    },
  },
  {
    key: "role-change",
    label: "Role change",
    nature: "mutating",
    purpose: "roleChange",
    pkg: "vtc.role_change",
    wired: "live",
    blurb:
      "A member's role changes in place (the DID + VMC are unchanged; the role VEC is re-minted). The one ceremony whose allow may grant admin — gated by a verified step-up; demotions are guarded by no-last-admin.",
    fields: [
      {
        key: "targetRole",
        label: "Target role",
        hint: "evidence.request.target_role",
        type: "select",
        options: [
          { value: "member", label: "member" },
          { value: "moderator", label: "moderator" },
          { value: "admin", label: "admin (promotion)" },
        ],
        default: "moderator",
      },
      {
        key: "stepUp",
        label: "Step-up verified",
        hint: "admin needs step-up — else the verdict refers",
        type: "toggle",
        default: false,
        showWhen: (v) => v.targetRole === "admin",
      },
    ],
    buildFacts: (v) => ({
      purpose: "role-change",
      now: new Date().toISOString(),
      actor: { did: "did:key:zAdmin", role: "admin", authenticated: true },
      subject: { did: "did:key:zTarget" },
      context: baseContext(),
      evidence: {
        request: { target_role: v.targetRole as string, step_up: v.stepUp === true },
      },
      state: { subject_member: memberRow("member") },
    }),
  },
];
