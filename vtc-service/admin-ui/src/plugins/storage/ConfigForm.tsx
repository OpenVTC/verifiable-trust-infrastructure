// A new storage config, or a change to one (`vtc/storage/configs/{create,update}`).
//
// Three kinds are served: `local` (a directory beneath one of the host's
// `local_storage_bases`), `s3` and `gcs`. An object store authenticates one of three
// ways (`vtc/storage/configs/create/0.2`):
//
// - `vta-account` (S3, recommended): an external account at the community's VTA,
//   named by its context and identifier; the VTA keeps the key.
// - `ambient`: this machine's own cloud identity — on S3 optionally assuming a
//   named role (`roleArn`) — downscoped to one room for at most 15 minutes.
// - `sealed` (discouraged): a long-lived credential the community keeps, set
//   afterwards on the config's page (sealed in the browser, `SetCredential.tsx`) or
//   with `cnm storage credentials set`. Labelled, wherever it is shown, as
//   no protection against whoever operates the community's machine.
//
// `ambient` and `sealed` are the host operator's to permit; a community whose host
// does not answers `authNotAllowed`. This form asks for nothing secret, ever.
// `walrus` is not offered until the VTC serves it.
//
// Both writes take an operation-bound step-up and are parked for the other
// holders of `vtc.rooms.admin`; the caller shows the parked notice.

import { useState, type FormEvent } from "react";

import { Field } from "@/components/Field";
import { exactBytes, formatBytes, parseBytes } from "@/lib/rooms-api";
import {
  BUCKET_PATTERN,
  CONFIG_ID_PATTERN,
  GCS_BUCKET_PATTERN,
  KIND_MEANS,
  PREFIX_PATTERN,
  REGION_PATTERN,
  ROLE_ARN_PATTERN,
  SEALED_WARNING,
} from "@/lib/storage-api";
import type {
  StorageAuth,
  StorageConfigCreatePayload,
  StorageConfigRecord,
  StorageConfigUpdatePayload,
  StorageSettings,
} from "@/lib/wire-types";

const REASON_MAX = 500;
const LABEL_MAX = 128;
const MODE_LABEL: Record<Mode, string> = {
  "vta-account": "Through the community's VTA (recommended)",
  ambient: "This machine's own cloud identity",
  sealed: "A stored credential (discouraged)",
};

const MODE_MEANS: Record<Mode, string> = {
  "vta-account":
    "The VTA keeps the key in an external account and signs one request per file, for five minutes. Create the account on the VTA and bind it to this community first (pnm external …).",
  ambient:
    "An instance role or workload identity, scoped by the community to one room for at most 15 minutes. Only where this community's host permits it.",
  sealed:
    "A long-lived key the community keeps, encrypted, and uses to mint room-scoped credentials where the store can. Only where this community's host permits it.",
};

/** An account's context and identifier at the VTA (`ExternalAccountId`). */
const ACCOUNT_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

type Kind = "local" | "s3" | "gcs";
type Mode = "vta-account" | "ambient" | "sealed";

/** Every field as typed, so a half-filled form survives switching kind. */
interface Draft {
  id: string;
  label: string;
  kind: Kind;
  root: string;
  bucket: string;
  region: string;
  endpoint: string;
  prefix: string;
  pathStyle: boolean;
  mode: Mode;
  roleArn: string;
  context: string;
  account: string;
  capacity: string;
  isDefault: boolean;
  reason: string;
}

const EMPTY: Draft = {
  id: "",
  label: "",
  kind: "s3",
  root: "",
  bucket: "",
  region: "",
  endpoint: "",
  prefix: "",
  pathStyle: false,
  mode: "vta-account",
  roleArn: "",
  context: "",
  account: "",
  capacity: "",
  isDefault: false,
  reason: "",
};

/** The modes a kind takes: Google Cloud Storage has no VTA account model. */
export function modesFor(kind: Kind): Mode[] {
  return kind === "gcs" ? ["ambient", "sealed"] : kind === "s3" ? ["vta-account", "ambient", "sealed"] : [];
}

/** What is wrong with each field, `null` where nothing is. Exported for tests. */
export function draftErrors(d: Draft, editing: boolean): Partial<Record<keyof Draft, string>> {
  const e: Partial<Record<keyof Draft, string>> = {};
  if (!editing && !CONFIG_ID_PATTERN.test(d.id)) {
    e.id = "Lowercase letters, digits and inner hyphens, at most 64. It can never change.";
  }
  if (d.label.trim() === "" || d.label.trim().length > LABEL_MAX) {
    e.label = `A name for administrators, at most ${LABEL_MAX} characters.`;
  }
  if (!editing && d.kind === "local" && !d.root.startsWith("/")) {
    e.root = "An absolute path beneath one of this host's local storage bases.";
  }
  if (!editing && d.kind === "s3") {
    if (!BUCKET_PATTERN.test(d.bucket)) e.bucket = "An S3 bucket name: 3–63 lowercase letters, digits, '.' and '-'.";
    if (!REGION_PATTERN.test(d.region)) e.region = "The region as the store names it: eu-west-1, or auto for R2.";
    if (d.endpoint !== "" && !/^https:\/\/\S+$/.test(d.endpoint)) {
      e.endpoint = "HTTPS only. Leave empty for AWS S3.";
    }
    if (d.mode === "ambient" && d.endpoint !== "") {
      e.endpoint = "The machine's own identity reaches AWS S3 only. Use a VTA account or a sealed key for another store.";
    }
  }
  if (!editing && (d.kind === "s3" || d.kind === "gcs")) {
    if (d.kind === "gcs" && !GCS_BUCKET_PATTERN.test(d.bucket)) e.bucket = "A Cloud Storage bucket name: lowercase letters, digits, '.', '_' and '-'.";
    if (d.prefix !== "" && !PREFIX_PATTERN.test(d.prefix)) {
      e.prefix = "Lowercase segments, each ending in '/': rooms-data/ or vtc/prod/.";
    }
  }
  if (d.kind !== "local" && !modesFor(d.kind).includes(d.mode)) {
    e.mode = "Choose how the community authenticates to this store.";
  }
  if (d.kind !== "local" && d.mode === "vta-account") {
    if (!ACCOUNT_PATTERN.test(d.context)) e.context = "The VTA context that owns the account.";
    if (!ACCOUNT_PATTERN.test(d.account)) e.account = "The account's identifier at the VTA.";
  }
  if (d.kind === "s3" && d.mode === "ambient" && d.roleArn !== "" && !ROLE_ARN_PATTERN.test(d.roleArn)) {
    e.roleArn = "An IAM role ARN: arn:aws:iam::123456789012:role/name. Empty to use the host's.";
  }
  if (parseBytes(d.capacity) === null) e.capacity = "A size such as 500 GB, or empty for none.";
  const reason = d.reason.trim();
  if (reason === "" || reason.length > REASON_MAX) {
    e.reason = `Required, at most ${REASON_MAX} characters. Shown to the approvers.`;
  }
  return e;
}

/** The `auth` a draft names, absent for `local`. */
export function authOf(d: Draft): StorageAuth | undefined {
  if (d.kind === "local") return undefined;
  switch (d.mode) {
    case "vta-account":
      return { mode: "vta-account", context: d.context, account: d.account };
    case "ambient":
      return d.kind === "s3" && d.roleArn !== "" ? { mode: "ambient", roleArn: d.roleArn } : { mode: "ambient" };
    case "sealed":
      return { mode: "sealed" };
  }
}

function settingsOf(d: Draft): StorageSettings {
  if (d.kind === "local") return { kind: "local", root: d.root };
  if (d.kind === "gcs") {
    return { kind: "gcs", bucket: d.bucket, ...(d.prefix ? { prefix: d.prefix } : {}) };
  }
  return {
    kind: "s3",
    bucket: d.bucket,
    region: d.region,
    ...(d.endpoint ? { endpoint: d.endpoint } : {}),
    ...(d.prefix ? { prefix: d.prefix } : {}),
    ...(d.pathStyle ? { pathStyle: true } : {}),
  };
}

/** The create payload a valid draft makes. */
export function createPayload(d: Draft): StorageConfigCreatePayload {
  const capacity = parseBytes(d.capacity);
  const auth = authOf(d);
  return {
    id: d.id,
    label: d.label.trim(),
    reason: d.reason.trim(),
    settings: settingsOf(d),
    ...(auth ? { auth } : {}),
    ...(typeof capacity === "number" ? { capacityBytes: capacity } : {}),
    ...(d.isDefault ? { isDefault: true } : {}),
  };
}

/**
 * The update payload: only what changed. `isDefault` is only ever set, never
 * cleared — a community always has a default, and making another config the
 * default is how this one stops being it.
 */
export function updatePayload(d: Draft, current: StorageConfigRecord): StorageConfigUpdatePayload {
  const capacity = parseBytes(d.capacity);
  const label = d.label.trim();
  // How it authenticates may change — the way off a mode the host withdrew
  // (`update/0.2` item 8). Sent only when it differs.
  const auth = authOf(d);
  const authChanged = auth !== undefined && JSON.stringify(auth) !== JSON.stringify(current.auth ?? null);
  return {
    configId: current.id,
    reason: d.reason.trim(),
    ...(label !== current.label ? { label } : {}),
    ...(authChanged ? { auth } : {}),
    ...(typeof capacity === "number" && capacity !== current.capacityBytes
      ? { capacityBytes: capacity }
      : {}),
    ...(d.isDefault && !current.isDefault ? { isDefault: true } : {}),
  };
}

function draftOf(current: StorageConfigRecord | undefined): Draft {
  if (!current) return EMPTY;
  const auth = current.auth;
  return {
    ...EMPTY,
    id: current.id,
    label: current.label,
    kind: current.settings.kind === "local" ? "local" : current.settings.kind === "gcs" ? "gcs" : "s3",
    mode: auth?.mode ?? "vta-account",
    roleArn: auth?.mode === "ambient" ? (auth.roleArn ?? "") : "",
    context: auth?.mode === "vta-account" ? auth.context : "",
    account: auth?.mode === "vta-account" ? auth.account : "",
    capacity: current.capacityBytes !== undefined ? exactBytes(current.capacityBytes) : "",
    isDefault: current.isDefault ?? false,
  };
}

export function ConfigForm({
  current,
  busy,
  onSubmit,
  onCancel,
}: {
  /** The config being changed; absent for a new one. */
  current?: StorageConfigRecord;
  busy: boolean;
  onSubmit: (payload: StorageConfigCreatePayload | StorageConfigUpdatePayload) => void;
  onCancel: () => void;
}) {
  const editing = current !== undefined;
  const [d, setD] = useState<Draft>(() => draftOf(current));
  const [touched, setTouched] = useState(false);
  const errors = draftErrors(d, editing);
  const valid = Object.keys(errors).length === 0;
  const unchanged = editing && Object.keys(updatePayload(d, current)).length === 2;
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((x) => ({ ...x, [k]: v }));
  const err = (k: keyof Draft) => (touched ? errors[k] : undefined);
  const capacity = parseBytes(d.capacity);

  function submit(e: FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!valid || unchanged || busy) return;
    onSubmit(editing ? updatePayload(d, current) : createPayload(d));
  }

  return (
    <form className="storage-form" onSubmit={submit} noValidate>
      {!editing && (
        <fieldset className="storage-kind">
          <legend className="field-label">Kind</legend>
          {(["s3", "gcs", "local"] as const).map((k) => (
            <label key={k}>
              <input
                type="radio"
                name="kind"
                checked={d.kind === k}
                onChange={() =>
                  setD((x) => ({ ...x, kind: k, mode: modesFor(k).includes(x.mode) ? x.mode : (modesFor(k)[0] ?? x.mode) }))
                }
              />{" "}
              {k === "s3" ? "S3-compatible" : k === "gcs" ? "Google Cloud Storage" : "A directory on this host"}
              <div className="muted rooms-sub">{KIND_MEANS[k]}</div>
            </label>
          ))}
        </fieldset>
      )}

      <div className="storage-fields">
        {!editing && (
          <Field label="Identifier" hint="eu-s3-primary. Files name their storage by it, so it never changes." error={err("id")}>
            <input value={d.id} onChange={(e) => set("id", e.target.value)} autoComplete="off" />
          </Field>
        )}
        <Field label="Label" hint="EU — S3 (main account)" error={err("label")}>
          <input value={d.label} onChange={(e) => set("label", e.target.value)} />
        </Field>
      </div>

      {!editing && d.kind === "local" && (
        <Field
          label="Directory"
          hint="Absolute, beneath one of this host's local_storage_bases, and not inside another config's directory."
          error={err("root")}
        >
          <input value={d.root} onChange={(e) => set("root", e.target.value)} placeholder="/var/lib/vtc/room-storage/main" />
        </Field>
      )}

      {d.kind !== "local" && (
        <fieldset className="storage-kind">
          <legend className="field-label">How the community authenticates</legend>
          {modesFor(d.kind).map((m) => (
            <label key={m}>
              <input type="radio" name="mode" checked={d.mode === m} onChange={() => set("mode", m)} />{" "}
              {MODE_LABEL[m]}
              <div className="muted rooms-sub">{MODE_MEANS[m]}</div>
            </label>
          ))}
          {err("mode") && <p className="field-error">{err("mode")}</p>}
        </fieldset>
      )}

      {d.kind !== "local" && d.mode === "sealed" && (
        <p className="storage-warning" role="note">
          {SEALED_WARNING} Set the credential on this storage's page once this is approved:
          it is sealed in the browser to this community before it is sent.
        </p>
      )}

      {d.kind !== "local" && (
        <div className="storage-fields">
          {d.mode === "vta-account" && (
            <>
              <Field label="VTA context" error={err("context")}>
                <input value={d.context} onChange={(e) => set("context", e.target.value)} autoComplete="off" />
              </Field>
              <Field label="VTA account" error={err("account")}>
                <input value={d.account} onChange={(e) => set("account", e.target.value)} autoComplete="off" />
              </Field>
            </>
          )}
          {d.kind === "s3" && d.mode === "ambient" && (
            <Field
              label="Role to assume"
              hint="Optional. The IAM role this machine's identity assumes for each room; empty for the one the host names."
              error={err("roleArn")}
            >
              <input
                value={d.roleArn}
                onChange={(e) => set("roleArn", e.target.value)}
                placeholder="arn:aws:iam::123456789012:role/rooms-writer"
                autoComplete="off"
              />
            </Field>
          )}
        </div>
      )}

      {!editing && d.kind !== "local" && (
        <>
          <div className="storage-fields">
            <Field label="Bucket" error={err("bucket")}>
              <input value={d.bucket} onChange={(e) => set("bucket", e.target.value)} autoComplete="off" />
            </Field>
            {d.kind === "s3" && (
              <>
                <Field label="Region" hint="auto for R2" error={err("region")}>
                  <input value={d.region} onChange={(e) => set("region", e.target.value)} autoComplete="off" />
                </Field>
                <Field label="Endpoint" hint="For R2, B2 or MinIO. Empty for AWS." error={err("endpoint")}>
                  <input value={d.endpoint} onChange={(e) => set("endpoint", e.target.value)} placeholder="https://…" autoComplete="off" />
                </Field>
              </>
            )}
            <Field label="Prefix" hint="Optional, ending in /" error={err("prefix")}>
              <input value={d.prefix} onChange={(e) => set("prefix", e.target.value)} autoComplete="off" />
            </Field>
          </div>
          {d.kind === "s3" && (
            <label className="storage-check">
              <input type="checkbox" checked={d.pathStyle} onChange={(e) => set("pathStyle", e.target.checked)} /> Path-style
              addressing (MinIO usually needs it)
            </label>
          )}
        </>
      )}

      <Field
        label="Capacity"
        hint={
          typeof capacity === "number"
            ? `${formatBytes(capacity)} across every room on it. An upload that would cross it is refused.`
            : "Optional. The most this community will store here, across every room."
        }
        error={err("capacity")}
      >
        <input value={d.capacity} onChange={(e) => set("capacity", e.target.value)} placeholder="500 GB" />
      </Field>

      {!(editing && current.isDefault) && (
        <label className="storage-check">
          <input type="checkbox" checked={d.isDefault} onChange={(e) => set("isDefault", e.target.checked)} /> Make
          this the default: new rooms go here unless the rooms policy or their creator names
          another
        </label>
      )}

      <Field label="Reason" hint="Recorded in the audit trail and shown to the approvers. No personal data, no credential." error={err("reason")}>
        <textarea rows={2} value={d.reason} onChange={(e) => set("reason", e.target.value)} />
      </Field>

      <p className="muted rooms-sub">
        This needs your passkey. Another holder of the room-hosting capability then
        approves it on the Actions page, and it takes effect when they do — at once, if
        this community runs with a single administrator.
      </p>
      <div className="rooms-form-actions">
        <button type="submit" disabled={busy || unchanged}>
          {busy ? "Sending…" : editing ? "Send change for approval" : "Send for approval"}
        </button>
        <button type="button" className="secondary" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
      </div>
    </form>
  );
}
