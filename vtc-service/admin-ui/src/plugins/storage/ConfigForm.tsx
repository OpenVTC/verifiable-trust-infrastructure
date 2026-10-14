// A new storage config, or a change to one (`vtc/storage/configs/{create,update}`).
//
// Two kinds are served by this build: `local` (a directory beneath one of the
// host's `local_storage_bases`) and `s3` through an external account at the
// community's VTA. The form asks for nothing secret: an S3 config names the
// account by its context and identifier, and the VTA keeps the key. `ambient`
// and `sealed` authentication, `gcs` and `walrus` are not offered until the VTC
// serves them — a form that collected a credential the community then refused
// would be worse than one that does not ask.
//
// Both writes take an operation-bound step-up and are parked for the other
// holders of `vtc.rooms.admin`; the caller shows the parked notice.

import { useState, type FormEvent } from "react";

import { Field } from "@/components/Field";
import { exactBytes, formatBytes, parseBytes } from "@/lib/rooms-api";
import {
  BUCKET_PATTERN,
  CONFIG_ID_PATTERN,
  KIND_MEANS,
  PREFIX_PATTERN,
  REGION_PATTERN,
} from "@/lib/storage-api";
import type {
  StorageConfigCreatePayload,
  StorageConfigRecord,
  StorageConfigUpdatePayload,
} from "@/lib/wire-types";

const REASON_MAX = 500;
const LABEL_MAX = 128;
/** An account's context and identifier at the VTA (`ExternalAccountId`). */
const ACCOUNT_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

type Kind = "local" | "s3";

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
  context: "",
  account: "",
  capacity: "",
  isDefault: false,
  reason: "",
};

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
    if (d.prefix !== "" && !PREFIX_PATTERN.test(d.prefix)) {
      e.prefix = "Lowercase segments, each ending in '/': rooms-data/ or vtc/prod/.";
    }
    if (!ACCOUNT_PATTERN.test(d.context)) e.context = "The VTA context that owns the account.";
    if (!ACCOUNT_PATTERN.test(d.account)) e.account = "The account's identifier at the VTA.";
  }
  if (parseBytes(d.capacity) === null) e.capacity = "A size such as 500 GB, or empty for none.";
  const reason = d.reason.trim();
  if (reason === "" || reason.length > REASON_MAX) {
    e.reason = `Required, at most ${REASON_MAX} characters. Shown to the approvers.`;
  }
  return e;
}

/** The create payload a valid draft makes. */
export function createPayload(d: Draft): StorageConfigCreatePayload {
  const capacity = parseBytes(d.capacity);
  return {
    id: d.id,
    label: d.label.trim(),
    reason: d.reason.trim(),
    settings:
      d.kind === "local"
        ? { kind: "local", root: d.root }
        : {
            kind: "s3",
            bucket: d.bucket,
            region: d.region,
            ...(d.endpoint ? { endpoint: d.endpoint } : {}),
            ...(d.prefix ? { prefix: d.prefix } : {}),
            ...(d.pathStyle ? { pathStyle: true } : {}),
          },
    ...(d.kind === "s3"
      ? { auth: { mode: "vta-account" as const, context: d.context, account: d.account } }
      : {}),
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
  return {
    configId: current.id,
    reason: d.reason.trim(),
    ...(label !== current.label ? { label } : {}),
    ...(typeof capacity === "number" && capacity !== current.capacityBytes
      ? { capacityBytes: capacity }
      : {}),
    ...(d.isDefault && !current.isDefault ? { isDefault: true } : {}),
  };
}

function draftOf(current: StorageConfigRecord | undefined): Draft {
  if (!current) return EMPTY;
  return {
    ...EMPTY,
    id: current.id,
    label: current.label,
    kind: current.settings.kind === "local" ? "local" : "s3",
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
          {(["s3", "local"] as const).map((k) => (
            <label key={k}>
              <input type="radio" name="kind" checked={d.kind === k} onChange={() => set("kind", k)} />{" "}
              {k === "s3" ? "S3-compatible, through the community's VTA" : "A directory on this host"}
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

      {!editing && d.kind === "s3" && (
        <>
          <p className="muted">
            The community holds no storage credential. Its VTA keeps the key in an
            external account and signs one request per file, for five minutes. Create
            the account on the VTA and bind it to this community first
            (<code>pnm external …</code>); the VTC checks it when this is applied.
          </p>
          <div className="storage-fields">
            <Field label="VTA context" error={err("context")}>
              <input value={d.context} onChange={(e) => set("context", e.target.value)} autoComplete="off" />
            </Field>
            <Field label="VTA account" error={err("account")}>
              <input value={d.account} onChange={(e) => set("account", e.target.value)} autoComplete="off" />
            </Field>
            <Field label="Bucket" error={err("bucket")}>
              <input value={d.bucket} onChange={(e) => set("bucket", e.target.value)} autoComplete="off" />
            </Field>
            <Field label="Region" hint="auto for R2" error={err("region")}>
              <input value={d.region} onChange={(e) => set("region", e.target.value)} autoComplete="off" />
            </Field>
            <Field label="Endpoint" hint="For R2, B2 or MinIO. Empty for AWS." error={err("endpoint")}>
              <input value={d.endpoint} onChange={(e) => set("endpoint", e.target.value)} placeholder="https://…" autoComplete="off" />
            </Field>
            <Field label="Prefix" hint="Optional, ending in /" error={err("prefix")}>
              <input value={d.prefix} onChange={(e) => set("prefix", e.target.value)} autoComplete="off" />
            </Field>
          </div>
          <label className="storage-check">
            <input type="checkbox" checked={d.pathStyle} onChange={(e) => set("pathStyle", e.target.checked)} /> Path-style
            addressing (MinIO usually needs it)
          </label>
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
