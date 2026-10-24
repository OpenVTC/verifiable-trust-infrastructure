// Setting a `sealed` config's credential (`vtc/storage/credentials/set/0.2`).
//
// The credential is sealed in this browser to the community — HPKE to the X25519
// form of the community DID's key (`lib/sealed-transfer.ts`) — before it leaves the
// page, as the specification requires of a producer. Only the sealed block and its
// digest are sent; no transport, relay, log or approver between here and the
// community can read it, and the community never returns it.
//
// What this page does with the cleartext, and nothing more:
// - it lives in this form's state while it is typed (or, for Google, read from the
//   key file the administrator picks), and is cleared the moment it is sealed, on
//   Cancel, and when the form closes;
// - it is sealed before anything that keeps its input sees it: the mutation that
//   sends the request is given the sealed payload, never the credential.
//
// The change is parked for another holder of `vtc.rooms.admin` like every storage
// change; they see the config and the block's digest. Where this browser cannot
// seal — the community serves no DID document here, or no console key is enrolled —
// the terminal command is the way, and is always shown beside the form.

import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { useConfirm } from "@/components/ConfirmDialog";
import { Field } from "@/components/Field";
import { ErrorOrParked } from "@/components/ParkedNotice";
import { parkedOf } from "@/lib/parked-action";
import { SealingUnavailableError } from "@/lib/sealed-transfer";
import { gestureFromConfirm } from "@/lib/signed-act";
import {
  credentialSetCommand,
  describeCredential,
  sealCredentialForCommunity,
  setStorageCredential,
} from "@/lib/storage-api";
import type { SealedStorageCredential, StorageCredentialsSetPayload } from "@/lib/wire-types";

/** The kinds that take a credential. */
export type CredentialKind = "s3" | "gcs" | "walrus";

const REASON_MAX = 500;
// The `SealedStorageCredential` members' own patterns, so a typo is caught here
// rather than as `invalidCredential` after an approval.
const ACCESS_KEY_ID = /^[A-Za-z0-9]{1,128}$/;
const SECRET_ACCESS_KEY = /^[!-~]{1,256}$/;
const SESSION_TOKEN = /^[!-~]{1,8192}$/;
const SUI_PRIVATE_KEY = /^suiprivkey1[02-9ac-hj-np-z]{9,245}$/;

/** A Google service-account key file, as read; only its identifying members are shown. */
type ServiceAccountKey = Extract<SealedStorageCredential, { kind: "gcs" }>["serviceAccountKey"];

interface Draft {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  suiPrivateKey: string;
  serviceAccountKey: ServiceAccountKey | null;
  keyFileError: string | null;
  reason: string;
}

const EMPTY: Draft = {
  accessKeyId: "",
  secretAccessKey: "",
  sessionToken: "",
  suiPrivateKey: "",
  serviceAccountKey: null,
  keyFileError: null,
  reason: "",
};

/** A Google service-account key file's text as the object the schema takes, or why not. */
export function readServiceAccountKey(text: string): ServiceAccountKey | string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return "That file is not JSON. Choose the key file Google gave you.";
  }
  const k = parsed as Record<string, unknown> | null;
  if (!k || typeof k !== "object" || Array.isArray(k) || k.type !== "service_account") {
    return "That is not a service-account key file (its type is not service_account).";
  }
  for (const member of ["client_email", "private_key_id", "private_key"]) {
    if (typeof k[member] !== "string" || k[member] === "") {
      return `That key file has no ${member}.`;
    }
  }
  if (!(k.private_key as string).startsWith("-----BEGIN PRIVATE KEY-----")) {
    return "That key file's private_key is not a PKCS #8 PEM key.";
  }
  return k as ServiceAccountKey;
}

export function draftErrors(kind: CredentialKind, d: Draft): Partial<Record<keyof Draft, string>> {
  const e: Partial<Record<keyof Draft, string>> = {};
  if (kind === "s3") {
    if (!ACCESS_KEY_ID.test(d.accessKeyId)) e.accessKeyId = "Letters and digits, as the store issued it.";
    if (!SECRET_ACCESS_KEY.test(d.secretAccessKey)) e.secretAccessKey = "Required, with no spaces.";
    if (d.sessionToken && !SESSION_TOKEN.test(d.sessionToken)) e.sessionToken = "No spaces.";
  } else if (kind === "gcs") {
    if (!d.serviceAccountKey) e.serviceAccountKey = d.keyFileError ?? "Choose the service account's JSON key file.";
  } else if (!SUI_PRIVATE_KEY.test(d.suiPrivateKey)) {
    e.suiPrivateKey = "A Sui private key in its suiprivkey1… form.";
  }
  const reason = d.reason.trim();
  if (!reason) e.reason = "Say why: approvers see it.";
  else if (reason.length > REASON_MAX) e.reason = `At most ${REASON_MAX} characters.`;
  return e;
}

/** The cleartext a valid draft seals. */
export function credentialOf(kind: CredentialKind, configId: string, d: Draft): SealedStorageCredential {
  switch (kind) {
    case "s3":
      return {
        kind,
        configId,
        accessKeyId: d.accessKeyId,
        secretAccessKey: d.secretAccessKey,
        ...(d.sessionToken ? { sessionToken: d.sessionToken } : {}),
      };
    case "gcs":
      return { kind, configId, serviceAccountKey: d.serviceAccountKey as ServiceAccountKey };
    case "walrus":
      return { kind, configId, suiPrivateKey: d.suiPrivateKey };
  }
}

export function SetCredential({
  configId,
  kind,
  isSet,
}: {
  configId: string;
  kind: CredentialKind;
  /** Whether a credential is stored already, so this replaces it. */
  isSet: boolean;
}) {
  const confirm = useConfirm();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [d, setD] = useState<Draft>(EMPTY);
  const [touched, setTouched] = useState(false);
  const [sealing, setSealing] = useState(false);
  const [sealError, setSealError] = useState<unknown>(null);
  const send = useMutation({
    mutationFn: (payload: StorageCredentialsSetPayload) =>
      setStorageCredential(payload, gestureFromConfirm(confirm)),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["storage"] }),
    onError: (err) => {
      if (parkedOf(err)) void queryClient.invalidateQueries({ queryKey: ["actions"] });
    },
  });

  const errors = draftErrors(kind, d);
  const valid = Object.keys(errors).length === 0;
  const err = (k: keyof Draft) => (touched ? errors[k] : undefined);
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((x) => ({ ...x, [k]: v }));
  const done = send.isSuccess || parkedOf(send.error) !== null;

  function close() {
    setD(EMPTY);
    setTouched(false);
    setSealError(null);
    send.reset();
    setOpen(false);
  }

  async function chooseKeyFile(file: File | undefined) {
    if (!file) return;
    const read = readServiceAccountKey(await file.text());
    setD((x) =>
      typeof read === "string"
        ? { ...x, serviceAccountKey: null, keyFileError: read }
        : { ...x, serviceAccountKey: read, keyFileError: null },
    );
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!valid || sealing || send.isPending) return;
    setSealing(true);
    setSealError(null);
    try {
      const block = await sealCredentialForCommunity(credentialOf(kind, configId, d));
      const reason = d.reason.trim();
      // Sealed: the cleartext has no further use here.
      setD(EMPTY);
      setTouched(false);
      send.mutate({ configId, sealed: block.armor, digestMultibase: block.digestMultibase, reason });
    } catch (error) {
      setSealError(error);
    } finally {
      setSealing(false);
    }
  }

  const terminal = (
    <div className="muted rooms-sub">
      Or from a terminal, where it is sealed the same way: <code>{credentialSetCommand(configId)}</code>
    </div>
  );

  if (!open) {
    return (
      <div className="storage-set-credential">
        <button type="button" className="secondary" onClick={() => setOpen(true)}>
          {isSet ? "Replace the credential" : "Set the credential"}
        </button>
        {terminal}
      </div>
    );
  }

  if (done) {
    return (
      <div className="storage-set-credential">
        <ErrorOrParked title="Not set" error={send.error} />
        {send.data && (
          <p role="status">
            Set: {describeCredential(send.data.credentialState)}.
            {send.data.probeOk !== undefined &&
              (send.data.probeOk ? " A probe with it succeeded." : " A probe with it failed — check the key's permissions.")}
          </p>
        )}
        <button type="button" className="secondary" onClick={close}>
          Close
        </button>
      </div>
    );
  }

  return (
    <form className="storage-form storage-set-credential" onSubmit={(e) => void submit(e)} noValidate>
      <p className="muted">
        Sealed in this browser to this community before it is sent. Nobody else can read it on the way, approvers
        see only its digest, and it cannot be read back {isSet ? "— it replaces the one stored now" : ""}.
      </p>
      {kind === "s3" && (
        <div className="storage-fields">
          <Field label="Access key ID" error={err("accessKeyId")}>
            <input
              value={d.accessKeyId}
              onChange={(e) => set("accessKeyId", e.target.value.trim())}
              autoComplete="off"
              spellCheck={false}
            />
          </Field>
          <Field label="Secret access key" error={err("secretAccessKey")}>
            <input
              type="password"
              value={d.secretAccessKey}
              onChange={(e) => set("secretAccessKey", e.target.value.trim())}
              autoComplete="off"
            />
          </Field>
          <Field
            label="Session token (optional)"
            hint="Only for a temporary key, which stops working when it expires."
            error={err("sessionToken")}
          >
            <input
              type="password"
              value={d.sessionToken}
              onChange={(e) => set("sessionToken", e.target.value.trim())}
              autoComplete="off"
            />
          </Field>
        </div>
      )}
      {kind === "gcs" && (
        <Field
          label="Service-account key file"
          hint="The JSON key file Google issued. It is read in this browser and sealed; it is not uploaded."
          error={err("serviceAccountKey") ?? d.keyFileError ?? undefined}
        >
          <input
            type="file"
            accept=".json,application/json"
            onChange={(e) => {
              void chooseKeyFile(e.target.files?.[0]);
              e.target.value = "";
            }}
          />
        </Field>
      )}
      {kind === "gcs" && d.serviceAccountKey && (
        <p className="muted rooms-sub">
          Key <code>{d.serviceAccountKey.private_key_id}</code> of <code>{d.serviceAccountKey.client_email}</code>
        </p>
      )}
      {kind === "walrus" && (
        <Field label="Sui private key" error={err("suiPrivateKey")}>
          <input
            type="password"
            value={d.suiPrivateKey}
            onChange={(e) => set("suiPrivateKey", e.target.value.trim())}
            autoComplete="off"
          />
        </Field>
      )}
      <Field label="Reason" hint="Recorded in the audit trail and shown to the approvers. No personal data, no credential." error={err("reason")}>
        <textarea rows={2} value={d.reason} onChange={(e) => set("reason", e.target.value)} />
      </Field>
      {sealError !== null && (
        <section className="card error">
          <h3>Not sealed</h3>
          <p>{(sealError as Error).message}</p>
          {sealError instanceof SealingUnavailableError && terminal}
        </section>
      )}
      <ErrorOrParked title="Not set" error={send.error} />
      <div className="rooms-toolbar">
        <button type="submit" disabled={sealing || send.isPending}>
          {sealing ? "Sealing…" : send.isPending ? "Sending…" : "Seal and send for approval"}
        </button>
        <button type="button" className="secondary" onClick={close}>
          Cancel
        </button>
      </div>
      {terminal}
    </form>
  );
}
