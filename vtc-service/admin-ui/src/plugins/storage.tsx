// Storage — the Storage tab of the Data rooms page (`dataRooms.tsx`): where
// this community keeps its rooms' files
// (docs/05-design-notes/data-rooms-files.md §7, §8.1 "Storage").
//
// A list of configs with §7.6's facts, one page per config (its rooms, capacity
// against use, health, credential state, a probe, and Retire), and a form for a
// new one. Configs whose credential is `required` — a restore carries none — or
// `notAllowed` — a mode the host no longer permits — are listed first, because
// until someone acts they store nothing.
//
// Nothing here shows a credential, and none is accepted but sealed. An S3 config through a VTA account
// names an external account at the community's VTA, which holds the key. A `sealed`
// config is labelled, wherever it is shown, as no protection against whoever operates
// the machine (`vtc/storage/configs/get/0.2` item 5), and its credential is set on its
// page — sealed in this browser to the community before it is sent
// (`storage/SetCredential.tsx`) — or from a terminal (`cnm storage credentials set`).
// Every change is parked for another holder of `vtc.rooms.admin`
// (§7.4), so the screen says "sent for approval", never "saved", when it is.

import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useLivePollMs } from "@/lib/use-live-events";
import { HardDrive, Plus } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { ErrorOrParked } from "@/components/ParkedNotice";
import { PageHeader } from "@/components/PageHeader";
import type { ApiError } from "@/lib/api";
import { formatIso, shorten } from "@/lib/format";
import { parkedOf } from "@/lib/parked-action";
import { formatBytes, fullness, thresholdOf } from "@/lib/rooms-api";
import { gestureFromConfirm } from "@/lib/signed-act";
import {
  KIND_MEANS,
  SEALED_WARNING,
  createStorageConfig,
  describeCredential,
  needsAttention,
  fetchStorageConfig,
  fetchStorageConfigs,
  probeStorageConfig,
  retireStorageConfig,
  updateStorageConfig,
} from "@/lib/storage-api";
import { useToast } from "@/lib/toast";
import type {
  StorageConfigCreatePayload,
  StorageConfigFacts,
  StorageConfigItem,
  StorageConfigRecord,
  StorageConfigUpdatePayload,
} from "@/lib/wire-types";

import { ROOMS_PATH, STORAGE_PATH, configPath, roomPath } from "./rooms/shared";
import { ConfigForm } from "./storage/ConfigForm";
import { SetCredential } from "./storage/SetCredential";

function StatePill({ state }: { state: string }) {
  const tone = state === "active" ? "success" : state === "draining" ? "warning" : "";
  const means: Record<string, string> = {
    active: "Accepts new rooms and new uploads.",
    draining: "Retired while files still name it: refuses new rooms and uploads, keeps serving reads.",
    retired: "Holds no file. Refuses new rooms and uploads.",
  };
  return (
    <span className={`chip ${tone}`} title={means[state] ?? state}>
      {state}
    </span>
  );
}

function Used({ config, facts }: { config: StorageConfigRecord; facts: StorageConfigFacts }) {
  if (config.capacityBytes === undefined) return <>{formatBytes(facts.bytes)}</>;
  const f = fullness({ files: facts.files, bytes: facts.bytes }, { maxBytes: config.capacityBytes });
  const band = thresholdOf(f);
  return (
    <>
      {formatBytes(facts.bytes)} / {formatBytes(config.capacityBytes)}{" "}
      <span className={`chip ${band === 100 ? "danger" : band ? "warning" : "success"}`}>
        {Math.round((f ?? 0) * 100)}%
      </span>
    </>
  );
}

function Health({ facts }: { facts: StorageConfigFacts }) {
  const h = facts.health;
  if (h.lastProbeAt === undefined && h.lastPutAt === undefined) {
    return <span className="muted">not probed</span>;
  }
  return (
    <span>
      {h.lastProbeAt !== undefined && (
        <span className={`chip ${h.lastProbeOk ? "success" : "danger"}`}>
          probe {h.lastProbeOk ? "ok" : "failed"}
        </span>
      )}
      {h.lastPutAt && <div className="muted rooms-sub">last write {formatIso(h.lastPutAt)}</div>}
    </span>
  );
}

/** The Storage tab of the Data rooms page (`plugins/dataRooms.tsx`). */
export function StorageList() {
  const [params, setParams] = useSearchParams();
  const creating = params.get("create") === "1";
  const pollMs = useLivePollMs("rooms");
  const q = useQuery({
    queryKey: ["storage", "list"],
    queryFn: fetchStorageConfigs,
    refetchInterval: pollMs,
  });
  const items = q.data ?? [];
  const needCredential = items.filter((i) => needsAttention(i.facts.credential));
  const others = items.filter((i) => !needsAttention(i.facts.credential));

  return (
    <>
      {creating && <NewConfig onDone={() => setParams({})} />}

      {q.isPending && (
        <section className="card">
          <p>Reading storage…</p>
        </section>
      )}
      {q.isError && (
        <section className="card">
          <p className="muted">Storage could not be read. This is a failure to ask, not a community with none.</p>
        </section>
      )}
      {q.data && items.length === 0 && (
        <section className="card">
          <EmptyState icon={HardDrive} title="No storage yet">
            Room files are off on this community, or its first storage location has
            not been set up. The <Link to={ROOMS_PATH}>Rooms</Link> tab says how to turn
            files on.
          </EmptyState>
        </section>
      )}

      {needCredential.length > 0 && (
        <section className="card storage-attention">
          <h2>Needs a credential</h2>
          <p>
            These cannot store anything until someone acts: a credential to provide —
            usually after a restore, which carries none — or a way of authenticating this
            community's host no longer permits, to change. Rooms assigned to them refuse
            new uploads; files already stored elsewhere are unaffected.
          </p>
          <ConfigsTable items={needCredential} />
        </section>
      )}
      {others.length > 0 && (
        <section className="card">
          <ConfigsTable items={others} />
        </section>
      )}
    </>
  );
}

/** The Storage tab's primary action, drawn in the page header: open the form
 *  for a new storage location (`?create=1`, which `StorageList` reads). */
export function NewStorageButton() {
  const [params, setParams] = useSearchParams();
  if (params.get("create") === "1") return null;
  return (
    <button type="button" onClick={() => setParams({ create: "1" })}>
      <Plus aria-hidden="true" />
      New storage
    </button>
  );
}

function ConfigsTable({ items }: { items: StorageConfigItem[] }) {
  return (
    <DataTable
      columns={[
        { key: "config", label: "Storage" },
        { key: "state", label: "State" },
        { key: "rooms", label: "Rooms" },
        { key: "held", label: "Held" },
        { key: "credential", label: "Credential" },
        { key: "health", label: "Health" },
      ]}
    >
      {items.map(({ config, facts }) => (
        <tr key={config.id}>
          <td>
            <Link to={configPath(config.id)}>
              <code>{config.id}</code>
            </Link>{" "}
            {config.isDefault && <span className="chip">default</span>}
            <div className="muted rooms-sub">
              {config.label} · {config.settings.kind}
            </div>
          </td>
          <td>
            <StatePill state={config.state} />
          </td>
          <td>{facts.rooms}</td>
          <td>
            <Used config={config} facts={facts} />
            <div className="muted rooms-sub">
              {facts.files} files
              {facts.pendingDeleteBytes > 0 && ` · ${formatBytes(facts.pendingDeleteBytes)} awaiting deletion`}
            </div>
          </td>
          <td>{describeCredential(facts.credential)}</td>
          <td>
            <Health facts={facts} />
          </td>
        </tr>
      ))}
    </DataTable>
  );
}

/** Send a gated storage change, and say what became of it. */
function useStorageChange<P>(send: (payload: P, gesture: ReturnType<typeof gestureFromConfirm>) => Promise<unknown>) {
  const confirm = useConfirm();
  const queryClient = useQueryClient();
  const toast = useToast();
  return useMutation({
    mutationFn: (payload: P) => send(payload, gestureFromConfirm(confirm)),
    onSuccess: () => {
      // Single-administrator mode applies a change at once (VTI-APV-022).
      toast.push("success", "Applied.");
      void queryClient.invalidateQueries({ queryKey: ["storage"] });
    },
    onError: (err) => {
      if (parkedOf(err)) void queryClient.invalidateQueries({ queryKey: ["actions"] });
    },
  });
}

function NewConfig({ onDone }: { onDone: () => void }) {
  const create = useStorageChange<StorageConfigCreatePayload>(createStorageConfig);
  const sent = create.isSuccess || parkedOf(create.error) !== null;
  return (
    <section className="card">
      <h2>New storage</h2>
      {sent ? (
        <>
          <ErrorOrParked title="Not created" error={create.error} />
          {create.isSuccess && <p>Created.</p>}
          <button type="button" className="secondary" onClick={onDone}>
            Close
          </button>
        </>
      ) : (
        <>
          <ConfigForm
            busy={create.isPending}
            onSubmit={(p) => create.mutate(p as StorageConfigCreatePayload)}
            onCancel={onDone}
          />
          <ErrorOrParked title="Not created" error={create.error} />
        </>
      )}
    </section>
  );
}

/** One storage location's page, `/rooms/storage/<configId>`. */
export function ConfigDetail() {
  // Already decoded by the router; decoding again could change the identifier.
  const { configId = "" } = useParams();
  const navigate = useNavigate();
  const q = useQuery({
    queryKey: ["storage", "get", configId],
    queryFn: () => fetchStorageConfig(configId),
  });
  const [editing, setEditing] = useState(false);
  const update = useStorageChange<StorageConfigUpdatePayload>(updateStorageConfig);
  const trail = [{ label: "Storage", to: STORAGE_PATH }, { label: configId }];

  if (q.isPending) {
    return (
      <section className="page">
        <PageHeader title="Storage" trail={trail} />
        <section className="card">
          <p>Reading the storage location…</p>
        </section>
      </section>
    );
  }
  if (q.isError) {
    const missing = (q.error as unknown as ApiError | null)?.code === "vtc/storage/configs/get:notFound";
    return (
      <section className="page">
        <PageHeader title="Storage" trail={trail} />
        <section className="card">
          <p className="muted">
            {missing ? "This community has no storage location with that identifier." : "It could not be read."}
          </p>
          <button type="button" className="secondary" onClick={() => navigate(STORAGE_PATH)}>
            Back to storage
          </button>
        </section>
      </section>
    );
  }
  const { config, facts, assignedRooms, assignedRoomsTruncated } = q.data;
  const s = config.settings;

  return (
    <section className="page">
      <PageHeader title={config.label} trail={trail} lead={KIND_MEANS[s.kind]} />

      <section className="card">
        <h2>Settings</h2>
        <dl className="rooms-facts">
          <dt>Identifier</dt>
          <dd>
            <code>{config.id}</code> {config.isDefault && <span className="chip">default</span>}
          </dd>
          <dt>State</dt>
          <dd>
            <StatePill state={config.state} />
          </dd>
          {s.kind === "local" && (
            <>
              <dt>Directory</dt>
              <dd>
                <code>{s.root}</code>
                <div className="muted rooms-sub">Not in a VTC backup: back it up beside the data directory.</div>
              </dd>
            </>
          )}
          {s.kind === "s3" && (
            <>
              <dt>Bucket</dt>
              <dd>
                <code>{s.bucket}</code> in <code>{s.region}</code>
                {s.prefix && (
                  <>
                    {" "}under <code>{s.prefix}</code>
                  </>
                )}
              </dd>
              {s.endpoint && (
                <>
                  <dt>Endpoint</dt>
                  <dd>
                    <code>{s.endpoint}</code>
                    {s.pathStyle && " (path-style)"}
                  </dd>
                </>
              )}
            </>
          )}
          {s.kind === "gcs" && (
            <>
              <dt>Bucket</dt>
              <dd>
                <code>{s.bucket}</code>
                {s.prefix && (
                  <>
                    {" "}under <code>{s.prefix}</code>
                  </>
                )}
              </dd>
            </>
          )}
          {config.auth?.mode === "ambient" && config.auth.roleArn && (
            <>
              <dt>Role</dt>
              <dd>
                <code>{config.auth.roleArn}</code>
                <div className="muted rooms-sub">Assumed by this machine's identity for each room, for at most 15 minutes.</div>
              </dd>
            </>
          )}
          <dt>Credential</dt>
          <dd>
            {describeCredential(facts.credential)}
            {config.auth?.mode === "sealed" && (
              <>
                <p className="storage-warning" role="note">
                  {SEALED_WARNING}
                </p>
                {config.state === "active" && s.kind !== "local" && (
                  <SetCredential
                    configId={config.id}
                    kind={s.kind}
                    isSet={facts.credential.status === "sealed"}
                  />
                )}
              </>
            )}
          </dd>
          <dt>Held</dt>
          <dd>
            <Used config={config} facts={facts} /> · {facts.files} files
            {facts.pendingDeleteBytes > 0 && ` · ${formatBytes(facts.pendingDeleteBytes)} awaiting deletion`}
          </dd>
          <dt>Created</dt>
          <dd>{formatIso(config.createdAt)}</dd>
          {config.updatedAt && (
            <>
              <dt>Changed</dt>
              <dd>{formatIso(config.updatedAt)}</dd>
            </>
          )}
        </dl>
        {config.state === "active" && !editing && !parkedOf(update.error) && (
          <p>
            <button type="button" className="secondary" onClick={() => setEditing(true)}>
              Change label, authentication, capacity or default
            </button>
          </p>
        )}
        {editing && !parkedOf(update.error) && (
          <div className="rooms-edit">
            <ConfigForm
              current={config}
              busy={update.isPending}
              onSubmit={(p) =>
                update.mutate(p as StorageConfigUpdatePayload, { onSuccess: () => setEditing(false) })
              }
              onCancel={() => setEditing(false)}
            />
          </div>
        )}
        <ErrorOrParked title="Not changed" error={update.error} />
      </section>

      <Probe configId={config.id} facts={facts} />

      <section className="card">
        <h2>Rooms</h2>
        <p className="muted">
          {facts.rooms} {facts.rooms === 1 ? "room sends" : "rooms send"} new uploads here.
          Files written here by rooms since moved elsewhere stay, and keep being served.
        </p>
        {assignedRooms && assignedRooms.length > 0 && (
          <ul className="storage-rooms">
            {assignedRooms.map((r) => (
              <li key={r}>
                <Link to={roomPath(r)} title={r}>
                  <code>{shorten(r)}</code>
                </Link>
              </li>
            ))}
          </ul>
        )}
        {assignedRoomsTruncated && <p className="muted">The first {assignedRooms?.length} are shown.</p>}
      </section>

      {config.state === "active" && <Retire config={config} facts={facts} />}
    </section>
  );
}

function Probe({ configId, facts }: { configId: string; facts: StorageConfigFacts }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [includeWrite, setIncludeWrite] = useState(true);
  const probe = useMutation({
    mutationFn: () => probeStorageConfig(configId, includeWrite),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["storage"] }),
    onError: (err) => toast.pushFromError(err, "The probe could not run"),
  });
  const h = facts.health;
  return (
    <section className="card">
      <h2>Health</h2>
      <dl className="rooms-facts">
        <dt>Last probe</dt>
        <dd>
          {h.lastProbeAt ? `${formatIso(h.lastProbeAt)}, ${h.lastProbeOk ? "ok" : "failed"}` : "never"}
        </dd>
        <dt>Last write</dt>
        <dd>{h.lastPutAt ? formatIso(h.lastPutAt) : "—"}</dd>
        <dt>Last read</dt>
        <dd>{h.lastGetAt ? formatIso(h.lastGetAt) : "—"}</dd>
        <dt>Last deletion</dt>
        <dd>{h.lastDeleteAt ? formatIso(h.lastDeleteAt) : "—"}</dd>
      </dl>
      <div className="rooms-toolbar">
        <label className="storage-check">
          <input type="checkbox" checked={includeWrite} onChange={(e) => setIncludeWrite(e.target.checked)} /> Write,
          read back and delete a small test file
        </label>
        <button type="button" className="secondary" onClick={() => probe.mutate()} disabled={probe.isPending}>
          {probe.isPending ? "Probing…" : "Probe now"}
        </button>
      </div>
      {probe.data && (
        <DataTable
          aria-label="Probe steps"
          columns={[
            { key: "step", label: "Step" },
            { key: "result", label: "Result" },
            { key: "time", label: "Time" },
          ]}
        >
          {probe.data.steps.map((st) => (
            <tr key={st.step}>
              <td>{st.step}</td>
              <td>
                <span className={`chip ${st.ok ? "success" : "danger"}`}>{st.ok ? "ok" : "failed"}</span>
                {st.error && <div className="muted rooms-sub">{st.error}</div>}
              </td>
              <td>{st.durationMs} ms</td>
            </tr>
          ))}
        </DataTable>
      )}
    </section>
  );
}

function Retire({ config, facts }: { config: StorageConfigRecord; facts: StorageConfigFacts }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const retire = useStorageChange<string>((r, gesture) => retireStorageConfig(config.id, r, gesture));
  const blocked = config.isDefault || facts.rooms > 0;
  return (
    <section className="card">
      <h2>Retire</h2>
      <p className="muted">
        A retired location takes no new rooms and no new uploads, and keeps serving the
        files it holds. While it still holds any it is <b>draining</b>; once emptied it is
        retired. Nothing is deleted, and its identifier is never reused.
      </p>
      {blocked ? (
        <p className="muted">
          {config.isDefault
            ? "Make another location the default first."
            : `Move its ${facts.rooms} ${facts.rooms === 1 ? "room" : "rooms"} to another location first, from each room's page.`}
        </p>
      ) : !open ? (
        <button type="button" className="secondary" onClick={() => setOpen(true)}>
          Retire {config.id}
        </button>
      ) : (
        !parkedOf(retire.error) && (
          <div className="rooms-edit">
            <label className="field">
              <span className="field-label">Reason</span>
              <textarea rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
            </label>
            <div className="rooms-form-actions">
              <button
                type="button"
                className="secondary destructive"
                onClick={() => retire.mutate(reason.trim())}
                disabled={retire.isPending || reason.trim() === "" || reason.trim().length > 500}
              >
                Send for approval
              </button>
              <button type="button" className="secondary" onClick={() => setOpen(false)}>
                Cancel
              </button>
            </div>
          </div>
        )
      )}
      <ErrorOrParked title="Not retired" error={retire.error} />
    </section>
  );
}
