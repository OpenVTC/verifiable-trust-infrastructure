// Member directory — the community's field schema and its members' entries
// (`vtc/directory/*`, docs/03-vtc/member-directory.md).
//
//   /directory           Fields tab: base and community fields, their ceilings
//                        and defaults; define, change, disable, retire.
//   /directory/entries   Entries tab: every member's entry as an administrator
//                        reads it, and the values administrators assert.
//
// Reading needs any administrative role; changing the schema and asserting
// values need `vtc.directory.admin`. A change that widens a field is parked for
// the other holders' approval (VTI-DIR-024), and the form says so before it is
// sent. Nothing here can change what a member chose to show: the ceiling is
// the widest a field may reach, never what any member's value does.
//
// Member values are text the member typed, rendered as text, never as markup.

import { Fragment, useMemo, useState } from "react";
import { Route, Routes } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Search, X } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { Field } from "@/components/Field";
import { PageHeader } from "@/components/PageHeader";
import { TabLinks } from "@/components/Tabs";
import {
  AUDIENCES,
  COMMUNITY_KEY_PATTERN,
  DIRECTORY_ADMIN,
  FIELD_TYPES,
  assertValues,
  defineField,
  listEntries,
  listFields,
  retireField,
  showEntry,
  updateField,
  widens,
  within,
  type Audience,
  type FieldType,
} from "@/lib/directory";
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";
import { holds, useCapabilities } from "@/lib/viewer";
import type { DirectoryFieldDefinition } from "@/lib/wire-types";

const FIELDS_KEY = ["directory", "fields"] as const;

function audienceLabel(a: Audience): string {
  return AUDIENCES.find((x) => x.id === a)?.label ?? a;
}

function AudienceSelect({
  label,
  value,
  max,
  onChange,
}: {
  label: string;
  value: Audience;
  /** Offer only audiences within this one. */
  max?: Audience;
  onChange: (a: Audience) => void;
}) {
  return (
    <select aria-label={label} value={value} onChange={(e) => onChange(e.target.value as Audience)}>
      {AUDIENCES.filter((a) => !max || within(a.id, max)).map((a) => (
        <option key={a.id} value={a.id} title={a.hint}>
          {a.label}
        </option>
      ))}
    </select>
  );
}

export function Directory() {
  return (
    <section className="page">
      <PageHeader
        lead={
          <>
            Each member decides who sees each value on their card, up to the ceiling set here.
            Narrowing a field applies at once; widening one is sent to the other directory
            administrators for approval, and never changes what any member already chose.
          </>
        }
      />
      <TabLinks
        label="Directory"
        items={[
          { id: "fields", label: "Fields", to: "/directory", end: true },
          { id: "entries", label: "Entries", to: "/directory/entries" },
        ]}
      />
      <Routes>
        <Route index element={<FieldsTab />} />
        <Route path="entries" element={<EntriesTab />} />
      </Routes>
    </section>
  );
}

// ─── fields ───────────────────────────────────────────────────────────────

function FieldsTab() {
  const caps = useCapabilities();
  const admin = holds(caps, DIRECTORY_ADMIN);
  const [defining, setDefining] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const query = useQuery({ queryKey: [...FIELDS_KEY, admin], queryFn: () => listFields(admin) });
  const queryClient = useQueryClient();
  const refresh = () => void queryClient.invalidateQueries({ queryKey: FIELDS_KEY });

  const fields = query.data?.fields ?? [];
  return (
    <>
      {query.data && (
        <p className="muted">
          A new card starts <strong>{query.data.listingDefaults.defaultListing}</strong>; members
          may always choose to be hidden. This is the operator&rsquo;s{" "}
          <code>[directory] default_listing</code>.
        </p>
      )}
      {admin && (
        <p>
          <button
            type="button"
            className={defining ? "secondary" : "primary"}
            onClick={() => setDefining((v) => !v)}
          >
            {defining ? (
              <>
                <X size={14} aria-hidden="true" /> Cancel
              </>
            ) : (
              <>
                <Plus size={14} aria-hidden="true" /> Define field
              </>
            )}
          </button>
        </p>
      )}
      {defining && (
        <DefineFieldForm
          onDone={() => {
            setDefining(false);
            refresh();
          }}
        />
      )}
      {query.error && (
        <section className="card error">
          <h3>Failed to load the directory&rsquo;s fields</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}
      <section className="card">
        <DataTable
          caption="Directory fields"
          columns={[
            { key: "field", label: "Field" },
            { key: "type", label: "Type" },
            { key: "source", label: "Written by" },
            { key: "ceiling", label: "Widest" },
            { key: "default", label: "New cards" },
            { key: "flags", label: "" },
            { key: "state", label: "State" },
            ...(admin ? [{ key: "actions", label: "" }] : []),
          ]}
        >
          {fields.map((f) => (
            <FieldRow
              key={f.key}
              field={f}
              admin={admin}
              editing={editing === f.key}
              onEdit={() => setEditing(editing === f.key ? null : f.key)}
              onDone={() => {
                setEditing(null);
                refresh();
              }}
            />
          ))}
        </DataTable>
      </section>
    </>
  );
}

const SOURCE_LABEL: Record<DirectoryFieldDefinition["source"], string> = {
  member: "the member",
  admin: "administrators",
  credential: "a credential",
  derived: "the community's records",
};

function FieldRow({
  field: f,
  admin,
  editing,
  onEdit,
  onDone,
}: {
  field: DirectoryFieldDefinition;
  admin: boolean;
  editing: boolean;
  onEdit: () => void;
  onDone: () => void;
}) {
  const flags = [f.required && "required", f.searchable && "searchable", f.facet && "facet"]
    .filter(Boolean)
    .join(", ");
  return (
    <>
      <tr>
        <td>
          <strong>{f.label}</strong> <code className="muted">{f.key}</code>
          {f.description && <div className="muted">{f.description}</div>}
        </td>
        <td>{f.type}</td>
        <td>{SOURCE_LABEL[f.source]}</td>
        <td>{audienceLabel(f.ceiling)}</td>
        <td>{audienceLabel(f.defaultVisibility)}</td>
        <td className="muted">{flags}</td>
        <td>
          {f.state}
          {f.purgeAfter && <div className="muted">values erased after {f.purgeAfter}</div>}
        </td>
        {admin && (
          <td>
            {f.state !== "retired" && (
              <button type="button" className="secondary" onClick={onEdit}>
                {editing ? "Close" : "Change"}
              </button>
            )}
          </td>
        )}
      </tr>
      {editing && (
        <tr>
          <td colSpan={8}>
            <EditFieldForm field={f} onDone={onDone} />
          </td>
        </tr>
      )}
    </>
  );
}

function EditFieldForm({ field, onDone }: { field: DirectoryFieldDefinition; onDone: () => void }) {
  const [draft, setDraft] = useState(field);
  const [reason, setReason] = useState("");
  const toast = useToast();
  const confirm = useConfirm();
  const derived = field.source === "derived";
  const facetable = ["enum", "multiEnum", "country"].includes(field.type);
  const wider = widens(field, draft);
  const aboveCeiling = !within(draft.defaultVisibility, draft.ceiling);

  const save = useMutation({
    mutationFn: () =>
      updateField(
        {
          key: field.key,
          label: draft.label,
          ceiling: draft.ceiling,
          defaultVisibility: draft.defaultVisibility,
          required: draft.required,
          searchable: draft.searchable,
          facet: draft.facet,
          order: draft.order,
          ...(field.base && draft.state !== field.state ? { enabled: draft.state === "active" } : {}),
          ...(reason ? { reason } : {}),
        },
        gestureFromConfirm(confirm),
      ),
    onSuccess: () => {
      toast.push("success", `Changed ${field.label}`);
      onDone();
    },
    onError: (err) => {
      toast.pushFromError(err, wider ? "Sent for approval" : "Change failed");
      onDone();
    },
  });

  const retire = useMutation({
    mutationFn: () => retireField(field.key, reason || "No longer collected."),
    onSuccess: (f) => {
      toast.push("success", `Retired ${field.label}; values erased after ${f.purgeAfter ?? "retention"}`);
      onDone();
    },
    onError: (err) => toast.pushFromError(err, "Retire failed"),
  });

  return (
    <form
      className="inline-form"
      onSubmit={(e) => {
        e.preventDefault();
        if (!aboveCeiling) save.mutate();
      }}
    >
      <Field label="Label">
        <input aria-label="Field label" value={draft.label} onChange={(e) => setDraft({ ...draft, label: e.target.value })} />
      </Field>
      <Field label="Widest audience">
        <AudienceSelect
          label="Widest audience"
          value={draft.ceiling}
          onChange={(ceiling) => setDraft({ ...draft, ceiling })}
        />
      </Field>
      <Field label="New cards show it to">
        <AudienceSelect
          label="New cards show it to"
          value={draft.defaultVisibility}
          max={draft.ceiling}
          onChange={(defaultVisibility) => setDraft({ ...draft, defaultVisibility })}
        />
      </Field>
      {!derived && (
        <>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={draft.required}
              onChange={(e) => setDraft({ ...draft, required: e.target.checked })}
            />
            <span className="checkbox-text">Required to be listed</span>
          </label>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={draft.searchable}
              onChange={(e) => setDraft({ ...draft, searchable: e.target.checked })}
            />
            <span className="checkbox-text">Searchable</span>
          </label>
          {facetable && (
            <label className="checkbox">
              <input
                type="checkbox"
                checked={draft.facet}
                onChange={(e) => setDraft({ ...draft, facet: e.target.checked })}
              />
              <span className="checkbox-text">Filter and count by it</span>
            </label>
          )}
        </>
      )}
      {field.base && (
        <label className="checkbox">
          <input
            type="checkbox"
            checked={draft.state === "active"}
            onChange={(e) => setDraft({ ...draft, state: e.target.checked ? "active" : "disabled" })}
          />
          <span className="checkbox-text">Enabled</span>
        </label>
      )}
      <Field label="Reason">
        <input aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} />
      </Field>
      {aboveCeiling && <p className="error">New cards cannot show it more widely than its widest audience.</p>}
      {wider && (
        <p className="warning">
          This widens the field: it goes to the other directory administrators for approval, and
          takes your passkey gesture. No member&rsquo;s own choice changes.
        </p>
      )}
      <button type="submit" className="primary" disabled={aboveCeiling || save.isPending}>
        {wider ? "Send for approval" : "Save"}
      </button>{" "}
      {!field.base && (
        <button
          type="button"
          className="danger"
          disabled={retire.isPending}
          onClick={async () => {
            if (
              await confirm({
                title: `Retire ${field.label}?`,
                message:
                  "It is hidden from every card at once, members' values of it are erased after the retention period, and its key can never be used again.",
                confirmLabel: "Retire",
                destructive: true,
              })
            )
              retire.mutate();
          }}
        >
          Retire
        </button>
      )}
    </form>
  );
}

function DefineFieldForm({ onDone }: { onDone: () => void }) {
  const [key, setKey] = useState("");
  const [label, setLabel] = useState("");
  const [type, setType] = useState<FieldType>("text");
  const [source, setSource] = useState<"member" | "admin">("member");
  const [ceiling, setCeiling] = useState<Audience>("members");
  const [defaultVisibility, setDefault] = useState<Audience>("admins");
  const [options, setOptions] = useState("");
  const [searchable, setSearchable] = useState(false);
  const [facet, setFacet] = useState(false);
  const [reason, setReason] = useState("");
  const toast = useToast();

  const isEnum = type === "enum" || type === "multiEnum";
  const optionList = options
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean)
    .map((o) => ({ value: o.toLowerCase().replace(/[^a-z0-9._-]/g, "-"), label: o }));
  const keyOk = COMMUNITY_KEY_PATTERN.test(key);

  const define = useMutation({
    mutationFn: () =>
      defineField(
        {
          key,
          label,
          type,
          source,
          ceiling,
          defaultVisibility: within(defaultVisibility, ceiling) ? defaultVisibility : "admins",
          searchable,
          facet: facet && (isEnum || type === "country"),
          ...(isEnum ? { constraints: { options: optionList } } : {}),
        },
        reason || undefined,
      ),
    onSuccess: (f) => {
      toast.push("success", `Defined ${f.label}`);
      onDone();
    },
    onError: (err) => toast.pushFromError(err, "Define failed"),
  });

  return (
    <section className="card">
      <h3>Define a field</h3>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (keyOk && label) define.mutate();
        }}
      >
        <Field label="Key">
          <input
            aria-label="Field key"
            value={key}
            placeholder="org.example.employer"
            onChange={(e) => setKey(e.target.value.trim())}
          />
        </Field>
        {key !== "" && !keyOk && (
          <p className="error">A reverse-DNS key with at least one dot; keys without one are the base fields&rsquo;.</p>
        )}
        <Field label="Label">
          <input aria-label="Field label" value={label} onChange={(e) => setLabel(e.target.value)} />
        </Field>
        <Field label="Type">
          <select aria-label="Field type" value={type} onChange={(e) => setType(e.target.value as FieldType)}>
            {FIELD_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </Field>
        {isEnum && (
          <Field label="Options (comma-separated)">
            <input aria-label="Options" value={options} onChange={(e) => setOptions(e.target.value)} />
          </Field>
        )}
        <Field label="Written by">
          <select
            aria-label="Written by"
            value={source}
            onChange={(e) => setSource(e.target.value as "member" | "admin")}
          >
            <option value="member">the member</option>
            <option value="admin">administrators (members read it and cannot change it)</option>
          </select>
        </Field>
        <Field label="Widest audience">
          <AudienceSelect label="Widest audience" value={ceiling} onChange={setCeiling} />
        </Field>
        <Field label="New cards show it to">
          <AudienceSelect
            label="New cards show it to"
            value={defaultVisibility}
            max={ceiling}
            onChange={setDefault}
          />
        </Field>
        <label className="checkbox">
          <input type="checkbox" checked={searchable} onChange={(e) => setSearchable(e.target.checked)} />
          <span className="checkbox-text">Searchable</span>
        </label>
        {(isEnum || type === "country") && (
          <label className="checkbox">
            <input type="checkbox" checked={facet} onChange={(e) => setFacet(e.target.checked)} />
            <span className="checkbox-text">Filter and count by it</span>
          </label>
        )}
        <Field label="Reason">
          <input aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
        <p className="muted">
          The key, type and writer are fixed for the field&rsquo;s life. A field is never deleted,
          only retired, and its key is never reused.
        </p>
        <button type="submit" className="primary" disabled={!keyOk || !label || define.isPending}>
          Define
        </button>
      </form>
    </section>
  );
}

// ─── entries ──────────────────────────────────────────────────────────────

function display(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function EntriesTab() {
  const [text, setText] = useState("");
  const [query, setQuery] = useState<string | undefined>(undefined);
  const [open, setOpen] = useState<string | null>(null);
  const list = useQuery({
    queryKey: ["directory", "entries", query ?? ""],
    queryFn: () => listEntries({ ...(query ? { query } : {}), limit: 100 }),
  });
  const fields = useQuery({ queryKey: [...FIELDS_KEY, true], queryFn: () => listFields(true) });
  const labels = useMemo(
    () => new Map((fields.data?.fields ?? []).map((f) => [f.key, f.label])),
    [fields.data],
  );

  return (
    <>
      <form
        className="inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          const t = text.trim();
          setQuery(t.length >= 3 ? t : undefined);
        }}
      >
        <input
          aria-label="Search the directory"
          placeholder="Name, nickname, a searchable value or a DID"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <button type="submit" className="secondary">
          <Search size={14} aria-hidden="true" /> Search
        </button>
      </form>
      <p className="muted">
        Administrators see every entry, listed or not, with every field. Members see only what each
        member chose to show them.
      </p>
      {list.error && (
        <section className="card error">
          <h3>Failed to read the directory</h3>
          <p>{(list.error as Error).message}</p>
        </section>
      )}
      <section className="card">
        <DataTable
          caption="Directory entries"
          columns={[
            { key: "name", label: "Name" },
            { key: "role", label: "Role" },
            { key: "did", label: "DID" },
            { key: "open", label: "" },
          ]}
        >
          {(list.data?.items ?? []).map((e) => (
            <Fragment key={e.entryId}>
              <tr>
                <td>{display(e.fields.displayName) || <span className="muted">(no name)</span>}</td>
                <td>{display(e.fields.role)}</td>
                <td>
                  <code>{display(e.fields.did)}</code>
                </td>
                <td>
                  <button type="button" className="secondary" onClick={() => setOpen(open === e.entryId ? null : e.entryId)}>
                    {open === e.entryId ? "Close" : "Open"}
                  </button>
                </td>
              </tr>
              {open === e.entryId && (
                <tr>
                  <td colSpan={4}>
                    <EntryDetail
                      entryId={e.entryId}
                      labels={labels}
                      adminFields={(fields.data?.fields ?? []).filter(
                        (f) => f.source === "admin" && f.state === "active",
                      )}
                    />
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </DataTable>
      </section>
    </>
  );
}

function EntryDetail({
  entryId,
  labels,
  adminFields,
}: {
  entryId: string;
  labels: Map<string, string>;
  adminFields: DirectoryFieldDefinition[];
}) {
  const caps = useCapabilities();
  const admin = holds(caps, DIRECTORY_ADMIN);
  const q = useQuery({ queryKey: ["directory", "entry", entryId], queryFn: () => showEntry(entryId) });
  const fields = q.data?.entry.fields ?? {};
  return (
    <div>
      {q.isLoading && <p className="muted">…</p>}
      {q.error && <p className="error">{(q.error as Error).message}</p>}
      <dl className="kv">
        {Object.entries(fields).map(([k, v]) => (
          <div key={k}>
            <dt>{labels.get(k) ?? k}</dt>
            <dd>{display(v)}</dd>
          </div>
        ))}
      </dl>
      {admin && adminFields.length > 0 && (
        <AssertForm entryId={entryId} fields={adminFields} current={fields} />
      )}
    </div>
  );
}

function AssertForm({
  entryId,
  fields,
  current,
}: {
  entryId: string;
  fields: DirectoryFieldDefinition[];
  current: Record<string, unknown>;
}) {
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(fields.map((f) => [f.key, display(current[f.key])])),
  );
  const [reason, setReason] = useState("");
  const toast = useToast();
  const queryClient = useQueryClient();
  const save = useMutation({
    mutationFn: () =>
      assertValues({
        entryId,
        reason,
        values: Object.fromEntries(
          fields.map((f) => {
            const v = values[f.key]?.trim() ?? "";
            if (v === "") return [f.key, null];
            if (f.type === "multiEnum") return [f.key, v.split(",").map((x) => x.trim())];
            return [f.key, v];
          }),
        ),
      }),
    onSuccess: (r) => {
      toast.push("success", `Recorded ${r.written.join(", ")}`);
      void queryClient.invalidateQueries({ queryKey: ["directory", "entry", entryId] });
    },
    onError: (err) => toast.pushFromError(err, "Not recorded"),
  });
  return (
    <form
      className="inline-form"
      onSubmit={(e) => {
        e.preventDefault();
        if (reason) save.mutate();
      }}
    >
      <h4>Values the community records</h4>
      {fields.map((f) => (
        <Field key={f.key} label={f.label}>
          {f.type === "enum" ? (
            <select
              aria-label={f.label}
              value={values[f.key] ?? ""}
              onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
            >
              <option value="">(none)</option>
              {(f.constraints?.options ?? []).map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          ) : (
            <input
              aria-label={f.label}
              value={values[f.key] ?? ""}
              onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
            />
          )}
        </Field>
      ))}
      <Field label="Reason">
        <input aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} />
      </Field>
      <p className="muted">The member sees these values and chooses who else does. They cannot change them.</p>
      <button type="submit" className="primary" disabled={!reason || save.isPending}>
        Record
      </button>
    </form>
  );
}
