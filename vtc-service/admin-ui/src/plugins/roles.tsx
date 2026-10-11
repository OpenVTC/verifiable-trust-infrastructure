// Roles plugin — the community's administrative role vocabulary.
//
// Lists the built-in roles and the community's custom ones
// (`vtc/roles/list/0.1`), each with its ceiling and approve ceiling — the
// records the VTC enforces. Any administrator may read it. Defining and
// deleting a custom role (`vtc/roles/{define,delete}/0.1`) are offered only to
// a viewer holding `vtc.roles.assign` and `vtc.approvals.admin`; both are
// parked for other holders' approval (`docs/05-design-notes/vtc-admin-roles.md`
// §6.2, §7) and land in the Actions list.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, X } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable, useSortedRows } from "@/components/DataTable";
import { Field } from "@/components/Field";
import { PageHeader } from "@/components/PageHeader";
import { CAPABILITIES } from "@/lib/acl";
import {
  ROLE_ADMIN_CAPABILITIES,
  ROLE_NAME_PATTERN,
  capRefLabel,
  defineRole,
  deleteRole,
  listRoles,
  showRole,
  type CapabilityRef,
  type RoleDefinition,
} from "@/lib/roles";
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";
import { holds, useCapabilities } from "@/lib/viewer";

type RoleSortKey = "name" | "kind";

/** Capabilities a ceiling may name: every registry entry but the additive one. */
const CEILING_CHOICES = CAPABILITIES.filter((c) => c.id !== "git.commit.sign");

function CapList({ refs }: { refs: CapabilityRef[] }) {
  if (refs.length === 0) return <span className="muted">none</span>;
  return (
    <ul className="cap-list">
      {refs.map((r) => (
        <li key={capRefLabel(r)}>
          <code>{capRefLabel(r)}</code>
        </li>
      ))}
    </ul>
  );
}

function Holders({ name }: { name: string }) {
  const q = useQuery({
    queryKey: ["roles", "show", name],
    queryFn: () => showRole(name),
  });
  if (q.isLoading) return <span className="muted">…</span>;
  if (q.error || q.data?.holders === undefined) return <span className="muted">—</span>;
  return <span>{q.data.holders}</span>;
}

export function Roles() {
  const caps = useCapabilities();
  const mayAdminister = ROLE_ADMIN_CAPABILITIES.every((c) => holds(caps, c));
  const [defining, setDefining] = useState(false);
  const queryClient = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();

  const query = useQuery({ queryKey: ["roles"], queryFn: () => listRoles(true) });

  const remove = useMutation({
    mutationFn: (name: string) => deleteRole(name, undefined, gestureFromConfirm(confirm)),
    onSuccess: (_, name) => {
      toast.push("success", `Deleted role ${name}`);
      void queryClient.invalidateQueries({ queryKey: ["roles"] });
    },
    onError: (err) => toast.pushFromError(err, "Delete failed"),
  });

  const roles = query.data ?? [];
  const sorted = useSortedRows<RoleDefinition, RoleSortKey>(roles, (r, key) =>
    key === "name" ? r.name : r.builtIn ? "built-in" : "custom",
  );

  return (
    <section className="page">
      <PageHeader
        count={query.data ? roles.length : undefined}
        countLabel={`${roles.length} roles`}
        lead="A role is a ceiling: what an entry holding it may hold and may approve. It grants nothing on its own."
        actions={
          mayAdminister && (
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
                  <Plus size={14} aria-hidden="true" /> Define role
                </>
              )}
            </button>
          )
        }
      />

      {defining && mayAdminister && (
        <DefineRoleForm
          onDone={() => {
            setDefining(false);
            void queryClient.invalidateQueries({ queryKey: ["roles"] });
          }}
        />
      )}

      {query.error && (
        <section className="card error">
          <h3>Failed to load roles</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <DataTable
          caption="Administrative roles"
          sort={sorted.sort}
          onSort={sorted.onSort}
          columns={[
            { key: "name", label: "Role", sortKey: "name" },
            { key: "kind", label: "Kind", sortKey: "kind" },
            { key: "hold", label: "May hold" },
            { key: "approve", label: "May approve" },
            { key: "holders", label: "Holders" },
            ...(mayAdminister ? [{ key: "actions", label: "" }] : []),
          ]}
        >
          {sorted.rows.map((r) => (
            <tr key={r.name}>
              <td>
                <strong>{r.name}</strong>
                {r.description && <div className="muted">{r.description}</div>}
              </td>
              <td>{r.builtIn ? "built-in" : "custom"}</td>
              <td>
                <CapList refs={r.ceiling} />
              </td>
              <td>
                <CapList refs={r.approveScope} />
              </td>
              <td>
                <Holders name={r.name} />
              </td>
              {mayAdminister && (
                <td>
                  {!r.builtIn && (
                    <button
                      type="button"
                      className="secondary"
                      aria-label={`Delete role ${r.name}`}
                      disabled={remove.isPending}
                      onClick={() => remove.mutate(r.name)}
                    >
                      <Trash2 size={14} aria-hidden="true" /> Delete
                    </button>
                  )}
                </td>
              )}
            </tr>
          ))}
        </DataTable>
      </section>
    </section>
  );
}

function CapChecklist({
  legend,
  selected,
  onChange,
}: {
  legend: string;
  selected: string[];
  onChange: (next: string[]) => void;
}) {
  return (
    <fieldset className="field">
      <legend className="field-label">{legend}</legend>
      {CEILING_CHOICES.map((c) => (
        <label key={c.id} className="checkbox">
          <input
            type="checkbox"
            aria-label={`${legend}: ${c.id}`}
            checked={selected.includes(c.id)}
            onChange={(e) =>
              onChange(e.target.checked ? [...selected, c.id] : selected.filter((x) => x !== c.id))
            }
          />
          <span className="checkbox-text">
            <code>{c.id}</code> <span className="muted">— {c.gates}</span>
          </span>
        </label>
      ))}
    </fieldset>
  );
}

function DefineRoleForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [ceiling, setCeiling] = useState<string[]>([]);
  const [approve, setApprove] = useState<string[]>([]);
  const [reason, setReason] = useState("");
  const toast = useToast();
  const confirm = useConfirm();

  const define = useMutation({
    mutationFn: () =>
      defineRole(
        {
          name,
          ...(description ? { description } : {}),
          ceiling: ceiling.map((capability) => ({ capability })),
          approveScope: approve.map((capability) => ({ capability })),
          ...(reason ? { reason } : {}),
        },
        gestureFromConfirm(confirm),
      ),
    onSuccess: (role) => {
      toast.push("success", `Defined role ${role.name}`);
      onDone();
    },
    onError: (err) => {
      toast.pushFromError(err, "Define failed");
      onDone();
    },
  });

  const nameOk = ROLE_NAME_PATTERN.test(name);
  return (
    <section className="card">
      <h3>Define a role</h3>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (nameOk) define.mutate();
        }}
      >
        <Field label="Name">
          <input
            aria-label="Role name"
            value={name}
            placeholder="events-team"
            onChange={(e) => setName(e.target.value.trim())}
          />
        </Field>
        {name !== "" && !nameOk && (
          <p className="error">Lowercase letters, digits and hyphens, starting with a letter.</p>
        )}
        <Field label="Description">
          <input
            aria-label="Role description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <CapChecklist legend="May hold" selected={ceiling} onChange={setCeiling} />
        <CapChecklist legend="May approve" selected={approve} onChange={setApprove} />
        <Field label="Reason (shown to approvers)">
          <input
            aria-label="Reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </Field>
        <p className="muted">
          Other holders of vtc.roles.assign and vtc.approvals.admin approve this before it takes
          effect. A role cannot name a capability its definers do not hold themselves.
        </p>
        <button type="submit" className="primary" disabled={!nameOk || define.isPending}>
          Send for approval
        </button>
      </form>
    </section>
  );
}
