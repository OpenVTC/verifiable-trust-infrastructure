// Member badges, administered (`vtc/badges/*`, docs/03-vtc/badges.md).
//
//   /badges            Every badge this administrator or owner may see; define a community
//                      badge; the settings.
//   /badges/settings   On or off, who may make kudos badges, the limits — vtc.config.admin
//                      with a bound step-up.
//   /badges/new        A new community badge: picture, credential regime, rules, owners.
//   /badges/:id        One badge: change it, give it, decide requests for it, its owners,
//                      every award given and taken back, retire it; a kudos badge's givings
//                      and its promotion to a community badge.
//
// A community badge is a badge group: requests for it and its owners are the group's requests
// and managers, through `@/lib/groups`. Members hold, hide and arrange their badges, and give
// kudos, from the member portal; this page never writes as a member (VTI-BDG-095).

import { useMemo, useState } from "react";
import { Link, Route, Routes, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Award as AwardIcon, Check, Gift, Pencil, Plus, Settings2, Sparkles, Trash2, X } from "lucide-react";

import { BadgePicture, BadgePictureField } from "@/components/BadgePicture";
import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { EntryName, useEntryFaces } from "@/components/EntryName";
import { Field } from "@/components/Field";
import { PageHeader } from "@/components/PageHeader";
import {
  AWARD_STATE_LABEL,
  BADGES_ADMIN,
  BADGES_KEY,
  CONFIG_ADMIN,
  DEFAULT_LIMITS,
  HOLDERS_AUDIENCES,
  SKIPPED_LABEL,
  createBadge,
  listAwards,
  listBadges,
  listHolders,
  listKudosGivings,
  offerAwards,
  promoteBadge,
  retireBadge,
  revokeAward,
  showBadge,
  showSettings,
  updateBadge,
  updateSettings,
  withdrawAward,
  type AwardRow,
  type Badge,
  type BadgeImageRef,
  type BadgeLimits,
  type BadgeSettings,
  type KudosMakers,
} from "@/lib/badges";
import {
  GROUPS_MANAGE,
  addGroupManager,
  decideGroupRequest,
  listGroupRequests,
  listGroups,
  removeGroupManager,
  showGroup,
} from "@/lib/groups";
import { type DynamicRule, RuleEditor, emptyRule, ruleReady, wireRule } from "@/plugins/GroupRule";
import { listRoles } from "@/lib/roles";
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";
import { holds, useCapabilities } from "@/lib/viewer";

const SETTINGS_KEY = ["badges", "settings"] as const;

function kindLabel(b: Badge): string {
  return b.kind === "community" ? "Community badge" : "Kudos badge";
}

function when(iso: string | undefined): string {
  return iso ? new Date(iso).toLocaleDateString() : "—";
}

export function Badges() {
  return (
    <section className="page">
      <Routes>
        <Route index element={<BadgesList />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="new" element={<CreateBadgePage />} />
        <Route path=":id" element={<BadgePage />} />
      </Routes>
    </section>
  );
}

// ─── the list ─────────────────────────────────────────────────────────────

function useSettings() {
  return useQuery({ queryKey: SETTINGS_KEY, queryFn: showSettings, retry: false });
}

function OffNotice({ settings }: { settings: BadgeSettings | undefined }) {
  const caps = useCapabilities();
  if (!settings || settings.enabled) return null;
  return (
    <section className="card badge-off" role="status">
      <h3>Badges are off</h3>
      <p>
        Members see no badge, and nothing is given while badges are off; every record is kept.
        {holds(caps, CONFIG_ADMIN) ? (
          <>
            {" "}
            Turn them on in <Link to="settings">the settings</Link>.
          </>
        ) : (
          " A holder of vtc.config.admin turns them on."
        )}
      </p>
    </section>
  );
}

function BadgesList() {
  const caps = useCapabilities();
  const navigate = useNavigate();
  const settings = useSettings();
  const list = useQuery({ queryKey: BADGES_KEY, queryFn: listBadges, retry: false });
  const items = list.data ?? [];
  const defines = holds(caps, BADGES_ADMIN);
  const configures = holds(caps, CONFIG_ADMIN);
  const community = items.filter((i) => i.badge.kind === "community").length;
  return (
    <>
      <PageHeader
        count={list.data ? items.length : null}
        countLabel={list.data ? `${items.length} badges` : undefined}
        lead="A badge is a picture with a name a member earns and shows on their card. A community badge is backed by a group of its own whose identity issues each holder an Open Badge; a kudos badge is one any member gives another."
        actions={
          <>
            {configures && (
              <Link className="secondary" to="settings">
                <Settings2 size={14} aria-hidden="true" /> Settings
              </Link>
            )}
            {defines && (
              <Link className="primary" to="new">
                <Plus size={14} aria-hidden="true" /> New badge
              </Link>
            )}
          </>
        }
      />
      <OffNotice settings={settings.data} />
      {list.error && (
        <section className="card error">
          <h3>Failed to read the badges</h3>
          <p>{(list.error as Error).message}</p>
        </section>
      )}
      <section className="card table-card">
        <DataTable
          caption="Badges"
          columns={[
            { key: "name", label: "Badge" },
            { key: "kind", label: "Kind" },
            { key: "holders", label: "Holders" },
            { key: "state", label: "State" },
          ]}
        >
          {list.isSuccess && items.length === 0 && (
            <tr>
              <td colSpan={4}>
                <EmptyState icon={AwardIcon} title="No badges yet">
                  Workshop host, a year in the community, thanks for the welcome
                  {defines ? ": define one with New badge." : "."}
                </EmptyState>
              </td>
            </tr>
          )}
          {items.map(({ badge }) => (
            <tr key={badge.badgeId} className="clickable" onClick={() => navigate(encodeURIComponent(badge.badgeId))}>
              <td>
                <div className="badge-name-cell">
                  <BadgePicture badgeId={badge.badgeId} image={badge.image} name={badge.name} size={44} />
                  <div>
                    <strong>{badge.name}</strong>
                    <span className="muted">{badge.description}</span>
                  </div>
                </div>
              </td>
              <td>{kindLabel(badge)}</td>
              <td>{typeof badge.holderCount === "number" ? badge.holderCount : <span className="muted">—</span>}</td>
              <td>
                {badge.state === "retired" ? (
                  <span className="chip">Retired</span>
                ) : badge.listed ? (
                  "Active"
                ) : (
                  <>
                    Active <span className="muted">(unlisted)</span>
                  </>
                )}
              </td>
            </tr>
          ))}
        </DataTable>
        {list.isSuccess && items.length > 0 && (
          <p className="muted">
            {community} community, {items.length - community} by members.
          </p>
        )}
      </section>
    </>
  );
}

// ─── the settings ─────────────────────────────────────────────────────────

const SAME_GIVER: { id: NonNullable<BadgeLimits["sameGiverSameMember"]>; label: string }[] = [
  { id: "day", label: "Once a day" },
  { id: "week", label: "Once a week" },
  { id: "unbounded", label: "No limit" },
];

function SettingsPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const caps = useCapabilities();
  const settings = useSettings();
  const roles = useQuery({ queryKey: ["roles", "list"], queryFn: () => listRoles(true), retry: false });
  const groups = useQuery({ queryKey: ["groups", "list"], queryFn: listGroups, retry: false });
  const [draft, setDraft] = useState<BadgeSettings | null>(null);
  const [reason, setReason] = useState("");
  const current = draft ?? settings.data ?? null;
  const limits: BadgeLimits = { ...DEFAULT_LIMITS, ...(current?.limits ?? {}) };
  const makers: KudosMakers = current?.kudosMakers ?? { policy: "members" };
  const set = (patch: Partial<BadgeSettings>) => current && setDraft({ ...current, ...patch });
  const setLimit = (patch: Partial<BadgeLimits>) => set({ limits: { ...limits, ...patch } });
  const save = useMutation({
    mutationFn: () => updateSettings(draft!, reason.trim(), gestureFromConfirm(confirm)),
    onSuccess: (s) => {
      qc.setQueryData(SETTINGS_KEY, s);
      void qc.invalidateQueries({ queryKey: BADGES_KEY });
      setDraft(null);
      setReason("");
      toast.push("success", "Badge settings saved.");
    },
    onError: (err) => toast.pushFromError(err, "The settings were not saved"),
  });
  const number = (key: keyof BadgeLimits, min: number, max: number) => (
    <input
      type="number"
      min={min}
      max={max}
      value={limits[key] ?? ""}
      onChange={(e) => {
        const v = e.target.value === "" ? undefined : Number(e.target.value);
        setLimit({ [key]: v } as Partial<BadgeLimits>);
      }}
    />
  );
  if (!holds(caps, CONFIG_ADMIN)) {
    return (
      <>
        <PageHeader title="Badge settings" trail={[{ label: "Settings" }]} />
        <EmptyState title="Only a holder of vtc.config.admin changes the badge settings." />
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="Badge settings"
        trail={[{ label: "Settings" }]}
        lead="Whether members see badges at all, who may make a kudos badge, and the limits. Saving takes a step-up with your passkey, like every community setting."
      />
      {settings.error && (
        <section className="card error">
          <h3>Failed to read the settings</h3>
          <p>{(settings.error as Error).message}</p>
        </section>
      )}
      {current && (
        <form
          className="card form-stack"
          onSubmit={(e) => {
            e.preventDefault();
            if (draft && reason.trim()) save.mutate();
          }}
        >
          <label className="checkbox">
            <input type="checkbox" checked={current.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
            <span className="checkbox-text">
              <strong>Badges are {current.enabled ? "on" : "off"}</strong>
              <br />
              Members see the Badges page, badges on cards, and can accept what they are given. Off hides
              everything at once and keeps every record; nothing is revoked.
            </span>
          </label>

          <div className="badge-settings-section">
            <h4>Who may make a kudos badge</h4>
            <p className="muted">
              Community badges are always defined here by holders of vtc.badges.admin. This is about members&rsquo;
              own badges in the portal, the ones any member gives another.
            </p>
            <div className="badge-choice-list" role="radiogroup" aria-label="Who may make a kudos badge">
              {(
                [
                  ["nobody", "Nobody", "No member-made badges; the portal shows no Make a badge button."],
                  ["roles", "Chosen roles and groups", "Members holding one of the roles, or in one of the groups, below."],
                  ["members", "Every active member", "Anyone who can sign in to the portal, within the limits."],
                ] as const
              ).map(([id, label, help]) => (
                <label key={id} className="checkbox">
                  <input
                    type="radio"
                    name="kudos-makers"
                    checked={makers.policy === id}
                    onChange={() => set({ kudosMakers: { ...makers, policy: id } })}
                  />
                  <span className="checkbox-text">
                    <strong>{label}</strong>
                    <br />
                    <span className="muted">{help}</span>
                  </span>
                </label>
              ))}
            </div>
            {makers.policy === "roles" && (
              <div className="form-grid">
                <Field label="Roles" hint="Members holding any of these may make a kudos badge.">
                  <div className="badge-member-picker" role="group" aria-label="Roles">
                    {(roles.data ?? []).map((r) => (
                      <label key={r.name} className="checkbox">
                        <input
                          type="checkbox"
                          checked={(makers.roles ?? []).includes(r.name)}
                          onChange={(e) => {
                            const next = new Set(makers.roles ?? []);
                            if (e.target.checked) next.add(r.name);
                            else next.delete(r.name);
                            set({ kudosMakers: { ...makers, roles: [...next] } });
                          }}
                        />
                        <span className="checkbox-text">{r.name}</span>
                      </label>
                    ))}
                  </div>
                </Field>
                <Field label="Groups" hint="Or members of any of these groups.">
                  <div className="badge-member-picker" role="group" aria-label="Groups">
                    {(groups.data ?? []).map(({ group }) => (
                      <label key={group.groupId} className="checkbox">
                        <input
                          type="checkbox"
                          checked={(makers.groups ?? []).includes(group.groupId)}
                          onChange={(e) => {
                            const next = new Set(makers.groups ?? []);
                            if (e.target.checked) next.add(group.groupId);
                            else next.delete(group.groupId);
                            set({ kudosMakers: { ...makers, groups: [...next] } });
                          }}
                        />
                        <span className="checkbox-text">{group.name}</span>
                      </label>
                    ))}
                  </div>
                </Field>
              </div>
            )}
          </div>

          <div className="badge-settings-section">
            <h4>Kudos</h4>
            <p className="muted">
              A kudos badge is one any active member may give to another. Each giving counts, so a member can hold
              &ldquo;Thanks for the welcome&rdquo; twenty times. Picture only, never a credential. Nobody gives kudos
              to themselves.
            </p>
            <div className="badge-settings-grid">
              <Field label="Kudos a member may give a day">{number("kudosPerGiverPerDay", 1, 1000)}</Field>
              <Field label="Same giver to the same member">
                <select
                  value={limits.sameGiverSameMember}
                  onChange={(e) => setLimit({ sameGiverSameMember: e.target.value as BadgeLimits["sameGiverSameMember"] })}
                >
                  {SAME_GIVER.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Days of membership before giving or making one">{number("minTenureDays", 0, 3650)}</Field>
              <Field label="Kudos badges a member may make a month">{number("kudosBadgesPerMakerPerMonth", 0, 1000)}</Field>
            </div>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={current.showKudosTotals}
                onChange={(e) => set({ showKudosTotals: e.target.checked })}
              />
              <span className="checkbox-text">Show each member&rsquo;s kudos total on their wall</span>
            </label>
          </div>

          <div className="badge-settings-section">
            <h4>Community badges</h4>
            <div className="badge-settings-grid">
              <Field label="Badges a member may pin beside their name">{number("maxPinned", 0, 8)}</Field>
              <Field label="Days an unanswered offer stands" hint="Empty: offers never expire.">
                {number("offerExpiresAfterDays", 1, 365)}
              </Field>
              <Field
                label="Days a credential shown outside lasts"
                hint="For badges marked shareable outside. Empty: two years. Renewed while held; revoked when taken back."
              >
                <input
                  type="number"
                  min={30}
                  max={3650}
                  value={current.credentialValidDays ?? ""}
                  onChange={(e) =>
                    set({ credentialValidDays: e.target.value === "" ? undefined : Number(e.target.value) })
                  }
                />
              </Field>
            </div>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={current.membersMayRequest}
                onChange={(e) => set({ membersMayRequest: e.target.checked })}
              />
              <span className="checkbox-text">Members may ask a badge&rsquo;s owners for it (a badge marked requestable)</span>
            </label>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={current.automaticBadges}
                onChange={(e) => set({ automaticBadges: e.target.checked })}
              />
              <span className="checkbox-text">
                Automatic badges: a community badge given by a rule over verified facts (role, join date, a verified
                field), without an owner&rsquo;s hand
              </span>
            </label>
          </div>

          <Field label="Why" className="span-2" hint="Recorded in the audit trail.">
            <input value={reason} maxLength={1024} onChange={(e) => setReason(e.target.value)} />
          </Field>
          <div className="form-actions">
            <button type="submit" className="primary" disabled={!draft || !reason.trim() || save.isPending}>
              {save.isPending ? "Saving…" : "Save with step-up"}
            </button>
            <button type="button" className="secondary" disabled={!draft} onClick={() => setDraft(null)}>
              Discard
            </button>
          </div>
        </form>
      )}
    </>
  );
}

// ─── a new community badge ────────────────────────────────────────────────

/** A picker of directory entries: checkboxes over the names the console shows. */
function MemberPicker({
  label,
  chosen,
  onChange,
  exclude = [],
}: {
  label: string;
  chosen: string[];
  onChange: (next: string[]) => void;
  exclude?: string[];
}) {
  const faces = useEntryFaces();
  const [filter, setFilter] = useState("");
  const entries = useMemo(
    () =>
      [...faces.entries()]
        .filter(([id]) => !exclude.includes(id))
        .filter(([, f]) => !filter || (f.name ?? "").toLowerCase().includes(filter.toLowerCase()))
        .sort(([, a], [, b]) => (a.name ?? "~").localeCompare(b.name ?? "~")),
    [faces, exclude, filter],
  );
  return (
    <Field label={label} hint={chosen.length > 0 ? `${chosen.length} chosen` : undefined}>
      <input
        type="search"
        placeholder="Find a member…"
        aria-label={`Find a member for ${label}`}
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      <div className="badge-member-picker" role="group" aria-label={label}>
        {entries.length === 0 && <span className="muted">No members match.</span>}
        {entries.map(([id, f]) => (
          <label key={id} className="checkbox">
            <input
              type="checkbox"
              checked={chosen.includes(id)}
              onChange={(e) => onChange(e.target.checked ? [...chosen, id] : chosen.filter((x) => x !== id))}
            />
            <span className="checkbox-text">{f.name ?? <span className="muted">(no name)</span>}</span>
          </label>
        ))}
      </div>
    </Field>
  );
}

function CreateBadgePage() {
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const caps = useCapabilities();
  const settings = useSettings();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [criteria, setCriteria] = useState("");
  const [image, setImage] = useState<BadgeImageRef | null>(null);
  const [repeatable, setRepeatable] = useState(false);
  const [requestable, setRequestable] = useState(true);
  const [listed, setListed] = useState(true);
  const [holdersVisibleTo, setHoldersVisibleTo] = useState<"admins" | "groupMembers" | "members">("members");
  const [shareableOutside, setShareableOutside] = useState(false);
  const [owners, setOwners] = useState<string[]>([]);
  const [automatic, setAutomatic] = useState(false);
  const [rule, setRule] = useState<DynamicRule>(emptyRule);
  const [reason, setReason] = useState("");
  const mayRequest = settings.data?.membersMayRequest ?? true;
  const mayAutomate = settings.data?.automaticBadges ?? false;
  const create = useMutation({
    mutationFn: () =>
      createBadge({
        kind: "community",
        name: name.trim(),
        description: description.trim(),
        ...(criteria.trim() ? { criteria: criteria.trim() } : {}),
        image: { sha256: image!.sha256 },
        repeatable,
        requestable: automatic ? false : requestable && mayRequest,
        listed,
        holdersVisibleTo,
        shareableOutside,
        ...(owners.length > 0 ? { owners } : {}),
        ...(automatic ? { automatic: { rule: wireRule(rule) } } : {}),
        reason: reason.trim(),
      }),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: BADGES_KEY });
      toast.push("success", `Defined ${r.badge.name}.`);
      navigate(`/badges/${encodeURIComponent(r.badge.badgeId)}`);
    },
    onError: (err) => toast.pushFromError(err, "The badge was not defined"),
  });
  const ok = name.trim() && description.trim() && image && reason.trim() && (!automatic || ruleReady(rule));
  if (!holds(caps, BADGES_ADMIN)) {
    return (
      <>
        <PageHeader title="New badge" trail={[{ label: "New badge" }]} />
        <EmptyState title="Only a holder of vtc.badges.admin defines a community badge." />
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="New community badge"
        trail={[{ label: "New badge" }]}
        lead="A community badge is a badge group: its holders are the group's members, its owners the group's managers, and the group's own identity issues each holder an Open Badge credential when they accept."
      />
      <form
        className="card form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (ok) create.mutate();
        }}
      >
        <div className="form-grid">
          <Field label="Name" hint="Shown on the wall and written into the credential.">
            <input value={name} maxLength={64} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field label="Who sees its holders">
            <select
              value={holdersVisibleTo}
              onChange={(e) => setHoldersVisibleTo(e.target.value as typeof holdersVisibleTo)}
            >
              {HOLDERS_AUDIENCES.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="What it is for" className="span-2" hint="Shown to members and written into the credential.">
            <textarea className="prose" rows={2} value={description} maxLength={1000} onChange={(e) => setDescription(e.target.value)} />
          </Field>
          <Field label="How it is earned" className="span-2" hint="Optional. The credential's criteria narrative.">
            <textarea className="prose" rows={2} value={criteria} maxLength={1000} onChange={(e) => setCriteria(e.target.value)} />
          </Field>
          <Field label="Picture" className="span-2">
            <BadgePictureField value={image} onChange={setImage} />
          </Field>
          <div className="span-2 badge-settings-section">
            <h4>Credential</h4>
            <p className="muted">
              Each holder gets an Open Badge credential issued by the badge&rsquo;s own group identity and endorsed
              by the community. Inside the community it is short-lived and renewed while they hold the badge, with
              no status list.
            </p>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={shareableOutside}
                onChange={(e) => setShareableOutside(e.target.checked)}
              />
              <span className="checkbox-text">
                May be shown outside the community
                <br />
                <span className="muted">
                  Long-lived ({settings.data?.credentialValidDays ?? 730} days, set in the settings) with a
                  revocation slot in the community&rsquo;s own status list. Fixed once created.
                </span>
              </span>
            </label>
          </div>
          <div className="span-2 badge-settings-section">
            <h4>Rules</h4>
            <label className="checkbox">
              <input type="checkbox" checked={repeatable} onChange={(e) => setRepeatable(e.target.checked)} />
              <span className="checkbox-text">Can be given to the same member more than once</span>
            </label>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={!automatic && requestable && mayRequest}
                disabled={automatic || !mayRequest}
                onChange={(e) => setRequestable(e.target.checked)}
              />
              <span className="checkbox-text">
                Members may ask for it{!mayRequest && <span className="muted"> (off in the settings)</span>}
              </span>
            </label>
            <label className="checkbox">
              <input type="checkbox" checked={listed} onChange={(e) => setListed(e.target.checked)} />
              <span className="checkbox-text">
                Listed in Browse all badges (off: members see it only once they hold it)
              </span>
            </label>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={automatic}
                disabled={!mayAutomate}
                onChange={(e) => setAutomatic(e.target.checked)}
              />
              <span className="checkbox-text">
                Given automatically by a rule over verified facts
                {!mayAutomate && <span className="muted"> (automatic badges are off in the settings)</span>}
              </span>
            </label>
            {automatic && <RuleEditor value={rule} onChange={setRule} />}
          </div>
          <div className="span-2 badge-settings-section">
            <MemberPicker label="Owners" chosen={owners} onChange={setOwners} />
            <p className="muted">
              Owners give the badge and decide requests for it. They are appointed as the badge group&rsquo;s
              managers, so they can change over time. Holders of vtc.badges.admin may give any badge regardless.
            </p>
          </div>
          <Field label="Why" className="span-2" hint="Recorded in the audit trail.">
            <input value={reason} maxLength={1024} onChange={(e) => setReason(e.target.value)} />
          </Field>
        </div>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={!ok || create.isPending}>
            {create.isPending ? "Creating…" : "Create badge"}
          </button>
          <Link className="secondary" to="/badges">
            Cancel
          </Link>
        </div>
      </form>
    </>
  );
}

// ─── one badge ────────────────────────────────────────────────────────────

function BadgePage() {
  const { id = "" } = useParams();
  const badgeId = decodeURIComponent(id);
  const caps = useCapabilities();
  const q = useQuery({ queryKey: ["badges", "show", badgeId], queryFn: () => showBadge(badgeId), retry: false });
  const badge = q.data?.badge;
  const admin = holds(caps, BADGES_ADMIN);
  const owns = Boolean(badge?.groupId && holds(caps, GROUPS_MANAGE, `group:${badge.groupId}`));
  const navigate = useNavigate();
  return (
    <>
      <PageHeader title={badge?.name ?? "Badge"} trail={[{ label: badge?.name ?? "Badge" }]} />
      {q.error && (
        <section className="card error">
          <h3>Failed to read the badge</h3>
          <p>{(q.error as Error).message}</p>
        </section>
      )}
      {badge && (
        <>
          <BadgeSummary badge={badge} owners={q.data?.owners ?? []} maker={q.data?.maker} admin={admin} owns={owns} />
          {badge.state === "active" && (admin || owns) && badge.kind === "community" && <OfferForm badge={badge} />}
          {badge.groupId && (admin || owns) && <BadgeRequests groupId={badge.groupId} />}
          {badge.groupId && (admin || owns) && <BadgeOwners groupId={badge.groupId} />}
          {(admin || owns) && badge.kind === "community" && <BadgeAwards badge={badge} />}
          {admin && badge.kind === "kudos" && <KudosGivings badge={badge} />}
          {badge.state === "active" && admin && badge.kind === "kudos" && <PromoteForm badge={badge} />}
          {badge.state === "active" && admin && <RetireForm badge={badge} onDone={() => navigate("/badges")} />}
        </>
      )}
    </>
  );
}

function BadgeSummary({
  badge,
  owners,
  maker,
  admin,
  owns,
}: {
  badge: Badge;
  owners: string[];
  maker: string | undefined;
  admin: boolean;
  owns: boolean;
}) {
  const faces = useEntryFaces();
  const [editing, setEditing] = useState(false);
  const holders = useQuery({
    queryKey: ["badges", "holders", badge.badgeId],
    queryFn: () => listHolders(badge.badgeId),
    retry: false,
  });
  const group = useQuery({
    queryKey: ["groups", "show", badge.groupId ?? ""],
    queryFn: () => showGroup(badge.groupId!),
    enabled: Boolean(badge.groupId),
    retry: false,
  });
  return (
    <section className="card" aria-labelledby="badge-summary-title">
      <div className="badge-summary">
        <BadgePicture badgeId={badge.badgeId} image={badge.image} name={badge.name} size={160} />
        <div className="badge-summary-text">
          <h3 id="badge-summary-title">{badge.name}</h3>
          <div className="pills">
            <span className="chip">{kindLabel(badge)}</span>
            {badge.state === "retired" && <span className="chip">Retired {when(badge.retiredAt)}</span>}
            {badge.kind === "community" && <span className="chip">Open Badge credential</span>}
            {badge.repeatable && <span className="chip">Repeatable</span>}
            {badge.requestable && <span className="chip">Members may ask</span>}
            {!badge.listed && <span className="chip">Unlisted</span>}
            {group.data?.group.kind === "dynamic" && <span className="chip">Automatic</span>}
          </div>
          <p>{badge.description}</p>
          {badge.criteria && (
            <p className="muted">
              <strong>How it is earned:</strong> {badge.criteria}
            </p>
          )}
          <dl className="badge-facts">
            <dt>Holders</dt>
            <dd>
              {holders.data ? `${holders.data.total} showing it` : "…"}
              {typeof badge.holderCount === "number" && holders.data && badge.holderCount !== holders.data.total
                ? ` · ${badge.holderCount} counted`
                : ""}
            </dd>
            {badge.kind === "community" && (
              <>
                <dt>Owners</dt>
                <dd>
                  {owners.length === 0 ? (
                    <span className="muted">none appointed; administrators give it</span>
                  ) : (
                    owners.map((e) => faces.get(e)?.name ?? e).join(", ")
                  )}
                </dd>
                <dt>Badge group</dt>
                <dd>
                  {badge.groupId ? (
                    <Link to={`/groups/${encodeURIComponent(badge.groupId)}`}>{group.data?.group.name ?? badge.groupId}</Link>
                  ) : (
                    "—"
                  )}
                </dd>
                <dt>Issued by</dt>
                <dd>The badge group&rsquo;s own identity, the community as the badge&rsquo;s creator</dd>
              </>
            )}
            {badge.kind === "kudos" && (
              <>
                <dt>Made by</dt>
                <dd>{maker ? (faces.get(maker)?.name ?? maker) : "a member"}</dd>
              </>
            )}
            <dt>Created</dt>
            <dd>{when(badge.createdAt)}</dd>
          </dl>
          {badge.state === "active" && (admin || owns) && (
            <div className="row-actions">
              <button type="button" className="secondary" onClick={() => setEditing(!editing)}>
                <Pencil size={14} aria-hidden="true" /> {editing ? "Close" : "Edit badge"}
              </button>
            </div>
          )}
        </div>
      </div>
      {editing && <EditBadgeForm badge={badge} onDone={() => setEditing(false)} />}
    </section>
  );
}

function EditBadgeForm({ badge, onDone }: { badge: Badge; onDone: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const settings = useSettings();
  const [name, setName] = useState(badge.name);
  const [description, setDescription] = useState(badge.description);
  const [criteria, setCriteria] = useState(badge.criteria ?? "");
  const [image, setImage] = useState<BadgeImageRef | null>(null);
  const [listed, setListed] = useState(badge.listed);
  const [requestable, setRequestable] = useState(badge.requestable ?? false);
  const [reason, setReason] = useState("");
  const mayRequest = settings.data?.membersMayRequest ?? true;
  const update = useMutation({
    mutationFn: () =>
      updateBadge({
        badgeId: badge.badgeId,
        ...(name.trim() !== badge.name ? { name: name.trim() } : {}),
        ...(description.trim() !== badge.description ? { description: description.trim() } : {}),
        ...(criteria.trim() !== (badge.criteria ?? "") ? { criteria: criteria.trim() || null } : {}),
        ...(image ? { image: { sha256: image.sha256 } } : {}),
        ...(listed !== badge.listed ? { listed } : {}),
        ...(badge.kind === "community" && requestable !== (badge.requestable ?? false) ? { requestable } : {}),
        reason: reason.trim(),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: BADGES_KEY });
      toast.push("success", "Badge changed.");
      onDone();
    },
    onError: (err) => toast.pushFromError(err, "The badge was not changed"),
  });
  return (
    <form
      className="form-stack"
      onSubmit={(e) => {
        e.preventDefault();
        if (name.trim() && description.trim() && reason.trim()) update.mutate();
      }}
    >
      <div className="form-grid">
        <Field label="Name">
          <input value={name} maxLength={64} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Listed">
          <select value={listed ? "yes" : "no"} onChange={(e) => setListed(e.target.value === "yes")}>
            <option value="yes">In Browse all badges</option>
            <option value="no">Holders, owners and administrators only</option>
          </select>
        </Field>
        <Field label="What it is for" className="span-2">
          <textarea className="prose" rows={2} value={description} maxLength={1000} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <Field label="How it is earned" className="span-2" hint="Empty clears it.">
          <textarea className="prose" rows={2} value={criteria} maxLength={1000} onChange={(e) => setCriteria(e.target.value)} />
        </Field>
        <Field label="Picture" className="span-2" hint="A new picture re-issues no credential.">
          <BadgePictureField badgeId={badge.badgeId} current={badge.image} value={image} onChange={setImage} />
        </Field>
        {badge.kind === "community" && (
          <label className="checkbox span-2">
            <input
              type="checkbox"
              checked={requestable && mayRequest}
              disabled={!mayRequest}
              onChange={(e) => setRequestable(e.target.checked)}
            />
            <span className="checkbox-text">
              Members may ask for it{!mayRequest && <span className="muted"> (off in the settings)</span>}
            </span>
          </label>
        )}
        <Field label="Why" className="span-2" hint="Recorded in the audit trail.">
          <input value={reason} maxLength={1024} onChange={(e) => setReason(e.target.value)} />
        </Field>
      </div>
      <div className="form-actions">
        <button type="submit" className="primary" disabled={!reason.trim() || update.isPending}>
          {update.isPending ? "Saving…" : "Save"}
        </button>
        <button type="button" className="secondary" onClick={onDone}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function OfferForm({ badge }: { badge: Badge }) {
  const qc = useQueryClient();
  const toast = useToast();
  const groups = useQuery({ queryKey: ["groups", "list"], queryFn: listGroups, retry: false });
  const [to, setTo] = useState<string[]>([]);
  const [group, setGroup] = useState("");
  const [note, setNote] = useState("");
  const offer = useMutation({
    mutationFn: () =>
      offerAwards({
        badgeId: badge.badgeId,
        ...(group ? { group } : { to }),
        ...(note.trim() ? { note: note.trim() } : {}),
      }),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: BADGES_KEY });
      setTo([]);
      setGroup("");
      setNote("");
      const skipped = r.skipped.length > 0 ? ` ${r.skipped.length} skipped: ${r.skipped.map((s) => SKIPPED_LABEL[s.reason]).join(", ")}.` : "";
      toast.push("success", `Offered to ${r.awards.length} member${r.awards.length === 1 ? "" : "s"}.${skipped}`);
    },
    onError: (err) => toast.pushFromError(err, "Not offered"),
  });
  const ok = group || to.length > 0;
  return (
    <section className="card" aria-labelledby="badge-offer-title">
      <h3 id="badge-offer-title">
        <Gift size={16} aria-hidden="true" /> Give {badge.name}
      </h3>
      <p className="muted">
        Each member is offered it and chooses. The credential is issued when they accept, to their wallet.
        {badge.repeatable ? "" : " A member who holds it, or was already offered it, is skipped."}
      </p>
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (ok) offer.mutate();
        }}
      >
        <div className="form-grid">
          {!group && <MemberPicker label="Members" chosen={to} onChange={setTo} />}
          <Field label="Or everyone in a group" hint="Every active member of the group is offered it.">
            <select aria-label="Group to offer to" value={group} onChange={(e) => setGroup(e.target.value)}>
              <option value="">Chosen members only</option>
              {/* Badge groups are never listed among the community's groups (VTI-BDG-012). */}
              {(groups.data ?? []).map(({ group: g }) => (
                <option key={g.groupId} value={g.groupId}>
                  {g.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="For" className="span-2" hint="Optional. Goes on the credential as the evidence line.">
            <input value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
          </Field>
        </div>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={!ok || offer.isPending}>
            {offer.isPending ? "Offering…" : group ? "Offer to the group" : `Offer to ${to.length} member${to.length === 1 ? "" : "s"}`}
          </button>
        </div>
      </form>
    </section>
  );
}

function BadgeRequests({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const faces = useEntryFaces();
  const requests = useQuery({
    queryKey: ["groups", "requests", groupId],
    queryFn: () => listGroupRequests(groupId),
    retry: false,
  });
  const decide = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "approve" | "decline" }) => decideGroupRequest(id, decision),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ["groups"] });
      void qc.invalidateQueries({ queryKey: BADGES_KEY });
      toast.push("success", r.state === "approved" ? "Given: the member's wallet receives the credential." : "Declined.");
    },
    onError: (err) => toast.pushFromError(err, "Not decided"),
  });
  const items = requests.data ?? [];
  if (items.length === 0) return null;
  return (
    <section className="card" aria-labelledby="badge-requests-title">
      <h3 id="badge-requests-title">
        Requests <span className="muted">({items.length})</span>
      </h3>
      <p className="muted">Members who asked for this badge. Approving gives it at once: their request is their consent.</p>
      <ul className="group-list">
        {items.map(({ request }) => (
          <li key={request.requestId}>
            <EntryName entryId={request.entryId} faces={faces} />
            <div className="row-actions">
              <button
                type="button"
                className="primary"
                onClick={() => decide.mutate({ id: request.requestId, decision: "approve" })}
                disabled={decide.isPending}
              >
                <Check size={14} aria-hidden="true" /> Give badge
              </button>
              <button
                type="button"
                className="secondary"
                onClick={() => decide.mutate({ id: request.requestId, decision: "decline" })}
                disabled={decide.isPending}
              >
                <X size={14} aria-hidden="true" /> Decline
              </button>
            </div>
            {request.message && <p className="group-request-note">{request.message}</p>}
          </li>
        ))}
      </ul>
    </section>
  );
}

function BadgeOwners({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const faces = useEntryFaces();
  const [adding, setAdding] = useState("");
  const group = useQuery({ queryKey: ["groups", "show", groupId], queryFn: () => showGroup(groupId), retry: false });
  const owners = group.data?.group.managers ?? [];
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["groups"] });
    void qc.invalidateQueries({ queryKey: BADGES_KEY });
  };
  const add = useMutation({
    mutationFn: (entryId: string) => addGroupManager(groupId, entryId),
    onSuccess: () => {
      setAdding("");
      refresh();
      toast.push("success", "Appointed as an owner.");
    },
    onError: (err) => toast.pushFromError(err, "Not appointed"),
  });
  const remove = useMutation({
    mutationFn: (entryId: string) => removeGroupManager(groupId, entryId),
    onSuccess: () => {
      refresh();
      toast.push("success", "No longer an owner.");
    },
    onError: (err) => toast.pushFromError(err, "Not changed"),
  });
  return (
    <section className="card" aria-labelledby="badge-owners-title">
      <h3 id="badge-owners-title">Owners</h3>
      <p className="muted">
        Owners give the badge, take it back and decide requests for it: the badge group&rsquo;s managers, appointed
        by name. Administrators who manage every group are not listed.
      </p>
      {owners.length === 0 ? (
        <EmptyState compact title="No owners appointed." />
      ) : (
        <ul className="group-list">
          {owners.map((e) => (
            <li key={e}>
              <EntryName entryId={e} faces={faces} />
              <div className="row-actions">
                <button type="button" className="secondary" onClick={() => remove.mutate(e)} disabled={remove.isPending}>
                  End appointment
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
      <form
        className="toolbar"
        onSubmit={(e) => {
          e.preventDefault();
          if (adding) add.mutate(adding);
        }}
      >
        <Field label="Appoint an owner" inline>
          <select aria-label="Member to appoint as owner" value={adding} onChange={(e) => setAdding(e.target.value)}>
            <option value="">Choose a member…</option>
            {[...faces.entries()]
              .filter(([e]) => !owners.includes(e))
              .map(([entryId, f]) => (
                <option key={entryId} value={entryId}>
                  {f.name ?? entryId}
                </option>
              ))}
          </select>
        </Field>
        <button type="submit" className="secondary" disabled={!adding || add.isPending}>
          Appoint
        </button>
      </form>
    </section>
  );
}

/** A reason asked for inline, for taking an award back or withdrawing an offer. */
function ReasonRow({
  label,
  onSubmit,
  onCancel,
  pending,
}: {
  label: string;
  onSubmit: (reason: string) => void;
  onCancel: () => void;
  pending: boolean;
}) {
  const [reason, setReason] = useState("");
  return (
    <form
      className="badge-reason-row"
      onSubmit={(e) => {
        e.preventDefault();
        if (reason.trim()) onSubmit(reason.trim());
      }}
    >
      <input
        aria-label={`Why: ${label}`}
        placeholder="Why (recorded in the audit trail)"
        value={reason}
        maxLength={1024}
        onChange={(e) => setReason(e.target.value)}
      />
      <button type="submit" className="primary" disabled={!reason.trim() || pending}>
        {label}
      </button>
      <button type="button" className="secondary" onClick={onCancel}>
        Cancel
      </button>
    </form>
  );
}

function BadgeAwards({ badge }: { badge: Badge }) {
  const qc = useQueryClient();
  const toast = useToast();
  const faces = useEntryFaces();
  const [pending, setPending] = useState<{ award: AwardRow["award"]; act: "withdraw" | "revoke" } | null>(null);
  const awards = useQuery({
    queryKey: ["badges", "awards", badge.badgeId],
    queryFn: () => listAwards(badge.badgeId),
    retry: false,
  });
  const done = (what: string) => () => {
    void qc.invalidateQueries({ queryKey: BADGES_KEY });
    void qc.invalidateQueries({ queryKey: ["groups"] });
    setPending(null);
    toast.push("success", what);
  };
  const withdraw = useMutation({
    mutationFn: ({ awardId, reason }: { awardId: string; reason: string }) => withdrawAward(awardId, reason),
    onSuccess: done("Offer withdrawn."),
    onError: (err) => toast.pushFromError(err, "Not withdrawn"),
  });
  const revoke = useMutation({
    mutationFn: ({ awardId, reason }: { awardId: string; reason: string }) => revokeAward(awardId, reason),
    onSuccess: done("Taken back."),
    onError: (err) => toast.pushFromError(err, "Not taken back"),
  });
  const rows = [...(awards.data ?? [])].sort((a, b) => (a.award.offeredAt < b.award.offeredAt ? 1 : -1));
  const open = rows.filter((r) => r.award.state === "offered").length;
  const hidden = rows.filter((r) => r.hidden).length;
  return (
    <section className="card table-card" aria-labelledby="badge-awards-title">
      <h3 id="badge-awards-title">
        Holders and offers{" "}
        {awards.data && (
          <span className="muted">
            ({rows.length} award{rows.length === 1 ? "" : "s"}
            {open ? `, ${open} waiting` : ""}
            {hidden ? `, ${hidden} hidden by their holders` : ""})
          </span>
        )}
      </h3>
      <p className="muted">
        A badge a holder has hidden shows here as hidden; the portal leaves it out. Taking a badge back ends its
        holder&rsquo;s membership of the badge group when it was their last award, and is audited by reference.
      </p>
      <DataTable
        caption="Awards"
        columns={[
          { key: "member", label: "Member" },
          { key: "state", label: "State" },
          { key: "when", label: "Offered" },
          { key: "by", label: "By" },
          { key: "note", label: "For" },
          { key: "actions", label: "" },
        ]}
      >
        {awards.isSuccess && rows.length === 0 && (
          <tr>
            <td colSpan={6}>
              <EmptyState compact title="Nobody has been offered it yet." />
            </td>
          </tr>
        )}
        {rows.map(({ award, hidden: h }) => (
          <tr key={award.awardId}>
            <td>
              <EntryName entryId={award.entryId} faces={faces} />
            </td>
            <td>
              {AWARD_STATE_LABEL[award.state]}
              {h && <span className="muted"> · hidden</span>}
              {award.state === "accepted" && award.credentialId && <span className="muted"> · credential issued</span>}
            </td>
            <td>
              {when(award.offeredAt)}
              {award.decidedAt && <span className="muted"> → {when(award.decidedAt)}</span>}
            </td>
            <td>{award.givenBy ? (faces.get(award.givenBy)?.name ?? "a member") : <span className="muted">the community</span>}</td>
            <td className="wrap">{award.note ?? <span className="muted">—</span>}</td>
            <td>
              <div className="row-actions">
                {award.state === "offered" && (
                  <button type="button" className="secondary" onClick={() => setPending({ award, act: "withdraw" })}>
                    Withdraw offer
                  </button>
                )}
                {award.state === "accepted" && (
                  <button type="button" className="secondary" onClick={() => setPending({ award, act: "revoke" })}>
                    <Trash2 size={14} aria-hidden="true" /> Take back…
                  </button>
                )}
              </div>
            </td>
          </tr>
        ))}
      </DataTable>
      {pending && (
        <ReasonRow
          label={pending.act === "withdraw" ? "Withdraw the offer" : "Take the badge back"}
          pending={withdraw.isPending || revoke.isPending}
          onCancel={() => setPending(null)}
          onSubmit={(reason) =>
            pending.act === "withdraw"
              ? withdraw.mutate({ awardId: pending.award.awardId, reason })
              : revoke.mutate({ awardId: pending.award.awardId, reason })
          }
        />
      )}
    </section>
  );
}

function KudosGivings({ badge }: { badge: Badge }) {
  const qc = useQueryClient();
  const toast = useToast();
  const faces = useEntryFaces();
  const [pending, setPending] = useState<string | null>(null);
  const givings = useQuery({
    queryKey: ["badges", "kudos", badge.badgeId],
    queryFn: () => listKudosGivings(badge.badgeId),
    retry: false,
  });
  const revoke = useMutation({
    mutationFn: ({ awardId, reason }: { awardId: string; reason: string }) => revokeAward(awardId, reason),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: BADGES_KEY });
      setPending(null);
      toast.push("success", "Taken back.");
    },
    onError: (err) => toast.pushFromError(err, "Not taken back"),
  });
  const rows = [...(givings.data ?? [])].sort((a, b) => (a.award.offeredAt < b.award.offeredAt ? 1 : -1));
  return (
    <section className="card table-card" aria-labelledby="badge-kudos-title">
      <h3 id="badge-kudos-title">
        Givings {givings.data && <span className="muted">({rows.length})</span>}
      </h3>
      <p className="muted">Who gave this badge to whom. Members see only what they received and gave.</p>
      <DataTable
        caption="Givings"
        columns={[
          { key: "to", label: "To" },
          { key: "from", label: "From" },
          { key: "state", label: "State" },
          { key: "when", label: "Given" },
          { key: "note", label: "Note" },
          { key: "actions", label: "" },
        ]}
      >
        {givings.isSuccess && rows.length === 0 && (
          <tr>
            <td colSpan={6}>
              <EmptyState compact title="Not given yet." />
            </td>
          </tr>
        )}
        {rows.map(({ award }) => (
          <tr key={award.awardId}>
            <td>
              <EntryName entryId={award.entryId} faces={faces} />
            </td>
            <td>{award.givenBy ? <EntryName entryId={award.givenBy} faces={faces} /> : "—"}</td>
            <td>{AWARD_STATE_LABEL[award.state]}</td>
            <td>{when(award.offeredAt)}</td>
            <td className="wrap">{award.note ?? <span className="muted">—</span>}</td>
            <td>
              {award.state === "accepted" && (
                <button type="button" className="secondary" onClick={() => setPending(award.awardId)}>
                  Take back…
                </button>
              )}
            </td>
          </tr>
        ))}
      </DataTable>
      {pending && (
        <ReasonRow
          label="Take the badge back"
          pending={revoke.isPending}
          onCancel={() => setPending(null)}
          onSubmit={(reason) => revoke.mutate({ awardId: pending, reason })}
        />
      )}
    </section>
  );
}

function PromoteForm({ badge }: { badge: Badge }) {
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const settings = useSettings();
  const [open, setOpen] = useState(false);
  const [owners, setOwners] = useState<string[]>([]);
  const [requestable, setRequestable] = useState(true);
  const [shareableOutside, setShareableOutside] = useState(false);
  const [reason, setReason] = useState("");
  const mayRequest = settings.data?.membersMayRequest ?? true;
  const promote = useMutation({
    mutationFn: () =>
      promoteBadge({
        badgeId: badge.badgeId,
        ...(owners.length > 0 ? { owners } : {}),
        requestable: requestable && mayRequest,
        shareableOutside,
        reason: reason.trim(),
      }),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: BADGES_KEY });
      toast.push(
        "success",
        `${r.badge.name} is a community badge now; ${r.holdersOffered} holder${r.holdersOffered === 1 ? "" : "s"} offered its credential.`,
      );
      navigate(`/badges/${encodeURIComponent(r.badge.badgeId)}`);
    },
    onError: (err) => toast.pushFromError(err, "Not promoted"),
  });
  return (
    <section className="card" aria-labelledby="badge-promote-title">
      <h3 id="badge-promote-title">
        <Sparkles size={16} aria-hidden="true" /> Make it a community badge
      </h3>
      <p className="muted">
        A kudos badge the community wants to stand behind: it gets a badge group with its own identity, and every
        holder is offered an Open Badge credential. Nothing changes for them until they accept.
      </p>
      {!open ? (
        <button type="button" className="secondary" onClick={() => setOpen(true)}>
          Promote…
        </button>
      ) : (
        <form
          className="form-stack"
          onSubmit={(e) => {
            e.preventDefault();
            if (reason.trim()) promote.mutate();
          }}
        >
          <div className="form-grid">
            <div className="span-2">
              <MemberPicker label="Owners" chosen={owners} onChange={setOwners} />
            </div>
            <label className="checkbox span-2">
              <input
                type="checkbox"
                checked={requestable && mayRequest}
                disabled={!mayRequest}
                onChange={(e) => setRequestable(e.target.checked)}
              />
              <span className="checkbox-text">Members may ask for it</span>
            </label>
            <label className="checkbox span-2">
              <input
                type="checkbox"
                checked={shareableOutside}
                onChange={(e) => setShareableOutside(e.target.checked)}
              />
              <span className="checkbox-text">
                May be shown outside the community (a long-lived credential with a revocation slot)
              </span>
            </label>
            <Field label="Why" className="span-2" hint="Recorded in the audit trail.">
              <input value={reason} maxLength={1024} onChange={(e) => setReason(e.target.value)} />
            </Field>
          </div>
          <div className="form-actions">
            <button type="submit" className="primary" disabled={!reason.trim() || promote.isPending}>
              {promote.isPending ? "Promoting…" : "Promote"}
            </button>
            <button type="button" className="secondary" onClick={() => setOpen(false)}>
              Cancel
            </button>
          </div>
        </form>
      )}
    </section>
  );
}

function RetireForm({ badge, onDone }: { badge: Badge; onDone: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const [reason, setReason] = useState("");
  const retire = useMutation({
    mutationFn: () => retireBadge(badge.badgeId, reason.trim(), gestureFromConfirm(confirm)),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: BADGES_KEY });
      void qc.invalidateQueries({ queryKey: ["groups"] });
      toast.push("success", `${badge.name} is retired.`);
      onDone();
    },
    onError: (err) => toast.pushFromError(err, "Not retired"),
  });
  return (
    <section className="card" aria-labelledby="badge-retire-title">
      <h3 id="badge-retire-title">Retire this badge</h3>
      <p className="muted">
        A retired badge is kept for its holders&rsquo; own history and never given again.
        {badge.kind === "community"
          ? " Its badge group is deleted and every credential it issued revoked at once; this takes a step-up with your passkey."
          : " Its holders keep the record; nobody is given it again."}
      </p>
      <form
        className="toolbar"
        onSubmit={async (e) => {
          e.preventDefault();
          if (!reason.trim()) return;
          const ok = await confirm({
            title: `Retire ${badge.name}?`,
            message: "Open offers are withdrawn and nothing is given again.",
            confirmLabel: "Retire",
            destructive: true,
          });
          if (ok) retire.mutate();
        }}
      >
        <Field label="Why" inline>
          <input value={reason} maxLength={1024} onChange={(e) => setReason(e.target.value)} />
        </Field>
        <button type="submit" className="secondary" disabled={!reason.trim() || retire.isPending}>
          <Trash2 size={14} aria-hidden="true" /> {retire.isPending ? "Retiring…" : "Retire…"}
        </button>
      </form>
    </section>
  );
}
