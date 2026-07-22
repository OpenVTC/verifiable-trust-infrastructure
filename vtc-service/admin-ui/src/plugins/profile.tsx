// Community profile plugin — GET + PUT /v1/community/profile.
//
// Read-only fields (community_did, created_at) render as plain
// text. Editable fields (name, description, language, contact
// email, public url, logo url) are inputs in a single form. The
// form tracks "dirty" state and only PUTs fields that changed.

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { Field } from "@/components/Field";
import { getJson, putJson } from "@/lib/api";

const TRUST_TASK =
  "https://trusttasks.org/spec/vtc/community/profile/show/0.1";
// PUT carries the update task — GET and PUT are separate Trust Tasks.
const TRUST_TASK_UPDATE =
  "https://trusttasks.org/spec/vtc/community/profile/update/0.1";

// GET /v1/community/profile wire shape: the persisted profile fields
// are flattened at the top level (server uses `#[serde(flatten)]`),
// alongside the live `registryStatus`. Do not look for a nested
// `profile` object — there isn't one.
interface ProfileResponse {
  communityDid: string;
  name: string;
  description: string;
  logoUrl: string | null;
  publicUrl: string | null;
  contactEmail: string | null;
  language: string;
  createdAt: string;
  extensions: unknown;
  registryStatus: string;
}

interface ProfileUpdateRequest {
  name?: string;
  description?: string;
  logoUrl?: string | null;
  publicUrl?: string | null;
  contactEmail?: string | null;
  language?: string;
}

async function getProfile(): Promise<ProfileResponse> {
  return getJson<ProfileResponse>("/v1/community/profile", {
    trustTask: TRUST_TASK,
  });
}

async function putProfile(body: ProfileUpdateRequest): Promise<unknown> {
  // PUT returns `{ profile, fieldsChanged }` (nested). We don't read
  // it — `onSuccess` invalidates the query, which refetches via
  // `getProfile` and seeds the form from the flat GET shape.
  return putJson<unknown>("/v1/community/profile", body, {
    trustTask: TRUST_TASK_UPDATE,
  });
}

export function Profile() {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["profile"],
    queryFn: getProfile,
  });

  // Form state is a separate copy of the profile so editing
  // doesn't mutate the cached query result.
  const [draft, setDraft] = useState<EditableFields | null>(null);

  // When the query result first loads (or changes from outside),
  // seed the draft. We don't overwrite an in-flight edit.
  useEffect(() => {
    if (!query.data) return;
    if (draft !== null) return;
    setDraft({
      name: query.data.name,
      description: query.data.description,
      logoUrl: query.data.logoUrl ?? "",
      publicUrl: query.data.publicUrl ?? "",
      contactEmail: query.data.contactEmail ?? "",
      language: query.data.language,
    });
  }, [query.data, draft]);

  const mutation = useMutation({
    mutationFn: putProfile,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["profile"] });
      setDraft(null);
    },
  });

  if (query.isPending) {
    return (
      <section className="page">
        <h2>Community profile</h2>
        <p>Loading…</p>
      </section>
    );
  }

  if (query.error) {
    return (
      <section className="page">
        <h2>Community profile</h2>
        <section className="card error">
          <h3>Failed to load profile</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      </section>
    );
  }

  if (!query.data || !draft) {
    return null;
  }

  const original = query.data;
  const dirty = isDirty(original, draft);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!dirty) return;
    mutation.mutate(buildPatch(original, draft));
  };

  const onCancel = () => {
    setDraft(null);
    mutation.reset();
  };

  return (
    <section className="page">
      <h2>Community profile</h2>

      <form onSubmit={onSubmit} className="form-stack">
        <section className="card">
          <h3>Identity</h3>
          <dl>
            <dt>Community DID</dt>
            <dd>
              <code>{original.communityDid}</code>
            </dd>
            <dt>Created</dt>
            <dd>
              <code>{original.createdAt}</code>
            </dd>
          </dl>
        </section>

        <section className="card">
          <h3>Editable</h3>
          <Field label="Name">
            <input
              type="text"
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              required
            />
          </Field>
          <Field label="Description">
            <textarea
              value={draft.description}
              onChange={(e) =>
                setDraft({ ...draft, description: e.target.value })
              }
              rows={3}
            />
          </Field>
          <Field label="Public URL">
            <input
              type="url"
              placeholder="https://community.example.com"
              value={draft.publicUrl}
              onChange={(e) =>
                setDraft({ ...draft, publicUrl: e.target.value })
              }
            />
          </Field>
          <Field label="Logo URL">
            <input
              type="url"
              placeholder="https://community.example.com/logo.svg"
              value={draft.logoUrl}
              onChange={(e) => setDraft({ ...draft, logoUrl: e.target.value })}
            />
          </Field>
          <Field label="Contact email">
            <input
              type="email"
              placeholder="ops@community.example.com"
              value={draft.contactEmail}
              onChange={(e) =>
                setDraft({ ...draft, contactEmail: e.target.value })
              }
            />
          </Field>
          <Field label="Language (BCP 47)">
            <input
              type="text"
              placeholder="en"
              value={draft.language}
              onChange={(e) =>
                setDraft({ ...draft, language: e.target.value })
              }
              required
            />
          </Field>
        </section>

        {mutation.error && (
          <section className="card error">
            <h3>Save failed</h3>
            <p>{(mutation.error as Error).message}</p>
          </section>
        )}

        <div className="form-actions">
          <button
            type="submit"
            className="primary"
            disabled={!dirty || mutation.isPending}
          >
            {mutation.isPending ? "Saving…" : "Save changes"}
          </button>
          <button
            type="button"
            className="secondary"
            onClick={onCancel}
            disabled={!dirty || mutation.isPending}
          >
            Discard changes
          </button>
        </div>
      </form>
    </section>
  );
}

interface EditableFields {
  name: string;
  description: string;
  logoUrl: string;
  publicUrl: string;
  contactEmail: string;
  language: string;
}

function isDirty(
  original: ProfileResponse,
  draft: EditableFields,
): boolean {
  if (original.name !== draft.name) return true;
  if (original.description !== draft.description) return true;
  if ((original.logoUrl ?? "") !== draft.logoUrl) return true;
  if ((original.publicUrl ?? "") !== draft.publicUrl) return true;
  if ((original.contactEmail ?? "") !== draft.contactEmail) return true;
  if (original.language !== draft.language) return true;
  return false;
}

function buildPatch(
  original: ProfileResponse,
  draft: EditableFields,
): ProfileUpdateRequest {
  const patch: ProfileUpdateRequest = {};
  if (original.name !== draft.name) patch.name = draft.name;
  if (original.description !== draft.description) {
    patch.description = draft.description;
  }
  // Empty string in the form means "clear the field" → send null.
  const norm = (s: string) => (s.trim() === "" ? null : s);
  if ((original.logoUrl ?? "") !== draft.logoUrl) {
    patch.logoUrl = norm(draft.logoUrl);
  }
  if ((original.publicUrl ?? "") !== draft.publicUrl) {
    patch.publicUrl = norm(draft.publicUrl);
  }
  if ((original.contactEmail ?? "") !== draft.contactEmail) {
    patch.contactEmail = norm(draft.contactEmail);
  }
  if (original.language !== draft.language) {
    patch.language = draft.language;
  }
  return patch;
}

