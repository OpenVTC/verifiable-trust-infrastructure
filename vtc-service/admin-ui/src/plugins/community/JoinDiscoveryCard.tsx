// Whether the join manifest answers a caller this community cannot identify —
// GET + PUT /v1/community/join-discovery.
//
// Its own card rather than a field on the profile form, because it is its own
// record: `vtc/community/profile/show/0.1` is a published schema that permits
// no new members, and this is an operational choice about how one endpoint
// behaves rather than part of the community's published description.

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { getJsonExempt, putJsonExempt } from "@/lib/api";

interface JoinDiscovery {
  public: boolean;
}

const PATH = "/v1/community/join-discovery";

// Exempt, like the branding card beside it: this route carries no Trust Task
// of its own — it is admin REST, mounted without a binding.
const getJoinDiscovery = (): Promise<JoinDiscovery> =>
  getJsonExempt<JoinDiscovery>(PATH);

const putJoinDiscovery = (body: JoinDiscovery): Promise<JoinDiscovery> =>
  putJsonExempt<JoinDiscovery>(PATH, body);

export function JoinDiscoveryCard() {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["community", "join-discovery"],
    queryFn: getJoinDiscovery,
  });

  // A draft, so the checkbox does not fight the cached value mid-edit.
  const [draft, setDraft] = useState<boolean | null>(null);
  useEffect(() => {
    if (query.data === undefined) return;
    if (draft !== null) return;
    setDraft(query.data.public);
  }, [query.data, draft]);

  const mutation = useMutation({
    mutationFn: putJoinDiscovery,
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["community", "join-discovery"],
      });
      setDraft(null);
    },
  });

  if (query.isPending) {
    return (
      <section className="card">
        <h3>Joining</h3>
        <p>Loading…</p>
      </section>
    );
  }

  if (query.error) {
    return (
      <section className="card error">
        <h3>Joining</h3>
        <p>{(query.error as Error).message}</p>
      </section>
    );
  }

  if (!query.data || draft === null) return null;

  const dirty = draft !== query.data.public;

  return (
    <section className="card">
      <h3>Joining</h3>
      <label className="field inline">
        <input
          type="checkbox"
          checked={draft}
          onChange={(e) => setDraft(e.target.checked)}
          style={{ width: "auto", height: "auto" }}
        />
        <span className="field-label">
          Answer “what do you require of people who join?” to anyone who asks
        </span>
      </label>
      <p className="field-hint">
        On, someone considering joining can read your admission criteria before
        they disclose anything — including on their first join, when they have
        no messaging channel to ask over. Off, the same question is still
        answered, but only to a caller this community can name: a signed
        request, or one over DIDComm. Turning it off does not hide anything
        from an applicant who is already talking to you, and it does not change
        who is admitted.
      </p>

      {mutation.error && (
        <p className="field-error">{(mutation.error as Error).message}</p>
      )}

      <div className="form-actions">
        <button
          type="button"
          className="primary"
          disabled={!dirty || mutation.isPending}
          onClick={() => mutation.mutate({ public: draft })}
        >
          {mutation.isPending ? "Saving…" : "Save"}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={!dirty || mutation.isPending}
          onClick={() => {
            setDraft(null);
            mutation.reset();
          }}
        >
          Discard
        </button>
      </div>
    </section>
  );
}
