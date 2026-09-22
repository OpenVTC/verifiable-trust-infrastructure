// Invitations plugin — issue an Invitation Credential (VIC) to a prospective
// member, then hand it off out-of-band (copy / download / QR).
//
// The operator enters an invitee DID (and optional validity); the VTC mints a
// short-lived, revocable VIC bound to that DID. The invitee presents it back in
// a join request and is auto-admitted by the default `join.rego` (a verified,
// trusted, unconsumed invitation → allow). See `routes/invitations.rs`.

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, QrCode, Send, Ticket, Trash2 } from "lucide-react";

import {
  deliverInvitation,
  issueInvitation,
  listInvitations,
  revokeInvitation,
  type DeliverChannel,
  type DeliverInvitationResponse,
  type InvitationListItem,
  type IssueInvitationResponse,
} from "@/lib/api";
import { offerDeepLink } from "@/lib/invitation-offer";
import { CopyButton } from "@/components/CopyButton";
import { useToast } from "@/lib/toast";
import { useNameBook } from "@/lib/names";
import { NamedDid } from "@/components/NamedDid";

/// QR capacity ceiling: a version-40 QR at error-correction level L holds
/// ~2,953 bytes. A signed VIC is typically ~1.5–2.5 KB, so it usually fits; we
/// still offer copy + download, and fall back to those for the rare VIC that
/// exceeds the QR limit.
const QR_MAX_CHARS = 2900;

export function Invitations() {
  const nameBook = useNameBook();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [did, setDid] = useState("");
  const [validityDays, setValidityDays] = useState("");
  const [role, setRole] = useState("member");

  const invitations = useQuery({
    queryKey: ["invitations"],
    queryFn: async () => (await listInvitations()).invitations,
  });

  const revoke = useMutation<unknown, Error, string>({
    mutationFn: (id: string) => revokeInvitation(id),
    onSuccess: () => {
      toast.push("success", "Invitation revoked");
      void queryClient.invalidateQueries({ queryKey: ["invitations"] });
    },
    onError: (e) => toast.pushFromError(e),
  });

  // Delivery: push an offer to the invitee, or show one as a QR code. The offer
  // redeems only for the invited DID's key, so showing it discloses nothing
  // that admits anyone else (vtc/invitations/deliver, Keyring VTI-21 / VTI-32).
  const [offerShown, setOfferShown] = useState<{
    subjectDid: string;
    link: string;
    expiresAt: string;
  } | null>(null);
  const deliver = useMutation<
    DeliverInvitationResponse,
    Error,
    { id: string; subjectDid: string; channel: DeliverChannel }
  >({
    mutationFn: ({ id, channel }) => deliverInvitation(id, channel),
    onSuccess: (resp, { subjectDid }) => {
      if (resp.channel === "offer" && resp.offer) {
        setOfferShown({ subjectDid, link: offerDeepLink(resp.offer), expiresAt: resp.expiresAt });
        toast.push("success", "Offer ready — any earlier offer for this invitation no longer works");
      } else {
        toast.push("success", "Invitation sent to the invitee");
      }
    },
    onError: (e) => toast.pushFromError(e),
  });

  const mutation = useMutation<IssueInvitationResponse, Error, void>({
    mutationFn: () => {
      const days = validityDays.trim() === "" ? undefined : Number(validityDays);
      if (days !== undefined && (!Number.isInteger(days) || days < 1)) {
        return Promise.reject(new Error("Validity must be a whole number of days ≥ 1"));
      }
      // "member" is the server default — send a role only when it differs.
      return issueInvitation(did.trim(), days, role === "member" ? undefined : role);
    },
    onSuccess: () => {
      toast.push("success", "Invitation issued");
      void queryClient.invalidateQueries({ queryKey: ["invitations"] });
    },
    onError: (e) => toast.pushFromError(e),
  });

  const result = mutation.data;
  const vicJson = result ? JSON.stringify(result.vic, null, 2) : "";

  return (
    <div className="page">
      <header className="page-header">
        <h2>
          <Ticket size={20} strokeWidth={1.75} /> Invitations
        </h2>
        <p className="muted">
          Issue a Verifiable Invitation Credential (VIC) for a prospective
          member. The holder presents it when joining and is auto-admitted — no
          manual approval needed.
        </p>
      </header>

      <section className="card">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (did.trim()) mutation.mutate();
          }}
        >
          <label className="field">
            <span className="field-label">Invitee DID</span>
            <input
              type="text"
              value={did}
              onChange={(e) => setDid(e.target.value)}
              placeholder="did:key:… or did:webvh:…"
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <label className="field">
            <span className="field-label">Validity (days, optional)</span>
            <input
              type="number"
              min={1}
              max={90}
              value={validityDays}
              onChange={(e) => setValidityDays(e.target.value)}
              placeholder="7"
            />
          </label>
          <label className="field">
            <span className="field-label">Role on join</span>
            <select value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="member">member</option>
              <option value="moderator">moderator</option>
              <option value="issuer">issuer</option>
            </select>
          </label>
          <button
            type="submit"
            className="btn primary"
            disabled={!did.trim() || mutation.isPending}
          >
            {mutation.isPending ? "Issuing…" : "Issue invitation"}
          </button>
        </form>
      </section>

      {result && (
        <section className="card">
          <h3>Invitation for {nameBook.nameOrDid(result.subjectDid)}</h3>
          {result.validUntil && (
            <p className="muted">
              Valid until <code>{result.validUntil}</code>
            </p>
          )}
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
            <CopyButton
              value={vicJson}
              label="Copy invitation JSON"
              successMessage="Invitation copied"
            />
            <DownloadButton filename={`vic-${shortId(result.subjectDid)}.json`} text={vicJson} />
          </div>
          <VicQr text={vicJson} />
          <textarea
            readOnly
            value={vicJson}
            rows={14}
            spellCheck={false}
            style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
          />
        </section>
      )}

      {offerShown && (
        <section className="card">
          <h3>Offer for {nameBook.nameOrDid(offerShown.subjectDid)}</h3>
          <p className="muted">
            Scan with the invitee&rsquo;s wallet. It redeems only with a key of the
            invited DID, so a photographed code admits no one else. Expires{" "}
            <code>{offerShown.expiresAt}</code>.
          </p>
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
            <CopyButton value={offerShown.link} label="Copy offer link" successMessage="Offer link copied" />
          </div>
          <VicQr text={offerShown.link} />
        </section>
      )}

      <section className="card">
        <h3>Issued invitations</h3>
        {invitations.isPending && <p className="muted">Loading…</p>}
        {invitations.isError && (
          <p className="muted">Could not load invitations.</p>
        )}
        {invitations.data && invitations.data.length === 0 && (
          <p className="muted">No invitations issued yet.</p>
        )}
        {invitations.data && invitations.data.length > 0 && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Invitee</th>
                <th>Role</th>
                <th>Issued</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {invitations.data.map((inv: InvitationListItem) => (
                <tr key={inv.id}>
                  <td>
                    <NamedDid book={nameBook} did={inv.subjectDid} />
                  </td>
                  <td>{inv.role ?? "member"}</td>
                  <td>{inv.issuedAt.slice(0, 10)}</td>
                  <td>
                    {inv.revokedAt ? (
                      <span className="muted">revoked</span>
                    ) : (
                      "live"
                    )}
                  </td>
                  <td>
                    {!inv.revokedAt && (
                      <>
                        <button
                          type="button"
                          className="btn"
                          disabled={deliver.isPending}
                          onClick={() =>
                            deliver.mutate({ id: inv.id, subjectDid: inv.subjectDid, channel: "message" })
                          }
                          title="Send an offer to the invitee's DID"
                        >
                          <Send size={16} strokeWidth={1.75} /> Send
                        </button>
                        <button
                          type="button"
                          className="btn"
                          disabled={deliver.isPending}
                          onClick={() =>
                            deliver.mutate({ id: inv.id, subjectDid: inv.subjectDid, channel: "offer" })
                          }
                          title="Show an offer as a QR code for the invitee to scan"
                        >
                          <QrCode size={16} strokeWidth={1.75} /> QR offer
                        </button>
                      </>
                    )}
                    {!inv.revokedAt && (
                      <button
                        type="button"
                        className="btn"
                        disabled={revoke.isPending}
                        onClick={() => revoke.mutate(inv.id)}
                        title="Revoke this invitation"
                      >
                        <Trash2 size={16} strokeWidth={1.75} /> Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

function DownloadButton({ filename, text }: { filename: string; text: string }) {
  const onClick = () => {
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <button type="button" className="btn" onClick={onClick}>
      <Download size={16} strokeWidth={1.75} /> Download .json
    </button>
  );
}

/// Renders a QR of the VIC when it's small enough to scan; otherwise explains
/// that copy/download is the hand-off path. The `qrcode` module is loaded
/// lazily so it doesn't weigh on the shell bundle.
function VicQr({ text }: { text: string }) {
  const [dataUrl, setDataUrl] = useState<string | null>(null);
  const tooBig = text.length > QR_MAX_CHARS;

  useEffect(() => {
    let cancelled = false;
    if (tooBig) {
      setDataUrl(null);
      return;
    }
    import("qrcode")
      // Level L (lowest EC) maximises payload capacity so a full VIC fits; the
      // larger render size keeps the denser code scannable.
      .then((qr) =>
        qr.toDataURL(text, {
          margin: 1,
          width: 360,
          errorCorrectionLevel: "L",
        }),
      )
      .then((url) => {
        if (!cancelled) setDataUrl(url);
      })
      .catch(() => {
        // Exceeds even a version-40 QR — fall back to copy / download.
        if (!cancelled) setDataUrl(null);
      });
    return () => {
      cancelled = true;
    };
  }, [text, tooBig]);

  if (tooBig) {
    return (
      <p className="muted">
        This invitation is too large for a scannable QR code. Use{" "}
        <strong>QR offer</strong> on it in the list below — a small offer the
        invitee&rsquo;s wallet redeems — or <strong>Copy</strong> /{" "}
        <strong>Download</strong> to hand it off.
      </p>
    );
  }
  if (!dataUrl) return null;
  return (
    <div style={{ marginBottom: 8 }}>
      <img src={dataUrl} alt="Invitation QR code" width={240} height={240} />
    </div>
  );
}

function shortId(did: string): string {
  return did.replace(/[^a-zA-Z0-9]/g, "").slice(-8) || "invite";
}
