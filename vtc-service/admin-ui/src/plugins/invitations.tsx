// Invitations plugin — issue an Invitation Credential (VIC) to a prospective
// member, then hand it off out-of-band (copy / download / QR).
//
// The operator enters an invitee DID (and optional validity); the VTC mints a
// short-lived, revocable VIC bound to that DID. The invitee presents it back in
// a join request and is auto-admitted by the default `join.rego` (a verified,
// trusted, unconsumed invitation → allow). See `routes/invitations.rs`.

import { useEffect, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Download, Ticket } from "lucide-react";

import { issueInvitation, type IssueInvitationResponse } from "@/lib/api";
import { CopyButton } from "@/components/CopyButton";
import { useToast } from "@/lib/toast";

/// Above this size a QR code becomes unscannable in practice; a full signed VC
/// usually exceeds it, so we render the QR only when it fits and always offer
/// copy + download.
const QR_MAX_CHARS = 1200;

export function Invitations() {
  const toast = useToast();
  const [did, setDid] = useState("");
  const [validityDays, setValidityDays] = useState("");

  const mutation = useMutation<IssueInvitationResponse, Error, void>({
    mutationFn: () => {
      const days = validityDays.trim() === "" ? undefined : Number(validityDays);
      if (days !== undefined && (!Number.isInteger(days) || days < 1)) {
        return Promise.reject(new Error("Validity must be a whole number of days ≥ 1"));
      }
      return issueInvitation(did.trim(), days);
    },
    onSuccess: () => toast.push("success", "Invitation issued"),
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
          <h3>Invitation for {result.subjectDid}</h3>
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
      .then((qr) => qr.toDataURL(text, { margin: 1, width: 240 }))
      .then((url) => {
        if (!cancelled) setDataUrl(url);
      })
      .catch(() => {
        if (!cancelled) setDataUrl(null);
      });
    return () => {
      cancelled = true;
    };
  }, [text, tooBig]);

  if (tooBig) {
    return (
      <p className="muted">
        This invitation is too large for a scannable QR code — use{" "}
        <strong>Copy</strong> or <strong>Download</strong> to hand it off.
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
