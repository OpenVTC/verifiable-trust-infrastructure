// A DID as a QR code, for handing to a phone: a wallet scanning a member's or
// a peer community's identifier instead of someone retyping 60 characters.
//
// The `qrcode` module loads only when a code is first opened, as the
// invitations page does, so it does not weigh on the shell bundle.

import { useEffect, useRef, useState } from "react";
import { QrCode, X } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";

export function DidQrButton({ did, label = "Show DID as QR code" }: { did: string; label?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        className="copy-icon-btn"
        aria-label={label}
        title={label}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setOpen(true);
        }}
      >
        <QrCode size={14} strokeWidth={1.75} aria-hidden="true" />
      </button>
      {open && <DidQrDialog did={did} onClose={() => setOpen(false)} />}
    </>
  );
}

function DidQrDialog({ did, onClose }: { did: string; onClose: () => void }) {
  const [dataUrl, setDataUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    let cancelled = false;
    import("qrcode")
      .then((qr) => qr.toDataURL(did, { margin: 1, width: 320, errorCorrectionLevel: "M" }))
      .then((url) => {
        if (!cancelled) setDataUrl(url);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [did]);

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      if (opener?.isConnected) opener.focus();
    };
  }, [onClose]);

  return (
    <div
      className="confirm-scrim"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div role="dialog" aria-modal="true" aria-label="DID QR code" className="confirm-dialog did-qr-dialog">
        <div className="did-qr-head">
          <h3>DID</h3>
          <button
            ref={closeRef}
            type="button"
            className="copy-icon-btn"
            aria-label="Close"
            onClick={onClose}
          >
            <X size={14} aria-hidden="true" />
          </button>
        </div>
        {dataUrl ? (
          <img src={dataUrl} alt={`QR code for ${did}`} width={240} height={240} className="did-qr-img" />
        ) : failed ? (
          <p className="muted">This DID is too long for a QR code. Copy it instead.</p>
        ) : (
          <p className="muted">Drawing the code…</p>
        )}
        <div className="did-qr-text">
          <code>{did}</code>
          <CopyButton value={did} label="Copy DID" successMessage="DID copied" />
        </div>
      </div>
    </div>
  );
}
