// A DID in a table cell: abbreviated where it carries least (the opaque SCID
// and the hosting domain's subdomains — see `shortenDid`), the full
// identifier on hover, and copy and QR buttons beside it.

import { Link } from "react-router-dom";

import { CopyButton } from "@/components/CopyButton";
import { DidQrButton } from "@/components/DidQrButton";
import { shortenDid } from "@/lib/format";

export function DidText({
  did,
  to,
  actions = true,
}: {
  did: string;
  /** Where the DID links to, if anywhere. */
  to?: string;
  /** Show the copy and QR buttons. */
  actions?: boolean;
}) {
  const text = (
    <code className="did-text-id" title={did}>
      {shortenDid(did)}
    </code>
  );
  return (
    <span className="did-text">
      {to ? <Link to={to}>{text}</Link> : text}
      {actions && (
        <span className="did-text-actions">
          <CopyButton value={did} label="Copy DID" successMessage="DID copied" />
          <DidQrButton did={did} />
        </span>
      )}
    </span>
  );
}
