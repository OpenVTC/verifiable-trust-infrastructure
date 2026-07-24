// Render a DID as its name, with the identifier still visible.
//
// One component so every table, dialog and detail pane in the console agrees
// on what a principal looks like. Drop-in for the `<code className="truncate"
// title={did}>{did}</code>` pattern the plugins used before.
//
// Two rules it enforces, both from `vta_sdk::display_name`:
//
//   * **The DID is never hidden.** A name the operator cannot cross-check
//     against an identifier is a name they cannot audit — and these screens
//     are where ACL grants get approved and members admitted. The name leads,
//     the abbreviated DID follows, the full DID is in the tooltip.
//
//   * **An unverified name is marked.** `alsoKnownAs` is self-asserted, so a
//     name that has not round-tripped carries its `[unverified]` suffix and a
//     warning style. Seeing that a DID *claims* to be `mybank.com/@treasury`
//     is useful; being told it *is* would be a lie.

import { shortenDid } from "@/lib/format";
import { isTrusted, type NameBook } from "@/lib/names";

interface NamedDidProps {
  book: NameBook;
  did: string;
  /** Omit the abbreviated DID and show the name alone. Only for places that
   *  render the DID separately in the same row — never to save space. */
  nameOnly?: boolean;
  className?: string;
}

export function NamedDid({ book, did, nameOnly, className }: NamedDidProps) {
  const entry = book.get(did);
  const name = book.nameOf(did);

  if (!name) {
    return (
      <code className={`truncate ${className ?? ""}`} title={did}>
        {shortenDid(did)}
      </code>
    );
  }

  const untrusted = entry && !isTrusted(entry.source);

  return (
    <span className={`named-did ${className ?? ""}`} title={did}>
      <span className={untrusted ? "named-did-name unverified" : "named-did-name"}>
        {name}
      </span>
      {!nameOnly && <code className="named-did-id">{shortenDid(did)}</code>}
    </span>
  );
}
