// Authorize another key — an assistant's (`vtc-mcp`), say — to sign as you.
//
// The same authorization `cnm access authorize-key` writes, signed as your
// identity through the wallet, for an administrator whose identity lives in
// their VTA rather than in `cnm`. Nothing is sent from here: the document is
// handed to the key's holder, which sends it inside its own
// `auth/signing-key/enroll/0.2`. Once enrolled, the key appears in the list
// above and is revoked there like a browser's.
//
// A delegated key never answers a step-up or approves an action (those stay
// with your own factor), and authorizes nothing beyond your own entry, read at
// every document.

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";

import { CopyButton } from "@/components/CopyButton";
import { Field } from "@/components/Field";
import { formatIso as formatDate } from "@/lib/format";
import {
  authorizeAnotherKey,
  MAX_DELEGATION_DAYS,
  type KeyAuthorization,
} from "@/lib/console-keys-api";
import { isWalletSigningAvailable } from "@/lib/wallet";

export function AuthorizeAnotherKey() {
  const [did, setDid] = useState("");
  const [label, setLabel] = useState("vtc-mcp");
  const [days, setDays] = useState(MAX_DELEGATION_DAYS);
  const sign = useMutation<KeyAuthorization, Error>({
    mutationFn: () => authorizeAnotherKey({ signingKeyDid: did, label, days }),
  });
  const walletReady = isWalletSigningAvailable();
  const text = sign.data ? JSON.stringify(sign.data.document, null, 2) : "";

  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "authorization.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="card" aria-labelledby="authorize-key-heading">
      <h3 id="authorize-key-heading">Authorize another key</h3>
      <p className="muted">
        Let a key you hold elsewhere — your assistant&apos;s (<code>vtc-mcp</code>), say — sign
        documents as you, the way this browser does. Your wallet signs the authorization as your
        identity; you give it to the key&apos;s holder, which enrols itself with it. It carries no
        authority of its own, never answers a step-up or approves an action, and appears in the list
        above once used, where you can revoke it.
      </p>
      <p className="muted">
        Use a key you use at no other community: two communities holding the same key can tell that
        the same person stands behind both.
      </p>
      {!walletReady ? (
        <div className="finding warn" role="status">
          <strong>Your wallet signs this</strong>
          <span>
            Sign in to this console with the VTA wallet plugin, as the identity this community knows
            you as. An identity held by <code>cnm</code> uses{" "}
            <code>cnm access authorize-key</code> instead.
          </span>
        </div>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            sign.mutate();
          }}
        >
          <Field label="The key's did:key" hint="vtc_enrol_signing_key answers with the bridge's own.">
            <input
              value={did}
              onChange={(e) => {
                setDid(e.target.value);
                sign.reset();
              }}
              placeholder="did:key:z6Mk…"
              spellCheck={false}
              required
            />
          </Field>
          <Field label="Label">
            <input value={label} maxLength={64} onChange={(e) => setLabel(e.target.value)} />
          </Field>
          <Field label={`Lasts (days, at most ${MAX_DELEGATION_DAYS})`}>
            <input
              type="number"
              min={1}
              max={MAX_DELEGATION_DAYS}
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
            />
          </Field>
          <button type="submit" disabled={sign.isPending || did.trim().length === 0}>
            {sign.isPending ? "Waiting for your wallet…" : "Sign with my wallet"}
          </button>
        </form>
      )}
      {sign.error && (
        <p className="error" role="alert">
          {sign.error.message}
        </p>
      )}
      {sign.data && (
        <div className="finding ok" role="status">
          <strong>Authorization signed</strong>
          <span>
            Give it to the key&apos;s holder before{" "}
            {formatDate(sign.data.usableUntil.toISOString())}. It can be used once, and only by that
            key. For <code>vtc-mcp</code>, pass it to{" "}
            <code>vtc_enrol_signing_key</code> as <code>authorization</code>, or save it and pass
            the file as <code>authorization_file</code>.
          </span>
          <textarea readOnly rows={8} value={text} aria-label="Signed authorization" />
          <span>
            <CopyButton value={text} label="Copy authorization" />{" "}
            <button type="button" className="secondary" onClick={download}>
              Download authorization.json
            </button>
          </span>
        </div>
      )}
    </section>
  );
}
