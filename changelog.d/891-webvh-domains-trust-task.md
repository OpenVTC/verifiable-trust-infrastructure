### vta-sdk 0.21.2 / vta-service 0.14.3 / vta-webvh 0.1.4 — the domain relay reaches TSP, and stops dropping `createdAt` (#891)

`list_webvh_server_domains` was the last webvh read with no published Trust Task,
and `VtaClient::rpc`'s TSP arm is an `UnsupportedTransport` error — so it did not
exist over TSP at all. The spec was authored upstream
(`trustoverip/dtgwg-trust-tasks-tf` #171, published in `trust-tasks-rs` 0.2.55);
this binds it.

The response items reference the **existing** canonical
`did-management/_shared/0.1/domain-entry#DomainEntry` rather than a parallel
shape. This is one object crossing two hops — operator → VTA → hosting server —
and an operator comparing the VTA's answer against the server's should not have
to reconcile two spellings of the same domain.

## The VTA was discarding `createdAt`

Not in the mapping — at its own HTTP boundary. `MyDomainEntry` had no field for
it, so the host's value was dropped before any VTA code saw it. Canonical
`DomainEntry` **requires** `createdAt`, so the relayed response was not merely
thinner than the host's: it could not satisfy the schema it relays into.

The host does send it (`did-hosting-common`'s `DomainEntry.created_at` is a
required `u64`), so this is recovered information, not invented: parsed, then
converted from Unix seconds to RFC 3339. An unrepresentable timestamp becomes
*absent* rather than epoch-zero, which would read as "created in 1970".

## The relay does not re-filter

The hosting server holds the ACL and has already scoped its answer to this
caller. A second filter in the VTA could only ever *narrow* it, reporting fewer
domains than the operator may actually use — and the operator would conclude a
domain is unavailable when the server would accept it. Under-reporting is the
dangerous direction here, because it silently removes valid choices instead of
raising an error, so the handler is deliberately transparent and the spec makes
that a **MUST**.

## Also in this PR

**Removes `ci-test.log`** (492 KB), a GitHub Actions runner log committed by
accident in #888 — a `curl -o` in the repo root met a `git add -A`. Nothing
references it. `.gitignore` had no `*.log` coverage at all, which it now does.

**Testing.** The call had no test on any transport before this. Now:
`vta-sdk/tests/client_rest.rs` covers the REST leg including `createdAt`
preservation and the empty-list answer (a server the VTA can reach but holds no
grant on — a true answer, not an error); `tests/e2e/tests/client_didcomm.rs`
pins the Trust Task; a conformance witness round-trips the payload through its
generated types, with `createdAt` populated so a witness cannot pass while the
real relay emits a non-conformant entry.

First-party legacy sends are now down to three, all deliberate or blocked:
`import_key`'s cleartext-multibase fork (which belongs on authcrypt), and
`backup_export`/`backup_import`, whose bulk bytes need the descriptor's
already-declared `chunked-trust-task` algorithm before they can leave HTTP.
