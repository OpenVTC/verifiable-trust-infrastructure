### vta-sdk 0.20.32 / vta-cli-common 0.10.22 — the webvh DID mutations reach TSP (#885)

`VtaClient::rpc`'s TSP arm is an `UnsupportedTransport` error, so a client method
still on the legacy DIDComm protocol message does not merely risk wire drift — it
**does not exist over TSP**. #884 moved the ACL slice; this moves the two webvh
DID mutations, which were the largest remaining pair.

`update_did_webvh_by_did` and `rotate_did_webvh_keys_by_did` send canonical
`webvh/dids/{update,rotate-keys}/1.0` on every transport, REST included (through
the trust-task endpoint, leaving the dedicated routes mounted for other
consumers). The maintainer has served both tasks all along — only the client
never used them.

**Why they were stranded:** the canonical tasks key on the **DID**, while the
methods took `(context_id, scid)`. That is not a transport swap, so #861 left
them behind. Callers already hold the DID — `pnm did-mgmt dids update` was
fetching the DID record purely to translate it into the pair the method wanted,
and now keeps that call only for the clean 404 it also provides.

Both bodies flatten *beside* `did` rather than nesting under it, because the
maintainer reads them back with `serde(flatten)`. A nested body would
deserialize into an update that changes nothing — published, version-bumped and
silently empty — so `flatten_with_did` refuses a body that is not a JSON object
or that already carries a `did`.

The `(context_id, scid)` methods are **deprecated, not removed**: they still work
over REST and DIDComm, and deleting them would be a breaking change to a
published crate for no gain. They have no TSP path and will not get one.

## Still not on TSP, and why

| method | blocker |
|---|---|
| `import_key`, `list_webvh_server_domains` | No published spec. The dispatcher's own guard (`every_served_uri_has_a_published_spec_or_is_tracked_debt`) refuses a newly-served URI the registry cannot resolve, and says so: author it upstream in `trustoverip/dtgwg-trust-tasks-tf` and bump `trust-tasks-rs` — growing the allowlist is the wrong fix. So these need an upstream spec PR first, not a binding here. |
| `backup_export`, `backup_import` | Tasks already bound (`backup/{initiate,complete}-export`, `backup/{initiate,finalize}-import`) — but the **bytes** ride an HTTPS blob URL carried in the descriptor, deliberately, so a multi-megabyte envelope never enters a message envelope. A TSP-only client still needs an HTTP leg until the descriptor's already-declared `chunked-trust-task` algorithm exists. That is a design change, not a rewiring. |

**Testing.** `tests/e2e/tests/client_didcomm.rs` pins both new calls as Trust
Tasks — including that the body's members arrive un-nested, the assertion that
would fail if `flatten` were dropped. `vta-sdk/tests/client_rest.rs` pins the
REST leg on `/api/trust-tasks`; the two legacy-route tests remain, under
`#[allow(deprecated)]`, so the deprecated path stays covered until it is removed.
