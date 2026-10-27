# CLAUDE.md — vti-voting-service

Crate guidance. The workspace `CLAUDE.md` applies too.

## What this crate is

(The crate's full entry from the workspace `CLAUDE.md` crate map.)

**The voting service** (`publish = false`): a host service holding ballot boxes for any number of communities, never a roster. Its identity is a `did:webvh` its operator's VTA mints from the `ballot-box` template (`vti-voting-service setup`, two-phase like the witness; keys in `[secrets]`). Communities and auditors reach it over **TSP, then DIDComm** through its own mediator session (`vti_common::host_session`; the transport-proven sender must be the document's issuer). **HTTPS** (`POST /trust-tasks`, advertised `TrustTaskHTTPS`) stays only as the sessionless cast door VTI-VOT-004 requires: a one-time key has no mediator session to take a receipt on, and opening one would hand the mediator the voter's address and timing. One dispatcher (`dispatch::answer`) behind both; every answer signed as its DID (receipts and heads are evidence); a file journal (`sync_data` before answering). Without `[identity]` it runs as a test `did:key` over HTTPS only
