# The voting service (`vti-voting-service`)

`vti-voting-service` runs **ballot boxes**: the party in a community election that admits
casts, keeps the board, decrypts with the trustees and publishes the result (VTI-VOT-001 – 100).
The community — a VTC — is the registrar: it decides who may vote and issues each voter a
ticket, blind. The two never share what they know. The community knows who took a ticket and
never sees a ballot; the ballot box sees every ballot and never learns whose it is.

It is a **host service**, never a role of the VTC or the VTA, for the same reasons a witness is
([the witness host service](../06-witness/README.md)):

- separation is the point, and the separation is only as good as the two operators'
  independence;
- a ballot box is public by design, so its identity is never a node's own (VTI-KEY-007);
- casts arrive anonymously, and their traffic and abuse handling belong away from a
  community's authenticated door.

One service holds ballot boxes for any number of communities. It never holds a roster.

> **Status.** Every secrecy level is served: `open`, `sealed` and `tallied-encrypted`. It runs
> end to end against a VTC over a mediator in the test suite. It has not yet run on deployed
> infrastructure. The ballot cryptography is unaudited protocol code over audited group
> operations: fine for polls and surveys; have it reviewed before a binding election.

## What it is

- **One binary, one identity.** The identity is a `did:webvh` the operator's VTA mints from the
  built-in [`ballot-box` DID template](../02-vta/did-templates.md). The VTA is the key
  custodian, and the service never acts as it.
- **TSP, then DIDComm**, through the identity's own mediator session (one websocket, both
  protocols). This is how a community registers, closes and cancels its elections, and how
  communities, auditors and trustees read boards (VTI-VOT-005).
- **HTTPS** (`POST <https_url>/trust-tasks`, advertised as `TrustTaskHTTPS`). This is the door
  a cast is always accepted on (VTI-VOT-004). A voter casts from a key made for that one cast,
  which has no mediator session to take a receipt on, and opening one would hand the mediator
  the voter's address and timing. Trustees also send their signed steps here.
- **Every answer is signed** as the service's DID. A receipt and a board head are evidence.
- **A file journal.** Every accepted step is written and `sync_data`'d before the answer. On
  restart the board is replayed through the same rules.

## Setup

Setup is two-phase, as for the witness and the VTC.

**1. Mint a setup key**, and print the grant to run at the operator's VTA:

```sh
vti-voting-service setup --setup-key-out /secrets/voting-setup-key.json   # --context voting
```

**2. Grant it** from a `pnm` connected to the operator's VTA (step 1 prints the command):

```sh
pnm contexts create --id voting --name "Voting service" \
  --admin-did did:key:z6Mk… --admin-expires 1h --admin-handoff
```

**3. Provision** the identity from a setup file:

```toml
# voting-setup.toml
config_path    = "/etc/vti-voting/config.toml"
vta_did        = "did:webvh:Qm…:vta.operator.example"
context        = "voting"                              # default
setup_key_file = "/secrets/voting-setup-key.json"
mediator_did   = "did:webvh:Qm…:mediator.example"      # where communities reach it
https_url      = "https://ballots.example.net"         # the cast door, advertised in the DID
webvh_server   = "prod"            # a DID-hosting server registered at the VTA…
# url          = "https://ballots.example.net/did"     # …or serve the DID log yourself
# data_dir     = "/var/lib/vti-voting"                 # default: data/ beside config_path
# listen       = "127.0.0.1:8740"                      # default
# resolver_url = "ws://resolver:8080/did/v1/ws"        # optional resolver sidecar

[secrets]                            # where the identity's keys are kept
backend = "keyring"
```

```sh
vti-voting-service setup --from voting-setup.toml     # prints ballot_box_did=…
```

Setup asks the VTA to render the `ballot-box` template at that mediator and `https_url`. It
opens the sealed bundle, keeps the keys in the `[secrets]` store (never in `config.toml`), and
writes an owner-only `config.toml`. With `url` instead of `webvh_server` it also writes the DID
log for you to serve where the DID resolves. The setup DID is never handed off. Its grant ends
at `--admin-expires`, and setup prints the `pnm acl delete` that ends it sooner.

## Configuration

`config.toml`, as setup writes it:

```toml
data_dir         = "/var/lib/vti-voting"
listen           = "127.0.0.1:8740"
operator_vta_did = "did:webvh:Qm…:vta.operator.example"
# resolver_url   = "ws://resolver:8080/did/v1/ws"

[secrets]
backend = "keyring"

[identity]
did          = "did:webvh:Qm…:ballots.example.net"
mediator_did = "did:webvh:Qm…:mediator.example"
```

| Key | Meaning |
|---|---|
| `data_dir` | The journal: one directory per election, named by a digest of the community and election (no caller-supplied string becomes a path). Back it up; it **is** the boards. |
| `listen` | Where the HTTPS binding is served. Terminate TLS in front of it, at the host `https_url` names. |
| `operator_vta_did` | The VTA that minted the identity. The service never answers as it. |
| `resolver_url` | Optional DID resolver sidecar. |
| `[secrets]` | The identity's keys, with the same backends as the VTA and VTC. |
| `[identity]` | The provisioned DID and its mediator. Without it the service runs as a test `did:key` over HTTPS only, which no community can reach. |

Every key is checked: an unknown one is a load error, never a silently ignored setting.

## Running

```sh
vti-voting-service run --config /etc/vti-voting/config.toml
```

`run` restores every election from the journal, then:

- **Opens the identity's mediator session.** It waits until the DID resolves over the network,
  connects with capped, jittered backoff, and supervises the session as the witness does.
- **Serves HTTPS on `listen`.**

SIGINT or SIGTERM closes both.

**Put a reverse proxy in front of `listen`.** It terminates TLS for `https_url`, and should
rate-limit and cap request sizes per source. The cast door is anonymous by design, and the
service itself does neither.

## Letting a community use it

The community's operator adds the ballot box to the VTC's `config.toml`, and restarts it.
This is host configuration, never a Trust Task (VTI-VOT-082):

```toml
[[voting.trusted_ballot_boxes]]
did = "did:webvh:Qm…:ballots.example.net"
operator = "Independent Ballots Ltd"
same_operator = false      # true when the community's operator runs this service too
```

The VTC must be built with `--features voting`. `operator` and `same_operator` are shown to
every member before they take a ticket (VTI-VOT-090).

From there, [Community elections](../03-vtc/elections.md) is the community's guide:

- managers create with `cnm elections create` or the console's **Elections** page;
- members vote with `pnm elections vote`;
- trustees take part with `pnm elections trustee step`.

## What it serves

| Task | Over | Who |
|---|---|---|
| `voting/election/register`, `close`, `cancel` | TSP / DIDComm | the community the payload names, by proof (and by transport) |
| `voting/ballot/cast`, `cast-encrypted` | HTTPS | nobody's identity: the cast's PCS attestation, under the community's registered voting key |
| `voting/trustees/enrol`, `deal`, `confirm`, `justify`, `decrypt` | HTTPS (or TSP / DIDComm) | the trustee the manifest names at that index, by proof |
| `voting/trustees/authorize` | TSP / DIDComm | the community, by proof, after close |
| `voting/election/show`, `voting/trustees/status` | any | public board: anyone; private board: the community, its auditors and its trustees |
| `voting/board/*`, `voting/result/show` | any | public board: anyone; private board: the community and its auditors (and a receipt holder, for one entry's inclusion) |

An election a caller may not read is answered `electionUnknown`, exactly as one that does not
exist.

Each trustee step goes on the board as the trustee's signed request, as received
(`trusteeStep`). That lets anyone check who took it, and stops a ballot box dealing in a
trustee's name to hold the election key itself. `voting/trustees/status` returns those steps
(`steps`), and the trustees' VTAs act on them, never on the summary beside them.

After close the community signs which ciphertexts are decrypted (`voting/trustees/authorize`); the
service accepts that only if it computes the same targets, puts it on the board
(`decryptionAuthorized`), and refuses partial decryptions before it.

What the service refuses before reading a request:

- a signed request without a `recipient`;
- a consequential request (register, close, cancel, casts, trustee steps, authorize) without an
  `issuedAt`, or one more than five minutes ahead;
- a cast not signed by a `did:key` — a cast's key is made for it, and must resolve without the
  service fetching anything the sender chose;
- a payload that does not validate against its task's schema.

And when it reads a cast: an encrypted form whose ciphertexts are already on the board under
another tag (a copied ballot).

## A first poll

A public poll is the shortest path to see it work. With the service running and the VTC trusting
it:

1. Write a manifest:
   - `"secrecy": "open"`, `"board": { "visibility": "public", "auditors": [] }`;
   - `"ballotBox"` set to this service's DID;
   - `votingOpens` a couple of minutes ahead, so the registration lands first.
2. Create it, then check it registered:
   ```sh
   cnm elections create poll.json
   cnm elections show <id>        # expect "registered"
   ```
3. Members vote:
   ```sh
   pnm elections vote <id> --answer <question>=<option> \
       --vtc … --vtc-did … --member … --context …
   ```
4. Close and certify:
   ```sh
   cnm elections close <id>
   cnm elections certify <id>
   ```

## What it sees, and what it keeps

**What it sees:** every ballot, or its encryption; the board; and the address and timing a cast
arrived from. It never sees a member DID: casts are signed by one-time keys, and their tags
link nothing across elections.

**What it keeps:** the registration, the board and the receipt tokens, durably. A crash part way
through writing a record loses only that record, whose answer was never sent; a restart finishes
a decryption whose result it had not yet written. A community or
an auditor holding a signed head holds the service to the board it showed them
(`voting/board/consistency`). The community checkpoints heads while voting is open, and
certification proves the final board extends every one.

## Code

`vti-voting-service/src/`:
- `setup.rs`, `config.rs`, `run.rs`;
- `messaging.rs`: the host session, `vti_common::host_session`;
- `http.rs`;
- `dispatch.rs`: one dispatcher behind both;
- `journal.rs`.

Every rule of every task is `vti_voting::service::BallotBox`. The test that runs it against a
VTC over a mediator is in `vtc-service/tests/it/election_tasks.rs`.
