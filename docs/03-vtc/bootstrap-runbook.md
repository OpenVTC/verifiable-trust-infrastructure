# Bootstrapping a new community: first admin, first vetter

`vtc setup` leaves a community with an identity and no one in it. Two things
have to happen, in a particular order, before it can admit anyone by vetting:

1. **The first admin has to be able to authenticate.** A fresh VTC's access
   list is empty — including for the admin DID setup prints.
2. **The first vetter has to be admitted as a member before the community asks
   for vetting.** An admin cannot be named a vetter, and a community that
   requires vetting from the start can never admit the vetter it needs.

Neither is a bug to work around; both follow from how admission is built. This
runbook gives the order and the reason for each step. It starts where
[`getting-started.md`](getting-started.md) (interactive) or
[`non-interactive-setup.md`](non-interactive-setup.md) (headless) finishes.

## What setup leaves you with

| | After `vtc setup` |
|---|---|
| Community DID, keys, `did.jsonl`, `config.toml` | Written |
| Admin DID | Minted by the VTA and printed (`Admin DID:`, or `admin_did=` headless) |
| One install URL + claim code for that admin DID | Minted, **15-minute** TTL |
| ACL | **Empty** — no entry for anyone, the admin DID included |
| Community profile | Not created until the first admin is bootstrapped |
| Members, vetters, admission criteria | None |

The admin DID is recorded in the install token, not in the ACL. The ACL entry
is written by `POST /v1/admin/bootstrap`, the last step of the install claim.
That is the only place the first admin's entry is written
(`vtc-service/src/routes/admin/bootstrap.rs`).

## Part 1 — the first admin

### Why the admin cannot sign in yet

Authentication checks the ACL. Until an entry exists for the DID:

- `POST /v1/auth/challenge` still answers. It is deliberately not an oracle
  for who is enrolled.
- `POST /v1/auth/` refuses with `403`. The key was never the problem: the DID
  has no entry.

Passkey sign-in to the admin console resolves the role from the same ACL, so it
fails in the same way.

### Path A (recommended): claim the install URL

1. **Start the daemon.** The browser has to reach it.

   ```sh
   vtc --config /srv/vtc/config.toml
   ```

2. **Open the install URL** that setup printed
   (`https://<host>/admin/install?token=…`) and enter the **claim code**. The
   URL and the code travel separately, so a leaked URL alone is not enough.
3. **Register a passkey.** The page then runs, in order:
   `POST /v1/install/claim/start`, `POST /v1/install/claim/finish` (which
   registers the passkey against the admin DID), and `POST /v1/admin/bootstrap`
   (which writes the admin ACL entry, labelled
   `first admin (install bootstrap)`, and creates the community profile).
4. **Sign in** at `https://<host>/admin/` with the passkey. **Access control**
   now lists the admin.

**If the URL expired** before you claimed it, stop the daemon and mint a fresh
URL and claim code for the same DID:

```sh
vtc --config /srv/vtc/config.toml admin invite --did <admin DID>
```

`admin invite` also writes an admin ACL entry for `--did` if there is none, so
a claim through it always leaves a DID that can sign in. `--ttl <seconds>`
changes the default 900. It needs the daemon stopped because it opens the store
directly. Once an admin exists, invite further admins from the running console
(**Access control → Invite**) or with `POST /v1/admin/invites`.

> **Claim before you add any other admin.** `POST /v1/admin/bootstrap` refuses
> with `409` once *any* admin ACL entry exists, and the install page treats
> that `409` as success, because an invited admin sees it too. So if you add an
> admin entry for a different DID first (for example with
> `vtc create-did-key --admin`, below), the claim registers the passkey but
> writes no ACL entry for the setup's admin DID, and passkey sign-in then
> fails. To recover, stop the daemon and run `vtc admin invite --did <admin DID>`
> or `vtc acl add --did <admin DID> --role admin`.

### Path B: no browser — seed the ACL offline

With the daemon **stopped**:

```sh
# Grant the admin DID that setup printed
vtc --config /srv/vtc/config.toml acl add --did <admin DID> --role admin --label "first admin"

# Check it
vtc --config /srv/vtc/config.toml acl list
```

This makes the DID able to authenticate. It does not register a passkey, and
it does not create the community profile. The first `vtc admin invite`, or a
later claim, is what gives that DID a way into the console. Because of the
`409` rule above, the claim itself will not write a second ACL entry.

**You also need the DID's private key.** Setup shows the admin DID's key only
once, in the interactive wizard, behind a confirmation. `vtc setup --from`
never prints it. For scripts and CI, mint a dedicated admin key on the VTC
instead:

```sh
vtc --config /srv/vtc/config.toml create-did-key --admin --label "automation"
```

It writes an admin ACL entry for a fresh `did:key`, prints the DID on stderr,
and prints a credential on **stdout**. The credential is a base64url-encoded
JSON `CredentialBundle`: `did`, `privateKeyMultibase`, `vtaDid` (this is the
community's DID; the field is named for the shared bundle type) and `vtaUrl`
(the VTC's `public_url`). Treat stdout as a secret. Mint this key **after**
the install claim, or it trips the `409` rule above.

### Authenticating a script

- **API base**: `<base_url>/v1`. A community minted after #1615 advertises it
  as the `VTCRest` service in its DID document. One minted before advertises
  the bare base URL, and a client that trusts that entry gets `405`.
- **Every route needs a `Trust-Task` header** naming its task, and answers
  `400` without it. Only `/health` and the browser wallet's `/v1/wallet/auth/*`
  aliases are exempt.
- **Rust**: `vtc_client::VtcClient::connect(base, vtc_did, did,
  private_key_multibase)` runs the challenge-response and returns a client that
  attaches the header for you.
- **On the wire**: `POST /v1/auth/challenge` with header
  `Trust-Task: https://trusttasks.org/spec/auth/challenge/0.1` and body
  `{"did": "<did>"}`. Then `POST /v1/auth/` with header
  `Trust-Task: https://trusttasks.org/spec/auth/authenticate/0.1` and a
  Data-Integrity-signed `auth/authenticate/0.1` document
  (`vta_sdk::auth_di::sign_authenticate_doc`). The response carries the bearer
  token.

### `cnm` needs its own super-admin row

`cnm vetting …`, `cnm audit verify`, `cnm backup …` and `cnm did-log install`
drive this VTC's admin routes ([`vetting.md`](vetting.md) §7). They sign in to
the VTC directly, with the VTC's DID as the audience, as the `cnm` community
profile's **own** DID: the one the community VTA provisioned for it, which
`cnm auth status` shows as `Client DID`. A fresh VTC's ACL has no entry for
that DID, and `backup` and `audit verify` need a **super-admin**: an `admin`
entry with no contexts.

1. **Tell `cnm` which VTC.** The DID is the one `vtc setup` printed for the
   community, not the community VTA's:

   ```sh
   cnm community set-vtc <VTC DID>
   ```

   `cnm` then calls the API base that DID's document advertises as `VTCRest`.
   Use `cnm --vtc-did <VTC DID> …` for a single command, and
   `cnm --url https://<host>/v1 …` to override the API base. `cnm` never reads
   the VTC's DID from the server: it is the audience the sign-in is signed for,
   so the operator names it.
2. **Add the profile's DID as a super-admin.** `set-vtc` prints the command
   with the DID filled in. With the daemon **stopped**:

   ```sh
   vtc --config /srv/vtc/config.toml acl add --did <cnm Client DID> --role admin --label cnm
   ```

   From a running console, use **Access control → Add entry** with role
   `admin` and no contexts. The console asks for your passkey before it
   writes: granting `admin` requires a live step-up (VTI-OPS-051), so the
   operator doing the granting must already have one enrolled. If they do
   not, use the offline command above.

When the VTC refuses the sign-in, `cnm` prints that same `vtc acl add`
command. A VTC gives the same refusal whether or not the DID is enrolled, so
also check that the DID named is the one `cnm auth status` shows now. A
profile provisioned from a temporary `did:key` rotates to a new one the first
time it signs in to the VTA, so run a VTA command (`cnm acl list`) before you
add the row.

Nothing below depends on `cnm`.

### Adding a second admin later

Two paths, and both ask the *granting* operator for their passkey first
(VTI-OPS-051 — conferring administrative authority takes a fresh second
factor, not just a live session):

- **Promote an existing member.** Console → **Members → *the member* → Promote
  to admin**. Over the API this is `acl/change-role/0.1`:
  `PATCH /v1/acl/{did}` with `{"fromRole": "<their current role>", "toRole":
  "admin"}`. `fromRole` is a compare-and-swap guard — if their role moved since
  you read it, the change is refused rather than applied over the top.
  `PATCH /v1/members/{did}` with `{"role": "admin"}` is **not** this: it
  answers `adminRoleForbidden` and points here.
- **Add an admin ACL entry for a DID that is not a member.** Console →
  **Access control → Add entry**, or `acl/grant/0.1`.

You cannot promote *yourself*, with or without a passkey: admin elevation
takes a second person, not a second factor. If you are the only admin and have
lost your passkey, the offline `vtc … acl add` above is the break-glass.

Making someone an **unrestricted** admin — an admin grant with no scopes,
promoting a member who has none, or an admin invite — takes a second person
in a stronger sense too: another unrestricted admin has to consent
(VTI-APV-014). The request is sent to them, and you send the same operation
again once one has approved. A community with a single unrestricted admin has
nobody to ask, which is why `vtc setup` takes an optional `co_admin_did`. If
you installed without one, add the second offline with `vtc acl add`, daemon
stopped.

Every offline ACL change — `vtc acl add` and `remove`, `vtc create-did-key
--admin`, `vtc admin invite` — skips these checks by design, and each is
recorded: the daemon writes an `AclBreakGlassWritten` audit row for it when it
next starts, naming the command, the DID and the host it ran on.

## Part 2 — the first vetter

### Why the order matters

- **A vetter must be a current member.** `POST /v1/vetting/vetters` checks for a
  Member row, not an ACL entry, and answers `400 "<did> is not a current member
  of this community"` otherwise (`vtc-service/src/vetting/vetters.rs`).
- **The admin cannot become a member.** An ACL entry is not membership: the ACL
  says who may run the service, and membership is the credential pair the
  community issues. An invitation to a DID that already has an ACL entry is
  refused with `409 "… is already a current member — no invitation needed"`
  (`routes/invitations.rs`). A join by that DID fails too, because admission
  would write a second ACL row for it. So the first vetter is a **different
  identity** from the admin, held by the person who will vet.
- **Once a criterion requires vetting, nothing bypasses it.** The default
  `join.rego` holds admission until `input.evidence.vetting` is satisfied.
  Neither an invitation nor a trusted credential bypasses it, and a
  `request_more` request is `Deferred`, which an admin cannot approve (only
  `Pending` requests can be decided). A statement counts only if a vetter
  issued it. So a community that requires vetting before it has a vetter
  cannot admit anyone by vetting.

So: admit the vetter first, grant the role, and only then start requiring
vetting.

### Steps

0. **Do not add a vetting criterion yet.** If one exists (an Accepts criterion
   carrying a `vetting` object), remove it on **Vetting → Requirements**, or
   with `DELETE /v1/schemas/accepts/{id}`, until step 4.

1. **Invite the vetter-to-be.** Use **Invitations** in the console, or:

   ```http
   POST /v1/invitations
   Trust-Task: https://trusttasks.org/spec/vtc/invitations/issue/0.1
   Authorization: Bearer <admin token>

   { "subjectDid": "did:…", "validityDays": 7 }
   ```

   The response's `vic` is a signed Invitation Credential bound to that DID.
   Send it to the invitee **out of band**. The console offers copy, download
   and a QR code, but a large VIC can exceed QR capacity, so keep copy or
   download as the fallback. Nothing delivers the invitation to the invitee
   for you.

   The vetter-to-be's DID must be able to **sign**. Vetting statements are
   credentials the vetter signs, so a DID that has only a key-agreement key
   passes admission and the grant but can never vet anyone.

2. **The vetter-to-be applies**, with the VIC in the presentation. That is
   `vtc/join-requests/submit/0.2` over `POST /v1/trust-tasks`, a DIDComm
   session or TSP (in Rust, `vtc_client::VtcClient::submit_join_as`). With no
   vetting criterion in force, the default `join.rego` answers **`allow`** for
   a valid, trusted, unconsumed invitation: the applicant is admitted as a
   member (or at the role the invitation names), and receives the membership
   credential and role endorsement. See
   [`credential-delivery.md`](credential-delivery.md) for how they arrive.

   *Without an invitation* the same submission is referred to the moderator
   queue. Approve it in **Join requests**, or with
   `POST /v1/join-requests/{id}/decide`, body `{"decision": "approved"}`.

3. **Name them a vetter.** Open **Members**, choose the member, then **Grant
   vetter role**. Or:

   ```http
   POST /v1/vetting/vetters
   Trust-Task: https://trusttasks.org/spec/vtc/vetting/vetters/grant/0.1
   Authorization: Bearer <admin token>

   { "memberDid": "did:…", "validitySeconds": 31536000 }
   ```

   `201` issues the vetter role credential and delivers it to the member; `200`
   means a live grant already existed and returns it.

4. **Now require vetting.** Register the statement type and add the criterion:
   [`vetting.md`](vetting.md) §1–2, or **Vetting → Requirements**. From here,
   applicants gather statements from the vetter you just named.

5. **Grow the vetter pool** as members join: one at a time (step 3), by the
   automatic-grant sweep ([`vetting.md`](vetting.md) §5), or from an existing
   OpenPGP web of trust ([`vetting.md`](vetting.md) §8). Each of these needs
   the people to be members first.

A criterion that asks for an invitation **and** vetting is still a vetting
criterion. Adding it in step 0 blocks the first vetter the same way: the
invitation alone answers `request_more` (`needs: ["vetting"]`).

## Checklist

| Check | How |
|---|---|
| The admin can sign in | Console sign-in with the passkey, or `vtc acl list` (daemon stopped) shows an `admin` entry |
| A script can authenticate | `POST /v1/auth/` returns a token, not `403` |
| `cnm` can administer the community | `cnm vetting vetters list` answers; if it prints `vtc acl add`, run that |
| The first vetter is a member | **Members** lists the DID |
| The vetter grant is live | **Vetting → Vetters** shows the grant as `live` |
| Vetting is required only now | **Vetting → Requirements** has a vetting criterion, added after the grant |

## See also

- [Getting started](getting-started.md) and
  [Non-interactive setup](non-interactive-setup.md) — what comes before this.
- [Peer identity vetting](vetting.md) — the vetting model, criteria, statements.
- [Credential delivery](credential-delivery.md) — how an admitted member
  receives its credentials.
- [Website + admin UX](website-and-admin.md) — the admin console.
