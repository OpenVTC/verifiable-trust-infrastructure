# vti-oob-server

The approving side of wallet sign-in started by a trigger link: the `auth/oob/*` Trust Task family, where a wallet approves a key `K_b` that a browser holds. The crate is independent of what the service grants for that key.

Used by:
- **`vtc-service`**: member-portal and operator-console sign-in. `redeem` issues a session and its cookies.
- **The VTN service**, in [OpenVTC/verifiable-trust-network](https://github.com/OpenVTC/verifiable-trust-network). It has no cookies or sessions: `redeem` registers `K_b` as a key delegated to act as the approver for a fixed `signingScope`, for a bounded time. It depends on this crate, never the reverse.

## The flow

1. `request`: the browser opens a request under `K_b`, over HTTPS, from the service's own origin (T19).
2. `claim`: a wallet claims it with a throwaway `K_a`. The service answers with step 1, signed for `assertionMethod`.
3. `prove`: the wallet carries the approver's `identify`, signed for `authentication`, and the number shown on the screen. The service answers with step 2, signed.
4. `respond`: the wallet carries the approver's `grant`, signed for `assertionMethod`, bound to step 2 by `contextDigest`.
5. `redeem`: the browser long-polls under `K_b`. On approval the request is consumed once and the host issues its result.
6. `cancel`: either party ends the request.

The crate owns the request store and its compare-and-set, the claim and decision clocks, the long poll and its caps, the `did:key` precheck (T21), the carried-document checks (type, issuer, recipient, freshness, purpose, proof, replay of the carried `id`, T7), the context binding, and every refusal the family defines, in the order of `design-docs/vtc-qr-login-design.md` §7.3 to §7.6.

## What a service supplies

`OobHost`, one async trait:

| Method | What |
|---|---|
| `records` | The keyspace for the `oob_req:*` rows. The host sweeps it with `sweep`. |
| `service_did`, `public_url`, `service_name` | Its DID (the carried documents' recipient), its origin, the name the wallet shows |
| `locate` | Optional: the starter's location from a local database |
| `sign_step` | Signs steps 1 and 2 and the `respond` and `cancel` answers for `assertionMethod` |
| `verify_authentication`, `verify_assertion` | Verify a carried document's proof as received |
| `freshness_policy`, `accepted_ids` | The acceptance window and the accepted-id record carried documents are held to |
| `gate` | Who may approve, per audience, at three fixed points (`Gate::Known` before resolution, `Gate::Proved`, `Gate::Decided`), and how a refusal reads |
| `told_message` | The message `redeem` carries for a reason the starter is told |
| `signing_scope` | The `signingScope` step 2 offers, per audience |
| `audit` | The audit sink |
| `complete` | What `redeem` issues for a consumed approval: `Issued`, `NotAuthorized` or `Declined` |
| `reject_app_error`, `messages` | Optional: error rendering and the messages that name the host's surface |

Its associated type `Audience` is the host's set of audiences, read from `ext["org.openvtc.session"]` and signed into steps 1 and 2. A host with one audience implements it as a one-variant enum.

The entry points are `precheck` (in the spine's before-proof hook) and `dispatch` (for any type in `URIS`). The HTTPS door wraps the call in `HttpContext::scope`.

`delegation` reads a key a grant armed as its approver: `covers` (scope match and the excluded families), `record`, and `armed`, which takes the host's row type (`DelegatedKey`) and liveness binding (`DelegationLiveness`, or `AlwaysLive`).

This crate depends on no service. It reads the generated `auth/oob` types from `vti-specs-core`, and nothing else from the specification crates.
