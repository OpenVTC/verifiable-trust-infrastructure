### vta-sdk 0.20.28 / vtc-service 0.11.46 — a community can advertise the registry authoritative for it (#877)

TRQP v2.0 recommends a trust registry be machine-discoverable *"via the
`authority_id`"* — from the DID document of the authority whose records it
holds. A VTC **is** the `authority_id` in every tuple evaluated under it, so
the pointer belongs in the community's own document. Nothing emitted one:
`trql-client` gained `registry_referral` to *follow* a referral
(affinidi/affinidi-trust-registry-rs#118) and returns `None` for every document
in the wild because no producer existed. This is the producer.

- **`vta-sdk`**: `vtc-host` gains an optional `#trust-registry` service entry
  whose `serviceEndpoint` is `{uri: <registry DID>, profile: <TRQP profile
  URI>}`. New `did_templates::referral_service` builds it, and owns
  `TRUST_REGISTRY_SERVICE_TYPE` + `TRQP_PROFILE_URI` — the **single source of
  truth** for both wire constants, matching `trust-registry`'s own values. The
  entry rides as the `SERVICE_TRUST_REGISTRY` var through the template's
  null-pruning slot, so a community with no registry renders byte-identically
  to before. Built in Rust rather than written into the template JSON because
  the format's only conditional is whole-array-element pruning, which requires
  the caller to supply the whole element — the template cannot own a constant
  it can also omit.
- **`vtc-service`**: `vtc setup` prompts for the registry DID; `setup --from`
  takes `registry_did`. Both refuse a non-DID before the first VTA round-trip
  — a referral is distinguished from a registry advertising its own endpoint
  by the `uri` carrying a `did:` prefix, so an https URL here would be read as
  this community serving TRQP itself. Blank reads as "no registry", since
  templated deploys emit empty strings for unset values.
- **Docs**: `docs/02-vta/did-templates.md`, `docs/05-design-notes/vtc-mvp.md`
  §4.4, and the shipped `vtc-setup.example.toml`.

A consuming repo can then configure **one** DID — the community — and resolve
one hop to its registry, instead of being handed both.

Publishing a referral asserts nothing about authority: anyone may name any
registry in their own document. Authority flows registry → subject, and
closing that loop is the client's job (`TrqlClient::referred_by`,
affinidi/affinidi-trust-registry-rs#122, which lands first for that reason).
Emitting the entry establishes where to ask and nothing more.

**Fixed at mint time.** A VTC serves a write-once `did.jsonl` and holds no
update authority over its own log, so changing the referral later needs a
VTA-side `pnm did-mgmt dids edit` plus redelivering the log by hand — a
serverless DID's updated log is persisted only in the VTA's store and nothing
pushes it. Existing communities therefore cannot gain a referral without
re-provisioning. Automating that redelivery (a VTC-side pull against the VTA's
public `GET /did/{did}/log`, plus a staleness check in `vtc status`) is the
natural follow-up and is not included here.
