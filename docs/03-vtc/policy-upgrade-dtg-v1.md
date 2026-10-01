# Custom policies after the DTG Credentials v1 upgrade

**Who needs this:** an operator who has uploaded and activated **their own Rego policy** for any VTC purpose. If every purpose still runs the policy the VTC shipped with, there is nothing to do. The shipped defaults have been updated, and an existing VTC replaces a stale shipped personhood default automatically.

**What changed:** with #1859 (`vta-sdk` 0.58, `vta-service` 0.47), every credential the VTC issues and verifies uses the DTG Credentials v1 shapes. Roles are authority credentials (VACs), and endorsements, witnessing and vetting are statement credentials (VSCs) with a registry predicate. The retired `EndorsementCredential` and `WitnessCredential` types no longer exist. Custom policies read those credentials, so a rule written against the old shapes now **silently denies**. Rego treats a missing field as undefined, not as an error, so the policy keeps loading, keeps running and stops ever allowing.

## The changes that can break a custom policy

### 1. `cross_community_roles`: `input.foreign_vec` is now `input.foreign_vac`

The foreign role credential in a recognise request is now a VAC, and the input key is renamed. The fields inside it are unchanged.

```rego
# before
allow if { input.foreign_vec.issuer == "did:webvh:…:partner" ; input.foreign_vec.role == "admin" }

# after
allow if { input.foreign_vac.issuer == "did:webvh:…:partner" ; input.foreign_vac.role == "admin" }
```

`issuer`, `role` and `subject_did` are as before, and `action` is still `"mint_session"`. The shipped default is deny-all and doesn't read this key, so only uploaded policies are affected.

### 2. `personhood`: witness and identity-verification evidence have new shapes

`input.vp_claims.credentials[]` carries the presented credentials, and two of them changed.

**Witness statements.** A witness statement is no longer `WitnessCredential`. It's a `StatementCredential` under the `witnessed/1` predicate:

```rego
# before
"WitnessCredential" in cred.type

# after
"StatementCredential" in cred.type
cred.credentialSubject.predicate == "https://registry.trustoverip.org/dtg/vsc/witnessed/1"
```

The witnessed credential's digest moved from `credentialSubject.digestMultibase` to `credentialSubject.object.digestMultibase`.

**In-person identity verification.** This is no longer an `EndorsementCredential` with `endorsement.type: "IdentityVerification"`. It's a plain W3C credential of type `IdentityVerificationCredential`, deliberately not a DTG credential, with its claims directly in `credentialSubject`:

```rego
# before
"EndorsementCredential" in cred.type
cred.credentialSubject.endorsement.type == "IdentityVerification"

# after
"IdentityVerificationCredential" in cred.type
not "DTGCredential" in cred.type
```

### 3. Any policy that reads role or endorsement credentials

- **Role credentials** are `AuthorityCredential`s. The role is an action, not an endorsement member: `credentialSubject.authority.actions` contains `"role:<name>"` (for example `"role:vetter"` or `"role:custom:editor"`), and `credentialSubject.authority.scope` is the community DID. A rule that read `credentialSubject.endorsement.role` or matched `"CommunityRole"` needs rewriting.
- **Custom endorsements** issued by `vtc/endorsements/issue` are `StatementCredential`s. The registered `typeUri` is now `credentialSubject.predicate`, and the claim is in `credentialSubject.object.value`, where it used to be `credentialSubject.endorsement`.

### 4. `relationships`: the issuer's declared scope is available

The input gains `issuer_scope` (`"pairwise"`, `"directed"` or `"public"`), read from the VRC's `issuerScope`. `identifier_form` is now derived from it: `pairwise` gives `"pairwise"`, and `directed` or `public` gives `"attributed"`. A policy that only reads `identifier_form` keeps working. A VRC without `issuerScope` is refused before policy runs. So is a VRC that declares `pairwise` but is issued under the member's membership DID, since that identifier is not pairwise.

### 5. Vetting and join: `statementType` is a predicate IRI

A join manifest's `vetting.statementType` is now the predicate a counted statement carries, `https://registry.trustoverip.org/dtg/vsc/vetted/1`. The old endorsement-type URI (`https://firstperson.network/endorsements/identity-vetting/0.1`) no longer appears. A join policy that compared against the old URI needs updating.

### 6. Ceremony rules: credential facts report the concrete type and predicate

A ceremony `Credential` fact now names the credential's concrete type (`MembershipCredential`, `StatementCredential` and so on) where it used to say `DTGCredential`, and a statement's fact carries its `predicate`. The admin UI's rule builder has a matching `holds_trusted_statement` condition.

## Checking your policies

For each purpose with an active uploaded policy, search its Rego for the retired names:

```sh
grep -nE 'foreign_vec|WitnessCredential|EndorsementCredential|endorsement\.type|endorsement\.role|CommunityRole|identity-vetting/0\.1|"IdentityVerification"' my-policy.rego
```

Any hit needs the change described above. Then upload and activate the new version as before:

```sh
cnm policies upload --purpose <purpose> --rego ./my-policy.rego
cnm policies activate --id <returned-policy-id>
```

For more on the new credential shapes, see [Credentials](credentials.md), [Personhood + relationships](personhood-and-graph.md) and [Peer identity vetting](vetting.md).
