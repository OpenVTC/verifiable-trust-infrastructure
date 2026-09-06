//! `pnm persona …` dispatch — thin shim over the shared persona commands,
//! plus the three places a flat CLI has to reconstruct a structured payload:
//! provenance, typed values, and profile entries.
//!
//! Each of those validates here rather than letting the VTA reject the
//! request, so the operator is told which flag is missing instead of reading a
//! schema-validation failure.

use std::io::Read;

use vta_cli_common::commands::persona as p;
use vta_sdk::prelude::*;
use vta_sdk::protocols::persona::{
    ContactDocument, LocalProfileEntry, ProfileEntry, ProofRung, Provenance, ValueType,
};

use crate::cli::{
    PersonaAttributeCommands, PersonaBindingCommands, PersonaCommands, PersonaContactCommands,
    PersonaDisclosureCommands, PersonaLocalBindingCommands, PersonaLocalCommands,
    PersonaLocalProfileCommands, PersonaProfileCommands, ProofRungOpt, ProvenanceOpt, ValueTypeOpt,
};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) async fn run(client: &VtaClient, command: PersonaCommands) -> CmdResult {
    match command {
        PersonaCommands::Attribute { command } => attribute(client, command).await,
        PersonaCommands::Profile { command } => profile(client, command).await,
        PersonaCommands::Binding { command } => binding(client, command).await,
        PersonaCommands::Contact { command } => contact(client, command).await,
        PersonaCommands::Disclosure { command } => disclosure(client, command).await,
        PersonaCommands::Local { command } => local(client, command).await,
        PersonaCommands::Correlate {
            attribute_id,
            profile_id,
            candidate_file,
        } => {
            let candidate = candidate_file.as_deref().map(read_json).transpose()?;
            if attribute_id.is_none() && profile_id.is_none() && candidate.is_none() {
                return Err(
                    "nothing to analyse — pass one of --attribute-id, --profile-id or \
                            --candidate-file"
                        .into(),
                );
            }
            p::cmd_correlate(client, attribute_id, profile_id, candidate).await
        }
        PersonaCommands::Renderers => p::cmd_renderers(client).await,
    }
}

async fn attribute(client: &VtaClient, command: PersonaAttributeCommands) -> CmdResult {
    match command {
        PersonaAttributeCommands::Put {
            claim_type,
            value,
            value_type,
            label,
            provenance,
            credential_id,
            claim_path,
            issuer_did,
            proof,
            generator,
            per_verifier,
            attribute_id,
            expected_version,
        } => {
            let vt = value_type_of(value_type);
            let parsed = parse_value(&value, vt)?;
            let prov = build_provenance(
                provenance,
                credential_id,
                claim_path,
                issuer_did,
                proof,
                generator,
                per_verifier,
            )?;
            p::cmd_attribute_put(
                client,
                claim_type,
                parsed,
                vt,
                prov,
                label,
                attribute_id,
                expected_version,
            )
            .await
        }
        PersonaAttributeCommands::List {
            type_prefix,
            values,
            include_stale,
            limit,
            cursor,
        } => p::cmd_attribute_list(client, type_prefix, values, include_stale, limit, cursor).await,
        PersonaAttributeCommands::Delete {
            attribute_id,
            cascade,
            expected_version,
        } => p::cmd_attribute_delete(client, attribute_id, cascade, expected_version).await,
    }
}

async fn profile(client: &VtaClient, command: PersonaProfileCommands) -> CmdResult {
    match command {
        PersonaProfileCommands::Put {
            name,
            refs,
            entries_file,
            credential_refs,
            profile_id,
            expected_version,
        } => {
            let entries = profile_entries(refs, entries_file)?;
            p::cmd_profile_put(
                client,
                name,
                entries,
                credential_refs,
                profile_id,
                expected_version,
            )
            .await
        }
        PersonaProfileCommands::Get {
            profile_id,
            resolve,
        } => p::cmd_profile_get(client, profile_id, resolve).await,
        PersonaProfileCommands::List { limit, cursor } => {
            p::cmd_profile_list(client, limit, cursor).await
        }
        PersonaProfileCommands::Delete {
            profile_id,
            unbind,
            expected_version,
        } => p::cmd_profile_delete(client, profile_id, unbind, expected_version).await,
    }
}

async fn binding(client: &VtaClient, command: PersonaBindingCommands) -> CmdResult {
    match command {
        PersonaBindingCommands::Set {
            context,
            persona_did,
            profile_id,
            public_entries,
            expected_version,
        } => {
            p::cmd_binding_set(
                client,
                context,
                persona_did,
                profile_id,
                public_entries,
                expected_version,
            )
            .await
        }
        PersonaBindingCommands::Get {
            context,
            persona_did,
        } => p::cmd_binding_get(client, context, persona_did).await,
        PersonaBindingCommands::List {
            context,
            limit,
            cursor,
        } => p::cmd_binding_list(client, context, limit, cursor).await,
    }
}

async fn contact(client: &VtaClient, command: PersonaContactCommands) -> CmdResult {
    match command {
        PersonaContactCommands::Put {
            context,
            subject_did,
            known_by_persona,
            document_file,
            credential_refs,
            notes,
        } => {
            let raw = read_json(&document_file)?;
            let document: ContactDocument = serde_json::from_value(raw).map_err(|e| {
                format!(
                    "{document_file}: not a contact document ({e}) — expected an object with a \
                         `claims` array, each entry carrying at least `type` and `value`"
                )
            })?;
            p::cmd_contact_put(
                client,
                context,
                subject_did,
                known_by_persona,
                document,
                credential_refs,
                notes,
            )
            .await
        }
        PersonaContactCommands::Get {
            context,
            contact_id,
            rev,
            include_history,
        } => p::cmd_contact_get(client, context, contact_id, rev, include_history).await,
        PersonaContactCommands::List {
            context,
            known_by_persona,
            changed_since,
            limit,
            cursor,
        } => {
            p::cmd_contact_list(
                client,
                context,
                known_by_persona,
                changed_since,
                limit,
                cursor,
            )
            .await
        }
        PersonaContactCommands::Delete {
            context,
            contact_id,
        } => p::cmd_contact_delete(client, context, contact_id).await,
    }
}

async fn disclosure(client: &VtaClient, command: PersonaDisclosureCommands) -> CmdResult {
    match command {
        PersonaDisclosureCommands::Preview {
            context,
            persona_did,
            verifier_did,
            requested_claims,
            purpose,
            renderer,
        } => {
            p::cmd_disclosure_preview(
                client,
                context,
                persona_did,
                verifier_did,
                requested_claims,
                purpose,
                renderer,
            )
            .await
        }
        PersonaDisclosureCommands::Present {
            context,
            preview_id,
            challenge,
            mint_file,
        } => {
            let mint = mint_file.as_deref().map(read_json).transpose()?;
            p::cmd_disclosure_present(client, context, preview_id, challenge, mint).await
        }
        PersonaDisclosureCommands::History {
            context,
            verifier_did,
            attribute_type,
            since,
            limit,
            cursor,
        } => {
            p::cmd_disclosure_history(
                client,
                context,
                verifier_did,
                attribute_type,
                since,
                limit,
                cursor,
            )
            .await
        }
    }
}

async fn local(client: &VtaClient, command: PersonaLocalCommands) -> CmdResult {
    match command {
        PersonaLocalCommands::Profile { command } => match command {
            PersonaLocalProfileCommands::Put {
                context,
                name,
                entries_file,
                profile_id,
                expected_version,
            } => {
                let entries = local_entries(&entries_file)?;
                p::cmd_local_profile_put(
                    client,
                    context,
                    name,
                    entries,
                    profile_id,
                    expected_version,
                )
                .await
            }
            PersonaLocalProfileCommands::Get {
                context,
                profile_id,
            } => p::cmd_local_profile_get(client, context, profile_id).await,
            PersonaLocalProfileCommands::List {
                context,
                limit,
                cursor,
            } => p::cmd_local_profile_list(client, context, limit, cursor).await,
            PersonaLocalProfileCommands::Delete {
                context,
                profile_id,
                unbind,
            } => p::cmd_local_profile_delete(client, context, profile_id, unbind).await,
        },
        PersonaLocalCommands::Binding { command } => match command {
            PersonaLocalBindingCommands::Set {
                context,
                persona_did,
                profile_id,
                expected_version,
            } => {
                p::cmd_local_binding_set(client, context, persona_did, profile_id, expected_version)
                    .await
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Reconstructing structure from flags
// ---------------------------------------------------------------------------

fn value_type_of(v: ValueTypeOpt) -> ValueType {
    match v {
        ValueTypeOpt::String => ValueType::String,
        ValueTypeOpt::Number => ValueType::Number,
        ValueTypeOpt::Boolean => ValueType::Boolean,
        ValueTypeOpt::Date => ValueType::Date,
        ValueTypeOpt::Object => ValueType::Object,
    }
}

/// Interpret `--value` according to `--value-type`.
///
/// Strings and dates are taken literally: parsing them as JSON would turn the
/// perfectly ordinary name `null`, or a house number typed as `7`, into
/// something other than what the operator wrote. Everything else is parsed,
/// and a parse failure names the type that was asked for rather than reporting
/// a syntax error against a document the operator did not think they were
/// writing.
fn parse_value(raw: &str, value_type: ValueType) -> Result<serde_json::Value, String> {
    match value_type {
        ValueType::String | ValueType::Date => Ok(serde_json::Value::String(raw.to_string())),
        ValueType::Number | ValueType::Boolean | ValueType::Object => serde_json::from_str(raw)
            .map_err(|e| {
                format!(
                    "--value is not a valid {}: {e}. Pass `--value-type string` to store it \
                     literally.",
                    match value_type {
                        ValueType::Number => "number",
                        ValueType::Boolean => "boolean",
                        _ => "JSON object",
                    }
                )
            }),
    }
}

/// Build a [`Provenance`] from the flat flags, refusing an incomplete one.
///
/// A `credentialBacked` claim missing its credential is not a claim with a
/// gap — it is a self-asserted value wearing a credential's authority, which
/// is the one thing provenance exists to prevent. So the incomplete
/// combination is an error here rather than a silent downgrade anywhere.
fn build_provenance(
    kind: ProvenanceOpt,
    credential_id: Option<String>,
    claim_path: Option<String>,
    issuer_did: Option<String>,
    proof: Option<ProofRungOpt>,
    generator: Option<String>,
    per_verifier: Option<bool>,
) -> Result<Provenance, String> {
    let unused = |flags: &[(&str, bool)]| -> Result<(), String> {
        let set: Vec<&str> = flags
            .iter()
            .filter(|(_, on)| *on)
            .map(|(n, _)| *n)
            .collect();
        if set.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{} ignored by --provenance {}; remove them or change the provenance",
                set.join(", "),
                match kind {
                    ProvenanceOpt::SelfAsserted => "self-asserted",
                    ProvenanceOpt::CredentialBacked => "credential-backed",
                    ProvenanceOpt::Generated => "generated",
                }
            ))
        }
    };

    match kind {
        ProvenanceOpt::SelfAsserted => {
            unused(&[
                ("--credential-id", credential_id.is_some()),
                ("--claim-path", claim_path.is_some()),
                ("--issuer-did", issuer_did.is_some()),
                ("--proof", proof.is_some()),
                ("--generator", generator.is_some()),
                ("--per-verifier", per_verifier.is_some()),
            ])?;
            Ok(Provenance::SelfAsserted)
        }
        ProvenanceOpt::CredentialBacked => {
            unused(&[
                ("--generator", generator.is_some()),
                ("--per-verifier", per_verifier.is_some()),
            ])?;
            let credential_id =
                credential_id.ok_or("--provenance credential-backed requires --credential-id")?;
            let claim_path = claim_path.ok_or(
                "--provenance credential-backed requires --claim-path, e.g. \
                 /credentialSubject/familyName",
            )?;
            Ok(Provenance::CredentialBacked {
                credential_id,
                claim_path,
                issuer_did,
                proof: proof.map(|r| match r {
                    ProofRungOpt::Predicate => ProofRung::Predicate,
                    ProofRungOpt::Derived => ProofRung::Derived,
                    ProofRungOpt::SelectiveDisclosure => ProofRung::SelectiveDisclosure,
                    ProofRungOpt::Whole => ProofRung::Whole,
                }),
            })
        }
        ProvenanceOpt::Generated => {
            unused(&[
                ("--credential-id", credential_id.is_some()),
                ("--claim-path", claim_path.is_some()),
                ("--issuer-did", issuer_did.is_some()),
                ("--proof", proof.is_some()),
            ])?;
            let generator =
                generator.ok_or("--provenance generated requires --generator, e.g. relayEmail")?;
            Ok(Provenance::Generated {
                generator,
                per_verifier,
            })
        }
    }
}

/// Profile entries from either the `--ref` shorthand or a JSON file.
fn profile_entries(
    refs: Vec<String>,
    entries_file: Option<String>,
) -> Result<Vec<ProfileEntry>, String> {
    if let Some(path) = entries_file {
        let raw = read_json(&path)?;
        return serde_json::from_value(raw).map_err(|e| {
            format!(
                "{path}: not a profile-entry array ({e}) — each entry is one of \
                 {{\"ref\":\"…\"}}, {{\"ref\":\"…\",\"pinVersion\":n}}, \
                 {{\"ref\":\"…\",\"override\":{{\"value\":…}}}} or {{\"inline\":{{…}}}}"
            )
        });
    }
    if refs.is_empty() {
        return Err(
            "a profile needs entries — pass --ref <attribute-id> (repeatable) or --entries-file"
                .into(),
        );
    }
    Ok(refs
        .into_iter()
        .map(|attribute_id| ProfileEntry::Ref { attribute_id })
        .collect())
}

/// Entries for a context-local profile: inline values only.
///
/// The error path is the interesting one. A `{"ref": …}` entry fails to parse,
/// and serde's own message ("unknown field `ref`") describes the symptom
/// rather than the rule, so it is replaced with the rule: a profile inside a
/// context cannot reach into the holder's pool, and the way to get a pool
/// value in here is to bind an agent-scoped profile instead.
fn local_entries(path: &str) -> Result<Vec<LocalProfileEntry>, String> {
    let raw = read_json(path)?;
    let mentions_ref = raw
        .as_array()
        .is_some_and(|a| a.iter().any(|e| e.get("ref").is_some()));
    serde_json::from_value(raw).map_err(|e| {
        if mentions_ref {
            format!(
                "{path}: a context-local profile cannot reference the holder's attribute pool. \
                 Its entries are inline values only — {{\"inline\":{{\"type\":…,\"value\":…, \
                 \"valueType\":…,\"provenance\":{{\"kind\":\"selfAsserted\"}}}}}}. To present a \
                 pool attribute in this context, build an agent-scoped profile with \
                 `persona profile put` and bind it with `persona binding set`."
            )
        } else {
            format!("{path}: not a local-profile-entry array ({e})")
        }
    })
}

/// Read a JSON document from a file path, or stdin when `path` is `-`.
fn read_json(path: &str) -> Result<serde_json::Value, String> {
    let contents = if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("stdin: {e}"))?;
        buf
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?
    };
    serde_json::from_str(&contents).map_err(|e| format!("{path}: invalid JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name that happens to read as JSON is still a name.
    ///
    /// `null`, `7` and `true` are all things a person legitimately types into
    /// a string field — a house number, a nickname, a nom de plume. Parsing
    /// `--value` as JSON regardless of `--value-type` would store something
    /// other than what was written, and the holder would find out when a
    /// verifier saw it.
    #[test]
    fn a_string_value_is_taken_literally() {
        for raw in ["null", "7", "true", "{\"not\": \"an object\"}"] {
            let v = parse_value(raw, ValueType::String).expect("string values always parse");
            assert_eq!(v, serde_json::Value::String(raw.to_string()));
        }
    }

    /// A typed value that is not of its type fails here, naming the escape
    /// hatch, rather than at the VTA's schema validator.
    #[test]
    fn a_mistyped_value_names_the_way_out() {
        let err = parse_value("not-a-number", ValueType::Number).expect_err("must not parse");
        assert!(
            err.contains("--value-type string"),
            "the error should name the escape hatch, got: {err}"
        );
    }

    /// An incomplete `credentialBacked` claim is refused rather than
    /// downgraded.
    ///
    /// The alternative — dropping the missing members and sending it anyway —
    /// produces a self-asserted value wearing a credential's authority, which
    /// is the single thing provenance exists to prevent.
    #[test]
    fn credential_backed_provenance_refuses_to_be_incomplete() {
        let err = build_provenance(
            ProvenanceOpt::CredentialBacked,
            None,
            Some("/credentialSubject/familyName".into()),
            None,
            None,
            None,
            None,
        )
        .expect_err("must refuse without a credential id");
        assert!(err.contains("--credential-id"), "got: {err}");

        let err = build_provenance(
            ProvenanceOpt::CredentialBacked,
            Some("cred-1".into()),
            None,
            None,
            None,
            None,
            None,
        )
        .expect_err("must refuse without a claim path");
        assert!(err.contains("--claim-path"), "got: {err}");
    }

    /// A flag that the chosen provenance would ignore is an error, not a
    /// no-op.
    ///
    /// Silently dropping `--credential-id` from a self-asserted attribute
    /// leaves the operator believing they stored something attested.
    #[test]
    fn a_flag_the_provenance_ignores_is_refused() {
        let err = build_provenance(
            ProvenanceOpt::SelfAsserted,
            Some("cred-1".into()),
            None,
            None,
            None,
            None,
            None,
        )
        .expect_err("must refuse a flag it would ignore");
        assert!(err.contains("--credential-id"), "got: {err}");
    }

    #[test]
    fn a_complete_generated_provenance_builds() {
        let p = build_provenance(
            ProvenanceOpt::Generated,
            None,
            None,
            None,
            None,
            Some("relayEmail".into()),
            Some(true),
        )
        .expect("builds");
        assert!(matches!(
            p,
            Provenance::Generated {
                ref generator,
                per_verifier: Some(true)
            } if generator == "relayEmail"
        ));
    }

    /// `--ref` shorthand produces live references, not pins.
    #[test]
    fn the_ref_shorthand_produces_live_references() {
        let entries = profile_entries(vec!["01J8".into(), "01J9".into()], None).expect("builds");
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .all(|e| matches!(e, ProfileEntry::Ref { .. }))
        );
    }

    /// A profile with no entries is a mistake worth catching before the round
    /// trip: it would discloses nothing, which is never what was meant.
    #[test]
    fn a_profile_with_no_entries_is_refused() {
        let err = profile_entries(Vec::new(), None).expect_err("must refuse");
        assert!(err.contains("--ref"), "got: {err}");
    }
}
