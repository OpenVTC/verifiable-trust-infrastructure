//! The witnesses this community trusts.
//!
//! A Verifiable Witness Credential (VWC) is a `witnessed/1` statement: its
//! issuer says it watched one party present one relationship credential
//! (`docs/05-design-notes/witness-host-service.md`). Anyone can issue one, so
//! a verifier that weighs every VWC that verifies takes evidence from whoever
//! chose to sign it. The VTI specification separates the two questions
//! (VTI-CMP-030: verification establishes provenance and integrity, never
//! authority), and the design note gives the VTC the second half: a configured
//! list of the witnesses it trusts (§3.5).
//!
//! ## What the list does
//!
//! A VWC whose issuer is not on the list counts for nothing here, on every path
//! that reads one — the personhood assertion, the ceremony facts of a join
//! presentation, and the credentials a join criterion's query can be met by. It
//! is refused by the host, before any policy runs, as
//! [`WitnessBinding::UntrustedWitness`](super::witness::WitnessBinding), so a
//! policy cannot accept it: VTI-VTC-022 lets a policy refuse what the host
//! permits, never the reverse.
//!
//! ## Absence is the most restrictive reading
//!
//! The default is empty, and empty trusts **no** witness. A community has to
//! name a witness before any VWC counts. A corrupt stored list, or one that
//! cannot be read, is read the same way: nobody.
//!
//! ## Where it is set, and who may change it
//!
//! `[witnesses] trusted` in `config.toml`, or the runtime key
//! `witnesses.trusted` through `config/patch` (and `vtc/config/import`). The
//! list is community configuration that the host reads locally, so it needs no
//! Trust Task family of its own (trust-tasks-tf #779).
//!
//! **Every runtime change is a consent-gated action.** Adding a witness,
//! removing one or changing a label takes `vtc.config.admin`, the requester's
//! passkey gesture bound to that one patch or import, and then the approval of
//! the community's other holders of `vtc.config.admin`
//! ([`crate::acl::admin_consent::Act::ChangeTrustedWitnesses`]): the operation
//! is parked in the action list and runs itself on the N-th approval, against
//! the list as it is then. In single-administrator mode (VTI-APV-022) the
//! requester's bound gesture stands in for the consent and the waiver is
//! audited at `Critical`, as for every other consent the mode waives.
//!
//! Why: whose attestation counts as evidence is a major trust change for a
//! community — the community's decision (2026-10-16) — and VTI-CMP-090 asks
//! that a change to trust semantics attract the same review as a code change,
//! which here means a second administrator's. Removing a witness parks too: it
//! narrows what counts, but it can also strip the evidence a member's standing
//! rests on, and one administrator alone should not decide that either. The key
//! is marked as trust-bearing
//! ([`crate::config_store::ConfigKeyDef::trust_semantics`]) and every applied
//! change is audited with both lists, which is what lets a past decision's
//! effective list be reconstructed (VTI-CMP-091).
//!
//! `config.toml` is the host's: an edit there is an operator's offline change,
//! outside the action list, as every other host-only setting is.
//!
//! ## Kept minimal
//!
//! An entry is a DID and an optional label. There are no per-witness
//! constraints (which purposes or criteria a witness counts for): nothing in
//! the specification asks for them yet, and a community that wants one witness
//! for personhood and another for joining can say so in its policy, which may
//! refuse a witness the list admits.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vti_common::error::AppError;

use crate::config_store::ConfigStore;

/// The runtime configuration key the list is patched under.
pub const WITNESSES_TRUSTED: &str = "witnesses.trusted";

/// The most witnesses one community may list. A sanity bound, not a policy:
/// the list is read on every VWC, and a community trusting more than this many
/// independent witnesses is not choosing among them.
pub const MAX_TRUSTED_WITNESSES: usize = 64;

/// The longest label, in characters.
pub const MAX_LABEL_CHARS: usize = 128;

/// `[witnesses]` in `config.toml`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct WitnessesConfig {
    /// The witnesses whose VWCs count here. Empty (the default) trusts none.
    #[serde(default)]
    pub trusted: Vec<TrustedWitness>,
}

/// One trusted witness.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedWitness {
    /// The witness's DID, compared verbatim with a VWC's `issuer`.
    pub did: String,
    /// What an administrator calls it. Display only; never compared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl WitnessesConfig {
    /// Whether the section says nothing — so a config that never named a
    /// witness is not rewritten with an empty `[witnesses]` table.
    pub fn is_empty(&self) -> bool {
        self.trusted.is_empty()
    }

    /// Refuse a list that would not be accepted through `config/patch`, plus
    /// this community's own DID (`own_did`) as a witness of itself.
    pub fn validate(&self, own_did: Option<&str>) -> Result<(), AppError> {
        validate_entries(&self.trusted, own_did)
            .map_err(|e| AppError::Config(format!("[witnesses] trusted: {e}")))
    }
}

/// Parse and validate a `witnesses.trusted` value as `config/patch` carries it:
/// a JSON array of `{ "did": "...", "label": "..." }` objects.
pub fn parse_list(value: &Value, own_did: Option<&str>) -> Result<Vec<TrustedWitness>, AppError> {
    let list: Vec<TrustedWitness> = serde_json::from_value(value.clone()).map_err(|e| {
        AppError::Validation(format!(
            "expected an array of {{ \"did\": \"did:…\", \"label\": \"…\" }} objects: {e}"
        ))
    })?;
    validate_entries(&list, own_did).map_err(AppError::Validation)?;
    Ok(list)
}

/// The rules every list obeys, wherever it was written.
fn validate_entries(list: &[TrustedWitness], own_did: Option<&str>) -> Result<(), String> {
    if list.len() > MAX_TRUSTED_WITNESSES {
        return Err(format!(
            "{} witnesses listed; at most {MAX_TRUSTED_WITNESSES} may be",
            list.len()
        ));
    }
    let mut seen = BTreeSet::new();
    for w in list {
        vti_common::identifier::validate_did("did", &w.did).map_err(|e| e.to_string())?;
        // A VWC's issuer is a DID, never a verification method or a URL.
        if w.did.contains(['#', '?', '/']) {
            return Err(format!(
                "{} is not a bare DID: name the witness, not one of its keys or resources",
                w.did
            ));
        }
        if own_did == Some(w.did.as_str()) {
            return Err(format!(
                "{} is this community's own DID. A witness has value only as a party \
                 independent of what it attests, and a community never witnesses \
                 (VTI-KEY-007)",
                w.did
            ));
        }
        if !seen.insert(w.did.as_str()) {
            return Err(format!("{} is listed twice", w.did));
        }
        if let Some(label) = &w.label {
            if label.trim().is_empty() {
                return Err(format!("the label of {} is blank; omit it instead", w.did));
            }
            if label.chars().count() > MAX_LABEL_CHARS {
                return Err(format!(
                    "the label of {} is longer than {MAX_LABEL_CHARS} characters",
                    w.did
                ));
            }
            if label.chars().any(char::is_control) {
                return Err(format!(
                    "the label of {} contains a control character",
                    w.did
                ));
            }
        }
    }
    Ok(())
}

/// The set of trusted witness DIDs in force for one decision.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedWitnesses {
    dids: BTreeSet<String>,
}

impl TrustedWitnesses {
    /// No witness — the default, and the reading of anything unreadable.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn from_list(list: &[TrustedWitness]) -> Self {
        Self {
            dids: list.iter().map(|w| w.did.clone()).collect(),
        }
    }

    /// Whether `issuer` is a trusted witness. Compared verbatim: a DID is case
    /// sensitive, and no canonicalization is sanctioned that would make two
    /// spellings one witness.
    pub fn contains(&self, issuer: &str) -> bool {
        self.dids.contains(issuer)
    }

    pub fn is_empty(&self) -> bool {
        self.dids.is_empty()
    }
}

/// The list in force **now**: the database layer when `config/patch` wrote one,
/// else the in-memory value (TOML, or the default). Read live, as the consent
/// threshold is, so a patch binds the next presentation without a reload.
///
/// Fail closed: a stored value that does not parse, or a store that cannot be
/// read, trusts no witness — never the TOML list, which the patch replaced.
pub async fn live(cfg: &crate::config::AppConfig, db: &ConfigStore) -> TrustedWitnesses {
    match db.get(WITNESSES_TRUSTED).await {
        Ok(Some(value)) => match parse_list(&value, cfg.vtc_did.as_deref()) {
            Ok(list) => TrustedWitnesses::from_list(&list),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "stored `{WITNESSES_TRUSTED}` does not parse; trusting no witness until it is \
                     rewritten"
                );
                TrustedWitnesses::none()
            }
        },
        Ok(None) => TrustedWitnesses::from_list(&cfg.witnesses.trusted),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not read `{WITNESSES_TRUSTED}`; trusting no witness for this decision"
            );
            TrustedWitnesses::none()
        }
    }
}

/// [`live`], from the service state.
pub async fn live_for(state: &crate::server::AppState) -> TrustedWitnesses {
    let cfg = state.config.read().await.clone();
    live(&cfg, &ConfigStore::new(state.config_ks.clone())).await
}

/// The list in force now, as written: the database layer's value when
/// `config/patch` wrote one — verbatim, even one that no longer parses —
/// else the in-memory list. What a consent to change the list is pinned to
/// ([`crate::acl::admin_consent::Act::ChangeTrustedWitnesses`]), so a list
/// that moves between the ask and the write voids the action.
pub async fn current_value(state: &crate::server::AppState) -> Result<Value, AppError> {
    if let Some(value) = ConfigStore::new(state.config_ks.clone())
        .get(WITNESSES_TRUSTED)
        .await?
    {
        return Ok(value);
    }
    let cfg = state.config.read().await;
    serde_json::to_value(&cfg.witnesses.trusted)
        .map_err(|e| AppError::Internal(format!("serialising the witness list: {e}")))
}

/// What a write of `overrides` would change the list from, and to — `None`
/// when it leaves the list alone, or names a value the write would refuse
/// anyway (that is refused there, without a gesture). The trigger of the
/// consent gate on `config/patch` and `vtc/config/import`.
///
/// "From" is the list in force ([`current_value`]); one that no longer parses
/// is shown as empty, which is what it trusts.
pub async fn change_in<'a>(
    state: &crate::server::AppState,
    overrides: impl IntoIterator<Item = (&'a String, &'a Value)>,
) -> Result<Option<(Vec<TrustedWitness>, Vec<TrustedWitness>)>, AppError> {
    let Some((_, value)) = overrides
        .into_iter()
        .find(|(k, _)| k.as_str() == WITNESSES_TRUSTED)
    else {
        return Ok(None);
    };
    let own = state.config.read().await.vtc_did.clone();
    let Ok(next) = parse_list(value, own.as_deref()) else {
        return Ok(None);
    };
    let current = current_value(state).await?;
    let prev = parse_list(&current, own.as_deref()).unwrap_or_default();
    // Order carries no meaning (DIDs are unique within a list), so the same
    // witnesses under the same labels in another order are no change.
    let sorted = |l: &[TrustedWitness]| {
        let mut l = l.to_vec();
        l.sort_by(|a, b| a.did.cmp(&b.did));
        l
    };
    Ok((sorted(&prev) != sorted(&next)).then_some((prev, next)))
}

/// A list for a person to read: each witness's label and DID, or `none`.
pub fn describe(list: &[TrustedWitness]) -> String {
    if list.is_empty() {
        return "none".into();
    }
    list.iter()
        .map(|w| match &w.label {
            Some(label) => format!("{label} ({})", w.did),
            None => w.did.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const W: &str = "did:webvh:QmScid:witness.example";

    #[test]
    fn the_default_trusts_no_witness() {
        let cfg = WitnessesConfig::default();
        assert!(cfg.is_empty());
        assert!(TrustedWitnesses::from_list(&cfg.trusted).is_empty());
        assert!(!TrustedWitnesses::none().contains(W));
    }

    #[test]
    fn a_listed_witness_is_trusted_verbatim() {
        let t = TrustedWitnesses::from_list(&[TrustedWitness {
            did: W.into(),
            label: Some("Independent witness".into()),
        }]);
        assert!(t.contains(W));
        assert!(!t.contains(&W.to_uppercase()), "no case folding");
        assert!(
            !t.contains(&format!("{W}#key-0")),
            "a key is not the witness"
        );
    }

    #[test]
    fn a_patch_value_parses_and_round_trips() {
        let v = json!([{ "did": W, "label": "A" }, { "did": "did:key:z6MkWitness" }]);
        let list = parse_list(&v, None).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(serde_json::to_value(&list).unwrap(), v);
    }

    #[test]
    fn malformed_lists_are_refused() {
        let own = "did:webvh:QmScid:vtc.example";
        let refused = [
            json!("did:key:z6Mk"),                    // not an array
            json!([W]),                               // bare strings
            json!([{ "did": "not-a-did" }]),          // not a DID
            json!([{ "did": format!("{W}#key-0") }]), // a key
            json!([{ "did": W }, { "did": W }]),      // duplicate
            json!([{ "did": W, "label": "  " }]),     // blank label
            json!([{ "did": W, "label": "a\nb" }]),   // control character
            json!([{ "did": W, "label": "x".repeat(MAX_LABEL_CHARS + 1) }]),
            json!([{ "did": W, "weight": 2 }]), // unknown member
            json!([{ "did": own }]),            // the community itself
        ];
        for v in refused {
            assert!(parse_list(&v, Some(own)).is_err(), "{v} must be refused");
        }
        let too_many: Vec<_> = (0..=MAX_TRUSTED_WITNESSES)
            .map(|n| json!({ "did": format!("did:key:z6MkWitness{n}") }))
            .collect();
        assert!(parse_list(&json!(too_many), None).is_err());
    }

    #[test]
    fn the_toml_section_reads_and_validates() {
        let cfg: WitnessesConfig = toml::from_str(&format!(
            "trusted = [{{ did = \"{W}\", label = \"Independent\" }}]"
        ))
        .unwrap();
        assert!(cfg.validate(None).is_ok());
        assert!(cfg.validate(Some(W)).is_err(), "never the community itself");
        assert!(toml::from_str::<WitnessesConfig>("trusted = [{ did = \"x\", y = 1 }]").is_err());
    }
}
