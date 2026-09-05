//! Persona Trust Task client methods (`spec/persona/*`).
//!
//! Drives the family through the generic trust-task dispatcher
//! ([`VtaClient::dispatch_trust_task`]) — there are no dedicated REST routes.
//!
//! Bodies are built from the typed [`protocols::persona`] structs rather than
//! `json!` literals, so a schema change surfaces here as a compile error
//! rather than as a payload the VTA rejects at run time.
//!
//! ## Two scopes, and callers should know which they are in
//!
//! Eleven of these tasks are **holder-scoped**: the attribute pool, the
//! profiles built over it, correlation analysis, the renderer registry. The
//! VTA gates them on *unrestricted* authority — an administrator scoped to a
//! single trust context is refused, because the pool is not any context's to
//! read. A client holding a context-scoped credential will get
//! `e.p.msg.forbidden` from every one of them, and that is the boundary
//! working rather than a misconfiguration.
//!
//! The rest are context-scoped and take a `context_id`.
//!
//! ## Disclosure is two calls, on purpose
//!
//! [`persona_disclosure_preview`](VtaClient::persona_disclosure_preview) signs
//! nothing and sends nothing; it returns a `previewId` that
//! [`persona_disclosure_present`](VtaClient::persona_disclosure_present)
//! consumes. There is no single-call form, and adding one would remove the
//! only point at which a human can see what is about to be handed over.

use serde_json::Value;

use super::VtaClient;
use crate::error::VtaError;
use crate::protocols::persona::{
    ContactDocument, LocalProfileEntry, PersonaAttributeDeleteBody, PersonaAttributeListBody,
    PersonaAttributePutBody, PersonaBindingGetBody, PersonaBindingListBody, PersonaBindingSetBody,
    PersonaContactDeleteBody, PersonaContactGetBody, PersonaContactListBody, PersonaContactPutBody,
    PersonaCorrelationAnalyzeBody, PersonaDisclosureHistoryBody, PersonaDisclosurePresentBody,
    PersonaDisclosurePreviewBody, PersonaLocalBindingSetBody, PersonaLocalProfileDeleteBody,
    PersonaLocalProfileGetBody, PersonaLocalProfileListBody, PersonaLocalProfilePutBody,
    PersonaProfileDeleteBody, PersonaProfileGetBody, PersonaProfileListBody, PersonaProfilePutBody,
    PersonaRenderersListBody, ProfileEntry, Provenance, ValueType,
};
use crate::trust_tasks;

/// Round-trip timeout (seconds) for persona trust tasks. Matches the
/// application-state and memory slices: these are local store operations, and
/// the two that are not — preview and present — are bounded by the VTA's own
/// credential work rather than by anything a client can wait longer for.
const PERSONA_TT_TIMEOUT: u64 = 30;

/// Serialize a typed body, mapping the (unreachable in practice) failure into
/// a typed SDK error rather than panicking inside a client call.
fn body(value: impl serde::Serialize) -> Result<Value, VtaError> {
    serde_json::to_value(value)
        .map_err(|e| VtaError::Validation(format!("encode persona payload: {e}")))
}

impl VtaClient {
    // -----------------------------------------------------------------------
    // The pool — holder-scoped
    // -----------------------------------------------------------------------

    /// `persona/attribute/put/1.0` — create or update one attribute in the
    /// holder's pool.
    ///
    /// Omit `attribute_id` to create. Supplying one makes a create idempotent;
    /// supplying one that exists is an update, and `expected_version` is the
    /// precondition that keeps two editors from silently overwriting each
    /// other.
    #[allow(clippy::too_many_arguments)]
    pub async fn persona_attribute_put(
        &self,
        claim_type: &str,
        value: Value,
        value_type: ValueType,
        provenance: Provenance,
        label: Option<&str>,
        attribute_id: Option<&str>,
        expected_version: Option<u64>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaAttributePutBody {
            claim_type: claim_type.to_string(),
            value,
            value_type,
            provenance,
            label: label.map(str::to_string),
            attribute_id: attribute_id.map(str::to_string),
            expected_version,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_ATTRIBUTE_PUT_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/attribute/list/1.0` — enumerate the pool.
    ///
    /// Metadata-only unless `include_values` is set. That default is the
    /// difference between "how many phone numbers do I hold" and a read of the
    /// holder's identity, so it is opt-in rather than something a caller has
    /// to remember to narrow.
    pub async fn persona_attribute_list(
        &self,
        type_prefix: Option<&str>,
        include_values: bool,
        include_stale: Option<bool>,
        limit: Option<std::num::NonZeroU64>,
        cursor: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaAttributeListBody {
            type_prefix: type_prefix.map(str::to_string),
            include_values: include_values.then_some(true),
            include_stale,
            limit,
            cursor: cursor.map(str::to_string),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_ATTRIBUTE_LIST_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/attribute/delete/1.0` — remove an attribute.
    ///
    /// Refused while a profile still references it unless `cascade` is set;
    /// the alternative would be profiles quietly presenting a dangling
    /// reference.
    pub async fn persona_attribute_delete(
        &self,
        attribute_id: &str,
        cascade: bool,
        expected_version: Option<u64>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaAttributeDeleteBody {
            attribute_id: attribute_id.to_string(),
            cascade: cascade.then_some(true),
            expected_version,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_ATTRIBUTE_DELETE_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Profiles — holder-scoped
    // -----------------------------------------------------------------------

    /// `persona/profile/put/1.0` — create or update an agent-scoped profile.
    pub async fn persona_profile_put(
        &self,
        name: &str,
        entries: Vec<ProfileEntry>,
        credential_refs: Vec<String>,
        profile_id: Option<&str>,
        expected_version: Option<u64>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaProfilePutBody {
            name: name.to_string(),
            entries,
            credential_refs,
            profile_id: profile_id.map(str::to_string),
            expected_version,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_PROFILE_PUT_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/profile/get/1.0` — read one profile.
    ///
    /// `resolve` returns the values the profile would present rather than the
    /// references it is built from — which is what a holder needs to answer
    /// "what does this actually show", and what a diff against the pool needs
    /// to answer "has it drifted".
    pub async fn persona_profile_get(
        &self,
        profile_id: &str,
        resolve: bool,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaProfileGetBody {
            profile_id: profile_id.to_string(),
            resolve: resolve.then_some(true),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_PROFILE_GET_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/profile/list/1.0` — enumerate agent-scoped profiles.
    pub async fn persona_profile_list(
        &self,
        limit: Option<std::num::NonZeroU64>,
        cursor: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaProfileListBody {
            limit,
            cursor: cursor.map(str::to_string),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_PROFILE_LIST_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/profile/delete/1.0` — remove an agent-scoped profile.
    ///
    /// Refused while a persona still presents under it unless `unbind` is set.
    /// A context losing its identity mid-relationship is not something to do
    /// by omission.
    pub async fn persona_profile_delete(
        &self,
        profile_id: &str,
        unbind: bool,
        expected_version: Option<u64>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaProfileDeleteBody {
            profile_id: profile_id.to_string(),
            unbind: unbind.then_some(true),
            expected_version,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_PROFILE_DELETE_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Bindings — context-scoped
    // -----------------------------------------------------------------------

    /// `persona/binding/set/1.0` — assign a profile to a persona DID in one
    /// context.
    ///
    /// The push across the boundary. The profile is resolved above the context
    /// and a *materialised* projection is written into it — the context
    /// receives values, never pool identifiers, so nothing inside it can walk
    /// back to the holder's other faces. Pass `profile_id: None` to clear.
    pub async fn persona_binding_set(
        &self,
        context_id: &str,
        persona_did: &str,
        profile_id: Option<&str>,
        public_entries: Vec<String>,
        expected_version: Option<u64>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaBindingSetBody {
            context_id: context_id.to_string(),
            persona_did: persona_did.to_string(),
            profile_id: profile_id.map(str::to_string),
            public_entries,
            expected_version,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_BINDING_SET_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/binding/get/1.0` — what one persona DID presents in one
    /// context.
    pub async fn persona_binding_get(
        &self,
        context_id: &str,
        persona_did: &str,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaBindingGetBody {
            context_id: context_id.to_string(),
            persona_did: persona_did.to_string(),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_BINDING_GET_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/binding/list/1.0` — every persona bound in one context.
    pub async fn persona_binding_list(
        &self,
        context_id: &str,
        limit: Option<std::num::NonZeroU64>,
        cursor: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaBindingListBody {
            context_id: context_id.to_string(),
            limit,
            cursor: cursor.map(str::to_string),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_BINDING_LIST_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Contacts — context-scoped
    // -----------------------------------------------------------------------

    /// `persona/contact/put/1.0` — record what a peer disclosed.
    ///
    /// Writes a new revision rather than overwriting: the previous one is
    /// retained while anything still references it, so "what did they tell me
    /// in March" survives them changing their mind in April.
    pub async fn persona_contact_put(
        &self,
        context_id: &str,
        subject_did: &str,
        known_by_persona: &str,
        document: ContactDocument,
        credential_refs: Vec<String>,
        notes: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaContactPutBody {
            context_id: context_id.to_string(),
            subject_did: subject_did.to_string(),
            known_by_persona: known_by_persona.to_string(),
            document,
            credential_refs,
            notes: notes.map(str::to_string),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_CONTACT_PUT_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/contact/get/1.0` — read one contact, optionally at an older
    /// revision or with its full history.
    pub async fn persona_contact_get(
        &self,
        context_id: &str,
        contact_id: &str,
        rev: Option<std::num::NonZeroU64>,
        include_history: bool,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaContactGetBody {
            context_id: context_id.to_string(),
            contact_id: contact_id.to_string(),
            rev,
            include_history: include_history.then_some(true),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_CONTACT_GET_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/contact/list/1.0` — enumerate contacts in one context.
    pub async fn persona_contact_list(
        &self,
        context_id: &str,
        known_by_persona: Option<&str>,
        changed_since: Option<&str>,
        limit: Option<std::num::NonZeroU64>,
        cursor: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaContactListBody {
            context_id: context_id.to_string(),
            known_by_persona: known_by_persona.map(str::to_string),
            changed_since: changed_since.map(str::to_string),
            limit,
            cursor: cursor.map(str::to_string),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_CONTACT_LIST_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/contact/delete/1.0` — forget a contact.
    pub async fn persona_contact_delete(
        &self,
        context_id: &str,
        contact_id: &str,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaContactDeleteBody {
            context_id: context_id.to_string(),
            contact_id: contact_id.to_string(),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_CONTACT_DELETE_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Disclosure — context-scoped, and deliberately two calls
    // -----------------------------------------------------------------------

    /// `persona/disclosure/preview/1.0` — what would this disclosure reveal?
    ///
    /// Signs nothing, sends nothing, and is the **only** way to obtain the
    /// `previewId` that
    /// [`persona_disclosure_present`](Self::persona_disclosure_present)
    /// consumes. The response carries what would be disclosed, what the chosen
    /// renderer would *drop*, how much the disclosure would correlate the
    /// holder, and which claims are unusual for the verifier's stated purpose
    /// — the last so a holder reads the line worth reading rather than
    /// clicking through fourteen equal-weighted fields.
    ///
    /// The preview is single-use and short-lived. One approved an hour ago is
    /// not evidence of approval now.
    pub async fn persona_disclosure_preview(
        &self,
        context_id: &str,
        persona_did: &str,
        verifier_did: &str,
        requested_claims: Vec<String>,
        purpose: Option<&str>,
        renderer: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaDisclosurePreviewBody {
            context_id: context_id.to_string(),
            persona_did: persona_did.to_string(),
            verifier_did: verifier_did.to_string(),
            requested_claims,
            purpose: purpose.map(str::to_string),
            renderer: renderer.map(str::to_string),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_DISCLOSURE_PREVIEW_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/disclosure/present/1.0` — hand over what the preview showed.
    ///
    /// Consumes `preview_id`. A replay is refused rather than riding the
    /// earlier decision, and a claim that went stale between the two calls
    /// refuses the *whole* disclosure rather than quietly presenting a shorter
    /// one than the holder approved.
    pub async fn persona_disclosure_present(
        &self,
        context_id: &str,
        preview_id: &str,
        challenge: Option<&str>,
        mint: Option<Value>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaDisclosurePresentBody {
            context_id: context_id.to_string(),
            preview_id: preview_id.to_string(),
            challenge: challenge.map(str::to_string),
            mint,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_DISCLOSURE_PRESENT_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/disclosure/history/1.0` — what was disclosed, to whom, when.
    ///
    /// Omitting `context_id` reads across every context, which is a
    /// holder-scoped read and gated as one.
    pub async fn persona_disclosure_history(
        &self,
        context_id: Option<&str>,
        verifier_did: Option<&str>,
        attribute_type: Option<&str>,
        since: Option<&str>,
        limit: Option<std::num::NonZeroU64>,
        cursor: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaDisclosureHistoryBody {
            context_id: context_id.map(str::to_string),
            verifier_did: verifier_did.map(str::to_string),
            attribute_type: attribute_type.map(str::to_string),
            since: since.map(str::to_string),
            limit,
            cursor: cursor.map(str::to_string),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_DISCLOSURE_HISTORY_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Correlation and renderers — holder-scoped
    // -----------------------------------------------------------------------

    /// `persona/correlation/analyze/1.0` — how linkable would this make me?
    ///
    /// Pass a `candidate` to ask before disclosing rather than after — the
    /// answer is worth more then. Note the inversion the response encodes: a
    /// credential presented **whole** correlates *more* than a self-asserted
    /// value, because the issuer's signature is byte-identical at every
    /// verifier, while a derived proof correlates *less* because it differs on
    /// every presentation.
    pub async fn persona_correlation_analyze(
        &self,
        attribute_id: Option<&str>,
        profile_id: Option<&str>,
        candidate: Option<Value>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaCorrelationAnalyzeBody {
            attribute_id: attribute_id.map(str::to_string),
            profile_id: profile_id.map(str::to_string),
            candidate,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_CORRELATION_ANALYZE_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/renderers/list/1.0` — the output formats this VTA can produce,
    /// and what each one cannot carry.
    ///
    /// Worth calling before a preview: a renderer that drops provenance turns
    /// "my employer attested this number" into "this number", and a holder is
    /// owed that before choosing, not after.
    pub async fn persona_renderers_list(&self) -> Result<Value, VtaError> {
        let payload = body(PersonaRenderersListBody { ext: None })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_RENDERERS_LIST_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Context-local profiles and bindings
    // -----------------------------------------------------------------------

    /// `persona/local/profile/put/1.0` — a profile that lives inside one
    /// context.
    ///
    /// Entries are [`LocalProfileEntry`] — inline only. A context-local
    /// profile cannot reference, pin or override a pool attribute, because
    /// there is nowhere in the type to name one.
    pub async fn persona_local_profile_put(
        &self,
        context_id: &str,
        name: &str,
        entries: Vec<LocalProfileEntry>,
        profile_id: Option<&str>,
        expected_version: Option<u64>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaLocalProfilePutBody {
            context_id: context_id.to_string(),
            name: name.to_string(),
            entries,
            profile_id: profile_id.map(str::to_string),
            expected_version,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_LOCAL_PROFILE_PUT_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/local/profile/get/1.0` — read one context-local profile.
    pub async fn persona_local_profile_get(
        &self,
        context_id: &str,
        profile_id: &str,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaLocalProfileGetBody {
            context_id: context_id.to_string(),
            profile_id: profile_id.to_string(),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_LOCAL_PROFILE_GET_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/local/profile/list/1.0` — enumerate one context's own
    /// profiles.
    pub async fn persona_local_profile_list(
        &self,
        context_id: &str,
        limit: Option<std::num::NonZeroU64>,
        cursor: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaLocalProfileListBody {
            context_id: context_id.to_string(),
            limit,
            cursor: cursor.map(str::to_string),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_LOCAL_PROFILE_LIST_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/local/profile/delete/1.0` — remove a context-local profile.
    pub async fn persona_local_profile_delete(
        &self,
        context_id: &str,
        profile_id: &str,
        unbind: bool,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaLocalProfileDeleteBody {
            context_id: context_id.to_string(),
            profile_id: profile_id.to_string(),
            unbind: unbind.then_some(true),
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_LOCAL_PROFILE_DELETE_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }

    /// `persona/local/binding/set/1.0` — bind a persona DID to a
    /// context-local profile.
    ///
    /// The counterpart to [`persona_binding_set`](Self::persona_binding_set)
    /// for an identity that never existed above the context. There is no pool
    /// read on this path at all.
    pub async fn persona_local_binding_set(
        &self,
        context_id: &str,
        persona_did: &str,
        profile_id: Option<&str>,
        expected_version: Option<u64>,
    ) -> Result<Value, VtaError> {
        let payload = body(PersonaLocalBindingSetBody {
            context_id: context_id.to_string(),
            persona_did: persona_did.to_string(),
            profile_id: profile_id.map(str::to_string),
            expected_version,
            ext: None,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_PERSONA_LOCAL_BINDING_SET_1_0,
            payload,
            PERSONA_TT_TIMEOUT,
        )
        .await
    }
}
