//! Operator-facing strings supplied by the consumer.
//!
//! The provision-client library never hardcodes integration nouns
//! ("mediator", "WebVH server") or full PNM commands in its own output.
//! Each consumer implements [`OperatorMessages`] and passes an
//! `Arc<dyn OperatorMessages>` into [`super::run_provision`] and friends;
//! the runners and the headless [`super::driver`] read all user-facing
//! strings off it.
//!
//! [`MediatorMessages`] and [`WebvhServerMessages`] are shipped as default
//! implementations for the two integration kinds with built-in support in
//! the SDK ([`super::ask::ProvisionAsk::didcomm_mediator`] and
//! [`super::ask::ProvisionAsk::webvh_server`]). Other integration kinds
//! ship their own impls.

/// User-visible labels and command suggestions for a single integration
/// kind. Trait so consumers can extend with new integration kinds without
/// modifying the SDK.
pub trait OperatorMessages: Send + Sync {
    /// Human-readable noun used in prose ("the {Mediator}", "the {WebVH
    /// service}"). Capitalised.
    fn integration_label(&self) -> &str;

    /// Lower-case form for inline references ("connecting to the
    /// {mediator}").
    fn integration_label_lower(&self) -> &str;

    /// PNM command the operator should run to grant the setup DID admin
    /// access to the integration's context. Returned without leading
    /// indentation; the consumer's renderer adds it.
    ///
    /// `context_id` is the VTA context the integration will live in
    /// (becomes the ACL scope). `setup_did` is the ephemeral `did:key`
    /// minted by [`super::EphemeralSetupKey::generate`].
    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String;

    /// Optional one-line message to display on the success screen of a
    /// TUI consumer. Defaults to `None` — most consumers render their
    /// own.
    fn success_screen_message(&self) -> Option<&str> {
        None
    }
}

/// Default messages for [`super::ask::ProvisionAsk::didcomm_mediator`].
pub struct MediatorMessages;

impl OperatorMessages for MediatorMessages {
    fn integration_label(&self) -> &str {
        "Mediator"
    }

    fn integration_label_lower(&self) -> &str {
        "mediator"
    }

    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm contexts create --id {context_id} --name \"Mediator\" \\\n  \
             --admin-did {setup_did} --admin-expires 1h --admin-handoff"
        )
    }
}

/// Default messages for [`super::ask::ProvisionAsk::webvh_server`].
pub struct WebvhServerMessages;

impl OperatorMessages for WebvhServerMessages {
    fn integration_label(&self) -> &str {
        "WebVH server"
    }

    fn integration_label_lower(&self) -> &str {
        "webvh server"
    }

    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm contexts create --id {context_id} --name \"WebVH server\" \\\n  \
             --admin-did {setup_did} --admin-expires 1h --admin-handoff"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mediator_pnm_command_matches_donor_layout() {
        // Snapshot of the form the donor `mediator-setup` cli currently
        // prints: `pnm contexts create --id <ctx> --name "Mediator" \
        //   --admin-did <did> --admin-expires 1h --admin-handoff`.
        // Matching this verbatim keeps mediator-setup's external
        // appearance unchanged after migration.
        assert_eq!(
            MediatorMessages.pnm_admin_command_hint("prod-mediator", "did:key:z6MkExample"),
            "pnm contexts create --id prod-mediator --name \"Mediator\" \\\n  --admin-did did:key:z6MkExample --admin-expires 1h --admin-handoff",
        );
    }

    #[test]
    fn webvh_server_pnm_command_uses_webvh_label() {
        let cmd = WebvhServerMessages.pnm_admin_command_hint("prod-webvh", "did:key:z6MkExample");
        assert!(cmd.contains("--name \"WebVH server\""));
        assert!(cmd.contains("--admin-did did:key:z6MkExample"));
        assert!(cmd.contains("--id prod-webvh"));
    }

    #[test]
    fn integration_labels_are_distinct() {
        assert_ne!(
            MediatorMessages.integration_label(),
            WebvhServerMessages.integration_label()
        );
        assert_ne!(
            MediatorMessages.integration_label_lower(),
            WebvhServerMessages.integration_label_lower()
        );
    }

    #[test]
    fn defaults_have_no_success_message() {
        assert!(MediatorMessages.success_screen_message().is_none());
        assert!(WebvhServerMessages.success_screen_message().is_none());
    }

    #[test]
    fn trait_object_is_send_sync() {
        // Compile-time guard: run_provision will take `Arc<dyn OperatorMessages>`,
        // which requires `Send + Sync`. Add a new impl that violates this and
        // this test fails to compile.
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn OperatorMessages>();
    }
}
