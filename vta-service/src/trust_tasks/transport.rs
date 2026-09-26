//! What the transport that carried a Trust Task guarantees about
//! confidentiality — and how a handler asks.
//!
//! One dispatcher serves the Trust-Task surface over REST, DIDComm and TSP.
//! That is the point of the spine, but it means a handler cannot tell how a
//! request reached it, and a few tasks genuinely need to know: `keys/import`
//! admits a **cleartext** private-key carrier, and its specification permits
//! that "only where the transport is end-to-end confidential". Without this,
//! the handler's only safe reading was to refuse cleartext on every transport
//! — over-refusing on exactly the transports where it is safe.
//!
//! # Why a task-local rather than a handler parameter
//!
//! The dispatch table has 157 entries sharing one handler signature. Threading
//! a parameter through all of them to serve one handler would be a large,
//! noisy change whose diff obscures the one call site that matters. This is set
//! in exactly one place ([`crate::trust_tasks::dispatch_trust_task_core`]) and
//! read in exactly one ([`crate::trust_tasks::keys::handle_import`]).
//!
//! # The default is the restrictive one, deliberately
//!
//! [`current`] returns [`TransportConfidentiality::HopByHop`] when nothing has
//! been set. A future entry point that dispatches without establishing the
//! scope therefore **refuses** cleartext rather than accepting it: a wiring
//! mistake costs a working import, not a leaked key.

/// Whether the transport established confidentiality end-to-end between the
/// producer and this consumer, or only hop-by-hop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportConfidentiality {
    /// The producer encrypted to *this* consumer, so no intermediary — and no
    /// terminating proxy — ever held the plaintext. DIDComm authcrypt and TSP
    /// both provide this.
    EndToEnd,
    /// Confidential in transit at best. TLS qualifies, but it terminates
    /// wherever the operator terminates it: a load balancer, an ingress, a
    /// sidecar. The plaintext exists there, so a secret-bearing member must not
    /// travel this way.
    HopByHop,
}

tokio::task_local! {
    static CONFIDENTIALITY: TransportConfidentiality;
}

/// Run `f` with the transport's confidentiality recorded for its duration.
pub(crate) async fn with_confidentiality<F, T>(level: TransportConfidentiality, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    CONFIDENTIALITY.scope(level, f).await
}

/// What the transport carrying the current Trust Task guarantees.
///
/// Falls back to [`TransportConfidentiality::HopByHop`] outside a dispatch
/// scope — see the module docs on why the default is the restrictive one.
pub(crate) fn current() -> TransportConfidentiality {
    CONFIDENTIALITY
        .try_with(|c| *c)
        .unwrap_or(TransportConfidentiality::HopByHop)
}

// Which binding carried the current Trust Task — `https`, `didcomm` or `tsp`.
//
// Separate from [`TransportConfidentiality`] because the two answer different
// questions: DIDComm and TSP are both end-to-end, and an audit row recording a
// key export has to say which of them the key left over, not only how well it
// was protected on the way. Set by the three entry points that hand a document
// to the spine; read by the handlers whose audit rows name the transport.
tokio::task_local! {
    static BINDING: &'static str;
}

/// Run `f` with the carrying binding recorded for its duration.
pub(crate) async fn with_binding<F, T>(binding: &'static str, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    BINDING.scope(binding, f).await
}

/// The audit `channel` for a Trust Task handler: `trust-task/<binding>` when an
/// entry point recorded the binding, and the bare surface name otherwise.
///
/// The bare fallback is deliberate rather than a guess: a dispatch path that
/// forgot to record its binding writes a row that says less, not one that
/// names the wrong transport.
pub(crate) fn audit_channel() -> &'static str {
    match BINDING.try_with(|b| *b) {
        Ok("https") => "trust-task/https",
        Ok("didcomm") => "trust-task/didcomm",
        Ok("tsp") => "trust-task/tsp",
        _ => super::helpers::TRANSPORT_TRUST_TASK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole safety argument rests on this: an unset scope must read as
    /// hop-by-hop, so a dispatch path someone forgets to wire refuses a
    /// cleartext key instead of forwarding one.
    #[test]
    fn defaults_to_hop_by_hop_outside_a_scope() {
        assert_eq!(current(), TransportConfidentiality::HopByHop);
    }

    #[tokio::test]
    async fn reports_what_the_scope_set() {
        let seen =
            with_confidentiality(TransportConfidentiality::EndToEnd, async { current() }).await;
        assert_eq!(seen, TransportConfidentiality::EndToEnd);
        // And the scope does not leak past its future.
        assert_eq!(current(), TransportConfidentiality::HopByHop);
    }

    #[tokio::test]
    async fn audit_channel_names_the_binding_only_inside_a_scope() {
        assert_eq!(audit_channel(), "trust-task");
        for (binding, channel) in [
            ("https", "trust-task/https"),
            ("didcomm", "trust-task/didcomm"),
            ("tsp", "trust-task/tsp"),
        ] {
            assert_eq!(
                with_binding(binding, async { audit_channel() }).await,
                channel
            );
        }
    }
}
