//! Non-interactive driver for the online provisioning flow.
//!
//! Two scriptable phases for orchestrated deploys (no TUI involved):
//!
//! - **Phase 1** ([`run_phase1_init`]): generate an ephemeral `did:key`,
//!   persist it under owner-only permissions, and emit the `pnm`
//!   command the operator (or automation) needs to register the ACL on
//!   the VTA between phases.
//! - **Phase 2** ([`run_phase2_connect`]): reload the persisted key,
//!   drive the diagnostic + auth runner, stream checklist lines, return
//!   on success or with a structured [`HeadlessVtaError`] on failure.
//!
//! All output writes to a caller-supplied `&mut dyn Write`. The driver
//! never touches stdout/stderr directly — the consuming binary chooses
//! where the lines go (stdout, a buffer, a tracing sink, …). This keeps
//! the SDK TUI- *and* CLI-agnostic.
//!
//! Multi-attempt fallback logic (auto-switch between DIDComm/REST,
//! retry-on-ACL-wait, etc.) is intentionally **not** included here;
//! consumers wrap their own retry loop around [`run_phase2_connect`] if
//! they need it.

use std::fmt;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use super::diagnostics::{DiagCheck, DiagStatus, Protocol};
use super::error::ProvisionError;
use super::event::{AttemptResultKind, VtaEvent};
use super::intent::VtaIntent;
use super::messages::OperatorMessages;
use super::setup_key::EphemeralSetupKey;
use super::{ProvisionAsk, run_provision};

/// Categorises a headless terminal failure. The CLI driver returns this
/// in the `Err` variant of [`HeadlessVtaError`] so the calling binary
/// can pick a fixed exit code without re-parsing the error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadlessFailureKind {
    /// VTA advertises no usable transport (no `#tsp`, no DIDComm mediator,
    /// no REST endpoint), OR every advertised transport's auth attempt
    /// failed pre-auth.
    NoTransport,
    /// VTA accepted the auth handshake but rejected the request body
    /// afterwards (template render error, validation, etc.). A
    /// different wire would reproduce the rejection.
    PostAuthFailed,
}

/// Structured terminal-failure shape for the headless flow.
///
/// `Display` is stable and grep-friendly for CI logs.
#[derive(Debug)]
pub struct HeadlessVtaError {
    /// Failure reported by the TSP leg, if it ran. Populated when the VTA
    /// advertises a `#tsp` service — including the "built without the
    /// `tsp` feature" case, which is a TSP-leg pre-auth failure.
    pub tsp: Option<String>,
    pub didcomm: Option<String>,
    pub rest: Option<String>,
    pub kind: HeadlessFailureKind,
}

impl fmt::Display for HeadlessVtaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Headless VTA setup failed.")?;
        if let Some(reason) = &self.tsp {
            writeln!(f, "  TSP: {reason}")?;
        }
        if let Some(reason) = &self.didcomm {
            writeln!(f, "  DIDComm: {reason}")?;
        }
        if let Some(reason) = &self.rest {
            writeln!(f, "  REST: {reason}")?;
        }
        if self.tsp.is_none() && self.didcomm.is_none() && self.rest.is_none() {
            writeln!(f, "  No transport advertised by the VTA's DID document.")?;
        }
        writeln!(f)?;
        match self.kind {
            HeadlessFailureKind::NoTransport => {
                writeln!(
                    f,
                    "Switch to the offline sealed-handoff flow: bundle a request \
                     file for the VTA admin via the `vta bootstrap provision-request` \
                     CLI."
                )?;
            }
            HeadlessFailureKind::PostAuthFailed => {
                writeln!(
                    f,
                    "VTA accepted the auth handshake then rejected the request body. \
                     Inspect the VTA-side error above and either correct the request \
                     or switch to the offline sealed-handoff flow."
                )?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for HeadlessVtaError {}

/// Phase 1: generate + persist ephemeral key, write the ACL command to
/// `writer`. The caller (or automation) registers the ACL on the VTA
/// between phases, then re-runs phase 2 with the persisted key path.
pub async fn run_phase1_init(
    writer: &mut dyn Write,
    out_path: &Path,
    context_id: &str,
    messages: &dyn OperatorMessages,
    finalise_command: Option<&str>,
) -> Result<(), ProvisionError> {
    let key = EphemeralSetupKey::generate()?;
    key.persist_to(out_path)?;

    let label_lower = messages.integration_label_lower();
    let label = messages.integration_label();

    writeln!(writer)?;
    writeln!(writer, "  Setup DID (ephemeral):")?;
    writeln!(writer, "    {}", key.did)?;
    writeln!(writer)?;
    writeln!(writer, "  Key stored at {} (0600)", out_path.display())?;
    writeln!(writer)?;
    writeln!(
        writer,
        "  Using your Personal Network Manager (PNM) connected to this VTA,"
    )?;
    writeln!(
        writer,
        "  create the {label_lower} context and grant admin access to the setup DID:"
    )?;
    writeln!(writer)?;
    writeln!(
        writer,
        "    {}",
        messages.pnm_admin_command_hint(context_id, &key.did)
    )?;
    writeln!(writer)?;
    writeln!(
        writer,
        "  --name is a human-readable label — change \"{label}\" to anything"
    )?;
    writeln!(writer, "  that fits your naming conventions.")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "  --admin-expires defaults to 1h. Use 24h, 7d, etc. for longer"
    )?;
    writeln!(
        writer,
        "  roll-outs; the entry is promoted to permanent on first auth."
    )?;
    writeln!(writer)?;
    if let Some(cmd) = finalise_command {
        writeln!(writer, "  Then finalise with:")?;
        writeln!(writer, "    {cmd}")?;
        writeln!(writer)?;
    }
    Ok(())
}

/// Phase 2: reload key + run [`run_provision`] + stream diagnostics.
/// Returns `Ok(())` on a successful round-trip; on failure returns a
/// structured [`HeadlessVtaError`] the caller maps to an exit code.
///
/// `intent` chooses between AdminOnly and FullSetup. For FullSetup the
/// `ask` carries the integration template + vars (use one of the
/// curated [`ProvisionAsk`] builders).
#[allow(clippy::too_many_arguments)]
pub async fn run_phase2_connect(
    writer: &mut dyn Write,
    key_path: &Path,
    intent: VtaIntent,
    vta_did: &str,
    ask: ProvisionAsk,
    messages: Arc<dyn OperatorMessages>,
    force_transport: Option<Protocol>,
) -> Result<(), HeadlessVtaError> {
    let key = EphemeralSetupKey::load_from(key_path).map_err(|e| HeadlessVtaError {
        tsp: None,
        didcomm: Some(format!("could not load setup key: {e}")),
        rest: None,
        kind: HeadlessFailureKind::NoTransport,
    })?;

    let _ = writeln!(writer);
    let _ = writeln!(writer, "  VTA DID:    {vta_did}");
    let _ = writeln!(writer, "  Context:    {}", ask.context);
    let _ = writeln!(writer, "  Setup DID:  {}", key.did);
    let _ = writeln!(writer);

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<VtaEvent>();
    let vta_did_owned = vta_did.to_string();
    let setup_did = key.did.clone();
    let privkey_mb = key.private_key_multibase().to_string();
    let messages_clone = messages.clone();
    let ask_clone = ask.clone();

    let runner = tokio::spawn(async move {
        run_provision(
            intent,
            vta_did_owned,
            setup_did,
            privkey_mb,
            ask_clone,
            force_transport,
            messages_clone,
            tx,
        )
        .await
    });

    let mut connected = false;
    let mut last_failure: Option<String> = None;
    let mut tsp_failure: Option<String> = None;
    let mut didcomm_failure: Option<String> = None;
    let mut rest_failure: Option<String> = None;
    let mut last_attempt: Option<(Protocol, AttemptResultKind)> = None;

    while let Some(event) = rx.recv().await {
        match event {
            VtaEvent::CheckStart(c) => {
                let _ = writeln!(writer, "  [..] {}", c.label());
            }
            VtaEvent::CheckDone(c, status) => {
                let _ = writeln!(writer, "  {}", format_check_line(c, &status));
            }
            VtaEvent::Connected { protocol, .. } => {
                connected = true;
                let _ = writeln!(writer);
                let _ = writeln!(writer, "  Connected via {}", protocol.label());
            }
            VtaEvent::PreflightDone { servers, .. } => {
                let _ = writeln!(
                    writer,
                    "  Preflight complete — webvh servers advertised: {}",
                    servers.len()
                );
            }
            VtaEvent::Resolved(_) => {}
            VtaEvent::AttemptCompleted { protocol, outcome } => {
                if let AttemptResultKind::PreAuthFailure(reason)
                | AttemptResultKind::PostAuthFailure(reason) = &outcome
                {
                    match protocol {
                        Protocol::Tsp => tsp_failure = Some(reason.clone()),
                        Protocol::DidComm => didcomm_failure = Some(reason.clone()),
                        Protocol::Rest => rest_failure = Some(reason.clone()),
                    }
                }
                last_attempt = Some((protocol, outcome));
            }
            VtaEvent::Failed(reason) => {
                last_failure = Some(reason);
            }
        }
    }
    let _ = runner.await;

    if connected {
        return Ok(());
    }

    let kind = match &last_attempt {
        Some((_, AttemptResultKind::PostAuthFailure(_))) => HeadlessFailureKind::PostAuthFailed,
        _ => HeadlessFailureKind::NoTransport,
    };

    if tsp_failure.is_none()
        && didcomm_failure.is_none()
        && rest_failure.is_none()
        && let Some(reason) = last_failure
    {
        return Err(HeadlessVtaError {
            tsp: None,
            didcomm: Some(reason),
            rest: None,
            kind,
        });
    }

    Err(HeadlessVtaError {
        tsp: tsp_failure,
        didcomm: didcomm_failure,
        rest: rest_failure,
        kind,
    })
}

fn format_check_line(c: DiagCheck, status: &DiagStatus) -> String {
    match status {
        DiagStatus::Pending => format!("[  ] {}", c.label()),
        DiagStatus::Running => format!("[..] {}", c.label()),
        DiagStatus::Ok(d) => format!("[OK] {}  {d}", c.label()),
        DiagStatus::Skipped(d) => format!("[--] {}  {d}", c.label()),
        DiagStatus::Failed(d) => format!("[!!] {}  {d}", c.label()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision_client::messages::MediatorMessages;

    #[test]
    fn headless_error_display_names_every_protocol() {
        let err = HeadlessVtaError {
            tsp: Some("TSP mediator unreachable".into()),
            didcomm: Some("ACL not found".into()),
            rest: Some("REST 401".into()),
            kind: HeadlessFailureKind::NoTransport,
        };
        let s = err.to_string();
        assert!(s.contains("TSP: TSP mediator unreachable"));
        assert!(s.contains("DIDComm: ACL not found"));
        assert!(s.contains("REST: REST 401"));
        assert!(s.contains("sealed-handoff"));
    }

    /// A TSP-only VTA whose TSP leg failed reports the TSP reason — not the
    /// "no transport advertised" line, which is reserved for a document that
    /// really advertised nothing (#869).
    #[test]
    fn headless_error_with_only_a_tsp_failure_does_not_claim_nothing_was_advertised() {
        let s = HeadlessVtaError {
            tsp: Some("built without the `tsp` feature".into()),
            didcomm: None,
            rest: None,
            kind: HeadlessFailureKind::NoTransport,
        }
        .to_string();
        assert!(s.contains("TSP: built without the `tsp` feature"));
        assert!(!s.contains("No transport advertised"));
    }

    #[test]
    fn headless_error_display_no_transport_message_differs_from_post_auth() {
        let no_transport = HeadlessVtaError {
            tsp: None,
            didcomm: Some("network".into()),
            rest: None,
            kind: HeadlessFailureKind::NoTransport,
        }
        .to_string();
        let post_auth = HeadlessVtaError {
            tsp: None,
            didcomm: Some("template error".into()),
            rest: None,
            kind: HeadlessFailureKind::PostAuthFailed,
        }
        .to_string();
        assert_ne!(no_transport, post_auth);
        assert!(post_auth.contains("rejected the request body"));
    }

    #[test]
    fn format_check_line_uses_expected_tags() {
        let ok = format_check_line(
            DiagCheck::ResolveDid,
            &DiagStatus::Ok("did:webvh:...".into()),
        );
        assert!(ok.contains("[OK]"));
        assert!(ok.contains("Resolve VTA DID"));

        let failed = format_check_line(
            DiagCheck::AuthenticateDIDComm,
            &DiagStatus::Failed("boom".into()),
        );
        assert!(failed.contains("[!!]"));
    }

    #[tokio::test]
    async fn phase1_writes_a_valid_key_file_and_prints_pnm_command() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let mut out: Vec<u8> = Vec::new();
        run_phase1_init(
            &mut out,
            &path,
            "mediator-context",
            &MediatorMessages,
            Some("my-setup --setup-key-file /tmp/key.json"),
        )
        .await
        .unwrap();
        let reloaded = EphemeralSetupKey::load_from(&path).unwrap();
        assert!(reloaded.did.starts_with("did:key:z6Mk"));

        let s = String::from_utf8(out).unwrap();
        // Operator-facing message uses the consumer's label, not "mediator"
        // hardcoded in the SDK.
        assert!(s.contains("Mediator")); // from MediatorMessages
        assert!(s.contains("pnm contexts create"));
        assert!(s.contains("--id mediator-context"));
        assert!(s.contains(&reloaded.did));
        assert!(s.contains("my-setup --setup-key-file"));
    }

    #[tokio::test]
    async fn phase1_uses_writer_not_stdout() {
        // Compile-time guard: run_phase1_init takes a `&mut dyn Write`.
        // The test exercises that path with a Vec<u8> to confirm the
        // SDK never reaches for stdout.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut buf: Vec<u8> = Vec::new();
        run_phase1_init(&mut buf, tmp.path(), "ctx", &MediatorMessages, None)
            .await
            .unwrap();
        assert!(!buf.is_empty(), "writer should have received output");
    }
}
