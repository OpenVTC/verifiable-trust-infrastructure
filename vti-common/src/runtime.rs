//! Process plumbing every VTI service shares.

/// Resolve when the process is asked to stop: Ctrl-C (SIGINT) or, on Unix,
/// SIGTERM — what a service passes to its server's graceful shutdown.
///
/// One copy for every service (#2572). A signal handler that cannot be
/// installed is logged and that signal is not watched; the other still is.
/// It never panics and never resolves on its own, either of which would stop a
/// running service for a reason that is not a request to stop.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "cannot watch Ctrl-C; only SIGTERM stops this process");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot watch SIGTERM; only Ctrl-C stops this process");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received SIGINT"),
        () = terminate => tracing::info!("received SIGTERM"),
    }
}
