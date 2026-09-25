//! The control master: holds one authenticated session and serves commands.
//!
//! Started either explicitly (`pnm sidecar serve`) or, far more often, spawned
//! in the background by the first invocation that wanted a master and did not
//! find one — the same way nobody ever types `ssh -M`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::net::UnixListener;
use vta_sdk::client::VtaClient;

use super::proto::{Control, Envelope, PROTOCOL, Response};
use super::{ControlPersist, fdpass, peer_uid, vet_socket_path};
use crate::cli::Cli;

/// Run until idle-timeout or `sidecar stop`.
///
/// `client` is already authenticated; holding it here for the master's lifetime
/// is the entire point — the DIDComm session, the mediator WebSocket and the
/// shared DID-resolver cache all live inside it.
pub(crate) async fn serve(
    client: &VtaClient,
    keyring_key: &str,
    url_override: Option<&str>,
    mediator_did_hint: Option<&str>,
    slug: &str,
    path: &Path,
    persist: ControlPersist,
) -> Result<(), Box<dyn std::error::Error>> {
    vet_socket_path(path)?;
    let listener = claim_socket(path)?;

    let idle = persist.0.unwrap_or(Duration::ZERO);
    eprintln!(
        "pnm: control master for `{slug}` on {} (persist {persist}, pid {})",
        path.display(),
        std::process::id()
    );

    let started = Instant::now();
    let mut last_client = Instant::now();

    loop {
        let timeout = remaining(idle, last_client);
        let accepted = tokio::select! {
            res = listener.accept() => res,
            () = sleep_or_forever(timeout) => {
                eprintln!("pnm: control master idle for {persist}, exiting");
                break;
            }
        };

        let (stream, _) = match accepted {
            Ok(v) => v,
            Err(e) => {
                eprintln!("pnm: accept failed: {e}");
                continue;
            }
        };

        // Blocking std socket for the duration of one exchange: the message is
        // small, the client sends it immediately, and SCM_RIGHTS needs recvmsg.
        let stream = stream.into_std()?;
        stream.set_nonblocking(false)?;

        last_client = Instant::now();
        match handle(
            &stream,
            client,
            keyring_key,
            url_override,
            mediator_did_hint,
            slug,
            persist,
            started,
        )
        .await
        {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => eprintln!("pnm: control client error: {e}"),
        }
    }

    let _ = std::fs::remove_file(path);
    Ok(())
}

/// Bind a private temp path, then `link()` it into place.
///
/// Copied from OpenSSH's `muxserver()` (`mux.c`), which binds
/// `<path>.<random>` and hard-links it onto the real path precisely so two
/// processes racing to become master cannot clobber each other: `link` fails
/// `EEXIST` for the loser instead of replacing a live socket. The obvious
/// unlink-then-bind is what ssh deliberately does *not* do — it would remove a
/// working master's socket out from under it, leaving that master alive but
/// unreachable while every later client silently started another one.
///
/// Permissions come from a `0177` umask around the bind, as in ssh, so the
/// socket is never even momentarily group- or world-reachable.
fn claim_socket(path: &Path) -> std::io::Result<UnixListener> {
    let tmp = path.with_file_name(format!(
        "{}.{}.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("pnm"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&tmp);

    // SAFETY: umask is process-global; it is restored immediately after bind.
    let old_umask = unsafe { libc::umask(0o177) };
    let bound = UnixListener::bind(&tmp);
    // SAFETY: restoring the value umask() just returned.
    unsafe { libc::umask(old_umask) };
    let listener = bound?;

    match std::fs::hard_link(&tmp, path) {
        Ok(()) => {
            let _ = std::fs::remove_file(&tmp);
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            Ok(listener)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&tmp);
            Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "another control master already owns this path",
            ))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn remaining(idle: Duration, last: Instant) -> Option<Duration> {
    if idle.is_zero() {
        // ControlPersist no: still serve, but never outlive the first client's
        // window — handled by the caller exiting after it is done.
        return Some(Duration::ZERO);
    }
    if idle == Duration::MAX {
        return None;
    }
    Some(idle.saturating_sub(last.elapsed()))
}

async fn sleep_or_forever(d: Option<Duration>) {
    match d {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending().await,
    }
}

/// Handle one connection. Returns `true` when the master should exit.
#[allow(clippy::too_many_arguments)]
async fn handle(
    stream: &StdUnixStream,
    client: &VtaClient,
    keyring_key: &str,
    url_override: Option<&str>,
    mediator_did_hint: Option<&str>,
    slug: &str,
    persist: ControlPersist,
    started: Instant,
) -> Result<bool, Box<dyn std::error::Error>> {
    // The socket mode is 0600, but permissions are not the whole story on every
    // platform (abstract sockets, bind-mounts, a path inherited from a wider
    // directory). Check who is actually on the far end.
    let peer = peer_uid(stream)?;
    if peer != super::current_uid() {
        reply(
            stream,
            &Response::Refused {
                reason: format!("peer uid {peer} is not the owner"),
            },
        )?;
        return Ok(false);
    }

    let mut buf = vec![0u8; 64 * 1024];
    let (n, fds) = fdpass::recv_with_fds(stream, &mut buf)?;
    if n == 0 {
        return Ok(false);
    }
    let line = std::str::from_utf8(&buf[..n])?.trim();

    match serde_json::from_str::<Envelope>(line)? {
        Envelope::Control(Control::Check) => {
            reply(
                stream,
                &Response::Status {
                    pid: std::process::id(),
                    slug: slug.to_string(),
                    persist: persist.to_string(),
                    idle_secs: started.elapsed().as_secs(),
                },
            )?;
            Ok(false)
        }
        Envelope::Control(Control::Exit) => {
            reply(stream, &Response::Exiting)?;
            Ok(true)
        }
        Envelope::Command(req) => {
            if req.protocol != PROTOCOL {
                reply(
                    stream,
                    &Response::Refused {
                        reason: format!("protocol {} != master {PROTOCOL}", req.protocol),
                    },
                )?;
                return Ok(false);
            }
            if fds.len() != fdpass::FD_COUNT {
                reply(
                    stream,
                    &Response::Refused {
                        reason: "missing stdio descriptors".into(),
                    },
                )?;
                return Ok(false);
            }

            let parsed =
                match Cli::try_parse_from(std::iter::once("pnm".to_string()).chain(req.args)) {
                    Ok(c) => c,
                    Err(e) => {
                        reply(
                            stream,
                            &Response::Refused {
                                reason: e
                                    .to_string()
                                    .lines()
                                    .next()
                                    .unwrap_or("bad arguments")
                                    .into(),
                            },
                        )?;
                        return Ok(false);
                    }
                };

            // Run with the caller's stdio installed, so output reaches their
            // terminal with tty detection and colours intact.
            let elapsed;
            let code;
            {
                let _stdio = fdpass::StdioSwap::install(&fds)?;
                let t0 = Instant::now();
                // Box::pin breaks the dispatch -> serve -> dispatch async cycle.
                let result = Box::pin(crate::dispatch(
                    client,
                    keyring_key,
                    url_override,
                    mediator_did_hint,
                    parsed.command,
                ))
                .await;
                elapsed = t0.elapsed();
                code = match result {
                    Ok(()) => 0,
                    Err(e) => {
                        vta_cli_common::render::print_cli_error(e.as_ref());
                        1
                    }
                };
                let _ = std::io::stdout().flush();
                let _ = std::io::stderr().flush();
            }

            reply(
                stream,
                &Response::Done {
                    code,
                    elapsed_ms: elapsed.as_millis() as u64,
                },
            )?;
            Ok(false)
        }
    }
}

fn reply(stream: &StdUnixStream, resp: &Response) -> std::io::Result<()> {
    let mut s = stream.try_clone()?;
    writeln!(s, "{}", serde_json::to_string(resp)?)?;
    s.flush()
}

/// Read one response line from a master.
pub(crate) fn read_response(stream: &StdUnixStream) -> std::io::Result<Response> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    serde_json::from_str(line.trim()).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `claim_socket` binds a tokio listener, which needs a reactor.
    fn in_runtime<T>(f: impl FnOnce() -> T) -> T {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        f()
    }

    /// The race OpenSSH's temp-path + `link()` exists to prevent: a second
    /// master must lose, and — critically — must not have destroyed the first
    /// one's socket on its way out.
    #[test]
    fn a_second_master_loses_the_race_without_clobbering_the_first() {
        let dir = std::env::temp_dir().join(format!("pnm-claim-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ctl.sock");
        let _ = std::fs::remove_file(&path);

        let (first, second) = in_runtime(|| {
            let first = claim_socket(&path).expect("first master should win");
            let second = claim_socket(&path);
            (first, second)
        });
        assert!(
            matches!(&second, Err(e) if e.kind() == std::io::ErrorKind::AddrInUse),
            "second master must lose, got {second:?}"
        );

        // The winner is still reachable — an unlink-then-bind implementation
        // would have left the first master alive but orphaned here.
        assert!(
            std::os::unix::net::UnixStream::connect(&path).is_ok(),
            "first master's socket must survive the losing attempt"
        );

        // And no temp files were left lying around.
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "ctl.sock")
            .collect();
        assert!(strays.is_empty(), "left temp sockets behind: {strays:?}");

        drop(first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_socket_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pnm-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ctl.sock");
        let _ = std::fs::remove_file(&path);

        let listener = in_runtime(|| claim_socket(&path).unwrap());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "control socket must be owner-only, got {mode:o}"
        );

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
