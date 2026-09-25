//! Client side of the control socket: try a master, else fall back.
//!
//! The contract that makes this safe to leave on by default is ssh's: a master
//! that is absent, stale, wrong-version or unhealthy is **not** an error. Every
//! such path returns [`Attempt::Fallback`] and the caller runs the ordinary
//! one-shot command, so the worst case is exactly today's behaviour.
//!
//! # Where this deliberately differs from OpenSSH
//!
//! - **Spawning.** ssh has the first client *become* the master in-process and,
//!   under `ControlPersist`, `fork()` so the child keeps the connection while
//!   the parent reconnects to it as an ordinary mux client (`ssh.c`,
//!   `control_persist_detach`). We spawn a separate `pnm sidecar serve` child
//!   instead: this process already runs a multi-threaded tokio runtime, and
//!   forking a thread-bearing process is not a foundation for a privilege
//!   boundary. The observable result is the same — the first command's work is
//!   done by the master and reaches the caller over the socket.
//! - **Confirmation.** ssh asks in the *master*, per attaching session, through
//!   `ssh-askpass`, which silently denies on a headless box with no `DISPLAY`.
//!   We ask in the client, on its terminal, once per master. For a CLI that is
//!   both usable headless and still an explicit operator decision; the
//!   authorisation itself rests on the peer-uid check, not on the prompt.
//! - **Path vetting.** ssh performs none — no `lstat`, no `O_NOFOLLOW`, no
//!   directory-mode check — and leans entirely on `~/.ssh` being sane. We
//!   refuse a symlinked or foreign-owned control path and force the containing
//!   directory to `0700`, because this socket fronts an admin key.
//! - **Peer check.** ssh exempts `euid 0` (`channels.c`); we do not.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::master::read_response;
use super::proto::{Control, Envelope, PROTOCOL, Request, Response};
use super::{ControlConfig, ControlMaster, vet_socket_path};

/// What happened when we tried to use a master.
pub(crate) enum Attempt {
    /// The master ran it; exit with this code.
    Ran(i32),
    /// No usable master. Run the command directly.
    Fallback(String),
}

/// Try to run `args` on the master at `cfg.path`, spawning one if allowed.
pub(crate) fn try_delegate(cfg: &ControlConfig, args: &[String]) -> Attempt {
    if !cfg.mode.enabled() {
        return Attempt::Fallback("control master disabled".into());
    }
    if let Err(e) = vet_socket_path(&cfg.path) {
        // A refused path is a security signal, not a transient miss: say so
        // rather than silently running direct.
        eprintln!("pnm: refusing control path {}: {e}", cfg.path.display());
        return Attempt::Fallback("unsafe control path".into());
    }

    match send(&cfg.path, args) {
        Ok(a) => return a,
        Err(e) => {
            // OpenSSH's `muxclient()` distinguishes these precisely, and so do
            // we: ECONNREFUSED means the file is there but nobody is listening
            // — a crashed master — so the *client* removes it, and only when
            // multiplexing is enabled. ENOENT is the ordinary cold start.
            // Anything else is reported but still falls back.
            match e.kind() {
                std::io::ErrorKind::ConnectionRefused => {
                    tracing::debug!("stale control socket {}, unlinking", cfg.path.display());
                    let _ = std::fs::remove_file(&cfg.path);
                }
                std::io::ErrorKind::NotFound => {
                    tracing::debug!("no control socket at {}", cfg.path.display());
                }
                _ => eprintln!("pnm: control socket {}: {e}", cfg.path.display()),
            }
        }
    }

    // Nothing listening. Under `yes`/`auto`/`ask` we may start one.
    if cfg.mode == ControlMaster::Ask && !confirm(&cfg.path) {
        return Attempt::Fallback("operator declined".into());
    }
    if cfg.persist.0.is_none() {
        // ControlPersist no: a master would die with us, so it buys nothing
        // for a single command.
        return Attempt::Fallback("control-persist no".into());
    }

    match spawn_master(cfg) {
        Ok(()) => match send(&cfg.path, args) {
            Ok(a) => a,
            Err(e) => Attempt::Fallback(format!("master did not answer: {e}")),
        },
        Err(e) => Attempt::Fallback(format!("could not start master: {e}")),
    }
}

/// One request/response exchange with a live master.
fn send(path: &Path, args: &[String]) -> std::io::Result<Attempt> {
    let stream = UnixStream::connect(path)?;
    let req = Envelope::Command(Request {
        protocol: PROTOCOL,
        args: args.to_vec(),
    });
    let mut payload = serde_json::to_vec(&req)?;
    payload.push(b'\n');

    // Hand over our own stdio so the master's output is indistinguishable from
    // a direct run — same terminal, same tty detection, same redirection.
    let fds = [
        std::io::stdin().as_raw_fd(),
        std::io::stdout().as_raw_fd(),
        std::io::stderr().as_raw_fd(),
    ];
    super::fdpass::send_with_fds(&stream, &payload, &fds)?;

    match read_response(&stream)? {
        Response::Done { code, elapsed_ms } => {
            tracing::debug!("control master ran the command in {elapsed_ms}ms");
            Ok(Attempt::Ran(code))
        }
        Response::Refused { reason } => Ok(Attempt::Fallback(reason)),
        other => Ok(Attempt::Fallback(format!("unexpected reply: {other:?}"))),
    }
}

/// Start a detached master and wait for its socket to answer.
///
/// A child process rather than forking ourselves: this process already has a
/// tokio runtime with worker threads, and forking after threads exist is not
/// something to build a security boundary on.
fn spawn_master(cfg: &ControlConfig) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.arg("--control-master")
        .arg("no") // the master must not try to delegate to itself
        .arg("--control-path")
        .arg(&cfg.path)
        .arg("--control-persist")
        .arg(cfg.persist.to_string());
    if let Ok(v) = std::env::var("PNM_VTA") {
        cmd.env("PNM_VTA", v);
    }
    cmd.arg("sidecar")
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid in the child between fork and exec detaches it from our
    // controlling terminal, so it survives the shell that started us. It calls
    // only async-signal-safe functions.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;

    // Wait for the socket, bounded. The master has to authenticate before it
    // can listen, which is one cold session — on a distant VTA that is seconds.
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if UnixStream::connect(&cfg.path).is_ok() {
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(std::io::Error::other(format!("master exited: {status}")));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(std::io::Error::other(
        "timed out waiting for the control socket",
    ))
}

fn confirm(path: &Path) -> bool {
    eprint!("pnm: start a control master on {}? [y/N] ", path.display());
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim(), "y" | "Y" | "yes")
}

/// `pnm sidecar status` — the equivalent of `ssh -O check`.
pub(crate) fn status(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let stream = match UnixStream::connect(path) {
        Ok(s) => s,
        Err(_) => {
            println!("no control master on {}", path.display());
            return Ok(());
        }
    };
    control_exchange(&stream, Control::Check)?;
    match read_response(&stream)? {
        Response::Status {
            pid,
            slug,
            persist,
            idle_secs,
        } => {
            println!(
                "control master running: pid {pid}, vta {slug}, persist {persist}, up {idle_secs}s"
            );
            Ok(())
        }
        other => Err(format!("unexpected reply: {other:?}").into()),
    }
}

/// `pnm sidecar stop` — the equivalent of `ssh -O exit`.
pub(crate) fn stop(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let stream = match UnixStream::connect(path) {
        Ok(s) => s,
        Err(_) => {
            println!("no control master on {}", path.display());
            return Ok(());
        }
    };
    control_exchange(&stream, Control::Exit)?;
    match read_response(&stream)? {
        Response::Exiting => {
            println!("control master exiting");
            Ok(())
        }
        other => Err(format!("unexpected reply: {other:?}").into()),
    }
}

/// Control verbs still carry descriptors: the master's `recvmsg` expects them,
/// and a uniform request shape keeps its parsing single-path.
fn control_exchange(stream: &UnixStream, op: Control) -> std::io::Result<()> {
    let mut payload = serde_json::to_vec(&Envelope::Control(op))?;
    payload.push(b'\n');
    let fds = [
        std::io::stdin().as_raw_fd(),
        std::io::stdout().as_raw_fd(),
        std::io::stderr().as_raw_fd(),
    ];
    super::fdpass::send_with_fds(stream, &payload, &fds)
}
