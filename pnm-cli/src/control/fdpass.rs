//! `SCM_RIGHTS` file-descriptor passing over a unix socket.
//!
//! The control client hands the master its own stdin/stdout/stderr, and the
//! master runs the command with those installed. Output therefore lands on the
//! caller's terminal directly — colours, `isatty`, redirection and pipes behave
//! exactly as they do for a one-shot `pnm`, with no capture or re-encoding in
//! between. This is how `ssh`'s multiplexer keeps a delegated session
//! indistinguishable from a direct one.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// Number of descriptors exchanged: stdin, stdout, stderr.
pub(crate) const FD_COUNT: usize = 3;

/// Send `payload` together with `fds` on `stream`.
pub(crate) fn send_with_fds(stream: &UnixStream, payload: &[u8], fds: &[RawFd]) -> io::Result<()> {
    assert!(!payload.is_empty(), "SCM_RIGHTS needs at least one byte");
    let mut cmsg =
        vec![0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    // SAFETY: msghdr is zero-initialised then populated with pointers that
    // outlive the sendmsg call; cmsg is sized by CMSG_SPACE for exactly
    // `fds.len()` descriptors.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg.len() as _;

        let hdr = libc::CMSG_FIRSTHDR(&msg);
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        (*hdr).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(hdr) as *mut RawFd, fds.len());

        if libc::sendmsg(stream.as_raw_fd(), &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receive a payload plus exactly [`FD_COUNT`] descriptors.
///
/// Returns the bytes read and the descriptors as [`OwnedFd`], so a caller that
/// drops them closes them — a leaked client fd would keep the caller's pipe
/// open and hang whatever is reading it.
pub(crate) fn recv_with_fds(
    stream: &UnixStream,
    buf: &mut [u8],
) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut cmsg =
        vec![0u8; unsafe { libc::CMSG_SPACE((size_of::<RawFd>() * FD_COUNT) as u32) } as usize];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: as above; the control buffer is sized for FD_COUNT descriptors
    // and every fd handed back is wrapped in OwnedFd exactly once.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg.len() as _;

        let n = libc::recvmsg(stream.as_raw_fd(), &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut fds = Vec::new();
        let mut hdr = libc::CMSG_FIRSTHDR(&msg);
        while !hdr.is_null() {
            if (*hdr).cmsg_level == libc::SOL_SOCKET && (*hdr).cmsg_type == libc::SCM_RIGHTS {
                let count =
                    ((*hdr).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / size_of::<RawFd>();
                let data = libc::CMSG_DATA(hdr) as *const RawFd;
                for i in 0..count {
                    fds.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            hdr = libc::CMSG_NXTHDR(&msg, hdr);
        }
        Ok((n as usize, fds))
    }
}

/// Install `fds` as stdin/stdout/stderr for the duration of the returned guard.
///
/// The originals are saved and restored on drop, so a master that ran one
/// client's command is left exactly as it was for the next.
pub(crate) struct StdioSwap {
    saved: [OwnedFd; FD_COUNT],
}

impl StdioSwap {
    pub(crate) fn install(fds: &[OwnedFd]) -> io::Result<Self> {
        // SAFETY: dup/dup2 on the process's own standard descriptors. The saved
        // copies are owned and restored in Drop.
        unsafe {
            let saved = [dup_owned(0)?, dup_owned(1)?, dup_owned(2)?];
            for (target, fd) in fds.iter().enumerate().take(FD_COUNT) {
                if libc::dup2(fd.as_raw_fd(), target as RawFd) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(Self { saved })
        }
    }
}

impl Drop for StdioSwap {
    fn drop(&mut self) {
        // SAFETY: restoring descriptors this guard saved in `install`.
        unsafe {
            for (target, fd) in self.saved.iter().enumerate() {
                libc::dup2(fd.as_raw_fd(), target as RawFd);
            }
        }
    }
}

unsafe fn dup_owned(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: caller passes a valid descriptor; dup returns a fresh one we own.
    let new = unsafe { libc::dup(fd) };
    if new < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}
