//! One question a host may want answered as it happens: **may what a rooms
//! administrator's reads show have changed?**
//!
//! A community service tells an open administrator console *when* to re-read its
//! rooms pages (`vtc/admin/events/event/0.2`, topic `rooms`): a room registered,
//! a room renewed out of a lapse, a room's or a storage config's holdings or
//! limits moving. Those writes happen here, in storage functions that take a
//! keyspace handle and nothing else, so the signal is a process-wide hook rather
//! than something threaded through every caller.
//!
//! The hook carries **nothing** — no room, no member, no size. It is a prompt to
//! look, and the host decides by re-reading whether anything it reports moved.
//! It is called after the write it follows has landed, from a non-async context,
//! and must not block: the host's hook is a broadcast send.
//!
//! No hook set (the default, and every host that does not stream) costs one
//! atomic load per write.

use std::sync::OnceLock;

static HOOK: OnceLock<fn()> = OnceLock::new();

/// Set the process's hook. The first call wins; later calls are ignored, so a
/// process that opens several hosts (tests) sets it once for all of them.
pub fn set_hook(hook: fn()) {
    let _ = HOOK.set(hook);
}

/// Something a rooms administrator's reads report may have changed.
pub(crate) fn changed() {
    if let Some(hook) = HOOK.get() {
        hook();
    }
}
