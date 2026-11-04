//! The long poll: `redeem` waits on [`Notifier`] for a change of state, one
//! open poll per request and a per-address cap ([`PollGuard`]).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

use tokio::sync::Notify;

use crate::record::MAX_POLLS_PER_ADDRESS;

/// One [`Notify`] per request with a poll waiting on it.
pub struct Notifier {
    inner: std::sync::Mutex<HashMap<String, Arc<Notify>>>,
}

pub static NOTIFIER: LazyLock<Notifier> = LazyLock::new(|| Notifier {
    inner: std::sync::Mutex::new(HashMap::new()),
});

impl Notifier {
    /// The handle a poll waits on. Create the `notified()` future and
    /// `enable()` it **before** reading the record, or a change landing
    /// between the read and the wait is missed.
    pub fn handle(&self, request_id: &str) -> Arc<Notify> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(request_id.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    pub(crate) fn wake(&self, request_id: &str) {
        if let Some(n) = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(request_id)
        {
            n.notify_waiters();
        }
    }

    fn forget(&self, request_id: &str) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(request_id);
    }
}

struct PollBook {
    open: HashSet<String>,
    per_address: HashMap<IpAddr, usize>,
}

static POLLS: LazyLock<std::sync::Mutex<PollBook>> = LazyLock::new(|| {
    std::sync::Mutex::new(PollBook {
        open: HashSet::new(),
        per_address: HashMap::new(),
    })
});

/// Why a poll was not admitted.
#[derive(Debug, PartialEq, Eq)]
pub enum PollRefused {
    /// Another poll on this request is open.
    AlreadyOpen,
    /// The address holds [`MAX_POLLS_PER_ADDRESS`] polls.
    AddressCap,
}

/// An open `redeem` poll; dropping it closes the slot.
pub struct PollGuard {
    request_id: String,
    address: IpAddr,
}

impl PollGuard {
    /// One open poll per request (base design §7.6), and a per-address cap.
    pub fn open(request_id: &str, address: IpAddr) -> Result<Self, PollRefused> {
        let mut book = POLLS.lock().unwrap_or_else(|p| p.into_inner());
        if book.open.contains(request_id) {
            return Err(PollRefused::AlreadyOpen);
        }
        let n = book.per_address.get(&address).copied().unwrap_or(0);
        if n >= MAX_POLLS_PER_ADDRESS {
            return Err(PollRefused::AddressCap);
        }
        book.open.insert(request_id.to_string());
        *book.per_address.entry(address).or_default() += 1;
        Ok(Self {
            request_id: request_id.to_string(),
            address,
        })
    }
}

impl Drop for PollGuard {
    fn drop(&mut self) {
        let mut book = POLLS.lock().unwrap_or_else(|p| p.into_inner());
        book.open.remove(&self.request_id);
        if let Some(n) = book.per_address.get_mut(&self.address) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                book.per_address.remove(&self.address);
            }
        }
        drop(book);
        NOTIFIER.forget(&self.request_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_poll_per_request_and_a_cap_per_address() {
        let ip: IpAddr = "192.0.2.44".parse().unwrap();
        let first = PollGuard::open("poll-a", ip).unwrap();
        assert_eq!(
            PollGuard::open("poll-a", ip).err(),
            Some(PollRefused::AlreadyOpen)
        );
        drop(first);
        let held: Vec<_> = (0..MAX_POLLS_PER_ADDRESS)
            .map(|i| PollGuard::open(&format!("poll-cap-{i}"), ip).unwrap())
            .collect();
        assert_eq!(
            PollGuard::open("poll-cap-over", ip).err(),
            Some(PollRefused::AddressCap)
        );
        drop(held);
        assert!(PollGuard::open("poll-cap-over", ip).is_ok());
    }
}
