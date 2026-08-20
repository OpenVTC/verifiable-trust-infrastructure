//! The backend a build with no session store gets.
//!
//! Its whole job is to be honest. A session store holds an admin private key;
//! if the build was never told where to put one, the answer is not "a file in
//! the working directory" — it is that there is nowhere to put it, said out
//! loud, on the operation that would have persisted it.

use crate::session::SessionBackend;

pub(crate) struct RefusingBackend {
    /// Why no store was selected, phrased for an operator and carrying the
    /// remedy. Rendered on every operation that would have touched a store.
    pub(crate) reason: String,
}

impl SessionBackend for RefusingBackend {
    /// There is genuinely nothing stored, so `None` is the truthful answer —
    /// but it is the answer that hid this whole class of failure, so it is not
    /// given silently.
    fn load(&self, _key: &str) -> Option<String> {
        eprintln!("error: cannot read session — {}", self.reason);
        None
    }

    fn save(&self, _key: &str, _value: &str) -> Result<(), Box<dyn std::error::Error>> {
        Err(format!("cannot store session — {}", self.reason).into())
    }

    fn clear(&self, _key: &str) {}
}
