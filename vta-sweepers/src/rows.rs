//! Rows under a prefix, read a bounded page at a time (#2626).
//!
//! What every sweeper reads through. `prefix_iter_raw` answers in one piece,
//! and over vsock that is one response frame: once a keyspace's rows pass
//! 16 MiB the sweep fails on every tick, nothing is pruned, and the keyspace
//! only grows. A page is small whatever the keyspace holds.

use vti_common::error::AppError;
use vti_common::store::{KeyspaceHandle, RawKvPair, ScanOpts, ScanPager};

/// Rows one page reads.
const PAGE: usize = 256;

/// A walk over the rows under one prefix, in key order.
pub(crate) struct Rows {
    pages: ScanPager,
    page: std::vec::IntoIter<RawKvPair>,
}

/// Every row under `prefix`, a page at a time. Rows removed during the walk
/// do not disturb it: each page resumes strictly after the last key served.
pub(crate) fn rows(ks: &KeyspaceHandle, prefix: &str) -> Rows {
    Rows {
        pages: ks.scan_pager(ScanOpts::new(prefix, PAGE)),
        page: Vec::new().into_iter(),
    }
}

impl Rows {
    /// The next row, or `None` once the prefix is exhausted.
    pub(crate) async fn next(&mut self) -> Result<Option<RawKvPair>, AppError> {
        if let Some(row) = self.page.next() {
            return Ok(Some(row));
        }
        self.page = self.pages.next_page().await?.into_iter();
        Ok(self.page.next())
    }
}
