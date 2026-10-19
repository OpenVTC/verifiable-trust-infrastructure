//! Durability: an append-only file journal of what the ballot box accepted.
//!
//! One directory per election, named by a digest of `(community, electionId)` so no caller-
//! supplied string becomes a path. In it:
//!
//! - `election.json` — the registration as received (manifest and parameters);
//! - `entries.log` — the board, one record per entry: a big-endian `u32` length and the entry's
//!   JCS bytes;
//! - `receipts.log` — receipt tokens: a `u64` leaf index, a `u32` length, the token.
//!
//! Every write is followed by `sync_data` before the ballot box answers, so an answer is never
//! given for something a crash could lose. A torn final record (a crash mid-write) is
//! truncated away on open: its answer was never sent.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use vti_voting::service::{Journal, Restored, StoredElection};

pub struct FileJournal {
    root: PathBuf,
    /// Serialises writers. The ballot box is driven under one lock already; this keeps the
    /// journal correct on its own.
    lock: Mutex<()>,
}

impl std::fmt::Debug for FileJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileJournal")
            .field("root", &self.root)
            .finish()
    }
}

/// SHA-256 over the length-framed pair, hex: no caller-supplied string reaches a path.
fn dir_name(community: &str, election_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for f in [community, election_id] {
        h.update((f.len() as u64).to_be_bytes());
        h.update(f.as_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn append_record(path: &Path, record: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(record)?;
    f.sync_data()
}

impl FileJournal {
    /// Open (creating) the journal under `root`.
    ///
    /// # Errors
    /// If the directory cannot be created.
    pub fn open(root: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            lock: Mutex::new(()),
        })
    }

    fn dir(&self, community: &str, election_id: &str) -> std::io::Result<PathBuf> {
        let d = self.root.join(dir_name(community, election_id));
        fs::create_dir_all(&d)?;
        Ok(d)
    }

    /// Everything the journal holds, for [`vti_voting::service::BallotBox::restore`].
    ///
    /// # Errors
    /// If a file cannot be read or a registration does not parse.
    pub fn load(&self) -> anyhow::Result<Vec<Restored>> {
        let mut out = Vec::new();
        for dir in fs::read_dir(&self.root)? {
            let dir = dir?.path();
            if !dir.is_dir() {
                continue;
            }
            let election_path = dir.join("election.json");
            if !election_path.exists() {
                continue;
            }
            let election: StoredElection = serde_json::from_slice(&fs::read(&election_path)?)?;
            let entries = read_entries(&dir.join("entries.log"))?;
            let receipts = read_receipts(&dir.join("receipts.log"))?;
            out.push(Restored {
                election: Some(election),
                entries,
                receipts,
            });
        }
        Ok(out)
    }
}

/// Read length-prefixed records, truncating a torn tail.
fn read_entries(path: &Path) -> std::io::Result<Vec<Vec<u8>>> {
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut f) => f.read_to_end(&mut bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 4 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[at..at + 4].try_into().expect("4 bytes")) as usize;
        if at + 4 + len > bytes.len() {
            break;
        }
        out.push(bytes[at + 4..at + 4 + len].to_vec());
        at += 4 + len;
    }
    if at != bytes.len() {
        tracing::warn!(path = %path.display(), "truncating a torn final board entry");
        OpenOptions::new()
            .write(true)
            .open(path)?
            .set_len(at as u64)?;
    }
    Ok(out)
}

fn read_receipts(path: &Path) -> std::io::Result<HashMap<u64, String>> {
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut f) => f.read_to_end(&mut bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e),
    };
    let mut out = HashMap::new();
    let mut at = 0usize;
    while at + 12 <= bytes.len() {
        let leaf = u64::from_be_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        let len = u32::from_be_bytes(bytes[at + 8..at + 12].try_into().expect("4 bytes")) as usize;
        if at + 12 + len > bytes.len() {
            break;
        }
        out.insert(
            leaf,
            String::from_utf8_lossy(&bytes[at + 12..at + 12 + len]).into_owned(),
        );
        at += 12 + len;
    }
    Ok(out)
}

impl Journal for FileJournal {
    fn election(
        &self,
        community: &str,
        election_id: &str,
        e: &StoredElection,
    ) -> Result<(), String> {
        let _guard = self.lock.lock().map_err(|e| e.to_string())?;
        let dir = self
            .dir(community, election_id)
            .map_err(|e| e.to_string())?;
        let path = dir.join("election.json");
        let tmp = dir.join("election.json.tmp");
        let bytes = serde_json::to_vec(e).map_err(|e| e.to_string())?;
        let mut f = File::create(&tmp).map_err(|e| e.to_string())?;
        f.write_all(&bytes).map_err(|e| e.to_string())?;
        f.sync_data().map_err(|e| e.to_string())?;
        fs::rename(&tmp, &path).map_err(|e| e.to_string())
    }

    fn entry(
        &self,
        community: &str,
        election_id: &str,
        _index: u64,
        bytes: &[u8],
    ) -> Result<(), String> {
        let _guard = self.lock.lock().map_err(|e| e.to_string())?;
        let dir = self
            .dir(community, election_id)
            .map_err(|e| e.to_string())?;
        let len = u32::try_from(bytes.len()).map_err(|_| "entry too large".to_string())?;
        let mut record = Vec::with_capacity(4 + bytes.len());
        record.extend(len.to_be_bytes());
        record.extend(bytes);
        append_record(&dir.join("entries.log"), &record).map_err(|e| e.to_string())
    }

    fn receipt(
        &self,
        community: &str,
        election_id: &str,
        leaf: u64,
        token: &str,
    ) -> Result<(), String> {
        let _guard = self.lock.lock().map_err(|e| e.to_string())?;
        let dir = self
            .dir(community, election_id)
            .map_err(|e| e.to_string())?;
        let len = u32::try_from(token.len()).map_err(|_| "token too large".to_string())?;
        let mut record = Vec::with_capacity(12 + token.len());
        record.extend(leaf.to_be_bytes());
        record.extend(len.to_be_bytes());
        record.extend(token.as_bytes());
        append_record(&dir.join("receipts.log"), &record).map_err(|e| e.to_string())
    }
}
