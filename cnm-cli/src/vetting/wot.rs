//! The OpenPGP web of trust `cnm vetting bootstrap-pgp` reads.
//!
//! Pure: it parses bytes it is given, verifies signatures, and computes
//! distances. No network, no filesystem, and no clock of its own — every
//! validity check takes `now` (Unix seconds) so the tests are deterministic.
//!
//! ## What counts
//!
//! - A **usable key** has at least one user ID bound by a live self-
//!   certification, carries no verified key revocation, and has not expired by
//!   its newest self-signature.
//! - **Key A certifies key B** when A — itself usable — made a third-party
//!   certification (signature types 0x10–0x13) over one of B's bound user IDs
//!   that verifies cryptographically, is exportable, is not expired, was not
//!   created in the future, and that A has not since revoked (0x30 over the
//!   same user ID, created no earlier). Anything else is ignored and counted
//!   in [`CertStats`].
//! - A key's **depth** is the fewest certification hops from any root key; a
//!   root is depth 0.
//! - A **link** is a cleartext-signed message whose signed text has exactly
//!   one line `openvtc-link: <memberDid>`, signed by exactly one usable
//!   keyring key (its primary key or a bound signing subkey). The link ties
//!   that key's primary fingerprint to the DID. A DID claimed by several keys,
//!   or a key linking several DIDs, is ambiguous and not trusted.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;

use pgp::composed::{CleartextSignedMessage, PublicOrSecret, SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{Signature, SignatureType};
use pgp::types::{KeyDetails, Tag};

/// Clock skew tolerated for a signature's creation time.
pub const CLOCK_SKEW_SECS: u64 = 300;

/// 2019-01-19T00:00:00Z. A SHA-1 or RIPEMD-160 third-party certification made
/// after this is not trusted — GnuPG's cut-off, adopted because SHA-1
/// chosen-prefix collisions make a forged certification practical
/// ("SHA-1 is a Shambles", 2020). Older ones still count, as they do in GnuPG:
/// much of a long-lived web of trust was signed with SHA-1.
pub const SHA1_CERTIFICATION_CUTOFF: u64 = 1_547_856_000;

/// The line prefix a link statement carries.
pub const LINK_PREFIX: &str = "openvtc-link:";

/// Longest DID a link may name.
const MAX_DID_CHARS: usize = 2048;

/// Why the keyring or the roots could not be used at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WotError {
    /// Nothing in the file parsed as an OpenPGP public key.
    NoKeys { detail: String },
    /// A `--roots` value is not a full fingerprint.
    BadRoot(String),
    /// A root fingerprint names no key in the keyring.
    UnknownRoot(String),
    /// A root key is in the keyring but cannot certify anything.
    UnusableRoot {
        fingerprint: String,
        problem: KeyProblem,
    },
}

impl fmt::Display for WotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKeys { detail } => write!(
                f,
                "the keyring holds no OpenPGP public keys ({detail}).\n\
                 Export one with `gpg --export > keyring.gpg` (binary) or \
                 `gpg --armor --export > keyring.asc`, then pass it as --keyring"
            ),
            Self::BadRoot(root) => write!(
                f,
                "--roots `{root}` is not a full key fingerprint.\n\
                 Pass the 40-hex-digit fingerprint `gpg --fingerprint <key>` prints \
                 (spaces are fine); short and long key ids are not accepted because \
                 they can collide"
            ),
            Self::UnknownRoot(root) => write!(
                f,
                "root {root} is not in the keyring.\n\
                 Add it to the export (`gpg --armor --export {root} >> keyring.asc`) \
                 or correct the fingerprint"
            ),
            Self::UnusableRoot {
                fingerprint,
                problem,
            } => write!(
                f,
                "root {fingerprint} cannot anchor the web of trust: the key is {problem}.\n\
                 Choose a root whose key is current, or refresh the keyring so it \
                 carries the key's latest self-signatures"
            ),
        }
    }
}

impl std::error::Error for WotError {}

/// Why a key cannot certify or be linked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProblem {
    /// No user ID is bound by a valid, live self-certification.
    NoValidUserId,
    /// The key carries a verified key revocation.
    Revoked,
    /// The key's newest self-signature says it has expired.
    Expired,
}

impl fmt::Display for KeyProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoValidUserId => "without a validly self-signed user ID",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        })
    }
}

/// What happened to every third-party certification the graph looked at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CertStats {
    /// Certifications that make an edge.
    pub counted: usize,
    /// Made by a key that is not in the keyring.
    pub unknown_issuer: usize,
    /// Made by a key that is revoked, expired or has no bound user ID.
    pub unusable_issuer: usize,
    /// Expired, or created in the future.
    pub expired: usize,
    /// Revoked by their issuer.
    pub revoked: usize,
    /// Did not verify, or marked non-exportable.
    pub invalid: usize,
}

/// One parsed key and what the keyring knows about it.
#[derive(Debug, Clone)]
pub struct KeyEntry {
    /// The primary key's fingerprint, upper-case hex.
    pub fingerprint: String,
    /// The primary user ID, when one is bound.
    pub primary_user_id: Option<String>,
    /// Why the key is unusable; `None` when it is usable.
    pub problem: Option<KeyProblem>,
    key: SignedPublicKey,
    /// Indices into `key.details.users` of the user IDs a live self-
    /// certification binds.
    bound_users: Vec<usize>,
}

/// A parsed keyring: every key, indexed by fingerprint and key id (primary and
/// subkey).
#[derive(Debug)]
pub struct Keyring {
    entries: Vec<KeyEntry>,
    by_fingerprint: HashMap<String, usize>,
    by_key_id: HashMap<String, Vec<usize>>,
    subkey_by_fingerprint: HashMap<String, (usize, usize)>,
    subkey_by_key_id: HashMap<String, Vec<(usize, usize)>>,
    /// Keys or blocks that could not be read, for the operator.
    pub skipped: Vec<String>,
}

impl Keyring {
    /// Parse a keyring — binary, or ASCII-armored with one or more
    /// `PUBLIC KEY BLOCK`s — and evaluate every key at `now`.
    ///
    /// A key that appears twice (two exports concatenated) is merged: its user
    /// IDs and their signatures are combined, so a certification carried by
    /// either copy counts.
    ///
    /// # Errors
    ///
    /// [`WotError::NoKeys`] when nothing parses as a public key.
    pub fn parse(bytes: &[u8], now: u64) -> Result<Self, WotError> {
        let mut skipped = Vec::new();
        let mut keys: Vec<SignedPublicKey> = Vec::new();
        let first = bytes.iter().find(|b| !b.is_ascii_whitespace()).copied();
        match first {
            None => {
                return Err(WotError::NoKeys {
                    detail: "the file is empty".into(),
                });
            }
            Some(b) if b & 0x80 != 0 => {
                read_keys(
                    PublicOrSecret::from_bytes_many(bytes),
                    "binary keyring",
                    &mut keys,
                    &mut skipped,
                );
            }
            Some(_) => {
                let text = String::from_utf8_lossy(bytes);
                let blocks = armor_blocks(&text);
                if blocks.is_empty() {
                    return Err(WotError::NoKeys {
                        detail: "no `-----BEGIN PGP PUBLIC KEY BLOCK-----` armor found".into(),
                    });
                }
                for (n, block) in blocks.iter().enumerate() {
                    let label = format!("armor block {}", n + 1);
                    match PublicOrSecret::from_armor_many(block.as_bytes()) {
                        Ok((iter, _headers)) => {
                            read_keys(Ok(iter), &label, &mut keys, &mut skipped);
                        }
                        Err(e) => skipped.push(format!("{label}: {e}")),
                    }
                }
            }
        }

        // Merge duplicate primaries before evaluating anything.
        let mut merged: Vec<SignedPublicKey> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        for key in keys {
            let fp = fingerprint_hex(&key.primary_key);
            match index.get(&fp) {
                Some(&i) => merge_key(&mut merged[i], key),
                None => {
                    index.insert(fp, merged.len());
                    merged.push(key);
                }
            }
        }
        if merged.is_empty() {
            return Err(WotError::NoKeys {
                detail: skipped
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "no public key packets".into()),
            });
        }

        let mut keyring = Self {
            entries: Vec::with_capacity(merged.len()),
            by_fingerprint: HashMap::new(),
            by_key_id: HashMap::new(),
            subkey_by_fingerprint: HashMap::new(),
            subkey_by_key_id: HashMap::new(),
            skipped,
        };
        for key in merged {
            let i = keyring.entries.len();
            let fingerprint = fingerprint_hex(&key.primary_key);
            keyring.by_fingerprint.insert(fingerprint.clone(), i);
            keyring
                .by_key_id
                .entry(hex_upper(key.primary_key.legacy_key_id().as_ref()))
                .or_default()
                .push(i);
            for (j, sub) in key.public_subkeys.iter().enumerate() {
                keyring
                    .subkey_by_fingerprint
                    .insert(fingerprint_hex(&sub.key), (i, j));
                keyring
                    .subkey_by_key_id
                    .entry(hex_upper(sub.key.legacy_key_id().as_ref()))
                    .or_default()
                    .push((i, j));
            }
            let (problem, bound_users, primary_user_id) = evaluate_key(&key, now);
            keyring.entries.push(KeyEntry {
                fingerprint,
                primary_user_id,
                problem,
                key,
                bound_users,
            });
        }
        Ok(keyring)
    }

    /// Every key, in keyring order.
    pub fn keys(&self) -> &[KeyEntry] {
        &self.entries
    }

    /// The key with this primary fingerprint (upper-case hex).
    pub fn get(&self, fingerprint: &str) -> Option<&KeyEntry> {
        self.by_fingerprint
            .get(fingerprint)
            .map(|&i| &self.entries[i])
    }

    /// Resolve `--roots` values to fingerprints of usable keys in the keyring.
    ///
    /// # Errors
    ///
    /// The first root that is malformed, absent or unusable.
    pub fn resolve_roots(&self, roots: &[String]) -> Result<Vec<String>, WotError> {
        let mut out = BTreeSet::new();
        for root in roots {
            let fp = normalize_fingerprint(root).ok_or_else(|| WotError::BadRoot(root.clone()))?;
            let entry = self
                .get(&fp)
                .ok_or_else(|| WotError::UnknownRoot(fp.clone()))?;
            if let Some(problem) = entry.problem {
                return Err(WotError::UnusableRoot {
                    fingerprint: fp,
                    problem,
                });
            }
            out.insert(fp);
        }
        Ok(out.into_iter().collect())
    }

    /// The certification graph at `now`: for each certifier fingerprint, the
    /// fingerprints it certifies.
    pub fn certifications(&self, now: u64) -> (BTreeMap<String, BTreeSet<String>>, CertStats) {
        let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut stats = CertStats::default();
        for target in &self.entries {
            if target.problem.is_some() {
                continue;
            }
            let signee = &target.key.primary_key;
            for &u in &target.bound_users {
                let user = &target.key.details.users[u];
                for sig in &user.signatures {
                    if !is_certification(sig) || issued_by(sig, signee) {
                        continue;
                    }
                    let candidates = self.primary_candidates(sig);
                    if candidates.is_empty() {
                        stats.unknown_issuer += 1;
                        continue;
                    }
                    for c in candidates {
                        let certifier = &self.entries[c];
                        if certifier.fingerprint == target.fingerprint {
                            continue;
                        }
                        if certifier.problem.is_some() {
                            stats.unusable_issuer += 1;
                            continue;
                        }
                        let signer = &certifier.key.primary_key;
                        if !sig.exportable_certification()
                            || weak_certification_hash(sig)
                            || sig
                                .verify_third_party_certification(
                                    signee,
                                    signer,
                                    Tag::UserId,
                                    &user.id,
                                )
                                .is_err()
                        {
                            stats.invalid += 1;
                            continue;
                        }
                        if !is_live(sig, now) {
                            stats.expired += 1;
                            continue;
                        }
                        let created = created_secs(sig);
                        let revoked = user.signatures.iter().any(|r| {
                            r.typ() == Some(SignatureType::CertRevocation)
                                && issued_by(r, signer)
                                && created_secs(r) >= created
                                && created_secs(r) <= now + CLOCK_SKEW_SECS
                                && r.verify_third_party_certification(
                                    signee,
                                    signer,
                                    Tag::UserId,
                                    &user.id,
                                )
                                .is_ok()
                        });
                        if revoked {
                            stats.revoked += 1;
                            continue;
                        }
                        stats.counted += 1;
                        edges
                            .entry(certifier.fingerprint.clone())
                            .or_default()
                            .insert(target.fingerprint.clone());
                    }
                }
            }
        }
        (edges, stats)
    }

    /// Primary keys a signature names as its issuer — by fingerprint when it
    /// carries one, otherwise by key id.
    fn primary_candidates(&self, sig: &Signature) -> Vec<usize> {
        let by_fp: Vec<usize> = sig
            .issuer_fingerprint()
            .iter()
            .filter_map(|fp| self.by_fingerprint.get(&hex_upper(fp.as_bytes())).copied())
            .collect();
        if !by_fp.is_empty() || !sig.issuer_fingerprint().is_empty() {
            return by_fp;
        }
        let mut out: Vec<usize> = sig
            .issuer_key_id()
            .iter()
            .flat_map(|id| {
                self.by_key_id
                    .get(&hex_upper(id.as_ref()))
                    .cloned()
                    .unwrap_or_default()
            })
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// `(key, Some(subkey))` or `(key, None)` for every keyring key a
    /// signature names as its issuer.
    fn signer_candidates(&self, sig: &Signature) -> Vec<(usize, Option<usize>)> {
        let mut out = Vec::new();
        for fp in sig.issuer_fingerprint() {
            let hex = hex_upper(fp.as_bytes());
            if let Some(&i) = self.by_fingerprint.get(&hex) {
                out.push((i, None));
            }
            if let Some(&(i, j)) = self.subkey_by_fingerprint.get(&hex) {
                out.push((i, Some(j)));
            }
        }
        if out.is_empty() {
            for id in sig.issuer_key_id() {
                let hex = hex_upper(id.as_ref());
                for &i in self.by_key_id.get(&hex).into_iter().flatten() {
                    out.push((i, None));
                }
                for &(i, j) in self.subkey_by_key_id.get(&hex).into_iter().flatten() {
                    out.push((i, Some(j)));
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// How a key is reached from the roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reach {
    /// Certification hops from the nearest root; 0 for a root.
    pub depth: u32,
    /// Fingerprints from a root to this key, both ends included.
    pub path: Vec<String>,
}

/// Shortest certification paths from `roots` to every key they reach.
///
/// Breadth-first over `edges`. Neighbours are visited in fingerprint order and
/// roots in fingerprint order, so among equally short paths the one reported
/// is the same on every run.
pub fn shortest_paths(
    edges: &BTreeMap<String, BTreeSet<String>>,
    roots: &[String],
) -> BTreeMap<String, Reach> {
    let mut parent: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut depth: BTreeMap<String, u32> = BTreeMap::new();
    let mut queue = VecDeque::new();
    let mut sorted_roots = roots.to_vec();
    sorted_roots.sort();
    for root in sorted_roots {
        if depth.contains_key(&root) {
            continue;
        }
        depth.insert(root.clone(), 0);
        parent.insert(root.clone(), None);
        queue.push_back(root);
    }
    while let Some(node) = queue.pop_front() {
        let d = depth[&node];
        for next in edges.get(&node).into_iter().flatten() {
            if depth.contains_key(next) {
                continue;
            }
            depth.insert(next.clone(), d + 1);
            parent.insert(next.clone(), Some(node.clone()));
            queue.push_back(next.clone());
        }
    }
    depth
        .into_iter()
        .map(|(fp, d)| {
            let mut path = vec![fp.clone()];
            let mut cursor = parent.get(&fp).cloned().flatten();
            while let Some(p) = cursor {
                cursor = parent.get(&p).cloned().flatten();
                path.push(p);
            }
            path.reverse();
            (fp, Reach { depth: d, path })
        })
        .collect()
}

/// Why a link statement is not trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkProblem {
    /// The file is not an OpenPGP cleartext-signed message.
    NotCleartextSigned(String),
    /// The signed text has no `openvtc-link:` line.
    NoLinkLine,
    /// The signed text names more than one DID.
    SeveralDids(Vec<String>),
    /// The named DID is not shaped like a DID.
    BadDid(String),
    /// No signature names a key in the keyring.
    UnknownSigner(Vec<String>),
    /// A signature names a keyring key but does not verify with it (or has
    /// expired, or its subkey is not bound).
    BadSignature,
    /// The only signatures use a digest too weak for a new statement.
    WeakHash(String),
    /// The signature verifies, but the signing key is unusable.
    UnusableSigner {
        fingerprint: String,
        problem: KeyProblem,
    },
    /// Signatures from more than one key verify.
    SignedBySeveralKeys(Vec<String>),
    /// Another verified link names the same DID with a different key.
    DidClaimedBySeveralKeys(Vec<String>),
    /// The same key links more than one DID.
    KeyLinksSeveralDids(Vec<String>),
}

impl fmt::Display for LinkProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCleartextSigned(e) => write!(
                f,
                "not a cleartext-signed message ({e}); sign it with `gpg --clearsign`"
            ),
            Self::NoLinkLine => write!(f, "no `{LINK_PREFIX} <memberDid>` line in the signed text"),
            Self::SeveralDids(dids) => write!(f, "names several DIDs: {}", dids.join(", ")),
            Self::BadDid(did) => write!(f, "`{did}` is not a DID"),
            Self::UnknownSigner(ids) => {
                if ids.is_empty() {
                    write!(f, "unsigned: the signature names no issuer key")
                } else {
                    write!(
                        f,
                        "signed by {} which is not in the keyring",
                        ids.join(", ")
                    )
                }
            }
            Self::BadSignature => write!(
                f,
                "bad signature: it does not verify with the key it names (was the text \
                 changed after signing, or has the signature or signing subkey expired?)"
            ),
            Self::WeakHash(alg) => write!(
                f,
                "signed with {alg}, too weak for a new statement; re-sign with \
                 `gpg --digest-algo SHA256 --clearsign`"
            ),
            Self::UnusableSigner {
                fingerprint,
                problem,
            } => write!(f, "signed by {fingerprint}, which is {problem}"),
            Self::SignedBySeveralKeys(fps) => {
                write!(f, "signed by several keys: {}", fps.join(", "))
            }
            Self::DidClaimedBySeveralKeys(fps) => write!(
                f,
                "ambiguous: the DID is claimed by several keys ({})",
                fps.join(", ")
            ),
            Self::KeyLinksSeveralDids(dids) => write!(
                f,
                "ambiguous: the key links several DIDs ({})",
                dids.join(", ")
            ),
        }
    }
}

/// The outcome of reading one link file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkCheck {
    /// Where the statement came from (the file name).
    pub source: String,
    /// The DID the statement names, when one could be read.
    pub member_did: Option<String>,
    /// The linked key's primary fingerprint, when a signature identified one.
    pub fingerprint: Option<String>,
    /// Why the link is not trusted; `None` for a trusted link.
    pub problem: Option<LinkProblem>,
}

impl LinkCheck {
    fn failed(source: &str, did: Option<String>, problem: LinkProblem) -> Self {
        Self {
            source: source.to_string(),
            member_did: did,
            fingerprint: None,
            problem: Some(problem),
        }
    }
}

/// Read and verify one link statement against the keyring at `now`.
pub fn check_link(keyring: &Keyring, source: &str, text: &str, now: u64) -> LinkCheck {
    let msg = match CleartextSignedMessage::from_string(text) {
        Ok((msg, _headers)) => msg,
        Err(e) => {
            return LinkCheck::failed(source, None, LinkProblem::NotCleartextSigned(e.to_string()));
        }
    };

    let signed = msg.signed_text();
    let dids: BTreeSet<String> = signed
        .lines()
        .filter_map(|line| line.trim().strip_prefix(LINK_PREFIX))
        .map(|rest| rest.trim().to_string())
        .collect();
    let did = match dids.len() {
        0 => return LinkCheck::failed(source, None, LinkProblem::NoLinkLine),
        1 => dids.into_iter().next().expect("one DID"),
        _ => {
            return LinkCheck::failed(
                source,
                None,
                LinkProblem::SeveralDids(dids.into_iter().collect()),
            );
        }
    };
    if !looks_like_did(&did) {
        return LinkCheck::failed(source, None, LinkProblem::BadDid(did));
    }

    let mut issuers = BTreeSet::new();
    let mut named_a_keyring_key = false;
    let mut weak_hash: Option<HashAlgorithm> = None;
    // Primary fingerprint → the key's problem, for every key a signature
    // verified with.
    let mut verified: BTreeMap<String, Option<KeyProblem>> = BTreeMap::new();
    for sig in msg.signatures() {
        for fp in sig.issuer_fingerprint() {
            issuers.insert(hex_upper(fp.as_bytes()));
        }
        if sig.issuer_fingerprint().is_empty() {
            for id in sig.issuer_key_id() {
                issuers.insert(hex_upper(id.as_ref()));
            }
        }
        // A link is a new statement: there is no legacy to honour, so no
        // SHA-1, RIPEMD-160 or MD5 at all.
        if let Some(alg @ (HashAlgorithm::Md5 | HashAlgorithm::Sha1 | HashAlgorithm::Ripemd160)) =
            sig.hash_alg()
        {
            weak_hash = Some(alg);
            continue;
        }
        if !matches!(sig.typ(), Some(SignatureType::Text | SignatureType::Binary))
            || !is_live(sig, now)
        {
            if !keyring.signer_candidates(sig).is_empty() {
                named_a_keyring_key = true;
            }
            continue;
        }
        for (i, sub) in keyring.signer_candidates(sig) {
            named_a_keyring_key = true;
            let entry = &keyring.entries[i];
            let ok = match sub {
                None => sig
                    .verify(&entry.key.primary_key, signed.as_bytes())
                    .is_ok(),
                Some(j) => {
                    let subkey = &entry.key.public_subkeys[j];
                    signing_subkey_bound(&entry.key, subkey, now)
                        && sig.verify(subkey, signed.as_bytes()).is_ok()
                }
            };
            if ok {
                verified.insert(entry.fingerprint.clone(), entry.problem);
            }
        }
    }

    match verified.len() {
        0 if weak_hash.is_some() => LinkCheck::failed(
            source,
            Some(did),
            LinkProblem::WeakHash(weak_hash.map(|a| a.to_string()).unwrap_or_default()),
        ),
        0 if named_a_keyring_key => LinkCheck::failed(source, Some(did), LinkProblem::BadSignature),
        0 => LinkCheck::failed(
            source,
            Some(did),
            LinkProblem::UnknownSigner(issuers.into_iter().collect()),
        ),
        1 => {
            let (fingerprint, problem) = verified.into_iter().next().expect("one key");
            LinkCheck {
                source: source.to_string(),
                member_did: Some(did),
                problem: problem.map(|problem| LinkProblem::UnusableSigner {
                    fingerprint: fingerprint.clone(),
                    problem,
                }),
                fingerprint: Some(fingerprint),
            }
        }
        _ => LinkCheck::failed(
            source,
            Some(did),
            LinkProblem::SignedBySeveralKeys(verified.into_keys().collect()),
        ),
    }
}

/// Refuse every trusted link that another trusted link contradicts: a DID
/// claimed by more than one key, or a key linking more than one DID.
///
/// The same key linking the same DID in two files is not a contradiction.
pub fn mark_ambiguous(checks: &mut [LinkCheck]) {
    let mut keys_of_did: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut dids_of_key: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for c in checks.iter().filter(|c| c.problem.is_none()) {
        if let (Some(did), Some(fp)) = (&c.member_did, &c.fingerprint) {
            keys_of_did
                .entry(did.clone())
                .or_default()
                .insert(fp.clone());
            dids_of_key
                .entry(fp.clone())
                .or_default()
                .insert(did.clone());
        }
    }
    for c in checks.iter_mut().filter(|c| c.problem.is_none()) {
        let (Some(did), Some(fp)) = (&c.member_did, &c.fingerprint) else {
            continue;
        };
        let keys = &keys_of_did[did];
        let dids = &dids_of_key[fp];
        if keys.len() > 1 {
            c.problem = Some(LinkProblem::DidClaimedBySeveralKeys(
                keys.iter().cloned().collect(),
            ));
        } else if dids.len() > 1 {
            c.problem = Some(LinkProblem::KeyLinksSeveralDids(
                dids.iter().cloned().collect(),
            ));
        }
    }
}

/// Normalise a fingerprint as an operator types it: spaces and a `0x` prefix
/// dropped, upper-cased. `None` unless it is 40 (v4) or 64 (v6) hex digits.
pub fn normalize_fingerprint(input: &str) -> Option<String> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let hex = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
        .unwrap_or(&compact)
        .to_ascii_uppercase();
    ((hex.len() == 40 || hex.len() == 64) && hex.chars().all(|c| c.is_ascii_hexdigit()))
        .then_some(hex)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

type KeyIter<'a> = Box<dyn Iterator<Item = pgp::errors::Result<PublicOrSecret>> + 'a>;

fn read_keys(
    parsed: pgp::errors::Result<KeyIter<'_>>,
    label: &str,
    keys: &mut Vec<SignedPublicKey>,
    skipped: &mut Vec<String>,
) {
    match parsed {
        Ok(iter) => {
            for item in iter {
                match item {
                    Ok(PublicOrSecret::Public(k)) => keys.push(k),
                    // A keyring carrying secret material is a mistake worth
                    // naming, but its public half is still usable.
                    Ok(PublicOrSecret::Secret(k)) => {
                        skipped.push(format!(
                            "{label}: secret key {} — only its public part was read; \
                             export public keys with `gpg --export`",
                            fingerprint_hex(&k.primary_key)
                        ));
                        keys.push(k.to_public_key());
                    }
                    Err(e) => skipped.push(format!("{label}: {e}")),
                }
            }
        }
        Err(e) => skipped.push(format!("{label}: {e}")),
    }
}

/// Each `-----BEGIN PGP … KEY BLOCK-----` … `-----END …-----` span in `text`.
///
/// rPGP reads one armor block per call; a keyring built by concatenating
/// `gpg --armor --export` outputs carries many.
fn armor_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN PGP ") && trimmed.contains("KEY BLOCK") {
            current = Some(String::new());
        }
        if let Some(block) = current.as_mut() {
            block.push_str(trimmed);
            block.push('\n');
            if trimmed.starts_with("-----END PGP ") {
                blocks.push(current.take().expect("block"));
            }
        }
    }
    blocks
}

fn merge_key(into: &mut SignedPublicKey, from: SignedPublicKey) {
    for user in from.details.users {
        match into.details.users.iter_mut().find(|u| u.id == user.id) {
            Some(existing) => {
                for sig in user.signatures {
                    if !existing.signatures.contains(&sig) {
                        existing.signatures.push(sig);
                    }
                }
            }
            None => into.details.users.push(user),
        }
    }
    for sig in from.details.revocation_signatures {
        if !into.details.revocation_signatures.contains(&sig) {
            into.details.revocation_signatures.push(sig);
        }
    }
    for sig in from.details.direct_signatures {
        if !into.details.direct_signatures.contains(&sig) {
            into.details.direct_signatures.push(sig);
        }
    }
    for sub in from.public_subkeys {
        if !into.public_subkeys.iter().any(|s| s.key == sub.key) {
            into.public_subkeys.push(sub);
        }
    }
}

/// `(problem, bound user indices, primary user ID)` for a key at `now`.
fn evaluate_key(
    key: &SignedPublicKey,
    now: u64,
) -> (Option<KeyProblem>, Vec<usize>, Option<String>) {
    let primary = &key.primary_key;
    let mut bound = Vec::new();
    // (created, is_primary, user index) of each bound user's newest self-cert.
    let mut newest_per_user: Vec<(u64, bool, usize)> = Vec::new();
    // Newest self-signature overall that can carry a key expiration.
    let mut newest_self: Option<&Signature> = None;

    for (i, user) in key.details.users.iter().enumerate() {
        let mut best: Option<&Signature> = None;
        let mut revoked_at: Option<u64> = None;
        for sig in user.signatures.iter().filter(|s| issued_by(s, primary)) {
            if is_certification(sig) {
                if is_live(sig, now)
                    && sig
                        .verify_certification(primary, Tag::UserId, &user.id)
                        .is_ok()
                    && best.is_none_or(|b| created_secs(sig) > created_secs(b))
                {
                    best = Some(sig);
                }
            } else if sig.typ() == Some(SignatureType::CertRevocation)
                && sig
                    .verify_certification(primary, Tag::UserId, &user.id)
                    .is_ok()
            {
                revoked_at = Some(revoked_at.unwrap_or(0).max(created_secs(sig)));
            }
        }
        let Some(best) = best else { continue };
        if revoked_at.is_some_and(|r| r >= created_secs(best)) {
            continue;
        }
        bound.push(i);
        newest_per_user.push((created_secs(best), best.is_primary(), i));
        if newest_self.is_none_or(|n| created_secs(best) > created_secs(n)) {
            newest_self = Some(best);
        }
    }
    for sig in &key.details.direct_signatures {
        if sig.typ() == Some(SignatureType::Key)
            && issued_by(sig, primary)
            && sig.verify_key(primary).is_ok()
            && newest_self.is_none_or(|n| created_secs(sig) > created_secs(n))
        {
            newest_self = Some(sig);
        }
    }

    let primary_user_id = newest_per_user
        .iter()
        .max_by_key(|(created, is_primary, i)| (*is_primary, *created, std::cmp::Reverse(*i)))
        .map(|&(_, _, i)| user_id_text(&key.details.users[i].id));

    let revoked = key.details.revocation_signatures.iter().any(|sig| {
        sig.typ() == Some(SignatureType::KeyRevocation)
            && issued_by(sig, primary)
            && sig.verify_key(primary).is_ok()
    });
    let problem = if bound.is_empty() {
        Some(KeyProblem::NoValidUserId)
    } else if revoked {
        Some(KeyProblem::Revoked)
    } else if newest_self
        .and_then(Signature::key_expiration_time)
        .is_some_and(|d| {
            d.as_secs() > 0
                && u64::from(primary.created_at().as_secs()) + u64::from(d.as_secs()) <= now
        })
    {
        Some(KeyProblem::Expired)
    } else {
        None
    };
    (problem, bound, primary_user_id)
}

/// A signing subkey counts when a live binding from the primary verifies, it
/// is flagged for signing and cross-signed back, it has not expired, and no
/// subkey revocation verifies.
fn signing_subkey_bound(key: &SignedPublicKey, subkey: &SignedPublicSubKey, now: u64) -> bool {
    let primary = &key.primary_key;
    let revoked = subkey.signatures.iter().any(|sig| {
        sig.typ() == Some(SignatureType::SubkeyRevocation)
            && sig.verify_subkey_binding(primary, &subkey.key).is_ok()
    });
    if revoked {
        return false;
    }
    subkey.signatures.iter().any(|sig| {
        sig.typ() == Some(SignatureType::SubkeyBinding)
            && is_live(sig, now)
            && sig.key_flags().sign()
            && sig.verify_subkey_binding(primary, &subkey.key).is_ok()
            && sig.embedded_signature().is_some_and(|back| {
                back.verify_primary_key_binding(&subkey.key, primary)
                    .is_ok()
            })
            && sig.key_expiration_time().is_none_or(|d| {
                d.as_secs() == 0
                    || u64::from(subkey.key.created_at().as_secs()) + u64::from(d.as_secs()) > now
            })
    })
}

/// MD5 ever, or SHA-1/RIPEMD-160 after [`SHA1_CERTIFICATION_CUTOFF`].
fn weak_certification_hash(sig: &Signature) -> bool {
    match sig.hash_alg() {
        Some(HashAlgorithm::Md5) | None => true,
        Some(HashAlgorithm::Sha1 | HashAlgorithm::Ripemd160) => {
            created_secs(sig) > SHA1_CERTIFICATION_CUTOFF
        }
        Some(_) => false,
    }
}

fn is_certification(sig: &Signature) -> bool {
    matches!(
        sig.typ(),
        Some(
            SignatureType::CertGeneric
                | SignatureType::CertPersona
                | SignatureType::CertCasual
                | SignatureType::CertPositive
        )
    )
}

fn issued_by(sig: &Signature, key: &impl KeyDetails) -> bool {
    let fp = key.fingerprint();
    let id = key.legacy_key_id();
    sig.issuer_fingerprint().iter().any(|f| **f == fp)
        || sig.issuer_key_id().iter().any(|k| **k == id)
}

fn created_secs(sig: &Signature) -> u64 {
    sig.created().map_or(0, |t| u64::from(t.as_secs()))
}

/// Created (not in the future) and not expired at `now`.
fn is_live(sig: &Signature, now: u64) -> bool {
    let Some(created) = sig.created().map(|t| u64::from(t.as_secs())) else {
        return false;
    };
    if created > now + CLOCK_SKEW_SECS {
        return false;
    }
    sig.signature_expiration_time()
        .is_none_or(|d| d.as_secs() == 0 || created + u64::from(d.as_secs()) > now)
}

fn looks_like_did(did: &str) -> bool {
    let mut parts = did.splitn(3, ':');
    did.len() <= MAX_DID_CHARS
        && parts.next() == Some("did")
        && parts.next().is_some_and(|method| {
            !method.is_empty()
                && method
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
        && parts.next().is_some_and(|id| !id.is_empty())
        && !did.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn fingerprint_hex(key: &impl KeyDetails) -> String {
    hex_upper(key.fingerprint().as_bytes())
}

fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02X}");
            s
        })
}

fn user_id_text(id: &pgp::packet::UserId) -> String {
    id.as_str()
        .map(str::to_string)
        .unwrap_or_else(|| String::from_utf8_lossy(id.id()).into_owned())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::vetting::test_web::{DAY, Person, armored_keyring, binary_keyring, link_text, now};

    /// The web of trust every test here reads:
    ///
    /// ```text
    /// root ──▶ alice ──▶ bob ──▶ carol        depths 1, 2, 3
    /// root ──▶ dave                           depth 1
    /// root ─x▶ erin     certification expired         (no edge)
    /// root ─x▶ victor   certification revoked by root (no edge)
    /// root ─x▶ xavier   root's certification of alice, copied onto
    ///                   xavier's user ID: does not verify (no edge)
    /// uma  ──▶ alice    uma's key is not in the keyring (ignored)
    /// ```
    pub(crate) struct Web {
        pub root: Person,
        pub alice: Person,
        pub bob: Person,
        pub carol: Person,
        pub dave: Person,
        pub erin: Person,
        pub victor: Person,
        pub xavier: Person,
        pub uma: Person,
    }

    impl Web {
        pub(crate) fn new() -> Self {
            let t = now();
            let root = Person::new(1, "Root");
            let mut alice = Person::new(2, "Alice");
            let mut bob = Person::new(3, "Bob");
            let mut carol = Person::new(4, "Carol");
            let mut dave = Person::new(5, "Dave");
            let mut erin = Person::new(6, "Erin");
            let mut victor = Person::new(7, "Victor");
            let mut xavier = Person::new(8, "Xavier");
            let uma = Person::new(9, "Uma");

            root.certify(&mut alice, t - 300 * DAY, None);
            alice.certify(&mut bob, t - 200 * DAY, None);
            bob.certify(&mut carol, t - 100 * DAY, None);
            root.certify(&mut dave, t - 300 * DAY, None);
            // Made a year ago, valid for thirty days.
            root.certify(&mut erin, t - 300 * DAY, Some(30 * DAY));
            root.certify(&mut victor, t - 300 * DAY, None);
            root.revoke_certification(&mut victor, t - 10 * DAY);
            let copied = root.certification_of(&alice, t - 300 * DAY, None);
            xavier.public.details.users[0].signatures.push(copied);
            uma.certify(&mut alice, t - 50 * DAY, None);

            Self {
                root,
                alice,
                bob,
                carol,
                dave,
                erin,
                victor,
                xavier,
                uma,
            }
        }

        /// Every key but uma's, as concatenated armored exports.
        pub(crate) fn keyring(&self) -> Keyring {
            Keyring::parse(&armored_keyring(&self.exported()), now()).expect("keyring parses")
        }

        pub(crate) fn exported(&self) -> Vec<&Person> {
            vec![
                &self.root,
                &self.alice,
                &self.bob,
                &self.carol,
                &self.dave,
                &self.erin,
                &self.victor,
                &self.xavier,
            ]
        }
    }

    #[test]
    fn depths_are_the_shortest_certification_paths_from_the_roots() {
        let web = Web::new();
        let ring = web.keyring();
        assert!(ring.keys().iter().all(|k| k.problem.is_none()));
        assert_eq!(
            ring.get(&web.alice.fingerprint())
                .and_then(|k| k.primary_user_id.as_deref()),
            Some("Alice <alice@kernel.example>")
        );

        let roots = ring.resolve_roots(&[web.root.fingerprint()]).unwrap();
        let (edges, stats) = ring.certifications(now());
        let reach = shortest_paths(&edges, &roots);

        assert_eq!(reach[&web.root.fingerprint()].depth, 0);
        assert_eq!(reach[&web.alice.fingerprint()].depth, 1);
        assert_eq!(reach[&web.dave.fingerprint()].depth, 1);
        assert_eq!(reach[&web.bob.fingerprint()].depth, 2);
        let carol = &reach[&web.carol.fingerprint()];
        assert_eq!(carol.depth, 3);
        assert_eq!(
            carol.path,
            vec![
                web.root.fingerprint(),
                web.alice.fingerprint(),
                web.bob.fingerprint(),
                web.carol.fingerprint()
            ]
        );

        // Rooting at alice instead: root is not reachable (edges point one
        // way), bob is one hop.
        let from_alice = shortest_paths(
            &edges,
            &ring.resolve_roots(&[web.alice.fingerprint()]).unwrap(),
        );
        assert_eq!(from_alice[&web.bob.fingerprint()].depth, 1);
        assert!(!from_alice.contains_key(&web.root.fingerprint()));

        // Two roots: the nearer one wins.
        let both = shortest_paths(
            &edges,
            &ring
                .resolve_roots(&[web.root.fingerprint(), web.bob.fingerprint()])
                .unwrap(),
        );
        assert_eq!(both[&web.carol.fingerprint()].depth, 1);

        let _ = stats;
    }

    #[test]
    fn expired_revoked_invalid_and_unknown_certifications_make_no_edge() {
        let web = Web::new();
        let ring = web.keyring();
        let roots = ring.resolve_roots(&[web.root.fingerprint()]).unwrap();
        let (edges, stats) = ring.certifications(now());
        let reach = shortest_paths(&edges, &roots);

        for (who, why) in [
            (&web.erin, "an expired certification"),
            (&web.victor, "a revoked certification"),
            (&web.xavier, "a certification that does not verify"),
        ] {
            assert!(
                !reach.contains_key(&who.fingerprint()),
                "{why} must not make an edge"
            );
        }
        assert_eq!(
            stats,
            CertStats {
                counted: 4,
                unknown_issuer: 1,
                unusable_issuer: 0,
                expired: 1,
                revoked: 1,
                invalid: 1,
            }
        );
    }

    /// A signature packet with a chosen digest, type and creation time, issued
    /// by `issuer`. rPGP will not *make* a SHA-1 or MD5 signature with an
    /// Ed25519 key, so the packet is assembled directly; its signature value
    /// is filler, which does not matter to a digest rule applied before any
    /// verification.
    fn signature_with_digest(
        issuer: &Person,
        typ: SignatureType,
        hash: HashAlgorithm,
        created: u64,
    ) -> Signature {
        use pgp::packet::{SignatureConfig, Subpacket, SubpacketData};
        use pgp::types::{Mpi, SignatureBytes, Timestamp};
        let key = &issuer.secret.primary_key;
        let mut config = SignatureConfig::v4(typ, key.algorithm(), hash);
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                u32::try_from(created).unwrap(),
            )))
            .unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint())).unwrap(),
        ];
        let filler =
            SignatureBytes::Mpis(vec![Mpi::from_slice(&[1; 32]), Mpi::from_slice(&[1; 32])]);
        Signature::from_config(config, [0, 0], filler).expect("signature packet")
    }

    #[test]
    fn weak_digests_are_refused_where_a_forgery_would_be_practical() {
        let t = now();
        let root = Person::new(1, "Root");
        let cert =
            |hash, created| signature_with_digest(&root, SignatureType::CertGeneric, hash, created);

        assert!(
            weak_certification_hash(&cert(HashAlgorithm::Sha1, SHA1_CERTIFICATION_CUTOFF + DAY)),
            "a SHA-1 certification after the cut-off does not count"
        );
        assert!(weak_certification_hash(&cert(
            HashAlgorithm::Ripemd160,
            t - DAY
        )));
        assert!(
            !weak_certification_hash(&cert(HashAlgorithm::Sha1, SHA1_CERTIFICATION_CUTOFF - DAY)),
            "a SHA-1 certification from before the cut-off still does"
        );
        assert!(
            weak_certification_hash(&cert(
                HashAlgorithm::Md5,
                SHA1_CERTIFICATION_CUTOFF - 365 * DAY
            )),
            "MD5 never counts"
        );
        assert!(!weak_certification_hash(&root.certification_of(
            &root,
            t - DAY,
            None
        )));

        // A link is a new statement, so SHA-1 is refused outright — with the
        // command that fixes it.
        let ring = Keyring::parse(&armored_keyring(&[&root]), t).unwrap();
        let link = CleartextSignedMessage::new_many(&link_text("did:key:zRoot"), |_| {
            Ok(vec![signature_with_digest(
                &root,
                SignatureType::Text,
                HashAlgorithm::Sha1,
                t - DAY,
            )])
        })
        .unwrap()
        .to_armored_string(pgp::composed::ArmorOptions::default())
        .unwrap();
        let check = check_link(&ring, "root.asc", &link, t);
        assert_eq!(check.problem, Some(LinkProblem::WeakHash("SHA1".into())));
        assert!(
            check
                .problem
                .unwrap()
                .to_string()
                .contains("--digest-algo SHA256")
        );
    }

    #[test]
    fn a_revoked_key_neither_certifies_nor_anchors() {
        let mut web = Web::new();
        web.alice.revoke_key(now() - DAY);
        let ring = web.keyring();
        assert_eq!(
            ring.get(&web.alice.fingerprint()).unwrap().problem,
            Some(KeyProblem::Revoked)
        );
        let roots = ring.resolve_roots(&[web.root.fingerprint()]).unwrap();
        let (edges, stats) = ring.certifications(now());
        let reach = shortest_paths(&edges, &roots);
        assert!(!reach.contains_key(&web.alice.fingerprint()));
        assert!(
            !reach.contains_key(&web.bob.fingerprint()),
            "bob was reachable only through alice's now-revoked key"
        );
        assert_eq!(stats.unusable_issuer, 1);

        assert_eq!(
            ring.resolve_roots(&[web.alice.fingerprint()]),
            Err(WotError::UnusableRoot {
                fingerprint: web.alice.fingerprint(),
                problem: KeyProblem::Revoked
            })
        );
    }

    /// A fingerprint covers the key's creation time: the same seed made in a
    /// later second must still be the same key, or duplicate exports stop merging.
    #[test]
    fn a_seed_is_the_same_key_in_a_later_second() {
        let first = Person::new(2, "Alice").fingerprint();
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        assert_eq!(Person::new(2, "Alice").fingerprint(), first);
    }

    #[test]
    fn binary_and_armored_keyrings_read_alike_and_duplicates_merge() {
        let web = Web::new();
        let t = now();
        let binary = Keyring::parse(&binary_keyring(&web.exported()), t).unwrap();
        assert_eq!(binary.keys().len(), 8);

        // Alice exported twice — once bare, once with her certifications —
        // is one key carrying every certification.
        let bare_alice = Person::new(2, "Alice");
        let mut bytes = armored_keyring(&[&bare_alice]);
        bytes.push(b'\n');
        bytes.extend(armored_keyring(&web.exported()));
        let ring = Keyring::parse(&bytes, t).unwrap();
        assert_eq!(ring.keys().len(), 8);
        let roots = ring.resolve_roots(&[web.root.fingerprint()]).unwrap();
        let (edges, _) = ring.certifications(t);
        assert_eq!(
            shortest_paths(&edges, &roots)[&web.bob.fingerprint()].depth,
            2
        );

        assert!(matches!(
            Keyring::parse(b"   ", t),
            Err(WotError::NoKeys { .. })
        ));
        assert!(matches!(
            Keyring::parse(b"hello, not a key", t),
            Err(WotError::NoKeys { .. })
        ));
    }

    #[test]
    fn roots_must_be_full_fingerprints_of_keyring_keys() {
        let web = Web::new();
        let ring = web.keyring();
        let fp = web.root.fingerprint();
        let typed = format!(
            "0x{} {}",
            fp[..20].to_ascii_lowercase(),
            fp[20..].to_ascii_lowercase()
        );
        assert_eq!(ring.resolve_roots(&[typed]).unwrap(), vec![fp.clone()]);
        assert!(matches!(
            ring.resolve_roots(&[fp[24..].to_string()]),
            Err(WotError::BadRoot(_))
        ));
        let absent = "0".repeat(40);
        assert_eq!(
            ring.resolve_roots(std::slice::from_ref(&absent)),
            Err(WotError::UnknownRoot(absent))
        );
        assert!(
            WotError::BadRoot("ABCD".into())
                .to_string()
                .contains("gpg --fingerprint")
        );
    }

    #[test]
    fn a_link_verifies_with_the_primary_key_or_a_signing_subkey() {
        let web = Web::new();
        let ring = web.keyring();
        let t = now();

        let by_primary = web
            .alice
            .clearsign(&link_text("did:key:zAlice"), t - DAY, false);
        let check = check_link(&ring, "alice.asc", &by_primary, t);
        assert_eq!(check.problem, None, "{check:?}");
        assert_eq!(check.member_did.as_deref(), Some("did:key:zAlice"));
        assert_eq!(check.fingerprint, Some(web.alice.fingerprint()));

        let by_subkey = web.bob.clearsign(&link_text("did:key:zBob"), t - DAY, true);
        let check = check_link(&ring, "bob.asc", &by_subkey, t);
        assert_eq!(check.problem, None, "{check:?}");
        assert_eq!(
            check.fingerprint,
            Some(web.bob.fingerprint()),
            "a subkey signature links the primary key"
        );
    }

    #[test]
    fn unsigned_badly_signed_and_malformed_links_are_refused() {
        let web = Web::new();
        let ring = web.keyring();
        let t = now();
        let problem = |text: &str| check_link(&ring, "x.asc", text, t).problem;

        assert!(matches!(
            problem("openvtc-link: did:key:zAlice\n"),
            Some(LinkProblem::NotCleartextSigned(_))
        ));

        let signed = web
            .alice
            .clearsign(&link_text("did:key:zAlice"), t - DAY, false);
        let tampered = signed.replace("did:key:zAlice", "did:key:zMallory");
        let check = check_link(&ring, "x.asc", &tampered, t);
        assert_eq!(check.problem, Some(LinkProblem::BadSignature));
        assert_eq!(check.member_did.as_deref(), Some("did:key:zMallory"));

        let from_the_future =
            web.alice
                .clearsign(&link_text("did:key:zAlice"), t + 30 * DAY, false);
        assert_eq!(problem(&from_the_future), Some(LinkProblem::BadSignature));

        let stranger = web
            .uma
            .clearsign(&link_text("did:key:zUma"), t - DAY, false);
        assert_eq!(
            problem(&stranger),
            Some(LinkProblem::UnknownSigner(vec![web.uma.fingerprint()]))
        );

        let no_line = web.alice.clearsign("I am Alice.\n", t - DAY, false);
        assert_eq!(problem(&no_line), Some(LinkProblem::NoLinkLine));

        let two = web.alice.clearsign(
            "openvtc-link: did:key:zA\nopenvtc-link: did:key:zB\n",
            t - DAY,
            false,
        );
        assert!(matches!(problem(&two), Some(LinkProblem::SeveralDids(_))));

        let not_a_did = web
            .alice
            .clearsign("openvtc-link: alice@kernel.org\n", t - DAY, false);
        assert!(matches!(problem(&not_a_did), Some(LinkProblem::BadDid(_))));

        let mut revoked = Person::new(2, "Alice");
        revoked.revoke_key(t - DAY);
        let ring = Keyring::parse(&armored_keyring(&[&revoked]), t).unwrap();
        let link = revoked.clearsign(&link_text("did:key:zAlice"), t - 2 * DAY, false);
        assert!(matches!(
            check_link(&ring, "x.asc", &link, t).problem,
            Some(LinkProblem::UnusableSigner {
                problem: KeyProblem::Revoked,
                ..
            })
        ));
    }

    #[test]
    fn contradicting_links_are_all_refused() {
        let web = Web::new();
        let ring = web.keyring();
        let t = now();
        let link = |p: &Person, did: &str, file: &str| {
            check_link(
                &ring,
                file,
                &p.clearsign(&link_text(did), t - DAY, false),
                t,
            )
        };
        let mut checks = vec![
            link(&web.carol, "did:key:zShared", "carol.asc"),
            link(&web.dave, "did:key:zShared", "dave.asc"),
            link(&web.erin, "did:key:zErin1", "erin-1.asc"),
            link(&web.erin, "did:key:zErin2", "erin-2.asc"),
            link(&web.alice, "did:key:zAlice", "alice.asc"),
            link(&web.alice, "did:key:zAlice", "alice-again.asc"),
        ];
        mark_ambiguous(&mut checks);
        assert!(matches!(
            checks[0].problem,
            Some(LinkProblem::DidClaimedBySeveralKeys(_))
        ));
        assert!(matches!(
            checks[1].problem,
            Some(LinkProblem::DidClaimedBySeveralKeys(_))
        ));
        assert!(matches!(
            checks[2].problem,
            Some(LinkProblem::KeyLinksSeveralDids(_))
        ));
        assert!(matches!(
            checks[3].problem,
            Some(LinkProblem::KeyLinksSeveralDids(_))
        ));
        assert_eq!(
            checks[4].problem, None,
            "the same link twice is no contradiction"
        );
        assert_eq!(checks[5].problem, None);
    }
}
