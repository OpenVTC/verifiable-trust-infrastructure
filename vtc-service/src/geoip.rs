//! Local GeoIP: the coarse "City, CC" a wallet shows its approver as the
//! sign-in request's `requester.location`.
//!
//! Base design §12.6: the lookup is against a **local database only — never a
//! third-party call**. The operator points `[geoip] database` (or
//! `VTC_GEOIP_DATABASE`) at a MaxMind DB (`.mmdb`) file with the GeoIP2 *City*
//! record shape — DB-IP "IP to City Lite" (CC BY 4.0, recommended) or MaxMind
//! GeoLite2 City. Unset, every address is `None`, which the caller reports as
//! `"unknown"` (the wallet shows that as a warning, not as neutral).
//!
//! The file is read into memory, and re-read when it changes on disk (a
//! periodic check of its modification time and length,
//! [`GeoIp::spawn_reloader`]), so a monthly database refresh needs no restart.
//! A replacement that cannot be read keeps the database already loaded. A
//! configured file that cannot be read at startup is a warning, not a boot
//! failure: location is advisory, and the sign-in flow is complete without it.
//!
//! Privacy: an address is never logged or stored here — only the coarse result
//! leaves this module, and warnings name the database path and the error only.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use maxminddb::{Reader, geoip2};
use tracing::{info, warn};

/// How often [`GeoIp::spawn_reloader`] checks the database file for a change.
/// One `stat` a minute; the read only happens when the file has changed.
pub const RELOAD_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// `requester.location`'s `maxLength` in the `auth/oob` specification (in
/// characters). A longer lookup result is cut to fit rather than dropped.
pub const MAX_LOCATION_CHARS: usize = 128;

/// What identifies one version of the database file on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    modified: Option<SystemTime>,
    len: u64,
}

impl FileStamp {
    fn of(path: &Path) -> std::io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        Ok(Self {
            modified: meta.modified().ok(),
            len: meta.len(),
        })
    }
}

/// The database file as last tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    Never,
    /// Not there (or not `stat`-able) — already warned about.
    Missing,
    /// This version, loaded or refused.
    File(FileStamp),
}

/// The outcome of one [`GeoIp::refresh`].
#[derive(Debug, PartialEq, Eq)]
pub enum Refresh {
    /// No database is configured.
    Disabled,
    /// The file is the one already loaded (or already refused).
    Unchanged,
    /// A new version of the file was loaded and is now in use.
    Loaded,
    /// The file is missing or could not be read as a database. Whatever was
    /// loaded before stays in use. The warning has been logged.
    Failed,
}

/// The process's GeoIP handle, carried on `AppState`.
pub struct GeoIp {
    path: Option<PathBuf>,
    /// The database in use. A lookup clones the `Arc` and releases the lock,
    /// so a reload swaps it without waiting on lookups, and a lookup in flight
    /// finishes on the version it started with.
    reader: RwLock<Option<Arc<Reader<Vec<u8>>>>>,
    /// The file version last tried — loaded or refused — so an unchanged bad
    /// file is not re-read (or re-warned about) every check.
    seen: Mutex<Seen>,
}

impl std::fmt::Debug for GeoIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoIp")
            .field("path", &self.path)
            .field("loaded", &self.is_loaded())
            .finish()
    }
}

impl GeoIp {
    /// No database: every lookup is `None`.
    pub fn disabled() -> Self {
        Self {
            path: None,
            reader: RwLock::new(None),
            seen: Mutex::new(Seen::Never),
        }
    }

    /// Open the configured database, if any. Never fails: a file that cannot
    /// be read is logged as a warning and the handle behaves as if none were
    /// configured until a readable file appears at the path.
    ///
    /// Reads the whole file, so call it off the async runtime's worker
    /// threads (`spawn_blocking`) once the database is large.
    pub fn open(path: Option<PathBuf>) -> Self {
        let geoip = Self {
            path,
            ..Self::disabled()
        };
        geoip.refresh();
        geoip
    }

    /// Whether a database is loaded.
    pub fn is_loaded(&self) -> bool {
        self.reader.read().map(|r| r.is_some()).unwrap_or(false)
    }

    /// Re-read the database file if it has changed since it was last tried.
    /// Blocking (a `stat`, and a full read when the file changed).
    pub fn refresh(&self) -> Refresh {
        let Some(path) = self.path.as_deref() else {
            return Refresh::Disabled;
        };
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        let stamp = match FileStamp::of(path) {
            Ok(stamp) => stamp,
            Err(e) => {
                // Once per disappearance, not once a minute.
                if *seen != Seen::Missing {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "GeoIP database not found or not readable; keeping any database \
                         already loaded, otherwise sign-in locations show as \"unknown\""
                    );
                }
                *seen = Seen::Missing;
                return Refresh::Failed;
            }
        };
        if *seen == Seen::File(stamp) {
            return Refresh::Unchanged;
        }
        *seen = Seen::File(stamp);
        match Reader::open_readfile(path) {
            Ok(reader) => {
                let meta = reader.metadata();
                info!(
                    path = %path.display(),
                    database_type = %meta.database_type,
                    build_epoch = meta.build_epoch,
                    "GeoIP database loaded"
                );
                let mut slot = self.reader.write().unwrap_or_else(|p| p.into_inner());
                *slot = Some(Arc::new(reader));
                Refresh::Loaded
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "GeoIP database could not be read as a MaxMind DB (.mmdb) file; \
                     keeping any database already loaded, otherwise sign-in locations \
                     show as \"unknown\""
                );
                Refresh::Failed
            }
        }
    }

    /// Check the database file every [`RELOAD_CHECK_INTERVAL`] and reload it
    /// when it changes, until shutdown. Does nothing when no database is
    /// configured.
    pub fn spawn_reloader(
        self: &Arc<Self>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        self.path.as_ref()?;
        let geoip = Arc::clone(self);
        Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => return,
                    _ = tokio::time::sleep(RELOAD_CHECK_INTERVAL) => {}
                }
                let g = Arc::clone(&geoip);
                if let Err(e) = tokio::task::spawn_blocking(move || g.refresh()).await {
                    warn!(error = %e, "GeoIP reload check failed");
                }
            }
        }))
    }

    /// City and country of `ip` from the local database: `"City, CC"`, or the
    /// country alone when the record has no city. `None` when no database is
    /// loaded, the address is not publicly routable (private, loopback,
    /// link-local, CGNAT, unique-local, documentation …) or has no record.
    pub fn locate(&self, ip: IpAddr) -> Option<String> {
        let ip = ip.to_canonical();
        if !is_locatable(ip) {
            return None;
        }
        let reader = self.reader.read().ok()?.as_ref().map(Arc::clone)?;
        let city = reader.lookup(ip).ok()?.decode::<geoip2::City>().ok()??;
        format_location(&city)
    }
}

/// `"City, CC"`, else the country's English name, else its ISO code.
fn format_location(rec: &geoip2::City<'_>) -> Option<String> {
    let clean = |s: Option<&str>| {
        s.map(|s| {
            s.chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty())
    };
    let city = clean(rec.city.names.english);
    let code = clean(rec.country.iso_code);
    let country = clean(rec.country.names.english);
    let out = match (city, code, country) {
        (Some(city), Some(code), _) => format!("{city}, {code}"),
        (Some(city), None, Some(country)) => format!("{city}, {country}"),
        (None, _, Some(country)) => country,
        (None, Some(code), None) => code,
        // A city with no country at all says too little to show.
        (Some(_), None, None) | (None, None, None) => return None,
    };
    Some(out.chars().take(MAX_LOCATION_CHARS).collect())
}

/// Whether `ip` (canonical form) is publicly routable, so worth a lookup.
/// Everything else — private, loopback, link-local, CGNAT, unique-local,
/// documentation, benchmarking, multicast, reserved — says nothing about where
/// a person is.
pub fn is_locatable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_private() // 10/8, 172.16/12, 192.168/16
        || ip.is_loopback() // 127/8
        || ip.is_link_local() // 169.254/16
        || ip.is_broadcast()
        || ip.is_multicast() // 224/4
        || ip.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || a == 0 // "this network"
        || (a == 100 && (b & 0xc0) == 64) // CGNAT 100.64/10
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 198 && (b & 0xfe) == 18) // benchmarking 198.18/15
        || a >= 240) // reserved 240/4
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation 2001:db8::/32
        || (s[0] & 0xfff0) == 0x3ff0 // documentation 3fff::/20
        || (s[0] == 0x0100 && s[1..4] == [0, 0, 0])) // discard-only 100::/64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// A minimal MaxMind DB writer — just enough of the format
    /// (<https://maxmind.github.io/MaxMind-DB/>) to build test databases
    /// without a fixture file or a writer dependency: an IPv6 search tree
    /// with 24-bit records, the data section, and the metadata.
    mod mmdb {
        pub enum V {
            S(String),
            U16(u16),
            U32(u32),
            U64(u64),
            Map(Vec<(String, V)>),
            Arr(Vec<V>),
        }

        pub fn s(v: &str) -> V {
            V::S(v.into())
        }

        pub fn map(kv: Vec<(&str, V)>) -> V {
            V::Map(kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
        }

        fn ctrl(out: &mut Vec<u8>, ty: u8, size: usize) {
            let (low, ext): (u8, Vec<u8>) = if size < 29 {
                (size as u8, vec![])
            } else if size < 29 + 256 {
                (29, vec![(size - 29) as u8])
            } else {
                (30, ((size - 285) as u16).to_be_bytes().to_vec())
            };
            if ty <= 7 {
                out.push((ty << 5) | low);
            } else {
                out.push(low);
                out.push(ty - 7);
            }
            out.extend(ext);
        }

        fn uint(out: &mut Vec<u8>, ty: u8, v: u64) {
            let bytes = v.to_be_bytes();
            let skip = bytes.iter().take_while(|b| **b == 0).count();
            ctrl(out, ty, 8 - skip);
            out.extend(&bytes[skip..]);
        }

        pub fn encode(out: &mut Vec<u8>, v: &V) {
            match v {
                V::S(s) => {
                    ctrl(out, 2, s.len());
                    out.extend(s.as_bytes());
                }
                V::U16(n) => uint(out, 5, u64::from(*n)),
                V::U32(n) => uint(out, 6, u64::from(*n)),
                V::U64(n) => uint(out, 9, *n),
                V::Map(kv) => {
                    ctrl(out, 7, kv.len());
                    for (k, v) in kv {
                        encode(out, &V::S(k.clone()));
                        encode(out, v);
                    }
                }
                V::Arr(items) => {
                    ctrl(out, 11, items.len());
                    for v in items {
                        encode(out, v);
                    }
                }
            }
        }

        #[derive(Clone, Copy)]
        enum Rec {
            Empty,
            Node(usize),
            Data(usize),
        }

        /// A database of `(IPv4 network, prefix length, record)` rows, the
        /// IPv4 space placed at `::/96` as real databases do.
        pub fn build(rows: &[(&str, u8, V)]) -> Vec<u8> {
            let mut data = Vec::new();
            let mut nodes: Vec<[Rec; 2]> = vec![[Rec::Empty; 2]];
            for (net, prefix, record) in rows {
                let offset = data.len();
                encode(&mut data, record);
                let v4: std::net::Ipv4Addr = net.parse().unwrap();
                let addr = u128::from(v4.to_ipv6_compatible());
                let depth = 96 + usize::from(*prefix);
                let mut node = 0;
                for i in 0..depth {
                    let bit = ((addr >> (127 - i)) & 1) as usize;
                    if i == depth - 1 {
                        nodes[node][bit] = Rec::Data(offset);
                    } else {
                        node = match nodes[node][bit] {
                            Rec::Node(n) => n,
                            _ => {
                                nodes.push([Rec::Empty; 2]);
                                let n = nodes.len() - 1;
                                nodes[node][bit] = Rec::Node(n);
                                n
                            }
                        };
                    }
                }
            }
            let count = nodes.len();
            let mut out = Vec::new();
            for pair in &nodes {
                for rec in pair {
                    let v = match *rec {
                        Rec::Node(n) => n,
                        Rec::Empty => count,
                        Rec::Data(off) => count + 16 + off,
                    } as u32;
                    out.extend(&v.to_be_bytes()[1..]);
                }
            }
            out.extend([0u8; 16]);
            out.extend(&data);
            out.extend(b"\xAB\xCD\xEFMaxMind.com");
            let meta = map(vec![
                ("binary_format_major_version", V::U16(2)),
                ("binary_format_minor_version", V::U16(0)),
                ("build_epoch", V::U64(1_790_000_000)),
                ("database_type", s("DBIP-City-Lite")),
                ("description", map(vec![("en", s("vtc-service test db"))])),
                ("ip_version", V::U16(6)),
                ("languages", V::Arr(vec![s("en")])),
                ("node_count", V::U32(count as u32)),
                ("record_size", V::U16(24)),
            ]);
            encode(&mut out, &meta);
            out
        }

        pub fn city(city: &str, code: &str, country: &str) -> V {
            map(vec![
                ("city", map(vec![("names", map(vec![("en", s(city))]))])),
                (
                    "country",
                    map(vec![
                        ("iso_code", s(code)),
                        ("names", map(vec![("en", s(country))])),
                    ]),
                ),
            ])
        }

        pub fn country_only(code: &str, country: &str) -> V {
            map(vec![(
                "country",
                map(vec![
                    ("iso_code", s(code)),
                    ("names", map(vec![("en", s(country))])),
                ]),
            )])
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn write_db(path: &Path, bytes: &[u8], mtime_secs: u64) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(bytes).unwrap();
        // An explicit mtime: two writes in one clock tick must still differ.
        f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(mtime_secs))
            .unwrap();
    }

    fn vienna_db() -> Vec<u8> {
        mmdb::build(&[
            ("81.2.69.0", 24, mmdb::city("Vienna", "AT", "Austria")),
            ("89.160.20.0", 24, mmdb::country_only("SE", "Sweden")),
        ])
    }

    /// Run `f` with a subscriber capturing WARN and above, and return them.
    fn capture_warnings<T>(f: impl FnOnce() -> T) -> (T, String) {
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        (out, logs)
    }

    #[test]
    fn unset_database_locates_nothing() {
        let g = GeoIp::open(None);
        assert!(!g.is_loaded());
        assert_eq!(g.refresh(), Refresh::Disabled);
        assert_eq!(g.locate(ip("81.2.69.160")), None);
        assert_eq!(GeoIp::disabled().locate(ip("81.2.69.160")), None);
    }

    #[test]
    fn known_address_is_city_and_country_code() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("city.mmdb");
        write_db(&path, &vienna_db(), 1_000);
        let g = GeoIp::open(Some(path));
        assert!(g.is_loaded());
        assert_eq!(g.locate(ip("81.2.69.160")).as_deref(), Some("Vienna, AT"));
        // The same address as an IPv4-mapped IPv6 one (a dual-stack socket).
        assert_eq!(
            g.locate(ip("::ffff:81.2.69.160")).as_deref(),
            Some("Vienna, AT")
        );
        // An address the database has no record for.
        assert_eq!(g.locate(ip("8.8.8.8")), None);
        assert_eq!(g.locate(ip("2a00:1450::1")), None);
    }

    #[test]
    fn country_only_record_is_the_country() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("city.mmdb");
        write_db(&path, &vienna_db(), 1_000);
        let g = GeoIp::open(Some(path));
        assert_eq!(g.locate(ip("89.160.20.128")).as_deref(), Some("Sweden"));
    }

    #[test]
    fn non_public_addresses_are_never_looked_up() {
        // A database answering for every IPv4 address: whatever comes back as
        // `None` was refused before the lookup.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("all.mmdb");
        let everywhere = mmdb::build(&[
            ("0.0.0.0", 1, mmdb::city("Nowhere", "ZZ", "Zedland")),
            ("128.0.0.0", 1, mmdb::city("Nowhere", "ZZ", "Zedland")),
        ]);
        write_db(&path, &everywhere, 1_000);
        let g = GeoIp::open(Some(path));
        assert_eq!(g.locate(ip("81.2.69.160")).as_deref(), Some("Nowhere, ZZ"));
        for addr in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.5",
            "198.18.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "::ffff:192.168.1.1",
            "::ffff:127.0.0.1",
        ] {
            assert_eq!(g.locate(ip(addr)), None, "{addr} must not be located");
        }
        for addr in [
            "10.1.2.3",
            "100.64.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "fc00::1",
            "2001:db8::1",
            "3fff::1",
            "ff02::1",
            "100::1",
        ] {
            assert!(!is_locatable(ip(addr).to_canonical()), "{addr}");
        }
        // CGNAT is 100.64/10 only; its neighbours are public.
        assert!(is_locatable(ip("100.63.255.255")));
        assert!(is_locatable(ip("100.128.0.1")));
        assert!(is_locatable(ip("2a00:1450::1")));
    }

    #[test]
    fn a_replaced_file_is_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("city.mmdb");
        write_db(&path, &vienna_db(), 1_000);
        let g = GeoIp::open(Some(path.clone()));
        assert_eq!(g.locate(ip("81.2.69.160")).as_deref(), Some("Vienna, AT"));
        assert_eq!(g.refresh(), Refresh::Unchanged);

        // Next month's database, moved into place.
        let next = dir.path().join("city.mmdb.new");
        let moved = mmdb::build(&[("81.2.69.0", 24, mmdb::city("Graz", "AT", "Austria"))]);
        write_db(&next, &moved, 2_000);
        std::fs::rename(&next, &path).unwrap();
        assert_eq!(g.refresh(), Refresh::Loaded);
        assert_eq!(g.locate(ip("81.2.69.160")).as_deref(), Some("Graz, AT"));
        assert_eq!(g.locate(ip("89.160.20.128")), None);
        assert_eq!(g.refresh(), Refresh::Unchanged);
    }

    #[test]
    fn a_bad_replacement_keeps_the_loaded_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("city.mmdb");
        write_db(&path, &vienna_db(), 1_000);
        let g = GeoIp::open(Some(path.clone()));
        // A half-written download.
        write_db(&path, &vienna_db()[..40], 2_000);
        let (outcome, logs) = capture_warnings(|| g.refresh());
        assert_eq!(outcome, Refresh::Failed);
        assert!(logs.contains("WARN"), "{logs}");
        assert_eq!(g.locate(ip("81.2.69.160")).as_deref(), Some("Vienna, AT"));
        // Not re-read, nor re-warned about, until it changes again.
        let (outcome, logs) = capture_warnings(|| g.refresh());
        assert_eq!(outcome, Refresh::Unchanged);
        assert!(logs.is_empty(), "{logs}");
    }

    #[test]
    fn a_bad_file_at_startup_warns_and_locates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("city.mmdb");
        std::fs::write(&path, b"not a database").unwrap();
        let (g, logs) = capture_warnings(|| GeoIp::open(Some(path.clone())));
        assert!(!g.is_loaded());
        assert!(
            logs.contains("WARN") && logs.contains("city.mmdb"),
            "{logs}"
        );
        assert_eq!(g.locate(ip("81.2.69.160")), None);

        // A missing file is the same, warned about once.
        let missing = dir.path().join("absent.mmdb");
        let (g, logs) = capture_warnings(|| GeoIp::open(Some(missing.clone())));
        assert!(!g.is_loaded());
        assert!(logs.contains("absent.mmdb"), "{logs}");
        let (_, logs) = capture_warnings(|| g.refresh());
        assert!(logs.is_empty(), "{logs}");

        // ...and picked up once a good file appears.
        write_db(&missing, &vienna_db(), 1_000);
        assert_eq!(g.refresh(), Refresh::Loaded);
        assert_eq!(g.locate(ip("81.2.69.160")).as_deref(), Some("Vienna, AT"));
    }

    #[test]
    fn lookups_never_log_the_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("city.mmdb");
        write_db(&path, &vienna_db(), 1_000);
        let (_, logs) = capture_warnings(|| {
            let g = GeoIp::open(Some(path.clone()));
            g.locate(ip("81.2.69.160"));
            g.locate(ip("8.8.8.8"));
            g.locate(ip("10.0.0.1"));
        });
        for addr in ["81.2.69.160", "8.8.8.8", "10.0.0.1"] {
            assert!(!logs.contains(addr), "{logs}");
        }
    }

    #[test]
    fn location_fits_the_schema() {
        let long = "x".repeat(300);
        let rec = mmdb::build(&[
            ("81.2.69.0", 24, mmdb::city(&long, "AT", "Austria")),
            ("81.2.70.0", 24, mmdb::city("Wien\u{7}\n", "AT", "Austria")),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("city.mmdb");
        write_db(&path, &rec, 1_000);
        let g = GeoIp::open(Some(path));
        let got = g.locate(ip("81.2.69.1")).unwrap();
        assert_eq!(got.chars().count(), MAX_LOCATION_CHARS);
        assert_eq!(g.locate(ip("81.2.70.1")).as_deref(), Some("Wien, AT"));
    }
}
