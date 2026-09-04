//! What a process does when the security material it read at boot is replaced
//! underneath it.
//!
//! **Security material is read ONCE, when the listener is built.** tonic 0.14
//! hands its acceptor an `Arc<ServerConfig>` built there and then, and documents
//! its TLS settings as ignored under `serve_with_incoming` — the only
//! custom-acceptor path there is. So a pod started today serves its day-0 leaf
//! until it restarts, whatever cert-manager writes into the Secret meanwhile.
//!
//! The charts mount those Secrets as DIRECTORIES rather than with `subPath`,
//! deliberately, so kubelet does refresh the files inside the pod. Only the
//! process never re-reads them.
//!
//! # The ruling: exit on change (ADR-0523)
//!
//! [`watch`] polls a digest of every file the process read at boot — one per
//! file, so a change can be reported by NAME. On a change it logs which file,
//! and the old and new leaf fingerprints, waits out a per-pod splay, and ends.
//! The caller selects on that, drains, and exits 0; the supervisor restarts the
//! process onto the fresh file.
//!
//! **THE WATCH SET IS NOT "THE TLS FILES", and that is the rule rather than a
//! detail.** ADR-0523 is about PROVENANCE, never payload: every file the process
//! read at boot is watched, whatever the bytes inside it are for. `iam` watches
//! a broker password and a token-issuing CA on exactly this ground — neither is
//! transport material, both are mounted as directories precisely so they can
//! rotate, and both are read exactly once. A rule that admitted only
//! certificates would let each of them go stale in silence.
//!
//! # How a service says what it read
//!
//! By implementing [`Material`] on the configuration types it already has, and
//! handing the list to [`Inputs::of`]. That is the whole seam, and it exists for
//! a reason spelled out in [`Inputs::of`]'s own documentation: the watch set
//! used to be assembled statement-by-statement in `main.rs`, where no test can
//! reach it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

/// The gauge carrying the expiry of the certificate a process actually loaded.
///
/// **A NAME IS AN INTERFACE TO A DASHBOARD.** Renaming it blanks the panel
/// rather than failing anything, so it is a constant and a test asserts its
/// spelling.
pub const CERTIFICATE_NOT_AFTER: &str = "yadgar_tls_certificate_not_after_seconds";

/// How often the watched files are re-hashed.
const POLL_KEY: &str = "TLS_ROTATION_POLL_SECS";

/// The top of the range this pod's splay is drawn from.
const SPLAY_MAX_KEY: &str = "TLS_ROTATION_SPLAY_MAX_SECS";

const DEFAULT_POLL: Duration = Duration::from_secs(60);

const DEFAULT_SPLAY_MAX: Duration = Duration::from_secs(300);

/// A schedule a deployment stated and this process cannot use.
#[derive(Debug, thiserror::Error)]
pub enum ScheduleError {
    #[error(
        "{key} is {value:?}, which is not a whole number of seconds ({source}). It is refused \
         rather than replaced with the default, because a deployment that believes it set this \
         and did not would run an interval nobody chose and see nothing wrong."
    )]
    Unparsable {
        key: &'static str,
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error(
        "{POLL_KEY} is 0, which is not a poll interval. Sleeping for no time at all turns the \
         rotation watcher into a loop that re-reads and re-hashes the watched files as fast as a \
         core allows, for the life of the pod. Set it to at least 1. Nothing is turned OFF by \
         setting it to 0 — an empty watch set is what leaves the watcher idle. {SPLAY_MAX_KEY} is \
         different: 0 there means exit at once, which is a supported choice."
    )]
    ZeroPoll,
}

/// How often to look, and how long this pod waits before acting on what it saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    poll: Duration,
    splay_max: Duration,
}

impl Default for Schedule {
    fn default() -> Self {
        Self::new(DEFAULT_POLL, DEFAULT_SPLAY_MAX)
    }
}

impl Schedule {
    pub fn new(poll: Duration, splay_max: Duration) -> Self {
        Self { poll, splay_max }
    }

    /// Read the schedule from the environment.
    ///
    /// # Errors
    ///
    /// If either variable is set to something that is not a whole number of
    /// seconds, or the poll interval is zero. See [`ScheduleError`].
    pub fn from_env() -> Result<Self, ScheduleError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The same, against any lookup — which is what makes it testable without
    /// mutating process-global state.
    ///
    /// # Errors
    ///
    /// As [`Schedule::from_env`].
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ScheduleError> {
        let seconds = |key: &'static str, default: Duration| match lookup(key) {
            None => Ok(default),
            Some(raw) => raw
                .trim()
                .parse()
                .map(Duration::from_secs)
                .map_err(|source| ScheduleError::Unparsable {
                    key,
                    value: raw,
                    source,
                }),
        };

        let poll = seconds(POLL_KEY, DEFAULT_POLL)?;
        if poll.is_zero() {
            return Err(ScheduleError::ZeroPoll);
        }
        Ok(Self::new(poll, seconds(SPLAY_MAX_KEY, DEFAULT_SPLAY_MAX)?))
    }

    pub fn poll(&self) -> Duration {
        self.poll
    }

    pub fn splay_max(&self) -> Duration {
        self.splay_max
    }
}

/// Which of the two certificates a process can hold this one is.
///
/// One process presents both: the leaf its listener serves, and the leaf it
/// presents to an upstream that verifies callers (ADR-0516). Both expire, both
/// are exported, and an expired CLIENT leaf stops the hop just as hard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presented {
    /// The certificate this process's listener serves.
    Serving,
    /// The certificate this process presents to an upstream.
    Client,
}

impl Presented {
    /// The `kind` label on [`CERTIFICATE_NOT_AFTER`]. Bounded at two values,
    /// which is what makes it a label rather than a cardinality leak.
    pub fn label(self) -> &'static str {
        match self {
            Self::Serving => "serving",
            Self::Client => "client",
        }
    }
}

/// One file a process read at boot, and the role it plays.
///
/// A file is either a certificate this process PRESENTS — whose expiry is
/// exported and whose fingerprint names it in a log line — or anything else the
/// process read: a private key, a CA bundle, a password, a token-issuing CA.
/// Both are watched identically. The role only decides what is reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct File<'a> {
    path: &'a Path,
    presented: Option<Presented>,
}

impl<'a> File<'a> {
    /// A file the process read at boot whose contents are not a certificate this
    /// process presents.
    pub fn read(path: &'a Path) -> Self {
        Self {
            path,
            presented: None,
        }
    }

    /// A certificate this process presents. Its leaf is parsed, fingerprinted
    /// and its expiry exported.
    pub fn certificate(which: Presented, path: &'a Path) -> Self {
        Self {
            path,
            presented: Some(which),
        }
    }

    pub fn path(&self) -> &'a Path {
        self.path
    }
}

/// Configuration that caused this process to read files at boot.
///
/// A service implements this on the types it already has — its listener's TLS
/// configuration, an upstream's, a broker credential — and never on a bag of
/// paths. **The difference is the whole point.** A helper that spelled paths out
/// proves only that the watcher watches what it is handed; implementing
/// `Material` on the configuration proves that a DEPLOYMENT'S configuration puts
/// them there, which is the half that can silently be wrong.
pub trait Material {
    /// Every file this piece of configuration read at boot, in the order they
    /// should be reported.
    fn files(&self) -> Vec<File<'_>>;
}

impl<M: Material + ?Sized> Material for &M {
    fn files(&self) -> Vec<File<'_>> {
        (**self).files()
    }
}

/// **Nothing configured is nothing to watch**, and that is the ordinary case
/// rather than an edge one: every TLS setting in this estate is opt-in and off
/// by default, so a `None` must contribute an empty list rather than needing a
/// branch at every call site.
impl<M: Material> Material for Option<M> {
    fn files(&self) -> Vec<File<'_>> {
        self.as_ref().map(Material::files).unwrap_or_default()
    }
}

impl Material for Path {
    fn files(&self) -> Vec<File<'_>> {
        vec![File::read(self)]
    }
}

impl Material for PathBuf {
    fn files(&self) -> Vec<File<'_>> {
        vec![File::read(self.as_path())]
    }
}

/// A certificate read at boot, kept as the DER the process actually loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Leaf {
    der: Option<Vec<u8>>,
    path: PathBuf,
}

/// One watched file and the digest it held when it was read.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Watched {
    path: PathBuf,
    loaded: Option<[u8; 32]>,
}

/// Everything this process read at boot, hashed as it was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    service: &'static str,
    serving: Option<Leaf>,
    client: Option<Leaf>,
    files: Vec<Watched>,
}

impl Inputs {
    /// An empty watch set, labelled with the service that owns it.
    ///
    /// The service name is stored rather than passed to
    /// [`Inputs::export_not_after`] because it is a property of the process, not
    /// of the moment the gauge is written — and a parameter would be one more
    /// thing a call site could get wrong.
    pub fn new(service: &'static str) -> Self {
        Self {
            service,
            serving: None,
            client: None,
            files: Vec::new(),
        }
    }

    /// **THE FOLD, and the reason this crate exists.**
    ///
    /// The watch set used to be built statement-by-statement inside `main.rs`,
    /// one builder call beside each piece of boot that read a file. No test
    /// spawns a binary, so deleting one of those calls compiled, passed the
    /// entire suite, and shipped a process that would never notice that file
    /// rotating. Three services, four calls each, not one of them killable.
    ///
    /// Here the set is a VALUE. A service's library returns the list, `main.rs`
    /// holds one expression, and a test calls the same function and asserts what
    /// came back. The fold over the list is tested in this crate; what each
    /// [`Material`] contributes is tested in the service that implements it.
    ///
    /// Order is preserved, and a path named twice is watched once — so an
    /// upstream and a listener sharing a CA bundle is hashed once and reported
    /// once.
    pub fn of(service: &'static str, materials: &[&dyn Material]) -> Self {
        materials
            .iter()
            .fold(Self::new(service), |inputs, material| {
                inputs.take(*material)
            })
    }

    /// Hash and record one piece of configuration NOW, beside the code that read
    /// it.
    ///
    /// **The baseline must be taken close to the read.** A watch set that
    /// remembered paths and hashed them when the watcher first polled would put
    /// the rest of boot inside a window where a kubelet swap becomes the
    /// baseline: the real rotation is then never noticed, and the gauge
    /// describes a certificate the listener is not serving.
    ///
    /// [`Inputs::of`] folds within boot rather than after it, which is the same
    /// sub-second window and not the sixty-second one. Use `take` where a
    /// service genuinely wants each hash beside its own read.
    pub fn take(self, material: &dyn Material) -> Self {
        material
            .files()
            .into_iter()
            .fold(self, |inputs, file| match file.presented {
                None => inputs.also(file.path),
                Some(which) => inputs.certificate(which, file.path),
            })
    }

    /// Watch one more file, hashing it now. A path already watched is not added
    /// twice.
    pub fn also(self, path: &Path) -> Self {
        if self.is_watching(path) {
            return self;
        }
        let loaded = std::fs::read(path).ok().as_deref().map(digest_of);
        self.watch(path, loaded)
    }

    /// Record a certificate this process presents, and watch its file.
    ///
    /// The LEAF is kept — the first certificate in the file — because that is
    /// what the listener serves. A file holding leaf-then-issuer is what
    /// cert-manager writes, and reporting the issuer's expiry keeps a gauge
    /// green for a decade while the certificate in use ages out.
    fn certificate(mut self, which: Presented, path: &Path) -> Self {
        let bytes = std::fs::read(path).ok();
        let leaf = Leaf {
            der: bytes
                .as_deref()
                .and_then(|b| CertificateDer::pem_slice_iter(b).next()?.ok())
                .map(|der| der.to_vec()),
            path: path.to_path_buf(),
        };
        match which {
            Presented::Serving => self.serving = Some(leaf),
            Presented::Client => self.client = Some(leaf),
        }
        self.watch(path, bytes.as_deref().map(digest_of))
    }

    fn watch(mut self, path: &Path, loaded: Option<[u8; 32]>) -> Self {
        if self.is_watching(path) {
            return self;
        }
        self.files.push(Watched {
            path: path.to_path_buf(),
            loaded,
        });
        self
    }

    fn is_watching(&self, path: &Path) -> bool {
        self.files.iter().any(|f| f.path == path)
    }

    /// Nothing was read, so nothing can rotate. [`watch`] never ends on an empty
    /// set — the alternative is exiting a process that holds no material at all.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Every file in the watch set, in the order it was added. This is what a
    /// test asserts membership against.
    pub fn watched(&self) -> Vec<&Path> {
        self.files.iter().map(|f| f.path.as_path()).collect()
    }

    /// The digests taken at boot, or `None` if any file could not be read.
    fn baseline(&self) -> Option<Vec<[u8; 32]>> {
        self.files.iter().map(|f| f.loaded).collect()
    }

    /// The digests now on disk, or `None` if any file could not be read — which
    /// is a TRANSIENT state during a kubelet rewrite, not a rotation.
    fn on_disk(&self) -> Option<Vec<[u8; 32]>> {
        self.files
            .iter()
            .map(|f| std::fs::read(&f.path).ok().as_deref().map(digest_of))
            .collect()
    }

    fn differing(&self, current: &[[u8; 32]]) -> Vec<String> {
        self.files
            .iter()
            .zip(current)
            .filter(|(f, now)| f.loaded.as_ref() != Some(*now))
            .map(|(f, _)| f.path.display().to_string())
            .collect()
    }

    fn loaded(&self, which: Presented) -> Option<&Leaf> {
        match which {
            Presented::Serving => self.serving.as_ref(),
            Presented::Client => self.client.as_ref(),
        }
    }

    fn leaf(&self, which: Presented) -> Option<CertificateDer<'static>> {
        Some(CertificateDer::from(self.loaded(which)?.der.clone()?))
    }

    fn fingerprint_on_disk(&self, which: Presented) -> Option<String> {
        let bytes = std::fs::read(&self.loaded(which)?.path).ok()?;
        let der = CertificateDer::pem_slice_iter(&bytes).next()?.ok()?;
        Some(hex(&Sha256::digest(&der)))
    }

    /// What to print for a certificate: `none` if none was configured, `unknown`
    /// if one was and could not be read. **The two are different facts** and a
    /// single placeholder would hide the second inside the first.
    fn reported(&self, which: Presented, on_disk: bool) -> String {
        if self.loaded(which).is_none() {
            return absent();
        }
        let found = if on_disk {
            self.fingerprint_on_disk(which)
        } else {
            self.fingerprint(which)
        };
        found.unwrap_or_else(unknown)
    }

    /// SHA-256 over the loaded leaf's DER, hex. This NAMES the certificate the
    /// process is on.
    pub fn fingerprint(&self, which: Presented) -> Option<String> {
        Some(hex(&Sha256::digest(self.leaf(which)?)))
    }

    /// The loaded leaf's expiry, as seconds since the epoch.
    pub fn not_after(&self, which: Presented) -> Option<i64> {
        let der = self.leaf(which)?;
        let (_, parsed) = X509Certificate::from_der(&der).ok()?;
        Some(parsed.validity().not_after.timestamp())
    }

    /// Publish [`CERTIFICATE_NOT_AFTER`] for every certificate this process
    /// loaded, and nothing for one it did not.
    ///
    /// **An invented number is worse than a missing series**: a dashboard cannot
    /// tell it apart from a real one.
    pub fn export_not_after(&self) {
        for which in [Presented::Serving, Presented::Client] {
            let Some(seconds) = self.not_after(which) else {
                continue;
            };
            metrics::gauge!(
                CERTIFICATE_NOT_AFTER,
                "service" => self.service,
                "kind" => which.label(),
            )
            .set(seconds as f64);
            tracing::info!(
                kind = which.label(),
                not_after = seconds,
                fingerprint = self.fingerprint(which).unwrap_or_else(unknown),
                "certificate loaded; its expiry is exported as {CERTIFICATE_NOT_AFTER}"
            );
        }
    }
}

/// Resolve when the material read at boot has changed on disk and this pod's
/// splay has elapsed. Never resolves otherwise.
///
/// The caller selects on this beside [`crate::shutdown`], so one drain path
/// serves both reasons to take it.
pub async fn watch(inputs: Inputs, schedule: Schedule) {
    watch_with_seed(inputs, schedule, seed()).await
}

/// [`watch`] with the splay's seed supplied, so a test can assert an exact wait
/// rather than a coin toss.
pub async fn watch_with_seed(inputs: Inputs, schedule: Schedule, seed: u64) {
    if inputs.is_empty() {
        // NOTHING TO WATCH IS NOT A REASON TO EXIT. A process holding no
        // material has nothing that can go stale.
        tracing::debug!("no watched files; this process will not exit on a rotation");
        never().await
    }
    let Some(booted) = inputs.baseline() else {
        // A watcher that cannot take a baseline is one that would compare
        // against nothing. Today's behaviour, never worse — see ADR-0523.
        tracing::warn!("the watched files could not be read; rotation will not be noticed");
        never().await
    };
    let serving_before = inputs.reported(Presented::Serving, false);
    let client_before = inputs.reported(Presented::Client, false);

    loop {
        tokio::time::sleep(schedule.poll).await;
        let Some(current) = inputs.on_disk() else {
            // TRANSIENT, not a rotation: kubelet is halfway through rewriting
            // the mount. Acting on it exits the process for nothing.
            tracing::warn!("a watched file could not be read; keeping what was already loaded");
            continue;
        };
        if current == booted {
            continue;
        }

        let waited = splay(schedule.splay_max, seed);
        tracing::warn!(
            serving_before,
            serving_after = inputs.reported(Presented::Serving, true),
            client_before,
            client_after = inputs.reported(Presented::Client, true),
            changed = inputs.differing(&current).join(", "),
            splay_secs = waited.as_secs(),
            "the files read at boot have CHANGED on disk. A running listener's certificate \
             cannot be swapped in place, so this process drains and exits 0 to be restarted \
             onto the new one; the wait is this pod's splay, so both replicas do not go at once"
        );
        tokio::time::sleep(waited).await;
        tracing::warn!("splay elapsed; draining");
        return;
    }
}

/// This pod's share of the splay range, drawn from `seed`.
///
/// Spans the whole range so two pods rarely collide, and never overshoots the
/// maximum however absurd it is.
fn splay(max: Duration, seed: u64) -> Duration {
    let millis = u128::from(seed).saturating_mul(max.as_millis()) / u128::from(u64::MAX);
    Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX)).min(max)
}

/// A seed that differs between pods without any coordination: the pid and the
/// clock, hashed.
fn seed() -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 is 32 bytes"))
}

async fn never() -> ! {
    let never: std::convert::Infallible = std::future::pending().await;
    match never {}
}

fn unknown() -> String {
    "unknown".to_string()
}

fn absent() -> String {
    "none".to_string()
}

fn digest_of(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: Duration = Duration::from_secs(300);

    #[test]
    fn the_splay_spans_the_whole_configured_range() {
        assert_eq!(splay(MAX, 0), Duration::ZERO);
        assert_eq!(splay(MAX, u64::MAX), MAX);
    }

    #[test]
    fn the_splay_never_exceeds_its_maximum() {
        for seed in [1, 7, 1_000, u64::MAX / 3, u64::MAX / 2, u64::MAX - 1] {
            assert!(splay(MAX, seed) <= MAX, "{seed} overshot");
        }
    }

    #[test]
    fn a_zero_maximum_waits_not_at_all() {
        assert_eq!(splay(Duration::ZERO, u64::MAX), Duration::ZERO);
    }

    #[test]
    fn different_seeds_wait_for_different_times() {
        let waits: std::collections::BTreeSet<_> =
            (1..=8).map(|n| splay(MAX, u64::MAX / 9 * n)).collect();
        assert_eq!(waits.len(), 8, "seeds must spread across the range");
    }

    #[test]
    fn the_seed_moves() {
        assert_ne!(seed(), seed());
    }

    #[test]
    fn nothing_configured_is_empty() {
        assert!(Inputs::new("test").is_empty());
        assert!(!Inputs::new("test")
            .also(Path::new("/etc/yadgar/tls.pem"))
            .is_empty());
    }

    #[test]
    fn an_unreadable_input_has_no_baseline() {
        let inputs = Inputs::new("test").also(Path::new("/etc/yadgar/quokka-4d81/absent.pem"));
        assert_eq!(inputs.baseline(), None);
        assert_eq!(inputs.on_disk(), None);
        assert_eq!(inputs.fingerprint(Presented::Serving), None);
        assert_eq!(inputs.not_after(Presented::Serving), None);
        assert_eq!(inputs.fingerprint(Presented::Client), None);
        assert_eq!(inputs.not_after(Presented::Client), None);
    }

    #[test]
    fn a_file_named_twice_is_watched_once() {
        let path = Path::new("/etc/yadgar/quokka-4d81/client.pem");
        let inputs = Inputs::new("test").also(path).also(path);
        assert_eq!(inputs.watched(), vec![path]);

        let both = Inputs::new("test")
            .certificate(Presented::Client, path)
            .also(path);
        assert_eq!(both.watched(), vec![path]);
    }

    #[test]
    fn an_absent_certificate_reads_differently_from_an_unreadable_one() {
        assert_eq!(
            Inputs::new("test").reported(Presented::Serving, false),
            "none"
        );

        let configured = Inputs::new("test").certificate(
            Presented::Serving,
            Path::new("/etc/yadgar/quokka-4d81/absent.pem"),
        );
        assert_eq!(configured.reported(Presented::Serving, false), "unknown");
        assert_eq!(configured.reported(Presented::Serving, true), "unknown");
    }

    #[test]
    fn an_absurd_maximum_neither_panics_nor_overshoots() {
        for max in [
            Duration::from_secs(20_000_000_000),
            Duration::from_secs(u64::MAX / 1000),
        ] {
            for seed in [0, 1, u64::MAX / 2, u64::MAX] {
                assert!(splay(max, seed) <= max, "{max:?}/{seed} overshot");
            }
        }
    }

    fn lookup<'a>(
        pairs: &'a [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn an_unconfigured_schedule_is_the_default_one() {
        assert_eq!(
            Schedule::from_lookup(lookup(&[])).unwrap(),
            Schedule::default()
        );
        assert_eq!(Schedule::default().poll(), Duration::from_secs(60));
        assert_eq!(Schedule::default().splay_max(), Duration::from_secs(300));
    }

    #[test]
    fn both_values_arrive() {
        let vars = [
            ("TLS_ROTATION_POLL_SECS", "17"),
            ("TLS_ROTATION_SPLAY_MAX_SECS", "941"),
        ];
        let schedule = Schedule::from_lookup(lookup(&vars)).unwrap();
        assert_eq!(schedule.poll(), Duration::from_secs(17));
        assert_eq!(schedule.splay_max(), Duration::from_secs(941));
    }

    #[test]
    fn a_zero_poll_interval_is_refused() {
        let vars = [("TLS_ROTATION_POLL_SECS", "0")];
        assert!(matches!(
            Schedule::from_lookup(lookup(&vars)),
            Err(ScheduleError::ZeroPoll)
        ));
    }

    #[test]
    fn a_zero_splay_is_allowed() {
        let vars = [("TLS_ROTATION_SPLAY_MAX_SECS", "0")];
        let schedule = Schedule::from_lookup(lookup(&vars)).unwrap();
        assert_eq!(schedule.splay_max(), Duration::ZERO);
        assert_eq!(schedule.poll(), Duration::from_secs(60));
    }

    #[test]
    fn a_value_that_cannot_be_parsed_is_refused() {
        for (key, value) in [
            ("TLS_ROTATION_POLL_SECS", ""),
            ("TLS_ROTATION_POLL_SECS", "60s"),
            ("TLS_ROTATION_POLL_SECS", "-1"),
            ("TLS_ROTATION_SPLAY_MAX_SECS", "five minutes"),
            ("TLS_ROTATION_SPLAY_MAX_SECS", "1.5"),
        ] {
            let vars = [(key, value)];
            assert!(
                matches!(
                    Schedule::from_lookup(lookup(&vars)),
                    Err(ScheduleError::Unparsable { key: named, .. }) if named == key
                ),
                "{key}={value:?} must be refused, naming the variable"
            );
        }
    }

    #[test]
    fn hex_renders_every_byte_as_two_digits() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
