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

/// How many of the watched files cannot be read.
///
/// **THIS IS THE INSTRUMENT THAT MAKES THE WATCHER'S OWN FAILURE VISIBLE.** A
/// file the watcher cannot read is one whose rotation it will never report, and
/// every other signal this crate emits stays perfectly healthy while that is
/// true — the log line scrolls away, the expiry gauge keeps describing the leaf
/// that WAS loaded, and the process serves on. A pod is expected to sit at zero
/// forever, so any other value is a condition rather than noise.
///
/// A COUNT, never one series per path. The paths are named in the log line
/// beside it; putting them in a label would make the cardinality of this metric
/// a property of a deployment's configuration, which D67 refuses.
///
/// The same naming rule applies as to [`CERTIFICATE_NOT_AFTER`]: renaming it
/// blanks a panel rather than failing anything, so it is a constant and a test
/// asserts its spelling.
pub const WATCHED_FILES_UNREADABLE: &str = "yadgar_rotation_watched_files_unreadable";

/// Where the configuration chart mounts what it renders.
///
/// **THIS IS AN ADDRESS, NOT A KNOB.** ADR-0569 governs the VALUE of a setting
/// and requires the refusal to name the file the value was looked for in — which
/// presumes the process already knows that path. A setting that said where
/// settings live would be an infinite regress, so this is a constant and a test
/// asserts its exact spelling.
///
/// The safety property, stated because it is the one way this can be wrong: the
/// chart's `mountPath` and this constant must agree. They disagree loudly rather
/// than quietly — a mismatch produces [`ScheduleError::Absent`], which names the
/// path this process looked in.
pub const CONFIG_DIR: &str = "/etc/yadgar/config";

/// The shared document, under [`CONFIG_DIR`].
///
/// The directory repeats the file name because the mount repeats it: ConfigMap
/// `shared` carries one key, `shared.yaml`, and is mounted at its own directory
/// so that one ConfigMap's rotation cannot disturb another's. The redundancy buys
/// something real — the path in a refusal is the same file name an operator edits
/// in `yadgarhq/config`, so the message points at the fix rather than at a mount.
pub const SHARED_DOCUMENT: &str = "shared/shared.yaml";

/// How often the watched files are re-hashed.
///
/// The KNOB constants are the whole path, because that is what a refusal has to
/// name for an operator to find the line: `shared.yaml` holds several sections
/// and `pollSeconds` alone would not say which one. The LEAF constants are what
/// the lookup uses, and they are derived from the same literal so the message
/// and the lookup cannot drift apart.
const POLL_LEAF: &str = "pollSeconds";
const SPLAY_MAX_LEAF: &str = "splayMaxSeconds";
const POLL_KNOB: &str = "tlsRotation.pollSeconds";

/// The top of the range this pod's splay is drawn from.
const SPLAY_MAX_KNOB: &str = "tlsRotation.splayMaxSeconds";

/// A schedule a deployment stated and this process cannot use, or did not state
/// at all.
///
/// **EVERY VARIANT REFUSES THE BOOT AND NAMES A FILE.** ADR-0569: a knob is read
/// from the configuration repository and from nowhere else, with no compiled-in
/// default, no system-level fallback and no last-resort constant. There used to
/// be two of those constants here — 60 seconds and 300 seconds — and an
/// installation that never set the knob ran them without anything saying so.
#[derive(Debug, thiserror::Error)]
pub enum ScheduleError {
    #[error(
        "{path} does not exist, so no configuration was read. It is the shared document of the \
         configuration chart in yadgarhq/config, mounted from the ConfigMap `shared`. There is no \
         default to fall back to (ADR-0569): every knob has one source and this is it. If the pod \
         reached this point at all the volume mounted, so the likely fault is a mountPath that \
         disagrees with the chart rather than a missing ConfigMap — a missing ConfigMap keeps the \
         pod in ContainerCreating instead."
    )]
    Absent { path: String },

    #[error(
        "A file this process must read exists and cannot be read. The likeliest cause is a \
         chart whose `mountPath` names the FILE rather than the directory holding it: kubelet \
         then creates a DIRECTORY at this path and the read fails as `Is a directory`. Mount the \
         ConfigMap at /etc/yadgar/config/<name> and let the key become the file inside it. \
         Reading {path} failed"
    )]
    Unreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "The file is either not parseable YAML at all, or a part of it is the wrong KIND: the \
         document must be a mapping, and `tlsRotation` within it must be a mapping of knobs \
         rather than a scalar or a list. Note that a wrong-KIND file is still valid YAML, so a \
         YAML linter will call it clean. {path} does not have the shape this reader expects"
    )]
    Malformed {
        path: String,
        #[source]
        source: serde_norway::Error,
    },

    #[error(
        "{knob} is not defined in {path}. That file is the only place it is read from — there is \
         no compiled-in default and no fallback (ADR-0569) — so this process refuses to start \
         rather than run a value nobody chose. Add the line to the document, or restore it from \
         the template in yadgarhq/config."
    )]
    Missing { knob: &'static str, path: String },

    #[error(
        "{knob} is present in {path} and has no value. That is a DIFFERENT fault from the knob \
         being missing and is reported separately on purpose: an empty setting is usually a \
         half-finished edit, and collapsing the two cases into one is how a deployment ends up \
         believing it configured something it did not."
    )]
    Empty { knob: &'static str, path: String },

    #[error(
        "A knob that is not a whole number of seconds is refused rather than replaced with a \
         default, because a deployment that believes it set this and did not would run an \
         interval nobody chose and see nothing wrong. {knob} in {path} is {value:?}"
    )]
    Unparsable {
        knob: &'static str,
        path: String,
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error(
        "{POLL_KNOB} in {path} is 0, which is not a poll interval. Sleeping for no time at all \
         turns the rotation watcher into a loop that re-reads and re-hashes the watched files as \
         fast as a core allows, for the life of the pod. Set it to at least 1. Nothing is turned \
         OFF by setting it to 0 — an empty watch set is what leaves the watcher idle. \
         {SPLAY_MAX_KNOB} is different: 0 there means exit at once, which is a supported choice."
    )]
    ZeroPoll { path: String },
}

/// The configuration document this process reads its knobs out of.
///
/// **A `Material` LIKE ANY OTHER, and that is the whole reload story.** ADR-0523
/// watches every file the process read at boot, so handing this to [`Inputs::of`]
/// alongside the TLS configuration puts the document in the watch set by the
/// existing rule: an operator edits `shared.yaml` in `yadgarhq/config`, Argo syncs
/// the ConfigMap, kubelet swaps the mounted file, the watcher sees a changed
/// digest, and the pod drains and restarts onto the new value. No new mechanism,
/// and no code beyond one more entry in the list a service already builds
/// (ADR-0570).
///
/// **A DIRECTORY MOUNT IS LOAD-BEARING.** A `subPath` mount is copied once at
/// container start and kubelet never updates it, so a chart that used one would
/// leave this file frozen for the life of the pod while the ConfigMap moved
/// underneath it — the watcher would see nothing and report nothing. The charts
/// mount the Secrets they read as directories for exactly this reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configuration {
    path: PathBuf,
}

impl Configuration {
    /// The document where the chart mounts it.
    pub fn mounted() -> Self {
        Self::under(CONFIG_DIR)
    }

    /// The same, under any root — which is what makes it testable without a
    /// cluster, and the seam that replaced `Schedule::from_lookup`.
    pub fn under(root: impl AsRef<Path>) -> Self {
        Self {
            path: root.as_ref().join(SHARED_DOCUMENT),
        }
    }

    /// The file the knobs are read from. This is what a refusal names.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the rotation schedule out of the document.
    ///
    /// # Errors
    ///
    /// Every way this file can fail to state a schedule: absent, unreadable,
    /// unparsable as YAML, missing the knob, holding it empty, holding something
    /// that is not a whole number of seconds, or asking for a zero poll interval.
    /// See [`ScheduleError`] — none of them has a fallback.
    pub fn schedule(&self) -> Result<Schedule, ScheduleError> {
        let where_ = || self.path.display().to_string();
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(ScheduleError::Absent { path: where_() })
            }
            Err(source) => {
                return Err(ScheduleError::Unreadable {
                    path: where_(),
                    source,
                })
            }
        };

        // `Option<Document>` rather than `Document`, because a file holding
        // nothing but comments is a YAML document whose value is null, and
        // deserialising null into a struct is an error that would be reported as
        // a malformed file. It is not malformed; it defines no knob, which is the
        // `Missing` case below and a much more useful thing to be told.
        let document: Option<Document> =
            serde_norway::from_str(&text).map_err(|source| ScheduleError::Malformed {
                path: where_(),
                source,
            })?;
        let section = document.and_then(|d| d.tls_rotation).unwrap_or_default();
        let poll = section.get(POLL_LEAF).cloned();
        let splay = section.get(SPLAY_MAX_LEAF).cloned();

        let poll = self.seconds(POLL_KNOB, poll)?;
        if poll.is_zero() {
            return Err(ScheduleError::ZeroPoll { path: where_() });
        }
        Ok(Schedule::new(poll, self.seconds(SPLAY_MAX_KNOB, splay)?))
    }

    /// One knob, and the four distinct ways it can fail to be a number.
    ///
    /// **ABSENT AND EMPTY ARE DIFFERENT CASES.** A `serde` field typed
    /// `Option<u64>` collapses them — `pollSeconds:` with nothing after it
    /// deserialises to `None` exactly as a missing key does — so the field is a
    /// `Value` and the distinction is drawn here.
    fn seconds(
        &self,
        knob: &'static str,
        value: Option<serde_norway::Value>,
    ) -> Result<Duration, ScheduleError> {
        let path = || self.path.display().to_string();
        let raw = match value {
            None => return Err(ScheduleError::Missing { knob, path: path() }),
            Some(serde_norway::Value::Null) => {
                return Err(ScheduleError::Empty { knob, path: path() })
            }
            // A NUMBER IS THE SHAPE THE TEMPLATE SHIPS, and a quoted one is
            // accepted beside it: `pollSeconds: "60"` is an operator writing the
            // right value in a slightly different way, and refusing it would
            // teach nothing. Everything else — a float, a list, a map, a word —
            // reaches `parse` and is refused by name.
            Some(other) => match other.as_u64() {
                Some(n) => return Ok(Duration::from_secs(n)),
                None => other
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| serde_norway::to_string(&other).unwrap_or_default()),
            },
        };
        if raw.trim().is_empty() {
            return Err(ScheduleError::Empty { knob, path: path() });
        }
        raw.trim()
            .parse()
            .map(Duration::from_secs)
            .map_err(|source| ScheduleError::Unparsable {
                knob,
                path: path(),
                value: raw,
                source,
            })
    }
}

impl Material for Configuration {
    fn files(&self) -> Vec<File<'_>> {
        vec![File::read(&self.path)]
    }
}

/// The document, carrying ONLY what this crate reads.
///
/// **`deny_unknown_fields` IS DELIBERATELY ABSENT.** `shared.yaml` holds knobs
/// owned by other code and will hold more; a parser that refused a key it had
/// not been told about would make adding somebody else's setting break the
/// rotation watcher in every service at once.
///
/// **THE SECTION IS A `Mapping` AND NOT A STRUCT, and that is the fix for the
/// collapse this file is about.** A field typed `Option<T>` cannot tell a key
/// that is absent from a key written with no value after it: serde deserialises
/// an explicit YAML `null` into `None`, exactly as it does a key that is not
/// there. That was MEASURED here rather than assumed — the first implementation
/// used `Option<serde_norway::Value>` on the belief that a `Value` would preserve
/// the difference, and the test asserting the two faults differ FAILED, reporting
/// `pollSeconds:` as a missing knob. Looking the key up in a map asks the
/// question the struct cannot: is it there, and if so what is in it.
#[derive(serde::Deserialize)]
struct Document {
    #[serde(rename = "tlsRotation")]
    tls_rotation: Option<serde_norway::Mapping>,
}

/// How often to look, and how long this pod waits before acting on what it saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    poll: Duration,
    splay_max: Duration,
}

impl Schedule {
    pub fn new(poll: Duration, splay_max: Duration) -> Self {
        Self { poll, splay_max }
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

    /// The watched files this process could NOT read at boot.
    ///
    /// Each is a path a DEPLOYMENT named and the process then failed to read.
    /// They stay in the watch set: dropping them would make the set quietly
    /// smaller than the configuration that produced it, which is the class of
    /// defect [`Inputs::of`] exists to close.
    pub fn unread_at_boot(&self) -> Vec<&Path> {
        self.files
            .iter()
            .filter(|f| f.loaded.is_none())
            .map(|f| f.path.as_path())
            .collect()
    }

    /// The digest each watched file holds NOW, `None` where it cannot be read.
    ///
    /// **ONE ENTRY PER FILE, NEVER ONE ANSWER FOR THE SET.** This used to
    /// `collect()` into an `Option<Vec<_>>`, so a single unreadable file
    /// answered `None` for all of them and every poll fell into the transient
    /// arm — six files rotating perfectly well went unnoticed for as long as one
    /// stayed gone.
    fn on_disk(&self) -> Vec<Option<[u8; 32]>> {
        self.files
            .iter()
            .map(|f| std::fs::read(&f.path).ok().as_deref().map(digest_of))
            .collect()
    }

    /// The watched files whose contents are not what this process loaded.
    ///
    /// **A FILE THAT CANNOT BE READ RIGHT NOW IS NOT ONE OF THEM.** That is the
    /// transient state kubelet passes through while it rewrites a mount, and
    /// acting on it would exit the process over a directory that is about to be
    /// fine — a watcher whose failure is worse than not having one.
    ///
    /// The reverse direction IS a change, and always was this function's answer:
    /// a file with no baseline that now reads is material the process never
    /// loaded, so `None != Some(digest)` reports it. Only `baseline()`'s collapse
    /// made that answer unreachable.
    fn differing(&self, current: &[Option<[u8; 32]>]) -> Vec<String> {
        self.files
            .iter()
            .zip(current)
            .filter(|(f, now)| now.is_some() && f.loaded != **now)
            .map(|(f, _)| f.path.display().to_string())
            .collect()
    }

    /// The watched files that cannot be read at this instant.
    fn unreadable(&self, current: &[Option<[u8; 32]>]) -> Vec<String> {
        self.files
            .iter()
            .zip(current)
            .filter(|(_, now)| now.is_none())
            .map(|(f, _)| f.path.display().to_string())
            .collect()
    }

    fn publish_unreadable(&self, count: usize) {
        metrics::gauge!(WATCHED_FILES_UNREADABLE, "service" => self.service).set(count as f64);
    }

    /// Publish [`WATCHED_FILES_UNREADABLE`] for the watched files that cannot be
    /// read right now, and name them.
    ///
    /// **A ZERO HERE IS A MEASUREMENT, WHICH IS WHY THIS PUBLISHES
    /// UNCONDITIONALLY** — and it is the opposite call from
    /// [`Inputs::export_not_after`], deliberately. An expiry for a certificate
    /// this process never loaded would be an invented number a dashboard cannot
    /// tell from a real one. "None of the watched files is unreadable" is not
    /// invented; it is the answer, and a series that appears only once something
    /// is wrong cannot be told apart from an exporter that is not running.
    pub fn export_unreadable(&self) -> Vec<String> {
        let names = self.unreadable(&self.on_disk());
        self.publish_unreadable(names.len());
        names
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
    // BEFORE THE FIRST POLL, AND BOTH WAYS. `schedule.poll` stands between here
    // and the loop's first `publish_unreadable`, so a gauge first written there
    // is silent for the whole of that wait — the same window `dial`'s
    // `UPSTREAM_NEVER_RESOLVED` closes for the same reason. A series that does
    // not exist yet cannot be told apart from a healthy pod, a crashed one, or a
    // build that never linked this crate, which is the shape ADR-0556 and
    // ADR-0558 name for a different metric. Zero here is a measurement, not an
    // invented number: `export_unreadable` already publishes unconditionally
    // for exactly that reason.
    let unread = inputs.unread_at_boot();
    inputs.publish_unreadable(unread.len());

    if inputs.is_empty() {
        // NOTHING TO WATCH IS NOT A REASON TO EXIT. A process holding no
        // material has nothing that can go stale.
        tracing::debug!("no watched files; this process will not exit on a rotation");
        never().await
    }
    // A FILE THE DEPLOYMENT NAMED AND THIS PROCESS COULD NOT READ IS A
    // CONFIGURATION DEFECT, and `error!` rather than `warn!` says so. It is a
    // different fact from the loop's transient warning below: that one is a
    // mount being rewritten, this one is a path that was already wrong when the
    // process started. The watcher carries on over every OTHER file, because one
    // bad path silently retiring six good ones is the failure this replaced.
    if !unread.is_empty() {
        tracing::error!(
            unreadable = unread
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            watched = inputs.watched().len(),
            "watched files could NOT be read at boot. Their rotation cannot be noticed until \
             they become readable, at which point this process exits to be restarted onto \
             them; every other watched file is still being watched. Exported as \
             {WATCHED_FILES_UNREADABLE}"
        );
    }

    let serving_before = inputs.reported(Presented::Serving, false);
    let client_before = inputs.reported(Presented::Client, false);
    let mut reported_unreadable: Vec<String> = Vec::new();

    loop {
        tokio::time::sleep(schedule.poll).await;
        let current = inputs.on_disk();

        // THE GAUGE IS WRITTEN EVERY POLL, the log line only when the set moves.
        // A standing condition belongs in a gauge; a transition belongs in a
        // log. Warning on every poll would put a line a minute in the journal
        // for the life of the pod and train a reader to skip it.
        let unreadable = inputs.unreadable(&current);
        inputs.publish_unreadable(unreadable.len());
        if unreadable != reported_unreadable {
            if !unreadable.is_empty() {
                // TRANSIENT, not a rotation: kubelet is halfway through
                // rewriting the mount. Acting on it exits the process for
                // nothing, so what was already loaded is kept — for these files
                // ALONE, which is the whole of the change here.
                tracing::warn!(
                    unreadable = unreadable.join(", "),
                    "watched files could not be read; keeping what was already loaded for them, \
                     and still watching the rest"
                );
            }
            reported_unreadable = unreadable;
        }

        let changed = inputs.differing(&current);
        if changed.is_empty() {
            continue;
        }

        let waited = splay(schedule.splay_max, seed);
        tracing::warn!(
            serving_before,
            serving_after = inputs.reported(Presented::Serving, true),
            client_before,
            client_after = inputs.reported(Presented::Client, true),
            changed = changed.join(", "),
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

    /// An unreadable file has no baseline OF ITS OWN, and that is now the whole
    /// of what it means. It used to mean the SET had none.
    #[test]
    fn an_unreadable_input_has_no_baseline() {
        let path = Path::new("/etc/yadgar/quokka-4d81/absent.pem");
        let inputs = Inputs::new("test").also(path);
        assert_eq!(inputs.unread_at_boot(), vec![path]);
        assert_eq!(inputs.on_disk(), vec![None]);
        assert_eq!(inputs.fingerprint(Presented::Serving), None);
        assert_eq!(inputs.not_after(Presented::Serving), None);
        assert_eq!(inputs.fingerprint(Presented::Client), None);
        assert_eq!(inputs.not_after(Presented::Client), None);
    }

    /// **ONE UNREADABLE FILE LEAVES EVERY OTHER FILE'S BASELINE INTACT.** The
    /// collapse this replaced turned the first `None` into a `None` for the set,
    /// which is what disabled the watcher.
    #[test]
    fn an_unreadable_input_does_not_erase_the_baselines_beside_it() {
        let absent = Path::new("/etc/yadgar/quokka-4d81/absent.pem");
        let readable = Path::new("/proc/self/cmdline");
        let inputs = Inputs::new("test").also(absent).also(readable);

        assert_eq!(inputs.unread_at_boot(), vec![absent]);
        let on_disk = inputs.on_disk();
        assert_eq!(on_disk.len(), 2);
        assert_eq!(on_disk[0], None, "the unreadable one, and only it");
        assert!(on_disk[1].is_some(), "the readable one still answers");

        // AND THE UNREADABLE ONE IS NOT REPORTED AS A CHANGE. `None` on both
        // sides is "still unreadable", never "rotated".
        assert!(inputs.differing(&on_disk).is_empty());
        assert_eq!(
            inputs.unreadable(&on_disk),
            vec![absent.display().to_string()]
        );
    }

    /// The direction that IS a change: no baseline, and bytes on disk now.
    #[test]
    fn a_file_with_no_baseline_that_now_reads_is_a_change() {
        let absent = Path::new("/etc/yadgar/quokka-4d81/absent.pem");
        let inputs = Inputs::new("test").also(absent);
        let appeared = vec![Some(digest_of(b"material this process never loaded"))];

        assert_eq!(
            inputs.differing(&appeared),
            vec![absent.display().to_string()]
        );
        assert!(inputs.unreadable(&appeared).is_empty());
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

    /// A document at the path the mount produces, under a directory of this
    /// test's own. Nothing here overwrites a file in place: each case builds its
    /// own tree, so a stale file cannot make a broken implementation pass.
    fn document(body: &str) -> (PathBuf, Configuration) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "yadgar-config-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("shared")).unwrap();
        let path = root.join(SHARED_DOCUMENT);
        std::fs::write(&path, body).unwrap();
        (path, Configuration::under(&root))
    }

    /// The same tree with NO document in it — the case a fresh installation
    /// reaches when the ConfigMap is mounted somewhere else.
    fn no_document() -> Configuration {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "yadgar-config-absent-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        Configuration::under(&root)
    }

    #[test]
    fn the_stated_values_are_the_ones_used() {
        // NOT "it starts". A test that only asserted success would pass against
        // a surviving compiled-in default, which is the whole thing ADR-0569
        // deletes. The numbers are deliberately nothing like 60 and 300.
        let (_, config) = document("tlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n");
        let schedule = config.schedule().unwrap();
        assert_eq!(schedule.poll(), Duration::from_secs(17));
        assert_eq!(schedule.splay_max(), Duration::from_secs(941));
    }

    #[test]
    fn an_absent_document_refuses_and_names_the_file() {
        let config = no_document();
        let error = config.schedule().unwrap_err();
        assert!(
            matches!(error, ScheduleError::Absent { .. }),
            "an absent document must refuse, got {error:?}"
        );
        assert!(
            error.to_string().contains("shared/shared.yaml"),
            "the refusal must name the file: {error}"
        );
    }

    #[test]
    fn a_document_that_defines_nothing_refuses_naming_the_knob() {
        // Comments only, which is what a half-emptied template looks like. It is
        // a VALID YAML document whose value is null, so this must not be reported
        // as a malformed file.
        let (path, config) = document("# every knob deleted\n");
        let error = config.schedule().unwrap_err();
        assert!(
            matches!(error, ScheduleError::Missing { knob, .. } if knob == POLL_KNOB),
            "got {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains("tlsRotation.pollSeconds"),
            "must name the knob: {message}"
        );
        assert!(
            message.contains(&path.display().to_string()),
            "must name the file: {message}"
        );
    }

    #[test]
    fn each_knob_is_named_when_it_is_the_missing_one() {
        for (body, expected) in [
            ("tlsRotation:\n  splayMaxSeconds: 300\n", POLL_KNOB),
            ("tlsRotation:\n  pollSeconds: 60\n", SPLAY_MAX_KNOB),
        ] {
            let (_, config) = document(body);
            let error = config.schedule().unwrap_err();
            assert!(
                matches!(error, ScheduleError::Missing { knob, .. } if knob == expected),
                "{body:?} must refuse naming {expected}, got {error:?}"
            );
        }
    }

    #[test]
    fn an_empty_knob_is_not_the_same_case_as_a_missing_one() {
        // THE CASE A NAIVE IMPLEMENTATION GETS WRONG. `pollSeconds:` with nothing
        // after it deserialises to the same `None` a missing key does when the
        // field is typed `Option<u64>`, so the two collapse into one branch and a
        // half-finished edit is reported as a deleted knob.
        let (_, empty) = document("tlsRotation:\n  pollSeconds:\n  splayMaxSeconds: 300\n");
        let (_, missing) = document("tlsRotation:\n  splayMaxSeconds: 300\n");
        let empty = empty.schedule().unwrap_err();
        let missing = missing.schedule().unwrap_err();
        assert!(
            matches!(empty, ScheduleError::Empty { knob, .. } if knob == POLL_KNOB),
            "an empty knob must report as empty, got {empty:?}"
        );
        assert!(matches!(missing, ScheduleError::Missing { .. }));
        assert_ne!(
            empty.to_string(),
            missing.to_string(),
            "the two faults must not read identically"
        );
        // The quoted-empty form is the same fault written another way.
        let (_, quoted) = document("tlsRotation:\n  pollSeconds: \"  \"\n  splayMaxSeconds: 1\n");
        assert!(matches!(
            quoted.schedule().unwrap_err(),
            ScheduleError::Empty { .. }
        ));
    }

    #[test]
    fn a_zero_poll_interval_is_refused() {
        let (_, config) = document("tlsRotation:\n  pollSeconds: 0\n  splayMaxSeconds: 300\n");
        let error = config.schedule().unwrap_err();
        assert!(matches!(error, ScheduleError::ZeroPoll { .. }));

        // LEDGER 732. `ZeroPoll` is the one message that interpolates BOTH knob
        // constants, and nothing asserted its text — so renaming either
        // constant silently rewrote the line an operator reads at a refused
        // boot. The literals are the pin; see
        // `the_knob_paths_are_the_ones_an_operator_edits`.
        let message = error.to_string();
        assert!(
            message.contains("tlsRotation.pollSeconds"),
            "must name the knob that is 0: {message}"
        );
        assert!(
            message.contains("tlsRotation.splayMaxSeconds"),
            "must name the knob whose 0 IS supported, or the contrast it draws \
             is unreadable: {message}"
        );
    }

    #[test]
    fn a_zero_splay_is_allowed() {
        let (_, config) = document("tlsRotation:\n  pollSeconds: 60\n  splayMaxSeconds: 0\n");
        let schedule = config.schedule().unwrap();
        assert_eq!(schedule.splay_max(), Duration::ZERO);
        assert_eq!(schedule.poll(), Duration::from_secs(60));
    }

    #[test]
    fn a_value_that_is_not_a_whole_number_of_seconds_is_refused() {
        for (knob, value) in [
            (POLL_KNOB, "60s"),
            (POLL_KNOB, "-1"),
            (POLL_KNOB, "1.5"),
            (SPLAY_MAX_KNOB, "five minutes"),
            (SPLAY_MAX_KNOB, "[1, 2]"),
        ] {
            let body = if knob == POLL_KNOB {
                format!("tlsRotation:\n  pollSeconds: {value}\n  splayMaxSeconds: 300\n")
            } else {
                format!("tlsRotation:\n  pollSeconds: 60\n  splayMaxSeconds: {value}\n")
            };
            let (_, config) = document(&body);
            let error = config.schedule().unwrap_err();
            assert!(
                matches!(&error, ScheduleError::Unparsable { knob: named, .. } if *named == knob),
                "{knob}={value:?} must be refused naming the knob, got {error:?}"
            );
        }
    }

    #[test]
    fn a_quoted_whole_number_is_the_same_value() {
        let (_, config) =
            document("tlsRotation:\n  pollSeconds: \"17\"\n  splayMaxSeconds: \"941\"\n");
        let schedule = config.schedule().unwrap();
        assert_eq!(schedule.poll(), Duration::from_secs(17));
        assert_eq!(schedule.splay_max(), Duration::from_secs(941));
    }

    #[test]
    fn a_knob_this_crate_does_not_read_is_ignored() {
        // `audit.retentionDays` is in the same document and belongs to code that
        // does not exist yet. A parser with `deny_unknown_fields` would make
        // adding it break every service's rotation watcher at once.
        let (_, config) = document(
            "audit:\n  retentionDays: 90\ntlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n",
        );
        assert_eq!(config.schedule().unwrap().poll(), Duration::from_secs(17));
    }

    #[test]
    fn a_file_that_is_not_yaml_is_refused_as_malformed() {
        let (_, config) = document("tlsRotation:\n  pollSeconds: 60\n :\n\t- broken\n");
        assert!(matches!(
            config.schedule(),
            Err(ScheduleError::Malformed { .. })
        ));
    }

    #[test]
    fn a_directory_where_the_document_should_be_is_refused_with_the_reason() {
        // THE FAULT A CHART AUTHOR ACTUALLY PRODUCES. `mountPath` naming the file
        // rather than the directory holding it makes kubelet create a DIRECTORY
        // at this path, and the read then fails with `Is a directory` rather than
        // `Not found` — so it lands in `Unreadable` and not in `Absent`. Without
        // this test that variant carried the shortest message in the enum for the
        // most reachable mistake in the mount.
        let (path, config) = document("tlsRotation:\n  pollSeconds: 60\n  splayMaxSeconds: 1\n");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let error = config.schedule().unwrap_err();
        assert!(
            matches!(error, ScheduleError::Unreadable { .. }),
            "a directory at the document's path must refuse, got {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains(&path.display().to_string()),
            "must name the file: {message}"
        );
        assert!(
            message.contains("mountPath"),
            "must name the likely cause: {message}"
        );
    }

    #[test]
    fn the_mount_path_is_the_one_the_chart_writes() {
        // A PATH IS AN INTERFACE TO A CHART, exactly as a metric name is an
        // interface to a dashboard. Changing either of these strings without
        // changing the chart produces a refusal at boot rather than a failure
        // here, so the spelling is asserted.
        assert_eq!(CONFIG_DIR, "/etc/yadgar/config");
        assert_eq!(SHARED_DOCUMENT, "shared/shared.yaml");
        assert_eq!(
            Configuration::mounted().path(),
            Path::new("/etc/yadgar/config/shared/shared.yaml")
        );
    }

    /// LEDGER 732. A KNOB PATH IS AN INTERFACE TO AN OPERATOR, exactly as the
    /// mount path above is an interface to a chart.
    ///
    /// The KNOB constants reach an operator only as text inside a
    /// `ScheduleError`, and every assertion about them read the constant back
    /// into itself — `matches!(.. if knob == POLL_KNOB)`,
    /// `message.contains(POLL_KNOB)`. A certifying fixture: measured by
    /// mutation on the commit this test was added to, renaming `POLL_KNOB` left
    /// the suite at 28 passed, 0 failed, and renaming `SPLAY_MAX_KNOB` did the
    /// same. So the line a boot refusal prints was pinned by nothing, and an
    /// operator could be sent looking for a key the document does not spell.
    ///
    /// The LEAF constants are deliberately NOT pinned here. They sit on the
    /// READ path and the fixture YAML spells them literally, so they are
    /// already certified by use: renaming `POLL_LEAF` reds 8 of 28 and
    /// `SPLAY_MAX_LEAF` reds 5 of 28. Adding an equality for them would assert
    /// something the suite already proves, and would be weaker than the proof.
    ///
    /// Each literal here is the FULL dotted path, because that is what a
    /// refusal has to print: `shared.yaml` holds several sections and
    /// `pollSeconds` alone would not say which one.
    #[test]
    fn the_knob_paths_are_the_ones_an_operator_edits() {
        assert_eq!(POLL_KNOB, "tlsRotation.pollSeconds");
        assert_eq!(SPLAY_MAX_KNOB, "tlsRotation.splayMaxSeconds");
    }

    #[test]
    fn the_document_joins_the_watch_set() {
        // ADR-0523 reloads by restart, and this is the whole of the wiring: the
        // document is a `Material`, so a service that hands it to `Inputs::of`
        // exits when an operator edits it. A `Material` impl that returned
        // nothing would leave configuration changes silently ignored until
        // something unrelated restarted the pod.
        let (path, config) = document("tlsRotation:\n  pollSeconds: 60\n  splayMaxSeconds: 1\n");
        let inputs = Inputs::of("test", &[&config]);
        assert_eq!(inputs.watched(), vec![path.as_path()]);
    }

    #[test]
    fn hex_renders_every_byte_as_two_digits() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    /// The `Error::source()` walk a caller performs, inlined.
    ///
    /// This is `yadgar-telemetry`'s `diagnose::chain` byte for byte. It is
    /// COPIED rather than depended on because the property under test is a
    /// property of THIS crate's messages, and every module that rotates its
    /// certificates depends on this crate.
    fn flattened(error: &dyn std::error::Error) -> String {
        let mut rendered = error.to_string();
        let mut source = error.source();
        while let Some(current) = source {
            rendered.push_str(": ");
            rendered.push_str(&current.to_string());
            source = current.source();
        }
        rendered
    }

    /// LEDGER 737. A variant that marks a field `#[source]` must not also
    /// interpolate that field into its own `#[error]` string.
    ///
    /// A caller that walks `Error::source()` appends every layer itself, so a
    /// message that already carries the layer prints the inner cause TWICE.
    /// Each variant is reached through the REAL path that produces it rather
    /// than built by hand, because `Malformed` carries a `serde_norway::Error`
    /// that cannot be constructed from outside that crate — and reaching all
    /// three the same way keeps the case honest about what a deployment sees.
    ///
    /// The cause is taken from the error's OWN `source()` rather than written
    /// as a literal, so the count cannot drift from what the type actually
    /// carries.
    #[test]
    fn a_source_bearing_variant_does_not_also_interpolate_it() {
        let (_, unparsable) =
            document("tlsRotation:\n  pollSeconds: 60s\n  splayMaxSeconds: 300\n");
        let (_, malformed) = document("tlsRotation: [1, 2]\n");

        // `Unreadable` the way a deployment reaches it: a chart whose
        // `mountPath` names the FILE leaves kubelet a DIRECTORY where the
        // document belongs, and the read fails as `Is a directory`.
        let root =
            std::env::temp_dir().join(format!("yadgar-config-unreadable-{}", std::process::id()));
        std::fs::create_dir_all(root.join(SHARED_DOCUMENT)).unwrap();

        let cases: Vec<(&str, ScheduleError)> = vec![
            (
                "Unreadable",
                Configuration::under(&root).schedule().unwrap_err(),
            ),
            ("Malformed", malformed.schedule().unwrap_err()),
            ("Unparsable", unparsable.schedule().unwrap_err()),
        ];

        for (variant, error) in cases {
            assert!(
                matches!(
                    (variant, &error),
                    ("Unreadable", ScheduleError::Unreadable { .. })
                        | ("Malformed", ScheduleError::Malformed { .. })
                        | ("Unparsable", ScheduleError::Unparsable { .. })
                ),
                "the {variant} case produced {error:?} instead"
            );

            let cause = std::error::Error::source(&error)
                .unwrap_or_else(|| {
                    panic!(
                        "{variant} must keep its `#[source]` link — the cause \
                         moves to the chain, it does not go away"
                    )
                })
                .to_string();
            let flat = flattened(&error);
            let seen = flat.matches(&cause).count();
            assert_eq!(
                seen, 1,
                "{variant} prints its cause {seen} time(s) in a walked chain, \
                 not once.\n  cause:  {cause}\n  walked: {flat}"
            );
        }
    }

    /// LEDGER 737, stated as the whole operator-facing line rather than as a
    /// count, so the diff shows a human what a boot refusal actually reads.
    ///
    /// `ParseIntError` is a `std` type, so its wording is the same everywhere
    /// and this can be an equality rather than a `contains`.
    #[test]
    fn the_walked_message_for_an_unparsable_knob_reads_end_to_end() {
        let (path, config) = document("tlsRotation:\n  pollSeconds: 60s\n  splayMaxSeconds: 300\n");
        let error = config.schedule().unwrap_err();
        assert_eq!(
            flattened(&error),
            format!(
                "A knob that is not a whole number of seconds is refused rather \
                 than replaced with a default, because a deployment that \
                 believes it set this and did not would run an interval nobody \
                 chose and see nothing wrong. tlsRotation.pollSeconds in {} is \
                 \"60s\": invalid digit found in string",
                path.display()
            )
        );
    }
}
