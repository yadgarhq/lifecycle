//! Reading the rotation schedule out of the shared configuration document.
//! Split out of `rotate.rs` (ledger 719) — [`Configuration`] and [`Schedule`]
//! are the seam ADR-0569 governs; the refusal taxonomy they produce lives in
//! [`super::schedule_error`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::schedule_error::ScheduleError;
use super::{File, Material};

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
pub(crate) const POLL_KNOB: &str = "tlsRotation.pollSeconds";

/// The top of the range this pod's splay is drawn from.
pub(crate) const SPLAY_MAX_KNOB: &str = "tlsRotation.splayMaxSeconds";

/// The configuration document this process reads its knobs out of.
///
/// **A `Material` LIKE ANY OTHER, and that is the whole reload story.** ADR-0523
/// watches every file the process read at boot, so handing this to [`super::Inputs::of`]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotate::Inputs;

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
    fn a_zero_splay_is_allowed() {
        let (_, config) = document("tlsRotation:\n  pollSeconds: 60\n  splayMaxSeconds: 0\n");
        let schedule = config.schedule().unwrap();
        assert_eq!(schedule.splay_max(), Duration::ZERO);
        assert_eq!(schedule.poll(), Duration::from_secs(60));
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
}
