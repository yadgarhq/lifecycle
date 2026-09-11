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

mod inputs;
mod schedule;
mod schedule_error;

pub use inputs::Inputs;
pub use schedule::{Configuration, Schedule, CONFIG_DIR, SHARED_DOCUMENT};
pub use schedule_error::ScheduleError;

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

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
        tokio::time::sleep(schedule.poll()).await;
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

        let waited = splay(schedule.splay_max(), seed);
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

    #[test]
    fn hex_renders_every_byte_as_two_digits() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
