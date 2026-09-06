//! The rotation watcher, proved against the directory shape kubelet actually
//! writes.
//!
//! **THE NEGATIVE CASE IS THE LOAD-BEARING ONE.** After an atomic `..data` swap
//! every path resolves to a different inode with a fresh modification time, so
//! an mtime-based watcher fires on EVERY swap — including the ones that changed
//! nothing. [`an_atomic_swap_of_identical_bytes_does_not_end_the_watch`] is what
//! separates a content hash from an mtime, and it is the case to mutate when
//! checking that this suite still bites.
//!
//! **The failure mode this must never grow.** If the watcher dies, the process
//! keeps serving the material it loaded — today's behaviour, never worse.
//! [`a_mount_that_cannot_be_read_does_not_end_the_watch`] and
//! [`nothing_configured_never_ends_the_watch`] pin that: neither is allowed to
//! end the watch, because ending it exits the process.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use tokio::time::timeout;

use common::{
    generation, with_exchanged, with_replaced, Generation, Mount, CA_NOT_AFTER, CLIENT_NOT_AFTER,
    LEAF_NOT_AFTER, NAMES,
};
use yadgar_lifecycle::rotate::{
    self, Inputs, Presented, Schedule, CERTIFICATE_NOT_AFTER, WATCHED_FILES_UNREADABLE,
};

/// The label every gauge in this suite carries.
const SERVICE: &str = "lifecycle-test";

/// Short enough that a case finishes quickly, long enough that the watcher
/// really does go round its loop rather than reading everything in one pass.
const POLL: Duration = Duration::from_millis(20);

/// How long a case waits for a watch that SHOULD end. Generous: the assertion is
/// about whether it ends at all, never about how fast.
const GENEROUS: Duration = Duration::from_secs(5);

/// How long a case waits before concluding a watch will NOT end. Many poll
/// intervals, so a watcher that was going to fire has had every chance to.
const PATIENT: Duration = Duration::from_millis(600);

/// The watch set a deployment of a service like `iam` produces — **assembled
/// through [`Inputs::of`] over the same configuration types a service holds**,
/// never by naming seven paths.
///
/// A helper that spelled the paths out would prove only that the watcher watches
/// what it is handed. This proves that a configuration puts them there, which is
/// the half that can silently be wrong.
fn inputs(mount: &Mount) -> Inputs {
    let listener = mount.listener();
    let upstream = mount.upstream();
    let broker = mount.broker();
    let enrolment = mount.enrolment_ca();
    Inputs::of(SERVICE, &[&listener, &upstream, &broker, &enrolment])
}

/// Rotate the mount once the watcher has had time to take its boot reading.
///
/// Sequencing rather than a guess: the watcher reads its baseline before its
/// first sleep, so a swap that lands several poll intervals later is
/// unambiguously a CHANGE rather than the state it started from.
fn swap_shortly(mount: &Arc<Mount>, files: Generation) {
    let mount = Arc::clone(mount);
    tokio::spawn(async move {
        tokio::time::sleep(POLL * 4).await;
        mount.swap(&files);
    });
}

fn at_once(poll: Duration) -> Schedule {
    Schedule::new(poll, Duration::ZERO)
}

/// THE CASE THE CHANGE EXISTS FOR. cert-manager rewrites the Secret, kubelet
/// swaps `..data`, and the process that read the old certificate at boot ends
/// its watch so it can be restarted onto the new one.
#[tokio::test]
async fn an_atomic_swap_of_a_new_certificate_ends_the_watch() {
    let mount = Arc::new(Mount::new(&generation("yadgar")));
    let watched = inputs(&mount);
    swap_shortly(&mount, generation("yadgar"));

    timeout(GENEROUS, rotate::watch_with_seed(watched, at_once(POLL), 0))
        .await
        .expect("a renewed certificate behind an atomic ..data swap must end the watch");
}

/// THE CASE THAT SEPARATES A HASH FROM AN mtime, and the one to mutate when
/// checking this suite still bites.
///
/// Every path resolves to a new inode with a new modification time, and not one
/// byte the process read has changed. Ending the watch here would restart both
/// replicas for nothing, on every kubelet resync, forever.
#[tokio::test]
async fn an_atomic_swap_of_identical_bytes_does_not_end_the_watch() {
    let files = generation("yadgar");
    let mount = Arc::new(Mount::new(&files));
    let watched = inputs(&mount);
    swap_shortly(&mount, files);

    assert!(
        timeout(PATIENT, rotate::watch_with_seed(watched, at_once(POLL), 0))
            .await
            .is_err(),
        "the bytes are identical, so nothing rotated; only an mtime check fires here"
    );
}

/// A mount that cannot be read is a TRANSIENT state, not a rotation. Acting on
/// it would exit the process over a directory kubelet is halfway through
/// rewriting — a watcher whose failure is WORSE than not having one.
#[tokio::test]
async fn a_mount_that_cannot_be_read_does_not_end_the_watch() {
    let mount = Arc::new(Mount::new(&generation("yadgar")));
    let watched = inputs(&mount);

    let breaker = Arc::clone(&mount);
    tokio::spawn(async move {
        tokio::time::sleep(POLL * 4).await;
        breaker.break_it();
    });

    assert!(
        timeout(PATIENT, rotate::watch_with_seed(watched, at_once(POLL), 0))
            .await
            .is_err(),
        "an unreadable file is not a changed one; the process must keep serving what it loaded"
    );
}

/// A path the deployment named and this process could NOT read at boot.
///
/// It resolves to nothing, so `also` records `loaded: None` for it, and it stays
/// in the watch set — which is where the collapse lives.
fn absent(mount: &Mount) -> std::path::PathBuf {
    mount.path("never-written.pem")
}

/// **ONE UNREADABLE FILE MUST NOT DISABLE THE WHOLE WATCH SET, and this is the
/// case the crate shipped wrong.** `baseline()` collected `Option<[u8; 32]>` into
/// `Option<Vec<_>>`, so a single `None` collapsed the entire set and
/// `watch_with_seed` took `never()` for the life of the process behind one
/// `warn!`. Rotation then went unnoticed for every OTHER file — seven of them in
/// a service like `iam` — and the pod served its day-0 leaf until the
/// certificate expired.
///
/// The listener's certificate here is rotated on its own while the other watched
/// files are left byte-identical, so nothing but that file can be ending this
/// watch.
#[tokio::test]
async fn one_file_unreadable_at_boot_does_not_disable_the_files_that_are_readable() {
    let base = generation("yadgar");
    let mount = Arc::new(Mount::new(&base));
    let missing = absent(&mount);
    let listener = mount.listener();
    let watched = Inputs::of(SERVICE, &[&listener, &missing]);
    assert!(
        watched.watched().contains(&missing.as_path()),
        "the unreadable path must stay IN the set; dropping it is a different bug"
    );

    let fresh = generation("yadgar");
    let replacement = fresh
        .iter()
        .find(|(n, _)| n == "tls.pem")
        .map(|(_, c)| c.clone())
        .expect("the fresh generation holds that file");
    swap_shortly(&mount, with_replaced(&base, "tls.pem", &replacement));

    timeout(GENEROUS, rotate::watch_with_seed(watched, at_once(POLL), 0))
        .await
        .expect("one file that could not be read must not stop the rest being watched");
}

/// **A FILE THAT WAS UNREADABLE AT BOOT AND IS READABLE NOW HAS CHANGED**, and
/// the change is the one that matters most: the process is running on material
/// it never loaded at all.
///
/// This is not new policy. `differing()` ALREADY answers "changed" for a file
/// whose baseline is `None` and whose disk reading is `Some` — the collapse in
/// `baseline()` is what made that answer unreachable. Removing the collapse
/// makes the module's existing rule apply rather than inventing one.
///
/// It also settles "is an unreadable file permanent?" by measurement instead of
/// by guess. A late mount resolves itself: the process exits once, and the
/// replacement takes a real baseline. A genuinely wrong path never becomes
/// readable, so this never fires and the gauge below is what says so.
#[tokio::test]
async fn a_file_that_could_not_be_read_at_boot_ends_the_watch_when_it_appears() {
    let mount = Arc::new(Mount::new(&generation("yadgar")));
    let missing = absent(&mount);
    let listener = mount.listener();
    let watched = Inputs::of(SERVICE, &[&listener, &missing]);

    let appears = missing.clone();
    tokio::spawn(async move {
        tokio::time::sleep(POLL * 4).await;
        std::fs::write(&appears, "material this process never loaded\n").unwrap();
    });

    timeout(GENEROUS, rotate::watch_with_seed(watched, at_once(POLL), 0))
        .await
        .expect("a file the process could not read, which now holds bytes, is a change");
}

/// The SAME collapse on the polling side, reached later.
///
/// `on_disk()` collected the same way, so one file becoming unreadable made
/// every poll `continue` — and the six files still rotating perfectly well went
/// unnoticed for as long as that one stayed gone. Only ONE file is removed here;
/// the other six keep resolving through an untouched `..data`.
///
/// The transient rule is kept and is what
/// [`a_mount_that_cannot_be_read_does_not_end_the_watch`] pins: a file that goes
/// from readable to unreadable is NOT a change, because that is the state
/// kubelet passes through. What changes is that it no longer silences the rest.
#[tokio::test]
async fn one_file_becoming_unreadable_does_not_disable_the_files_that_are_readable() {
    let base = generation("yadgar");
    let mount = Arc::new(Mount::new(&base));
    let watched = inputs(&mount);

    let gone = mount.path("ca.pem");
    let swapper = Arc::clone(&mount);
    let fresh = generation("yadgar");
    let replacement = fresh
        .iter()
        .find(|(n, _)| n == "tls.pem")
        .map(|(_, c)| c.clone())
        .expect("the fresh generation holds that file");
    let rotated = with_replaced(&base, "tls.pem", &replacement);
    tokio::spawn(async move {
        tokio::time::sleep(POLL * 4).await;
        std::fs::remove_file(&gone).unwrap();
        tokio::time::sleep(POLL * 4).await;
        swapper.swap(&rotated);
    });

    timeout(GENEROUS, rotate::watch_with_seed(watched, at_once(POLL), 0))
        .await
        .expect("one file that went away must not stop the other six being watched");
}

/// THE DEFAULT. Every TLS setting in this estate is opt-in and off, so nothing
/// was read and there is nothing to watch — and a watch that ended here would
/// exit a process holding no material at all.
#[tokio::test]
async fn nothing_configured_never_ends_the_watch() {
    assert!(
        timeout(
            PATIENT,
            rotate::watch_with_seed(Inputs::new(SERVICE), at_once(POLL), 0)
        )
        .await
        .is_err(),
        "an unconfigured deployment has nothing to watch and must never exit on its account"
    );
}

/// THE SPLAY IS WAITED OUT BEFORE THE WATCH ENDS.
///
/// Both replicas see the refreshed file inside the same kubelet sync window, so
/// an unsplayed exit drops both at once. A PodDisruptionBudget does not govern a
/// self-exit — this wait is the only thing that does.
///
/// `u64::MAX` is the top of the seed range, so the splay is the whole configured
/// maximum and the assertion is an equality rather than a coin toss.
#[tokio::test]
async fn the_watch_ends_only_after_the_splay() {
    let mount = Arc::new(Mount::new(&generation("yadgar")));
    let watched = inputs(&mount);
    swap_shortly(&mount, generation("yadgar"));

    let splay = Duration::from_millis(700);
    let started = Instant::now();
    timeout(
        GENEROUS,
        rotate::watch_with_seed(watched, Schedule::new(POLL, splay), u64::MAX),
    )
    .await
    .expect("the watch must still end");
    assert!(
        started.elapsed() >= splay,
        "the watch ended after {:?}, which is inside the {splay:?} splay",
        started.elapsed()
    );
}

/// THE EXPIRY IS THE LEAF'S, NEVER THE CHAIN'S.
///
/// `tls.pem` holds the leaf followed by the authority that issued it, and the
/// authority outlives it by a decade. A gauge reporting the CA's expiry is worse
/// than no gauge: it reads healthy for ten years while the certificate the
/// listener is actually serving ages out.
#[test]
fn the_expiry_reported_is_the_leaf_certificate_not_the_chain() {
    let mount = Mount::new(&generation("yadgar"));

    assert_eq!(
        inputs(&mount).not_after(Presented::Serving),
        Some(LEAF_NOT_AFTER),
        "the first certificate in the file is the one being served"
    );
    assert_ne!(
        inputs(&mount).not_after(Presented::Serving),
        Some(CA_NOT_AFTER),
        "reporting the issuer's expiry would keep the gauge green for a decade"
    );
    // The CLIENT leaf is written the same way, so the same mistake is available
    // on the same file — and that leaf is what ADR-0516 makes load-bearing for
    // availability.
    assert_eq!(
        inputs(&mount).not_after(Presented::Client),
        Some(CLIENT_NOT_AFTER),
        "the first certificate in the client file is the one being presented"
    );
}

/// The fingerprint NAMES the certificate, so two different certificates cannot
/// share one — that is the whole of what a log line saying "which certificate am
/// I on" is worth.
#[test]
fn the_fingerprint_distinguishes_two_certificates() {
    let one = Mount::new(&generation("yadgar"));
    let other = Mount::new(&generation("yadgar"));

    let a = inputs(&one)
        .fingerprint(Presented::Serving)
        .expect("a certificate was read");
    let b = inputs(&other)
        .fingerprint(Presented::Serving)
        .expect("a certificate was read");
    assert_eq!(a.len(), 64, "SHA-256 over the leaf's DER, hex");
    assert_ne!(a, b, "two certificates must not share a fingerprint");

    // AND THE TWO KINDS ARE NOT EACH OTHER. One process holds both, so a
    // fingerprint that answered "which certificate am I on" with the wrong one
    // would read as a plausible answer.
    let client = inputs(&one)
        .fingerprint(Presented::Client)
        .expect("a client certificate was read");
    assert_ne!(
        a, client,
        "the serving and client leaves are different files"
    );
}

/// THE GAUGE LANDS UNDER THE NAME AND THE LABELS A DASHBOARD QUERIES.
///
/// A typo in either string compiles, passes clippy, and passes every other case
/// in this file — and produces a series nothing asks for. That is
/// indistinguishable from a certificate that never expires.
#[test]
fn the_expiry_is_exported_under_the_name_a_dashboard_queries() {
    assert_eq!(
        CERTIFICATE_NOT_AFTER, "yadgar_tls_certificate_not_after_seconds",
        "the name is an interface to Grafana; renaming it blanks the panel"
    );

    let mount = Mount::new(&generation("yadgar"));
    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || inputs(&mount).export_not_after());

    let emitted = snapshotter.snapshot().into_vec();
    // A metrics-util built against another `metrics` major links a SECOND
    // facade: everything compiles, nothing is captured, and the assertions below
    // would pass vacuously against an empty snapshot.
    assert_eq!(
        emitted.len(),
        2,
        "one gauge per certificate this process loaded, and nothing else — check for a \
         duplicate `metrics` crate"
    );

    let mut seen: Vec<(Vec<(String, String)>, f64)> = emitted
        .iter()
        .map(|(composite, _unit, _description, value)| {
            let key = composite.key();
            assert_eq!(key.name(), CERTIFICATE_NOT_AFTER);
            let labels = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            let seconds = match value {
                DebugValue::Gauge(seconds) => seconds.into_inner(),
                other => panic!("expected a gauge, got {other:?}"),
            };
            (labels, seconds)
        })
        .collect();
    seen.sort_by(|a, b| a.0.cmp(&b.0));

    // BOTH LABELS ARE BOUNDED. `kind` has exactly two values and always will, so
    // it costs two series rather than one per rotation — which is what D67's
    // rule is actually about. A fingerprint or a path here would not be.
    assert_eq!(
        seen,
        vec![
            (
                vec![
                    ("service".to_string(), SERVICE.to_string()),
                    ("kind".to_string(), "client".to_string()),
                ],
                CLIENT_NOT_AFTER as f64
            ),
            (
                vec![
                    ("service".to_string(), SERVICE.to_string()),
                    ("kind".to_string(), "serving".to_string()),
                ],
                LEAF_NOT_AFTER as f64
            ),
        ],
        "each gauge carries the expiry of the leaf it names, and the two are not \
         interchangeable: an expired CLIENT leaf STOPS this hop (ADR-0516)"
    );
}

/// The gauge that makes the WATCHER'S OWN failure visible, under the name and
/// labels a dashboard queries.
///
/// **A CHARACTERIZATION TEST, and it passed the moment it was written** — the
/// name and the label set are the interface, not a behaviour derived from
/// anything. Its RED comes from mutation instead: misspell the constant, or
/// publish a constant `0` in place of the count, and this is what dies.
///
/// The ZERO half is the load-bearing one and is a DELIBERATE departure from
/// [`no_certificate_exports_no_gauge`] below. An expiry for a certificate the
/// process never loaded would be invented. "None of the watched files is
/// unreadable" is measured — and a series that only appears once something is
/// wrong cannot be told apart from an exporter that is not running.
#[test]
fn the_unreadable_count_is_exported_under_the_name_a_dashboard_queries() {
    assert_eq!(
        WATCHED_FILES_UNREADABLE, "yadgar_rotation_watched_files_unreadable",
        "the name is an interface to Grafana; renaming it blanks the panel"
    );

    let mount = Mount::new(&generation("yadgar"));
    let missing = mount.path("never-written.pem");
    let listener = mount.listener();

    // Two watched files, exactly one of which cannot be read — so a gauge
    // reporting "the size of the set" or "one if any" lands on a different
    // number than a gauge reporting the count.
    let watched = Inputs::of(SERVICE, &[&listener, &missing]);
    assert_eq!(
        watched.watched().len(),
        3,
        "a cert, its key, and the absent one"
    );

    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    let named = metrics::with_local_recorder(&recorder, || watched.export_unreadable());
    assert_eq!(
        named,
        vec![missing.display().to_string()],
        "the paths are NAMED to the caller; only the count goes in the label-free gauge"
    );

    let emitted = snapshotter.snapshot().into_vec();
    // A metrics-util built against another `metrics` major links a SECOND
    // facade: everything compiles, nothing is captured, and every assertion
    // below would pass vacuously against an empty snapshot.
    assert_eq!(
        emitted.len(),
        1,
        "one gauge — check for a duplicate `metrics` crate"
    );
    let (composite, _unit, _description, value) = &emitted[0];
    let key = composite.key();
    assert_eq!(key.name(), WATCHED_FILES_UNREADABLE);
    assert_eq!(
        key.labels()
            .map(|l| (l.key().to_string(), l.value().to_string()))
            .collect::<Vec<_>>(),
        vec![("service".to_string(), SERVICE.to_string())],
        "the service and NOTHING per-path: a path label makes the cardinality a \
         property of a deployment's configuration"
    );
    assert_eq!(
        match value {
            DebugValue::Gauge(count) => count.into_inner(),
            other => panic!("expected a gauge, got {other:?}"),
        },
        1.0
    );

    // AND A HEALTHY WATCH SET PUBLISHES THE ZERO.
    let healthy = Inputs::of(SERVICE, &[&listener]);
    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    let named = metrics::with_local_recorder(&recorder, || healthy.export_unreadable());
    assert!(named.is_empty());

    let emitted = snapshotter.snapshot().into_vec();
    assert_eq!(
        emitted.len(),
        1,
        "the series must exist while everything is fine"
    );
    assert_eq!(
        match &emitted[0].3 {
            DebugValue::Gauge(count) => count.into_inner(),
            other => panic!("expected a gauge, got {other:?}"),
        },
        0.0
    );
}

/// **THE GAUGE MUST EXIST BEFORE THE FIRST POLL EVER COMPLETES, not only after
/// one has run.** [`watch_with_seed`]'s loop already writes
/// [`WATCHED_FILES_UNREADABLE`] every tick, unconditionally — the defect this
/// pins is the window BEFORE the first tick, which used to hold nothing at all.
/// An absent series and a healthy zero are different things to a query: `> 0`
/// never fires on an absent series, and a dashboard shows a gap rather than a
/// zero. The same shape as `dial`'s `UPSTREAM_NEVER_RESOLVED`, which is written
/// "before the first tick, and both ways" for exactly this reason.
///
/// A `metrics::LocalRecorderGuard` is used rather than `with_local_recorder`,
/// deliberately: the recorder has to stay the thread-local default across the
/// `.await` in [`tokio::task::yield_now`], which a closure-scoped guard cannot
/// do since `tokio::spawn` only SCHEDULES the task rather than running it.
///
/// `start_paused` makes this deterministic rather than a race against a real
/// clock: the schedule's poll interval is an hour, and the paused clock does
/// not move on its own while this test still holds a runnable task, so the
/// single `yield_now` below runs the spawned watch up to its first pending
/// `.await` — the `sleep` — and no further.
#[tokio::test(start_paused = true)]
async fn the_unreadable_gauge_is_present_at_zero_before_the_first_poll() {
    let mount = Mount::new(&generation("yadgar"));
    let listener = mount.listener();
    let watched = Inputs::of(SERVICE, &[&listener]);

    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);

    // Long enough that nothing in this test could ever wait it out; the point
    // is what exists BEFORE this elapses, not a race against it.
    let schedule = Schedule::new(Duration::from_secs(3600), Duration::ZERO);
    let task = tokio::spawn(rotate::watch_with_seed(watched, schedule, 0));

    // Runs the spawned watch synchronously up to and including its first
    // pending `.await`, and no further — the paused clock never advances on
    // its own while this task is still runnable.
    tokio::task::yield_now().await;

    let emitted = snapshotter.snapshot().into_vec();
    // A metrics-util built against another `metrics` major links a SECOND
    // facade: everything compiles, nothing is captured, and every assertion
    // below would pass vacuously against an empty snapshot.
    assert_eq!(
        emitted.len(),
        1,
        "the gauge must exist before the first poll completes; a healthy pod \
         must not be indistinguishable from one whose watcher never started"
    );
    let (composite, _unit, _description, value) = &emitted[0];
    assert_eq!(composite.key().name(), WATCHED_FILES_UNREADABLE);
    assert_eq!(
        match value {
            DebugValue::Gauge(count) => count.into_inner(),
            other => panic!("expected a gauge, got {other:?}"),
        },
        0.0,
        "nothing is unreadable yet; this must be a measured zero, not be absent"
    );

    task.abort();
}

/// NOTHING IS PUBLISHED WHEN THERE IS NOTHING TO PUBLISH. An invented number is
/// worse than a missing series: a dashboard cannot tell it apart from a real one.
#[test]
fn no_certificate_exports_no_gauge() {
    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || Inputs::new(SERVICE).export_not_after());
    assert!(snapshotter.snapshot().into_vec().is_empty());
}

/// EVERY WATCHED FILE IS WATCHED, one at a time.
///
/// **This is the case a whole-generation swap cannot make.** [`swap_shortly`]
/// rewrites all seven files, so an implementation that hashed only the first
/// would pass every other case in this file. Here each file is rotated with the
/// other six left byte-identical, so a file missing from the watch set is a case
/// that hangs.
#[tokio::test]
async fn each_watched_file_ends_the_watch_on_its_own() {
    for name in NAMES {
        let base = generation("yadgar");
        let mount = Arc::new(Mount::new(&base));
        let watched = inputs(&mount);

        // A replacement minted independently, so the new contents cannot
        // coincide with the old by construction.
        let fresh = generation("yadgar");
        let replacement = fresh
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, c)| c.clone())
            .expect("the fresh generation holds that file");
        swap_shortly(&mount, with_replaced(&base, name, &replacement));

        timeout(GENEROUS, rotate::watch_with_seed(watched, at_once(POLL), 0))
            .await
            .unwrap_or_else(|_| {
                panic!("rotating {name} alone did not end the watch, so it is not being watched")
            });
    }
}

/// TWO FILES EXCHANGING CONTENTS IS A ROTATION, not a wash.
///
/// The mount holds exactly the same bytes afterwards, and every file is the same
/// length as before. Only a digest that is per-file and POSITIONAL sees it.
#[tokio::test]
async fn exchanging_the_contents_of_two_watched_files_ends_the_watch() {
    let base = generation("yadgar");
    let mount = Arc::new(Mount::new(&base));
    let watched = inputs(&mount);
    swap_shortly(&mount, with_exchanged(&base, "tls-key.pem", "ca.pem"));

    timeout(GENEROUS, rotate::watch_with_seed(watched, at_once(POLL), 0))
        .await
        .expect("the same bytes in different files are different inputs");
}

/// THE BASELINE IS THE BYTES THE PROCESS READ, NOT A LATER READING.
///
/// If a watch set merely remembered paths and read them when the watcher first
/// polled, everything between boot and that first poll would be a window in
/// which a kubelet swap silently became the baseline: the rotation would never
/// be noticed, and the gauge would describe a certificate the listener is not
/// serving. Here the swap lands BEFORE the watch begins, and both must still
/// speak for the original.
#[tokio::test]
async fn the_baseline_is_what_was_loaded_not_what_is_on_disk_later() {
    let mount = Arc::new(Mount::new(&generation("yadgar")));
    let watched = inputs(&mount);
    let loaded = watched
        .fingerprint(Presented::Serving)
        .expect("a certificate was read");
    let loaded_client = watched
        .fingerprint(Presented::Client)
        .expect("a client certificate was read");

    // The whole mount is replaced before the watcher has polled once.
    mount.swap(&generation("yadgar"));

    assert_eq!(
        watched.fingerprint(Presented::Serving),
        Some(loaded),
        "the fingerprint must name the loaded certificate, not the one now on disk"
    );
    assert_eq!(
        watched.fingerprint(Presented::Client),
        Some(loaded_client),
        "and the same for the client leaf, which fails harder when it is stale"
    );
    assert_eq!(
        watched.not_after(Presented::Serving),
        Some(LEAF_NOT_AFTER),
        "and so must the expiry the gauge carries"
    );
    timeout(GENEROUS, rotate::watch_with_seed(watched, at_once(POLL), 0))
        .await
        .expect("a swap that landed before the first poll is still a rotation");
}
