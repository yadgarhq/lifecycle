use super::*;

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
        .certificate(Presented::Client, None, path)
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
        None,
        Path::new("/etc/yadgar/quokka-4d81/absent.pem"),
    );
    assert_eq!(configured.reported(Presented::Serving, false), "unknown");
    assert_eq!(configured.reported(Presented::Serving, true), "unknown");
}

/// A self-signed leaf, PEM. Minted per case rather than checked in, for the
/// reason `Cargo.toml` gives about a fixture key in a repository.
fn self_signed(name: &str) -> String {
    let key = rcgen::KeyPair::generate().expect("a key pair");
    let mut params =
        rcgen::CertificateParams::new(vec![name.to_string()]).expect("a subject alternative name");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.self_signed(&key).expect("a self-signed leaf").pem()
}

/// A self-signed leaf, PEM, expiring on an EXPLICIT date — unlike
/// [`self_signed`], whose expiry is whatever `rcgen` defaults to. Two
/// leaves of the same kind are told apart by `not_after` here, never by
/// minting the same leaf twice.
fn self_signed_expiring(name: &str, year: i32, month: u8, day: u8) -> String {
    let key = rcgen::KeyPair::generate().expect("a key pair");
    let mut params =
        rcgen::CertificateParams::new(vec![name.to_string()]).expect("a subject alternative name");
    params.not_after = rcgen::date_time_ymd(year, month, day);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.self_signed(&key).expect("a self-signed leaf").pem()
}

/// A directory of this case's own, so a stale file cannot make a broken
/// implementation pass.
fn scratch() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "yadgar-lifecycle-reported-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).expect("a scratch directory");
    root
}

/// **`_before` IS THE LEAF THIS PROCESS LOADED AND `_after` IS THE ONE ON
/// DISK**, and the rotation line is worth nothing unless they are.
///
/// [`watch`] prints `serving_before = reported(.., false)` beside
/// `serving_after = reported(.., true)`, so an operator can read which
/// certificate the pod is leaving and which one it is restarting onto.
/// NOTHING PINNED IT. `reported` was exercised only for `none` and for
/// `unknown` — and in both of those cases the two arms answer the SAME
/// string, so swapping the bools at the four call sites, or reading the
/// loaded bytes on both sides, compiled, passed clippy and passed every
/// other case in this crate while printing one fingerprint twice.
///
/// ADR-0523 makes the fingerprints an obligation of the decision, not a
/// decoration on the log line: "it logs the old and new fingerprints".
#[test]
fn the_boot_baseline_and_the_file_on_disk_are_reported_apart() {
    let root = scratch();
    let path = root.join("tls.pem");
    let loaded = self_signed("before.yadgar.internal");
    std::fs::write(&path, &loaded).expect("the leaf this process reads at boot");

    let inputs = Inputs::new("test").certificate(Presented::Serving, None, &path);
    let baseline = inputs.reported(Presented::Serving, false);
    assert_eq!(
        baseline.len(),
        64,
        "SHA-256 over the loaded leaf's DER, hex"
    );
    assert_eq!(
        inputs.reported(Presented::Serving, true),
        baseline,
        "nothing has rotated, so both sides name the same certificate"
    );

    // WHAT KUBELET DOES TO A DIRECTORY MOUNT: the same path, other bytes.
    let rotated_onto = self_signed("after.yadgar.internal");
    assert_ne!(loaded, rotated_onto, "two mints must differ");
    std::fs::write(&path, &rotated_onto).expect("the leaf cert-manager wrote");

    assert_eq!(
        inputs.reported(Presented::Serving, false),
        baseline,
        "`serving_before` must keep naming the leaf that was LOADED, never the file"
    );
    let after = inputs.reported(Presented::Serving, true);
    assert_eq!(after.len(), 64, "SHA-256 over the rotated leaf's DER, hex");
    assert_ne!(
        after, baseline,
        "`serving_after` must name the leaf on disk, or the line reports a rotation by \
             printing one fingerprint twice"
    );

    // AND THE TWO KINDS ARE NOT EACH OTHER. One process holds both, so a
    // `reported` that answered with the serving leaf under both labels would
    // land on a plausible fingerprint and pass every assertion above.
    let client = root.join("client.pem");
    std::fs::write(&client, self_signed("caller.yadgar.internal")).expect("a client leaf");
    let both = inputs.certificate(Presented::Client, None, &client);
    assert_ne!(
        both.reported(Presented::Client, false),
        both.reported(Presented::Serving, false),
        "the serving and client leaves are different certificates"
    );

    std::fs::remove_dir_all(&root).expect("the scratch directory");
}

/// **A SECOND LEAF OF THE SAME KIND USED TO OVERWRITE THE FIRST** (ledger
/// 1417): `self.client = Some(leaf)` had one slot, so `iam`'s broker leaf
/// could never sit beside its unnamed client leaf without erasing it.
///
/// The two leaves here carry DIFFERENT `not_after` dates on purpose — the
/// property this change exists for is observable only if a broken
/// (single-slot) implementation collapses them to one, and minting the
/// same leaf twice would not show that collapse.
#[test]
fn a_named_leaf_does_not_overwrite_the_primary_leaf_of_the_same_kind() {
    let root = scratch();
    let primary_path = root.join("client.pem");
    let broker_path = root.join("broker.pem");
    std::fs::write(
        &primary_path,
        self_signed_expiring("caller.yadgar.internal", 2028, 6, 15),
    )
    .expect("the primary client leaf");
    std::fs::write(
        &broker_path,
        self_signed_expiring("broker.yadgar.internal", 2031, 6, 15),
    )
    .expect("the broker leaf");

    let inputs = Inputs::new("test")
        .certificate(Presented::Client, None, &primary_path)
        .certificate(Presented::Client, Some("broker"), &broker_path);

    // THE PRIMARY ACCESSOR STILL ANSWERS FOR THE PRIMARY LEAF ALONE — a
    // consumer that never learns about the broker leaf sees exactly what it
    // saw before this change.
    assert_eq!(
        inputs.not_after(Presented::Client),
        Some(1_844_640_000), // 2028-06-15T00:00:00Z
        "the unnamed accessor must keep naming the PRIMARY leaf, not whichever was added last"
    );
    assert_eq!(
        inputs.watched(),
        vec![primary_path.as_path(), broker_path.as_path()],
        "both files are watched, so a rotation of EITHER one is still noticed"
    );

    std::fs::remove_dir_all(&root).expect("the scratch directory");
}

/// **ONE GAUGE PER LEAF, NEVER ONE PER KIND.** The mutant this kills: a
/// single-slot `Inputs` that keeps only the LAST leaf written for a kind
/// would export exactly one `kind="client"` series, and that series would
/// carry whichever `not_after` was written last — plausible, not caught by
/// an equality against the same value on both sides.
#[test]
fn export_not_after_emits_one_gauge_per_leaf_with_a_bounded_name_label() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

    let root = scratch();
    let serving_path = root.join("tls.pem");
    let primary_path = root.join("client.pem");
    let broker_path = root.join("broker.pem");
    std::fs::write(
        &serving_path,
        self_signed_expiring("yadgar.internal", 2027, 6, 15),
    )
    .expect("the serving leaf");
    std::fs::write(
        &primary_path,
        self_signed_expiring("caller.yadgar.internal", 2028, 6, 15),
    )
    .expect("the primary client leaf");
    std::fs::write(
        &broker_path,
        self_signed_expiring("broker.yadgar.internal", 2031, 6, 15),
    )
    .expect("the broker leaf");

    let inputs = Inputs::new("test")
        .certificate(Presented::Serving, None, &serving_path)
        .certificate(Presented::Client, None, &primary_path)
        .certificate(Presented::Client, Some("broker"), &broker_path);

    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || inputs.export_not_after());

    let mut seen: Vec<(Vec<(String, String)>, f64)> = snapshotter
        .snapshot()
        .into_vec()
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

    assert_eq!(
        seen,
        vec![
            (
                vec![
                    ("service".to_string(), "test".to_string()),
                    ("kind".to_string(), "client".to_string()),
                ],
                1_844_640_000.0, // 2028-06-15T00:00:00Z, the PRIMARY client leaf
            ),
            (
                vec![
                    ("service".to_string(), "test".to_string()),
                    ("kind".to_string(), "client".to_string()),
                    ("name".to_string(), "broker".to_string()),
                ],
                1_939_248_000.0, // 2031-06-15T00:00:00Z, the NAMED broker leaf
            ),
            (
                vec![
                    ("service".to_string(), "test".to_string()),
                    ("kind".to_string(), "serving".to_string()),
                ],
                1_813_017_600.0, // 2027-06-15T00:00:00Z
            ),
        ],
        "the primary leaf of each kind keeps the pre-1417 label set (no `name`); the named \
             broker leaf is a THIRD series, not a replacement of the primary client one, and the \
             three values are not interchangeable"
    );

    std::fs::remove_dir_all(&root).expect("the scratch directory");
}

/// [`File::named_certificate`] THREADS THROUGH `Material` AND [`Inputs::of`]
/// exactly like [`File::certificate`] already does — proved here rather
/// than only against the private `certificate` method, because a service
/// reaches this through its own `Material` impl, never by calling `Inputs`
/// directly.
#[test]
fn a_named_certificate_threads_through_material_and_the_fold() {
    struct TwoClientLeaves {
        primary: PathBuf,
        broker: PathBuf,
    }

    impl Material for TwoClientLeaves {
        fn files(&self) -> Vec<File<'_>> {
            vec![
                File::certificate(Presented::Client, &self.primary),
                File::named_certificate(Presented::Client, "broker", &self.broker),
            ]
        }
    }

    let root = scratch();
    let primary = root.join("client.pem");
    let broker = root.join("broker.pem");
    std::fs::write(
        &primary,
        self_signed_expiring("caller.yadgar.internal", 2028, 6, 15),
    )
    .expect("the primary client leaf");
    std::fs::write(
        &broker,
        self_signed_expiring("broker.yadgar.internal", 2031, 6, 15),
    )
    .expect("the broker leaf");

    let material = TwoClientLeaves {
        primary: primary.clone(),
        broker: broker.clone(),
    };
    let inputs = Inputs::of("test", &[&material]);

    assert_eq!(
        inputs.watched(),
        vec![primary.as_path(), broker.as_path()],
        "the fold watches both files the Material named"
    );
    assert_eq!(
        inputs.not_after(Presented::Client),
        Some(1_844_640_000), // 2028-06-15T00:00:00Z — the PRIMARY leaf alone
        "the unnamed accessor must still answer for the primary leaf when the two arrive \
             through the SAME Material, not only when added one call at a time"
    );

    std::fs::remove_dir_all(&root).expect("the scratch directory");
}
