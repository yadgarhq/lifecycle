//! What a rotation schedule can fail to say, and why. Split out of
//! `rotate.rs` (ledger 719) — [`ScheduleError`] is a taxonomy of refusals,
//! distinct from [`super::schedule`]'s reading logic that raises them.

use super::schedule::{POLL_KNOB, SPLAY_MAX_KNOB};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotate::{Configuration, CONFIG_DIR, SHARED_DOCUMENT};
    use std::path::{Path, PathBuf};

    /// A document at the path the mount produces, under a directory of this
    /// test's own. Nothing here overwrites a file in place: each case builds its
    /// own tree, so a stale file cannot make a broken implementation pass.
    fn document(body: &str) -> (PathBuf, Configuration) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "yadgar-config-err-{}-{}",
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
            "yadgar-config-err-absent-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        Configuration::under(&root)
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
