//! The watch set as a VALUE, which is the reason this crate exists.
//!
//! **THE MUTANT THAT COULD NOT BE KILLED.** Every service built its watch set as
//! a run of builder calls inside `main.rs`, interleaved with boot:
//!
//! ```ignore
//! let mut tls_inputs = rotate::Inputs::default().listener(listen_tls.as_ref());
//! // ... forty lines of boot ...
//! tls_inputs = tls_inputs.upstream(db_tls.as_ref());
//! // ... fifty more ...
//! tls_inputs = tls_inputs.broker(nats_credentials.as_ref());
//! // ... sixty more ...
//! tls_inputs = tls_inputs.enrolment(Some(&config));
//! ```
//!
//! No test spawns the binary. Deleting any one of those lines compiled, passed
//! the entire suite, and shipped a process that would never notice that file
//! rotating. Eight such calls stand across three `main.rs` files — four in
//! `iam` (the shape above), two in `task`, two in `gateway` — and not one of
//! them is killable. The service suites cannot catch it either: each rebuilds
//! the same assembly by hand in its own test file, so the two can disagree and
//! both stay green.
//!
//! Here the set is a list, [`Inputs::of`] is the fold over it, and this file is
//! what a mutation of either dies against.

mod common;

use std::path::Path;

use common::{generation, Mount, Upstream, NAMES};
use yadgar_lifecycle::rotate::{Inputs, Presented};

const SERVICE: &str = "lifecycle-test";

/// EVERY FILE THE CONFIGURATION NAMED IS IN THE WATCH SET, AND NOTHING ELSE.
///
/// Membership, not behaviour. A fold that skipped a material — or a `Material`
/// that forgot half its pair — leaves every rotation case green, because those
/// swap the whole mount at once. This is the shape that catches it.
#[test]
fn the_watch_set_holds_every_file_the_configuration_named() {
    let mount = Mount::new(&generation("yadgar"));
    let listener = mount.listener();
    let upstream = mount.upstream();
    let broker = mount.broker();
    let enrolment = mount.enrolment_ca();

    let watched: Vec<String> = Inputs::of(SERVICE, &[&listener, &upstream, &broker, &enrolment])
        .watched()
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    for name in NAMES {
        let expected = mount.path(name).display().to_string();
        assert!(
            watched.contains(&expected),
            "{name} is not in the watch set, so a rotation of it would never be noticed. \
             Watching: {watched:?}"
        );
    }
    assert_eq!(watched.len(), NAMES.len(), "and nothing else: {watched:?}");
}

/// THE MUTANT, MADE ON PURPOSE. One entry removed from the list — the exact edit
/// that used to compile and pass everything.
///
/// This is the case that could not be written before: the assembly lived in
/// `main.rs`, so there was no expression a test could hold two versions of.
#[test]
fn a_watch_set_assembled_without_one_member_is_caught() {
    let mount = Mount::new(&generation("yadgar"));
    let listener = mount.listener();
    let upstream = mount.upstream();
    let broker = mount.broker();
    let enrolment = mount.enrolment_ca();

    let whole = Inputs::of(SERVICE, &[&listener, &upstream, &broker, &enrolment]);
    // THE MUTANT: `&enrolment` deleted. In `main.rs` this was
    // `tls_inputs = tls_inputs.enrolment(Some(&config));` removed.
    let mutant = Inputs::of(SERVICE, &[&listener, &upstream, &broker]);

    assert!(
        whole.watched().contains(&enrolment.as_path()),
        "the whole assembly must watch the file its configuration named"
    );
    assert!(
        !mutant.watched().contains(&enrolment.as_path()),
        "the mutant must be observably different; if it is not, this assertion proves nothing"
    );
    assert_eq!(
        mutant.watched().len(),
        whole.watched().len() - 1,
        "one member dropped, one file unwatched — and the count is what a service's own \
         assembly test asserts against"
    );
}

/// THE SAME, ONE LEVEL DOWN: a `Material` that forgets half of what it read.
///
/// A listener reads a certificate AND the private key beside it. An
/// implementation returning only the certificate watches a file that rotates in
/// lockstep with one it does not, so half the time the swap is caught and half
/// the time it is not.
#[test]
fn a_material_that_names_only_half_its_pair_is_caught() {
    let mount = Mount::new(&generation("yadgar"));
    let listener = mount.listener();

    let whole = Inputs::of(SERVICE, &[&listener]);
    assert_eq!(
        whole.watched(),
        vec![
            mount.path("tls.pem").as_path(),
            mount.path("tls-key.pem").as_path()
        ],
        "a listener reads its certificate and the key belonging to it"
    );

    // THE MUTANT: an `Upstream` whose client pair was dropped. It still watches
    // its bundle, so nothing about it looks broken.
    let without_client = Upstream {
        ca: mount.path("ca.pem"),
        client: None,
    };
    assert_eq!(
        Inputs::of(SERVICE, &[&without_client]).watched(),
        vec![mount.path("ca.pem").as_path()],
        "and the client leaf ADR-0516 makes load-bearing is simply absent"
    );
}

/// THE ORDER OF THE LIST IS THE ORDER OF THE WATCH SET, and the serving
/// certificate is first because it is what the gauge and the fingerprints speak
/// for.
#[test]
fn the_list_decides_the_order_and_the_certificate_leads_it() {
    let mount = Mount::new(&generation("yadgar"));
    let listener = mount.listener();
    let upstream = mount.upstream();

    let inputs = Inputs::of(SERVICE, &[&listener, &upstream]);
    assert_eq!(
        inputs.watched(),
        vec![
            mount.path("tls.pem").as_path(),
            mount.path("tls-key.pem").as_path(),
            mount.path("ca.pem").as_path(),
            mount.path("client.pem").as_path(),
            mount.path("client-key.pem").as_path(),
        ]
    );
    assert!(inputs.fingerprint(Presented::Serving).is_some());
    assert!(inputs.fingerprint(Presented::Client).is_some());
}

/// NOTHING CONFIGURED CONTRIBUTES NOTHING, and that is the ordinary case.
///
/// Every TLS setting in this estate is opt-in and off by default, so a `None`
/// must fold to an empty list rather than needing a branch at each call site —
/// which is what `Option<M>: Material` buys. It is also what let the four
/// per-service builder methods collapse into one trait: a service lists what it
/// has instead of calling a method per role.
#[test]
fn an_absent_material_contributes_nothing() {
    let mount = Mount::new(&generation("yadgar"));
    let nothing: Option<common::Listener> = None;
    assert!(Inputs::of(SERVICE, &[&nothing]).is_empty());

    // TLS OFF, a token-issuing CA set: a default install's shape. Something is
    // still read at boot, so something is still watched.
    let enrolment = mount.enrolment_ca();
    let cleartext = Inputs::of(SERVICE, &[&nothing, &Some(enrolment.clone())]);
    assert_eq!(
        cleartext.watched(),
        vec![enrolment.as_path()],
        "a cleartext deployment that read a CA at boot still watches it"
    );
}

/// A FILE NAMED BY TWO MATERIALS IS WATCHED ONCE.
///
/// `gateway` presents ONE client leaf to both of its upstreams, so the same two
/// paths arrive twice. De-duplicating means the pair is hashed once and named
/// once in the line that reports a change.
#[test]
fn a_file_named_by_two_materials_is_watched_once() {
    let mount = Mount::new(&generation("yadgar"));
    let one = mount.upstream();
    let other = Upstream {
        ca: mount.path("enrolment-ca.pem"),
        client: Some((mount.path("client.pem"), mount.path("client-key.pem"))),
    };

    let inputs = Inputs::of(SERVICE, &[&one, &other]);
    assert_eq!(
        inputs.watched(),
        vec![
            mount.path("ca.pem").as_path(),
            mount.path("client.pem").as_path(),
            mount.path("client-key.pem").as_path(),
            mount.path("enrolment-ca.pem").as_path(),
        ],
        "the shared client pair is hashed once, in the position it first appeared"
    );
}

/// A BARE PATH IS A MATERIAL, because ADR-0523's rule is about PROVENANCE and
/// not payload: a file the process read at boot is watched whatever its bytes
/// are for.
#[test]
fn a_bare_path_is_material() {
    let mount = Mount::new(&generation("yadgar"));
    let password = mount.path("broker-password");
    assert_eq!(
        Inputs::of(SERVICE, &[&password]).watched(),
        vec![password.as_path()]
    );
    assert!(
        Inputs::of(SERVICE, &[&password])
            .fingerprint(Presented::Serving)
            .is_none(),
        "a password is not a certificate, and nothing pretends it has an expiry"
    );
}

/// `take` FOLDS ONE MATERIAL AT A TIME, for a service that wants each hash
/// beside its own read rather than in one place.
///
/// It must reach the same watch set as [`Inputs::of`], or the two seams would
/// mean different things and a service could not move between them.
#[test]
fn taking_one_at_a_time_reaches_the_same_watch_set() {
    let mount = Mount::new(&generation("yadgar"));
    let listener = mount.listener();
    let upstream = mount.upstream();
    let broker = mount.broker();

    let folded = Inputs::of(SERVICE, &[&listener, &upstream, &broker]);
    let taken = Inputs::new(SERVICE)
        .take(&listener)
        .take(&upstream)
        .take(&broker);
    assert_eq!(folded.watched(), taken.watched());
    assert_eq!(
        folded.fingerprint(Presented::Serving),
        taken.fingerprint(Presented::Serving)
    );
}

/// AN UNREADABLE FILE IS STILL WATCHED. It is a configuration a deployment
/// stated, and dropping it would silently shrink the watch set to the files that
/// happened to exist at boot.
#[test]
fn a_file_that_could_not_be_read_is_still_in_the_watch_set() {
    let absent = Path::new("/etc/yadgar/quokka-4d81/absent.pem").to_path_buf();
    let inputs = Inputs::of(SERVICE, &[&absent]);
    assert_eq!(inputs.watched(), vec![absent.as_path()]);
    assert!(!inputs.is_empty());
}
