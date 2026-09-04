//! WHEN the signal handlers are installed, which is a different question from
//! whether they work.
//!
//! `tests/shutdown.rs` proves that a SIGTERM drains the server. It cannot prove
//! WHEN [`yadgar_lifecycle::shutdown`] armed the handler, and its own comments
//! used to claim it did. The reason it cannot is structural rather than a
//! missing assertion: that rig waits for the port to accept before it raises the
//! signal, and a port that accepts belongs to a task the executor has already
//! polled — so the shutdown future has been polled too, and the handlers are
//! installed by then whether `shutdown` registers eagerly or on first poll.
//!
//! **Measured, not argued.** A mutant moving both `signal()` calls INSIDE the
//! returned future survives the whole of this crate's suite, and survived the
//! suites of both services that had adopted the crate. The window the doc named
//! was never open while any test was watching.
//!
//! **THIS FILE OPENS THAT WINDOW AND KEEPS IT OPEN.** It calls `shutdown()`,
//! never polls the future it returned, and raises SIGTERM into the gap. Nothing
//! else in the process has installed a handler for that signal, so:
//!
//! - **armed eagerly** — the disposition is already replaced, the process
//!   survives, tokio records the signal against a receiver nobody has polled,
//!   and the first poll below resolves on it;
//! - **armed lazily** — the disposition is still "terminate the process", and
//!   this test binary is gone at the `kill`. Cargo reports it as a test that
//!   died on signal 15 rather than as a failed assertion, which is exactly the
//!   production failure written down: a SIGTERM in the window between binding
//!   the listener and the executor reaching the shutdown future kills the pod
//!   outright and severs every request in flight.
//!
//! There is no sleep and no race. The two outcomes differ in whether the process
//! is alive, which no amount of scheduling luck can blur.
//!
//! **ONE TEST IN ITS OWN BINARY, and here that is load-bearing rather than
//! tidy.** A signal is delivered to a PROCESS, and the FIRST `shutdown()` call
//! in a process arms the handler for every test after it — so a second test in
//! this file would silently destroy the measurement, leaving a file that passes
//! against the lazy mutant while appearing to check it. That is the same shape
//! as the defect this file exists to close. Cargo compiles each `tests/*.rs` to
//! its own binary, so the isolation this needs is the file itself.

use std::process::Command;
use std::time::Duration;

use yadgar_lifecycle::shutdown;

/// Send SIGTERM to this test process.
///
/// **Through `kill(1)` rather than `libc::raise`, because this package FORBIDS
/// unsafe code** — `[lints.rust] unsafe_code = "forbid"` in `Cargo.toml` applies
/// to every target including this one, and `libc::raise` is an unsafe call. The
/// signal is identical either way; only the spelling differs.
///
/// A failure to run `kill` is reported as a RIG failure in its own words, so a
/// missing binary can never be mistaken for a shutdown that did not happen.
fn sigterm_this_process() {
    let pid = std::process::id().to_string();
    let status = Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .unwrap_or_else(|e| panic!("the test rig could not run kill(1) to raise SIGTERM: {e}"));
    assert!(
        status.success(),
        "the test rig ran kill(1) and it refused: {status}"
    );
}

/// **NOT `#[tokio::test]`, and that is the whole rig.** `#[tokio::test]` runs
/// the body INSIDE `block_on`, so every future the body builds is one the
/// executor is already driving, and there is no un-polled state to raise a
/// signal into. Driving the runtime by hand is what lets the signal land between
/// the call and the first poll.
#[test]
fn the_handlers_are_armed_when_shutdown_is_called_not_when_it_is_first_polled() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime with the io and time drivers");

    // Registration needs a runtime IN SCOPE; being INSIDE one is a different
    // thing, and it is the thing this test refuses to do. `enter()` supplies the
    // context without driving anything, so the future below is built and then
    // left alone.
    let signals = {
        let _context = runtime.enter();
        shutdown().expect("the signal handlers install")
    };

    // THE WINDOW. `signals` has never been polled and will not be until the
    // `block_on` below. A process that armed nothing until first poll takes
    // SIGTERM's default disposition here and never reaches another line.
    sigterm_this_process();

    // Reaching this at all is half the assertion; the other half is that the
    // signal raised into an un-polled future is not lost.
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), signals)
            .await
            .expect(
                "the process survived the SIGTERM, so a handler was installed — but the future \
                 never resolved on it. The signal raised before the first poll was dropped rather \
                 than recorded, so a pod signalled during boot would hang until the SIGKILL",
            );
    });
}
