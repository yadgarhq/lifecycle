//! The signal a process drains on, and the budget that bounds the drain.
//!
//! [`shutdown`] is here rather than in each `main` for the reason every service
//! in this estate keeps a boot-time decision out of its binary entry point: a
//! decision inside `main` is one no test can reach, and WHICH SIGNALS END THIS
//! PROCESS is exactly the kind that fails silently. Four services listened for
//! SIGINT alone while Kubernetes sends SIGTERM, and every rolling update
//! dropped whatever was in flight.
//!
//! **[`DRAIN_BUDGET`] and [`drain_within`] belong beside it rather than in a
//! module of their own**, because they arrived with the rotation watcher and
//! for its sake. Once `crate::rotate::watch` can end the serving future on
//! its own, outside any signal, `terminationGracePeriodSeconds` never runs —
//! kubelet started no drain and its clock never starts. Worse, tokio never
//! unregisters a libc signal handler, so once a non-signal arm wins the
//! `select!` and [`shutdown`]'s receivers drop, a later SIGTERM is SWALLOWED
//! and only SIGKILL remains. The two are one decision, not two.

use std::time::Duration;

/// The longest a drain may take before the process gives up and ends anyway.
///
/// **NOTHING OUTSIDE THIS PROCESS WILL END A SELF-INITIATED DRAIN, and that is
/// what makes this necessary rather than tidy.** `terminationGracePeriodSeconds`
/// bounds a drain KUBELET started; when `crate::rotate::watch` ends the serve,
/// kubelet started nothing and its clock never runs. There is no
/// `Server::timeout`, no deadline on an upstream channel, and no liveness probe.
/// One request blocked on a responsive-but-slow upstream would otherwise leave
/// the process alive with its listener already released — NotReady, serving
/// nothing, still holding the certificate the exit existed to replace, and never
/// restarted. That is strictly worse than not exiting at all.
///
/// **A SECOND SIGTERM WOULD NOT SAVE IT EITHER.** Tokio never unregisters a
/// libc signal handler once installed (`tokio/src/signal/unix.rs`), so after
/// [`shutdown`] loses the `select!` and its receivers drop, SIGTERM is swallowed
/// rather than taking its default disposition. Only SIGKILL would end the
/// process. This budget is what makes that impossible to reach.
///
/// **A CONSTANT rather than a setting**, deliberately. It is pinned between two
/// numbers it must sit between, and a configurable value invites one that does
/// not.
///
/// Above: it must outlast the slowest legitimate call by an order of magnitude,
/// or it cuts off requests it was supposed to let finish. `iam`'s
/// `DEFAULT_REDEEM_RESPONSE_FLOOR` is the estate's only real lower bound, and
/// the constant was chosen against it; the test that compares the two lives in
/// `iam`, because that is where both numbers are.
///
/// **THAT LOWER-BOUND TEST NO LONGER WATCHES THE DEPLOYED NUMBER, and this
/// paragraph used to imply it did.** `iam` reads its redemption floor from
/// `REDEEM_RESPONSE_FLOOR_MS` with `env_required` (ADR-0569), so
/// `DEFAULT_REDEEM_RESPONSE_FLOOR` survives as the measurement the chart's value
/// was calibrated from and is read by no knob path. The assertion in
/// `iam/src/serve.rs` compares this budget against that constant, which the
/// chart happens to agree with today — so a deployment raising the floor changes
/// the number that matters and leaves the assertion green. Nothing here can fix
/// that: both of its numbers live in `iam`.
///
/// Below: it must expire before the SIGKILL on the SIGTERM path, or it bounds
/// nothing there. **The rule is `terminationGracePeriodSeconds >= DRAIN_BUDGET +
/// 5s`, plus any `preStop` sleep**, and the five seconds are what this process
/// needs to log the outcome and exit after the budget expires. At a 25s budget
/// that is 30s, which is also what Kubernetes defaults to — so today the estate
/// satisfies the rule by inheritance rather than by writing it down.
///
/// **A deployment that lowers the grace period below 30s must lower this with
/// it**, which is the one thing a reader has to carry away from this paragraph.
/// An earlier revision said "below 25s" and that was wrong by exactly the exit
/// margin: at a 25s grace period the budget expires at the same instant SIGKILL
/// lands, and the logging this margin exists for never happens.
///
/// `the_budget_and_its_exit_margin_fit_inside_the_default_grace_period` asserts
/// the rule rather than restating it. It cannot read a chart — no chart in this
/// estate sets `terminationGracePeriodSeconds` — so it pins the INHERITED
/// default as a literal (ADR-0573) and goes red the day this constant is raised
/// past what that default allows.
pub const DRAIN_BUDGET: Duration = Duration::from_secs(25);

/// What became of a drain.
#[derive(Debug)]
pub enum Drain<T> {
    /// The server stopped within its budget. Carries whatever it returned.
    Finished(T),
    /// The budget expired with work still in flight, and the caller should end
    /// the process anyway.
    Overran,
}

/// Wait for `stop`, ask the server to shut down, and give it `budget` to finish.
///
/// **THE CLOCK STARTS WHEN SHUTDOWN IS REQUESTED, AND THAT IS THE WHOLE POINT OF
/// THIS FUNCTION EXISTING.** `tokio::time::timeout` fixes its deadline when it is
/// CALLED, so wrapping the serving future itself bounds the SERVER'S WHOLE LIFE
/// rather than its drain: the process then ends `budget` after boot, on every
/// boot, with nothing having asked it to stop. That defect shipped once, and
/// `tests/drain.rs` exists to keep it dead.
///
/// The server is handed a [`tokio::sync::oneshot::Receiver`] as its shutdown
/// future — tonic's `serve_with_shutdown`, axum's `with_graceful_shutdown`, or
/// a bare accept loop — and spawned by the caller; this holds the sender. A send
/// that fails means the server already ended on its own, which is not an error.
///
/// **`Overran` is not a reason to fail.** The caller logs and exits 0: the
/// restart is the point, and a CrashLoopBackOff on top of a slow drain helps
/// nobody. See [`DRAIN_BUDGET`] for why anything at all bounds a drain that this
/// process, rather than kubelet, began.
///
/// # Panics
///
/// If the serving task panicked. A panicked server has already stopped serving,
/// and reporting that as an ordinary drain outcome would hide it.
pub async fn drain_within<T>(
    server: tokio::task::JoinHandle<T>,
    ask_to_stop: tokio::sync::oneshot::Sender<()>,
    stop: impl std::future::Future<Output = ()>,
    budget: Duration,
) -> Drain<T> {
    stop.await;
    let _ = ask_to_stop.send(());
    match tokio::time::timeout(budget, server).await {
        Ok(joined) => Drain::Finished(joined.expect("the serving task panicked")),
        Err(_) => Drain::Overran,
    }
}

/// The future a server's graceful-shutdown hook drains on: SIGTERM, and SIGINT
/// beside it.
///
/// **SIGTERM IS THE ONE THAT MATTERS, and it was the one missing.** Kubernetes
/// ends a pod by sending SIGTERM and waiting out `terminationGracePeriodSeconds`
/// before SIGKILL; it never sends SIGINT. Four binaries listened for `ctrl_c()`
/// alone, so on every rolling update the drain was simply never reached — the
/// process ran until the kill, and whatever was in flight died with it.
///
/// SIGINT is kept because it is what a terminal sends, and losing the local
/// behaviour to fix the deployed one would be a poor trade.
///
/// **BOTH HANDLERS ARE REGISTERED BEFORE THIS RETURNS, and that is the reason
/// this is a function returning a future rather than an `async fn`.** Installing
/// a handler is what replaces the signal's default disposition, which for
/// SIGTERM is "terminate the process". An `async fn` registers nothing until it
/// is first polled, so a signal arriving in the window between binding the
/// listener and the executor reaching the shutdown future would kill the process
/// outright — the precise failure this exists to prevent, reintroduced as a
/// race. `tests/arming.rs` is the file that measures it: it calls this, NEVER
/// polls what it returned, raises SIGTERM into that gap, and then polls. Lazy
/// arming does not fail an assertion there — the test binary is gone on signal
/// 15, which is the production failure in miniature.
///
/// **`tests/shutdown.rs` does NOT measure that window, and this comment used to
/// say it did.** That rig waits for its port to accept before raising the
/// signal, and a port that accepts belongs to a task the executor has already
/// polled — so the handlers are installed by then either way. A mutant moving
/// both `signal()` calls inside the returned future survived that file, this
/// crate's whole suite, and the suites of two services that had adopted it.
/// What `tests/shutdown.rs` proves is the other half, and it is worth as much:
/// that a real SIGTERM reaches a real drain rather than only a handler.
///
/// # Errors
///
/// Registration can fail, and `main` should refuse to start on it. A server that
/// cannot hear SIGTERM is one that cannot drain, and starting anyway would hide
/// that until the next rollout.
pub fn shutdown() -> std::io::Result<impl std::future::Future<Output = ()>> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    Ok(async move {
        let signal = tokio::select! {
            _ = terminate.recv() => "SIGTERM",
            _ = interrupt.recv() => "SIGINT",
        };
        // NAMED, because the two arrive for different reasons: SIGTERM is a
        // rollout or an eviction and SIGINT is a person at a terminal. An
        // operator reading why a pod went away wants to know which.
        tracing::info!(signal, "draining in-flight requests before shutting down");
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The relationship the constant exists inside, asserted rather than only
    /// described: a budget that outlasts Kubernetes' default grace period bounds
    /// nothing, because SIGKILL arrives first.
    ///
    /// **`<` WAS THE WRONG COMPARISON AND IT PASSED AT 29 SECONDS.** The doc
    /// comment on [`DRAIN_BUDGET`] says "five seconds to log and exit"; a strict
    /// inequality admits a budget that leaves one, or none but a nanosecond, and
    /// the case would still have been green while the outcome line this crate
    /// exists to write went unwritten. What the estate means is
    /// `terminationGracePeriodSeconds >= DRAIN_BUDGET + EXIT_MARGIN`, and that is
    /// what is asserted now.
    ///
    /// **BOTH NUMBERS ARE LITERALS HERE ON PURPOSE (ADR-0573).** `DEFAULT_GRACE`
    /// is Kubernetes' inherited default, not a value read from a chart: no chart
    /// in this estate sets `terminationGracePeriodSeconds`, so there is nothing
    /// to read. Should one begin to — ledger 690 proposes exactly that, at 30 —
    /// this literal becomes the number that chart must not go under, and the two
    /// should name each other rather than one deriving the other. A cross-repo
    /// derivation is machinery this fact does not deserve.
    ///
    /// `EXIT_MARGIN` is spelled here rather than exported: it is not a knob and
    /// not a bound any caller needs, it is the slack inside one inequality.
    #[test]
    fn the_budget_and_its_exit_margin_fit_inside_the_default_grace_period() {
        const DEFAULT_GRACE: Duration = Duration::from_secs(30);
        const EXIT_MARGIN: Duration = Duration::from_secs(5);
        assert!(
            DRAIN_BUDGET.saturating_add(EXIT_MARGIN) <= DEFAULT_GRACE,
            "a {DRAIN_BUDGET:?} budget plus a {EXIT_MARGIN:?} margin to log and exit does not \
             fit inside a {DEFAULT_GRACE:?} grace period: SIGKILL lands before this process \
             reports what became of the drain, and a budget nobody hears the outcome of is \
             the silent failure this crate exists to prevent"
        );
    }
}
