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
//! for its sake. Once [`crate::rotate::watch`] can end the serving future on
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
/// bounds a drain KUBELET started; when [`crate::rotate::watch`] ends the serve,
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
/// Below: it must expire before the SIGKILL on the SIGTERM path, or it bounds
/// nothing there. Kubernetes defaults `terminationGracePeriodSeconds` to 30s and
/// no chart in this estate sets or exposes it, so there is no rendered value to
/// assert against and the relationship is stated here rather than faked as a
/// test. 25s leaves five seconds to log and exit. **A deployment that lowers the
/// grace period below 25s must lower this with it**, which is the one thing a
/// reader has to carry away from this paragraph.
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
/// race. `tests/shutdown.rs` raises SIGTERM after this call and before the
/// future is awaited, so that window is what it measures.
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
    #[test]
    fn the_budget_expires_before_the_default_grace_period() {
        const DEFAULT_GRACE: Duration = Duration::from_secs(30);
        assert!(
            DRAIN_BUDGET < DEFAULT_GRACE,
            "a {DRAIN_BUDGET:?} budget under a {DEFAULT_GRACE:?} grace period is not a budget: \
             SIGKILL lands first and nothing this crate does is reached"
        );
    }
}
