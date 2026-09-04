//! The drain budget, and the defect it was introduced as.
//!
//! **THE BUG THIS FILE EXISTS TO KEEP DEAD.** The first attempt at bounding the
//! drain wrapped the SERVING FUTURE in `tokio::time::timeout`:
//!
//! ```ignore
//! tokio::time::timeout(DRAIN_BUDGET, server.serve_with_shutdown(addr, stop)).await
//! ```
//!
//! `timeout` fixes its deadline when it is CALLED, and the serving future spans
//! the server's whole life — so that bounds the SERVER, not its drain. The
//! process logged "the drain did not finish within its budget" and exited 25
//! seconds after boot, on every boot, TLS on or off, with no rotation and no
//! signal, and kubelet restarted it to do it again. A flapping authentication
//! plane, in exchange for a watcher whose default poll interval of 60s meant it
//! never completed one pass.
//!
//! It passed 123 tests, because every one of them tested a piece and none tested
//! the composition. So the assertions below are about ELAPSED TIME rather than
//! outcome: a server asked to stop at 600ms under a 100ms budget must still be
//! serving at 350ms, and the call must return at 600ms and not at 100ms. The
//! broken shape fails both.
//!
//! [`yadgar_lifecycle::drain_within`] exists to make that shape unavailable: it
//! takes the server ALREADY SPAWNED and the sender that asks it to stop, so the
//! budget cannot be started before the request that it bounds.
//!
//! **THE RIG IS A BARE ACCEPT LOOP, and that is deliberate.** `drain_within` is
//! generic over a `JoinHandle`, so it bounds tonic, axum or this equally — and a
//! lifecycle crate that pulled in a gRPC stack to test itself would make every
//! adopter pay for one.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use yadgar_lifecycle::{drain_within, Drain};

/// Far shorter than the real `DRAIN_BUDGET`, so a case finishes quickly. What is
/// under test is WHEN the clock starts, which is independent of its length.
const BUDGET: Duration = Duration::from_millis(100);

/// Long enough after the budget that a clock started at the wrong moment cannot
/// be mistaken for one started at the right moment.
const SERVE_FOR: Duration = Duration::from_millis(600);

/// A real server on a real port, already spawned, with a oneshot as its shutdown
/// future — exactly the shape `main` uses.
///
/// It answers nothing. The LIFECYCLE is what is under test, not any handler: it
/// accepts, it stops accepting when asked, and it releases the port on the way
/// out.
async fn spawned() -> (
    u16,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .expect("a free loopback port");
    let port = listener.local_addr().unwrap().port();
    let (ask_to_stop, stop_requested) = tokio::sync::oneshot::channel();

    let serving = tokio::spawn(async move {
        let accepting = async {
            loop {
                // Accepted and dropped. A connection is proof the listener is
                // live, which is all any assertion here needs.
                let _ = listener.accept().await;
            }
        };
        tokio::select! {
            _ = stop_requested => {}
            () = accepting => {}
        }
        // The listener is dropped here, which is what releases the port.
    });
    (port, serving, ask_to_stop)
}

async fn accepts(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

/// THE REGRESSION. The budget must not run until something asks the server to
/// stop.
///
/// The broken shape ends the server at `BUDGET` — 100ms — while `stop` has not
/// resolved and nothing has asked for anything. Both assertions below catch it:
/// the port is closed at 350ms, and the call returns far too early.
#[tokio::test]
async fn the_budget_does_not_run_until_something_asks_the_server_to_stop() {
    let (port, serving, ask_to_stop) = spawned().await;
    assert!(accepts(port).await, "the rig never came up");

    let started = Instant::now();
    let stop = async {
        tokio::time::sleep(SERVE_FOR).await;
    };
    let still_serving = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(350)).await;
        accepts(port).await
    });

    let outcome = drain_within(serving, ask_to_stop, stop, BUDGET).await;
    let elapsed = started.elapsed();

    assert!(
        still_serving.await.unwrap(),
        "the server stopped accepting {:?} in, long before anything asked it to. The budget's \
         clock started at the wrong moment, so it bounds the SERVER rather than its drain",
        Duration::from_millis(350)
    );
    assert!(
        elapsed >= SERVE_FOR,
        "the drain returned after {elapsed:?}, before the {SERVE_FOR:?} at which shutdown was \
         requested — so the budget was already running while the server was serving normally"
    );
    assert!(
        matches!(outcome, Drain::Finished(())),
        "a server with nothing in flight drains at once"
    );
}

/// The ordinary path: asked to stop, finishes well inside its budget, and the
/// port it held is released.
#[tokio::test]
async fn a_drain_that_finishes_inside_its_budget_releases_the_port() {
    let (port, serving, ask_to_stop) = spawned().await;
    assert!(accepts(port).await, "the rig never came up");

    let outcome = drain_within(serving, ask_to_stop, std::future::ready(()), BUDGET).await;

    assert!(matches!(outcome, Drain::Finished(())));
    assert!(
        !accepts(port).await,
        "the drain returned but port {port} still accepts; the listener outlived the server"
    );
}

/// THE EXPIRY PATH. A server that will not finish is abandoned, and the caller is
/// told so rather than waiting for ever.
///
/// The stall is the server itself rather than a slow handler: what `drain_within`
/// promises is that a handle which does not complete cannot hold the process open
/// past the budget, and a task that never ends is the cleanest statement of that.
/// In production the same shape is one RPC blocked on a responsive-but-slow
/// upstream, with no deadline anywhere to end it.
#[tokio::test]
async fn a_drain_that_overruns_its_budget_ends_anyway() {
    let (ask_to_stop, stop_requested) = tokio::sync::oneshot::channel::<()>();
    let never_finishes = tokio::spawn(async move {
        let _ = stop_requested.await;
        std::future::pending::<()>().await
    });

    let started = Instant::now();
    let outcome = drain_within(never_finishes, ask_to_stop, std::future::ready(()), BUDGET).await;

    assert!(
        matches!(outcome, Drain::Overran),
        "a server that never finishes must be abandoned, not waited on for ever"
    );
    assert!(
        started.elapsed() >= BUDGET,
        "it gave up before the budget had even elapsed"
    );
}

/// A SERVER THAT ENDED ON ITS OWN IS NOT AN ERROR. The send fails because the
/// receiver is gone, and the drain reports what the server returned.
#[tokio::test]
async fn a_server_that_already_stopped_drains_at_once() {
    let (ask_to_stop, stop_requested) = tokio::sync::oneshot::channel::<()>();
    let already_done = tokio::spawn(async move {
        drop(stop_requested);
        "whatever the server returned"
    });

    let outcome = drain_within(already_done, ask_to_stop, std::future::ready(()), BUDGET).await;
    assert!(matches!(
        outcome,
        Drain::Finished("whatever the server returned")
    ));
}
