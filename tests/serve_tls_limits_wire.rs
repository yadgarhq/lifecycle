//! The limits ON THE WIRE: what the listener built by [`serve_tls::server`]
//! actually advertises and does, read off a raw TCP socket (ADR-1006).
//!
//! **THE VALUES ARE CHOSEN BELOW EVERY LIBRARY DEFAULT, and that is what makes
//! these cases able to fail** (yaadgaar #370). hyper already advertises a 16 KiB
//! header list, so a case at 16 KiB stays green with the setter deleted. 4 KiB
//! and seven streams are values no layer below this crate would pick, so a
//! SETTINGS frame carrying them can only have come from the builder.
//!
//! **RAW FRAMES, NOT AN h2 CLIENT.** A client library acts on the peer's
//! SETTINGS and answers its PINGs without exposing either; the bytes are the
//! only place the question is asked directly.

mod serve_tls_rig;

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use serve_tls_rig::{lookup, request_in_cleartext, serve_routes_with, serve_with, SERVED_NAME};
use tonic::codegen::{http, Service};
use tonic::server::NamedService;
use yadgar_lifecycle::serve_tls::{ServerLimits, LISTEN};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const ACK: u8 = 0x1;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

fn limits(interval_secs: u64, timeout_secs: u64) -> ServerLimits {
    aged(interval_secs, timeout_secs, 1800)
}

fn aged(interval_secs: u64, timeout_secs: u64, age_secs: u64) -> ServerLimits {
    let pairs = [
        ("LISTEN_MAX_CONCURRENT_STREAMS", "7".to_string()),
        ("LISTEN_KEEPALIVE_INTERVAL_SECS", interval_secs.to_string()),
        ("LISTEN_KEEPALIVE_TIMEOUT_SECS", timeout_secs.to_string()),
        ("LISTEN_MAX_HEADER_LIST_BYTES", "4096".to_string()),
        ("LISTEN_MAX_CONNECTION_AGE_SECS", age_secs.to_string()),
    ];
    ServerLimits::from_lookup(LISTEN, "server.limits", lookup(&pairs)).expect("in range")
}

struct Frame {
    kind: u8,
    flags: u8,
    payload: Vec<u8>,
}

/// Open a cleartext h2 connection: the client preface and an empty SETTINGS.
async fn connect(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect((SERVED_NAME, port)).await.unwrap();
    stream.write_all(PREFACE).await.unwrap();
    stream
        .write_all(&[0, 0, 0, SETTINGS, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    stream
}

async fn frame(stream: &mut TcpStream) -> Frame {
    next_frame(stream).await.expect("the server sent a frame")
}

/// The value the server's first SETTINGS frame gives `id`, if it names it.
fn setting(settings: &Frame, id: u16) -> Option<u32> {
    settings
        .payload
        .as_chunks::<6>()
        .0
        .iter()
        .find_map(|entry| {
            (u16::from_be_bytes([entry[0], entry[1]]) == id)
                .then(|| u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]))
        })
}

#[tokio::test]
async fn the_server_settings_advertise_the_configured_streams_and_header_list() {
    let port = serve_with(None, &limits(30, 10)).await;
    let mut stream = connect(port).await;
    let settings = tokio::time::timeout(Duration::from_secs(5), frame(&mut stream))
        .await
        .expect("the server's SETTINGS within 5s");
    assert_eq!(
        settings.kind, SETTINGS,
        "the first server frame is SETTINGS"
    );
    assert_eq!(settings.flags & ACK, 0, "and it is not an ACK");
    assert_eq!(
        setting(&settings, SETTINGS_MAX_CONCURRENT_STREAMS),
        Some(7),
        "MAX_CONCURRENT_STREAMS"
    );
    assert_eq!(
        setting(&settings, SETTINGS_MAX_HEADER_LIST_SIZE),
        Some(4096),
        "MAX_HEADER_LIST_SIZE"
    );
}

/// An idle connection is PINGed on the configured interval: the bound that
/// finds a peer which vanished without a FIN.
#[tokio::test]
async fn an_idle_connection_is_pinged_on_the_configured_interval() {
    let port = serve_with(None, &limits(2, 1)).await;
    let mut stream = connect(port).await;
    let started = Instant::now();
    let ping = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let f = frame(&mut stream).await;
            if f.kind == PING && f.flags & ACK == 0 {
                return f;
            }
        }
    })
    .await
    .expect("a keepalive PING within interval + slack");
    assert_eq!(ping.payload.len(), 8);
    assert!(
        started.elapsed() >= Duration::from_millis(1500),
        "the PING came after {:?}, before the 2s interval",
        started.elapsed()
    );
}

/// A connection older than the configured age is sent GOAWAY and then closed
/// (ADR-1006). Keepalive is set far above the age, so the GOAWAY can only come
/// from the age bound. The client answers every PING, as a live peer does, so
/// the server's graceful close is not waiting on it.
#[tokio::test]
async fn a_connection_older_than_the_age_is_sent_goaway_then_closed() {
    let port = serve_with(None, &aged(600, 10, 1)).await;
    let mut stream = connect(port).await;
    let started = Instant::now();
    let goaway = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let f = frame(&mut stream).await;
            if f.kind == PING && f.flags & ACK == 0 {
                answer(&mut stream, &f).await;
            } else if f.kind == SETTINGS && f.flags & ACK == 0 {
                stream
                    .write_all(&[0, 0, 0, SETTINGS, ACK, 0, 0, 0, 0])
                    .await
                    .unwrap();
            } else if f.kind == GOAWAY {
                return f;
            }
        }
    })
    .await
    .expect("a GOAWAY within the 1s age + slack");
    assert!(
        started.elapsed() >= Duration::from_millis(800),
        "the GOAWAY came after {:?}, before the 1s age",
        started.elapsed()
    );
    assert!(
        goaway.payload.len() >= 8,
        "a GOAWAY carries 8 bytes or more"
    );

    // The connection then CLOSES. hyper's graceful close PINGs before its
    // final GOAWAY, so the client keeps answering until the socket ends.
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(f) = next_frame(&mut stream).await {
            if f.kind == PING && f.flags & ACK == 0 {
                answer(&mut stream, &f).await;
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "the connection stayed open after its GOAWAY"
    );
}

/// THE REASON THE AGE WAS LEFT OUT UNTIL NOW (yaadgaar #290 item 2, #417). A
/// call still running when the connection reaches its age must FINISH: the
/// GOAWAY stops new streams, not the ones in flight. On tonic 0.14.6 the
/// connection task panicked right after the GOAWAY and this call failed with
/// BrokenPipe; tonic 0.14.7 carries the fix (tonic#2780).
#[tokio::test]
async fn a_call_in_flight_when_the_age_is_reached_completes() {
    let routes = tonic::service::Routes::new(Slow(Duration::from_secs(3)));
    let port = serve_routes_with(None, &aged(600, 10, 1), routes).await;
    let started = Instant::now();
    let answer = request_in_cleartext(port).await;
    assert_eq!(answer, Ok(200), "the in-flight call was cut off");
    assert!(
        started.elapsed() >= Duration::from_secs(3),
        "the call returned after {:?}, before its handler finished",
        started.elapsed()
    );
}

/// The next frame, or `None` once the server has closed the socket.
async fn next_frame(stream: &mut TcpStream) -> Option<Frame> {
    let mut head = [0u8; 9];
    stream.read_exact(&mut head).await.ok()?;
    let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.ok()?;
    Some(Frame {
        kind: head[3],
        flags: head[4],
        payload,
    })
}

/// ACK a PING with its own payload, as a live peer does. A write to a socket
/// the server already closed is not an error here: closing is the outcome the
/// case waits for.
async fn answer(stream: &mut TcpStream, ping: &Frame) {
    let mut out = vec![0, 0, 8, PING, ACK, 0, 0, 0, 0];
    out.extend_from_slice(&ping.payload);
    let _ = stream.write_all(&out).await;
}

/// A handler that answers OK after a fixed delay, under the method name the
/// rig's request dials.
#[derive(Clone)]
struct Slow(Duration);

impl NamedService for Slow {
    const NAME: &'static str = "yadgar.lifecycle.v1.Probe";
}

impl Service<http::Request<tonic::body::Body>> for Slow {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: http::Request<tonic::body::Body>) -> Self::Future {
        let delay = self.0;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Ok(http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .header("grpc-status", "0")
                .body(tonic::body::Body::empty())
                .expect("a static response"))
        })
    }
}
