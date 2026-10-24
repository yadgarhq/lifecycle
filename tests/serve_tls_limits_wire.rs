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

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use serve_tls_rig::{lookup, serve_with, SERVED_NAME};
use yadgar_lifecycle::serve_tls::{ServerLimits, LISTEN};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const ACK: u8 = 0x1;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

fn limits(interval_secs: u64, timeout_secs: u64) -> ServerLimits {
    let pairs = [
        ("LISTEN_MAX_CONCURRENT_STREAMS", "7".to_string()),
        ("LISTEN_KEEPALIVE_INTERVAL_SECS", interval_secs.to_string()),
        ("LISTEN_KEEPALIVE_TIMEOUT_SECS", timeout_secs.to_string()),
        ("LISTEN_MAX_HEADER_LIST_BYTES", "4096".to_string()),
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
    let mut head = [0u8; 9];
    stream
        .read_exact(&mut head)
        .await
        .expect("the server sent a frame");
    let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.unwrap();
    Frame {
        kind: head[3],
        flags: head[4],
        payload,
    }
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
