//! The rig the `serve-tls` suites share: authorities and leaves minted per run,
//! PEM files handed over as paths, and a listener built through the one
//! function a service builds its listener with.
//!
//! **ITS OWN MODULE, NOT `tests/common`.** Every rotation target compiles
//! `tests/common/mod.rs`, so a helper added there for these suites alone would
//! be dead code in four other targets. This module is compiled only by the
//! `serve-tls` targets.
//!
//! The binding, readiness and naming helpers are `task-db`'s
//! `tests/serve_tls.rs` rig, carried over with the measurements behind them:
//! one port bound on EVERY address `localhost` resolves to, and temporary names
//! made unique by a counter rather than a clock (ledger 629, ledger 708).

#![allow(dead_code)]

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::{http, Service};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use yadgar_lifecycle::serve_tls::{self, ServerTls, LISTEN};

/// The name every serving leaf is issued for, and the name the rig listens on.
pub const SERVED_NAME: &str = "localhost";

/// The chart block the rig's listener reads its keys under.
pub const CHART: &str = "tls";

/// A certificate authority, minted per run.
pub struct Authority {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

/// A leaf and its private key, both PEM.
pub struct Leaf {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Which validity window a leaf carries.
#[derive(Clone, Copy)]
pub enum Validity {
    /// rcgen's default window, which contains today.
    Current,
    /// A window that closed years ago.
    Expired,
}

impl Authority {
    pub fn new(name: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        Self {
            issuer: CertifiedIssuer::self_signed(params, key).unwrap(),
        }
    }

    pub fn pem(&self) -> String {
        self.issuer.pem()
    }

    /// The certificate this rig's listener presents.
    pub fn serving_leaf(&self) -> Leaf {
        self.leaf(
            vec![SERVED_NAME.to_string()],
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            Validity::Current,
        )
    }

    /// A client leaf carrying exactly the extended key usages given. An EMPTY
    /// list makes rcgen omit the extension, which is the "no EKU" leaf.
    pub fn client_leaf(&self, ekus: Vec<ExtendedKeyUsagePurpose>, validity: Validity) -> Leaf {
        self.leaf(vec!["a-client".to_string()], ekus, validity)
    }

    /// The ordinary client leaf: `clientAuth`, valid today.
    pub fn valid_client(&self) -> Leaf {
        self.client_leaf(vec![ExtendedKeyUsagePurpose::ClientAuth], Validity::Current)
    }

    fn leaf(&self, sans: Vec<String>, ekus: Vec<ExtendedKeyUsagePurpose>, v: Validity) -> Leaf {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(sans.clone()).unwrap();
        params.extended_key_usages = ekus;
        params.distinguished_name.push(DnType::CommonName, &sans[0]);
        if let Validity::Expired = v {
            params.not_before = date_time_ymd(2020, 1, 1);
            params.not_after = date_time_ymd(2021, 1, 1);
        }
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }
}

/// One reading of the clock per PROCESS, so two runs given the same recycled pid
/// do not name the same files.
fn run_id() -> u128 {
    static RUN: OnceLock<u128> = OnceLock::new();
    *RUN.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    })
}

/// A temporary PEM name, unique within the process by a counter — a clock is a
/// timestamp, not a nonce (ledger 629).
fn unique_name() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "yadgar-lifecycle-serve-tls-{}-{}-{}.pem",
        std::process::id(),
        run_id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// A file that deletes itself, so material is handed over as a PATH (D80).
pub struct TempPem(PathBuf);

impl TempPem {
    pub fn with(contents: &str) -> Self {
        let path = std::env::temp_dir().join(unique_name());
        let mut file = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("{} already exists or cannot be made: {e}", path.display()));
        file.write_all(contents.as_bytes()).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn display(&self) -> String {
        self.0.display().to_string()
    }
}

impl Drop for TempPem {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A lookup over a fixed list of `(key, value)` pairs — the seam `from_env`
/// reads the environment through, so every case exercises the shipped path.
pub fn lookup(pairs: &[(&str, String)]) -> impl Fn(&str) -> Option<String> {
    let pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    move |key| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

/// A listener's files, kept alive for as long as the listener needs them.
pub struct Mounted {
    pub tls: ServerTls,
    _files: Vec<TempPem>,
}

/// Mount a serving leaf from `server_ca`, and — when `client_ca_pem` is given —
/// a client CA bundle, then read the configuration through `from_lookup` with
/// `LISTEN_TLS_ENABLED=1` and the given client-auth mode.
pub fn mount(server_ca: &Authority, mode: &str, client_ca_pem: Option<&str>) -> Mounted {
    let leaf = server_ca.serving_leaf();
    let cert = TempPem::with(&leaf.cert_pem);
    let key = TempPem::with(&leaf.key_pem);
    let mut pairs = vec![
        ("LISTEN_TLS_ENABLED", "1".to_string()),
        ("LISTEN_TLS_CERT_FILE", cert.display()),
        ("LISTEN_TLS_KEY_FILE", key.display()),
        ("LISTEN_TLS_CLIENT_AUTH", mode.to_string()),
    ];
    let mut files = vec![cert, key];
    if let Some(pem) = client_ca_pem {
        let ca = TempPem::with(pem);
        pairs.push(("LISTEN_TLS_CLIENT_CA_FILE", ca.display()));
        files.push(ca);
    }
    let tls = ServerTls::from_lookup(LISTEN, CHART, lookup(&pairs))
        .expect("a complete configuration")
        .expect("LISTEN_TLS_ENABLED=1 enables TLS");
    Mounted { tls, _files: files }
}

/// Serve gRPC through [`serve_tls::server`] on every address `SERVED_NAME`
/// resolves to, and return the shared port. `Routes::default()` answers every
/// method with `Unimplemented`, which is all a case needs: the question is
/// whether a request reached the server at all.
pub async fn serve(tls: Option<&ServerTls>) -> u16 {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((SERVED_NAME, 0))
        .await
        .unwrap()
        .collect();
    assert!(!addrs.is_empty(), "{SERVED_NAME} resolved to nothing");

    let (port, listeners) = bind_one_port_on_every_address(&addrs).await;
    for listener in listeners {
        let mut builder = serve_tls::server(tls).expect("a usable listener configuration");
        let router = builder.add_routes(tonic::service::Routes::default());
        tokio::spawn(async move {
            let _ = router
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });
    }
    ready(port).await;
    port
}

const BIND_ATTEMPTS: usize = 50;

/// One ephemeral port bound on EVERY address. `AddrInUse` is retried; every
/// other error is permanent and names the address (ledger 708).
async fn bind_one_port_on_every_address(addrs: &[SocketAddr]) -> (u16, Vec<TcpListener>) {
    for _ in 0..BIND_ATTEMPTS {
        let first = TcpListener::bind(addrs[0])
            .await
            .unwrap_or_else(|e| panic!("no free port on {}: {e}", addrs[0].ip()));
        let port = first.local_addr().unwrap().port();

        let mut listeners = vec![first];
        for addr in &addrs[1..] {
            match TcpListener::bind(SocketAddr::new(addr.ip(), port)).await {
                Ok(listener) => listeners.push(listener),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => break,
                Err(e) => panic!("binding {} on port {port}: {e}", addr.ip()),
            }
        }
        if listeners.len() == addrs.len() {
            return (port, listeners);
        }
    }
    panic!(
        "no ephemeral port was free on all {} addresses in {BIND_ATTEMPTS} attempts",
        addrs.len()
    );
}

/// Wait until the port accepts TCP, rather than sleeping a guessed interval.
async fn ready(port: u16) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect((SERVED_NAME, port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the test server never accepted a connection on port {port}");
}

/// The bound on every network step, so a refused arm fails rather than hangs.
const STEP: Duration = Duration::from_secs(10);

/// Dial over TLS, trusting `server_ca_pem`, presenting `client` if given, and
/// send ONE request.
///
/// **ASSERTED AT THE REQUEST, NOT AT THE CONNECT.** Under TLS 1.3 the server
/// verifies the client's certificate AFTER the client considers the handshake
/// done, so a refused certificate can let `connect()` return and fail only when
/// the first request is read. A connect error and a request error are therefore
/// the same answer here: `Err`. `Ok(200)` means the request crossed the
/// transport and the server answered (with `Unimplemented`).
pub async fn request_over_tls(
    port: u16,
    server_ca_pem: &str,
    client: Option<&Leaf>,
) -> Result<u16, String> {
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(server_ca_pem))
        .domain_name(SERVED_NAME);
    if let Some(leaf) = client {
        tls = tls.identity(Identity::from_pem(&leaf.cert_pem, &leaf.key_pem));
    }
    let endpoint = Endpoint::from_shared(format!("https://{SERVED_NAME}:{port}"))
        .unwrap()
        .connect_timeout(STEP)
        .tls_config(tls)
        .map_err(|e| format!("{e}"))?;
    let channel = endpoint.connect().await.map_err(|e| format!("{e:?}"))?;
    request(channel).await
}

/// Dial in cleartext and send one request.
pub async fn request_in_cleartext(port: u16) -> Result<u16, String> {
    let channel = Endpoint::from_shared(format!("http://{SERVED_NAME}:{port}"))
        .unwrap()
        .connect_timeout(STEP)
        .connect()
        .await
        .map_err(|e| format!("{e:?}"))?;
    request(channel).await
}

async fn request(mut channel: Channel) -> Result<u16, String> {
    let req = http::Request::builder()
        .version(http::Version::HTTP_2)
        .method("POST")
        .uri(format!(
            "https://{SERVED_NAME}/yadgar.lifecycle.v1.Probe/Probe"
        ))
        .header("content-type", "application/grpc")
        .body(tonic::body::Body::empty())
        .unwrap();

    std::future::poll_fn(|cx| channel.poll_ready(cx))
        .await
        .map_err(|e| format!("{e:?}"))?;
    match tokio::time::timeout(STEP, channel.call(req)).await {
        Err(_) => Err("the request timed out".to_string()),
        Ok(Ok(response)) => Ok(response.status().as_u16()),
        Ok(Err(e)) => Err(format!("{e:?}")),
    }
}
