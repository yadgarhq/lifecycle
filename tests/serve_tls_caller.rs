//! WHO THE CALLER IS: the common name on the client leaf a verifying listener
//! accepted (ADR-0936, `plans/the-d35-seeder.md` stage 2).
//!
//! mTLS proves a caller holds a leaf the internal authority issued. It does not
//! say WHICH caller, because every module's leaf verifies against the same
//! authority. A verb that admits one caller only — `project-db`'s
//! `SyncProjects` admits `project-caller`, `project`'s admits `seeder-caller` —
//! reads the identity off the leaf, and both read it through this one function
//! so the two hops cannot parse it two ways.
//!
//! The unit cases mint DER directly. The handshake case stands a listener up
//! through `serve_tls::server`, under `required`, and lets the HANDLER report
//! what it read: tonic's `Request::peer_certs()` is present only when tonic's own
//! acceptor wrapped a `TcpStream` incoming, so "the helper parses a leaf" and
//! "a handler is given a leaf to parse" are two claims, and only a real
//! handshake makes the second.

mod serve_tls_rig;

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use rcgen::{CertificateParams, DnType, KeyPair};
use rustls_pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::{http, Service};
use tonic::server::NamedService;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use serve_tls_rig::{mount, Authority, SERVED_NAME};
use yadgar_lifecycle::serve_tls::{self, caller_common_name, leaf_common_name};

/// A self-signed certificate whose subject carries `common_names`, as DER.
fn der_with(common_names: &[&str]) -> CertificateDer<'static> {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    // rcgen's default subject carries a CN of its own; clear it so the case
    // states every name the subject holds.
    params.distinguished_name = rcgen::DistinguishedName::new();
    for name in common_names {
        params.distinguished_name.push(DnType::CommonName, *name);
    }
    params.self_signed(&key).unwrap().der().clone()
}

#[test]
fn a_leaf_s_common_name_is_its_identity() {
    assert_eq!(
        leaf_common_name(&der_with(&["project-caller"])),
        Some("project-caller".to_string())
    );
}

/// NO NAME IS NO IDENTITY. An empty string here would be an identity a caller
/// could match against an empty expectation.
#[test]
fn a_leaf_with_no_common_name_has_no_identity() {
    assert_eq!(leaf_common_name(&der_with(&[])), None);
}

/// TWO NAMES ARE NO IDENTITY EITHER. Picking the first or the last would let
/// a leaf carrying `project-caller` beside its real name pass a check by
/// order — so an ambiguous subject is refused rather than resolved.
///
/// rcgen keys its subject by attribute TYPE, so it cannot mint two CNs. The
/// case mints a CN and an `O`, then rewrites the `O` attribute's OID
/// (`2.5.4.10`) to the CN's (`2.5.4.3`). The two encodings are the same length,
/// so the DER stays well-formed. The signature no longer verifies, which does
/// not matter here: the parser reads the subject, and verification is the
/// listener's job, done before any handler runs.
#[test]
fn a_leaf_with_two_common_names_has_no_identity() {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "task-caller");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "project-caller");
    let mut der = params.self_signed(&key).unwrap().der().to_vec();

    const O: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x0a];
    const CN: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03];
    let mut rewritten = 0;
    let mut i = 0;
    while i + O.len() <= der.len() {
        if der[i..i + O.len()] == O {
            der[i..i + O.len()].copy_from_slice(&CN);
            rewritten += 1;
        }
        i += 1;
    }
    assert!(rewritten > 0, "the fixture found no O attribute to rewrite");

    assert_eq!(leaf_common_name(&CertificateDer::from(der)), None);
}

#[test]
fn bytes_that_are_not_a_certificate_have_no_identity() {
    assert_eq!(
        leaf_common_name(&CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00])),
        None
    );
}

/// A request that crossed no TLS handshake — a cleartext listener, or a
/// handler called directly — carries no chain, and so no caller.
#[test]
fn a_request_with_no_peer_chain_has_no_caller() {
    assert_eq!(caller_common_name(&tonic::Request::new(())), None);
}

/// The header the echo handler answers with.
const ECHO: &str = "x-caller";

/// Answers every request with the caller identity `caller_common_name` reads
/// from the request a handler is given.
#[derive(Clone)]
struct Echo;

impl NamedService for Echo {
    const NAME: &'static str = "yadgar.lifecycle.v1.Probe";
}

impl Service<http::Request<tonic::body::Body>> for Echo {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        // THROUGH `tonic::Request`, as a generated handler receives it — so the
        // case exercises `caller_common_name` itself, not a reimplementation.
        let caller =
            caller_common_name(&tonic::Request::from_http(req)).unwrap_or_else(|| "none".into());
        Box::pin(async move {
            Ok(http::Response::builder()
                .status(200)
                .header(ECHO, caller)
                .body(tonic::body::Body::empty())
                .unwrap())
        })
    }
}

/// THE POINT: under `required`, the handler reads the identity the caller's
/// leaf carries — in the shape `platform` issues: a common name, and a dNSName
/// SAN equal to it.
#[tokio::test]
async fn a_handler_behind_a_required_listener_reads_the_caller_s_common_name() {
    let server_ca = Authority::new("serving authority");
    let client_ca = Authority::new("client authority");
    let m = mount(&server_ca, "required", Some(&client_ca.pem()));

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = serve_tls::server(Some(&m.tls)).unwrap().add_service(Echo);
    tokio::spawn(async move {
        let _ = router
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });

    let leaf = client_ca.client_named("project-caller");
    let mut channel = Endpoint::from_shared(format!("https://127.0.0.1:{port}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(10))
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(server_ca.pem()))
                .domain_name(SERVED_NAME)
                .identity(Identity::from_pem(&leaf.cert_pem, &leaf.key_pem)),
        )
        .unwrap()
        .connect()
        .await
        .expect("the handshake completes");

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
        .unwrap();
    let response = channel.call(req).await.expect("answered");
    assert_eq!(
        response.headers().get(ECHO).and_then(|v| v.to_str().ok()),
        Some("project-caller")
    );
}
