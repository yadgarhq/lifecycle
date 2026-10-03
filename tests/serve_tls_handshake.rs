//! The client-auth modes, proved by real handshakes (ADR-0846, ADR-0852).
//!
//! **A test that inspects configuration passes against the broken version of
//! this change**, so nothing here does. Every case stands a listener up through
//! `serve_tls::server` — the function a service builds its gRPC server with —
//! and asks whether ONE REQUEST crossed the transport. The arm numbers are the
//! B-U4 matrix in the ledger-sweep plan; the configuration-only arms live in
//! `tests/serve_tls_config.rs`.
//!
//! Every wrong anchor, expired leaf and EKU variant is MINTED HERE, per run.
//!
//! **THE DOCUMENTED HOLE (arm 13).** A leaf from the right authority that
//! carries NO extended-key-usage extension is accepted: webpki treats an absent
//! EKU as unrestricted. Only a leaf that names some EKU and omits `clientAuth`
//! is refused (arm 4). Closing that is the issuer's job — the platform chart
//! issues every client leaf with `clientAuth` — and this case pins today's
//! behaviour so a change to it is seen rather than discovered.

mod serve_tls_rig;

use rcgen::ExtendedKeyUsagePurpose;
use serve_tls_rig::{mount, request_in_cleartext, request_over_tls, serve, Authority, Validity};
use yadgar_lifecycle::serve_tls::ClientAuth;

/// One listener in `mode`, trusting `client_ca` for client certificates.
struct Hop {
    server_ca: Authority,
    client_ca: Authority,
}

impl Hop {
    fn new() -> Self {
        Self {
            server_ca: Authority::new("serving authority"),
            client_ca: Authority::new("client authority"),
        }
    }
}

fn refused(outcome: &Result<u16, String>) -> bool {
    outcome.is_err()
}

// ---- required ---------------------------------------------------------------

/// Arm 1: `required` and no certificate presented → refused.
#[tokio::test]
async fn required_refuses_a_caller_presenting_no_certificate() {
    let hop = Hop::new();
    let m = mount(&hop.server_ca, "required", Some(&hop.client_ca.pem()));
    assert_eq!(m.tls.client_auth(), ClientAuth::Required);
    let port = serve(Some(&m.tls)).await;

    let outcome = request_over_tls(port, &hop.server_ca.pem(), None).await;
    assert!(
        refused(&outcome),
        "required must refuse a cert-less caller: {outcome:?}"
    );
}

/// Arm 2: `required` and a leaf from an authority the listener does not trust →
/// refused.
#[tokio::test]
async fn required_refuses_a_leaf_under_the_wrong_anchor() {
    let hop = Hop::new();
    let m = mount(&hop.server_ca, "required", Some(&hop.client_ca.pem()));
    let port = serve(Some(&m.tls)).await;

    let stranger = Authority::new("a stranger").valid_client();
    let outcome = request_over_tls(port, &hop.server_ca.pem(), Some(&stranger)).await;
    assert!(
        refused(&outcome),
        "required must refuse a stranger's leaf: {outcome:?}"
    );
}

/// Arm 3: `required` and a valid leaf from the trusted authority → accepted.
#[tokio::test]
async fn required_accepts_a_valid_leaf() {
    let hop = Hop::new();
    let m = mount(&hop.server_ca, "required", Some(&hop.client_ca.pem()));
    let port = serve(Some(&m.tls)).await;

    let leaf = hop.client_ca.valid_client();
    let outcome = request_over_tls(port, &hop.server_ca.pem(), Some(&leaf)).await;
    assert_eq!(outcome, Ok(200));
}

/// Arm 4: `required` and a right-authority leaf whose EKU is `serverAuth` only →
/// refused. A serving certificate is not a client credential.
#[tokio::test]
async fn required_refuses_a_server_auth_only_leaf() {
    let hop = Hop::new();
    let m = mount(&hop.server_ca, "required", Some(&hop.client_ca.pem()));
    let port = serve(Some(&m.tls)).await;

    let leaf = hop
        .client_ca
        .client_leaf(vec![ExtendedKeyUsagePurpose::ServerAuth], Validity::Current);
    let outcome = request_over_tls(port, &hop.server_ca.pem(), Some(&leaf)).await;
    assert!(
        refused(&outcome),
        "a serverAuth-only leaf must be refused: {outcome:?}"
    );
}

/// Arm 19: `required` and an expired right-authority leaf → refused.
#[tokio::test]
async fn required_refuses_an_expired_leaf() {
    let hop = Hop::new();
    let m = mount(&hop.server_ca, "required", Some(&hop.client_ca.pem()));
    let port = serve(Some(&m.tls)).await;

    let leaf = hop
        .client_ca
        .client_leaf(vec![ExtendedKeyUsagePurpose::ClientAuth], Validity::Expired);
    let outcome = request_over_tls(port, &hop.server_ca.pem(), Some(&leaf)).await;
    assert!(
        refused(&outcome),
        "an expired leaf must be refused: {outcome:?}"
    );
}

/// Arm 13, THE DOCUMENTED HOLE: a right-authority leaf with NO EKU extension is
/// accepted. See the module docs.
#[tokio::test]
async fn required_accepts_a_right_authority_leaf_with_no_eku() {
    let hop = Hop::new();
    let m = mount(&hop.server_ca, "required", Some(&hop.client_ca.pem()));
    let port = serve(Some(&m.tls)).await;

    let leaf = hop.client_ca.client_leaf(vec![], Validity::Current);
    let outcome = request_over_tls(port, &hop.server_ca.pem(), Some(&leaf)).await;
    assert_eq!(
        outcome,
        Ok(200),
        "the no-EKU hole is documented, not closed"
    );
}

/// Arm 20: a CA file holding TWO authorities → a leaf under EITHER is accepted.
/// This is the shape a CA rotation takes: old and new anchors side by side.
#[tokio::test]
async fn a_bundle_of_two_authorities_accepts_a_leaf_under_either() {
    let hop = Hop::new();
    let second = Authority::new("the next client authority");
    let bundle = format!("{}{}", hop.client_ca.pem(), second.pem());
    let m = mount(&hop.server_ca, "required", Some(&bundle));
    let port = serve(Some(&m.tls)).await;

    for (which, ca) in [("first", &hop.client_ca), ("second", &second)] {
        let leaf = ca.valid_client();
        let outcome = request_over_tls(port, &hop.server_ca.pem(), Some(&leaf)).await;
        assert_eq!(outcome, Ok(200), "a leaf under the {which} authority");
    }
}

// ---- optional ---------------------------------------------------------------

/// Arm 5: `optional` and no certificate → accepted. This is why optional is a
/// staging step and not a control on its own (ADR-0846).
#[tokio::test]
async fn optional_accepts_a_caller_presenting_no_certificate() {
    let hop = Hop::new();
    let m = mount(&hop.server_ca, "optional", Some(&hop.client_ca.pem()));
    assert_eq!(m.tls.client_auth(), ClientAuth::Optional);
    let port = serve(Some(&m.tls)).await;

    assert_eq!(
        request_over_tls(port, &hop.server_ca.pem(), None).await,
        Ok(200)
    );
}

/// Arm 6: `optional` still VERIFIES what is presented: a wrong-anchor leaf →
/// refused.
#[tokio::test]
async fn optional_refuses_a_leaf_under_the_wrong_anchor() {
    let hop = Hop::new();
    let m = mount(&hop.server_ca, "optional", Some(&hop.client_ca.pem()));
    let port = serve(Some(&m.tls)).await;

    let stranger = Authority::new("a stranger").valid_client();
    let outcome = request_over_tls(port, &hop.server_ca.pem(), Some(&stranger)).await;
    assert!(
        refused(&outcome),
        "optional must refuse a stranger's leaf: {outcome:?}"
    );
}

/// Arm 7: `optional` and a valid leaf → accepted.
#[tokio::test]
async fn optional_accepts_a_valid_leaf() {
    let hop = Hop::new();
    let m = mount(&hop.server_ca, "optional", Some(&hop.client_ca.pem()));
    let port = serve(Some(&m.tls)).await;

    let leaf = hop.client_ca.valid_client();
    assert_eq!(
        request_over_tls(port, &hop.server_ca.pem(), Some(&leaf)).await,
        Ok(200)
    );
}

/// Arm 18: `optional` and an expired right-authority leaf → refused.
#[tokio::test]
async fn optional_refuses_an_expired_leaf() {
    let hop = Hop::new();
    let m = mount(&hop.server_ca, "optional", Some(&hop.client_ca.pem()));
    let port = serve(Some(&m.tls)).await;

    let leaf = hop
        .client_ca
        .client_leaf(vec![ExtendedKeyUsagePurpose::ClientAuth], Validity::Expired);
    let outcome = request_over_tls(port, &hop.server_ca.pem(), Some(&leaf)).await;
    assert!(
        refused(&outcome),
        "an expired leaf must be refused: {outcome:?}"
    );
}

// ---- off --------------------------------------------------------------------

/// Arm 8: `off` and no certificate → accepted.
#[tokio::test]
async fn off_accepts_a_caller_presenting_no_certificate() {
    let hop = Hop::new();
    let m = mount(&hop.server_ca, "off", None);
    assert_eq!(m.tls.client_auth(), ClientAuth::Off);
    assert_eq!(m.tls.client_ca_file(), None);
    let port = serve(Some(&m.tls)).await;

    assert_eq!(
        request_over_tls(port, &hop.server_ca.pem(), None).await,
        Ok(200)
    );
}

/// Arm 8, the half an accessor cannot prove: `off` installs NO `client_ca_root`.
/// Even with a client CA mounted, a stranger's leaf is accepted — a listener
/// that had installed a verifier would refuse it, as arms 2 and 6 show.
#[tokio::test]
async fn off_installs_no_verifier_even_with_a_client_ca_mounted() {
    let hop = Hop::new();
    let m = mount(&hop.server_ca, "off", Some(&hop.client_ca.pem()));
    let port = serve(Some(&m.tls)).await;

    let stranger = Authority::new("a stranger").valid_client();
    assert_eq!(
        request_over_tls(port, &hop.server_ca.pem(), Some(&stranger)).await,
        Ok(200)
    );
}

/// Arm 17, the accepted half: `LISTEN_TLS_ENABLED=0` with `off` is the cleartext
/// listener, and a cleartext request is answered.
#[tokio::test]
async fn tls_disabled_with_client_auth_off_serves_cleartext() {
    use serve_tls_rig::{lookup, CHART};
    use yadgar_lifecycle::serve_tls::{ServerTls, LISTEN};

    let pairs = [
        ("LISTEN_TLS_ENABLED", "0".to_string()),
        ("LISTEN_TLS_CLIENT_AUTH", "off".to_string()),
    ];
    let tls = ServerTls::from_lookup(LISTEN, CHART, lookup(&pairs)).expect("=0 + off is valid");
    assert_eq!(tls, None, "=0 is the cleartext listener");

    let port = serve(tls.as_ref()).await;
    assert_eq!(request_in_cleartext(port).await, Ok(200));
}

/// The downgrade guard carried from the local copies: a TLS listener never
/// answers a cleartext caller, in any mode.
#[tokio::test]
async fn a_tls_listener_refuses_a_cleartext_caller_in_every_mode() {
    for mode in ["off", "optional", "required"] {
        let hop = Hop::new();
        let m = mount(&hop.server_ca, mode, Some(&hop.client_ca.pem()));
        let port = serve(Some(&m.tls)).await;
        let outcome = request_in_cleartext(port).await;
        assert!(
            refused(&outcome),
            "{mode}: cleartext must be refused: {outcome:?}"
        );
    }
}
