//! `ServerTls` as `rotate::Material`: the files the listener read at boot are
//! exactly the files the watcher is handed (ADR-0523).
//!
//! A file the listener reads and the watcher does not is a rotation the process
//! never notices; a file the watcher watches and the listener never read is a
//! restart for nothing. So the list is asserted exactly, in both modes that
//! differ: with a client CA read and without one.

mod serve_tls_rig;

use serve_tls_rig::{mount, Authority};
use yadgar_lifecycle::rotate::{File, Material, Presented};

#[test]
fn a_verifying_listener_watches_its_certificate_its_key_and_its_client_ca() {
    let client_ca = Authority::new("client authority");
    let m = mount(
        &Authority::new("serving"),
        "required",
        Some(&client_ca.pem()),
    );
    let ca = m.tls.client_ca_file().expect("required reads a client CA");
    assert_eq!(
        m.tls.files(),
        vec![
            File::certificate(Presented::Serving, m.tls.cert_file()),
            File::read(m.tls.key_file()),
            File::read(ca),
        ]
    );
}

#[test]
fn a_listener_with_client_auth_off_watches_no_client_ca() {
    let client_ca = Authority::new("client authority");
    let m = mount(&Authority::new("serving"), "off", Some(&client_ca.pem()));
    assert_eq!(
        m.tls.files(),
        vec![
            File::certificate(Presented::Serving, m.tls.cert_file()),
            File::read(m.tls.key_file()),
        ],
        "off never reads the CA, so a change to it must not restart the process"
    );
}
