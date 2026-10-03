//! The configuration arms of the B-U4 matrix: what `ServerTls::from_lookup`
//! and `ServerTls::builder` refuse at BOOT, before anything binds.
//!
//! **THE REFUSAL SENTENCES ARE A CONTRACT**, asserted whole rather than by
//! substring. Six gRPC servers adopt this type (B-U5) and each adoption asserts
//! the same sentence, so a sentence that drifted here would redden six
//! repositories — or, asserted loosely, drift silently into all six. Every
//! ADR-0845 / ADR-0854 refusal names the VARIABLE and the CHART KEY, because an
//! operator reads the first in a crash log and edits the second.

mod serve_tls_rig;

use std::sync::{Arc, Mutex};

use serve_tls_rig::{lookup, Authority, TempPem, CHART};
use yadgar_lifecycle::serve_tls::{ClientAuth, ServeTlsError, ServerTls, LISTEN};

/// A valid serving pair on disk, so a case varies exactly one key.
struct Pair {
    cert: TempPem,
    key: TempPem,
}

fn pair() -> Pair {
    let leaf = Authority::new("serving authority").serving_leaf();
    Pair {
        cert: TempPem::with(&leaf.cert_pem),
        key: TempPem::with(&leaf.key_pem),
    }
}

fn read(pairs: &[(&str, String)]) -> Result<Option<ServerTls>, ServeTlsError> {
    ServerTls::from_lookup(LISTEN, CHART, lookup(pairs))
}

fn refusal(pairs: &[(&str, String)]) -> String {
    match read(pairs) {
        // KEY NAMES ONLY. The values are file paths to key material, and
        // CodeQL's `rust/cleartext-logging` reads a panic message as a log.
        Ok(_) => {
            let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
            panic!("{keys:?} must refuse the boot, and it booted")
        }
        Err(e) => e.to_string(),
    }
}

fn s(v: &str) -> String {
    v.to_string()
}

/// Arm 15: `LISTEN_TLS_ENABLED` absent or empty refuses, naming it and
/// `tls.enabled` (ADR-0845). Absence used to mean cleartext.
#[test]
fn an_absent_or_empty_tls_switch_refuses_naming_the_variable_and_the_chart_key() {
    let want = "LISTEN_TLS_ENABLED is not set. Set the chart value `tls.enabled` to true (it \
                renders \"1\", TLS) or false (it renders \"0\", cleartext); an absent value \
                refuses to boot rather than defaulting to cleartext (ADR-0845)";
    let auth = ("LISTEN_TLS_CLIENT_AUTH", s("off"));
    assert_eq!(refusal(std::slice::from_ref(&auth)), want);
    for empty in ["", "   "] {
        assert_eq!(
            refusal(&[("LISTEN_TLS_ENABLED", s(empty)), auth.clone()]),
            want,
            "{empty:?}"
        );
    }
}

/// The switch takes exactly `"1"` or `"0"`. A permissive parse is how a setting
/// meant to be off ends up on.
#[test]
fn a_tls_switch_that_is_neither_one_nor_zero_refuses() {
    for bad in ["true", "false", "yes", "on", "2", "01"] {
        assert_eq!(
            refusal(&[
                ("LISTEN_TLS_ENABLED", s(bad)),
                ("LISTEN_TLS_CLIENT_AUTH", s("off")),
            ]),
            format!(
                "LISTEN_TLS_ENABLED is {bad:?}, which is neither \"1\" nor \"0\". Set the chart \
                 value `tls.enabled` (ADR-0845)"
            )
        );
    }
}

/// Arm 16: `LISTEN_TLS_CLIENT_AUTH` absent or empty refuses, naming it and
/// `tls.clientAuth` (ADR-0854) — with TLS on AND with TLS off, because absence
/// always refuses and `off` is the only way to say "no client auth".
#[test]
fn an_absent_or_empty_client_auth_mode_refuses_naming_the_variable_and_the_chart_key() {
    let want = "LISTEN_TLS_CLIENT_AUTH is not set. Set it to `off`, `optional` or `required`, \
                through the chart value `tls.clientAuth`; an absent value refuses to boot rather \
                than defaulting (ADR-0854)";
    let p = pair();
    for enabled in ["1", "0"] {
        let base = vec![
            ("LISTEN_TLS_ENABLED", s(enabled)),
            ("LISTEN_TLS_CERT_FILE", p.cert.display()),
            ("LISTEN_TLS_KEY_FILE", p.key.display()),
        ];
        assert_eq!(refusal(&base), want, "ENABLED={enabled}, mode absent");
        for empty in ["", "  "] {
            let mut pairs = base.clone();
            pairs.push(("LISTEN_TLS_CLIENT_AUTH", s(empty)));
            assert_eq!(refusal(&pairs), want, "ENABLED={enabled}, mode {empty:?}");
        }
    }
}

/// Arm 9: a mode string that is not exactly one of the three refuses.
#[test]
fn a_bad_client_auth_mode_refuses() {
    for bad in [
        "Off",
        "REQUIRED",
        "on",
        "true",
        "1",
        "none",
        "require",
        "optional,required",
    ] {
        assert_eq!(
            refusal(&[
                ("LISTEN_TLS_ENABLED", s("0")),
                ("LISTEN_TLS_CLIENT_AUTH", s(bad)),
            ]),
            format!(
                "LISTEN_TLS_CLIENT_AUTH is {bad:?}, which is not `off`, `optional` or \
                 `required`. Set the chart value `tls.clientAuth` (ADR-0854)"
            )
        );
    }
}

/// Arm 17, the refused half: `LISTEN_TLS_ENABLED=0` with `optional` or
/// `required` — a cleartext listener cannot verify a client certificate, and
/// serving cleartext while the mode claims verification is the lie this refuses.
#[test]
fn tls_disabled_with_client_auth_on_refuses() {
    for mode in ["optional", "required"] {
        assert_eq!(
            refusal(&[
                ("LISTEN_TLS_ENABLED", s("0")),
                ("LISTEN_TLS_CLIENT_AUTH", s(mode)),
            ]),
            format!(
                "LISTEN_TLS_CLIENT_AUTH is `{mode}` but LISTEN_TLS_ENABLED is \"0\": a \
                 cleartext listener cannot verify a client certificate. Set `tls.enabled` to \
                 true, or `tls.clientAuth` to `off` (ADR-0854)"
            )
        );
    }
}

/// Arm 10: a verifying mode with no client CA configured refuses.
#[test]
fn a_verifying_mode_without_a_client_ca_refuses() {
    let p = pair();
    for mode in ["optional", "required"] {
        assert_eq!(
            refusal(&[
                ("LISTEN_TLS_ENABLED", s("1")),
                ("LISTEN_TLS_CERT_FILE", p.cert.display()),
                ("LISTEN_TLS_KEY_FILE", p.key.display()),
                ("LISTEN_TLS_CLIENT_AUTH", s(mode)),
            ]),
            format!(
                "LISTEN_TLS_CLIENT_AUTH is `{mode}` but LISTEN_TLS_CLIENT_CA_FILE is not set, \
                 so there is no authority to verify a client certificate against. Set the chart \
                 value `tls.clientCaSecret`"
            )
        );
    }
}

/// TLS on with either half of the serving pair missing refuses, naming the key.
#[test]
fn tls_enabled_without_a_certificate_or_a_key_refuses() {
    let p = pair();
    let cert = ("LISTEN_TLS_CERT_FILE", p.cert.display());
    let key = ("LISTEN_TLS_KEY_FILE", p.key.display());
    let head = [
        ("LISTEN_TLS_ENABLED", s("1")),
        ("LISTEN_TLS_CLIENT_AUTH", s("off")),
    ];
    let without_cert = [head[0].clone(), head[1].clone(), key];
    let without_key = [head[0].clone(), head[1].clone(), cert];
    assert_eq!(
        refusal(&without_cert),
        "LISTEN_TLS_ENABLED is \"1\" but LISTEN_TLS_CERT_FILE is not set. Set the chart value \
         `tls.certSecret` (ADR-0845)"
    );
    assert_eq!(
        refusal(&without_key),
        "LISTEN_TLS_ENABLED is \"1\" but LISTEN_TLS_KEY_FILE is not set. Set the chart value \
         `tls.certSecret` (ADR-0845)"
    );
}

/// The three modes, each read to the value it names.
#[test]
fn each_mode_reads_to_what_it_names() {
    let p = pair();
    let ca = TempPem::with(&Authority::new("client authority").pem());
    for (text, mode) in [
        ("off", ClientAuth::Off),
        ("optional", ClientAuth::Optional),
        ("required", ClientAuth::Required),
    ] {
        let tls = read(&[
            ("LISTEN_TLS_ENABLED", s("1")),
            ("LISTEN_TLS_CERT_FILE", p.cert.display()),
            ("LISTEN_TLS_KEY_FILE", p.key.display()),
            ("LISTEN_TLS_CLIENT_AUTH", s(text)),
            ("LISTEN_TLS_CLIENT_CA_FILE", ca.display()),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(tls.client_auth(), mode);
        assert_eq!(tls.client_auth().to_string(), text);
        assert_eq!(tls.cert_file(), p.cert.path());
        assert_eq!(tls.key_file(), p.key.path());
    }
}

/// Configure a verifying listener whose client CA file holds `contents`, and
/// return what `builder()` refused with.
fn builder_refusal(ca_path: &str) -> String {
    let p = pair();
    let tls = read(&[
        ("LISTEN_TLS_ENABLED", s("1")),
        ("LISTEN_TLS_CERT_FILE", p.cert.display()),
        ("LISTEN_TLS_KEY_FILE", p.key.display()),
        ("LISTEN_TLS_CLIENT_AUTH", s("required")),
        ("LISTEN_TLS_CLIENT_CA_FILE", s(ca_path)),
    ])
    .unwrap()
    .unwrap();
    match tls.builder() {
        Ok(_) => panic!("a verifying listener with this client CA file must refuse the boot"),
        Err(e) => e.to_string(),
    }
}

/// Arm 11: an empty or non-PEM client CA file refuses at boot, naming the path.
/// tonic would drop every unparsable entry silently and then fail with "no root
/// anchors", which names no file; this refusal comes first.
#[test]
fn an_empty_or_non_pem_client_ca_refuses_naming_the_path() {
    for contents in ["", "   \n", "there is no certificate in this file\n"] {
        let ca = TempPem::with(contents);
        assert_eq!(
            builder_refusal(&ca.display()),
            format!(
                "the client CA file {} holds no PEM certificate, so no client certificate could \
                 ever verify against it",
                ca.display()
            ),
            "{contents:?}"
        );
    }
}

/// Arm 11, the unreadable form: a client CA path that is not there names it.
#[test]
fn a_missing_client_ca_file_refuses_naming_the_path() {
    let missing = std::env::temp_dir().join("yadgar-lifecycle-no-such-client-ca-5b1e.pem");
    let message = builder_refusal(&missing.display().to_string());
    assert!(
        message.starts_with(&format!(
            "cannot read the client CA file {}: ",
            missing.display()
        )),
        "{message}"
    );
}

/// Run `f` with a subscriber capturing every event as text, synchronously.
fn capture(f: impl FnOnce()) -> String {
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Buf::default();
    let sink = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || sink.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let bytes = buf.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

/// Arm 12: a client CA configured while the mode is `off` boots — leaving it in
/// place is how a staged rollout is reverted — but WARNS, because a deployment
/// that believes it verifies callers and does not should see that in its log.
#[test]
fn a_client_ca_with_client_auth_off_boots_with_a_warning() {
    let p = pair();
    let ca = TempPem::with(&Authority::new("client authority").pem());
    let pairs = [
        ("LISTEN_TLS_ENABLED", s("1")),
        ("LISTEN_TLS_CERT_FILE", p.cert.display()),
        ("LISTEN_TLS_KEY_FILE", p.key.display()),
        ("LISTEN_TLS_CLIENT_AUTH", s("off")),
        ("LISTEN_TLS_CLIENT_CA_FILE", ca.display()),
    ];
    let mut outcome = None;
    let log = capture(|| outcome = Some(read(&pairs)));
    let tls = outcome
        .unwrap()
        .expect("off + a CA boots")
        .expect("TLS is on");
    assert_eq!(tls.client_auth(), ClientAuth::Off);
    assert_eq!(tls.client_ca_file(), None, "off verifies against nothing");
    assert!(log.contains("WARN"), "{log}");
    assert!(
        log.contains(
            "LISTEN_TLS_CLIENT_CA_FILE names a client CA but LISTEN_TLS_CLIENT_AUTH is `off`, so \
             this listener verifies NO client certificate"
        ),
        "{log}"
    );
}

/// The quiet case that keeps arm 12 honest: `off` with no CA logs nothing.
#[test]
fn client_auth_off_with_no_client_ca_is_silent() {
    let p = pair();
    let pairs = [
        ("LISTEN_TLS_ENABLED", s("1")),
        ("LISTEN_TLS_CERT_FILE", p.cert.display()),
        ("LISTEN_TLS_KEY_FILE", p.key.display()),
        ("LISTEN_TLS_CLIENT_AUTH", s("off")),
    ];
    let log = capture(|| {
        read(&pairs).unwrap().unwrap();
    });
    assert_eq!(log, "");
}
