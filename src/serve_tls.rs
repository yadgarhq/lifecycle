//! The transport a gRPC server LISTENS on: the identity it presents, and whether
//! — and how — it verifies the certificate its caller presents.
//!
//! **ONE IMPLEMENTATION OF A SECURITY CONTROL (ADR-0846).** Six gRPC servers —
//! `iam`, `iam-db`, `task`, `task-db`, `project`, `project-db` — each held a
//! near-identical `ServerTls` copy, and NONE called `client_ca_root`, so no hop
//! in the estate verified a client certificate. ADR-0852 rules that every
//! internal hop verifies one. Writing that six times is how six copies come to
//! verify six slightly different things, so it is written here once and adopted.
//!
//! # The keys, and why none of them has a default
//!
//! Built from a PREFIX (every service passes [`LISTEN`]) and a CHART KEY (the
//! values block the keys render from, `tls` in every module chart):
//!
//! | variable | chart value | values |
//! | --- | --- | --- |
//! | `LISTEN_TLS_ENABLED` | `tls.enabled` | exactly `1` or `0` |
//! | `LISTEN_TLS_CERT_FILE`, `LISTEN_TLS_KEY_FILE` | `tls.certSecret` | paths |
//! | `LISTEN_TLS_CLIENT_AUTH` | `tls.clientAuth` | exactly `off`, `optional`, `required` |
//! | `LISTEN_TLS_CLIENT_CA_FILE` | `tls.clientCaSecret` | a path |
//!
//! **The switch and the mode are REQUIRED, and absence refuses to boot**
//! (ADR-0845, ADR-0854). A security posture must not depend on a value nobody
//! wrote, and cleartext-by-omission is the worst compiled-in default there is.
//! `off` is the emergency value for client auth; deleting the variable is a boot
//! refusal, not a way to turn verification off.
//!
//! # What `optional` is, and is not
//!
//! `optional` is tonic's `client_auth_optional(true)`, which is rustls's
//! `allow_unauthenticated`: a caller presenting NO certificate is accepted, and
//! a caller presenting one has it VERIFIED — a wrong anchor or an expired leaf
//! is still refused. It is a staging step (present → optional → required, per
//! hop) and **not a control on its own**: anyone can omit a certificate.
//!
//! # The documented hole
//!
//! A leaf from the trusted authority that carries NO extended-key-usage
//! extension is accepted, because webpki reads an absent EKU as unrestricted. A
//! leaf that names an EKU and omits `clientAuth` is refused. Closing the hole is
//! the issuer's job; `tests/serve_tls_handshake.rs` pins today's behaviour.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::CertificateDer;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

/// The prefix every service reads its listener's keys under. `LISTEN` is
/// already the variable holding the bind address, so the transport keys extend
/// a name the process has rather than inventing a second word for the listener.
pub const LISTEN: &str = "LISTEN";

/// Whether, and how, a TLS listener verifies its caller's certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuth {
    /// No client certificate is requested, and none is verified.
    Off,
    /// A presented certificate is verified; a caller presenting none is
    /// accepted. A staging step, not a control.
    Optional,
    /// Every caller must present a certificate that verifies.
    Required,
}

impl fmt::Display for ClientAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Optional => "optional",
            Self::Required => "required",
        })
    }
}

/// EXACT, case-sensitive. `Required` or `on` meaning something is how a typo
/// becomes a posture.
impl FromStr for ClientAuth {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "off" => Ok(Self::Off),
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            _ => Err(()),
        }
    }
}

/// Why the listener's transport refused to boot.
///
/// The ADR-0845 / ADR-0854 refusals carry the variable AND the chart key: the
/// operator reads the first in a crash log and edits the second.
#[derive(Debug, thiserror::Error)]
pub enum ServeTlsError {
    #[error(
        "{var} is not set. Set it to \"1\" to serve TLS or \"0\" to serve cleartext, through \
         the chart value `{chart}`; an absent value refuses to boot rather than defaulting to \
         cleartext (ADR-0845)"
    )]
    EnabledMissing { var: String, chart: String },

    #[error(
        "{var} is {value:?}, which is neither \"1\" nor \"0\". Set the chart value `{chart}` \
         (ADR-0845)"
    )]
    EnabledInvalid {
        var: String,
        chart: String,
        value: String,
    },

    #[error(
        "{var} is not set. Set it to `off`, `optional` or `required`, through the chart value \
         `{chart}`; an absent value refuses to boot rather than defaulting (ADR-0854)"
    )]
    ClientAuthMissing { var: String, chart: String },

    #[error(
        "{var} is {value:?}, which is not `off`, `optional` or `required`. Set the chart value \
         `{chart}` (ADR-0854)"
    )]
    ClientAuthInvalid {
        var: String,
        chart: String,
        value: String,
    },

    #[error(
        "{auth_var} is `{mode}` but {enabled_var} is \"0\": a cleartext listener cannot verify \
         a client certificate. Set `{enabled_chart}` to true, or `{auth_chart}` to `off` \
         (ADR-0854)"
    )]
    ClientAuthWithoutTls {
        mode: ClientAuth,
        auth_var: String,
        enabled_var: String,
        auth_chart: String,
        enabled_chart: String,
    },

    #[error("{enabled_var} is \"1\" but {var} is not set")]
    NoServingFile { enabled_var: String, var: String },

    #[error(
        "{auth_var} is `{mode}` but {var} is not set, so there is no authority to verify a \
         client certificate against. Set the chart value `{chart}`"
    )]
    NoClientCaFile {
        mode: ClientAuth,
        auth_var: String,
        var: String,
        chart: String,
    },

    #[error("cannot read the {what} {}: {source}", path.display())]
    Unreadable {
        what: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "the client CA file {} holds no PEM certificate, so no client certificate could ever \
         verify against it",
        path.display()
    )]
    ClientCaEmpty { path: PathBuf },

    #[error("the client CA file {} is not valid PEM: {detail}", path.display())]
    ClientCaUnparsable { path: PathBuf, detail: String },

    /// tonic's own `Display` is the two words `transport error`; the reason is
    /// one `source()` hop down. Kept as the source — not flattened here — so the
    /// binary's one chain flattener (ADR-0591) renders it.
    #[error("the serving identity {} / {} is unusable", cert.display(), key.display())]
    Unusable {
        cert: PathBuf,
        key: PathBuf,
        #[source]
        source: tonic::transport::Error,
    },
}

/// Every key name one listener reads, derived once from the prefix and the
/// chart key so no refusal can spell one differently from the lookup.
struct Keys {
    prefix: &'static str,
    chart: &'static str,
}

impl Keys {
    fn var(&self, suffix: &str) -> String {
        format!("{}_TLS_{suffix}", self.prefix)
    }

    fn chart(&self, leaf: &str) -> String {
        format!("{}.{leaf}", self.chart)
    }
}

/// A listener's TLS configuration: the identity it presents, and how it
/// verifies its callers.
///
/// **File paths, never an issuer-specific resource** (D80). cert-manager writes
/// these files in the reference deployment and a hand-assembled Secret anywhere
/// else; nothing here can tell the difference, which is the point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerTls {
    cert_file: PathBuf,
    key_file: PathBuf,
    client_auth: ClientAuth,
    /// `Some` exactly when `client_auth` verifies. A CA configured beside `off`
    /// is dropped with a warning, so it is neither read nor watched.
    client_ca_file: Option<PathBuf>,
}

impl ServerTls {
    /// [`Self::from_lookup`] over the process environment.
    pub fn from_env(
        prefix: &'static str,
        chart_key: &'static str,
    ) -> Result<Option<Self>, ServeTlsError> {
        Self::from_lookup(prefix, chart_key, |key| std::env::var(key).ok())
    }

    /// Read the listener's configuration through `lookup`.
    ///
    /// `Ok(None)` is the cleartext listener, and it is only ever the answer to
    /// an EXPLICIT `{prefix}_TLS_ENABLED=0` with client auth `off`. Every
    /// refusal happens here or in [`Self::builder`], before anything binds.
    ///
    /// The lookup is injected because `std::env` is process-global: a test that
    /// set one variable would steer every other test in the binary.
    pub fn from_lookup(
        prefix: &'static str,
        chart_key: &'static str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, ServeTlsError> {
        let keys = Keys {
            prefix,
            chart: chart_key,
        };
        let get = |suffix: &str| {
            lookup(&keys.var(suffix))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        let enabled = read_enabled(&keys, get("ENABLED"))?;
        let mode = read_client_auth(&keys, get("CLIENT_AUTH"))?;
        let ca = get("CLIENT_CA_FILE");

        if mode == ClientAuth::Off && ca.is_some() {
            tracing::warn!(
                "{} names a client CA but {} is `off`, so this listener verifies NO client \
                 certificate",
                keys.var("CLIENT_CA_FILE"),
                keys.var("CLIENT_AUTH"),
            );
        }
        if !enabled {
            return cleartext(&keys, mode, get("CERT_FILE").or(get("KEY_FILE")));
        }

        let serving = |suffix: &str| {
            get(suffix)
                .map(PathBuf::from)
                .ok_or_else(|| ServeTlsError::NoServingFile {
                    enabled_var: keys.var("ENABLED"),
                    var: keys.var(suffix),
                })
        };
        Ok(Some(Self {
            cert_file: serving("CERT_FILE")?,
            key_file: serving("KEY_FILE")?,
            client_auth: mode,
            client_ca_file: client_ca(&keys, mode, ca)?,
        }))
    }

    /// The PEM certificate this listener presents.
    pub fn cert_file(&self) -> &Path {
        &self.cert_file
    }

    /// The PEM private key belonging to that certificate.
    pub fn key_file(&self) -> &Path {
        &self.key_file
    }

    /// How this listener verifies its callers.
    pub fn client_auth(&self) -> ClientAuth {
        self.client_auth
    }

    /// The client CA bundle, present exactly when [`Self::client_auth`]
    /// verifies.
    pub fn client_ca_file(&self) -> Option<&Path> {
        self.client_ca_file.as_deref()
    }

    /// Read every file and build the gRPC server with this transport.
    ///
    /// **EAGER.** `tls_config` builds the rustls acceptor here — decoding the
    /// PEM, checking the certificate belongs to the key, and building the
    /// client verifier — so a bad mount refuses at boot rather than failing a
    /// stranger's first handshake. The files are read HERE rather than by tonic
    /// so the refusal names WHICH file was wrong.
    pub fn builder(&self) -> Result<Server, ServeTlsError> {
        let identity = Identity::from_pem(
            read(&self.cert_file, "serving certificate")?,
            read(&self.key_file, "serving private key")?,
        );
        let mut config = ServerTlsConfig::new().identity(identity);
        if let Some(path) = &self.client_ca_file {
            config = config
                .client_ca_root(client_ca_root(path)?)
                .client_auth_optional(self.client_auth == ClientAuth::Optional);
        }
        Server::builder()
            .tls_config(config)
            .map_err(|source| ServeTlsError::Unusable {
                cert: self.cert_file.clone(),
                key: self.key_file.clone(),
                source,
            })
    }
}

/// Build the gRPC server a service listens with — THE ONLY server construction
/// a service needs, so a cleartext fallback has exactly one place it could be
/// written. `None` is the cleartext listener `from_lookup` returned for an
/// explicit `ENABLED=0`; `Some` is TLS, or an error, never cleartext.
pub fn server(tls: Option<&ServerTls>) -> Result<Server, ServeTlsError> {
    match tls {
        None => Ok(Server::builder()),
        Some(tls) => tls.builder(),
    }
}

/// `{prefix}_TLS_ENABLED`: exactly `1` or `0`, and absence refuses (ADR-0845).
fn read_enabled(keys: &Keys, value: Option<String>) -> Result<bool, ServeTlsError> {
    match value.as_deref() {
        Some("1") => Ok(true),
        Some("0") => Ok(false),
        None => Err(ServeTlsError::EnabledMissing {
            var: keys.var("ENABLED"),
            chart: keys.chart("enabled"),
        }),
        Some(other) => Err(ServeTlsError::EnabledInvalid {
            var: keys.var("ENABLED"),
            chart: keys.chart("enabled"),
            value: other.to_string(),
        }),
    }
}

/// `{prefix}_TLS_CLIENT_AUTH`: exactly one of three, and absence refuses
/// (ADR-0854) — whether or not TLS is on.
fn read_client_auth(keys: &Keys, value: Option<String>) -> Result<ClientAuth, ServeTlsError> {
    let var = keys.var("CLIENT_AUTH");
    let chart = keys.chart("clientAuth");
    let Some(value) = value else {
        return Err(ServeTlsError::ClientAuthMissing { var, chart });
    };
    value
        .parse()
        .map_err(|()| ServeTlsError::ClientAuthInvalid { var, chart, value })
}

/// The `ENABLED=0` branch: cleartext, unless the mode claims verification.
fn cleartext(
    keys: &Keys,
    mode: ClientAuth,
    serving_file: Option<String>,
) -> Result<Option<ServerTls>, ServeTlsError> {
    if mode != ClientAuth::Off {
        return Err(ServeTlsError::ClientAuthWithoutTls {
            mode,
            auth_var: keys.var("CLIENT_AUTH"),
            enabled_var: keys.var("ENABLED"),
            auth_chart: keys.chart("clientAuth"),
            enabled_chart: keys.chart("enabled"),
        });
    }
    if serving_file.is_some() {
        // NOT an error: leaving the certificate mounted while the switch is `0`
        // is how a cut-over is reverted. It is still worth a line, so a
        // deployment that believes it is encrypted can see that it is not.
        tracing::warn!(
            "a serving certificate is configured but {} is \"0\", so this listener serves \
             CLEARTEXT",
            keys.var("ENABLED"),
        );
    }
    Ok(None)
}

/// The client CA path: required by a verifying mode, dropped by `off`.
fn client_ca(
    keys: &Keys,
    mode: ClientAuth,
    ca: Option<String>,
) -> Result<Option<PathBuf>, ServeTlsError> {
    if mode == ClientAuth::Off {
        return Ok(None);
    }
    ca.map(|p| Some(PathBuf::from(p)))
        .ok_or_else(|| ServeTlsError::NoClientCaFile {
            mode,
            auth_var: keys.var("CLIENT_AUTH"),
            var: keys.var("CLIENT_CA_FILE"),
            chart: keys.chart("clientCaSecret"),
        })
}

fn read(path: &Path, what: &'static str) -> Result<Vec<u8>, ServeTlsError> {
    std::fs::read(path).map_err(|source| ServeTlsError::Unreadable {
        what,
        path: path.to_path_buf(),
        source,
    })
}

/// Read the client CA bundle and require at least one certificate in it.
///
/// tonic hands the bytes to `add_parsable_certificates`, which drops every
/// entry it cannot parse SILENTLY, and an empty store then fails as "no root
/// anchors" — naming no file. Parsing here first is what makes the refusal name
/// the path. Every certificate in the file is an anchor, so a bundle of an old
/// and a new authority accepts leaves under either during a CA rotation.
fn client_ca_root(path: &Path) -> Result<Certificate, ServeTlsError> {
    let pem = read(path, "client CA file")?;
    let mut count = 0usize;
    for cert in CertificateDer::pem_slice_iter(&pem) {
        cert.map_err(|e| ServeTlsError::ClientCaUnparsable {
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;
        count += 1;
    }
    if count == 0 {
        return Err(ServeTlsError::ClientCaEmpty {
            path: path.to_path_buf(),
        });
    }
    Ok(Certificate::from_pem(pem))
}

/// The watch set: the files [`ServerTls::builder`] reads, and no others
/// (ADR-0523). The CA is watched exactly when it is read.
#[cfg(feature = "rotate")]
impl crate::rotate::Material for ServerTls {
    fn files(&self) -> Vec<crate::rotate::File<'_>> {
        use crate::rotate::{File, Presented};
        let mut files = vec![
            File::certificate(Presented::Serving, &self.cert_file),
            File::read(&self.key_file),
        ];
        if let Some(ca) = &self.client_ca_file {
            files.push(File::read(ca));
        }
        files
    }
}
