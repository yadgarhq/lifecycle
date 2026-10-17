//! WHICH CALLER a verified client leaf names. Its own file because it is the
//! other half of the listener: `serve_tls.rs` configures what a listener
//! accepts, and this reads what it accepted.

use rustls_pki_types::CertificateDer;
use x509_parser::prelude::{FromDer as _, X509Certificate};

/// WHO THE CALLER IS: the common name on the leaf of the client chain a
/// verifying listener accepted, or `None`.
///
/// **mTLS SAYS "ONE OF OURS", NOT "WHICH ONE".** Every module's client leaf
/// verifies against the same internal authority, so a verb that admits ONE
/// caller — `project-db`'s `SyncProjects` admits `project-caller`, `project`'s
/// admits `seeder-caller` (ADR-0936) — has to read the identity off the leaf.
/// Both hops read it here, so the two cannot parse it two ways.
///
/// **THE COMMON NAME**, because that is the field `platform` declares the
/// identity in: every client leaf it issues names `commonName: <module>-caller`.
/// The chart's Certificate template also renders `dnsNames: [commonName]`, so
/// the leaf carries a dNSName SAN equal to the CN. The CN is still the field
/// read: it is the one every leaf states once, by construction of the values,
/// while the SAN list may grow (a serving leaf adds cluster-local names).
///
/// `None` when the request crossed no TLS handshake (a cleartext listener, or a
/// handler called directly), when the listener verified no client certificate
/// (`off`, or `optional` with none presented), and for any leaf
/// [`leaf_common_name`] refuses. A caller check treats `None` as a refusal.
pub fn caller_common_name<T>(request: &tonic::Request<T>) -> Option<String> {
    let chain = request.peer_certs()?;
    leaf_common_name(chain.first()?)
}

/// The single common name in a certificate's subject, or `None`.
///
/// **EXACTLY ONE, OR NO IDENTITY.** A subject with no CN has no name to match.
/// A subject with two is AMBIGUOUS: taking the first or the last would let a
/// leaf carrying `project-caller` beside its real name pass a check by
/// attribute order. Neither is something `platform` issues, so refusing costs
/// no real caller anything. A CN that is not a UTF-8 string, and bytes that do
/// not parse as a certificate, are refused the same way.
pub fn leaf_common_name(leaf: &CertificateDer<'_>) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(leaf.as_ref()).ok()?;
    let mut names = cert.subject().iter_common_name();
    let only = names.next()?;
    if names.next().is_some() {
        return None;
    }
    only.as_str().ok().map(str::to_string)
}
