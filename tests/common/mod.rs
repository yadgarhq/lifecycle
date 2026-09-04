//! The mount kubelet actually writes, and the configuration types a service
//! actually holds.
//!
//! **A test that overwrites a file in place passes against a broken
//! implementation**, so nothing here does that. Every case builds the mount the
//! way kubelet builds a mounted Secret — a timestamped data directory, a
//! `..data` symlink pointing at it, and one symlink per key pointing through
//! `..data` — and rotates it by creating a NEW timestamped directory and
//! `rename`ing a replacement `..data` over the old one. That rename is the
//! atomic swap, and it is the only event the watcher ever sees in production.
//!
//! CERTIFICATES ARE MINTED PER RUN: a fixture key in the repository is a secret
//! in the repository, and it expires on a date nobody is watching.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use yadgar_lifecycle::rotate::{File, Material, Presented};

/// The leaf's expiry, and the issuing authority's — DELIBERATELY DIFFERENT and
/// deliberately a decade apart. cert-manager writes the leaf first and the chain
/// after it, so an implementation that parses the LAST certificate in the file
/// reports an expiry ten years out, and the gauge that exists to make a stale
/// leaf loud goes quiet instead.
pub const LEAF_NOT_AFTER: i64 = 1_813_017_600; // 2027-06-15T00:00:00Z
pub const CA_NOT_AFTER: i64 = 2_128_636_800; // 2037-06-15T00:00:00Z

/// The CLIENT leaf's expiry — a year past the serving leaf's, and deliberately
/// so. Both are exported under one metric name, separated only by the `kind`
/// label, so an implementation that gauged the wrong one would land on a
/// plausible number. A distinct date turns that into a failing equality.
pub const CLIENT_NOT_AFTER: i64 = 1_844_640_000; // 2028-06-15T00:00:00Z

/// Every file one generation of the mount holds.
pub const NAMES: [&str; 7] = [
    "tls.pem",
    "tls-key.pem",
    "ca.pem",
    "enrolment-ca.pem",
    "client.pem",
    "client-key.pem",
    "broker-password",
];

/// One generation of the mount: the file names a chart writes, and their
/// contents.
pub type Generation = Vec<(String, String)>;

/// A whole mount's worth of freshly minted material.
///
/// `tls.pem` holds the leaf FOLLOWED BY the authority that issued it, which is
/// the shape cert-manager writes.
pub fn generation(san: &str) -> Generation {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_after = date_time_ymd(2037, 6, 15);
    ca_params.distinguished_name.push(
        DnType::CommonName,
        "yadgar-lifecycle rotation test authority",
    );
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_after = date_time_ymd(2027, 6, 15);
    params.distinguished_name.push(DnType::CommonName, san);
    let leaf = params.signed_by(&key, &ca).unwrap();

    // THE CLIENT LEAF, a DIFFERENT certificate issued for a DIFFERENT purpose
    // (ADR-0516). `ClientAuth` rather than `ServerAuth`, because a peer
    // verifying a client chain refuses a leaf naming the wrong one even though
    // it trusts the issuer perfectly well.
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(vec![format!("{san}-caller")]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.not_after = date_time_ymd(2028, 6, 15);
    client_params
        .distinguished_name
        .push(DnType::CommonName, format!("{san}-caller"));
    let client_leaf = client_params.signed_by(&client_key, &ca).unwrap();

    vec![
        ("tls.pem".to_string(), format!("{}{}", leaf.pem(), ca.pem())),
        ("tls-key.pem".to_string(), key.serialize_pem()),
        ("ca.pem".to_string(), ca.pem()),
        ("enrolment-ca.pem".to_string(), ca.pem()),
        (
            "client.pem".to_string(),
            format!("{}{}", client_leaf.pem(), ca.pem()),
        ),
        ("client-key.pem".to_string(), client_key.serialize_pem()),
        // NOT A CERTIFICATE, and in the set for exactly the reason ADR-0523
        // gives: the process read it at boot and the chart mounts it as a
        // DIRECTORY precisely so it can rotate. A rule that admitted only
        // transport material would let it go stale in silence.
        (
            "broker-password".to_string(),
            format!("sentinel-broker-password-{}\n", unique()),
        ),
    ]
}

/// The same generation with ONE file's contents replaced.
///
/// **Every other byte is identical**, which is what makes a case built on this
/// prove that the named file is watched. A whole-generation swap cannot: it
/// changes everything at once, so an implementation hashing only the first file
/// passes it.
pub fn with_replaced(base: &Generation, name: &str, contents: &str) -> Generation {
    base.iter()
        .map(|(n, c)| {
            let replaced = if n == name { contents } else { c.as_str() };
            (n.clone(), replaced.to_string())
        })
        .collect()
}

/// The same generation with the contents of two files EXCHANGED.
///
/// Every byte in the mount is still present, and no file is longer or shorter
/// than before — so an implementation that hashed the concatenation without
/// regard to which file each byte came from would see no change at all.
pub fn with_exchanged(base: &Generation, one: &str, other: &str) -> Generation {
    let get = |name: &str| {
        base.iter()
            .find(|(n, _)| n == name)
            .map(|(_, c)| c.clone())
            .expect("the mount holds that file")
    };
    let (a, b) = (get(one), get(other));
    base.iter()
        .map(|(n, c)| match n.as_str() {
            m if m == one => (n.clone(), b.clone()),
            m if m == other => (n.clone(), a.clone()),
            _ => (n.clone(), c.clone()),
        })
        .collect()
}

/// A directory shaped the way kubelet shapes a mounted Secret.
///
/// ```text
///   <root>/..1234-5678/tls.pem
///   <root>/..data      -> ..1234-5678
///   <root>/tls.pem     -> ..data/tls.pem
/// ```
///
/// The service is handed `<root>/tls.pem` and never learns any of the rest,
/// which is exactly what a chart does: a DIRECTORY mount, never `subPath`,
/// because a `subPath` mount is a one-time copy kubelet never refreshes.
pub struct Mount {
    root: PathBuf,
}

impl Mount {
    /// Write the first generation and the symlinks that point at it.
    pub fn new(files: &Generation) -> Self {
        let root = std::env::temp_dir().join(format!("yadgar-lifecycle-rotation-{}", unique()));
        std::fs::create_dir(&root).unwrap();
        let mount = Self { root };
        mount.swap(files);
        for (name, _) in files {
            std::os::unix::fs::symlink(Path::new("..data").join(name), mount.path(name)).unwrap();
        }
        mount
    }

    /// The path the SERVICE is given — a symlink through `..data`.
    pub fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// What kubelet does when the Secret changes: write a whole new generation,
    /// then move a replacement `..data` symlink over the old one.
    ///
    /// **The `rename` is the point.** It is atomic, so a reader never sees half
    /// a generation, and it leaves every path the service holds resolving to a
    /// DIFFERENT inode with a fresh modification time — which is why an mtime
    /// check cannot tell a real rotation from a no-op one.
    pub fn swap(&self, files: &Generation) {
        let generation = self.root.join(format!("..{}", unique()));
        std::fs::create_dir(&generation).unwrap();
        for (name, contents) in files {
            std::fs::write(generation.join(name), contents).unwrap();
        }
        self.point_data_at(generation.file_name().unwrap());
    }

    /// Point `..data` at a generation that does not exist, so every path the
    /// service holds becomes unreadable without any of them being deleted.
    ///
    /// A transient state, and one the watcher must survive rather than act on.
    pub fn break_it(&self) {
        self.point_data_at("..no-such-generation".as_ref());
    }

    fn point_data_at(&self, generation: &std::ffi::OsStr) {
        let staged = self.root.join("..data_tmp");
        let _ = std::fs::remove_file(&staged);
        std::os::unix::fs::symlink(generation, &staged).unwrap();
        std::fs::rename(&staged, self.root.join("..data")).unwrap();
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A name no other case in this run can collide with.
///
/// **A PROCESS-WIDE COUNTER, not the clock alone.** Cases run in parallel
/// threads and two of them can read the SAME nanosecond — measured elsewhere in
/// this estate as an intermittent `EEXIST` in roughly one run in five. The
/// counter makes the name unique by construction.
pub fn unique() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

// ---------------------------------------------------------------------------
// The shapes a service's own configuration has, as `Material` implementors.
//
// These stand in for `iam::serve::ServerTls`, `task::upstream::UpstreamTls`,
// `iam::invalidate::Credentials` and `iam::service::EnrolmentConfig`. They are
// here rather than in one test file because both the rotation suite and the
// assembly suite build watch sets out of them.
// ---------------------------------------------------------------------------

/// A listener's transport: the certificate it serves and the key beside it.
///
/// Stands in for the type each service spells differently — `ServerTls` in `iam`
/// and `iam-db`, `ServeTls` in `task`. **The crate never names it**, which is
/// how one of the four per-service differences stopped being a difference.
pub struct Listener {
    pub certificate: PathBuf,
    pub key: PathBuf,
}

impl Material for Listener {
    fn files(&self) -> Vec<File<'_>> {
        vec![
            File::certificate(Presented::Serving, &self.certificate),
            File::read(&self.key),
        ]
    }
}

/// How an upstream is verified, and what this process presents to it.
pub struct Upstream {
    pub ca: PathBuf,
    pub client: Option<(PathBuf, PathBuf)>,
}

impl Material for Upstream {
    fn files(&self) -> Vec<File<'_>> {
        let mut files = vec![File::read(&self.ca)];
        if let Some((certificate, key)) = &self.client {
            files.push(File::certificate(Presented::Client, certificate));
            files.push(File::read(key));
        }
        files
    }
}

/// A credential that is not a certificate at all, watched on provenance alone.
pub struct BrokerCredentials {
    pub password_file: PathBuf,
}

impl Material for BrokerCredentials {
    fn files(&self) -> Vec<File<'_>> {
        vec![File::read(&self.password_file)]
    }
}

impl Mount {
    /// The listener's transport as a deployment configured it.
    pub fn listener(&self) -> Listener {
        Listener {
            certificate: self.path("tls.pem"),
            key: self.path("tls-key.pem"),
        }
    }

    /// The upstream, with the client pair ADR-0516 makes load-bearing.
    pub fn upstream(&self) -> Upstream {
        Upstream {
            ca: self.path("ca.pem"),
            client: Some((self.path("client.pem"), self.path("client-key.pem"))),
        }
    }

    pub fn broker(&self) -> BrokerCredentials {
        BrokerCredentials {
            password_file: self.path("broker-password"),
        }
    }

    /// A token-issuing CA: a bare path, watched because the process read it.
    pub fn enrolment_ca(&self) -> PathBuf {
        self.path("enrolment-ca.pem")
    }
}
