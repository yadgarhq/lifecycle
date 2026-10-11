//! The watch set a service assembles at boot: [`Inputs`], the value that
//! replaces the builder calls scattered through a `main.rs` (see the crate
//! docs). Split out of `rotate.rs` (ledger 719) — this impl block alone was
//! the largest cohesive piece of that file.

use std::path::{Path, PathBuf};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

#[cfg(test)]
use super::File;
use super::{absent, digest_of, hex, unknown, Material, Presented};
use super::{CERTIFICATE_NOT_AFTER, WATCHED_FILES_UNREADABLE};

/// A certificate read at boot, kept as the DER the process actually loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Leaf {
    der: Option<Vec<u8>>,
    path: PathBuf,
}

/// One leaf of a [`Presented`] kind, and the name (if any) that tells it apart
/// from the others of that same kind.
///
/// `name` is `None` for the PRIMARY leaf — the one [`Inputs::fingerprint`],
/// [`Inputs::not_after`] and `Inputs::reported` answer for, unchanged from
/// before ledger 1417 gave a kind more than one slot.
#[derive(Clone, Debug, PartialEq, Eq)]
struct NamedLeaf {
    name: Option<&'static str>,
    leaf: Leaf,
}

/// One watched file and the digest it held when it was read.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Watched {
    path: PathBuf,
    loaded: Option<[u8; 32]>,
}

/// Everything this process read at boot, hashed as it was read.
///
/// `serving` and `client` each hold every leaf of that kind this process
/// presents (ledger 1417) — ordinarily one, but a service like `iam` that also
/// watches a broker leaf keeps that leaf beside the unnamed one rather than
/// overwriting it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    service: &'static str,
    serving: Vec<NamedLeaf>,
    client: Vec<NamedLeaf>,
    files: Vec<Watched>,
}

impl Inputs {
    /// An empty watch set, labelled with the service that owns it.
    ///
    /// The service name is stored rather than passed to
    /// [`Inputs::export_not_after`] because it is a property of the process, not
    /// of the moment the gauge is written — and a parameter would be one more
    /// thing a call site could get wrong.
    pub fn new(service: &'static str) -> Self {
        Self {
            service,
            serving: Vec::new(),
            client: Vec::new(),
            files: Vec::new(),
        }
    }

    /// **THE FOLD, and the reason this crate exists.**
    ///
    /// The watch set used to be built statement-by-statement inside `main.rs`,
    /// one builder call beside each piece of boot that read a file. No test
    /// spawns a binary, so deleting one of those calls compiled, passed the
    /// entire suite, and shipped a process that would never notice that file
    /// rotating. Three services, four calls each, not one of them killable.
    ///
    /// Here the set is a VALUE. A service's library returns the list, `main.rs`
    /// holds one expression, and a test calls the same function and asserts what
    /// came back. The fold over the list is tested in this crate; what each
    /// [`Material`] contributes is tested in the service that implements it.
    ///
    /// Order is preserved, and a path named twice is watched once — so an
    /// upstream and a listener sharing a CA bundle is hashed once and reported
    /// once.
    pub fn of(service: &'static str, materials: &[&dyn Material]) -> Self {
        materials
            .iter()
            .fold(Self::new(service), |inputs, material| {
                inputs.take(*material)
            })
    }

    /// Hash and record one piece of configuration NOW, beside the code that read
    /// it.
    ///
    /// **The baseline must be taken close to the read.** A watch set that
    /// remembered paths and hashed them when the watcher first polled would put
    /// the rest of boot inside a window where a kubelet swap becomes the
    /// baseline: the real rotation is then never noticed, and the gauge
    /// describes a certificate the listener is not serving.
    ///
    /// [`Inputs::of`] folds within boot rather than after it, which is the same
    /// sub-second window and not the sixty-second one. Use `take` where a
    /// service genuinely wants each hash beside its own read.
    pub fn take(self, material: &dyn Material) -> Self {
        material
            .files()
            .into_iter()
            .fold(self, |inputs, file| match file.presented {
                None => inputs.also(file.path),
                Some(which) => inputs.certificate(which, file.name, file.path),
            })
    }

    /// Watch one more file, hashing it now. A path already watched is not added
    /// twice.
    pub fn also(self, path: &Path) -> Self {
        if self.is_watching(path) {
            return self;
        }
        let loaded = std::fs::read(path).ok().as_deref().map(digest_of);
        self.watch(path, loaded)
    }

    /// Record a certificate this process presents, and watch its file.
    ///
    /// The LEAF is kept — the first certificate in the file — because that is
    /// what the listener serves. A file holding leaf-then-issuer is what
    /// cert-manager writes, and reporting the issuer's expiry keeps a gauge
    /// green for a decade while the certificate in use ages out.
    ///
    /// `name` tells this leaf apart from any others of the same `which` kind
    /// (ledger 1417). A second call naming the SAME `(which, name)` pair
    /// replaces that leaf, exactly as a single call used to; a second call with
    /// a DIFFERENT name keeps both.
    fn certificate(mut self, which: Presented, name: Option<&'static str>, path: &Path) -> Self {
        let bytes = std::fs::read(path).ok();
        let leaf = Leaf {
            der: bytes
                .as_deref()
                .and_then(|b| CertificateDer::pem_slice_iter(b).next()?.ok())
                .map(|der| der.to_vec()),
            path: path.to_path_buf(),
        };
        let leaves = self.leaves_mut(which);
        match leaves.iter_mut().find(|nl| nl.name == name) {
            Some(existing) => existing.leaf = leaf,
            None => leaves.push(NamedLeaf { name, leaf }),
        }
        self.watch(path, bytes.as_deref().map(digest_of))
    }

    /// Every leaf of `which`'s kind, in the order it was added.
    fn leaves(&self, which: Presented) -> &[NamedLeaf] {
        match which {
            Presented::Serving => &self.serving,
            Presented::Client => &self.client,
        }
    }

    /// The mutable counterpart to `Inputs::leaves`, for `Inputs::certificate` alone.
    fn leaves_mut(&mut self, which: Presented) -> &mut Vec<NamedLeaf> {
        match which {
            Presented::Serving => &mut self.serving,
            Presented::Client => &mut self.client,
        }
    }

    fn watch(mut self, path: &Path, loaded: Option<[u8; 32]>) -> Self {
        if self.is_watching(path) {
            return self;
        }
        self.files.push(Watched {
            path: path.to_path_buf(),
            loaded,
        });
        self
    }

    fn is_watching(&self, path: &Path) -> bool {
        self.files.iter().any(|f| f.path == path)
    }

    /// Nothing was read, so nothing can rotate. [`super::watch`] never ends on an empty
    /// set — the alternative is exiting a process that holds no material at all.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Every file in the watch set, in the order it was added. This is what a
    /// test asserts membership against.
    pub fn watched(&self) -> Vec<&Path> {
        self.files.iter().map(|f| f.path.as_path()).collect()
    }

    /// The watched files this process could NOT read at boot.
    ///
    /// Each is a path a DEPLOYMENT named and the process then failed to read.
    /// They stay in the watch set: dropping them would make the set quietly
    /// smaller than the configuration that produced it, which is the class of
    /// defect [`Inputs::of`] exists to close.
    pub fn unread_at_boot(&self) -> Vec<&Path> {
        self.files
            .iter()
            .filter(|f| f.loaded.is_none())
            .map(|f| f.path.as_path())
            .collect()
    }

    /// The digest each watched file holds NOW, `None` where it cannot be read.
    ///
    /// **ONE ENTRY PER FILE, NEVER ONE ANSWER FOR THE SET.** This used to
    /// `collect()` into an `Option<Vec<_>>`, so a single unreadable file
    /// answered `None` for all of them and every poll fell into the transient
    /// arm — six files rotating perfectly well went unnoticed for as long as one
    /// stayed gone.
    pub(crate) fn on_disk(&self) -> Vec<Option<[u8; 32]>> {
        self.files
            .iter()
            .map(|f| std::fs::read(&f.path).ok().as_deref().map(digest_of))
            .collect()
    }

    /// The watched files whose contents are not what this process loaded.
    ///
    /// **A FILE THAT CANNOT BE READ RIGHT NOW IS NOT ONE OF THEM.** That is the
    /// transient state kubelet passes through while it rewrites a mount, and
    /// acting on it would exit the process over a directory that is about to be
    /// fine — a watcher whose failure is worse than not having one.
    ///
    /// The reverse direction IS a change, and always was this function's answer:
    /// a file with no baseline that now reads is material the process never
    /// loaded, so `None != Some(digest)` reports it. Only `baseline()`'s collapse
    /// made that answer unreachable.
    pub(crate) fn differing(&self, current: &[Option<[u8; 32]>]) -> Vec<String> {
        self.files
            .iter()
            .zip(current)
            .filter(|(f, now)| now.is_some() && f.loaded != **now)
            .map(|(f, _)| f.path.display().to_string())
            .collect()
    }

    /// The watched files that cannot be read at this instant.
    pub(crate) fn unreadable(&self, current: &[Option<[u8; 32]>]) -> Vec<String> {
        self.files
            .iter()
            .zip(current)
            .filter(|(_, now)| now.is_none())
            .map(|(f, _)| f.path.display().to_string())
            .collect()
    }

    pub(crate) fn publish_unreadable(&self, count: usize) {
        metrics::gauge!(WATCHED_FILES_UNREADABLE, "service" => self.service).set(count as f64);
    }

    /// Publish [`WATCHED_FILES_UNREADABLE`] for the watched files that cannot be
    /// read right now, and name them.
    ///
    /// **A ZERO HERE IS A MEASUREMENT, WHICH IS WHY THIS PUBLISHES
    /// UNCONDITIONALLY** — and it is the opposite call from
    /// [`Inputs::export_not_after`], deliberately. An expiry for a certificate
    /// this process never loaded would be an invented number a dashboard cannot
    /// tell from a real one. "None of the watched files is unreadable" is not
    /// invented; it is the answer, and a series that appears only once something
    /// is wrong cannot be told apart from an exporter that is not running.
    pub fn export_unreadable(&self) -> Vec<String> {
        let names = self.unreadable(&self.on_disk());
        self.publish_unreadable(names.len());
        names
    }

    /// The PRIMARY leaf of `which`'s kind — the unnamed one every caller
    /// before ledger 1417 already had, and the only one [`Inputs::fingerprint`],
    /// [`Inputs::not_after`] and `Inputs::reported` answer for. A further,
    /// named leaf of the same kind (`iam`'s broker leaf) is invisible here;
    /// [`Inputs::export_not_after`] is what reports it.
    fn loaded(&self, which: Presented) -> Option<&Leaf> {
        self.leaves(which)
            .iter()
            .find(|nl| nl.name.is_none())
            .map(|nl| &nl.leaf)
    }

    fn leaf(&self, which: Presented) -> Option<CertificateDer<'static>> {
        Some(CertificateDer::from(self.loaded(which)?.der.clone()?))
    }

    fn fingerprint_on_disk(&self, which: Presented) -> Option<String> {
        let bytes = std::fs::read(&self.loaded(which)?.path).ok()?;
        let der = CertificateDer::pem_slice_iter(&bytes).next()?.ok()?;
        Some(hex(&Sha256::digest(&der)))
    }

    /// What to print for a certificate: `none` if none was configured, `unknown`
    /// if one was and could not be read. **The two are different facts** and a
    /// single placeholder would hide the second inside the first.
    pub(crate) fn reported(&self, which: Presented, on_disk: bool) -> String {
        if self.loaded(which).is_none() {
            return absent();
        }
        let found = if on_disk {
            self.fingerprint_on_disk(which)
        } else {
            self.fingerprint(which)
        };
        found.unwrap_or_else(unknown)
    }

    /// SHA-256 over the loaded leaf's DER, hex. This NAMES the certificate the
    /// process is on.
    pub fn fingerprint(&self, which: Presented) -> Option<String> {
        Some(hex(&Sha256::digest(self.leaf(which)?)))
    }

    /// The loaded leaf's expiry, as seconds since the epoch.
    pub fn not_after(&self, which: Presented) -> Option<i64> {
        let der = self.leaf(which)?;
        let (_, parsed) = X509Certificate::from_der(&der).ok()?;
        Some(parsed.validity().not_after.timestamp())
    }

    /// Publish [`CERTIFICATE_NOT_AFTER`] for every certificate this process
    /// loaded, and nothing for one it did not.
    ///
    /// **An invented number is worse than a missing series**: a dashboard cannot
    /// tell it apart from a real one.
    ///
    /// **ONE GAUGE PER LEAF, NEVER ONE PER KIND** (ledger 1417). A kind with a
    /// further, named leaf beside its primary one — `iam`'s broker leaf beside
    /// its unnamed client leaf — gets a series each: the primary carries
    /// `service` and `kind`, exactly as before this leaf could have a
    /// neighbour; a named leaf carries `name` too, bounded at the names a
    /// caller actually writes in source (D67), never at a path.
    pub fn export_not_after(&self) {
        for which in [Presented::Serving, Presented::Client] {
            for named in self.leaves(which) {
                let Some(bytes) = named.leaf.der.clone() else {
                    continue;
                };
                let der = CertificateDer::from(bytes);
                let Ok((_, parsed)) = X509Certificate::from_der(&der) else {
                    continue;
                };
                let seconds = parsed.validity().not_after.timestamp();
                let fingerprint = hex(&Sha256::digest(&der));
                match named.name {
                    None => {
                        metrics::gauge!(
                            CERTIFICATE_NOT_AFTER,
                            "service" => self.service,
                            "kind" => which.label(),
                        )
                        .set(seconds as f64);
                        tracing::info!(
                            kind = which.label(),
                            not_after = seconds,
                            fingerprint,
                            "certificate loaded; its expiry is exported as {CERTIFICATE_NOT_AFTER}"
                        );
                    }
                    Some(name) => {
                        metrics::gauge!(
                            CERTIFICATE_NOT_AFTER,
                            "service" => self.service,
                            "kind" => which.label(),
                            "name" => name,
                        )
                        .set(seconds as f64);
                        tracing::info!(
                            kind = which.label(),
                            name,
                            not_after = seconds,
                            fingerprint,
                            "certificate loaded; its expiry is exported as {CERTIFICATE_NOT_AFTER}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
