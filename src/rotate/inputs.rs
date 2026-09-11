//! The watch set a service assembles at boot: [`Inputs`], the value that
//! replaces the builder calls scattered through a `main.rs` (see the crate
//! docs). Split out of `rotate.rs` (ledger 719) — this impl block alone was
//! the largest cohesive piece of that file.

use std::path::{Path, PathBuf};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::{absent, digest_of, hex, unknown, Material, Presented};
use super::{CERTIFICATE_NOT_AFTER, WATCHED_FILES_UNREADABLE};

/// A certificate read at boot, kept as the DER the process actually loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Leaf {
    der: Option<Vec<u8>>,
    path: PathBuf,
}

/// One watched file and the digest it held when it was read.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Watched {
    path: PathBuf,
    loaded: Option<[u8; 32]>,
}

/// Everything this process read at boot, hashed as it was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    service: &'static str,
    serving: Option<Leaf>,
    client: Option<Leaf>,
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
            serving: None,
            client: None,
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
                Some(which) => inputs.certificate(which, file.path),
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
    fn certificate(mut self, which: Presented, path: &Path) -> Self {
        let bytes = std::fs::read(path).ok();
        let leaf = Leaf {
            der: bytes
                .as_deref()
                .and_then(|b| CertificateDer::pem_slice_iter(b).next()?.ok())
                .map(|der| der.to_vec()),
            path: path.to_path_buf(),
        };
        match which {
            Presented::Serving => self.serving = Some(leaf),
            Presented::Client => self.client = Some(leaf),
        }
        self.watch(path, bytes.as_deref().map(digest_of))
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

    fn loaded(&self, which: Presented) -> Option<&Leaf> {
        match which {
            Presented::Serving => self.serving.as_ref(),
            Presented::Client => self.client.as_ref(),
        }
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
    pub fn export_not_after(&self) {
        for which in [Presented::Serving, Presented::Client] {
            let Some(seconds) = self.not_after(which) else {
                continue;
            };
            metrics::gauge!(
                CERTIFICATE_NOT_AFTER,
                "service" => self.service,
                "kind" => which.label(),
            )
            .set(seconds as f64);
            tracing::info!(
                kind = which.label(),
                not_after = seconds,
                fingerprint = self.fingerprint(which).unwrap_or_else(unknown),
                "certificate loaded; its expiry is exported as {CERTIFICATE_NOT_AFTER}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_configured_is_empty() {
        assert!(Inputs::new("test").is_empty());
        assert!(!Inputs::new("test")
            .also(Path::new("/etc/yadgar/tls.pem"))
            .is_empty());
    }

    /// An unreadable file has no baseline OF ITS OWN, and that is now the whole
    /// of what it means. It used to mean the SET had none.
    #[test]
    fn an_unreadable_input_has_no_baseline() {
        let path = Path::new("/etc/yadgar/quokka-4d81/absent.pem");
        let inputs = Inputs::new("test").also(path);
        assert_eq!(inputs.unread_at_boot(), vec![path]);
        assert_eq!(inputs.on_disk(), vec![None]);
        assert_eq!(inputs.fingerprint(Presented::Serving), None);
        assert_eq!(inputs.not_after(Presented::Serving), None);
        assert_eq!(inputs.fingerprint(Presented::Client), None);
        assert_eq!(inputs.not_after(Presented::Client), None);
    }

    /// **ONE UNREADABLE FILE LEAVES EVERY OTHER FILE'S BASELINE INTACT.** The
    /// collapse this replaced turned the first `None` into a `None` for the set,
    /// which is what disabled the watcher.
    #[test]
    fn an_unreadable_input_does_not_erase_the_baselines_beside_it() {
        let absent = Path::new("/etc/yadgar/quokka-4d81/absent.pem");
        let readable = Path::new("/proc/self/cmdline");
        let inputs = Inputs::new("test").also(absent).also(readable);

        assert_eq!(inputs.unread_at_boot(), vec![absent]);
        let on_disk = inputs.on_disk();
        assert_eq!(on_disk.len(), 2);
        assert_eq!(on_disk[0], None, "the unreadable one, and only it");
        assert!(on_disk[1].is_some(), "the readable one still answers");

        // AND THE UNREADABLE ONE IS NOT REPORTED AS A CHANGE. `None` on both
        // sides is "still unreadable", never "rotated".
        assert!(inputs.differing(&on_disk).is_empty());
        assert_eq!(
            inputs.unreadable(&on_disk),
            vec![absent.display().to_string()]
        );
    }

    /// The direction that IS a change: no baseline, and bytes on disk now.
    #[test]
    fn a_file_with_no_baseline_that_now_reads_is_a_change() {
        let absent = Path::new("/etc/yadgar/quokka-4d81/absent.pem");
        let inputs = Inputs::new("test").also(absent);
        let appeared = vec![Some(digest_of(b"material this process never loaded"))];

        assert_eq!(
            inputs.differing(&appeared),
            vec![absent.display().to_string()]
        );
        assert!(inputs.unreadable(&appeared).is_empty());
    }

    #[test]
    fn a_file_named_twice_is_watched_once() {
        let path = Path::new("/etc/yadgar/quokka-4d81/client.pem");
        let inputs = Inputs::new("test").also(path).also(path);
        assert_eq!(inputs.watched(), vec![path]);

        let both = Inputs::new("test")
            .certificate(Presented::Client, path)
            .also(path);
        assert_eq!(both.watched(), vec![path]);
    }

    #[test]
    fn an_absent_certificate_reads_differently_from_an_unreadable_one() {
        assert_eq!(
            Inputs::new("test").reported(Presented::Serving, false),
            "none"
        );

        let configured = Inputs::new("test").certificate(
            Presented::Serving,
            Path::new("/etc/yadgar/quokka-4d81/absent.pem"),
        );
        assert_eq!(configured.reported(Presented::Serving, false), "unknown");
        assert_eq!(configured.reported(Presented::Serving, true), "unknown");
    }

    /// A self-signed leaf, PEM. Minted per case rather than checked in, for the
    /// reason `Cargo.toml` gives about a fixture key in a repository.
    fn self_signed(name: &str) -> String {
        let key = rcgen::KeyPair::generate().expect("a key pair");
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()])
            .expect("a subject alternative name");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.self_signed(&key).expect("a self-signed leaf").pem()
    }

    /// A directory of this case's own, so a stale file cannot make a broken
    /// implementation pass.
    fn scratch() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "yadgar-lifecycle-reported-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).expect("a scratch directory");
        root
    }

    /// **`_before` IS THE LEAF THIS PROCESS LOADED AND `_after` IS THE ONE ON
    /// DISK**, and the rotation line is worth nothing unless they are.
    ///
    /// [`watch`] prints `serving_before = reported(.., false)` beside
    /// `serving_after = reported(.., true)`, so an operator can read which
    /// certificate the pod is leaving and which one it is restarting onto.
    /// NOTHING PINNED IT. `reported` was exercised only for `none` and for
    /// `unknown` — and in both of those cases the two arms answer the SAME
    /// string, so swapping the bools at the four call sites, or reading the
    /// loaded bytes on both sides, compiled, passed clippy and passed every
    /// other case in this crate while printing one fingerprint twice.
    ///
    /// ADR-0523 makes the fingerprints an obligation of the decision, not a
    /// decoration on the log line: "it logs the old and new fingerprints".
    #[test]
    fn the_boot_baseline_and_the_file_on_disk_are_reported_apart() {
        let root = scratch();
        let path = root.join("tls.pem");
        let loaded = self_signed("before.yadgar.internal");
        std::fs::write(&path, &loaded).expect("the leaf this process reads at boot");

        let inputs = Inputs::new("test").certificate(Presented::Serving, &path);
        let baseline = inputs.reported(Presented::Serving, false);
        assert_eq!(
            baseline.len(),
            64,
            "SHA-256 over the loaded leaf's DER, hex"
        );
        assert_eq!(
            inputs.reported(Presented::Serving, true),
            baseline,
            "nothing has rotated, so both sides name the same certificate"
        );

        // WHAT KUBELET DOES TO A DIRECTORY MOUNT: the same path, other bytes.
        let rotated_onto = self_signed("after.yadgar.internal");
        assert_ne!(loaded, rotated_onto, "two mints must differ");
        std::fs::write(&path, &rotated_onto).expect("the leaf cert-manager wrote");

        assert_eq!(
            inputs.reported(Presented::Serving, false),
            baseline,
            "`serving_before` must keep naming the leaf that was LOADED, never the file"
        );
        let after = inputs.reported(Presented::Serving, true);
        assert_eq!(after.len(), 64, "SHA-256 over the rotated leaf's DER, hex");
        assert_ne!(
            after, baseline,
            "`serving_after` must name the leaf on disk, or the line reports a rotation by \
             printing one fingerprint twice"
        );

        // AND THE TWO KINDS ARE NOT EACH OTHER. One process holds both, so a
        // `reported` that answered with the serving leaf under both labels would
        // land on a plausible fingerprint and pass every assertion above.
        let client = root.join("client.pem");
        std::fs::write(&client, self_signed("caller.yadgar.internal")).expect("a client leaf");
        let both = inputs.certificate(Presented::Client, &client);
        assert_ne!(
            both.reported(Presented::Client, false),
            both.reported(Presented::Serving, false),
            "the serving and client leaves are different certificates"
        );

        std::fs::remove_dir_all(&root).expect("the scratch directory");
    }
}
