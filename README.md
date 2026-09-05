# yadgar-lifecycle

How a server process starts, stops and restarts.

Three units live here, and they are **one** unit rather than three that happen to share a crate:

| unit                            | what it does                                                                  |
| ------------------------------- | ----------------------------------------------------------------------------- |
| `rotate::watch`                 | resolves when the security material this process read at boot changes on disk |
| `shutdown`                      | the future SIGTERM and SIGINT resolve                                         |
| `DRAIN_BUDGET` + `drain_within` | bounds the drain that follows, whichever of the two ended the serve           |

`rotate::watch` and `shutdown` are the two arms of one `select!`, and whichever wins, `drain_within` bounds what comes next. Lifting any one of them alone would put a single control flow across a crate boundary.

## Why it exists

Not de-duplication. Measured on 2026-09-04, before this crate:

| unit                            | copies                                           |
| ------------------------------- | ------------------------------------------------ |
| the rotation watcher            | 3 — `iam`, `task`, `gateway`                     |
| `shutdown`                      | 5 — the three above, plus `iam-db` and `task-db` |
| `DRAIN_BUDGET` + `drain_within` | 3 — `iam`, `task`, `gateway`                     |

ADR-0523 asked for it in its own consequences: _"the watcher core is repo-agnostic and is about to exist in four copies; lift it into a shared crate before the third."_ But de-duplication is the smaller half.

**The bigger half is that the watch set was assembled in `main.rs`, where no test can reach it.** Every service built its `Inputs` as a run of builder calls interleaved with boot:

```rust
let mut tls_inputs = rotate::Inputs::default().listener(listen_tls.as_ref());
// ... forty lines of boot ...
tls_inputs = tls_inputs.upstream(db_tls.as_ref());
// ... fifty more ...
tls_inputs = tls_inputs.broker(nats_credentials.as_ref());
// ... sixty more ...
tls_inputs = tls_inputs.enrolment(Some(&config));
```

No test spawns the binary. Deleting any one of those lines compiled, passed the entire suite, and shipped a process that would never notice that file rotating. Eight such calls stand across three `main.rs` files today: four in `iam`, two in `task`, two in `gateway`. Each service's own test file rebuilds the same assembly by hand, so `main.rs` and the test can disagree and both stay green.

`Inputs::of` is the answer: **the watch set is a value, not a sequence of statements.**

```rust
let inputs = rotate::Inputs::of("iam", &[
    &listen_tls,       // Option<ServerTls>
    &db_tls,           // Option<UpstreamTls>
    &nats_credentials, // Option<Credentials>
    &enrolment,        // Option<EnrolmentConfig>
]);
```

A value can be returned from a function in a service's library, and a function in a library is something a test can call. `tests/assembly.rs` is what a mutation of the fold, or of any `Material`, dies against.

## The API

One trait. A service implements `Material` on the configuration types it already holds:

```rust
impl Material for ServerTls {
    fn files(&self) -> Vec<File<'_>> {
        vec![
            File::certificate(Presented::Serving, self.cert_file()),
            File::read(self.key_file()),
        ]
    }
}
```

`File::certificate` marks a leaf whose fingerprint names it in a log line and whose expiry is exported as `yadgar_tls_certificate_not_after_seconds`. `File::read` is everything else the process read. **Both are watched identically** — ADR-0523's rule is about provenance, never payload, which is why `iam` watches a broker password and a token-issuing CA on the same ground as its certificate.

`Option<M>`, `&M`, `Path` and `PathBuf` implement `Material` too, so an opt-in setting that is off contributes nothing without a branch at the call site.

### A file the watcher cannot read

**Every watched file is watched on its own, and one the process cannot read disables nothing but itself.** It did not used to be. The baseline collected `Option<[u8; 32]>` into an `Option<Vec<_>>`, so a single unreadable file collapsed the whole set to `None` and the watcher waited forever behind one `warn!`. Rotation then went unnoticed for every other file — seven of them in a service like `iam` — and the pod served its day-0 leaf until the certificate expired. The same collapse sat on the polling side, where one file going away made every poll skip the six still rotating perfectly well.

Three states, and the DIRECTION is what separates them:

| at boot            | now             | what happens                                                     |
| ------------------ | --------------- | ---------------------------------------------------------------- |
| read               | different bytes | a rotation: splay, then end the watch                            |
| **could not read** | **readable**    | a rotation. The process is running on material it never loaded   |
| read               | cannot be read  | **not** a change. Transient; keep what was loaded, keep watching |

The second row is not new policy. The per-file comparison already answered "changed" for a file with no baseline that now reads; the collapse is what made that answer unreachable. It also settles _"is an unreadable file permanent?"_ by measurement rather than by guess: a late mount resolves itself, because the process exits once and the replacement takes a real baseline, while a genuinely wrong path never becomes readable and so never fires it.

**A path the deployment named and the process could not read is a configuration defect, so it is logged at `error!` at boot** — a different fact from the loop's transient `warn!`, separated by level so a reader can tell them apart. The loop's warning fires when the unreadable SET changes rather than on every poll, because a standing condition belongs in a gauge and a transition belongs in a log.

`yadgar_rotation_watched_files_unreadable` carries how many watched files cannot be read, labelled by `service` and by nothing per-path — a path label would make this metric's cardinality a property of a deployment's configuration. It is written on every poll **including when it is zero**, which is the opposite call from the expiry gauge and deliberately so: an expiry for a certificate that was never loaded would be an invented number, whereas "none of the watched files is unreadable" is the measurement, and a series that appears only once something is wrong cannot be told apart from an exporter that is not running.

**The one case that emits nothing is an EMPTY watch set**, where the watcher never reaches its loop: nothing was read, so there is nothing that can be unreadable, and a deployment with every TLS setting off is the ordinary case rather than a broken one. `Inputs::export_unreadable()` still publishes a zero if a caller asks it directly.

**The gauge is a capability rather than a live signal until the pins move.** Five repositories still pin `v0.1.0`, and adoption is a separate change per ADR-0526 — so until then the only loudness that reaches an operator is the log line.

The per-service differences the old copies carried are gone:

- the **`SERVICE` constant** is now `Inputs::new(service)` / `Inputs::of(service, ..)`, stored once;
- the **`ServeTls` / `ServerTls` spelling** is gone because the crate never names that type — it names `Material`;
- the **absent builders** (`gateway` has no listener; only `iam` has a broker or an enrolment CA) are gone because a service lists what it has instead of calling a method per role.

## What this does NOT close

**The remaining unkillable mutant is the call site.** `Inputs::of(service, &[..])` makes the list an expression, but the expression still lives in each service's `main.rs` until that service moves it into a library function. Until then, deleting `&nats_credentials` from the list is still a mutant no test kills — it is now a one-line move away from being killable, which it was not before.

A crate test asserting "the fold visits every element of its own fixture" would be a tautology dressed as a mutation kill, so this crate does not claim one. What `tests/assembly.rs` proves is that the assertion **bites**: it builds the whole watch set and a deliberately mutated one, and shows they differ. That is the assertion a service will make against its own boot function.

## Timing: when the baseline is taken

The baseline hash must be taken close to the read. A watch set that remembered paths and hashed them when the watcher first polled would put the whole of boot inside a sixty-second window in which a kubelet swap silently becomes the baseline — the real rotation is then never noticed.

`Inputs::of` folds at one point **inside** boot, which is a sub-second window and not that one. `gateway` already shipped exactly that shape, folding both of its upstreams in one expression. `Inputs::take` is there for a service that genuinely wants each hash beside its own read; the two reach the same watch set, and a test says so.

## Consuming it

Per ADR-0526, an in-org crate is pinned by a published tag, never a bare revision:

```toml
[dependencies]
yadgar-lifecycle = { git = "https://github.com/yadgarhq/lifecycle", tag = "v0.1.0" }
```

Five repositories pin it: `iam`, `task`, `gateway`, `iam-db` and `task-db`. Each adoption is a separate, reviewed change.

### Features

| feature  | default | what it carries                                          |
| -------- | ------- | -------------------------------------------------------- |
| `rotate` | on      | `rotate::watch` and everything that parses a certificate |

`shutdown`, `drain_within` and `DRAIN_BUDGET` are always present. A service that only wants to hear SIGTERM adds `default-features = false` to the dependency above.

**`v0.1.0` — the tag in the block above — PREDATES the feature, and `default-features = false` against it is silently a no-op rather than an error.** A service turning the watcher off must first move its pin to the tag this change cuts, because a published tag never moves (ADR-0526). Cargo will not warn about the mismatch; the build simply keeps everything.

**Measured with `cargo tree -e normal`, not estimated: 64 crates with the feature and 16 without it.** The 48 that go are `x509-parser` over `asn1-rs`, `der-parser`, `oid-registry`, `nom` and their tree, plus `sha2`, `thiserror`, the `metrics` facade, and — since the configuration reader landed — `serde` and `serde_norway` over `unsafe-libyaml-norway`, `indexmap`, `ryu` and `itoa`. The numbers were 54/16/38 before that reader existed and are re-measured rather than carried forward.

There is no `drain` feature, and that is a measurement rather than a taste: `src/drain.rs` reaches for `tokio` and `tracing` alone, both of which `rotate` needs anyway, so gating it would drop **zero** crates while admitting a build of this crate with no public items in it.

## Where the schedule comes from

Two knobs govern the watcher, and as of this change they have exactly one source:

| knob                          | what it sets                                                      |
| ----------------------------- | ----------------------------------------------------------------- |
| `tlsRotation.pollSeconds`     | how often the watched files are re-hashed                         |
| `tlsRotation.splayMaxSeconds` | the top of the range this pod's wait before exiting is drawn from |

Both are read from **`/etc/yadgar/config/shared/shared.yaml`**, which is ConfigMap `shared`, rendered by the chart in [`yadgarhq/config`](https://github.com/yadgarhq/config) and mounted as a directory. `Configuration::mounted().schedule()` is the whole of reading them.

**There is no default, no fallback and no last-resort constant (ADR-0569).** A knob the document does not define makes this process refuse to start, naming the knob and the file. That is a deliberate reversal: `DEFAULT_POLL = 60s` and `DEFAULT_SPLAY_MAX = 300s` used to sit in `src/rotate.rs`, and an installation that never set the values ran them with nothing saying so.

Six ways it refuses, and they are separate variants because they are separate mistakes:

| what is wrong                              | variant      |
| ------------------------------------------ | ------------ |
| the document is not there                  | `Absent`     |
| it is there and cannot be read             | `Unreadable` |
| it is not a YAML document                  | `Malformed`  |
| the knob is not in it                      | `Missing`    |
| the knob is there with no value            | `Empty`      |
| the value is not a whole number of seconds | `Unparsable` |

`Missing` and `Empty` are the pair worth the extra variant. A field typed `Option<u64>` cannot tell them apart — serde deserialises an explicit YAML `null` into `None` exactly as it does an absent key — so the section is read as a `Mapping` and the key is looked up rather than deserialised. That was measured here, not assumed: the first attempt used `Option<Value>` on the belief a `Value` would keep the difference, and the test asserting the two faults differ failed.

**The document is a `Material`, so configuration reloads by restart with no new mechanism.** Hand it to `Inputs::of` beside the TLS configuration and ADR-0523's watcher covers it by its own rule — every file the process read at boot. An operator edits `shared.yaml`, Argo syncs the ConfigMap, kubelet swaps the mounted file, the digest changes, and the pod drains and exits onto the new value (ADR-0570). This is why the chart mounts a **directory** and never a `subPath`: a `subPath` mount is copied once at container start and kubelet never updates it, so the file would be frozen for the life of the pod and the watcher would see nothing.

`CONFIG_DIR` is a compiled-in constant and that is not a violation of the rule above. ADR-0569 governs the VALUE of a setting; this is the ADDRESS of the settings, and a setting that said where settings live is an infinite regress — the ADR's own requirement that a refusal name the file presumes the process knows the path already. The one way it can be wrong is a chart whose `mountPath` disagrees with it, and that fails loudly: `Absent`, naming the path this process looked in.

## Layout

```
src/lib.rs          crate docs and the re-exports
src/rotate.rs       Configuration, Schedule, Material, File, Inputs, watch  (feature `rotate`)
src/drain.rs        DRAIN_BUDGET, Drain, drain_within, shutdown
tests/common/       the kubelet-shaped mount, and stand-ins for a service's config types
tests/rotation.rs   the watcher against real atomic ..data swaps
tests/assembly.rs   the watch set as a value — the seam this crate exists for
tests/drain.rs      when the budget's clock starts
tests/shutdown.rs   a real SIGTERM to this process, and the drain it reaches
tests/arming.rs     WHEN the handlers are installed — a SIGTERM into an un-polled future
```

`tests/rotation.rs` and `tests/assembly.rs` declare `required-features = ["rotate"]`, so `cargo test --no-default-features` skips them rather than failing to compile. Cargo forbids an optional dev-dependency, so the gate removes a consumer's cost and not a test build's.

**The feature-off build IS checked now, and this paragraph used to say it was not.** It read "CI runs `cargo test --all-features` and nothing else, so the feature-off build is checked by hand and by nobody else", and `yadgarhq/actions` v1.10.0 made that false: the shared `test` job reads `cargo metadata`, finds that this package declares a feature, and runs `cargo test --no-default-features` after the `--all-features` suite. The failure the old paragraph named — a change making the ungated `src/drain.rs` reach for `sha2`, a `rotate`-only dependency — is the exact one that step was written for, and it is now caught on the pull request.

Two holes are left, and they are narrower than the sentence they replace:

- **Clippy still sees only one build.** The shared `cargo-clippy` hook is `--all-targets --all-features`, so a lint that fires only with the feature off ships green. Run `cargo clippy --all-targets --no-default-features -- -D warnings` before proposing a change to `src/drain.rs` or to `Cargo.toml`.
- **Rustdoc is covered here and nowhere else.** No workflow or shared hook in the estate runs `cargo doc` under any feature set, so this repository carries the two `cargo-doc-*` hooks in its own `.pre-commit-config.yaml` — one per feature set, because each build reads doc comments the other cannot see. See the crate docs in `src/lib.rs` for why the `--no-default-features` half is the one the backtick convention depends on.

There is no `Containerfile` and no `chart/`. This is a library: `ci-release` publishes nothing, and **the git tag is the release**.
