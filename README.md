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

Nothing depends on this crate yet. Adoption is a separate, reviewed change per repository.

## Layout

```
src/lib.rs          crate docs and the re-exports
src/rotate.rs       Schedule, Material, File, Inputs, watch
src/drain.rs        DRAIN_BUDGET, Drain, drain_within, shutdown
tests/common/       the kubelet-shaped mount, and stand-ins for a service's config types
tests/rotation.rs   the watcher against real atomic ..data swaps
tests/assembly.rs   the watch set as a value — the seam this crate exists for
tests/drain.rs      when the budget's clock starts
tests/shutdown.rs   a real SIGTERM to this process
```

There is no `Containerfile` and no `chart/`. This is a library: `ci-release` publishes nothing, and **the git tag is the release**.
