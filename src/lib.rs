//! How a server process starts, stops and restarts.
//!
//! Three units live here, and they are ONE unit rather than three that happen
//! to share a crate. `rotate::watch` resolves when the security material this
//! process read at boot changes on disk; the caller selects on it beside
//! [`shutdown`]; and whichever arm wins, [`drain_within`] bounds the drain that
//! follows. Lifting any one of them alone would put a single control flow
//! across a crate boundary.
//!
//! # Features
//!
//! `rotate` is on by default and carries the watcher. Switching it off leaves
//! [`shutdown`], [`drain_within`] and [`DRAIN_BUDGET`], and drops the
//! certificate-parsing tree and the `metrics` facade with it — which is what a
//! service that only wants to hear SIGTERM should take. `Cargo.toml` records
//! what the two builds measure and why `drain` has no gate of its own.
//!
//! **Every `rotate::*` name in these crate docs is written in plain backticks
//! rather than as an intra-doc link, and deliberately.** A link to an item
//! behind a `cfg` is a broken link in the build where the `cfg` is off.
//! Suppressing the lint would hide the next real one.
//!
//! **THE GATE THAT MAKES THAT A RULE RATHER THAN A HABIT IS THE
//! `cargo-doc-no-default-features` HOOK IN `.pre-commit-config.yaml`**, and it
//! is named here rather than merely asserted because this paragraph used to
//! assert a gate that did not exist. It said `RUSTDOCFLAGS="-D warnings" cargo
//! doc --no-default-features` was "one of this repository's gates". Measured on
//! 2026-09-04: no workflow, hook or script in ANY repository of this estate ran
//! `cargo doc` at all, under any feature set. So the convention this paragraph
//! justifies was held by nothing but attention, and the justification was the
//! load-bearing part. CI runs `pre-commit` in the job the branch ruleset
//! requires, so the hook is a blocking check rather than a local habit.
//!
//! # Why this is a crate rather than a file each service owns
//!
//! It was a file each service owned, and the copies had already begun to drift.
//! Measured on 2026-09-04, before this crate existed:
//!
//! | unit | copies |
//! | --- | --- |
//! | the rotation watcher | 3 — `iam`, `task`, `gateway` |
//! | `shutdown` | 5 — the three above, plus `iam-db` and `task-db` |
//! | `DRAIN_BUDGET` + `drain_within` | 3 — `iam`, `task`, `gateway` |
//!
//! The watcher's three copies were identical apart from a service name, one
//! type's spelling, and which of the per-role builders each service called.
//! `shutdown`'s five were byte-identical in four repos and a near-copy with a
//! different error type in the fifth. ADR-0523 says so in its own consequences:
//! *"the watcher core is repo-agnostic and is about to exist in four copies;
//! lift it into a shared crate before the third."*
//!
//! # THE REASON THAT IS WORTH MORE THAN DE-DUPLICATION
//!
//! **The watch set was assembled in `main.rs`, where no test can reach it.**
//! Every service built its `Inputs` as a run of builder calls interleaved with
//! boot, and no test spawns the binary — so deleting one of those calls
//! compiled, passed the whole suite, and shipped a process that would never
//! notice that file rotating. Eight such calls stand across three `main.rs`
//! files: four in `iam`, two in `task`, two in `gateway`. Not one of them is
//! killable.
//!
//! `rotate::Inputs::of` is the answer: the watch set becomes a VALUE — a list
//! of things that implement `rotate::Material` — rather than a sequence of
//! statements. A value can be returned from a function in a service's library,
//! and a function in a library is something a test can call and assert against.
//! What remains in `main.rs` is one expression naming the list, and the fold
//! over it is tested here.
//!
//! See the README for what that does and does not close.

pub mod drain;
#[cfg(feature = "rotate")]
pub mod rotate;

pub use drain::{drain_within, shutdown, Drain, DRAIN_BUDGET};
