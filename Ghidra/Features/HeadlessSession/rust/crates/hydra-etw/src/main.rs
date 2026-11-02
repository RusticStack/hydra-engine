//! `hydra-etw`: a real-time ETW consumer for the Hydra semantic trace (TRACE-1, Windows x64).
//!
//! It enables the kernel process/thread/image, file, registry, network and `PnP` providers in its own real-time
//! session, keeps the events of one process tree, and writes them to its own raw segment (`etw.seg`) with its own
//! health (`etw.health.json`). It writes nothing into the target. It needs elevation (or Performance Log Users);
//! without it the refusal is written as a `core.capture.source` event with the limitation `etw-not-elevated`, so the
//! missing coverage is visible in the session, and the exit code is 3.
//!
//! ```text
//! hydra-etw --dir <session>/trace --session <id> --pid <root> [--pid <root>...] --key-file <scope.key>
//!           [--gen 1] [--providers process,file,registry,network,pnp] [--stop-file <path>] [--duration-ms N]
//!           [--kernel-filter]
//! ```
//!
//! Exit codes: 0 stopped cleanly, 2 failed, 3 refused (not elevated).
#![expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_ptr_alignment,
    clippy::multiple_unsafe_ops_per_block,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::fn_params_excessive_bools,
    clippy::match_same_arms,
    reason = "a Win32 FFI boundary (handles, GUIDs, counted buffers) and a command-line tool: casts are the API, each unsafe block is one documented call sequence, stderr is the tool's diagnostic channel, and the kind table lists one arm per documented event id"
)]
#![cfg_attr(
    not(windows),
    allow(
        unused,
        reason = "the crate is Windows-only; other hosts build an empty binary"
    )
)]

#[cfg(windows)]
mod etw;
mod events;
mod segment;

#[cfg(not(windows))]
fn main() {
    std::process::exit(2);
}

#[cfg(windows)]
mod app;

#[cfg(windows)]
fn main() {
    std::process::exit(app::run(&std::env::args().skip(1).collect::<Vec<_>>()));
}
