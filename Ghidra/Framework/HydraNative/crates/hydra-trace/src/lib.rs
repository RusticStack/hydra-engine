//! Hydra semantic trace (TRACE-1): the raw segment format, the event model, a deterministic
//! synthetic generator and the verifier. The store, query, diff, explain and check modules build
//! on these (see `Ghidra/Features/HeadlessSession/TRACE-1.md`).

pub mod align;
pub mod artifact;
pub mod canon;
pub mod checks;
pub mod corrid;
pub mod explain;
pub mod export;
pub mod interp;
pub mod lifetime;
pub mod minidump;
pub mod model;
pub mod query;
pub mod raw;
pub mod rawio;
pub mod relations;
pub mod service;
pub mod session;
pub mod store;
pub mod symbolize;
pub mod synth;

/// The contract version these modules implement.
pub const SCHEMA: &str = "hydra.trace.event/1";

#[cfg(test)]
mod store_tests;
