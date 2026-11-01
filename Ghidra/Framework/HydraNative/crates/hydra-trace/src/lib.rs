//! Hydra semantic trace (TRACE-1): the raw segment format, the event model, a deterministic
//! synthetic generator and the verifier. The store, query, diff, explain and check modules build
//! on these (see `Ghidra/Features/HeadlessSession/TRACE-1.md`).

pub mod canon;
pub mod model;
pub mod query;
pub mod raw;
pub mod store;
pub mod synth;

/// The contract version these modules implement.
pub const SCHEMA: &str = "hydra.trace.event/1";
