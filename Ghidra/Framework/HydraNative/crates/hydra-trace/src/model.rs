//! The TRACE-1 event envelope. Times are integer nanoseconds in a declared clock domain (no
//! floats, so the chained bytes are identical across languages). Unknown fields are kept in
//! `payload`; the envelope itself is closed.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Core event kinds (spec section 4.3). Profiles add `<profile>.*` kinds.
pub const CORE_KINDS: &[&str] = &[
    "core.session.start",
    "core.session.end",
    "core.process.start",
    "core.process.exit",
    "core.module.load",
    "core.module.unload",
    "core.thread.start",
    "core.thread.exit",
    "core.function.enter",
    "core.function.exit",
    "core.resource.open",
    "core.resource.close",
    "core.resource.read",
    "core.resource.write",
    "core.resource.missing",
    "core.object.create",
    "core.object.destroy",
    "core.state.read",
    "core.state.write",
    "core.sync.wait",
    "core.sync.signal",
    "core.error",
    "core.marker",
    "core.capture.source",
    "core.capture.gap",
];

/// True for a kind the envelope accepts: a core kind, or a `<namespace>.<name>` profile kind.
pub fn kind_is_valid(kind: &str) -> bool {
    if kind.starts_with("core.") {
        return CORE_KINDS.contains(&kind);
    }
    let mut parts = kind.split('.');
    let ok = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    matches!((parts.next(), parts.next(), parts.next()), (Some(a), Some(b), None) if ok(a) && ok(b) && a != "core")
}

/// How the value of an event was acquired (spec 14.2, 14.3). Sampling is an acquisition policy,
/// not a confidence level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Acquisition {
    Atomic,
    Bracketed,
    Snapshot,
    Inferred,
}

/// The envelope of one event as written by a producer (before ingest assigns `seq` and ids).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub kind: String,
    pub source_id: String,
    /// Producer sequence within `source_id` and `producer_gen`.
    pub source_seq: u64,
    /// Bumped on every producer reconnect; (source_id, producer_gen, source_seq) is unique.
    pub producer_gen: u32,
    pub clock_domain: String,
    /// Monotonic nanoseconds in `clock_domain`.
    pub t_mono_ns: u64,
    /// Wall-clock nanoseconds since the Unix epoch; for humans, not ordering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t_wall_ns: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<u32>,
    /// Session-local process generation (a reused PID gets a new one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_gen: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_gen: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_instance: Option<u32>,
    /// `exact`, `inferred` or `sampled`: a summary only; relations carry the evidence.
    pub confidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acquisition: Option<Acquisition>,
    /// Code address (VA) of the call site, when captured; absent means "not captured".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub va: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callstack: Vec<u64>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub payload: Map<String, Value>,
}

impl Event {
    pub fn to_record(&self) -> Map<String, Value> {
        match serde_json::to_value(self) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        assert!(kind_is_valid("core.resource.open"));
        assert!(!kind_is_valid("core.resource.nope"));
        assert!(kind_is_valid("app.feature"));
        assert!(!kind_is_valid("app"));
        assert!(!kind_is_valid("App.feature"));
        assert!(!kind_is_valid("a.b.c"));
    }
}
