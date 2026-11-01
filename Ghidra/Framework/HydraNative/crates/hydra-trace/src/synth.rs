//! A seeded, deterministic synthetic trace generator. Every recipe is a scenario the acceptance
//! gates need (spec 14.1, 14.2, 14.3, 14.7, 14.8): the same seed gives byte-identical segments.

use crate::model::Event;
use crate::raw::Chain;
use serde_json::{json, Map, Value};

/// A scenario recipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipe {
    /// Process and module lifecycle, resource opens and state writes.
    Baseline,
    /// Two unrelated operations interleave; only correlation ids connect request and completion.
    Interleave,
    /// A PID, a handle and an object address are reused; a module reloads at another base.
    Reuse,
    /// Two producers whose events arrive out of order.
    Delayed,
    /// A producer is lost mid-run: a `core.capture.gap` and a missing source_seq range.
    Gap,
    /// A ring overflow reported out of band (`core.capture.gap` with a dropped count).
    Overflow,
    /// A segment whose last line is torn.
    Torn,
}

pub const ALL: &[Recipe] = &[
    Recipe::Baseline,
    Recipe::Interleave,
    Recipe::Reuse,
    Recipe::Delayed,
    Recipe::Gap,
    Recipe::Overflow,
    Recipe::Torn,
];

impl Recipe {
    pub fn name(self) -> &'static str {
        match self {
            Recipe::Baseline => "baseline",
            Recipe::Interleave => "interleave",
            Recipe::Reuse => "reuse",
            Recipe::Delayed => "delayed",
            Recipe::Gap => "gap",
            Recipe::Overflow => "overflow",
            Recipe::Torn => "torn",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        ALL.iter().copied().find(|r| r.name() == name)
    }
}

/// One generated segment: its id and bytes.
pub struct Segment {
    pub id: String,
    pub bytes: Vec<u8>,
}

/// xorshift64*: small, fast, deterministic across platforms.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

struct Source {
    id: String,
    chain: Chain,
    seq: u64,
    pgen: u32,
    out: Vec<u8>,
}

impl Source {
    fn new(id: &str) -> Self {
        Self { id: id.into(), chain: Chain::new(id), seq: 0, pgen: 1, out: Vec::new() }
    }

    fn emit(&mut self, kind: &str, t: u64, pid: u32, tid: u32, payload: Value) {
        self.emit_with(kind, t, pid, tid, payload, |_| {});
    }

    fn emit_with(&mut self, kind: &str, t: u64, pid: u32, tid: u32, payload: Value, tweak: impl FnOnce(&mut Event)) {
        let mut event = Event {
            kind: kind.into(),
            source_id: self.id.clone(),
            source_seq: self.seq,
            producer_gen: self.pgen,
            clock_domain: "qpc-10mhz".into(),
            t_mono_ns: t,
            t_wall_ns: None,
            process_id: Some(pid),
            thread_id: Some(tid),
            process_gen: None,
            thread_gen: None,
            module: None,
            module_instance: None,
            confidence: "exact".into(),
            acquisition: None,
            va: None,
            callstack: Vec::new(),
            payload: payload.as_object().cloned().unwrap_or_default(),
        };
        tweak(&mut event);
        self.seq += 1;
        if let Ok(line) = self.chain.push(event.to_record()) {
            self.out.extend_from_slice(&line);
        }
    }

    fn skip(&mut self, count: u64) {
        self.seq += count;
    }

    fn finish(self) -> Segment {
        Segment { id: self.id, bytes: self.out }
    }
}

/// Generate `events` events of `recipe` (at least the recipe's fixed scenario) from `seed`.
pub fn generate(recipe: Recipe, seed: u64, events: usize) -> Vec<Segment> {
    let mut rng = Rng(seed ^ 0x9E37_79B9_7F4A_7C15 | 1);
    let mut a = Source::new("src_a");
    let pid = 1000 + rng.below(5000) as u32;
    a.emit("core.process.start", 1_000, pid, 1, json!({"image": "main.exe", "ppid": 4}));
    a.emit_with(
        "core.module.load",
        1_100,
        pid,
        1,
        json!({"name": "main.exe", "base": 0x40_0000, "size": 0x2000}),
        |e| {
            e.module = Some("main.exe".into());
            e.module_instance = Some(1);
        },
    );
    match recipe {
        Recipe::Baseline | Recipe::Gap | Recipe::Overflow | Recipe::Torn => {
            for i in 0..events as u64 {
                let t = 2_000 + i * 10;
                if i % 3 == 0 {
                    a.emit(
                        "core.resource.open",
                        t,
                        pid,
                        1,
                        json!({"type": "file", "key": format!("res/{}", rng.below(50)), "provider": "disk"}),
                    );
                } else {
                    a.emit_with(
                        "core.state.write",
                        t,
                        pid,
                        1 + (i % 4) as u32,
                        json!({"scope": "object", "object": 0x1000 + rng.below(8) * 0x10, "key": "hp", "new": rng.below(100)}),
                        |e| e.acquisition = Some(crate::model::Acquisition::Bracketed),
                    );
                }
            }
            match recipe {
                Recipe::Gap => {
                    a.emit(
                        "core.capture.gap",
                        2_000 + events as u64 * 10,
                        pid,
                        1,
                        json!({"reason": "producer-lost", "first_missing_source_seq": a.seq, "last_missing_source_seq": a.seq + 9}),
                    );
                    a.skip(10);
                }
                Recipe::Overflow => a.emit(
                    "core.capture.gap",
                    2_000 + events as u64 * 10,
                    pid,
                    1,
                    json!({"reason": "ring-overflow", "dropped": 17, "out_of_band": true}),
                ),
                _ => {}
            }
        }
        Recipe::Interleave => {
            // Operations X and Y interleave; each request has its own correlation id.
            for i in 0..(events as u64 / 4).max(1) {
                let (x, y) = (format!("op-x-{i}"), format!("op-y-{i}"));
                let t = 2_000 + i * 100;
                a.emit("app.request", t, pid, 2, json!({"corr": x, "name": "load"}));
                a.emit("app.request", t + 5, pid, 3, json!({"corr": y, "name": "save"}));
                a.emit("app.completion", t + 10, pid, 3, json!({"corr": y, "result": 0}));
                a.emit("app.completion", t + 15, pid, 2, json!({"corr": x, "result": 0}));
            }
        }
        Recipe::Reuse => {
            // PID reuse: the same pid starts again after an exit, a handle number is reused and
            // the module reloads at another base. Each lifetime has its own generation.
            a.emit_with("core.resource.open", 2_000, pid, 1, json!({"type": "file", "key": "a.dat", "handle": 0x44}), |e| {
                e.process_gen = Some(1)
            });
            a.emit_with("core.resource.close", 2_100, pid, 1, json!({"handle": 0x44}), |e| e.process_gen = Some(1));
            a.emit("core.process.exit", 2_200, pid, 1, json!({"code": 0}));
            a.emit("core.process.start", 3_000, pid, 1, json!({"image": "main.exe", "ppid": 4}));
            a.emit_with(
                "core.module.load",
                3_100,
                pid,
                1,
                json!({"name": "main.exe", "base": 0x7000_0000u64, "size": 0x2000}),
                |e| {
                    e.module = Some("main.exe".into());
                    e.module_instance = Some(2);
                    e.process_gen = Some(2);
                },
            );
            a.emit_with("core.resource.open", 3_200, pid, 1, json!({"type": "file", "key": "b.dat", "handle": 0x44}), |e| {
                e.process_gen = Some(2)
            });
            a.emit("core.object.create", 3_300, pid, 1, json!({"object": 0x1000, "type": "T", "generation": 1}));
            a.emit("core.object.destroy", 3_400, pid, 1, json!({"object": 0x1000}));
            a.emit("core.object.create", 3_500, pid, 1, json!({"object": 0x1000, "type": "U", "generation": 2}));
        }
        Recipe::Delayed => {
            let mut b = Source::new("src_b");
            for i in 0..(events as u64 / 2).max(1) {
                a.emit("app.tick", 2_000 + i * 20, pid, 1, json!({"i": i}));
            }
            // b's events carry earlier timestamps but are appended to its segment later.
            for i in 0..(events as u64 / 2).max(1) {
                b.emit("app.tick", 2_000 + i * 20 + 7, pid, 9, json!({"i": i, "producer": "b"}));
            }
            return vec![a.finish(), b.finish()];
        }
    }
    let mut segment = a.finish();
    if recipe == Recipe::Torn {
        let keep = segment.bytes.len().saturating_sub(17);
        segment.bytes.truncate(keep);
    }
    vec![segment]
}

/// The generated segments as one `name -> bytes` map, for callers that just need the data.
pub fn as_map(segments: &[Segment]) -> Map<String, Value> {
    segments.iter().map(|s| (s.id.clone(), Value::from(s.bytes.len() as u64))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::{scan, Damage};

    #[test]
    fn same_seed_is_byte_identical() {
        for &recipe in ALL {
            let a = generate(recipe, 7, 200);
            let b = generate(recipe, 7, 200);
            assert_eq!(a.len(), b.len());
            for (x, y) in a.iter().zip(&b) {
                assert_eq!(x.bytes, y.bytes, "{}", recipe.name());
            }
        }
    }

    #[test]
    fn different_seed_differs() {
        assert_ne!(generate(Recipe::Baseline, 1, 50)[0].bytes, generate(Recipe::Baseline, 2, 50)[0].bytes);
    }

    #[test]
    fn every_recipe_verifies_except_torn() {
        for &recipe in ALL {
            for s in generate(recipe, 3, 120) {
                let result = scan(&s.bytes, &s.id);
                if recipe == Recipe::Torn {
                    assert!(matches!(result.damage, Some(Damage::TornTail { .. })));
                } else {
                    assert!(result.is_clean(), "{} {:?}", recipe.name(), result.damage);
                }
                assert!(!result.records.is_empty());
            }
        }
    }
}
