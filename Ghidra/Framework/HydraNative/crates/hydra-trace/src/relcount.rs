//! An incrementally maintained count of the relations `relations::compute` would return, so
//! `trace_info` on a live session does not recompute every relation (O(session size)) on each
//! poll. The writer feeds every stored event, in order, to [`RelCounter`] and stores the total
//! with the batch; a reader whose revision matches reads the number.
//!
//! The count only needs the shape of each rule, not its edges: a correlation group yields
//! `c + max(r - c, 0) + s + [s > 0 and c > 0]` request-completion relations (requests, stages,
//! completions), a function stack one relation per enter below another frame, per exit and per
//! frame lost or left open, a handoff token one per consecutive pair on different threads (or one
//! for a lone event), and so on. `relations::compute` stays the definition; a test compares both
//! on every synthetic recipe.

use crate::model::Event;
use serde_json::Value;
use std::collections::HashMap;

/// The most entries the counter keeps (a few tens of MiB).
pub const MAX_TRACKED: usize = 1_000_000;

type ThreadKey = (i64, i64, i64);

#[derive(Clone, Debug)]
struct Hand {
    clock: String,
    t: i64,
    seq: i64,
    thread: ThreadKey,
}

impl Hand {
    fn order(&self) -> (&str, i64, i64) {
        (&self.clock, self.t, self.seq)
    }
}

/// Counts relations as events arrive in sequence order.
#[derive(Debug, Default)]
pub struct RelCounter {
    /// Relations that are final already.
    closed: u64,
    /// (requests, stages, completions) per correlation id, and the sum of their contributions.
    corr: HashMap<String, (u64, u64, u64)>,
    corr_total: u64,
    stacks: HashMap<ThreadKey, Vec<String>>,
    open_frames: u64,
    handoff: HashMap<String, Vec<Hand>>,
    handoff_total: u64,
    written: std::collections::HashSet<String>,
    hand_events: usize,
}

fn completion_like(kind: &str) -> bool {
    matches!(
        kind.rsplit('.').next().unwrap_or(""),
        "completion" | "response" | "reply" | "done" | "complete" | "result"
    )
}

fn corr_contribution((r, s, c): (u64, u64, u64)) -> u64 {
    c + r.saturating_sub(c) + s + u64::from(s > 0 && c > 0)
}

fn pair(a: &Hand, b: &Hand) -> u64 {
    u64::from(a.thread != b.thread)
}

impl RelCounter {
    /// The number of relations among the events fed so far.
    pub fn total(&self) -> u64 {
        self.closed + self.corr_total + self.handoff_total + self.open_frames
    }

    /// How many entries the counter holds; the writer drops the counter past [`MAX_TRACKED`] so
    /// its memory stays bounded (readers then compute the count once per revision).
    pub fn tracked(&self) -> usize {
        self.corr.len() + self.written.len() + self.hand_events + self.open_frames as usize
    }

    /// Feed the next stored event. `corr` and `state_key` are the values stored with it.
    pub fn feed(&mut self, seq: i64, event: &Event, corr: Option<&str>, state_key: Option<&str>) {
        let payload = &event.payload;
        let thread: ThreadKey = (
            i64::from(event.process_gen.unwrap_or(0)),
            i64::from(event.thread_id.unwrap_or(0)),
            i64::from(event.thread_gen.unwrap_or(0)),
        );
        if let Some(c) = corr {
            let slot = match self.corr.get_mut(c) {
                Some(slot) => slot,
                None => self.corr.entry(c.to_string()).or_default(),
            };
            let before = corr_contribution(*slot);
            if payload.contains_key("stage") {
                slot.1 += 1;
            } else if completion_like(&event.kind) {
                slot.2 += 1;
            } else {
                slot.0 += 1;
            }
            self.corr_total = self.corr_total - before + corr_contribution(*slot);
        }
        match event.kind.as_str() {
            "core.function.enter" => {
                let stack = self.stacks.entry(thread).or_default();
                if !stack.is_empty() {
                    self.closed += 1;
                }
                stack.push(
                    payload
                        .get("function")
                        .map(Value::to_string)
                        .unwrap_or_default(),
                );
                self.open_frames += 1;
            }
            "core.function.exit" => {
                let stack = self.stacks.entry(thread).or_default();
                let wanted = payload
                    .get("function")
                    .map(Value::to_string)
                    .unwrap_or_default();
                if let Some(pos) = stack.iter().rposition(|n| *n == wanted) {
                    let drained = (stack.len() - pos) as u64;
                    stack.truncate(pos);
                    self.open_frames -= drained;
                    // The match pairs up (one relation); the frames above it are lost (one each).
                    self.closed += drained;
                } else {
                    self.closed += 1;
                }
            }
            _ => {}
        }
        if let Some(token) = payload.get("handoff") {
            let hand = Hand {
                clock: event.clock_domain.clone(),
                t: event.t_mono_ns as i64,
                seq,
                thread,
            };
            let group = self.handoff.entry(token.to_string()).or_default();
            let at = group.partition_point(|h| h.order() <= hand.order());
            let len_before = group.len();
            if len_before == 1 {
                self.handoff_total -= 1;
            }
            if at > 0 && at < len_before {
                self.handoff_total -= pair(&group[at - 1], &group[at]);
            }
            if at > 0 {
                self.handoff_total += pair(&group[at - 1], &hand);
            }
            if at < len_before {
                self.handoff_total += pair(&hand, &group[at]);
            }
            group.insert(at, hand);
            self.hand_events += 1;
            if group.len() == 1 {
                self.handoff_total += 1;
            }
        }
        if payload.get("created_by").is_some_and(Value::is_string) {
            self.closed += 1;
        }
        if payload.contains_key("consumes") {
            self.closed += 1;
        }
        if let Some(key) = state_key {
            match event.kind.as_str() {
                "core.state.write" => {
                    if !self.written.contains(key) {
                        self.written.insert(key.to_string());
                    }
                }
                "core.state.read" if self.written.contains(key) => self.closed += 1,
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::raw;
    use crate::relations;
    use crate::store::Store;
    use crate::synth::{self, Recipe};

    #[test]
    fn the_count_equals_the_computed_relations() {
        let mut any = false;
        for recipe in [
            Recipe::Baseline,
            Recipe::Interleave,
            Recipe::Reuse,
            Recipe::Delayed,
            Recipe::Gap,
        ] {
            let mut store = Store::memory("rc").unwrap();
            for s in synth::generate(recipe, 3, 600) {
                let scan = raw::scan(&s.bytes, &s.id);
                for (i, chunk) in scan.records.chunks(97).enumerate() {
                    store.ingest(&s.id, (i * 97) as u64, chunk).unwrap();
                }
            }
            let computed = relations::compute(&store, false).unwrap().len() as u64;
            assert_eq!(
                relations::count(&store).unwrap(),
                (computed, "computed"),
                "{}",
                recipe.name()
            );
            any |= computed > 0;
        }
        assert!(any, "some recipe yields relations");
    }

    #[test]
    fn a_mixed_stream_with_every_rule_and_shuffled_clocks_counts_the_same() {
        use crate::store_tests::{ev, records};
        use serde_json::json;
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move |m: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % m
        };
        let mut events = Vec::new();
        for i in 0..4000u64 {
            let pid = 1 + next(2) as u32;
            let corr = format!("c{}", next(40));
            let f = format!("f{}", next(4));
            let (kind, payload) = match next(12) {
                0 => ("app.request", json!({"corr": corr})),
                1 => ("app.completion", json!({"corr": corr})),
                2 => ("app.stage", json!({"corr": corr, "stage": next(3)})),
                3 => ("core.function.enter", json!({"function": f})),
                4 => ("core.function.exit", json!({"function": f})),
                5 => ("app.send", json!({"handoff": format!("t{}", next(30))})),
                6 => (
                    "app.make",
                    json!({"created_by": corr, "corr": format!("n{i}")}),
                ),
                7 => (
                    "app.use",
                    json!({"consumes": next(20), "produces": next(20)}),
                ),
                8 => (
                    "core.state.write",
                    json!({"object": next(5), "key": "hp", "new": next(3)}),
                ),
                9 => (
                    "core.state.read",
                    json!({"object": next(5), "key": "hp", "value": next(3)}),
                ),
                10 => ("app.note", json!({"corr": corr, "handoff": next(5)})),
                _ => ("core.function.enter", json!({"function": f, "corr": corr})),
            };
            let clock = if next(3) == 0 { "other" } else { "qpc" };
            let t = 1000 + next(500);
            let tid = 1 + next(3) as u32;
            events.push(ev(kind, i, pid, payload, |e| {
                e.clock_domain = clock.into();
                e.t_mono_ns = t;
                e.thread_id = Some(tid);
            }));
        }
        let mut store = Store::memory("mix").unwrap();
        for (n, chunk) in records(events).chunks(333).enumerate() {
            store.ingest("s", (n * 333) as u64, chunk).unwrap();
        }
        let computed = relations::compute(&store, false).unwrap().len() as u64;
        assert!(computed > 500);
        assert_eq!(relations::count(&store).unwrap(), (computed, "computed"));
        let kept: String = store
            .conn()
            .query_row(
                "SELECT value FROM meta WHERE key='relations_count'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(kept.starts_with(&format!("{computed}:")), "{kept}");
    }
}
