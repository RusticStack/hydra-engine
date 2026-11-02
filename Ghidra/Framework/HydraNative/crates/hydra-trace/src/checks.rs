//! The richer assertions of TRACE-1 section 14 (ordered, required and forbidden transitions,
//! `only on role`, `W precedes R in frame`, `at most once per frame`, `no frame without E`, round
//! trips). Each evaluator counts the eligible cases and cites counterexamples; the shared
//! finalizer in `query::check` turns an empty eligible set or an overlapping gap into `unknown`.
//!
//! A frame is delimited by `core.marker` events whose payload carries an integer `frame`: an
//! event belongs to the frame of the latest such marker of its process generation.

use crate::query::{Assertion, CheckResult, Verdict, id_of};
use crate::store::{Result, Store};
use rusqlite::params;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap};

const MAX_COUNTEREXAMPLES: usize = 50;

struct Row {
    seq: i64,
    kind: String,
    pgen: i64,
    state_key: Option<String>,
    payload: Map<String, Value>,
}

fn load(store: &Store, kinds: &[&str]) -> Result<Vec<Row>> {
    let marks = vec!["?"; kinds.len()].join(",");
    let mut stmt = store.conn().prepare(&format!(
        "SELECT seq,kind,COALESCE(process_gen,0),state_key,payload FROM events WHERE kind IN ({marks}) ORDER BY seq"
    ))?;
    let rows = stmt.query_map(rusqlite::params_from_iter(kinds.iter()), |r| {
        let payload: String = r.get(4)?;
        Ok(Row {
            seq: r.get(0)?,
            kind: r.get(1)?,
            pgen: r.get(2)?,
            state_key: r.get(3)?,
            payload: serde_json::from_str::<Value>(&payload)
                .ok()
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default(),
        })
    })?;
    rows.collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}

fn text(row: &Row, field: &str) -> Option<String> {
    row.payload
        .get(field)
        .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string))
}

struct Out<'a> {
    store: &'a Store,
    result: &'a mut CheckResult,
}

impl Out<'_> {
    fn counter(&mut self, seq: i64) {
        if self.result.counterexamples.len() < MAX_COUNTEREXAMPLES {
            self.result.counterexamples.push(id_of(self.store, seq));
        }
    }
}

/// Fill `result.checked`, its counterexamples and a provisional verdict for `assertion`.
pub(crate) fn eval(store: &Store, assertion: &Assertion, result: &mut CheckResult) -> Result<()> {
    let mut out = Out { store, result };
    let mut failed = false;
    let mut checked = 0u64;
    let mut unknown_cases = 0u64;
    match assertion {
        Assertion::OrderedTransitions {
            kinds, key_field, ..
        } => {
            let names: Vec<&str> = kinds.iter().map(String::as_str).collect();
            let mut progress: HashMap<String, usize> = HashMap::new();
            let mut bad: HashMap<String, i64> = HashMap::new();
            for row in load(store, &names)? {
                let Some(key) = text(&row, key_field).or_else(|| corr_of(store, row.seq)) else {
                    continue;
                };
                let idx = kinds.iter().position(|k| *k == row.kind).unwrap_or(0);
                let seen = progress.entry(key.clone()).or_insert(0);
                if idx < *seen {
                    bad.entry(key).or_insert(row.seq);
                } else {
                    *seen = idx;
                }
            }
            checked = progress.len() as u64;
            let mut firsts: Vec<i64> = bad.values().copied().collect();
            firsts.sort_unstable();
            for seq in firsts {
                failed = true;
                out.counter(seq);
            }
        }
        Assertion::RequiredTransition {
            from,
            to,
            key_field,
            ..
        }
        | Assertion::ForbiddenTransition {
            from,
            to,
            key_field,
            ..
        } => {
            let required = matches!(assertion, Assertion::RequiredTransition { .. });
            let rows = load(store, &[from.as_str(), to.as_str()])?;
            let key_of = |r: &Row| text(r, key_field).or_else(|| corr_of(store, r.seq));
            // For each key: the first `from` and whether a `to` follows it.
            let mut first_from: BTreeMap<String, i64> = BTreeMap::new();
            let mut followed: HashMap<String, i64> = HashMap::new();
            for row in &rows {
                let Some(key) = key_of(row) else { continue };
                if row.kind == *from {
                    first_from.entry(key).or_insert(row.seq);
                } else if first_from.contains_key(&key) {
                    followed.entry(key).or_insert(row.seq);
                }
            }
            checked = first_from.len() as u64;
            for (key, seq) in &first_from {
                let hit = followed.get(key);
                if required && hit.is_none() {
                    failed = true;
                    out.counter(*seq);
                } else if !required && let Some(&bad) = hit {
                    failed = true;
                    out.counter(bad);
                }
            }
        }
        Assertion::OnlyOnRole {
            kind,
            role,
            role_field,
            ..
        } => {
            for row in load(store, &[kind.as_str()])? {
                match text(&row, role_field) {
                    Some(r) if r == *role => checked += 1,
                    Some(_) => {
                        checked += 1;
                        failed = true;
                        out.counter(row.seq);
                    }
                    // No role recorded: neither a pass nor a counterexample.
                    None => unknown_cases += 1,
                }
            }
        }
        Assertion::WritePrecedesReadInFrame { .. } => {
            let mut frame: HashMap<i64, i64> = HashMap::new();
            // (frame, state key) -> has a write been seen in this frame
            let mut written: HashMap<(i64, i64, String), bool> = HashMap::new();
            let mut judged: HashMap<(i64, i64, String), ()> = HashMap::new();
            for row in load(
                store,
                &["core.marker", "core.state.write", "core.state.read"],
            )? {
                if row.kind == "core.marker" {
                    if let Some(f) = row.payload.get("frame").and_then(Value::as_i64) {
                        frame.insert(row.pgen, f);
                    }
                    continue;
                }
                let Some(key) = row.state_key.clone() else {
                    continue;
                };
                let f = *frame.get(&row.pgen).unwrap_or(&-1);
                let k = (row.pgen, f, key);
                if row.kind == "core.state.write" {
                    written.insert(k, true);
                } else if f >= 0 && judged.insert(k.clone(), ()).is_none() {
                    checked += 1;
                    if !written.get(&k).copied().unwrap_or(false) {
                        failed = true;
                        out.counter(row.seq);
                    }
                }
            }
        }
        Assertion::AtMostOncePerFrame { kind, .. } => {
            let mut frame: HashMap<i64, i64> = HashMap::new();
            let mut count: HashMap<(i64, i64), (u64, i64)> = HashMap::new();
            for row in load(store, &["core.marker", kind.as_str()])? {
                if row.kind == "core.marker" {
                    if let Some(f) = row.payload.get("frame").and_then(Value::as_i64) {
                        frame.insert(row.pgen, f);
                    }
                    if row.kind != *kind {
                        continue;
                    }
                }
                let f = *frame.get(&row.pgen).unwrap_or(&-1);
                if f < 0 {
                    continue;
                }
                let e = count.entry((row.pgen, f)).or_insert((0, row.seq));
                e.0 += 1;
                if e.0 == 2 {
                    failed = true;
                    out.counter(row.seq);
                }
            }
            checked = count.len() as u64;
        }
        Assertion::NoFrameWithout { required, .. } => {
            // (pgen, frame) -> (marker seq, saw required)
            let mut frames: BTreeMap<(i64, i64), (i64, bool)> = BTreeMap::new();
            let mut current: HashMap<i64, i64> = HashMap::new();
            for row in load(store, &["core.marker", required.as_str()])? {
                if row.kind == "core.marker"
                    && let Some(f) = row.payload.get("frame").and_then(Value::as_i64)
                {
                    current.insert(row.pgen, f);
                    frames.entry((row.pgen, f)).or_insert((row.seq, false));
                    if row.kind != *required {
                        continue;
                    }
                }
                if row.kind == *required
                    && let Some(f) = current.get(&row.pgen)
                    && let Some(e) = frames.get_mut(&(row.pgen, *f))
                {
                    e.1 = true;
                }
            }
            checked = frames.len() as u64;
            let mut missing: Vec<i64> = frames
                .values()
                .filter(|(_, seen)| !seen)
                .map(|(seq, _)| *seq)
                .collect();
            missing.sort_unstable();
            for seq in missing {
                failed = true;
                out.counter(seq);
            }
        }
        Assertion::RoundTrip {
            write_kind,
            read_kind,
            key_field,
            value_field,
            ..
        } => {
            let mut last: HashMap<String, Value> = HashMap::new();
            for row in load(store, &[write_kind.as_str(), read_kind.as_str()])? {
                let Some(key) = text(&row, key_field).or_else(|| corr_of(store, row.seq)) else {
                    continue;
                };
                let Some(value) = row.payload.get(value_field).cloned() else {
                    continue;
                };
                if row.kind == *write_kind {
                    last.insert(key, value);
                } else if let Some(written) = last.get(&key) {
                    checked += 1;
                    if *written != value {
                        failed = true;
                        out.counter(row.seq);
                    }
                }
            }
        }
        // The first-generation assertions are evaluated in `query::check`.
        _ => {}
    }
    out.result.checked = checked;
    out.result.verdict = if failed {
        Verdict::Fail
    } else if checked == 0 {
        out.result.reason = Some(if unknown_cases > 0 {
            format!("{unknown_cases} case(s) lack the role field")
        } else {
            "no eligible cases".into()
        });
        Verdict::Unknown
    } else if unknown_cases > 0 {
        out.result.reason = Some(format!("{unknown_cases} case(s) lack the role field"));
        Verdict::Unknown
    } else {
        Verdict::Pass
    };
    Ok(())
}

fn corr_of(store: &Store, seq: i64) -> Option<String> {
    store
        .conn()
        .query_row("SELECT corr FROM events WHERE seq=?1", params![seq], |r| {
            r.get(0)
        })
        .ok()
        .flatten()
}

/// Evaluate and persist: the assertion spec and the result are stored (a writer).
pub fn run(store: &mut Store, assertion: &Assertion) -> Result<CheckResult> {
    let result = crate::query::check(store, assertion)?;
    let label = assertion.label();
    let (name, rev) = label.rsplit_once('/').unwrap_or((&label, "1"));
    let tx = store.conn_mut().transaction()?;
    tx.execute(
        "INSERT OR REPLACE INTO assertions(name,rev,spec) VALUES(?1,?2,?3)",
        params![
            name,
            rev.parse::<i64>().unwrap_or(1),
            serde_json::to_string(assertion)?
        ],
    )?;
    tx.execute(
        "INSERT INTO check_results(assertion,revision,verdict,checked,counterexamples,coverage,reason) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            result.assertion,
            result.revision as i64,
            serde_json::to_value(result.verdict)?.as_str().unwrap_or("unknown"),
            result.checked as i64,
            serde_json::to_string(&result.counterexamples)?,
            result.coverage,
            result.reason
        ],
    )?;
    tx.commit()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::check;
    use crate::store_tests::{ev, records};
    use serde_json::json;

    fn load_events(events: Vec<crate::model::Event>) -> Store {
        let mut store = Store::memory("c").unwrap();
        store.ingest("s", 0, &records(events)).unwrap();
        store
    }

    fn verdict(store: &Store, a: Assertion) -> CheckResult {
        check(store, &a).unwrap()
    }

    #[test]
    fn ordered_transitions() {
        let order = |kinds: &[&str]| Assertion::OrderedTransitions {
            name: "o".into(),
            rev: 1,
            kinds: kinds.iter().map(|s| s.to_string()).collect(),
            key_field: "corr".into(),
        };
        let good = load_events(vec![
            ev("app.open", 0, 1, json!({"corr": "a"}), |_| {}),
            ev("app.use", 1, 1, json!({"corr": "a"}), |_| {}),
            ev("app.close", 2, 1, json!({"corr": "a"}), |_| {}),
        ]);
        assert_eq!(
            verdict(&good, order(&["app.open", "app.use", "app.close"])).verdict,
            Verdict::Pass
        );
        let bad = load_events(vec![
            ev("app.use", 0, 1, json!({"corr": "a"}), |_| {}),
            ev("app.open", 1, 1, json!({"corr": "a"}), |_| {}),
        ]);
        let r = verdict(&bad, order(&["app.open", "app.use", "app.close"]));
        assert_eq!(r.verdict, Verdict::Fail);
        assert_eq!(r.counterexamples, vec!["ev_c_2"]);
        let none = load_events(vec![ev("app.x", 0, 1, json!({}), |_| {})]);
        assert_eq!(
            verdict(&none, order(&["app.open", "app.use"])).verdict,
            Verdict::Unknown
        );
    }

    #[test]
    fn required_and_forbidden_transitions() {
        let store = load_events(vec![
            ev("app.lock", 0, 1, json!({"corr": "a"}), |_| {}),
            ev("app.unlock", 1, 1, json!({"corr": "a"}), |_| {}),
            ev("app.lock", 2, 1, json!({"corr": "b"}), |_| {}),
        ]);
        let req = verdict(
            &store,
            Assertion::RequiredTransition {
                name: "r".into(),
                rev: 1,
                from: "app.lock".into(),
                to: "app.unlock".into(),
                key_field: "corr".into(),
            },
        );
        assert_eq!(
            (req.verdict, req.checked, req.counterexamples),
            (Verdict::Fail, 2, vec!["ev_c_3".to_string()])
        );
        let forb = verdict(
            &store,
            Assertion::ForbiddenTransition {
                name: "f".into(),
                rev: 1,
                from: "app.lock".into(),
                to: "app.unlock".into(),
                key_field: "corr".into(),
            },
        );
        assert_eq!(forb.verdict, Verdict::Fail);
        assert_eq!(forb.counterexamples, vec!["ev_c_2"]);
        let ok = verdict(
            &store,
            Assertion::ForbiddenTransition {
                name: "f".into(),
                rev: 1,
                from: "app.unlock".into(),
                to: "app.lock".into(),
                key_field: "corr".into(),
            },
        );
        assert_eq!(ok.verdict, Verdict::Pass);
    }

    #[test]
    fn only_on_role() {
        let a = |kind: &str| Assertion::OnlyOnRole {
            name: "role".into(),
            rev: 1,
            kind: kind.into(),
            role: "server".into(),
            role_field: "role".into(),
        };
        let store = load_events(vec![
            ev("app.spawn", 0, 1, json!({"role": "server"}), |_| {}),
            ev("app.spawn", 1, 1, json!({"role": "client"}), |_| {}),
            ev("app.grant", 2, 1, json!({"role": "server"}), |_| {}),
            ev("app.other", 3, 1, json!({}), |_| {}),
        ]);
        assert_eq!(verdict(&store, a("app.spawn")).verdict, Verdict::Fail);
        assert_eq!(verdict(&store, a("app.grant")).verdict, Verdict::Pass);
        // No role recorded at all: unknown, not pass.
        assert_eq!(verdict(&store, a("app.other")).verdict, Verdict::Unknown);
    }

    fn frame(seq: u64, n: i64) -> crate::model::Event {
        ev("core.marker", seq, 1, json!({"frame": n}), |_| {})
    }

    fn w(seq: u64, key: &str) -> crate::model::Event {
        ev(
            "core.state.write",
            seq,
            1,
            json!({"object": 1, "key": key}),
            |_| {},
        )
    }

    fn r(seq: u64, key: &str) -> crate::model::Event {
        ev(
            "core.state.read",
            seq,
            1,
            json!({"object": 1, "key": key}),
            |_| {},
        )
    }

    #[test]
    fn write_precedes_read_in_frame() {
        let a = Assertion::WritePrecedesReadInFrame {
            name: "wr".into(),
            rev: 1,
        };
        let good = load_events(vec![
            frame(0, 1),
            w(1, "a"),
            r(2, "a"),
            frame(3, 2),
            w(4, "a"),
            r(5, "a"),
        ]);
        let v = verdict(&good, a.clone());
        assert_eq!((v.verdict, v.checked), (Verdict::Pass, 2));
        let bad = load_events(vec![frame(0, 1), w(1, "a"), frame(2, 2), r(3, "a")]);
        let v = verdict(&bad, a);
        assert_eq!(v.verdict, Verdict::Fail);
        assert_eq!(v.counterexamples, vec!["ev_c_4"]);
    }

    #[test]
    fn at_most_once_per_frame_and_no_frame_without() {
        let once = Assertion::AtMostOncePerFrame {
            name: "once".into(),
            rev: 1,
            kind: "app.draw".into(),
        };
        let draw = |seq| ev("app.draw", seq, 1, json!({}), |_| {});
        let store = load_events(vec![
            frame(0, 1),
            draw(1),
            frame(2, 2),
            draw(3),
            draw(4),
            frame(5, 3),
        ]);
        let v = verdict(&store, once);
        assert_eq!(
            (v.verdict, v.counterexamples),
            (Verdict::Fail, vec!["ev_c_5".to_string()])
        );
        let need = Assertion::NoFrameWithout {
            name: "e".into(),
            rev: 1,
            required: "app.draw".into(),
        };
        let v = verdict(&store, need);
        assert_eq!(v.verdict, Verdict::Fail);
        assert_eq!(v.checked, 3);
        assert_eq!(v.counterexamples, vec!["ev_c_6"]);
        let full = load_events(vec![frame(0, 1), draw(1), frame(2, 2), draw(3)]);
        let need = Assertion::NoFrameWithout {
            name: "e".into(),
            rev: 1,
            required: "app.draw".into(),
        };
        assert_eq!(verdict(&full, need).verdict, Verdict::Pass);
    }

    #[test]
    fn round_trip() {
        let rt = Assertion::RoundTrip {
            name: "rt".into(),
            rev: 1,
            write_kind: "app.save".into(),
            read_kind: "app.load".into(),
            key_field: "slot".into(),
            value_field: "value".into(),
        };
        let store = load_events(vec![
            ev("app.save", 0, 1, json!({"slot": 1, "value": 10}), |_| {}),
            ev("app.save", 1, 1, json!({"slot": 2, "value": 20}), |_| {}),
            ev("app.load", 2, 1, json!({"slot": 1, "value": 10}), |_| {}),
            ev("app.load", 3, 1, json!({"slot": 2, "value": 0}), |_| {}),
        ]);
        let v = verdict(&store, rt);
        assert_eq!(
            (v.verdict, v.checked, v.counterexamples),
            (Verdict::Fail, 2, vec!["ev_c_4".to_string()])
        );
    }

    #[test]
    fn a_gap_makes_a_pass_unknown_for_the_new_checks_too() {
        let store = load_events(vec![
            frame(0, 1),
            ev("app.draw", 1, 1, json!({}), |_| {}),
            ev(
                "core.capture.gap",
                2,
                1,
                json!({"reason": "ring-overflow", "dropped": 4, "out_of_band": true}),
                |_| {},
            ),
        ]);
        let v = verdict(
            &store,
            Assertion::NoFrameWithout {
                name: "e".into(),
                rev: 1,
                required: "app.draw".into(),
            },
        );
        assert_eq!(v.verdict, Verdict::Unknown);
    }

    #[test]
    fn run_persists_assertion_and_result_and_specs_round_trip_json() {
        let mut store = load_events(vec![
            ev("app.save", 0, 1, json!({"slot": 1, "value": 10}), |_| {}),
            ev("app.load", 1, 1, json!({"slot": 1, "value": 10}), |_| {}),
        ]);
        let spec: Assertion = serde_json::from_value(json!({
            "type": "round_trip", "name": "rt", "write_kind": "app.save", "read_kind": "app.load", "key_field": "slot"
        }))
        .unwrap();
        let r = run(&mut store, &spec).unwrap();
        assert_eq!(r.verdict, Verdict::Pass);
        let n: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM check_results WHERE verdict='pass'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        let spec_back: String = store
            .conn()
            .query_row("SELECT spec FROM assertions WHERE name='rt'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(spec_back.contains("round_trip"));
    }
}
