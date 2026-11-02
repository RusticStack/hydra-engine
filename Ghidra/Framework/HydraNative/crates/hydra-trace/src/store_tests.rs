//! Tests of generation resolution, ingest-time symbolization, the retention budget and the
//! clock and coverage tables.

use crate::model::Event;
use crate::query;
use crate::raw::{self, Chain};
use crate::store::{Budget, Options, Store, rebuild_with};
use crate::symbolize::{self, FunctionRange, ModuleTable, TableSymbolizer};
use crate::synth::{self, Recipe};
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub(crate) fn ev(
    kind: &str,
    seq: u64,
    pid: u32,
    payload: Value,
    tweak: impl FnOnce(&mut Event),
) -> Event {
    let mut e = Event {
        kind: kind.into(),
        source_id: "s".into(),
        source_seq: seq,
        producer_gen: 1,
        clock_domain: "qpc".into(),
        t_mono_ns: 100 + seq,
        t_wall_ns: None,
        process_id: Some(pid),
        thread_id: Some(1),
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
    tweak(&mut e);
    e
}

pub(crate) fn records(events: Vec<Event>) -> Vec<Map<String, Value>> {
    let mut chain = Chain::new("s");
    let bytes: Vec<u8> = events
        .iter()
        .flat_map(|e| chain.push(e.to_record()).unwrap())
        .collect();
    raw::scan(&bytes, "s").records
}

fn one(store: &Store, sql: &str) -> i64 {
    store.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn reused_pid_module_and_object_get_new_generations() {
    let mut store = Store::memory("g").unwrap();
    for s in synth::generate(Recipe::Reuse, 1, 10) {
        let scan = raw::scan(&s.bytes, &s.id);
        store.ingest(&s.id, 0, &scan.records).unwrap();
    }
    assert_eq!(one(&store, "SELECT COUNT(*) FROM processes WHERE gen>0"), 2);
    assert_eq!(
        one(
            &store,
            "SELECT COUNT(DISTINCT process_gen) FROM events WHERE process_gen>0"
        ),
        2
    );
    assert_eq!(one(&store, "SELECT COUNT(*) FROM module_instances"), 2);
    assert_eq!(one(&store, "SELECT COUNT(*) FROM objects WHERE gen>0"), 2);
    // The same handle number in two process generations is two different resources.
    assert_eq!(
        one(
            &store,
            "SELECT COUNT(DISTINCT process_gen) FROM events WHERE kind='core.resource.open'"
        ),
        2
    );
}

#[test]
fn an_unobserved_start_is_unresolved_not_merged() {
    let mut store = Store::memory("g").unwrap();
    let records = records(vec![
        ev(
            "core.state.write",
            0,
            7,
            json!({"object": 16, "key": "hp"}),
            |_| {},
        ),
        ev("core.process.start", 1, 7, json!({}), |_| {}),
        ev(
            "core.state.write",
            2,
            7,
            json!({"object": 16, "key": "hp"}),
            |_| {},
        ),
    ]);
    store.ingest("s", 0, &records).unwrap();
    let gens: Vec<i64> = store
        .conn()
        .prepare("SELECT process_gen FROM events ORDER BY seq")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(gens, vec![0, 1, 1]);
    assert_eq!(
        one(
            &store,
            "SELECT COUNT(*) FROM processes WHERE gen=0 AND resolved=0"
        ),
        1
    );
    let keys: Vec<String> = store
        .conn()
        .prepare("SELECT state_key FROM events WHERE kind='core.state.write' ORDER BY seq")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_ne!(keys[0], keys[1]);
}

fn symbolizing_store() -> (Store, Vec<Map<String, Value>>) {
    let events = vec![
        ev("core.process.start", 0, 7, json!({}), |_| {}),
        ev(
            "core.module.load",
            1,
            7,
            json!({"name": "m.dll", "base": 0x1000, "size": 0x1000}),
            |_| {},
        ),
        ev("app.a", 2, 7, json!({}), |e| e.va = Some(0x1150)),
        ev("app.a", 3, 7, json!({}), |e| e.va = Some(0x1f00)),
        ev("app.a", 4, 7, json!({}), |e| {
            e.callstack = vec![0x9000_0000]
        }),
        ev("app.a", 5, 7, json!({}), |_| {}),
        ev("app.a", 6, 7, json!({}), |e| e.va = Some(0x1800)),
    ];
    let mut store = Store::memory("sym").unwrap();
    store
        .set_options(Options {
            symbolizer: Some(Arc::new(foo_table(0x900))),
            symbol_revision: "prog@1".into(),
            budget: Budget::default(),
        })
        .unwrap();
    (store, records(events))
}

fn foo_table(code_end: u64) -> TableSymbolizer {
    let mut table = TableSymbolizer::default();
    table.modules.insert(
        "m.dll".into(),
        ModuleTable {
            code: vec![(0, code_end)],
            functions: vec![FunctionRange {
                start: 0x100,
                end: 0x200,
                name: "Foo".into(),
                type_name: None,
            }],
        },
    );
    table
}

#[test]
fn ingest_symbolizes_and_counts_each_reason() {
    let (mut store, records) = symbolizing_store();
    store.ingest("s", 0, &records).unwrap();
    let c = symbolize::counts(&store, None).unwrap().unwrap();
    // seq 1 start and 2 load carry no site and the last-but-one has none either: no-stack.
    // 0x1150 resolves to Foo; 0x1f00 and 0x1800 are beyond the code range; the stack frame
    // 0x9000_0000 lies in no module.
    assert_eq!(c.total, 7);
    assert_eq!(c.symbolized, 1);
    assert_eq!(c.not_code, 1);
    assert_eq!(c.module_unknown, 1);
    assert_eq!(c.no_stack, 3);
    assert_eq!(c.no_symbol, 1);
    assert_eq!(c.symbol_revision, "prog@1");
}

#[test]
fn resymbolization_is_a_new_revision_and_leaves_the_old_one() {
    let (mut store, records) = symbolizing_store();
    store.ingest("s", 0, &records).unwrap();
    let before = store.digest().unwrap();
    let mut table = TableSymbolizer::default();
    table.modules.insert(
        "m.dll".into(),
        ModuleTable {
            code: vec![],
            functions: vec![FunctionRange {
                start: 0x700,
                end: 0x900,
                name: "Bar".into(),
                type_name: None,
            }],
        },
    );
    let rev = symbolize::resymbolize(&mut store, &table, "prog@2").unwrap();
    let old = symbolize::counts(&store, Some(1)).unwrap().unwrap();
    let new = symbolize::counts(&store, Some(rev)).unwrap().unwrap();
    assert_eq!(old.symbolized, 1);
    assert_eq!(new.symbolized, 1);
    assert_eq!(new.no_symbol, 2);
    assert_eq!(new.symbol_revision, "prog@2");
    assert_ne!(before, store.digest().unwrap());
    // The original observation is untouched.
    assert_eq!(one(&store, "SELECT va FROM events WHERE seq=3"), 0x1150);
}

#[test]
fn ingest_time_and_offline_symbolization_agree() {
    let (mut store, records) = symbolizing_store();
    store.ingest("s", 0, &records).unwrap();
    let rev = symbolize::resymbolize(&mut store, &foo_table(0x900), "prog@1").unwrap();
    let a = symbolize::counts(&store, Some(1)).unwrap().unwrap();
    let mut b = symbolize::counts(&store, Some(rev)).unwrap().unwrap();
    b.interp = a.interp;
    assert_eq!(a, b);
}

#[test]
fn budget_stops_recording_with_a_gap_and_a_rebuild_agrees() {
    let segments = synth::generate(Recipe::Baseline, 3, 200);
    let scan = raw::scan(&segments[0].bytes, &segments[0].id);
    let options = Options {
        budget: Budget {
            max_events: Some(50),
            max_bytes: None,
        },
        ..Options::default()
    };
    let mut store = Store::memory("b").unwrap();
    store.set_options(options.clone()).unwrap();
    let mut dropped = 0;
    for (i, chunk) in scan.records.chunks(60).enumerate() {
        dropped += store
            .ingest("src_a", (i * 60) as u64, chunk)
            .unwrap()
            .dropped_budget;
    }
    assert!(dropped > 100);
    assert!(store.stopped());
    assert_eq!(
        one(
            &store,
            "SELECT COUNT(*) FROM events WHERE kind='core.capture.gap'"
        ),
        1
    );
    assert_eq!(
        one(&store, "SELECT dropped FROM gaps WHERE reason='budget'") as u64,
        dropped
    );
    let rebuilt = rebuild_with(
        "b",
        &[("src_a".into(), segments[0].bytes.clone())],
        &store.batches().unwrap(),
        &options,
    )
    .unwrap();
    assert_eq!(rebuilt.digest().unwrap(), store.digest().unwrap());
    // Budget gaps make absence unknown for checks and diffs.
    assert!(query::lossy_gap_count(&store).unwrap() >= 1);
}

#[test]
fn clock_domains_and_coverage_intervals_are_recorded() {
    let mut store = Store::memory("c").unwrap();
    let records = records(vec![
        ev(
            "core.capture.source",
            0,
            7,
            json!({"state": "observing", "clock": {"unit": "qpc-10mhz", "resolution_ns": 100, "offset_ns": 5, "uncertainty_ns": 200, "to": "wall"}}),
            |_| {},
        ),
        ev("app.a", 1, 7, json!({}), |_| {}),
        ev("app.a", 2, 7, json!({}), |_| {}),
        ev(
            "core.capture.gap",
            3,
            7,
            json!({"reason": "ring-overflow", "dropped": 3, "out_of_band": true}),
            |_| {},
        ),
        ev("app.a", 4, 7, json!({}), |_| {}),
    ]);
    store.ingest("s", 0, &records).unwrap();
    let (cal, res): (i64, i64) = store
        .conn()
        .query_row(
            "SELECT calibrated,resolution_ns FROM clock_domains WHERE name='qpc'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((cal, res), (1, 100));
    let states: Vec<String> = store
        .conn()
        .prepare("SELECT state FROM coverage_intervals ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(states, vec!["observing", "gap", "observing"]);
}
