//! Typed relations between events (TRACE-1 section 9). Edges are directed cause to effect and
//! built only from evidence: correlation ids, observed call and return, buffer ids, async
//! handoff tokens and state keys. Timestamps alone never create an edge; a `temporal-only`
//! relation exists only when asked for and says exactly that.

use crate::store::{Result, Store};
use rusqlite::params;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

pub const RELATIONS: &[&str] = &[
    "call-return",
    "request-completion",
    "created-by",
    "buffer-transform",
    "field-write",
    "async-handoff",
    "observed-call",
    "temporal-only",
];

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Relation {
    pub relation: String,
    /// The cause (earlier in the dependency, not necessarily in time).
    pub from_seq: i64,
    /// The effect; `None` for an unresolved boundary attached to `from_seq`.
    pub to_seq: Option<i64>,
    pub basis: Vec<String>,
    /// `supported`, `inferred` or `unresolved`.
    pub status: String,
    pub unresolved: Vec<String>,
}

struct Ev {
    seq: i64,
    kind: String,
    corr: Option<String>,
    clock: String,
    t: i64,
    pgen: i64,
    thread: i64,
    tgen: i64,
    state_key: Option<String>,
    payload: serde_json::Map<String, Value>,
}

fn completion_like(kind: &str) -> bool {
    matches!(
        kind.rsplit('.').next().unwrap_or(""),
        "completion" | "response" | "reply" | "done" | "complete" | "result"
    )
}

fn rel(
    relation: &str,
    from: i64,
    to: Option<i64>,
    basis: &[&str],
    status: &str,
    unresolved: &[&str],
) -> Relation {
    Relation {
        relation: relation.into(),
        from_seq: from,
        to_seq: to,
        basis: basis.iter().map(|s| (*s).to_string()).collect(),
        status: status.into(),
        unresolved: unresolved.iter().map(|s| (*s).to_string()).collect(),
    }
}

fn load_candidates(store: &Store) -> Result<Vec<Ev>> {
    let mut stmt = store.conn().prepare(
        "SELECT seq,kind,corr,clock_domain,t_mono_ns,COALESCE(process_gen,0),COALESCE(thread_id,0),COALESCE(thread_gen,0),state_key,payload
         FROM events
         WHERE corr IS NOT NULL
            OR kind IN ('core.function.enter','core.function.exit','core.state.write','core.state.read')
            OR payload LIKE '%\"handoff\"%' OR payload LIKE '%\"created_by\"%'
            OR payload LIKE '%\"produces\"%' OR payload LIKE '%\"consumes\"%'
         ORDER BY seq",
    )?;
    let rows = stmt.query_map([], |r| {
        let payload: String = r.get(9)?;
        Ok(Ev {
            seq: r.get(0)?,
            kind: r.get(1)?,
            corr: r.get(2)?,
            clock: r.get(3)?,
            t: r.get(4)?,
            pgen: r.get(5)?,
            thread: r.get(6)?,
            tgen: r.get(7)?,
            state_key: r.get(8)?,
            payload: serde_json::from_str::<Value>(&payload)
                .ok()
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default(),
        })
    })?;
    rows.collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}

/// Compute every relation from the events of `store`. Deterministic: sorted by
/// `(from_seq, to_seq, relation)`. `include_temporal` adds `temporal-only` edges between
/// consecutive events of one thread, the only edges built from order alone.
pub fn compute(store: &Store, include_temporal: bool) -> Result<Vec<Relation>> {
    let events = load_candidates(store)?;
    let mut out: Vec<Relation> = Vec::new();

    // request-completion by correlation id. The roles decide the pairing, never arrival order: the
    // producers of a request and of its completion are different threads whose batches reach the
    // collector in any order (TRACE-1 section 7). Within a role the clock decides (FIFO).
    let mut by_corr: BTreeMap<&str, Vec<&Ev>> = BTreeMap::new();
    for e in &events {
        if let Some(c) = &e.corr {
            by_corr.entry(c).or_default().push(e);
        }
    }
    for group in by_corr.values() {
        let mut requests: Vec<&Ev> = Vec::new();
        let mut stages: Vec<&Ev> = Vec::new();
        let mut completions: Vec<&Ev> = Vec::new();
        for e in group {
            if e.payload.get("stage").is_some() {
                stages.push(e);
            } else if completion_like(&e.kind) {
                completions.push(e);
            } else {
                requests.push(e);
            }
        }
        let by_clock = |v: &mut Vec<&Ev>| {
            v.sort_by(|a, b| (&a.clock, a.t, a.seq).cmp(&(&b.clock, b.t, b.seq)))
        };
        by_clock(&mut requests);
        by_clock(&mut stages);
        by_clock(&mut completions);
        for (i, done) in completions.iter().enumerate() {
            match requests.get(i) {
                Some(req) if requests.len() - i == 1 => out.push(rel(
                    "request-completion",
                    req.seq,
                    Some(done.seq),
                    &["corr"],
                    "supported",
                    &[],
                )),
                Some(req) => out.push(rel(
                    "request-completion",
                    req.seq,
                    Some(done.seq),
                    &["corr", "fifo-order"],
                    "inferred",
                    &["ambiguous-pairing"],
                )),
                None => out.push(rel(
                    "request-completion",
                    done.seq,
                    None,
                    &["corr"],
                    "unresolved",
                    &["missing-request"],
                )),
            }
        }
        for req in requests.iter().skip(completions.len()) {
            out.push(rel(
                "request-completion",
                req.seq,
                None,
                &["corr"],
                "unresolved",
                &["missing-completion"],
            ));
        }
        // The work between them: each stage follows the previous stage (or the request) of the id.
        let mut previous = requests.first().map(|r| r.seq);
        let sure = requests.len() <= 1;
        for stage in &stages {
            match previous {
                Some(from) => out.push(rel(
                    "request-completion",
                    from,
                    Some(stage.seq),
                    &["corr", "stage"],
                    if sure { "supported" } else { "inferred" },
                    if sure { &[] } else { &["ambiguous-pairing"] },
                )),
                None => out.push(rel(
                    "request-completion",
                    stage.seq,
                    None,
                    &["corr", "stage"],
                    "unresolved",
                    &["missing-request"],
                )),
            }
            previous = Some(stage.seq);
        }
        if let (Some(last), Some(done)) = (stages.last(), completions.first()) {
            out.push(rel(
                "request-completion",
                last.seq,
                Some(done.seq),
                &["corr", "stage"],
                if sure { "supported" } else { "inferred" },
                if sure { &[] } else { &["ambiguous-pairing"] },
            ));
        }
    }

    // call-return and observed-call per thread generation.
    let mut stacks: HashMap<(i64, i64, i64), Vec<&Ev>> = HashMap::new();
    let name_of = |e: &Ev| {
        e.payload
            .get("function")
            .map(|v| v.to_string())
            .unwrap_or_default()
    };
    for e in &events {
        let key = (e.pgen, e.thread, e.tgen);
        match e.kind.as_str() {
            "core.function.enter" => {
                let stack = stacks.entry(key).or_default();
                if let Some(parent) = stack.last() {
                    out.push(rel(
                        "observed-call",
                        parent.seq,
                        Some(e.seq),
                        &["call-stack"],
                        "supported",
                        &[],
                    ));
                }
                stack.push(e);
            }
            "core.function.exit" => {
                let stack = stacks.entry(key).or_default();
                let wanted = name_of(e);
                if let Some(pos) = stack.iter().rposition(|c| name_of(c) == wanted) {
                    let unwound = stack.len() - 1 - pos;
                    let enter = stack[pos].seq;
                    // Frames above the match never saw their exit: unresolved boundaries.
                    for lost in stack.drain(pos..).skip(1) {
                        out.push(rel(
                            "call-return",
                            lost.seq,
                            None,
                            &["call-stack"],
                            "unresolved",
                            &["missing-exit"],
                        ));
                    }
                    if unwound == 0 {
                        out.push(rel(
                            "call-return",
                            enter,
                            Some(e.seq),
                            &["call-stack", "function"],
                            "supported",
                            &[],
                        ));
                    } else {
                        out.push(rel(
                            "call-return",
                            enter,
                            Some(e.seq),
                            &["call-stack", "function"],
                            "inferred",
                            &["frames-unwound"],
                        ));
                    }
                } else {
                    out.push(rel(
                        "call-return",
                        e.seq,
                        None,
                        &["function"],
                        "unresolved",
                        &["missing-enter"],
                    ));
                }
            }
            _ => {}
        }
    }
    let mut open: Vec<&Ev> = stacks.into_values().flatten().collect();
    open.sort_by_key(|e| e.seq);
    for e in open {
        out.push(rel(
            "call-return",
            e.seq,
            None,
            &["call-stack"],
            "unresolved",
            &["missing-exit"],
        ));
    }

    // async handoff by token, across threads.
    let mut by_token: BTreeMap<String, Vec<&Ev>> = BTreeMap::new();
    for e in &events {
        if let Some(t) = e.payload.get("handoff") {
            by_token.entry(t.to_string()).or_default().push(e);
        }
    }
    for group in by_token.values_mut() {
        // The sender is the side whose clock says so, not the batch that reached the collector
        // first. Events of different clock domains cannot be ordered: the edge says so.
        group.sort_by(|a, b| (&a.clock, a.t, a.seq).cmp(&(&b.clock, b.t, b.seq)));
        for pair in group.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            if (a.pgen, a.thread, a.tgen) != (b.pgen, b.thread, b.tgen) {
                let same_clock = a.clock == b.clock;
                out.push(rel(
                    "async-handoff",
                    a.seq,
                    Some(b.seq),
                    &["handoff-token"],
                    if same_clock { "supported" } else { "inferred" },
                    if same_clock {
                        &[]
                    } else {
                        &["clock-uncalibrated"]
                    },
                ));
            }
        }
        if group.len() == 1 {
            out.push(rel(
                "async-handoff",
                group[0].seq,
                None,
                &["handoff-token"],
                "unresolved",
                &["handoff-unmatched"],
            ));
        }
    }

    // created-by: the creator is named by a correlation id.
    let first_with_corr: HashMap<&str, i64> = {
        let mut m = HashMap::new();
        for e in &events {
            if let Some(c) = &e.corr {
                m.entry(c.as_str()).or_insert(e.seq);
            }
        }
        m
    };
    for e in &events {
        if let Some(creator) = e.payload.get("created_by").and_then(Value::as_str) {
            match first_with_corr.get(creator) {
                Some(&c) => out.push(rel(
                    "created-by",
                    c,
                    Some(e.seq),
                    &["created_by"],
                    "supported",
                    &[],
                )),
                None => out.push(rel(
                    "created-by",
                    e.seq,
                    None,
                    &["created_by"],
                    "unresolved",
                    &["creator-unobserved"],
                )),
            }
        }
    }

    // buffer-transform: a buffer id produced by one event and consumed by later ones.
    let mut producer: HashMap<String, i64> = HashMap::new();
    for e in &events {
        if let Some(c) = e.payload.get("consumes") {
            match producer.get(&c.to_string()) {
                Some(&p) => out.push(rel(
                    "buffer-transform",
                    p,
                    Some(e.seq),
                    &["buffer-id"],
                    "supported",
                    &[],
                )),
                None => out.push(rel(
                    "buffer-transform",
                    e.seq,
                    None,
                    &["buffer-id"],
                    "unresolved",
                    &["producer-unobserved"],
                )),
            }
        }
        if let Some(p) = e.payload.get("produces") {
            producer.insert(p.to_string(), e.seq);
        }
    }

    // field-write: a read observes the last write to the same state key.
    let mut last_write: HashMap<&str, &Ev> = HashMap::new();
    for e in &events {
        let Some(key) = e.state_key.as_deref() else {
            continue;
        };
        match e.kind.as_str() {
            "core.state.write" => {
                last_write.insert(key, e);
            }
            "core.state.read" => {
                if let Some(w) = last_write.get(key) {
                    let (wv, rv) = (w.payload.get("new"), e.payload.get("value"));
                    let (status, unresolved): (&str, &[&str]) = match (wv, rv) {
                        (Some(a), Some(b)) if a == b => ("supported", &[]),
                        (Some(_), Some(_)) => ("unresolved", &["value-differs-from-last-write"]),
                        _ => ("inferred", &[]),
                    };
                    out.push(rel(
                        "field-write",
                        w.seq,
                        Some(e.seq),
                        &["state-key"],
                        status,
                        unresolved,
                    ));
                }
            }
            _ => {}
        }
    }

    if include_temporal {
        let mut last: HashMap<(i64, i64, i64), i64> = HashMap::new();
        for e in &events {
            let key = (e.pgen, e.thread, e.tgen);
            if let Some(prev) = last.insert(key, e.seq) {
                out.push(rel(
                    "temporal-only",
                    prev,
                    Some(e.seq),
                    &["same-thread-order"],
                    "inferred",
                    &["no-causal-evidence"],
                ));
            }
        }
    }

    out.sort_by(|a, b| {
        (a.from_seq, a.to_seq, &a.relation).cmp(&(b.from_seq, b.to_seq, &b.relation))
    });
    Ok(out)
}

/// Write the computed relations (a writer). Replaces the table and records the revision it was
/// computed at, so readers can tell whether the stored edges are current.
pub fn materialize(store: &mut Store) -> Result<usize> {
    let revision = store.revision()?;
    let all = compute(store, false)?;
    let tx = store.conn_mut().transaction()?;
    tx.execute("DELETE FROM relations", [])?;
    {
        let mut ins = tx.prepare_cached(
            "INSERT INTO relations(relation,from_seq,to_seq,basis,status,unresolved) VALUES(?1,?2,?3,?4,?5,?6)",
        )?;
        for r in &all {
            ins.execute(params![
                r.relation,
                r.from_seq,
                r.to_seq,
                serde_json::to_string(&r.basis)?,
                r.status,
                serde_json::to_string(&r.unresolved)?
            ])?;
        }
    }
    tx.execute(
        "INSERT INTO meta(key,value) VALUES('relations_revision',?1) ON CONFLICT(key) DO UPDATE SET value=?1",
        params![revision.to_string()],
    )?;
    tx.commit()?;
    Ok(all.len())
}

/// The relations current at the store's revision: the stored ones when fresh, else computed in
/// memory (a reader cannot write).
pub fn current(store: &Store) -> Result<(Vec<Relation>, &'static str)> {
    let revision = store.revision()?;
    let stored: Option<String> = store
        .conn()
        .query_row(
            "SELECT value FROM meta WHERE key='relations_revision'",
            [],
            |r| r.get(0),
        )
        .ok();
    if stored.as_deref() == Some(revision.to_string().as_str()) {
        let mut stmt = store.conn().prepare(
            "SELECT relation,from_seq,to_seq,basis,status,unresolved FROM relations ORDER BY from_seq,to_seq,relation",
        )?;
        let rows = stmt.query_map([], |r| {
            let basis: String = r.get(3)?;
            let unresolved: String = r.get(5)?;
            Ok(Relation {
                relation: r.get(0)?,
                from_seq: r.get(1)?,
                to_seq: r.get(2)?,
                basis: serde_json::from_str(&basis).unwrap_or_default(),
                status: r.get(4)?,
                unresolved: serde_json::from_str(&unresolved).unwrap_or_default(),
            })
        })?;
        let all: Vec<Relation> = rows.collect::<std::result::Result<_, _>>()?;
        return Ok((all, "materialized"));
    }
    Ok((compute(store, false)?, "computed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw;
    use crate::store_tests::{ev, records};
    use crate::synth::{self, Recipe};
    use serde_json::json;

    fn load(events: Vec<crate::model::Event>) -> Store {
        let mut store = Store::memory("r").unwrap();
        store.ingest("s", 0, &records(events)).unwrap();
        store
    }

    #[test]
    fn interleaved_requests_pair_by_correlation_not_time() {
        let mut store = Store::memory("r").unwrap();
        for s in synth::generate(Recipe::Interleave, 5, 40) {
            let scan = raw::scan(&s.bytes, &s.id);
            store.ingest(&s.id, 0, &scan.records).unwrap();
        }
        let all = compute(&store, false).unwrap();
        let rc: Vec<_> = all
            .iter()
            .filter(|r| r.relation == "request-completion")
            .collect();
        assert_eq!(rc.len(), 20);
        assert!(
            rc.iter()
                .all(|r| r.status == "supported" && r.to_seq.is_some())
        );
        assert!(all.iter().all(|r| r.relation != "temporal-only"));
        // x's request is paired with x's completion even though y's completion came first.
        let corr_of = |seq: i64| -> String {
            store
                .conn()
                .query_row("SELECT corr FROM events WHERE seq=?1", params![seq], |r| {
                    r.get(0)
                })
                .unwrap()
        };
        assert!(
            rc.iter()
                .all(|r| corr_of(r.from_seq) == corr_of(r.to_seq.unwrap()))
        );
    }

    #[test]
    fn call_return_matches_and_reports_unwound_and_missing() {
        let f = |name: &str| json!({ "function": name });
        let store = load(vec![
            ev("core.function.enter", 0, 7, f("a"), |_| {}),
            ev("core.function.enter", 1, 7, f("b"), |_| {}),
            ev("core.function.exit", 2, 7, f("b"), |_| {}),
            ev("core.function.enter", 3, 7, f("c"), |_| {}),
            // c never exits; a's exit unwinds it.
            ev("core.function.exit", 4, 7, f("a"), |_| {}),
            ev("core.function.exit", 5, 7, f("zzz"), |_| {}),
        ]);
        let all = compute(&store, false).unwrap();
        let get = |relation: &str, status: &str| {
            all.iter()
                .filter(|r| r.relation == relation && r.status == status)
                .count()
        };
        assert_eq!(get("observed-call", "supported"), 2);
        assert_eq!(get("call-return", "supported"), 1);
        assert_eq!(get("call-return", "inferred"), 1);
        // c's missing exit and the exit with no enter.
        assert_eq!(get("call-return", "unresolved"), 2);
    }

    #[test]
    fn a_completion_without_a_request_and_a_request_without_one_are_unresolved() {
        let store = load(vec![
            ev("app.request", 0, 7, json!({"corr": "a"}), |_| {}),
            ev("app.completion", 1, 7, json!({"corr": "b"}), |_| {}),
        ]);
        let all = compute(&store, false).unwrap();
        let reasons: Vec<_> = all.iter().flat_map(|r| r.unresolved.clone()).collect();
        assert!(reasons.contains(&"missing-completion".to_string()));
        assert!(reasons.contains(&"missing-request".to_string()));
    }

    #[test]
    fn a_completion_that_arrives_before_its_request_still_pairs_and_stages_chain() {
        // The batches of two producers reach the collector in any order: the completion is ingested
        // first, yet it pairs with its own request, and the stages between them chain by id.
        let worker = |e: &mut crate::model::Event| {
            e.source_id = "worker".into();
            e.thread_id = Some(2);
        };
        let mut store = Store::memory("r").unwrap();
        // the worker's batch is committed first; the main thread's request arrives later
        let first = vec![
            ev(
                "app.handle",
                1,
                8,
                json!({"corr": "x", "stage": "handle"}),
                worker,
            ),
            ev(
                "app.result",
                2,
                8,
                json!({"corr": "x", "stage": "store"}),
                worker,
            ),
            ev("app.complete", 3, 8, json!({"corr": "x"}), worker),
        ];
        store.ingest("worker", 0, &records(first)).unwrap();
        let later = vec![
            ev("app.request", 1, 8, json!({"corr": "x"}), |_| {}),
            ev("app.request", 2, 8, json!({"corr": "lost"}), |_| {}),
        ];
        store.ingest("s", 0, &records(later)).unwrap();
        let all = compute(&store, false).unwrap();
        let rc: Vec<_> = all
            .iter()
            .filter(|r| r.relation == "request-completion")
            .collect();
        let seq_of = |kind: &str, corr: &str| -> i64 {
            store
                .conn()
                .query_row(
                    "SELECT seq FROM events WHERE kind=?1 AND corr=?2",
                    params![kind, corr],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let (req, handle, result, done) = (
            seq_of("app.request", "x"),
            seq_of("app.handle", "x"),
            seq_of("app.result", "x"),
            seq_of("app.complete", "x"),
        );
        let has = |from: i64, to: i64| {
            rc.iter()
                .any(|r| r.from_seq == from && r.to_seq == Some(to) && r.status == "supported")
        };
        assert!(has(req, done) && has(req, handle) && has(handle, result) && has(result, done));
        let lost = seq_of("app.request", "lost");
        assert!(rc.iter().any(|r| r.from_seq == lost
            && r.to_seq.is_none()
            && r.unresolved == ["missing-completion"]));
    }

    #[test]
    fn handoff_buffer_creation_and_field_write_edges() {
        let store = load(vec![
            ev(
                "app.post",
                0,
                7,
                json!({"handoff": "t1", "produces": "buf1", "corr": "job"}),
                |e| e.thread_id = Some(1),
            ),
            ev(
                "app.run",
                1,
                7,
                json!({"handoff": "t1", "consumes": "buf1", "created_by": "job"}),
                |e| e.thread_id = Some(2),
            ),
            ev(
                "core.state.write",
                2,
                7,
                json!({"object": 1, "key": "hp", "new": 5}),
                |_| {},
            ),
            ev(
                "core.state.read",
                3,
                7,
                json!({"object": 1, "key": "hp", "value": 5}),
                |_| {},
            ),
            ev(
                "core.state.read",
                4,
                7,
                json!({"object": 1, "key": "hp", "value": 9}),
                |_| {},
            ),
        ]);
        let all = compute(&store, false).unwrap();
        let has = |relation: &str, status: &str| {
            all.iter()
                .any(|r| r.relation == relation && r.status == status)
        };
        assert!(has("async-handoff", "supported"));
        assert!(has("buffer-transform", "supported"));
        assert!(has("created-by", "supported"));
        assert!(has("field-write", "supported"));
        assert!(has("field-write", "unresolved"));
    }

    #[test]
    fn temporal_only_exists_only_when_asked_and_says_so() {
        let store = load(vec![
            ev(
                "core.state.write",
                0,
                7,
                json!({"object": 1, "key": "a"}),
                |_| {},
            ),
            ev(
                "core.state.write",
                1,
                7,
                json!({"object": 1, "key": "b"}),
                |_| {},
            ),
        ]);
        assert!(
            compute(&store, false)
                .unwrap()
                .iter()
                .all(|r| r.relation != "temporal-only")
        );
        let t = compute(&store, true).unwrap();
        let temporal: Vec<_> = t.iter().filter(|r| r.relation == "temporal-only").collect();
        assert_eq!(temporal.len(), 1);
        assert_eq!(temporal[0].unresolved, vec!["no-causal-evidence"]);
    }

    #[test]
    fn materialized_equals_computed_and_is_stale_after_an_append() {
        let mut store = Store::memory("r").unwrap();
        for s in synth::generate(Recipe::Interleave, 5, 40) {
            let scan = raw::scan(&s.bytes, &s.id);
            store.ingest(&s.id, 0, &scan.records).unwrap();
        }
        let computed = compute(&store, false).unwrap();
        materialize(&mut store).unwrap();
        let (stored, how) = current(&store).unwrap();
        assert_eq!(how, "materialized");
        assert_eq!(stored, computed);
        let more = synth::generate(Recipe::Baseline, 1, 5);
        let scan = raw::scan(&more[0].bytes, &more[0].id);
        store.ingest(&more[0].id, 0, &scan.records).unwrap();
        assert_eq!(current(&store).unwrap().1, "computed");
    }
}
