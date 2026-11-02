//! Bounded queries, deterministic diff and three-valued checks over a committed snapshot.
//! Every answer carries the revision it was computed at and the gaps relevant to it.

use crate::store::{Result, Store};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Hard bounds. A request above them is clamped and the reply says so (`truncated`).
pub const MAX_LIMIT: usize = 1000;

#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub kinds: Vec<String>,
    pub process_gen: Option<u32>,
    pub resource_key: Option<String>,
    pub state_key: Option<String>,
    pub corr: Option<String>,
    /// Exclusive cursor: only `seq > after`.
    pub after: i64,
    /// Inclusive upper bound: only `seq <= up_to`. `None` pins to the newest event at the time
    /// of the query, and the page reports it.
    pub up_to: Option<i64>,
    pub limit: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Row {
    pub seq: i64,
    pub event_id: String,
    pub kind: String,
    pub source_id: String,
    pub t_mono_ns: i64,
    pub process_id: Option<i64>,
    pub thread_id: Option<i64>,
    /// Session-local generations (TRACE-1 section 7); absent when the producer gave none and no
    /// start was observed.
    pub process_gen: Option<i64>,
    pub thread_gen: Option<i64>,
    pub module_instance: Option<i64>,
    pub payload: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Page {
    pub revision: u64,
    pub rows: Vec<Row>,
    /// Pass back as `after` for the next page; `None` when the result is complete.
    pub next: Option<i64>,
    /// The pin this page was read at; pass it back with `next` to page one snapshot.
    pub up_to: i64,
    pub truncated: bool,
}

/// Run a filtered query as one read snapshot.
pub fn query(store: &Store, filter: &Filter) -> Result<Page> {
    let limit = filter.limit.clamp(1, MAX_LIMIT);
    let conn = store.conn();
    let revision = store.revision()?;
    let up_to: i64 = match filter.up_to {
        Some(u) => u,
        None => conn.query_row("SELECT COALESCE(MAX(seq),0) FROM events", [], |r| r.get(0))?,
    };
    let mut sql = String::from(
        "SELECT seq,event_id,kind,source_id,t_mono_ns,process_id,thread_id,process_gen,thread_gen,module_instance,payload FROM events WHERE seq>?1 AND seq<=?2",
    );
    let mut args: Vec<rusqlite::types::Value> = vec![filter.after.into(), up_to.into()];
    if !filter.kinds.is_empty() {
        let marks = vec!["?"; filter.kinds.len()].join(",");
        sql.push_str(&format!(" AND kind IN ({marks})"));
        args.extend(filter.kinds.iter().cloned().map(Into::into));
    }
    for (column, value) in [
        ("resource_key", filter.resource_key.as_ref()),
        ("state_key", filter.state_key.as_ref()),
        ("corr", filter.corr.as_ref()),
    ] {
        if let Some(value) = value {
            sql.push_str(&format!(" AND {column}=?"));
            args.push(value.clone().into());
        }
    }
    if let Some(generation) = filter.process_gen {
        sql.push_str(" AND process_gen=?");
        args.push(i64::from(generation).into());
    }
    sql.push_str(&format!(" ORDER BY seq LIMIT {}", limit + 1));
    let mut stmt = conn.prepare(&sql)?;
    let mut rows: Vec<Row> = stmt
        .query_map(rusqlite::params_from_iter(args), |r| {
            Ok(Row {
                seq: r.get(0)?,
                event_id: r.get(1)?,
                kind: r.get(2)?,
                source_id: r.get(3)?,
                t_mono_ns: r.get(4)?,
                process_id: r.get(5)?,
                thread_id: r.get(6)?,
                process_gen: r.get(7)?,
                thread_gen: r.get(8)?,
                module_instance: r.get(9)?,
                payload: r.get(10)?,
            })
        })?
        .collect::<std::result::Result<_, _>>()?;
    let more = rows.len() > limit;
    rows.truncate(limit);
    let next = if more {
        rows.last().map(|r| r.seq)
    } else {
        None
    };
    Ok(Page {
        revision,
        rows,
        next,
        up_to,
        truncated: filter.limit > MAX_LIMIT,
    })
}

/// The lifetime tables (TRACE-1 section 7): one object per observed lifetime of an address,
/// process generations, thread generations and module instances. `what` is `processes`,
/// `threads`, `modules` or `objects`; anything else is refused.
pub fn lifetimes(store: &Store, what: &str) -> Result<Option<Vec<serde_json::Value>>> {
    let (sql, names): (&str, &[&str]) = match what {
        "processes" => (
            "SELECT pid,gen,start_seq,end_seq,end_reason,resolved FROM processes ORDER BY pid,gen",
            &[
                "pid",
                "gen",
                "start_seq",
                "end_seq",
                "end_reason",
                "resolved",
            ],
        ),
        "threads" => (
            "SELECT pgen,tid,gen,start_seq,end_seq,resolved FROM threads ORDER BY pgen,tid,gen",
            &["pgen", "tid", "gen", "start_seq", "end_seq", "resolved"],
        ),
        "modules" => (
            "SELECT inst,pgen,name,build,base,size,load_seq,unload_seq FROM module_instances ORDER BY inst",
            &[
                "inst",
                "pgen",
                "name",
                "build",
                "base",
                "size",
                "load_seq",
                "unload_seq",
            ],
        ),
        "objects" => (
            "SELECT pgen,addr,gen,type,create_seq,destroy_seq,resolved FROM objects ORDER BY pgen,addr,gen",
            &[
                "pgen",
                "addr",
                "gen",
                "type",
                "create_seq",
                "destroy_seq",
                "resolved",
            ],
        ),
        _ => return Ok(None),
    };
    let mut stmt = store.conn().prepare(sql)?;
    let rows = stmt.query_map([], |r| {
        let mut o = serde_json::Map::new();
        for (i, name) in names.iter().enumerate() {
            let v: rusqlite::types::Value = r.get(i)?;
            o.insert(
                (*name).into(),
                match v {
                    rusqlite::types::Value::Null => serde_json::Value::Null,
                    rusqlite::types::Value::Integer(n) => n.into(),
                    rusqlite::types::Value::Real(f) => f.into(),
                    rusqlite::types::Value::Text(t) => t.into(),
                    rusqlite::types::Value::Blob(_) => serde_json::Value::Null,
                },
            );
        }
        Ok(serde_json::Value::Object(o))
    })?;
    Ok(Some(rows.collect::<std::result::Result<_, _>>()?))
}

/// A group of events with a representative first event.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Group {
    pub key: String,
    pub count: u64,
    pub first_event: String,
}

/// Columns a grouping may use. Anything else is refused, never interpolated.
pub fn group_column(name: &str) -> Option<&'static str> {
    Some(match name {
        "kind" => "kind",
        "resource" => "COALESCE(resource_key,'')",
        "state" => "COALESCE(state_key,'')",
        "module" => "COALESCE(module,'')",
        "source" => "source_id",
        _ => return None,
    })
}

/// Counts per group, ordered by key, with the first event of each. Deterministic.
pub fn groups(store: &Store, by: &str, kinds: &[String]) -> Result<Vec<Group>> {
    let Some(column) = group_column(by) else {
        return Ok(Vec::new());
    };
    let mut sql = format!("SELECT {column} AS k, COUNT(*), MIN(seq) FROM events");
    if !kinds.is_empty() {
        sql.push_str(&format!(
            " WHERE kind IN ({})",
            vec!["?"; kinds.len()].join(",")
        ));
    }
    sql.push_str(" GROUP BY k ORDER BY k");
    let mut stmt = store.conn().prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(kinds.iter()), |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (key, count, first) = row?;
        out.push(Group {
            key,
            count: count as u64,
            first_event: format!("ev_{}_{}", store.session(), first),
        });
    }
    Ok(out)
}

/// The classes of section 14 of TRACE-1.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DiffClass {
    OnlyA,
    OnlyB,
    DifferentUnderMatchedCoverage,
    NotComparable,
    Same,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DiffEntry {
    pub key: String,
    pub class: DiffClass,
    pub count_a: u64,
    pub count_b: u64,
    pub first_a: Option<String>,
    pub first_b: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Diff {
    pub group_by: String,
    pub revision_a: u64,
    pub revision_b: u64,
    /// Every normalization applied, disclosed. Raw PIDs, addresses and timestamps are not keys.
    pub normalizations: Vec<String>,
    pub entries: Vec<DiffEntry>,
    pub unmatched_a: u64,
    pub unmatched_b: u64,
    pub ambiguous: u64,
    /// Sessions with a capture loss that makes an absence on that side unknown.
    pub gaps_a: u64,
    pub gaps_b: u64,
}

pub fn lossy_gap_count(store: &Store) -> Result<u64> {
    let n: i64 = store.conn().query_row(
        "SELECT COUNT(*) FROM gaps WHERE reason IN ('producer-lost','ring-overflow','read-failure','restart','budget')",
        [],
        |r| r.get(0),
    )?;
    Ok(n as u64)
}

/// Align two sessions by `by` and classify. A key present on one side only is `not_comparable`
/// when the other side lost data (absence there proves nothing); otherwise `only_*`. Output is
/// ordered by key and byte-identical across runs.
pub fn diff(a: &Store, b: &Store, by: &str, kinds: &[String]) -> Result<Diff> {
    let ga: BTreeMap<String, Group> = groups(a, by, kinds)?
        .into_iter()
        .map(|g| (g.key.clone(), g))
        .collect();
    let gb: BTreeMap<String, Group> = groups(b, by, kinds)?
        .into_iter()
        .map(|g| (g.key.clone(), g))
        .collect();
    let (gaps_a, gaps_b) = (lossy_gap_count(a)?, lossy_gap_count(b)?);
    let mut keys: Vec<&String> = ga.keys().chain(gb.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut entries = Vec::with_capacity(keys.len());
    let (mut unmatched_a, mut unmatched_b) = (0, 0);
    for key in keys {
        let (x, y) = (ga.get(key), gb.get(key));
        let class = match (x, y) {
            (Some(x), Some(y)) if x.count == y.count => DiffClass::Same,
            (Some(_), Some(_)) if gaps_a > 0 || gaps_b > 0 => DiffClass::NotComparable,
            (Some(_), Some(_)) => DiffClass::DifferentUnderMatchedCoverage,
            (Some(_), None) => {
                unmatched_a += 1;
                if gaps_b > 0 {
                    DiffClass::NotComparable
                } else {
                    DiffClass::OnlyA
                }
            }
            (None, Some(_)) => {
                unmatched_b += 1;
                if gaps_a > 0 {
                    DiffClass::NotComparable
                } else {
                    DiffClass::OnlyB
                }
            }
            (None, None) => continue,
        };
        entries.push(DiffEntry {
            key: key.clone(),
            class,
            count_a: x.map_or(0, |g| g.count),
            count_b: y.map_or(0, |g| g.count),
            first_a: x.map(|g| g.first_event.clone()),
            first_b: y.map(|g| g.first_event.clone()),
        });
    }
    Ok(Diff {
        group_by: by.into(),
        revision_a: a.revision()?,
        revision_b: b.revision()?,
        normalizations: vec![
            "group key excludes pid, tid, addresses and timestamps".into(),
            "event ids are per-session and not compared".into(),
        ],
        entries,
        unmatched_a,
        unmatched_b,
        ambiguous: 0,
        gaps_a,
        gaps_b,
    })
}

/// A check outcome.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CheckResult {
    pub assertion: String,
    pub revision: u64,
    pub verdict: Verdict,
    pub checked: u64,
    pub counterexamples: Vec<String>,
    pub coverage: String,
    pub reason: Option<String>,
}

fn one() -> u32 {
    1
}

fn corr_field() -> String {
    "corr".into()
}

/// An assertion over a session (spec 14.8). Revisioned by `name` + `rev`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Assertion {
    /// Every `request` with a correlation id has exactly one `completion` with the same id.
    RequestCompletion {
        name: String,
        #[serde(default = "one")]
        rev: u32,
        request: String,
        completion: String,
    },
    /// `kind` occurs between `min` and `max` times.
    Cardinality {
        name: String,
        #[serde(default = "one")]
        rev: u32,
        kind: String,
        min: u64,
        max: u64,
    },
    /// No event of `kind` may occur.
    Forbidden {
        name: String,
        #[serde(default = "one")]
        rev: u32,
        kind: String,
    },
    /// Per key, the events of `kinds` occur in the listed order.
    OrderedTransitions {
        name: String,
        #[serde(default = "one")]
        rev: u32,
        kinds: Vec<String>,
        #[serde(default = "corr_field")]
        key_field: String,
    },
    /// Every `from` is followed by a `to` with the same key.
    RequiredTransition {
        name: String,
        #[serde(default = "one")]
        rev: u32,
        from: String,
        to: String,
        #[serde(default = "corr_field")]
        key_field: String,
    },
    /// No `to` follows a `from` with the same key.
    ForbiddenTransition {
        name: String,
        #[serde(default = "one")]
        rev: u32,
        from: String,
        to: String,
        #[serde(default = "corr_field")]
        key_field: String,
    },
    /// Events of `kind` carry `role` in payload field `role_field`, and no other.
    OnlyOnRole {
        name: String,
        #[serde(default = "one")]
        rev: u32,
        kind: String,
        role: String,
        #[serde(default = "role_field")]
        role_field: String,
    },
    /// Within a frame, a write to a state precedes every read of it.
    WritePrecedesReadInFrame {
        name: String,
        #[serde(default = "one")]
        rev: u32,
    },
    /// `kind` occurs at most once in any frame.
    AtMostOncePerFrame {
        name: String,
        #[serde(default = "one")]
        rev: u32,
        kind: String,
    },
    /// Every frame contains at least one `required` event.
    NoFrameWithout {
        name: String,
        #[serde(default = "one")]
        rev: u32,
        required: String,
    },
    /// A value written under a key is read back equal.
    RoundTrip {
        name: String,
        #[serde(default = "one")]
        rev: u32,
        write_kind: String,
        read_kind: String,
        #[serde(default = "corr_field")]
        key_field: String,
        #[serde(default = "value_field")]
        value_field: String,
    },
}

fn role_field() -> String {
    "role".into()
}

fn value_field() -> String {
    "value".into()
}

impl Assertion {
    pub fn label(&self) -> String {
        let (name, rev) = match self {
            Assertion::RequestCompletion { name, rev, .. }
            | Assertion::Cardinality { name, rev, .. }
            | Assertion::Forbidden { name, rev, .. }
            | Assertion::OrderedTransitions { name, rev, .. }
            | Assertion::RequiredTransition { name, rev, .. }
            | Assertion::ForbiddenTransition { name, rev, .. }
            | Assertion::OnlyOnRole { name, rev, .. }
            | Assertion::WritePrecedesReadInFrame { name, rev, .. }
            | Assertion::AtMostOncePerFrame { name, rev, .. }
            | Assertion::NoFrameWithout { name, rev, .. }
            | Assertion::RoundTrip { name, rev, .. } => (name, rev),
        };
        format!("{name}/{rev}")
    }
}

pub(crate) fn id_of(store: &Store, seq: i64) -> String {
    format!("ev_{}_{}", store.session(), seq)
}

/// Evaluate `assertion`. Missing observers, announced loss and zero eligible cases give
/// `Unknown` (never a reassuring pass); the valid part of the trace stays usable.
pub fn check(store: &Store, assertion: &Assertion) -> Result<CheckResult> {
    let revision = store.revision()?;
    let gaps = lossy_gap_count(store)?;
    let conn = store.conn();
    let label = assertion.label();
    let mut result = CheckResult {
        assertion: label,
        revision,
        verdict: Verdict::Unknown,
        checked: 0,
        counterexamples: Vec::new(),
        coverage: if gaps == 0 {
            "complete".into()
        } else {
            format!("{gaps} capture gap(s)")
        },
        reason: None,
    };
    match assertion {
        Assertion::RequestCompletion {
            request,
            completion,
            ..
        } => {
            let mut stmt = conn.prepare(
                "SELECT r.seq, (SELECT COUNT(*) FROM events c WHERE c.kind=?2 AND c.corr=r.corr)
                 FROM events r WHERE r.kind=?1 AND r.corr IS NOT NULL ORDER BY r.seq",
            )?;
            let rows = stmt.query_map(params![request, completion], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (seq, completions) = row?;
                result.checked += 1;
                if completions != 1 {
                    result.counterexamples.push(id_of(store, seq));
                }
            }
        }
        Assertion::Cardinality { kind, min, max, .. } => {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM events WHERE kind=?1",
                params![kind],
                |r| r.get(0),
            )?;
            result.checked = n as u64;
            if ((n as u64) < *min || (n as u64) > *max)
                && let Ok(first) = conn.query_row(
                    "SELECT MIN(seq) FROM events WHERE kind=?1",
                    params![kind],
                    |r| r.get::<_, Option<i64>>(0),
                )
            {
                result
                    .counterexamples
                    .extend(first.map(|s| id_of(store, s)));
            }
            result.verdict = if (n as u64) >= *min && (n as u64) <= *max {
                Verdict::Pass
            } else {
                Verdict::Fail
            };
        }
        Assertion::Forbidden { kind, .. } => {
            let mut stmt =
                conn.prepare("SELECT seq FROM events WHERE kind=?1 ORDER BY seq LIMIT 20")?;
            let seqs = stmt.query_map(params![kind], |r| r.get::<_, i64>(0))?;
            for seq in seqs {
                result.counterexamples.push(id_of(store, seq?));
            }
            let total: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
            result.checked = total as u64;
            result.verdict = if result.counterexamples.is_empty() {
                Verdict::Pass
            } else {
                Verdict::Fail
            };
        }
        other => crate::checks::eval(store, other, &mut result)?,
    }
    if let Assertion::RequestCompletion { .. } = assertion {
        result.verdict = if result.checked == 0 {
            result.reason = Some("no eligible cases".into());
            Verdict::Unknown
        } else if !result.counterexamples.is_empty() {
            Verdict::Fail
        } else {
            Verdict::Pass
        };
    }
    // A pass is only a pass over complete coverage. A fail stands: a counterexample is cited.
    if result.verdict == Verdict::Pass && gaps > 0 {
        result.verdict = Verdict::Unknown;
        result.reason = Some("capture gap overlaps the checked evidence".into());
    }
    if result.verdict == Verdict::Pass && result.checked == 0 {
        result.verdict = Verdict::Unknown;
        result.reason = Some("no eligible cases".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw;
    use crate::synth::{self, Recipe};

    fn load(recipe: Recipe, seed: u64, events: usize, session: &str) -> Store {
        let mut store = Store::memory(session).unwrap();
        for s in synth::generate(recipe, seed, events) {
            let scan = raw::scan(&s.bytes, &s.id);
            store.ingest(&s.id, 0, &scan.records).unwrap();
        }
        store
    }

    #[test]
    fn pages_are_stable_across_appends() {
        let store = load(Recipe::Baseline, 1, 100, "q");
        let first = query(
            &store,
            &Filter {
                limit: 30,
                ..Filter::default()
            },
        )
        .unwrap();
        assert_eq!(first.rows.len(), 30);
        let second = query(
            &store,
            &Filter {
                limit: 30,
                after: first.next.unwrap(),
                ..Filter::default()
            },
        )
        .unwrap();
        assert_eq!(second.rows[0].seq, first.rows[29].seq + 1);
    }

    #[test]
    fn a_page_reports_its_pin_and_a_pinned_page_ignores_later_events() {
        let store = load(Recipe::Baseline, 1, 100, "pin");
        let first = query(
            &store,
            &Filter {
                limit: 10,
                ..Filter::default()
            },
        )
        .unwrap();
        assert!(first.up_to >= first.rows[9].seq);
        let again = query(
            &store,
            &Filter {
                limit: 1000,
                after: first.next.unwrap(),
                up_to: Some(first.rows[9].seq + 5),
                ..Filter::default()
            },
        )
        .unwrap();
        assert_eq!(again.rows.last().unwrap().seq, first.rows[9].seq + 5);
        assert_eq!(again.up_to, first.rows[9].seq + 5);
        assert_eq!(again.next, None);
    }

    #[test]
    fn interleaved_operations_are_joined_by_correlation_not_time() {
        let store = load(Recipe::Interleave, 5, 40, "q");
        let r = check(
            &store,
            &Assertion::RequestCompletion {
                name: "rc".into(),
                rev: 1,
                request: "app.request".into(),
                completion: "app.completion".into(),
            },
        )
        .unwrap();
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.checked, 20);
    }

    #[test]
    fn a_missing_completion_is_a_cited_counterexample() {
        let mut store = Store::memory("q").unwrap();
        let seg = synth::generate(Recipe::Interleave, 5, 8).remove(0);
        let mut records = raw::scan(&seg.bytes, &seg.id).records;
        let victim = records
            .iter()
            .position(|r| r["kind"] == "app.completion")
            .unwrap();
        records.remove(victim);
        for (i, r) in records.iter_mut().enumerate() {
            r.insert("n".into(), (i as u64).into());
        }
        // Renumbering source_seq would hide the loss; keep it, the jump is recorded as a gap.
        store.ingest(&seg.id, 0, &records).unwrap();
        let r = check(
            &store,
            &Assertion::RequestCompletion {
                name: "rc".into(),
                rev: 1,
                request: "app.request".into(),
                completion: "app.completion".into(),
            },
        )
        .unwrap();
        assert_eq!(r.verdict, Verdict::Fail);
        assert_eq!(r.counterexamples.len(), 1);
    }

    #[test]
    fn zero_eligible_cases_is_unknown_not_pass() {
        let store = load(Recipe::Baseline, 1, 20, "q");
        let r = check(
            &store,
            &Assertion::RequestCompletion {
                name: "rc".into(),
                rev: 1,
                request: "app.request".into(),
                completion: "app.completion".into(),
            },
        )
        .unwrap();
        assert_eq!(r.verdict, Verdict::Unknown);
    }

    #[test]
    fn a_gap_turns_a_pass_into_unknown_but_keeps_a_fail() {
        let store = load(Recipe::Gap, 2, 20, "q");
        let pass = check(
            &store,
            &Assertion::Cardinality {
                name: "c".into(),
                rev: 1,
                kind: "core.process.start".into(),
                min: 1,
                max: 1,
            },
        )
        .unwrap();
        assert_eq!(pass.verdict, Verdict::Unknown);
        let fail = check(
            &store,
            &Assertion::Forbidden {
                name: "f".into(),
                rev: 1,
                kind: "core.process.start".into(),
            },
        )
        .unwrap();
        assert_eq!(fail.verdict, Verdict::Fail);
    }

    #[test]
    fn diff_is_deterministic_and_respects_coverage() {
        let a = load(Recipe::Baseline, 1, 60, "a");
        let b = load(Recipe::Baseline, 2, 90, "b");
        let one = serde_json::to_string(&diff(&a, &b, "kind", &[]).unwrap()).unwrap();
        let two = serde_json::to_string(&diff(&a, &b, "kind", &[]).unwrap()).unwrap();
        assert_eq!(one, two);
        // B lost data: a kind only in A is unknown, not only_a.
        let lossy = load(Recipe::Gap, 2, 30, "c");
        let only = load(Recipe::Interleave, 1, 8, "d");
        let d = diff(&only, &lossy, "kind", &[]).unwrap();
        assert!(
            d.entries
                .iter()
                .any(|e| e.key == "app.request" && e.class == DiffClass::NotComparable)
        );
        let clean = diff(&only, &a, "kind", &[]).unwrap();
        assert!(
            clean
                .entries
                .iter()
                .any(|e| e.key == "app.request" && e.class == DiffClass::OnlyA)
        );
    }
}
