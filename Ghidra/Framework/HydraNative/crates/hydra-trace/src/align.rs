//! Aligned diff (TRACE-1 section 14, spec 14.7). Two sessions are normalized into comparable keys
//! before anything is compared: process generations become ordinals, functions go through a
//! verified cross-build map, frames become `(offset from the phase start, phase)`, and a role
//! resolver hook names the object role. PIDs, addresses, sequence numbers and timestamps are
//! never keys. Every normalization is disclosed with unmatched and ambiguous counts, and the
//! output is byte-deterministic.

use crate::query::{DiffClass, DiffEntry, lossy_gap_count};
use crate::store::{Error, Result, Store};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// The most events scanned per side unless the request says otherwise.
pub const DEFAULT_EVENT_BUDGET: usize = 2_000_000;

const KEYS: [&str; 7] = [
    "kind", "resource", "state", "function", "role", "process", "phase",
];
/// A key component `payload:<field>` compares one payload field's value (a keyed id stays a keyed id).
const PAYLOAD_PREFIX: &str = "payload:";

fn payload_field(key: &str) -> Option<&str> {
    key.strip_prefix(PAYLOAD_PREFIX)
        .filter(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
}

fn default_keys() -> Vec<String> {
    vec!["kind".into(), "resource".into()]
}

fn default_budget() -> usize {
    DEFAULT_EVENT_BUDGET
}

/// What to align on and how.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlignSpec {
    /// Event kinds to compare; empty means all.
    #[serde(default)]
    pub kinds: Vec<String>,
    /// Key components in order, from `kind`, `resource`, `state` (the state key without its process
    /// generation), `function`, `role`, `process`, `phase`, or `payload:<field>`.
    #[serde(default = "default_keys")]
    pub keys: Vec<String>,
    /// Payload field the default role resolver reads.
    #[serde(default)]
    pub role_field: Option<String>,
    /// Verified cross-build function map: B's function name to A's.
    #[serde(default)]
    pub function_map: BTreeMap<String, String>,
    #[serde(default = "default_budget")]
    pub event_budget: usize,
    /// Pin a symbolization revision per side; the latest by default.
    #[serde(default)]
    pub interp_a: Option<i64>,
    #[serde(default)]
    pub interp_b: Option<i64>,
}

impl Default for AlignSpec {
    fn default() -> Self {
        Self {
            kinds: Vec::new(),
            keys: default_keys(),
            role_field: None,
            function_map: BTreeMap::new(),
            event_budget: DEFAULT_EVENT_BUDGET,
            interp_a: None,
            interp_b: None,
        }
    }
}

/// What a role resolver says about one event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    Is(String),
    /// Not resolvable: the key component is `-`.
    Unknown,
    /// More than one role fits: the event's group is `not_comparable`.
    Ambiguous,
}

/// The view of an event a role resolver gets.
pub struct AlignEvent<'a> {
    pub kind: &'a str,
    pub resource: Option<&'a str>,
    pub function: Option<&'a str>,
    pub process_ordinal: u32,
    /// The value of `AlignSpec::role_field` in the payload, when set.
    pub field: Option<&'a str>,
}

/// A hook that names the role an event plays (profile role resolvers plug in here).
pub trait RoleResolver {
    fn role(&self, event: &AlignEvent<'_>) -> Role;
}

/// The default resolver: the configured payload field, else unknown.
pub struct FieldRole;

impl RoleResolver for FieldRole {
    fn role(&self, event: &AlignEvent<'_>) -> Role {
        match event.field {
            Some(f) => Role::Is(f.to_string()),
            None => Role::Unknown,
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AlignedDiff {
    pub keys: Vec<String>,
    pub revision_a: u64,
    pub revision_b: u64,
    pub normalizations: Vec<String>,
    pub entries: Vec<DiffEntry>,
    pub unmatched_a: u64,
    pub unmatched_b: u64,
    /// Events whose role resolved ambiguously.
    pub ambiguous: u64,
    pub unmapped_functions: u64,
    pub scanned_a: u64,
    pub scanned_b: u64,
    pub gaps_a: u64,
    pub gaps_b: u64,
    /// Limitation codes that apply to the whole diff.
    pub limitations: Vec<String>,
}

#[derive(Default)]
struct Side {
    groups: BTreeMap<String, (u64, i64)>,
    ambiguous_keys: BTreeMap<String, ()>,
    ambiguous: u64,
    unmapped: u64,
    scanned: u64,
    truncated: bool,
}

fn latest_interp(store: &Store) -> Result<Option<i64>> {
    crate::symbolize::latest_symbolization(store)
}

fn scan_side(
    store: &Store,
    spec: &AlignSpec,
    map: Option<&BTreeMap<String, String>>,
    interp: Option<i64>,
    roles: &dyn RoleResolver,
) -> Result<Side> {
    let role_expr = match &spec.role_field {
        Some(f) if f.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') && !f.is_empty() => {
            format!("CAST(json_extract(e.payload,'$.{f}') AS TEXT)")
        }
        Some(_) => return Err(Error::Refused("role_field must be [A-Za-z0-9_]+".into())),
        None => "NULL".to_string(),
    };
    let fields: String = spec
        .keys
        .iter()
        .filter_map(|k| payload_field(k))
        .map(|f| format!(", CAST(json_extract(e.payload,'$.{f}') AS TEXT)"))
        .collect();
    let mut sql = format!(
        "SELECT e.seq,e.kind,e.resource_key,COALESCE(e.process_gen,0),
                CASE WHEN e.kind='core.marker' THEN e.payload END, s.function, {role_expr}, e.state_key{fields}
         FROM events e LEFT JOIN event_symbols s ON s.interp=?1 AND s.seq=e.seq"
    );
    if !spec.kinds.is_empty() {
        sql.push_str(&format!(
            " WHERE e.kind IN ({}) OR e.kind='core.marker'",
            vec!["?"; spec.kinds.len()].join(",")
        ));
    }
    sql.push_str(&format!(" ORDER BY e.seq LIMIT {}", spec.event_budget + 1));
    let mut args: Vec<rusqlite::types::Value> = vec![interp.into()];
    args.extend(spec.kinds.iter().cloned().map(Into::into));
    let mut stmt = store.conn().prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(args))?;
    let mut side = Side::default();
    let mut ordinals: HashMap<i64, u32> = HashMap::new();
    let mut frame: HashMap<i64, i64> = HashMap::new();
    let mut phase: HashMap<i64, (String, Option<i64>)> = HashMap::new();
    while let Some(row) = rows.next()? {
        if side.scanned as usize >= spec.event_budget {
            side.truncated = true;
            break;
        }
        side.scanned += 1;
        if side.scanned.is_multiple_of(4096) {
            crate::cancel::check()?;
            crate::cancel::progress(side.scanned, spec.event_budget as u64);
        }
        let seq: i64 = row.get(0)?;
        let kind: String = row.get(1)?;
        let resource: Option<String> = row.get(2)?;
        let pgen: i64 = row.get(3)?;
        let marker: Option<String> = row.get(4)?;
        let function: Option<String> = row.get(5)?;
        let field: Option<String> = row.get(6)?;
        let state: Option<String> = row.get(7)?;
        let next_ordinal = ordinals.len() as u32 + 1;
        let ordinal = if pgen == 0 {
            0
        } else {
            *ordinals.entry(pgen).or_insert(next_ordinal)
        };
        if let Some(text) = marker {
            let payload: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            if let Some(f) = payload.get("frame").and_then(Value::as_i64) {
                frame.insert(pgen, f);
                // The first frame at or after a phase marker is the phase's frame zero.
                if let Some(p) = phase.get_mut(&pgen) {
                    p.1.get_or_insert(f);
                }
            }
            if let Some(name) = payload.get("phase").and_then(Value::as_str) {
                phase.insert(pgen, (name.to_string(), None));
            }
        }
        if !spec.kinds.is_empty() && !spec.kinds.contains(&kind) {
            continue;
        }
        let mapped = function.as_deref().map(|f| match map {
            Some(m) => match m.get(f) {
                Some(a) => a.as_str(),
                None => {
                    side.unmapped += 1;
                    f
                }
            },
            None => f,
        });
        let event = AlignEvent {
            kind: &kind,
            resource: resource.as_deref(),
            function: mapped,
            process_ordinal: ordinal,
            field: field.as_deref(),
        };
        let mut ambiguous = false;
        let mut key = String::new();
        let mut payload_index = 8;
        for (i, component) in spec.keys.iter().enumerate() {
            if i > 0 {
                key.push('|');
            }
            if payload_field(component).is_some() {
                let value: Option<String> = row.get(payload_index)?;
                payload_index += 1;
                key.push_str(&format!(
                    "{}={}",
                    &component[PAYLOAD_PREFIX.len()..],
                    value.as_deref().unwrap_or("-")
                ));
                continue;
            }
            match component.as_str() {
                // the state key's leading process generation is session-local: dropped
                "state" => key.push_str(
                    state
                        .as_deref()
                        .map_or("-", |k| k.split_once(':').map_or(k, |(_, rest)| rest)),
                ),
                "kind" => key.push_str(&kind),
                "resource" => key.push_str(resource.as_deref().unwrap_or("-")),
                "function" => key.push_str(mapped.unwrap_or("-")),
                "process" => key.push_str(&format!("p{ordinal}")),
                "role" => match roles.role(&event) {
                    Role::Is(r) => key.push_str(&r),
                    Role::Unknown => key.push('-'),
                    Role::Ambiguous => {
                        ambiguous = true;
                        key.push_str("?ambiguous");
                    }
                },
                "phase" => match phase.get(&pgen) {
                    Some((name, start)) => {
                        let offset = start.map_or(0, |s| frame.get(&pgen).unwrap_or(&s) - s);
                        key.push_str(&format!("{name}@{offset:+}"));
                    }
                    None => key.push('-'),
                },
                _ => {}
            }
        }
        if ambiguous {
            side.ambiguous += 1;
            side.ambiguous_keys.insert(key.clone(), ());
        }
        let entry = side.groups.entry(key).or_insert((0, seq));
        entry.0 += 1;
    }
    Ok(side)
}

fn validate(spec: &AlignSpec) -> Result<()> {
    if spec.keys.is_empty() {
        return Err(Error::Refused("an alignment needs at least one key".into()));
    }
    for k in &spec.keys {
        if !KEYS.contains(&k.as_str()) && payload_field(k).is_none() {
            return Err(Error::Refused(format!(
                "unknown alignment key {k}; use one of {KEYS:?}"
            )));
        }
    }
    Ok(())
}

/// Diff `a` against `b` after normalization. See the module documentation.
pub fn diff_aligned(
    a: &Store,
    b: &Store,
    spec: &AlignSpec,
    roles: &(dyn RoleResolver + Sync),
) -> Result<AlignedDiff> {
    validate(spec)?;
    let wants_function = spec.keys.iter().any(|k| k == "function");
    let interp_a = match spec.interp_a {
        Some(i) => Some(i),
        None if wants_function => latest_interp(a)?,
        None => None,
    };
    let interp_b = match spec.interp_b {
        Some(i) => Some(i),
        None if wants_function => latest_interp(b)?,
        None => None,
    };
    let map = (!spec.function_map.is_empty()).then_some(&spec.function_map);
    // The two sides are independent scans: with two or more compute threads granted, B runs on a
    // worker with its own read-only handle. Each side is computed alone, so the result does not
    // depend on the thread count.
    let b_worker = if crate::workers::compute() >= 2 {
        b.reader_clone()
    } else {
        None
    };
    let (sa, sb) = match b_worker {
        Some(b2) => std::thread::scope(|scope| {
            let inherited = crate::cancel::current();
            let handle = scope.spawn(move || {
                crate::cancel::inherit(inherited);
                scan_side(&b2, spec, map, interp_b, roles)
            });
            let sa = scan_side(a, spec, None, interp_a, roles);
            let sb = handle
                .join()
                .unwrap_or_else(|_| Err(Error::Refused("diff worker panicked".into())));
            (sa, sb)
        }),
        None => (
            scan_side(a, spec, None, interp_a, roles),
            scan_side(b, spec, map, interp_b, roles),
        ),
    };
    let (sa, sb) = (sa?, sb?);
    let (gaps_a, gaps_b) = (lossy_gap_count(a)?, lossy_gap_count(b)?);
    // A side that was cut by the event budget, or lost data, cannot prove absence.
    let unsure_a = gaps_a > 0 || sa.truncated;
    let unsure_b = gaps_b > 0 || sb.truncated;

    let mut keys: Vec<&String> = sa.groups.keys().chain(sb.groups.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut entries = Vec::with_capacity(keys.len());
    let (mut unmatched_a, mut unmatched_b) = (0u64, 0u64);
    for key in keys {
        let (x, y) = (sa.groups.get(key), sb.groups.get(key));
        let ambiguous = sa.ambiguous_keys.contains_key(key) || sb.ambiguous_keys.contains_key(key);
        let class = match (x, y) {
            _ if ambiguous => DiffClass::NotComparable,
            (Some(x), Some(y)) if x.0 == y.0 => DiffClass::Same,
            (Some(_), Some(_)) if unsure_a || unsure_b => DiffClass::NotComparable,
            (Some(_), Some(_)) => DiffClass::DifferentUnderMatchedCoverage,
            (Some(_), None) => {
                unmatched_a += 1;
                if unsure_b {
                    DiffClass::NotComparable
                } else {
                    DiffClass::OnlyA
                }
            }
            (None, Some(_)) => {
                unmatched_b += 1;
                if unsure_a {
                    DiffClass::NotComparable
                } else {
                    DiffClass::OnlyB
                }
            }
            (None, None) => continue,
        };
        let id = |s: &Store, seq: i64| format!("ev_{}_{}", s.session(), seq);
        entries.push(DiffEntry {
            key: key.clone(),
            class,
            count_a: x.map_or(0, |g| g.0),
            count_b: y.map_or(0, |g| g.0),
            first_a: x.map(|g| id(a, g.1)),
            first_b: y.map(|g| id(b, g.1)),
        });
    }

    let mut normalizations = vec![
        "event ids, sequence numbers, timestamps, pids, tids and addresses are never keys"
            .to_string(),
    ];
    for k in &spec.keys {
        normalizations.push(match k.as_str() {
            "kind" => "kind: event kind, as recorded".to_string(),
            "resource" => "resource: the logical resource key".to_string(),
            "state" => "state: the state key without its session-local process generation".to_string(),
            k if payload_field(k).is_some() => format!("{k}: the value of that payload field"),
            "function" => format!(
                "function: symbolized at interpretation revision {} (a) and {} (b); B names mapped through {} verified map entries",
                interp_a.map_or("none".into(), |i| i.to_string()),
                interp_b.map_or("none".into(), |i| i.to_string()),
                spec.function_map.len()
            ),
            "role" => format!(
                "role: resolved from payload field {}",
                spec.role_field.as_deref().unwrap_or("(resolver hook)")
            ),
            "process" => "process: process generation replaced by its ordinal of first appearance".into(),
            _ => "phase: (frame offset from the phase start, phase); absolute frame numbers are not keys".into(),
        });
    }
    let mut limitations = Vec::new();
    if sa.truncated || sb.truncated {
        limitations.push("budget-reached".to_string());
    }
    if sa.ambiguous + sb.ambiguous > 0 {
        limitations.push("alignment-ambiguous".to_string());
    }
    Ok(AlignedDiff {
        keys: spec.keys.clone(),
        revision_a: a.revision()?,
        revision_b: b.revision()?,
        normalizations,
        entries,
        unmatched_a,
        unmatched_b,
        ambiguous: sa.ambiguous + sb.ambiguous,
        unmapped_functions: sa.unmapped + sb.unmapped,
        scanned_a: sa.scanned,
        scanned_b: sb.scanned,
        gaps_a,
        gaps_b,
        limitations,
    })
}

/// Convenience: [`diff_aligned`] with the default field resolver.
pub fn diff_aligned_default(a: &Store, b: &Store, spec: &AlignSpec) -> Result<AlignedDiff> {
    diff_aligned(a, b, spec, &FieldRole)
}

/// The cross-domain rule: a join across clock domains carries the uncertainty, or is not
/// comparable. Returns the combined uncertainty in nanoseconds.
pub fn clock_uncertainty(store: &Store, domain_a: &str, domain_b: &str) -> Result<Option<u64>> {
    if domain_a == domain_b {
        return Ok(Some(0));
    }
    let get = |name: &str| -> Result<Option<(i64, Option<String>)>> {
        Ok(store
            .conn()
            .query_row(
                "SELECT COALESCE(uncertainty_ns,0), to_domain FROM clock_domains WHERE name=?1 AND calibrated=1",
                params![name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok())
    };
    // One side calibrated against the other.
    if let Some((u, Some(to))) = get(domain_a)?
        && to == domain_b
    {
        return Ok(Some(u as u64));
    }
    if let Some((u, Some(to))) = get(domain_b)?
        && to == domain_a
    {
        return Ok(Some(u as u64));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Event;
    use crate::store::{Budget, Options};
    use crate::store_tests::{ev, records};
    use crate::symbolize::{FunctionRange, ModuleTable, TableSymbolizer};
    use serde_json::json;
    use std::sync::Arc;

    /// A run with a main loop: `frame0` is the absolute number of its first frame, `pid` the
    /// process. Phase "load" starts at the first frame; each frame draws, frame 2 also saves.
    fn run(session: &str, pid: u32, frame0: i64, extra: bool) -> Store {
        let mut events: Vec<Event> = Vec::new();
        let mut n = 0u64;
        let mut push = |kind: &str, payload: Value| {
            events.push(ev(kind, n, pid, payload, |_| {}));
            n += 1;
        };
        push("core.process.start", json!({}));
        push("core.marker", json!({"phase": "load"}));
        for i in 0..3 {
            push("core.marker", json!({"frame": frame0 + i}));
            push("app.draw", json!({"role": "main"}));
            if i == 2 {
                push("app.save", json!({"role": "main"}));
            }
        }
        if extra {
            push("app.extra", json!({"role": "worker"}));
        }
        let mut store = Store::memory(session).unwrap();
        store.ingest("s", 0, &records(events)).unwrap();
        store
    }

    fn spec(keys: &[&str]) -> AlignSpec {
        AlignSpec {
            keys: keys.iter().map(|s| s.to_string()).collect(),
            role_field: Some("role".into()),
            ..AlignSpec::default()
        }
    }

    #[test]
    fn different_pids_and_frame_numbers_align_by_offset_and_phase() {
        let a = run("a", 100, 100, false);
        let b = run("b", 999, 5000, false);
        let d = diff_aligned_default(&a, &b, &spec(&["kind", "phase", "process"])).unwrap();
        assert!(
            d.entries.iter().all(|e| e.class == DiffClass::Same),
            "{:?}",
            d.entries
        );
        assert!(d.entries.iter().any(|e| e.key == "app.draw|load@+2|p1"));
        assert!(d.normalizations.iter().any(|n| n.starts_with("phase:")));
        assert_eq!((d.unmatched_a, d.unmatched_b), (0, 0));
    }

    #[test]
    fn an_extra_event_is_only_in_b_and_a_moved_one_differs_by_offset() {
        let a = run("a", 100, 100, false);
        let b = run("b", 999, 5000, true);
        let d = diff_aligned_default(&a, &b, &spec(&["kind", "role"])).unwrap();
        let extra = d
            .entries
            .iter()
            .find(|e| e.key.starts_with("app.extra"))
            .unwrap();
        assert_eq!(extra.class, DiffClass::OnlyB);
        assert_eq!(d.unmatched_b, 1);
        // Same event counts, different frame offsets: keys only match under the offset key.
        let mut c_events = Vec::new();
        let mut n = 0u64;
        let mut push = |kind: &str, payload: Value| {
            c_events.push(ev(kind, n, 1, payload, |_| {}));
            n += 1;
        };
        push("core.marker", json!({"phase": "load"}));
        for i in 0..3 {
            push("core.marker", json!({"frame": i}));
            push("app.draw", json!({}));
            if i == 0 {
                push("app.save", json!({}));
            }
        }
        let mut c = Store::memory("c").unwrap();
        c.ingest("s", 0, &records(c_events)).unwrap();
        let d = diff_aligned_default(&a, &c, &spec(&["kind", "phase"])).unwrap();
        let save: Vec<_> = d
            .entries
            .iter()
            .filter(|e| e.key.starts_with("app.save"))
            .collect();
        assert_eq!(save.len(), 2);
        assert!(
            save.iter()
                .any(|e| e.key.ends_with("@+2") && e.class == DiffClass::OnlyA)
        );
        assert!(
            save.iter()
                .any(|e| e.key.ends_with("@+0") && e.class == DiffClass::OnlyB)
        );
    }

    struct EveryoneIsAmbiguous;
    impl RoleResolver for EveryoneIsAmbiguous {
        fn role(&self, e: &AlignEvent<'_>) -> Role {
            if e.kind == "app.save" {
                Role::Ambiguous
            } else {
                Role::Unknown
            }
        }
    }

    #[test]
    fn role_resolver_hooks_can_declare_ambiguity() {
        let a = run("a", 1, 0, false);
        let b = run("b", 2, 0, false);
        let d = diff_aligned(&a, &b, &spec(&["kind", "role"]), &EveryoneIsAmbiguous).unwrap();
        let save = d
            .entries
            .iter()
            .find(|e| e.key.starts_with("app.save"))
            .unwrap();
        assert_eq!(save.class, DiffClass::NotComparable);
        assert_eq!(d.ambiguous, 2);
        assert!(d.limitations.contains(&"alignment-ambiguous".to_string()));
    }

    fn symbolized(session: &str, fname: &str) -> Store {
        let mut table = TableSymbolizer::default();
        table.modules.insert(
            "m.dll".into(),
            ModuleTable {
                code: vec![],
                functions: vec![FunctionRange {
                    start: 0x100,
                    end: 0x200,
                    name: fname.into(),
                    type_name: None,
                }],
            },
        );
        let mut store = Store::memory(session).unwrap();
        store
            .set_options(Options {
                symbolizer: Some(Arc::new(table)),
                symbol_revision: "p".into(),
                budget: Budget::default(),
            })
            .unwrap();
        let events = vec![
            ev("core.process.start", 0, 1, json!({}), |_| {}),
            ev(
                "core.module.load",
                1,
                1,
                json!({"name": "m.dll", "base": 0x1000, "size": 0x1000}),
                |_| {},
            ),
            ev("app.call", 2, 1, json!({}), |e| e.va = Some(0x1150)),
            ev("app.call", 3, 1, json!({}), |e| e.va = Some(0x1150)),
        ];
        store.ingest("s", 0, &records(events)).unwrap();
        store
    }

    #[test]
    fn cross_build_function_map_aligns_renamed_functions() {
        let a = symbolized("a", "Update");
        let b = symbolized("b", "Update_v2");
        let mut s = spec(&["kind", "function"]);
        let unmapped = diff_aligned_default(&a, &b, &s).unwrap();
        assert!(
            unmapped
                .entries
                .iter()
                .any(|e| e.key == "app.call|Update" && e.class == DiffClass::OnlyA)
        );
        s.function_map.insert("Update_v2".into(), "Update".into());
        let mapped = diff_aligned_default(&a, &b, &s).unwrap();
        let call = mapped
            .entries
            .iter()
            .find(|e| e.key == "app.call|Update")
            .unwrap();
        assert_eq!(call.class, DiffClass::Same);
        assert_eq!(mapped.unmapped_functions, 0);
    }

    #[test]
    fn budget_and_gaps_make_absence_unknown() {
        let a = run("a", 1, 0, false);
        let b = run("b", 2, 0, true);
        let mut s = spec(&["kind"]);
        s.event_budget = 4;
        let d = diff_aligned_default(&a, &b, &s).unwrap();
        assert!(d.limitations.contains(&"budget-reached".to_string()));
        assert!(
            d.entries
                .iter()
                .all(|e| e.class != DiffClass::OnlyA && e.class != DiffClass::OnlyB)
        );
        assert!(d.scanned_a <= 4 && d.scanned_b <= 4);
    }

    #[test]
    fn output_is_byte_identical_over_runs() {
        let a = run("a", 100, 100, false);
        let b = run("b", 999, 5000, true);
        let s = spec(&["kind", "phase", "process", "role"]);
        let one = serde_json::to_string(&diff_aligned_default(&a, &b, &s).unwrap()).unwrap();
        for _ in 0..3 {
            assert_eq!(
                one,
                serde_json::to_string(&diff_aligned_default(&a, &b, &s).unwrap()).unwrap()
            );
        }
    }

    #[test]
    fn bad_specs_are_refused_and_clocks_need_calibration() {
        let a = run("a", 1, 0, false);
        assert!(
            diff_aligned_default(
                &a,
                &a,
                &AlignSpec {
                    keys: vec![],
                    ..AlignSpec::default()
                }
            )
            .is_err()
        );
        assert!(diff_aligned_default(&a, &a, &spec(&["pid"])).is_err());
        let mut bad_role = spec(&["kind"]);
        bad_role.role_field = Some("a'); DROP".into());
        assert!(diff_aligned_default(&a, &a, &bad_role).is_err());
        assert_eq!(clock_uncertainty(&a, "qpc", "qpc").unwrap(), Some(0));
        assert_eq!(clock_uncertainty(&a, "qpc", "wall").unwrap(), None);
        let mut c = Store::memory("c").unwrap();
        c.ingest(
            "s",
            0,
            &records(vec![ev(
                "core.capture.source",
                0,
                1,
                json!({"clock": {"unit": "qpc", "offset_ns": 3, "uncertainty_ns": 250, "to": "wall"}}),
                |_| {},
            )]),
        )
        .unwrap();
        assert_eq!(clock_uncertainty(&c, "qpc", "wall").unwrap(), Some(250));
        assert_eq!(clock_uncertainty(&c, "wall", "qpc").unwrap(), Some(250));
    }
}
