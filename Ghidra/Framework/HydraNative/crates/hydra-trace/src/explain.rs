//! Explain: walk relations upstream (what led to this event) or downstream (what it led to)
//! under depth, event and byte budgets. The reply carries path counts and the unresolved
//! boundaries where the walk stops for lack of evidence or for lack of budget.

use crate::relations::{self, Relation};
use crate::store::{Error, Result, Store};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Upstream,
    Downstream,
}

/// Hard bounds on one explanation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Budget {
    pub max_depth: u32,
    pub max_events: usize,
    pub max_bytes: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_events: 200,
            max_bytes: 64 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Node {
    pub event_id: String,
    pub kind: String,
    pub depth: u32,
    pub payload: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub relation: String,
    pub status: String,
    pub basis: Vec<String>,
}

/// A place where the walk could not go on.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Boundary {
    pub event_id: String,
    /// A limitation code (`budget-reached`) or a relation reason (`missing-completion`, ...).
    pub reason: String,
    pub relation: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Explanation {
    pub revision: u64,
    pub root: String,
    pub direction: Direction,
    pub relations_source: String,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    /// Distinct root-to-leaf paths in the explored subgraph (saturating).
    pub paths: u64,
    pub boundaries: Vec<Boundary>,
    /// `depth`, `events` or `bytes` when a budget cut the walk; the cut edges are boundaries.
    pub truncated: Option<String>,
}

/// The ordinal of an event id of this store.
pub fn seq_of(store: &Store, event_id: &str) -> Option<i64> {
    let prefix = format!("ev_{}_", store.session());
    event_id.strip_prefix(&prefix)?.parse().ok()
}

fn id_of(store: &Store, seq: i64) -> String {
    format!("ev_{}_{}", store.session(), seq)
}

/// Explain `event_id` in `direction` within `budget`.
pub fn explain(
    store: &Store,
    event_id: &str,
    direction: Direction,
    budget: Budget,
) -> Result<Explanation> {
    let root = seq_of(store, event_id)
        .ok_or_else(|| Error::Refused(format!("unknown event id {event_id}")))?;
    let exists: i64 = store.conn().query_row(
        "SELECT COUNT(*) FROM events WHERE seq=?1",
        params![root],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Err(Error::Refused(format!("unknown event id {event_id}")));
    }
    let revision = store.revision()?;
    let (all, source) = relations::current(store)?;

    // Adjacency in the walk direction, and the unresolved boundaries by event.
    let mut next: HashMap<i64, Vec<&Relation>> = HashMap::new();
    let mut open: HashMap<i64, Vec<&Relation>> = HashMap::new();
    for r in &all {
        match r.to_seq {
            Some(to) => {
                let key = match direction {
                    Direction::Downstream => r.from_seq,
                    Direction::Upstream => to,
                };
                next.entry(key).or_default().push(r);
                if r.status == "unresolved" {
                    open.entry(key).or_default().push(r);
                }
            }
            None => open.entry(r.from_seq).or_default().push(r),
        }
    }

    let mut depth_of: BTreeMap<i64, u32> = BTreeMap::new();
    let mut order: Vec<i64> = Vec::new();
    let mut edges: Vec<(i64, i64, &Relation)> = Vec::new();
    let mut boundaries: Vec<Boundary> = Vec::new();
    let mut truncated: Option<String> = None;
    let mut bytes = 0usize;
    let mut queue: VecDeque<i64> = VecDeque::new();
    depth_of.insert(root, 0);
    order.push(root);
    queue.push_back(root);
    while let Some(cur) = queue.pop_front() {
        let depth = depth_of[&cur];
        let outgoing = next.get(&cur).map(Vec::as_slice).unwrap_or(&[]);
        for r in outgoing {
            let other = match direction {
                Direction::Downstream => r.to_seq.unwrap_or(cur),
                Direction::Upstream => r.from_seq,
            };
            if depth >= budget.max_depth {
                truncated.get_or_insert_with(|| "depth".into());
                boundaries.push(Boundary {
                    event_id: id_of(store, cur),
                    reason: "budget-reached".into(),
                    relation: Some(r.relation.clone()),
                });
                continue;
            }
            if let std::collections::btree_map::Entry::Vacant(slot) = depth_of.entry(other) {
                if order.len() >= budget.max_events || bytes >= budget.max_bytes {
                    truncated.get_or_insert_with(|| {
                        if order.len() >= budget.max_events {
                            "events".into()
                        } else {
                            "bytes".into()
                        }
                    });
                    boundaries.push(Boundary {
                        event_id: id_of(store, cur),
                        reason: "budget-reached".into(),
                        relation: Some(r.relation.clone()),
                    });
                    continue;
                }
                bytes += 160 + r.relation.len();
                slot.insert(depth + 1);
                order.push(other);
                queue.push_back(other);
            }
            edges.push((r.from_seq, other_end(r, direction, cur), r));
        }
    }
    for seq in &order {
        for r in open.get(seq).map(Vec::as_slice).unwrap_or(&[]) {
            for reason in &r.unresolved {
                boundaries.push(Boundary {
                    event_id: id_of(store, *seq),
                    reason: reason.clone(),
                    relation: Some(r.relation.clone()),
                });
            }
        }
    }
    boundaries.sort_by(|a, b| {
        (&a.event_id, &a.reason, &a.relation).cmp(&(&b.event_id, &b.reason, &b.relation))
    });
    boundaries.dedup();

    // Path count over the explored subgraph, in walk direction, with cycle protection.
    let explored: BTreeSet<i64> = depth_of.keys().copied().collect();
    let mut succ: HashMap<i64, Vec<i64>> = HashMap::new();
    for (from, to, _) in &edges {
        let (a, b) = match direction {
            Direction::Downstream => (*from, *to),
            Direction::Upstream => (*to, *from),
        };
        if explored.contains(&a) && explored.contains(&b) {
            succ.entry(a).or_default().push(b);
        }
    }
    for v in succ.values_mut() {
        v.sort_unstable();
        v.dedup();
    }
    let mut memo: HashMap<i64, u64> = HashMap::new();
    let paths = count_paths(root, &succ, &mut memo, &mut BTreeSet::new());

    // Nodes (bytes-bounded) and edges in a deterministic order.
    let mut nodes = Vec::new();
    let mut stmt = store
        .conn()
        .prepare("SELECT kind,payload FROM events WHERE seq=?1")?;
    let mut ordered: Vec<i64> = order.clone();
    ordered.sort_by_key(|s| (depth_of[s], *s));
    for seq in ordered {
        let (kind, payload): (String, String) =
            stmt.query_row(params![seq], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let payload: String = payload.chars().take(256).collect();
        bytes += payload.len() + kind.len();
        nodes.push(Node {
            event_id: id_of(store, seq),
            kind,
            depth: depth_of[&seq],
            payload,
        });
    }
    if bytes > budget.max_bytes && truncated.is_none() {
        truncated = Some("bytes".into());
    }
    let mut out_edges: Vec<Edge> = edges
        .iter()
        .map(|(from, to, r)| Edge {
            from: id_of(store, *from),
            to: id_of(store, *to),
            relation: r.relation.clone(),
            status: r.status.clone(),
            basis: r.basis.clone(),
        })
        .collect();
    out_edges.sort_by(|a, b| (&a.from, &a.to, &a.relation).cmp(&(&b.from, &b.to, &b.relation)));
    out_edges.dedup();
    Ok(Explanation {
        revision,
        root: id_of(store, root),
        direction,
        relations_source: source.into(),
        nodes,
        edges: out_edges,
        paths,
        boundaries,
        truncated,
    })
}

fn other_end(r: &Relation, direction: Direction, cur: i64) -> i64 {
    match direction {
        Direction::Downstream => r.to_seq.unwrap_or(cur),
        Direction::Upstream => cur,
    }
}

fn count_paths(
    node: i64,
    succ: &HashMap<i64, Vec<i64>>,
    memo: &mut HashMap<i64, u64>,
    visiting: &mut BTreeSet<i64>,
) -> u64 {
    if let Some(&n) = memo.get(&node) {
        return n;
    }
    let Some(children) = succ.get(&node).filter(|c| !c.is_empty()) else {
        return 1;
    };
    if !visiting.insert(node) {
        return 0; // a cycle is not a path
    }
    let mut total = 0u64;
    for &c in children {
        total = total.saturating_add(count_paths(c, succ, memo, visiting));
    }
    visiting.remove(&node);
    memo.insert(node, total);
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store_tests::{ev, records};
    use serde_json::json;

    fn load(events: Vec<crate::model::Event>) -> Store {
        let mut store = Store::memory("x").unwrap();
        store.ingest("s", 0, &records(events)).unwrap();
        store
    }

    /// handoff chain a -> b -> c plus a fork a -> d, all by tokens.
    fn chain() -> Store {
        load(vec![
            ev(
                "app.a",
                0,
                7,
                json!({"handoff": "t1", "produces": "p"}),
                |e| e.thread_id = Some(1),
            ),
            ev(
                "app.b",
                1,
                7,
                json!({"handoff": "t1", "consumes": "p", "produces": "q"}),
                |e| e.thread_id = Some(2),
            ),
            ev("app.c", 2, 7, json!({"consumes": "q"}), |e| {
                e.thread_id = Some(3)
            }),
            ev("app.d", 3, 7, json!({"consumes": "p"}), |e| {
                e.thread_id = Some(4)
            }),
        ])
    }

    #[test]
    fn downstream_counts_paths_and_upstream_walks_back() {
        let store = chain();
        let down = explain(&store, "ev_x_1", Direction::Downstream, Budget::default()).unwrap();
        assert_eq!(down.nodes.len(), 4);
        assert_eq!(down.paths, 2);
        let up = explain(&store, "ev_x_4", Direction::Upstream, Budget::default()).unwrap();
        let ids: Vec<_> = up.nodes.iter().map(|n| n.event_id.as_str()).collect();
        assert_eq!(ids, vec!["ev_x_4", "ev_x_1"]);
        assert_eq!(up.truncated, None);
    }

    #[test]
    fn depth_and_event_budgets_are_reported_as_boundaries() {
        let store = chain();
        let shallow = explain(
            &store,
            "ev_x_1",
            Direction::Downstream,
            Budget {
                max_depth: 1,
                ..Budget::default()
            },
        )
        .unwrap();
        assert_eq!(shallow.truncated.as_deref(), Some("depth"));
        assert!(
            shallow
                .boundaries
                .iter()
                .any(|b| b.reason == "budget-reached")
        );
        let tiny = explain(
            &store,
            "ev_x_1",
            Direction::Downstream,
            Budget {
                max_events: 1,
                ..Budget::default()
            },
        )
        .unwrap();
        assert_eq!(tiny.truncated.as_deref(), Some("events"));
        assert_eq!(tiny.nodes.len(), 1);
    }

    #[test]
    fn unresolved_boundaries_are_listed() {
        let store = load(vec![
            ev("app.request", 0, 7, json!({"corr": "a"}), |_| {}),
            ev("app.completion", 1, 7, json!({"corr": "b"}), |_| {}),
        ]);
        let x = explain(&store, "ev_x_2", Direction::Upstream, Budget::default()).unwrap();
        assert!(x.boundaries.iter().any(|b| b.reason == "missing-request"));
        assert_eq!(x.nodes.len(), 1);
    }

    #[test]
    fn unknown_event_is_refused_and_output_is_deterministic() {
        let store = chain();
        assert!(explain(&store, "ev_x_99", Direction::Upstream, Budget::default()).is_err());
        assert!(explain(&store, "nope", Direction::Upstream, Budget::default()).is_err());
        let a = serde_json::to_string(
            &explain(&store, "ev_x_1", Direction::Downstream, Budget::default()).unwrap(),
        )
        .unwrap();
        let b = serde_json::to_string(
            &explain(&store, "ev_x_1", Direction::Downstream, Budget::default()).unwrap(),
        )
        .unwrap();
        assert_eq!(a, b);
    }
}
