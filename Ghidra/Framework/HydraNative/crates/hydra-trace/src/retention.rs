//! Session-level retention (TRACE-1 section 12). A closed session can be evicted: its data is
//! deleted and a tombstone is written first, under `<root>/.tombstones/<id>.json`, so the id is
//! never reused for different data and anything that depends on the session (a bundle that pins
//! its revision, a client holding its cursors) learns why it can no longer be read. The store has
//! an optional quota: creating a session over it is refused with the sessions that could be
//! evicted, and `trace_evict` with `to_quota` evicts the oldest closed sessions until it fits.
//! Nothing is ever dropped silently: an eviction is a tombstone, a refusal is an answer.

use crate::export;
use crate::session;
use crate::store::{Error, Result};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// The directory of tombstones (not a valid session id, so no session can collide with it).
pub const TOMBSTONES: &str = ".tombstones";

pub fn tombstone_path(root: &Path, id: &str) -> PathBuf {
    root.join(TOMBSTONES).join(format!("{id}.json"))
}

/// The tombstone of an evicted session.
pub fn tombstone(root: &Path, id: &str) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(tombstone_path(root, id)).ok()?).ok()
}

/// Every tombstone, sorted by session id.
pub fn tombstones(root: &Path) -> Vec<Value> {
    let mut out: Vec<Value> = std::fs::read_dir(root.join(TOMBSTONES))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok())
        .collect();
    out.sort_by(|a, b| a["session"].as_str().cmp(&b["session"].as_str()));
    out
}

fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0;
    let Ok(read) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in read.flatten() {
        let path = entry.path();
        match entry.metadata() {
            Ok(m) if m.is_dir() => total += dir_bytes(&path),
            Ok(m) => total += m.len(),
            Err(_) => {}
        }
    }
    total
}

/// Bytes the store holds on disk (sessions only, not tombstones).
pub fn store_bytes(root: &Path) -> u64 {
    let Ok(read) = std::fs::read_dir(root) else {
        return 0;
    };
    read.flatten()
        .filter(|e| e.file_name() != TOMBSTONES)
        .map(|e| dir_bytes(&e.path()))
        .sum()
}

fn created_unix(dir: &Path) -> u64 {
    std::fs::read(dir.join("session.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.get("created_unix").and_then(Value::as_u64))
        .unwrap_or(0)
}

/// Closed or open, oldest first: `(created_unix, id)` of every session on disk.
pub fn by_age(root: &Path) -> Vec<(u64, String)> {
    let mut out: Vec<(u64, String)> = session::list(root)
        .into_iter()
        .map(|id| (created_unix(&root.join(&id)), id))
        .collect();
    out.sort();
    out
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Evict a closed session: write its tombstone (durably), then delete its directory. The caller
/// has checked that no writer holds it. Returns the tombstone.
pub fn evict(root: &Path, id: &str, reason: &str) -> Result<Value> {
    if !session::valid_name(id) {
        return Err(Error::Refused(format!("invalid session id {id:?}")));
    }
    let dir = root.join(id);
    if !session::index_path(&dir).is_file() {
        return Err(Error::Refused(format!("no session {id}")));
    }
    let (revision, events) = match session::reader(root, id) {
        Ok(s) => (s.revision().unwrap_or(0), s.event_count().unwrap_or(0)),
        Err(_) => (0, 0),
    };
    let mut artifacts = Vec::new();
    if let Ok(s) = session::reader(root, id)
        && let Ok(list) = crate::artifact::list(&s)
    {
        for a in list {
            artifacts
                .push(json!({"id": a.id, "sha256": a.sha256, "size": a.size, "scope": a.scope}));
        }
    }
    let mut bundles = Vec::new();
    if let Ok(read) = std::fs::read_dir(dir.join("export")) {
        for e in read.flatten() {
            if let Ok(b) = std::fs::read(e.path().join("manifest.json"))
                && let Ok(m) = serde_json::from_slice::<Value>(&b)
                && let Some(bid) = m.get("bundle_id")
            {
                bundles.push(bid.clone());
            }
        }
    }
    bundles.sort_by_key(Value::to_string);
    let bytes = dir_bytes(&dir);
    let stone = json!({
        "session": id, "reason": reason, "evicted_unix": now_unix(), "revision": revision,
        "events": events, "bytes_freed": bytes, "artifacts": artifacts, "bundles": bundles,
    });
    let path = tombstone_path(root, id);
    std::fs::create_dir_all(root.join(TOMBSTONES))?;
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec(&stone)?)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    // The tombstone is durable; now the data. A failure here leaves a session that is still
    // readable and a tombstone that says it is going: evict again to finish.
    std::fs::remove_dir_all(&dir)?;
    Ok(stone)
}

/// Whether the export `folder` still stands: its files match its manifest, and the session it
/// was exported from is still there (a bundle that pins a revision of an evicted session can no
/// longer be re-read from the store, and says so).
pub fn bundle_status(root: &Path, folder: &Path) -> Result<Value> {
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(folder.join("manifest.json"))
            .map_err(|_| Error::Refused(format!("{} has no manifest.json", folder.display())))?,
    )?;
    let integrity = export::verify(folder);
    let session = manifest
        .get("session")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let revision = manifest
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut reasons = Vec::new();
    if let Err(e) = &integrity {
        reasons.push(json!({"reason": "bundle-damaged", "detail": e.to_string()}));
    }
    let (state, current) = if let Some(t) = tombstone(root, &session) {
        reasons.push(json!({"reason": "session-evicted", "tombstone": t}));
        ("evicted", None)
    } else {
        match session::reader(root, &session) {
            Ok(s) => {
                let current = s.revision().unwrap_or(0);
                if current < revision {
                    reasons.push(json!({"reason": "revision-not-reached", "current": current}));
                }
                ("present", Some(current))
            }
            Err(_) => {
                reasons.push(json!({"reason": "session-unknown"}));
                ("unknown", None)
            }
        }
    };
    Ok(json!({
        "bundle_id": manifest.get("bundle_id"), "session": session, "bundle_revision": revision,
        "integrity_ok": integrity.is_ok(), "session_state": state, "current_revision": current,
        "reproducible": reasons.is_empty(), "reasons": reasons,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;
    use crate::store::Options;

    fn root(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hydra-retention-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn eviction_writes_the_tombstone_first_and_frees_the_data() {
        let r = root("a");
        let (_s, _) = Session::open(&r, "old", Options::default()).unwrap();
        drop(_s);
        assert!(store_bytes(&r) > 0);
        let t = evict(&r, "old", "quota").unwrap();
        assert_eq!(t["reason"], "quota");
        assert!(!r.join("old").exists());
        assert_eq!(tombstone(&r, "old").unwrap()["session"], "old");
        assert_eq!(tombstones(&r).len(), 1);
        assert!(session::list(&r).is_empty());
        assert!(evict(&r, "old", "again").is_err());
        let _ = std::fs::remove_dir_all(r);
    }
}
