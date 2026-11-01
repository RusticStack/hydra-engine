//! Payload artifacts (TRACE-1 section 11). Exact bytes exist only here, as private artifacts
//! with a declared scope, a maximum size, a retention period and optional redaction. An artifact
//! is durable (written, synced and renamed) before the row that names it commits, and an event
//! may reference it only afterwards. Export omits artifacts unless they are separately
//! authorized, and an evicted artifact leaves a tombstone.

use crate::store::{Error, Result, Store};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactSpec {
    /// What the bytes are for (a profile-declared scope); required.
    pub scope: String,
    /// The largest payload this scope may hold; a bigger one is refused, never truncated.
    pub max_bytes: u64,
    /// Seconds until eviction; `None` keeps it until the session is evicted.
    #[serde(default)]
    pub retention_secs: Option<u64>,
    /// Byte ranges `(offset, len)` zero-filled before anything is stored.
    #[serde(default)]
    pub redact: Vec<(u64, u64)>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ArtifactInfo {
    pub id: String,
    pub sha256: String,
    pub size: u64,
    pub scope: String,
    pub state: String,
}

/// The directory that holds a session's artifact files.
pub struct Artifacts {
    dir: PathBuf,
}

impl Artifacts {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.bin"))
    }

    /// Store `data`: validate, redact, write durably, then record. Returns the artifact id
    /// (content addressed). Nothing references the artifact before this returns.
    pub fn put(
        &self,
        store: &mut Store,
        data: &[u8],
        spec: &ArtifactSpec,
        now_unix: u64,
    ) -> Result<String> {
        if spec.scope.trim().is_empty() {
            return Err(Error::Refused("an artifact needs a declared scope".into()));
        }
        if spec.max_bytes == 0 || data.len() as u64 > spec.max_bytes {
            return Err(Error::Refused(format!(
                "payload of {} bytes exceeds the scope maximum of {}",
                data.len(),
                spec.max_bytes
            )));
        }
        let mut bytes = data.to_vec();
        for &(off, len) in &spec.redact {
            let start = (off as usize).min(bytes.len());
            let end = (off.saturating_add(len) as usize).min(bytes.len());
            bytes[start..end].fill(0);
        }
        let sha = hex(&Sha256::digest(&bytes));
        let id = format!("art_{}", &sha[..32]);
        let final_path = self.path(&id);
        if !final_path.exists() {
            let tmp = self.dir.join(format!("{id}.tmp"));
            {
                let mut f = std::fs::File::create(&tmp)?;
                f.write_all(&bytes)?;
                f.sync_all()?;
            }
            std::fs::rename(&tmp, &final_path)?;
            // Make the rename durable where the platform allows opening a directory.
            if let Ok(d) = std::fs::File::open(&self.dir) {
                let _ = d.sync_all();
            }
        }
        let rev = store.revision()?;
        let redaction = if spec.redact.is_empty() {
            "none".to_string()
        } else {
            format!("zero-fill:{}", serde_json::to_string(&spec.redact)?)
        };
        store.conn().execute(
            "INSERT INTO artifacts(id,sha256,size,scope,max_bytes,retention_secs,redaction,created_unix,state,created_rev)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'present',?9)
             ON CONFLICT(id) DO NOTHING",
            params![
                id,
                sha,
                bytes.len() as i64,
                spec.scope,
                spec.max_bytes as i64,
                spec.retention_secs.map(|v| v as i64),
                redaction,
                now_unix as i64,
                rev as i64
            ],
        )?;
        Ok(id)
    }

    /// The bytes of a present artifact. An evicted one is an error that names the limitation.
    pub fn read(&self, store: &Store, id: &str) -> Result<Vec<u8>> {
        match state(store, id)?.as_deref() {
            Some("present") => Ok(std::fs::read(self.path(id))?),
            Some(_) => Err(Error::Refused("artifact-evicted".into())),
            None => Err(Error::Refused(format!("unknown artifact {id}"))),
        }
    }

    /// Evict every artifact whose retention ran out at `now_unix`; each leaves a tombstone.
    pub fn evict_expired(&self, store: &mut Store, now_unix: u64) -> Result<Vec<String>> {
        let due: Vec<String> = {
            let mut stmt = store.conn().prepare(
                "SELECT id FROM artifacts WHERE state='present' AND retention_secs IS NOT NULL
                 AND created_unix + retention_secs <= ?1 ORDER BY id",
            )?;
            stmt.query_map(params![now_unix as i64], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?
        };
        for id in &due {
            self.tombstone(store, id, "retention-expired")?;
        }
        Ok(due)
    }

    /// Delete the bytes and record why.
    pub fn tombstone(&self, store: &mut Store, id: &str, reason: &str) -> Result<()> {
        let rev = store.revision()?;
        let sha: Option<String> = store
            .conn()
            .query_row("SELECT sha256 FROM artifacts WHERE id=?1", params![id], |r| {
                r.get(0)
            })
            .ok();
        let Some(sha) = sha else {
            return Err(Error::Refused(format!("unknown artifact {id}")));
        };
        match std::fs::remove_file(self.path(id)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let tx = store.conn_mut().transaction()?;
        tx.execute(
            "UPDATE artifacts SET state='tombstoned' WHERE id=?1",
            params![id],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO tombstones(id,kind,reason,at_rev,sha256) VALUES(?1,'artifact',?2,?3,?4)",
            params![id, reason, rev as i64, sha],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `present`, `tombstoned` or `None` for an unknown id.
pub fn state(store: &Store, id: &str) -> Result<Option<String>> {
    Ok(store
        .conn()
        .query_row("SELECT state FROM artifacts WHERE id=?1", params![id], |r| {
            r.get(0)
        })
        .ok())
}

/// Refuse a payload that names an artifact that is not durable yet (or never existed). A
/// tombstoned artifact may still be referenced by events that were written while it existed, but
/// no new reference is accepted.
pub fn require_present_refs(store: &Store, payload: &serde_json::Map<String, serde_json::Value>) -> Result<()> {
    for key in ["artifact", "artifacts"] {
        let ids: Vec<&str> = match payload.get(key) {
            Some(serde_json::Value::String(s)) => vec![s.as_str()],
            Some(serde_json::Value::Array(a)) => a.iter().filter_map(|v| v.as_str()).collect(),
            _ => continue,
        };
        for id in ids {
            if state(store, id)?.as_deref() != Some("present") {
                return Err(Error::Refused(format!(
                    "dangling artifact reference {id}: write the artifact before referencing it"
                )));
            }
        }
    }
    Ok(())
}

pub fn list(store: &Store) -> Result<Vec<ArtifactInfo>> {
    let mut stmt = store
        .conn()
        .prepare("SELECT id,sha256,size,scope,state FROM artifacts ORDER BY id")?;
    let rows = stmt.query_map([], |r| {
        Ok(ArtifactInfo {
            id: r.get(0)?,
            sha256: r.get(1)?,
            size: r.get::<_, i64>(2)? as u64,
            scope: r.get(3)?,
            state: r.get(4)?,
        })
    })?;
    rows.collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}

/// What an export may carry: authorized present artifacts, and the reason for each omission.
pub struct ExportGate {
    pub included: Vec<ArtifactInfo>,
    pub omitted: Vec<(String, &'static str)>,
}

pub fn gate(store: &Store, authorized: &[String]) -> Result<ExportGate> {
    let mut included = Vec::new();
    let mut omitted = Vec::new();
    for info in list(store)? {
        if info.state != "present" {
            omitted.push((info.id, "artifact-evicted"));
        } else if !authorized.contains(&info.id) {
            omitted.push((info.id, "payload-not-authorized"));
        } else {
            included.push(info);
        }
    }
    Ok(ExportGate { included, omitted })
}

/// Where a session keeps artifacts, under its directory.
pub fn dir_of(session_dir: &Path) -> PathBuf {
    session_dir.join("artifacts")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(name: &str) -> (Artifacts, Store, PathBuf) {
        let d = std::env::temp_dir().join(format!("hydra-art-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        (
            Artifacts::open(&d).unwrap(),
            Store::memory("a").unwrap(),
            d,
        )
    }

    fn spec() -> ArtifactSpec {
        ArtifactSpec {
            scope: "packet".into(),
            max_bytes: 16,
            retention_secs: Some(60),
            redact: vec![],
        }
    }

    #[test]
    fn put_is_durable_before_it_is_referenceable() {
        let (arts, mut store, d) = setup("a");
        let id = arts.put(&mut store, b"0123456789", &spec(), 1000).unwrap();
        assert!(arts.path(&id).is_file());
        assert_eq!(arts.read(&store, &id).unwrap(), b"0123456789");
        let ok = serde_json::json!({"artifact": id}).as_object().unwrap().clone();
        assert!(require_present_refs(&store, &ok).is_ok());
        let bad = serde_json::json!({"artifact": "art_missing"}).as_object().unwrap().clone();
        assert!(require_present_refs(&store, &bad).is_err());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn scope_and_size_are_enforced_never_truncated() {
        let (arts, mut store, d) = setup("b");
        assert!(arts.put(&mut store, &[0; 17], &spec(), 0).is_err());
        let mut no_scope = spec();
        no_scope.scope = " ".into();
        assert!(arts.put(&mut store, b"x", &no_scope, 0).is_err());
        assert!(list(&store).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn redaction_zero_fills_only_the_declared_ranges() {
        let (arts, mut store, d) = setup("c");
        let mut s = spec();
        s.redact = vec![(2, 3)];
        let id = arts.put(&mut store, b"abcdefgh", &s, 0).unwrap();
        assert_eq!(arts.read(&store, &id).unwrap(), b"ab\0\0\0fgh");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn retention_evicts_and_leaves_a_tombstone() {
        let (arts, mut store, d) = setup("d");
        let id = arts.put(&mut store, b"secret", &spec(), 1000).unwrap();
        assert!(arts.evict_expired(&mut store, 1059).unwrap().is_empty());
        assert_eq!(arts.evict_expired(&mut store, 1060).unwrap(), vec![id.clone()]);
        assert!(!arts.path(&id).exists());
        assert!(matches!(arts.read(&store, &id), Err(Error::Refused(m)) if m == "artifact-evicted"));
        let reason: String = store
            .conn()
            .query_row("SELECT reason FROM tombstones WHERE id=?1", params![id], |r| r.get(0))
            .unwrap();
        assert_eq!(reason, "retention-expired");
        // No new reference to a tombstoned artifact.
        let p = serde_json::json!({"artifact": id}).as_object().unwrap().clone();
        assert!(require_present_refs(&store, &p).is_err());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn export_gating_names_why_each_artifact_is_missing() {
        let (arts, mut store, d) = setup("e");
        let a = arts.put(&mut store, b"one", &spec(), 0).unwrap();
        let b = arts.put(&mut store, b"two", &spec(), 0).unwrap();
        let c = arts.put(&mut store, b"three", &spec(), 0).unwrap();
        arts.tombstone(&mut store, &c, "manual").unwrap();
        let g = gate(&store, &[a.clone(), c.clone()]).unwrap();
        assert_eq!(g.included.iter().map(|i| i.id.clone()).collect::<Vec<_>>(), vec![a]);
        assert!(g.omitted.contains(&(b, "payload-not-authorized")));
        assert!(g.omitted.contains(&(c, "artifact-evicted")));
        let _ = std::fs::remove_dir_all(d);
    }
}
