//! Export (TRACE-1): JSONL events and bundle members shaped like `evidence_bundle.py`'s folders,
//! so a bundle can carry a `traces/` member. Every file is listed in `manifest.json` with its
//! size and SHA-256 (the same `files` table), the content hash `bundle_id` leaves out volatile
//! fields, and artifact bytes are included only when separately authorized. What cannot be
//! reproduced (an artifact left out, an evicted one) is listed, never silently absent.

use crate::artifact::{self, Artifacts};
use crate::canon;
use crate::relations;
use crate::store::{Error, Result, Store};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

pub const FORMAT: &str = "hydra.trace.export/1";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn json_of(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or(Value::Null)
}

/// Write every event as one canonical JSON line, ordered by `seq`. Returns the count.
pub fn write_events_jsonl(store: &Store, out: &mut impl Write) -> Result<u64> {
    let mut stmt = store.conn().prepare(
        "SELECT seq,event_id,source_id,source_seq,producer_gen,kind,clock_domain,t_mono_ns,process_id,thread_id,
                process_gen,thread_gen,module,module_instance,va,confidence,acquisition,resource_key,state_key,corr,
                callstack,payload,t_wall_ns FROM events ORDER BY seq",
    )?;
    let mut rows = stmt.query([])?;
    let mut n = 0;
    while let Some(r) = rows.next()? {
        let mut m = Map::new();
        let put = |m: &mut Map<String, Value>, k: &str, v: Value| {
            m.insert(k.into(), v);
        };
        put(&mut m, "seq", r.get::<_, i64>(0)?.into());
        put(&mut m, "event_id", r.get::<_, String>(1)?.into());
        put(&mut m, "source_id", r.get::<_, String>(2)?.into());
        put(&mut m, "source_seq", r.get::<_, i64>(3)?.into());
        put(&mut m, "producer_gen", r.get::<_, i64>(4)?.into());
        put(&mut m, "kind", r.get::<_, String>(5)?.into());
        put(&mut m, "clock_domain", r.get::<_, String>(6)?.into());
        put(&mut m, "t_mono_ns", r.get::<_, i64>(7)?.into());
        for (i, k) in [
            (8, "process_id"),
            (9, "thread_id"),
            (10, "process_gen"),
            (11, "thread_gen"),
            (13, "module_instance"),
            (14, "va"),
            (22, "t_wall_ns"),
        ] {
            if let Some(v) = r.get::<_, Option<i64>>(i)? {
                put(&mut m, k, v.into());
            }
        }
        for (i, k) in [
            (12, "module"),
            (16, "acquisition"),
            (17, "resource_key"),
            (18, "state_key"),
            (19, "corr"),
        ] {
            if let Some(v) = r.get::<_, Option<String>>(i)? {
                put(&mut m, k, v.into());
            }
        }
        put(&mut m, "confidence", r.get::<_, String>(15)?.into());
        put(&mut m, "callstack", json_of(&r.get::<_, String>(20)?));
        put(&mut m, "payload", json_of(&r.get::<_, String>(21)?));
        let line = canon::to_vec(&Value::Object(m)).map_err(|e| Error::Refused(e.to_string()))?;
        out.write_all(&line)?;
        out.write_all(b"\n")?;
        n += 1;
    }
    Ok(n)
}

fn table_json(store: &Store, sql: &str, columns: &[&str]) -> Result<Value> {
    let mut stmt = store.conn().prepare(sql)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let mut m = Map::new();
        for (i, c) in columns.iter().enumerate() {
            let v: rusqlite::types::Value = r.get(i)?;
            m.insert(
                (*c).to_string(),
                match v {
                    rusqlite::types::Value::Null => Value::Null,
                    rusqlite::types::Value::Integer(n) => n.into(),
                    rusqlite::types::Value::Text(t) => Value::String(t),
                    rusqlite::types::Value::Real(f) => json!(f.to_string()),
                    rusqlite::types::Value::Blob(b) => Value::String(hex(&b)),
                },
            );
        }
        out.push(Value::Object(m));
    }
    Ok(Value::Array(out))
}

#[derive(Clone, Debug, Default)]
pub struct ExportOptions {
    /// Artifact ids whose bytes may leave the session. Everything else is omitted and listed.
    pub authorized_artifacts: Vec<String>,
    pub overwrite: bool,
    /// The exporter's clock, passed in so tests are exact (volatile, not part of `bundle_id`).
    pub exported_at: String,
}

#[derive(Debug, Serialize)]
pub struct ExportReport {
    pub out: String,
    pub bundle_id: String,
    pub revision: u64,
    pub events: u64,
    pub files: Vec<String>,
    pub artifacts_included: Vec<String>,
    pub not_reproducible: Vec<Value>,
}

fn json_bytes(v: &Value) -> Result<Vec<u8>> {
    let mut b = canon::to_vec(v).map_err(|e| Error::Refused(e.to_string()))?;
    b.push(b'\n');
    Ok(b)
}

/// Export `store` to the folder `out`. `artifacts` supplies authorized artifact bytes.
pub fn export(
    store: &Store,
    artifacts: Option<&Artifacts>,
    out: &Path,
    options: &ExportOptions,
) -> Result<ExportReport> {
    if out.exists() && !options.overwrite {
        return Err(Error::Refused(format!(
            "{} exists; pass overwrite to replace an export",
            out.display()
        )));
    }
    if out.exists() && !out.join("manifest.json").is_file() {
        return Err(Error::Refused(format!(
            "{} exists and is not an export folder; it is not replaced",
            out.display()
        )));
    }
    let revision = store.revision()?;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut events = Vec::new();
    let n_events = write_events_jsonl(store, &mut events)?;
    files.insert("traces/events.jsonl".into(), events);

    let (rels, _) = relations::current(store)?;
    let mut rel_bytes = Vec::new();
    for r in &rels {
        rel_bytes.extend(json_bytes(&serde_json::to_value(r)?)?);
    }
    files.insert("traces/relations.jsonl".into(), rel_bytes);

    let coverage = json!({
        "sources": table_json(store, "SELECT source_id,segment_records,state FROM sources ORDER BY source_id", &["source_id", "segment_records", "state"])?,
        "coverage_intervals": table_json(store, "SELECT source_id,state,t_start,t_end,seq_start,seq_end,reason FROM coverage_intervals ORDER BY id", &["source_id", "state", "t_start", "t_end", "seq_start", "seq_end", "reason"])?,
        "clock_domains": table_json(store, "SELECT name,source_id,unit,resolution_ns,calibrated,offset_ns,drift_ppm,uncertainty_ns,to_domain FROM clock_domains ORDER BY name", &["name", "source_id", "unit", "resolution_ns", "calibrated", "offset_ns", "drift_ppm", "uncertainty_ns", "to_domain"])?,
        "gaps": table_json(store, "SELECT source_id,reason,first_missing,last_missing,dropped,t_mono_ns,observed FROM gaps ORDER BY id", &["source_id", "reason", "first_missing", "last_missing", "dropped", "t_mono_ns", "observed"])?,
        "rejects": table_json(store, "SELECT source_id,n,reason FROM rejects ORDER BY id", &["source_id", "n", "reason"])?,
    });
    files.insert("traces/coverage.json".into(), json_bytes(&coverage)?);

    let lifetimes = json!({
        "processes": table_json(store, "SELECT pid,gen,start_seq,end_seq,end_reason,resolved FROM processes ORDER BY pid,gen", &["pid", "gen", "start_seq", "end_seq", "end_reason", "resolved"])?,
        "threads": table_json(store, "SELECT pgen,tid,gen,start_seq,end_seq,resolved FROM threads ORDER BY pgen,tid,gen", &["pgen", "tid", "gen", "start_seq", "end_seq", "resolved"])?,
        "module_instances": table_json(store, "SELECT inst,pgen,name,build,base,size,load_seq,unload_seq FROM module_instances ORDER BY inst", &["inst", "pgen", "name", "build", "base", "size", "load_seq", "unload_seq"])?,
        "objects": table_json(store, "SELECT pgen,addr,gen,type,create_seq,destroy_seq,resolved FROM objects ORDER BY pgen,addr,gen", &["pgen", "addr", "gen", "type", "create_seq", "destroy_seq", "resolved"])?,
    });
    files.insert("traces/lifetimes.json".into(), json_bytes(&lifetimes)?);

    let interp = json!({
        "interpretations": table_json(store, "SELECT rev,kind,parent,symbol_revision,codec_hash,schema_hash,context_from,context_to,note FROM interpretations ORDER BY rev", &["rev", "kind", "parent", "symbol_revision", "codec_hash", "schema_hash", "context_from", "context_to", "note"])?,
    });
    files.insert("traces/interpretations.json".into(), json_bytes(&interp)?);

    let checks = json!({
        "assertions": table_json(store, "SELECT name,rev,spec FROM assertions ORDER BY name,rev", &["name", "rev", "spec"])?,
        "results": table_json(store, "SELECT assertion,revision,verdict,checked,counterexamples,coverage,reason FROM check_results ORDER BY id", &["assertion", "revision", "verdict", "checked", "counterexamples", "coverage", "reason"])?,
    });
    files.insert("traces/checks.json".into(), json_bytes(&checks)?);
    files.insert(
        "traces/tombstones.json".into(),
        json_bytes(&table_json(
            store,
            "SELECT id,kind,reason,at_rev,sha256 FROM tombstones ORDER BY id",
            &["id", "kind", "reason", "at_rev", "sha256"],
        )?)?,
    );

    // Artifacts: only what is separately authorized leaves the session.
    let gate = artifact::gate(store, &options.authorized_artifacts)?;
    let mut included = Vec::new();
    for info in &gate.included {
        let Some(arts) = artifacts else {
            return Err(Error::Refused("no artifact store to read from".into()));
        };
        let bytes = arts.read(store, &info.id)?;
        files.insert(format!("traces/artifacts/{}.bin", info.id), bytes);
        included.push(info.id.clone());
    }
    let not_reproducible: Vec<Value> = gate
        .omitted
        .iter()
        .map(|(id, why)| json!({"artifact": id, "limitation": why}))
        .collect();
    let artifact_table = json!({
        "included": gate.included.iter().map(|i| json!({"id": i.id, "sha256": i.sha256, "size": i.size, "scope": i.scope})).collect::<Vec<_>>(),
        "omitted": not_reproducible,
    });
    files.insert("traces/artifacts.json".into(), json_bytes(&artifact_table)?);

    let pins = json!({
        "session": store.session(),
        "revision": revision,
        "index_digest": store.digest()?,
        "interpretation_revisions": table_json(store, "SELECT rev FROM interpretations ORDER BY rev", &["rev"])?,
    });
    files.insert("traces/pins.json".into(), json_bytes(&pins)?);

    let table: Map<String, Value> = files
        .iter()
        .map(|(name, data)| {
            (
                name.clone(),
                json!({"bytes": data.len(), "sha256": hex(&Sha256::digest(data))}),
            )
        })
        .collect();
    // The identity of the bundle is what it says, not when or by whom it was written.
    let bundle_id = format!(
        "tb_{}",
        hex(&Sha256::digest(canon::to_vec(&Value::Object(table.clone())).map_err(|e| Error::Refused(e.to_string()))?))
    );
    let manifest = json!({
        "format": FORMAT,
        "bundle_id": bundle_id,
        "session": store.session(),
        "revision": revision,
        "records": n_events,
        "files": Value::Object(table),
        "volatile": {"exported_at": options.exported_at, "files": []},
    });
    files.insert("manifest.json".into(), json_bytes(&manifest)?);

    // Stage, then move into place; a half-written export is never visible.
    let stage = out.with_extension(format!("{}.staging", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage);
    for (name, data) in &files {
        let path = stage.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::File::create(&path)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if out.exists() {
        std::fs::remove_dir_all(out)?;
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(&stage, out)?;
    Ok(ExportReport {
        out: out.display().to_string(),
        bundle_id,
        revision,
        events: n_events,
        files: files.keys().cloned().collect(),
        artifacts_included: included,
        not_reproducible: gate
            .omitted
            .iter()
            .map(|(id, why)| json!({"artifact": id, "limitation": why}))
            .collect(),
    })
}

/// Verify an export folder: every listed file matches its size and hash and nothing unlisted is
/// present.
pub fn verify(folder: &Path) -> Result<()> {
    let manifest: Value = serde_json::from_slice(&std::fs::read(folder.join("manifest.json"))?)?;
    if manifest.get("format").and_then(Value::as_str) != Some(FORMAT) {
        return Err(Error::Refused("not a hydra.trace.export/1 folder".into()));
    }
    let listed = manifest
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::Refused("manifest lists no files".into()))?;
    for (name, entry) in listed {
        let data = std::fs::read(folder.join(name))?;
        let want = entry.get("sha256").and_then(Value::as_str).unwrap_or("");
        if hex(&Sha256::digest(&data)) != want
            || entry.get("bytes").and_then(Value::as_u64) != Some(data.len() as u64)
        {
            return Err(Error::Refused(format!("{name} does not match the manifest")));
        }
    }
    let mut present = Vec::new();
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) -> std::io::Result<()> {
        for e in std::fs::read_dir(dir)? {
            let p = e?.path();
            if p.is_dir() {
                walk(&p, base, out)?;
            } else if let Ok(rel) = p.strip_prefix(base) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
        Ok(())
    }
    walk(folder, folder, &mut present)?;
    for name in present {
        if name != "manifest.json" && !listed.contains_key(&name) {
            return Err(Error::Refused(format!("{name} is not listed in the manifest")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactSpec;
    use crate::raw;
    use crate::synth::{self, Recipe};

    fn setup(name: &str) -> (std::path::PathBuf, Store, Artifacts) {
        let d = std::env::temp_dir().join(format!("hydra-export-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut store = Store::memory("x").unwrap();
        for s in synth::generate(Recipe::Interleave, 3, 20) {
            store
                .ingest(&s.id, 0, &raw::scan(&s.bytes, &s.id).records)
                .unwrap();
        }
        let arts = Artifacts::open(d.join("art")).unwrap();
        (d, store, arts)
    }

    fn opts() -> ExportOptions {
        ExportOptions {
            exported_at: "2026-11-01T00:00:00Z".into(),
            ..ExportOptions::default()
        }
    }

    #[test]
    fn jsonl_is_canonical_and_ordered() {
        let (d, store, _) = setup("a");
        let mut buf = Vec::new();
        let n = write_events_jsonl(&store, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(text.lines().count() as u64, n);
        let first: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first["seq"], 1);
        assert_eq!(first["event_id"], "ev_x_1");
        // keys are sorted: the line starts with the alphabetically first key
        assert!(text.starts_with("{\"callstack\""));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn export_lists_every_file_and_verifies() {
        let (d, store, arts) = setup("b");
        let out = d.join("out");
        let report = export(&store, Some(&arts), &out, &opts()).unwrap();
        assert!(report.files.contains(&"traces/events.jsonl".to_string()));
        verify(&out).unwrap();
        // tamper
        std::fs::write(out.join("traces/pins.json"), b"{}").unwrap();
        assert!(verify(&out).is_err());
        // an unlisted file is refused too
        let report2 = export(&store, Some(&arts), &out, &ExportOptions { overwrite: true, ..opts() }).unwrap();
        assert_eq!(report.bundle_id, report2.bundle_id);
        std::fs::write(out.join("extra.txt"), b"x").unwrap();
        assert!(verify(&out).is_err());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn bundle_id_ignores_volatile_fields_and_exports_are_reproducible() {
        let (d, store, arts) = setup("c");
        let a = export(&store, Some(&arts), &d.join("a"), &opts()).unwrap();
        let b = export(
            &store,
            Some(&arts),
            &d.join("b"),
            &ExportOptions { exported_at: "later".into(), ..opts() },
        )
        .unwrap();
        assert_eq!(a.bundle_id, b.bundle_id);
        for f in a.files.iter().filter(|f| *f != "manifest.json") {
            assert_eq!(std::fs::read(d.join("a").join(f)).unwrap(), std::fs::read(d.join("b").join(f)).unwrap(), "{f}");
        }
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn artifacts_are_omitted_unless_authorized_and_the_omission_is_listed() {
        let (d, mut store, arts) = setup("d");
        let spec = ArtifactSpec { scope: "packet".into(), max_bytes: 64, retention_secs: None, redact: vec![] };
        let kept = arts.put(&mut store, b"authorized bytes", &spec, 0).unwrap();
        let held = arts.put(&mut store, b"private bytes", &spec, 0).unwrap();
        let gone = arts.put(&mut store, b"gone", &spec, 0).unwrap();
        arts.tombstone(&mut store, &gone, "retention-expired").unwrap();
        let out = d.join("out");
        let r = export(
            &store,
            Some(&arts),
            &out,
            &ExportOptions { authorized_artifacts: vec![kept.clone(), gone.clone()], ..opts() },
        )
        .unwrap();
        assert_eq!(r.artifacts_included, vec![kept.clone()]);
        assert!(out.join(format!("traces/artifacts/{kept}.bin")).is_file());
        assert!(!out.join(format!("traces/artifacts/{held}.bin")).exists());
        assert!(r.not_reproducible.contains(&json!({"artifact": held, "limitation": "payload-not-authorized"})));
        assert!(r.not_reproducible.contains(&json!({"artifact": gone, "limitation": "artifact-evicted"})));
        // a payload never leaks into any other member
        for f in &r.files {
            let bytes = std::fs::read(out.join(f)).unwrap();
            if !f.starts_with("traces/artifacts/") {
                assert!(!String::from_utf8_lossy(&bytes).contains("private bytes"), "{f}");
            }
        }
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn refuses_to_replace_a_folder_that_is_not_an_export() {
        let (d, store, arts) = setup("e");
        let out = d.join("precious");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("keep.txt"), b"keep").unwrap();
        assert!(export(&store, Some(&arts), &out, &ExportOptions { overwrite: true, ..opts() }).is_err());
        assert!(export(&store, Some(&arts), &out, &opts()).is_err());
        assert!(out.join("keep.txt").is_file());
        let _ = std::fs::remove_dir_all(d);
    }
}
