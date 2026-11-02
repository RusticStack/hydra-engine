//! Crash tests: the importer is killed at arbitrary points of its write sequence (segment,
//! manifest, index commit). Reopening must repair the session so that the segments are clean and
//! the index equals one rebuilt from them.

use hydra_trace::session::{self, Session};
use hydra_trace::store::Options;
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hydra-crash-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn jsonl(path: &std::path::Path, events: u64) {
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    for i in 0..events {
        let line = json!({
            "kind": if i % 2 == 0 { "core.state.write" } else { "core.resource.open" },
            "source_id": "crash", "source_seq": i, "producer_gen": 1, "clock_domain": "c",
            "t_mono_ns": 1000 + i, "confidence": "exact", "process_id": 7, "thread_id": 1 + i % 4,
            "payload": {"object": i % 16, "key": "hp", "new": i % 100, "type": "file"}
        });
        writeln!(f, "{line}").unwrap();
    }
}

#[test]
fn a_killed_import_is_repaired_and_the_rebuilt_index_equals_the_original() {
    let dir = scratch("kill");
    let file = dir.join("events.jsonl");
    jsonl(&file, 400_000);
    let root = dir.join("root");
    let mut killed_mid_run = 0;
    for (round, delay_ms) in [150u64, 400, 900].into_iter().enumerate() {
        let session_id = format!("s{round}");
        let mut child = Command::new(env!("CARGO_BIN_EXE_hydra-trace"))
            .args(["import", root.to_str().unwrap(), &session_id, file.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(delay_ms));
        if child.try_wait().unwrap().is_none() {
            killed_mid_run += 1;
        }
        let _ = child.kill();
        let _ = child.wait();

        let (s, _recovery) = Session::open(&root, &session_id, Options::default()).unwrap();
        let before = s.store().digest().unwrap();
        let events = s.store().event_count().unwrap();
        drop(s);
        let v = session::verify(&root, &session_id, &Options::default()).unwrap();
        assert!(v.segments.iter().all(|c| c.clean), "{v:?}");
        assert!(v.index_matches_segments, "round {round}: {v:?}");
        assert_eq!(v.index_digest, before);
        // The repaired session accepts further appends on the same chain.
        let (mut s, _) = Session::open(&root, &session_id, Options::default()).unwrap();
        let next = s.store().event_count().unwrap();
        let r = s
            .append(&[json!({"kind": "app.after", "source_id": "crash", "source_seq": 9_000_000u64 + round as u64,
                "producer_gen": 1, "clock_domain": "c", "t_mono_ns": 5_000_000_000u64, "confidence": "exact"})])
            .unwrap();
        assert_eq!(r.accepted, 1);
        assert_eq!(s.store().event_count().unwrap(), next + 1);
        assert!(events <= 400_000);
    }
    assert!(killed_mid_run >= 1, "the importer finished before every kill; raise the event count");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn rebuild_after_losing_the_index_equals_the_original_digest() {
    let dir = scratch("lost");
    let file = dir.join("events.jsonl");
    jsonl(&file, 30_000);
    let root = dir.join("root");
    let status = Command::new(env!("CARGO_BIN_EXE_hydra-trace"))
        .args(["import", root.to_str().unwrap(), "s", file.to_str().unwrap()])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let original = {
        let r = session::reader(&root, "s").unwrap();
        r.digest().unwrap()
    };
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", session::index_path(&root.join("s")).display()));
    }
    let out = Command::new(env!("CARGO_BIN_EXE_hydra-trace"))
        .args(["rebuild", root.to_str().unwrap(), "s"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), original);
    let v = Command::new(env!("CARGO_BIN_EXE_hydra-trace"))
        .args(["verify", root.to_str().unwrap(), "s"])
        .output()
        .unwrap();
    assert!(v.status.success(), "{}", String::from_utf8_lossy(&v.stdout));
    let _ = std::fs::remove_dir_all(dir);
}
