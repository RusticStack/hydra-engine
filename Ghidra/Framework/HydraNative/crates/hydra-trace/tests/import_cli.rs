//! The importer reports an empty file, a torn tail and a corrupt line distinctly, keeps the valid
//! prefix in every case, and streams (the report carries the peak working set).

use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hydra-import-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn line(i: u64) -> String {
    json!({"kind": "app.x", "source_id": "imp", "source_seq": i, "producer_gen": 1,
        "clock_domain": "c", "t_mono_ns": 100 + i, "confidence": "exact"})
    .to_string()
}

fn run(dir: &std::path::Path, session: &str, file: &std::path::Path) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_hydra-trace"))
        .args([
            "import",
            dir.join("root").to_str().unwrap(),
            session,
            file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let report = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out.status.code().unwrap(), report)
}

#[test]
fn empty_torn_and_corrupt_inputs_are_told_apart_and_the_valid_prefix_is_kept() {
    let dir = scratch("outcomes");
    let clean = dir.join("clean.jsonl");
    let body: String = (0..25_000).map(|i| line(i) + "\n").collect();
    std::fs::write(&clean, &body).unwrap();
    let (code, r) = run(&dir, "clean", &clean);
    assert_eq!((code, r["outcome"].as_str()), (0, Some("clean")), "{r}");
    assert_eq!(r["accepted"], 25_000);
    assert!(r["peak_working_set"].as_u64().is_some());

    let empty = dir.join("empty.jsonl");
    std::fs::write(&empty, "\n\n").unwrap();
    let (code, r) = run(&dir, "empty", &empty);
    assert_eq!((code, r["outcome"].as_str()), (4, Some("empty")), "{r}");

    let torn = dir.join("torn.jsonl");
    std::fs::write(
        &torn,
        format!("{}\n{}\n{{\"kind\":\"app.", line(0), line(1)),
    )
    .unwrap();
    let (code, r) = run(&dir, "torn", &torn);
    assert_eq!((code, r["outcome"].as_str()), (3, Some("torn_tail")), "{r}");
    assert_eq!(
        (r["accepted"].as_u64(), r["damage_line"].as_u64()),
        (Some(2), Some(3))
    );

    let corrupt = dir.join("corrupt.jsonl");
    std::fs::write(&corrupt, format!("{}\nnot json\n{}\n", line(0), line(2))).unwrap();
    let (code, r) = run(&dir, "corrupt", &corrupt);
    assert_eq!((code, r["outcome"].as_str()), (3, Some("corrupt")), "{r}");
    assert_eq!(
        (r["accepted"].as_u64(), r["damage_line"].as_u64()),
        (Some(1), Some(2))
    );
    let _ = std::fs::remove_dir_all(dir);
}
