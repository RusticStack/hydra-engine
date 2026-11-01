//! One agent's row file: the benchmark's `Rows` schema, one JSON line per operation.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hydra_client::Result;
use serde_json::{Map, Value, json};

/// Writes rows; `op`/`op_hashed` time the closure and record `ok`, `ms`, and the digest.
#[derive(Debug)]
pub(crate) struct Rows {
    agent: String,
    out: BufWriter<File>,
}

impl Rows {
    /// Opens (appending to) the agent's row file.
    ///
    /// # Errors
    /// The file's I/O error.
    pub(crate) fn create(path: &Path, agent: &str) -> std::io::Result<Self> {
        let file = File::options().create(true).append(true).open(path)?;
        Ok(Self {
            agent: agent.to_owned(),
            out: BufWriter::new(file),
        })
    }

    /// Runs one operation and records its time and success; returns its value.
    pub(crate) fn op<T>(&mut self, name: &str, run: impl FnOnce() -> Result<T>) -> Option<T> {
        let row = self.row(name);
        let started = Instant::now();
        let result = run();
        self.finish(row, &result, None, started);
        result.ok()
    }

    /// Runs one operation, records its time, and records the reply digest under `key`: the
    /// benchmark's `hashit` (a projection for decompiles, `output` for reads).
    pub(crate) fn op_hashed<T>(
        &mut self,
        name: &str,
        key: &str,
        run: impl FnOnce() -> Result<T>,
        project: impl FnOnce(&T) -> Value,
    ) -> Option<T> {
        let row = self.row(name);
        let started = Instant::now();
        let result = run();
        let hash = match &result {
            Ok(value) => Some((key, hydra_client::digest(&project(value)))),
            Err(e) => Some((key, format!("ERR:{}", e.code()))),
        };
        self.finish(row, &result, hash, started);
        result.ok()
    }

    fn row(&self, name: &str) -> Map<String, Value> {
        let mut row = Map::new();
        row.insert("agent".to_owned(), Value::String(self.agent.clone()));
        row.insert("op".to_owned(), Value::String(name.to_owned()));
        row.insert("t".to_owned(), unix_time());
        row
    }

    fn finish<T>(
        &mut self,
        mut row: Map<String, Value>,
        result: &Result<T>,
        hash: Option<(&str, String)>,
        started: Instant,
    ) {
        match result {
            Ok(_) => {
                row.insert("ok".to_owned(), Value::Bool(true));
            }
            Err(e) => {
                row.insert("ok".to_owned(), Value::Bool(false));
                row.insert("code".to_owned(), Value::String(e.code().to_owned()));
                row.insert(
                    "msg".to_owned(),
                    Value::String(e.message().chars().take(200).collect()),
                );
            }
        }
        if let Some((key, sha)) = hash {
            row.insert("key".to_owned(), Value::String(key.to_owned()));
            row.insert("sha".to_owned(), Value::String(sha));
        }
        let millis = started.elapsed().as_secs_f64() * 1000.0;
        row.insert("ms".to_owned(), Value::from(round2(millis)));
        let _ = writeln!(self.out, "{}", Value::Object(row));
        let _ = self.out.flush();
    }
}

fn unix_time() -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    serde_json::Number::from_f64(now.as_secs_f64()).map_or(Value::Null, Value::Number)
}

/// Python's `round(x, 2)` for the millisecond field (the exact float text is not hashed).
fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// A row written outside `op` (the agent total), as the benchmark's subagents do.
pub(crate) fn write_extra(path: &Path, agent: &str, op: &str, millis: f64) {
    let Ok(mut file) = File::options().create(true).append(true).open(path) else {
        return;
    };
    let row = json!({"agent": agent, "op": op, "ok": true, "t": unix_time(),
                     "ms": round2(millis)});
    let _ = writeln!(file, "{row}");
}
