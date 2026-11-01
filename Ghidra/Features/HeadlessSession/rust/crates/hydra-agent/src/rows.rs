/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//! One agent's row file: the benchmark's `Rows` schema, one JSON line per operation.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hydra_client::Result;
use serde_json::{Map, Value};

/// Writes rows; `op`/`op_hashed` time the closure and record `ok`, `ms`, and the digest.
///
/// With `BENCH_SAVE_REPLIES=1` (the benchmark's `--save-replies`, for diagnosis) a hashed
/// operation also writes its hashed projection as `reply`, exactly as `multiagent_bench.Rows` does.
#[derive(Debug)]
pub(crate) struct Rows {
    agent: String,
    out: BufWriter<File>,
    save_replies: bool,
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
            save_replies: std::env::var_os("BENCH_SAVE_REPLIES").is_some_and(|v| v != "0"),
        })
    }

    /// Runs one operation and records its time and success; returns its value.
    pub(crate) fn op<T>(&mut self, name: &str, run: impl FnOnce() -> Result<T>) -> Option<T> {
        let row = self.row(name);
        let started = Instant::now();
        let result = run();
        self.finish(row, &result, None, None, started);
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
        let mut reply = None;
        let hash = match &result {
            Ok(value) => {
                let projected = project(value);
                let sha = hydra_client::digest(&projected);
                reply = Some(projected);
                Some((key, sha))
            }
            Err(e) => Some((key, format!("ERR:{}", e.code()))),
        };
        self.finish(row, &result, hash, reply, started);
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
        reply: Option<Value>,
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
        if self.save_replies
            && let Some(reply) = reply
        {
            row.insert("reply".to_owned(), reply);
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
