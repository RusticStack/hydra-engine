//! The agent's spec file: what the benchmark's driver writes per agent.
//!
//! Field names are the ones `multiagent_bench.py` already writes for its direct agents
//! (`name`, `endpoint`, `rows`, `project`, `hot`, `fresh`, `reads`, ...), so the driver that
//! runs Python agents can run Rust agents from the same shapes. A spec this port does not
//! implement (`fork`, `edit`) is refused loudly instead of silently skipped.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// One agent's work.
#[derive(Debug, Clone)]
pub(crate) struct Spec {
    /// The agent's name in every row and in the engine's `status`.
    pub(crate) name: String,
    /// The daemon endpoint file to dial (`<state>/<instance>.json`).
    pub(crate) endpoint: PathBuf,
    /// Where the rows go.
    pub(crate) rows: PathBuf,
    /// The project view to open.
    pub(crate) project: Project,
    /// Addresses decompiled after a warm call: the shared hot set.
    pub(crate) hot: Vec<String>,
    /// Addresses decompiled cold.
    pub(crate) fresh: Vec<String>,
    /// Addresses the `BenchRead.java` script reads, four per call.
    pub(crate) reads: Vec<String>,
    /// The `client` label; defaults to `name`.
    pub(crate) client: Option<String>,
    /// The `harness` label.
    pub(crate) harness: Option<String>,
    /// Per-request deadline, seconds (client side only). The benchmark's bench gives 120 s to
    /// a decompile; `None` waits without a limit, as the Python client does.
    pub(crate) deadline: Option<f64>,
    /// Decompile `maxChars`; the benchmark passes 10^7 for the agent decompiles.
    pub(crate) max_chars: u64,
    /// The decompile timeout in seconds; the benchmark passes 120.
    pub(crate) decompile_timeout_s: u64,
    /// Writes are not part of the read/query shape this runner implements.
    pub(crate) wants_writes: bool,
}

/// One project view.
#[derive(Debug, Clone)]
pub(crate) struct Project {
    /// The project name (`kotor`, `fx`), used in decompile keys.
    pub(crate) name: String,
    /// The `.gpr` path.
    pub(crate) gpr: String,
    /// The program path inside the project.
    pub(crate) program: String,
}

impl Spec {
    /// Reads a spec.
    ///
    /// # Errors
    /// The file's I/O error, or a message naming the missing or unusable field.
    pub(crate) fn read(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_value(&value)
    }

    /// Builds a spec from its JSON object.
    ///
    /// # Errors
    /// A message naming the missing or unusable field.
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        let text = |key: &str| -> Result<String, String> {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("the spec has no {key}"))
        };
        let list = |key: &str| -> Vec<String> {
            value
                .get(key)
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        let project = value
            .get("project")
            .ok_or_else(|| "the spec has no project".to_owned())?;
        let project = Project {
            name: project
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| "the spec's project has no name".to_owned())?
                .to_owned(),
            gpr: project
                .get("gpr")
                .and_then(Value::as_str)
                .ok_or_else(|| "the spec's project has no gpr".to_owned())?
                .to_owned(),
            program: project
                .get("program")
                .and_then(Value::as_str)
                .ok_or_else(|| "the spec's project has no program".to_owned())?
                .to_owned(),
        };
        Ok(Self {
            name: text("name")?,
            endpoint: PathBuf::from(text("endpoint")?),
            rows: PathBuf::from(text("rows")?),
            project,
            hot: list("hot"),
            fresh: list("fresh"),
            reads: list("reads"),
            client: value.get("client").and_then(Value::as_str).map(str::to_owned),
            harness: value.get("harness").and_then(Value::as_str).map(str::to_owned),
            deadline: value.get("deadline").and_then(Value::as_f64),
            max_chars: value
                .get("maxChars")
                .and_then(Value::as_u64)
                .unwrap_or(10_000_000),
            decompile_timeout_s: value
                .get("decompileTimeout")
                .and_then(Value::as_u64)
                .unwrap_or(120),
            wants_writes: value
                .get("fork")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || value.get("edit").is_some(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_read_spec_parses_with_the_benchmarks_field_names() {
        let spec = Spec::from_value(&json!({
            "name": "agent-00",
            "endpoint": "C:/state/rusticre.json",
            "rows": "rows/agent-00.jsonl",
            "project": {"name": "kotor", "gpr": "C:/p/kotor.gpr", "program": "/swkotor.exe"},
            "hot": ["0x401000", "0x402000"],
            "fresh": ["0x403000"],
            "reads": ["0x401000", "0x402000", "0x403000", "0x404000"],
            "harness": "bench-rust"
        }))
        .expect("a complete spec");
        assert_eq!(spec.name, "agent-00");
        assert_eq!(spec.project.name, "kotor");
        assert_eq!(spec.hot.len(), 2);
        assert_eq!(spec.reads.len(), 4);
        assert_eq!(spec.max_chars, 10_000_000);
        assert_eq!(spec.decompile_timeout_s, 120);
        assert!(!spec.wants_writes);
    }

    #[test]
    fn a_write_spec_is_recognised_so_it_is_refused_not_half_run() {
        let spec = Spec::from_value(&json!({
            "name": "a",
            "endpoint": "e.json",
            "rows": "r.jsonl",
            "project": {"name": "p", "gpr": "g", "program": "x"},
            "edit": "0x401000",
            "fork": true
        }))
        .expect("spec");
        assert!(spec.wants_writes);
    }

    #[test]
    fn a_spec_without_a_project_is_an_error_naming_the_field() {
        let e = Spec::from_value(&json!({"name": "a", "endpoint": "e", "rows": "r"}))
            .expect_err("no project");
        assert!(e.contains("project"), "{e}");
    }
}
