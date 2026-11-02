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
//! The agent's spec file: what the benchmark's driver writes per agent.
//!
//! Field names are the ones `multiagent_bench.py` already writes for its direct agents
//! (`name`, `endpoint`, `rows`, `project`, `hot`, `fresh`, `reads`, ...), so the driver that
//! runs Python agents can run Rust agents from the same shapes. `edit`, `edit_sig`, `fork` and
//! `fork_dir` are the benchmark's write shape, and `plan` optionally fixes the order of the
//! read/query work (the Python agent shuffles it with its seed; the driver can hand the same
//! order to both clients). A spec this port does not implement is refused loudly instead of
//! silently skipped.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// One step of the read/query work, in the order the driver chose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanItem {
    /// `decompile_hot`, `decompile_fresh`, `read_script`, `info` or `trace_read` (the trace read
    /// workload over the session named by `arg`).
    pub(crate) op: String,
    /// The step's argument: an address, four addresses, or nothing.
    pub(crate) arg: PlanArg,
}

/// The argument of a [`PlanItem`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlanArg {
    /// No argument (`info`).
    None,
    /// One address (`decompile_hot`, `decompile_fresh`) or one trace session id (`trace_read`).
    One(String),
    /// Several addresses (`read_script`, four at a time as the benchmark does).
    Many(Vec<String>),
}

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
    /// Per-request deadline, seconds (client side only). The benchmark gives 120 s to a
    /// decompile; `None` waits without a limit, as the Python client does.
    pub(crate) deadline: Option<f64>,
    /// Decompile `maxChars`; the benchmark passes 10^7 for the agent decompiles.
    pub(crate) max_chars: u64,
    /// The decompile timeout in seconds; the benchmark passes 120.
    pub(crate) decompile_timeout_s: u64,
    /// The address the overlay and fork edits rename and comment.
    pub(crate) edit: Option<String>,
    /// The subject's signature, as the setup decompile returned it (`;` stripped).
    pub(crate) edit_sig: Option<String>,
    /// The subject's current name, replaced by the agent's tag in the fork's signature.
    pub(crate) edit_name: Option<String>,
    /// Whether this agent also forks its project, edits, saves and drops the fork.
    pub(crate) fork: bool,
    /// Where the fork goes.
    pub(crate) fork_dir: Option<PathBuf>,
    /// The read/query order, when the driver fixed it.
    pub(crate) plan: Vec<PlanItem>,
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
        let value: Value =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
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
        let plan = parse_plan(value);
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
            client: value
                .get("client")
                .and_then(Value::as_str)
                .map(str::to_owned),
            harness: value
                .get("harness")
                .and_then(Value::as_str)
                .map(str::to_owned),
            deadline: value.get("deadline").and_then(Value::as_f64),
            max_chars: value
                .get("maxChars")
                .and_then(Value::as_u64)
                .unwrap_or(10_000_000),
            decompile_timeout_s: value
                .get("decompileTimeout")
                .and_then(Value::as_u64)
                .unwrap_or(120),
            edit: value.get("edit").and_then(Value::as_str).map(str::to_owned),
            edit_sig: value
                .get("edit_sig")
                .and_then(Value::as_str)
                .map(str::to_owned),
            edit_name: value
                .get("edit_name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            fork: value.get("fork").and_then(Value::as_bool).unwrap_or(false),
            fork_dir: value
                .get("fork_dir")
                .and_then(Value::as_str)
                .map(PathBuf::from),
            plan,
        })
    }
}

/// Reads the optional `plan`: the read/query steps in the driver's order.
fn parse_plan(value: &Value) -> Vec<PlanItem> {
    value
        .get("plan")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let op = item.get("op")?.as_str()?.to_owned();
                    let arg = match item.get("arg") {
                        None | Some(Value::Null) => PlanArg::None,
                        Some(Value::String(text)) => PlanArg::One(text.clone()),
                        Some(Value::Array(items)) => PlanArg::Many(
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect(),
                        ),
                        Some(_) => return None,
                    };
                    Some(PlanItem { op, arg })
                })
                .collect()
        })
        .unwrap_or_default()
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
        assert!(!spec.fork);
        assert!(spec.edit.is_none());
        assert_eq!(spec.plan.len(), 0);
    }

    #[test]
    fn a_write_spec_carries_the_edit_subject_the_signature_and_the_fork() {
        let spec = Spec::from_value(&json!({
            "name": "a",
            "endpoint": "e.json",
            "rows": "r.jsonl",
            "project": {"name": "p", "gpr": "g", "program": "x"},
            "edit": "0x401000",
            "edit_sig": "void f(int)",
            "edit_name": "f",
            "fork": true,
            "fork_dir": "C:/forks/a"
        }))
        .expect("spec");
        assert!(spec.fork);
        assert_eq!(spec.edit.as_deref(), Some("0x401000"));
        assert_eq!(spec.edit_sig.as_deref(), Some("void f(int)"));
        assert_eq!(spec.edit_name.as_deref(), Some("f"));
        assert_eq!(
            spec.fork_dir.as_deref(),
            Some(std::path::Path::new("C:/forks/a"))
        );
    }

    #[test]
    fn a_plan_keeps_the_drivers_order_and_the_three_argument_shapes() {
        let spec = Spec::from_value(&json!({
            "name": "a",
            "endpoint": "e.json",
            "rows": "r.jsonl",
            "project": {"name": "p", "gpr": "g", "program": "x"},
            "plan": [
                {"op": "decompile_hot", "arg": "0x401000"},
                {"op": "read_script", "arg": ["0x1", "0x2", "0x3", "0x4"]},
                {"op": "info"}
            ]
        }))
        .expect("spec");
        assert_eq!(spec.plan.len(), 3);
        assert_eq!(
            spec.plan[0],
            PlanItem {
                op: "decompile_hot".to_owned(),
                arg: PlanArg::One("0x401000".to_owned())
            }
        );
        assert_eq!(
            spec.plan[1].arg,
            PlanArg::Many(vec![
                "0x1".to_owned(),
                "0x2".to_owned(),
                "0x3".to_owned(),
                "0x4".to_owned()
            ])
        );
        assert_eq!(spec.plan[2].arg, PlanArg::None);
    }

    #[test]
    fn a_trace_read_step_names_its_session() {
        let spec = Spec::from_value(&json!({
            "name": "a",
            "endpoint": "e.json",
            "rows": "r.jsonl",
            "project": {"name": "p", "gpr": "g", "program": "x"},
            "plan": [{"op": "info"}, {"op": "trace_read", "arg": "tbench0001"}]
        }))
        .expect("spec");
        assert_eq!(spec.plan[1].op, "trace_read");
        assert_eq!(spec.plan[1].arg, PlanArg::One("tbench0001".to_owned()));
    }

    #[test]
    fn a_spec_without_a_project_is_an_error_naming_the_field() {
        let e = Spec::from_value(&json!({"name": "a", "endpoint": "e", "rows": "r"}))
            .expect_err("no project");
        assert!(e.contains("project"), "{e}");
    }
}
