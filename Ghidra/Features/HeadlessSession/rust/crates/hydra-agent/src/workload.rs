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
//! The benchmark's direct-agent shape, including its writes.
//!
//! Same requests, same keys, same digests as `multiagent_bench.cmd_agent`: `open_project`,
//! `open_program`, paged `functions`, hot and fresh `decompile`, `BenchRead.java` over four
//! addresses at a time, `info` twice, an overlay rename and plate comment with its decompile,
//! and — every second agent — a writable fork, a rename, plate comment and signature edit, its
//! decompile, a save and the fork's close. The reply identity this produces is comparable with
//! the Python agents' because both hash `decomp_hash` and the script's `output` the same way.
//!
//! The driver may hand the read/query order over in the spec's `plan`; without one, the order
//! is hot, fresh, reads, info, as this runner has always done.

use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use hydra_client::session::fields;
use hydra_client::{
    CommentKind, ConnectOptions, EditOp, Endpoint, Error, Session, decompile_projection,
};
use serde_json::{Map, Value};

use crate::rows::Rows;
use crate::spec::{PlanArg, Project, Spec};

/// A session that re-dials once when its connection ends: the daemon may have restarted
/// between two requests, and the endpoint file then names a new port and token.
struct Caller {
    session: Option<Session>,
    endpoint: PathBuf,
    options: ConnectOptions,
    deadline: Option<f64>,
    reconnected: bool,
}

impl Caller {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the request map is cloned for the reconnect retry, so the caller may pass a temporary"
    )]
    fn call(&mut self, cmd: &str, request: Map<String, Value>) -> Result<Value, Error> {
        let deadline = self.deadline;
        self.with(|session| session.call(cmd, request.clone(), deadline))
    }

    fn open_program_overlay(
        &mut self,
        path: &str,
        project: &str,
        overlay: &str,
    ) -> Result<Value, Error> {
        let deadline = self.deadline;
        self.with(|session| {
            session.open_program(
                path,
                Some(project),
                hydra_client::Access::ReadOnly,
                Some(overlay),
                deadline,
            )
        })
    }

    fn open_program_upgrading(&mut self, path: &str, project: &str) -> Result<Value, Error> {
        let deadline = self.deadline;
        self.with(|session| session.open_program_upgrading(path, Some(project), None, deadline))
    }

    fn apply_overlay(
        &mut self,
        program: &str,
        overlay: &str,
        ops: &[EditOp],
    ) -> Result<Value, Error> {
        let deadline = self.deadline;
        self.with(|session| session.apply_overlay(program, overlay, ops, deadline))
    }

    fn drop_overlay(&mut self, program: &str, overlay: &str) -> Result<Value, Error> {
        let deadline = self.deadline;
        self.with(|session| session.drop_overlay(program, overlay, deadline))
    }

    fn edit(&mut self, program: &str, ops: &[EditOp]) -> Result<Value, Error> {
        let deadline = self.deadline;
        self.with(|session| session.edit(program, ops, deadline))
    }

    fn save(&mut self, program: &str, comment: &str) -> Result<Value, Error> {
        let deadline = self.deadline;
        self.with(|session| session.save(program, Some(comment), deadline))
    }

    fn fork_project(&mut self, project: &str, path: &str) -> Result<Value, Error> {
        let deadline = self.deadline;
        self.with(|session| {
            session.fork_project(
                project,
                path,
                hydra_client::Access::Writable,
                Some(600),
                deadline,
            )
        })
    }

    fn close_project(&mut self, project: &str) -> Result<Value, Error> {
        let deadline = self.deadline;
        self.with(|session| session.close_project(Some(project), None, deadline))
    }

    fn close_project_discarding(&mut self, project: &str) -> Result<Value, Error> {
        let deadline = self.deadline;
        self.with(|session| {
            session.close_project(Some(project), Some(hydra_client::Discard::Discard), deadline)
        })
    }

    /// Runs one typed request, re-dialling once when the connection ended between requests.
    fn with<T>(
        &mut self,
        run: impl Fn(&Session) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let first = {
            let session = self
                .session
                .as_ref()
                .ok_or_else(|| Error::Invalid("the session was closed".to_owned()))?;
            run(session)
        };
        match first {
            Err(e) if is_transport(&e) && !self.reconnected => {
                self.reconnected = true;
                let endpoint = Endpoint::read_file(&self.endpoint)?;
                let options = self.options.clone();
                let old = self
                    .session
                    .take()
                    .ok_or_else(|| Error::Invalid("the session was closed".to_owned()))?;
                self.session = Some(old.reconnect(endpoint, &options)?);
                let session = self
                    .session
                    .as_ref()
                    .ok_or_else(|| Error::Invalid("the session was closed".to_owned()))?;
                run(session)
            }
            other => other,
        }
    }

    fn close(mut self) {
        if let Some(session) = self.session.take() {
            session.close();
        }
    }
}

fn is_transport(e: &Error) -> bool {
    matches!(e, Error::Io(_)) || e.code() == "closed"
}

/// Runs one agent from its spec file.
///
/// # Errors
/// A message for the operator: a bad spec, an engine error, or a missing write field.
pub(crate) fn run(path: &Path) -> Result<(), String> {
    let spec = Spec::read(path)?;
    let options = ConnectOptions {
        client: spec.client.clone().unwrap_or_else(|| spec.name.clone()),
        harness: spec.harness.clone().unwrap_or_else(|| "bench-rust".to_owned()),
        ..ConnectOptions::default()
    };
    let session = connect_retry(&spec.endpoint, &options, Duration::from_secs(30))
        .map_err(|e| format!("{}: {e}", spec.name))?;
    let mut rows = Rows::create(&spec.rows, &spec.name).map_err(|e| e.to_string())?;
    let protocol = session.protocol();
    let mut caller = Caller {
        session: Some(session),
        endpoint: spec.endpoint.clone(),
        options,
        deadline: spec.deadline,
        reconnected: false,
    };
    rows.op("connect", || Ok(protocol));

    let opened = rows.op("open_view", || open_view(&mut caller, &spec.project));
    let Some((project_id, program_key)) = opened else {
        caller.close();
        return Err(format!("{}: could not open the project view", spec.name));
    };

    rows.op("list_functions", || list_functions(&mut caller, &program_key));
    read_query(&mut rows, &mut caller, &spec, &program_key);
    overlay_round(&mut rows, &mut caller, &spec, &project_id, &program_key);
    if spec.fork {
        fork_round(&mut rows, &mut caller, &spec, &project_id);    }
    rows.op("close_view", || caller.close_project(&project_id));
    caller.close();
    Ok(())
}

/// The read/query work, in the driver's order when it gave one.
fn read_query(rows: &mut Rows, caller: &mut Caller, spec: &Spec, program: &str) {
    if spec.plan.is_empty() {
        decompile_set(rows, caller, spec, program, "decompile_hot", &spec.hot);
        decompile_set(rows, caller, spec, program, "decompile_fresh", &spec.fresh);
        for chunk in spec.reads.chunks(4) {
            read_script(rows, caller, spec, program, chunk);
        }
        for _ in 0..2 {
            info(rows, caller, program);
        }
        return;
    }
    for item in &spec.plan {
        match (item.op.as_str(), &item.arg) {
            ("decompile_hot" | "decompile_fresh", PlanArg::One(address)) => {
                decompile_one(rows, caller, spec, program, &item.op, address);
            }
            ("read_script", PlanArg::Many(addresses)) => {
                read_script(rows, caller, spec, program, addresses);
            }
            ("read_script", PlanArg::One(address)) => {
                read_script(rows, caller, spec, program, std::slice::from_ref(address));
            }
            ("info", _) => info(rows, caller, program),
            _ => {}
        }
    }
}

/// The benchmark's overlay round: open a view overlay on the shared program, rename and
/// comment the subject, decompile it through the overlay, drop it.
fn overlay_round(
    rows: &mut Rows,
    caller: &mut Caller,
    spec: &Spec,
    project: &str,
    program: &str,
) {
    let Some(subject) = spec.edit.as_deref() else {
        return;
    };
    let tag = tag(spec);
    let overlay = format!("ov-{}", spec.name);
    let opened = rows.op("overlay_open", || {
        caller.open_program_overlay(&spec.project.program, project, &overlay)
    });
    if opened.is_none() {
        return;
    }
    let ops = vec![
        EditOp::Rename {
            address: subject.to_owned(),
            name: format!("{tag}_ov"),
        },
        EditOp::Comment {
            address: subject.to_owned(),
            text: format!("bench overlay {tag}"),
            kind: CommentKind::Plate,
        },
    ];
    rows.op("overlay_edit", || caller.apply_overlay(program, &overlay, &ops));
    let key = format!("{}|overlay|{subject}|{tag}", spec.project.name);
    rows.op_hashed(
        "decompile_overlay",
        &key,
        || {
            caller.call(
                "decompile",
                fields([
                    ("program", Value::String(program.to_owned())),
                    ("overlay", Value::String(overlay.clone())),
                    ("address", Value::String(subject.to_owned())),
                    ("timeout", Value::from(120)),
                    ("maxChars", Value::from(10_000_000_u64)),
                ]),
            )
        },
        decompile_projection,
    );
    rows.op("overlay_drop", || caller.drop_overlay(program, &overlay));
}

/// The benchmark's fork round: copy the project, open the copy writable with upgrade, rename,
/// comment and re-sign the subject, decompile it, save and close the fork.
fn fork_round(rows: &mut Rows, caller: &mut Caller, spec: &Spec, project: &str) {
    let Some(subject) = spec.edit.as_deref() else {
        return;
    };
    let Some(fork_dir) = spec.fork_dir.as_deref() else {
        return;
    };
    let tag = tag(spec);
    let mut fork = Fork::default();
    let forked = rows.op("fork", || {
        let reply = caller.fork_project(project, &fork_dir.display().to_string())?;
        fork.project_id = reply
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                reply
                    .get("project")
                    .and_then(|p| p.get("id").or(Some(p)))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        let project_id = fork
            .project_id
            .as_deref()
            .ok_or_else(|| Error::BadReply("fork_project has no id".to_owned()))?;
        let opened = caller.open_program_upgrading(&spec.project.program, project_id)?;
        fork.program_key = opened
            .get("key")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Ok(reply)
    });
    if forked.is_none() {
        return;
    }
    let Some(fork_key) = fork.program_key.as_deref() else {
        return;
    };
    let mut ops = vec![
        EditOp::Rename {
            address: subject.to_owned(),
            name: tag.clone(),
        },
        EditOp::Comment {
            address: subject.to_owned(),
            text: format!("bench fork {tag}"),
            kind: CommentKind::Plate,
        },
    ];
    if let (Some(signature), Some(name)) = (spec.edit_sig.as_deref(), spec.edit_name.as_deref()) {
        let signature = strip_calling_convention(signature).replace(name, &tag);
        if !signature.is_empty() {
            ops.push(EditOp::Signature {
                address: subject.to_owned(),
                signature,
            });
        }
    }
    rows.op("edit", || caller.edit(fork_key, &ops));
    let key = format!("{}|fork|{subject}|{tag}", spec.project.name);
    rows.op_hashed(
        "decompile_edited",
        &key,
        || {
            caller.call(
                "decompile",
                fields([
                    ("program", Value::String(fork_key.to_owned())),
                    ("address", Value::String(subject.to_owned())),
                    ("timeout", Value::from(120)),
                    ("maxChars", Value::from(10_000_000_u64)),
                ]),
            )
        },
        decompile_projection,
    );
    rows.op("save", || caller.save(fork_key, &format!("bench {tag}")));
    if let Some(project_id) = fork.project_id.clone() {
        rows.op("fork_close", || caller.close_project_discarding(&project_id));
    }
}

/// The fork's ids, kept apart from the borrowed spec.
#[derive(Debug, Default)]
struct Fork {
    project_id: Option<String>,
    program_key: Option<String>,
}

fn tag(spec: &Spec) -> String {
    format!("bench_{}", spec.name.replace('-', "_"))
}

/// Python's `re.sub(r"\x08__(?:thiscall|fastcall|stdcall|cdecl|vectorcall)\x08 ?", "", sig)`.
///
/// The benchmark's raw string carries two literal backspaces (`\x08`) where a `\b` word
/// boundary was meant, so a normal signature does not match and keeps its calling convention;
/// the engine then answers `void __fastcall ...`, which is part of the benchmark's reply
/// digests. Reproduced byte for byte rather than "fixed": the Python client stays the reference.
fn strip_calling_convention(signature: &str) -> String {
    const MARKERS: [&str; 5] = [
        "\u{8}__thiscall\u{8}",
        "\u{8}__fastcall\u{8}",
        "\u{8}__stdcall\u{8}",
        "\u{8}__cdecl\u{8}",
        "\u{8}__vectorcall\u{8}",
    ];
    let mut out = String::with_capacity(signature.len());
    let mut rest = signature;
    loop {
        let best = MARKERS
            .iter()
            .filter_map(|marker| rest.find(marker).map(|at| (at, marker.len())))
            .min_by_key(|(at, _)| *at);
        if let Some((at, len)) = best {
            out.push_str(&rest[..at]);
            let after = &rest[at + len..];
            rest = after.strip_prefix(' ').unwrap_or(after);
        } else {
            out.push_str(rest);
            return out;
        }
    }
}

fn open_view(caller: &mut Caller, project: &Project) -> Result<(String, String), Error> {
    let project_id = caller.call(
        "open_project",
        fields([
            ("path", Value::String(project.gpr.clone())),
            ("writable", Value::Bool(false)),
        ]),
    )?;
    let id = project_id
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::BadReply("open_project has no id".to_owned()))?
        .to_owned();
    let program = caller.call(
        "open_program",
        fields([
            ("path", Value::String(project.program.clone())),
            ("project", Value::String(id.clone())),
            ("writable", Value::Bool(false)),
        ]),
    )?;
    let key = program
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::BadReply("open_program has no key".to_owned()))?
        .to_owned();
    Ok((id, key))
}

fn list_functions(caller: &mut Caller, program: &str) -> Result<usize, Error> {
    let mut offset = 0_u64;
    let mut total = 0_usize;
    loop {
        let page = caller.call(
            "functions",
            fields([
                ("program", Value::String(program.to_owned())),
                ("offset", Value::from(offset)),
                ("limit", Value::from(1000)),
            ]),
        )?;
        if let Some(items) = page.get("functions").and_then(Value::as_array) {
            total += items.len();
        }
        if page.get("truncated") != Some(&Value::Bool(true)) {
            return Ok(total);
        }
        let returned = page.get("returned").and_then(Value::as_u64).unwrap_or(0);
        if returned == 0 {
            return Err(Error::BadReply(
                "a functions page is truncated but returned nothing".to_owned(),
            ));
        }
        offset += returned;
    }
}

fn decompile_set(
    rows: &mut Rows,
    caller: &mut Caller,
    spec: &Spec,
    program: &str,
    op: &str,
    addresses: &[String],
) {
    for address in addresses {
        decompile_one(rows, caller, spec, program, op, address);
    }
}

fn decompile_one(
    rows: &mut Rows,
    caller: &mut Caller,
    spec: &Spec,
    program: &str,
    op: &str,
    address: &str,
) {
    let row_key = format!("{}|view|{}", spec.project.name, address);
    rows.op_hashed(
        op,
        &row_key,
        || decompile(caller, program, address, spec),
        decompile_projection,
    );
}

fn info(rows: &mut Rows, caller: &mut Caller, program: &str) {
    rows.op("info", || {
        caller.call(
            "info",
            fields([("program", Value::String(program.to_owned()))]),
        )
    });
}

fn read_script(
    rows: &mut Rows,
    caller: &mut Caller,
    spec: &Spec,
    program: &str,
    addresses: &[String],
) {
    let row_key = format!("{}|read|{}", spec.project.name, addresses.join(","));
    rows.op_hashed(
        "read_script",
        &row_key,
        || {
            let output = caller.call(
                "script",
                fields([
                    ("script", Value::String("BenchRead.java".to_owned())),
                    (
                        "args",
                        Value::Array(addresses.iter().cloned().map(Value::String).collect()),
                    ),
                    ("program", Value::String(program.to_owned())),
                    ("timeout", Value::from(120)),
                ]),
            )?;
            Ok(output
                .get("output")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned())
        },
        |output: &String| Value::String(output.clone()),
    );
}

fn decompile(
    caller: &mut Caller,
    program: &str,
    address: &str,
    spec: &Spec,
) -> Result<Value, Error> {
    caller.call(
        "decompile",
        fields([
            ("program", Value::String(program.to_owned())),
            ("address", Value::String(address.to_owned())),
            ("timeout", Value::from(spec.decompile_timeout_s)),
            ("maxChars", Value::from(spec.max_chars)),
        ]),
    )
}

/// Dials the endpoint, retrying while the daemon is still starting, until `budget` passes.
///
/// # Errors
/// The last connect error, or the endpoint file's, when the budget is spent.
fn connect_retry(
    endpoint: &Path,
    options: &ConnectOptions,
    budget: Duration,
) -> Result<Session, Error> {
    let end = Instant::now() + budget;
    loop {
        let attempt = Endpoint::read_file(endpoint).and_then(|ep| Session::connect(ep, options));
        match attempt {
            Ok(session) => return Ok(session),
            Err(e) => {
                if Instant::now() >= end {
                    return Err(e);
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Keeps the test build's imports honest when the plan types are only used behind branches.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{PlanArg, PlanItem};

    fn spec(plan: Vec<PlanItem>) -> Spec {
        Spec {
            name: "agent-02".to_owned(),
            endpoint: PathBuf::from("e.json"),
            rows: PathBuf::from("r.jsonl"),
            project: Project {
                name: "fx".to_owned(),
                gpr: "g".to_owned(),
                program: "x".to_owned(),
            },
            hot: Vec::new(),
            fresh: Vec::new(),
            reads: Vec::new(),
            client: None,
            harness: None,
            deadline: None,
            max_chars: 1,
            decompile_timeout_s: 1,
            edit: None,
            edit_sig: None,
            edit_name: None,
            fork: false,
            fork_dir: None,
            plan,
        }
    }

    #[test]
    fn the_tag_and_overlay_match_the_python_agents() {
        let s = spec(Vec::new());
        assert_eq!(tag(&s), "bench_agent_02");
        assert_eq!(format!("ov-{}", s.name), "ov-agent-02");
    }

    #[test]
    fn a_normal_signature_keeps_its_calling_convention_as_the_benchmark_does() {
        // The benchmark's regex has literal backspaces, so it matches nothing here; the Python
        // agent's signature op carries `__fastcall` and the engine keeps it. Same for Rust.
        assert_eq!(
            strip_calling_convention("void __thiscall Foo::bar(int)"),
            "void __thiscall Foo::bar(int)"
        );
        assert_eq!(
            strip_calling_convention("int __cdecl f(void)"),
            "int __cdecl f(void)"
        );
        assert_eq!(strip_calling_convention("void f()"), "void f()");
    }

    #[test]
    fn a_signature_with_literal_backspaces_is_rewritten_the_way_pythons_regex_would() {
        assert_eq!(
            strip_calling_convention("void \u{8}__fastcall\u{8} f(int)"),
            "void f(int)"
        );
        assert_eq!(
            strip_calling_convention("void \u{8}__thiscall\u{8}f(int)"),
            "void f(int)"
        );
    }

    #[test]
    fn a_plan_item_keeps_its_argument_shape() {
        let item = PlanItem {
            op: "read_script".to_owned(),
            arg: PlanArg::Many(vec!["0x1".to_owned()]),
        };
        assert_eq!(item.arg, PlanArg::Many(vec!["0x1".to_owned()]));
    }
}
