//! The read/query agent: the operations `cmd_agent` performs before it writes anything.
//!
//! Same requests, same keys, same digests as `multiagent_bench.cmd_agent`: `open_project`,
//! `open_program`, paged `functions`, hot and fresh `decompile`, `BenchRead.java` over four
//! addresses at a time, `info` twice, `close_project`. No project writes: no overlay, no fork,
//! no `edit`/`save`. The reply identity this produces is comparable with the Python agents'
//! because both hash `decomp_hash` and the script's `output` the same way.

use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use hydra_client::session::fields;
use hydra_client::{ConnectOptions, Endpoint, Error, Session, decompile_projection};
use serde_json::{Map, Value};

use crate::rows::{Rows, write_extra};
use crate::spec::{Project, Spec};

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
    fn call(&mut self, cmd: &str, request: Map<String, Value>) -> Result<Value, Error> {
        let first = self
            .session
            .as_ref()
            .ok_or_else(|| Error::Invalid("the session was closed".to_owned()))?
            .call(cmd, request.clone(), self.deadline);
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
                self.session
                    .as_ref()
                    .ok_or_else(|| Error::Invalid("the session was closed".to_owned()))?
                    .call(cmd, request, self.deadline)
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
/// A message for the operator: a bad spec, an engine error, or a refused write shape.
pub(crate) fn run(path: &Path) -> Result<(), String> {
    let spec = Spec::read(path)?;
    if spec.wants_writes {
        return Err(format!(
            "{}: this runner implements the benchmark's read/query shape only; a spec with \
             fork/edit belongs to the Python client, which stays the default for writes",
            spec.name
        ));
    }
    let started = Instant::now();
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
    decompile_set(&mut rows, &mut caller, &spec, &program_key, "decompile_hot", &spec.hot);
    decompile_set(
        &mut rows,
        &mut caller,
        &spec,
        &program_key,
        "decompile_fresh",
        &spec.fresh,
    );
    read_scripts(&mut rows, &mut caller, &spec, &program_key);
    for _ in 0..2 {
        rows.op("info", || {
            caller.call(
                "info",
                fields([("program", Value::String(program_key.clone()))]),
            )
        });
    }
    rows.op("close_view", || {
        caller.call(
            "close_project",
            fields([("project", Value::String(project_id.clone()))]),
        )
    });
    caller.close();
    let millis = started.elapsed().as_secs_f64() * 1000.0;
    write_extra(&spec.rows, &spec.name, "agent_total", millis);
    Ok(())
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
        let row_key = format!("{}|view|{}", spec.project.name, address);
        rows.op_hashed(
            op,
            &row_key,
            || decompile(caller, program, address, spec),
            decompile_projection,
        );
    }
}

fn read_scripts(rows: &mut Rows, caller: &mut Caller, spec: &Spec, program: &str) {
    for chunk in spec.reads.chunks(4) {
        let row_key = format!("{}|read|{}", spec.project.name, chunk.join(","));
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
                            Value::Array(
                                chunk.iter().cloned().map(Value::String).collect::<Vec<_>>(),
                            ),
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
