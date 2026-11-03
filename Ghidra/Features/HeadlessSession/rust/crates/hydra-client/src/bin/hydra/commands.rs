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
//! What each subcommand asks of the daemon. A command is a short sequence on one connection:
//! `open_project`, `open_program`, then the query, because a connection's selection does not
//! outlive it. The daemon keeps the project and program warm, so repeating this is cheap.

use std::path::{Path, PathBuf};

use hydra_client::{Access, Session, fields};
use serde_json::{Map, Value, json};

use crate::args::{
    Analysis, BackendChoice as Choice, Command, Creation, Duplicates, Force, ImportArgs,
};
use crate::daemon::{self, Instance};
use crate::env::{Env, SCRIPT_NAME, Selection};
use crate::error::{CliError, Exit};

/// Marks the one line of a script's output that carries its answer.
const SCRIPT_MARK: &str = "HYDRA-CLI-JSON ";
/// The output cap asked of the `script` command; a larger answer is refused, never cut.
const SCRIPT_MAX_CHARS: u64 = 16_000_000;

/// A command's answer and who gave it.
#[derive(Debug)]
pub struct Outcome {
    /// `full`, `lite`, or `none` for commands that need no daemon.
    pub backend: &'static str,
    /// The command's result.
    pub result: Value,
}

/// Whether `hydra-lite` could answer a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Capability {
    /// The lite daemon's protocol subset covers it (`open_project`, `open_program`, `list`,
    /// `info`, `functions`).
    LiteCapable,
    /// Only the full daemon can.
    FullOnly,
}

/// Which program a script runs against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgramArg {
    /// The connection's active program.
    Active,
    /// None (the script makes a project).
    None,
}

/// Whether a command needs a program as well as a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Project,
    Program,
}

/// Runs one parsed command.
///
/// # Errors
/// Whatever the command fails with, already classified for the exit status.
pub fn run(env: &Env, command: &Command) -> Result<Outcome, CliError> {
    match command {
        Command::Status => Ok(status(env)),
        Command::Start => start(env),
        Command::Shutdown(force) => shutdown(env, *force),
        Command::Open { path, creation } => open(env, path, *creation),
        Command::Import(args) => import(env, args),
        Command::Analyze { timeout_s } => analyze(env, *timeout_s),
        Command::Info => on_program(env, Capability::LiteCapable, Scope::Program, |s| {
            call(s, env, "info", Map::new())
        }),
        Command::List {
            folder,
            limit,
            offset,
        } => on_program(env, Capability::LiteCapable, Scope::Project, |s| {
            let mut f = Map::new();
            put_text(&mut f, "folder", folder.as_deref());
            put_number(&mut f, "limit", *limit);
            put_number(&mut f, "offset", *offset);
            call(s, env, "list", f)
        }),
        Command::Functions {
            contains,
            limit,
            offset,
        } => on_program(env, Capability::LiteCapable, Scope::Program, |s| {
            let mut f = Map::new();
            put_text(&mut f, "contains", contains.as_deref());
            put_number(&mut f, "limit", *limit);
            put_number(&mut f, "offset", *offset);
            call(s, env, "functions", f)
        }),
        Command::Decompile {
            target,
            timeout_s,
            max_chars,
        } => on_program(env, Capability::FullOnly, Scope::Program, |s| {
            let mut f = Map::new();
            let key = if looks_like_address(target) {
                "address"
            } else {
                "name"
            };
            f.insert(key.to_owned(), Value::String(target.clone()));
            put_number(&mut f, "timeout", *timeout_s);
            put_number(&mut f, "maxChars", *max_chars);
            call(s, env, "decompile", f)
        }),
        Command::Script { op, target, opts } => {
            on_program(env, Capability::FullOnly, Scope::Program, |s| {
                script(s, env, op, target.as_deref(), opts)
            })
        }
        Command::Version | Command::Help => Ok(Outcome {
            backend: "none",
            result: Value::Null,
        }),
    }
}

/// Whether `s` is spelled as an address (`0x..`, `rva:..`, `va:..`, `space:offset`) rather than a
/// function name. The script applies the same rule.
#[must_use]
pub fn looks_like_address(s: &str) -> bool {
    if s.starts_with("0x") || s.starts_with("rva:") || s.starts_with("va:") {
        return true;
    }
    s.split_once(':').is_some_and(|(space, offset)| {
        !space.is_empty()
            && !offset.is_empty()
            && !space.starts_with(|c: char| c.is_ascii_digit())
            && space.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && offset.chars().all(|c| c.is_ascii_hexdigit())
    })
}

fn put_text(f: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(v) = value {
        f.insert(key.to_owned(), Value::String(v.to_owned()));
    }
}

fn put_number(f: &mut Map<String, Value>, key: &str, value: Option<u64>) {
    if let Some(v) = value {
        f.insert(key.to_owned(), Value::from(v));
    }
}

fn call(session: &Session, env: &Env, cmd: &str, f: Map<String, Value>) -> Result<Value, CliError> {
    Ok(session.call(cmd, f, Some(env.deadline_s))?)
}

fn project_of(env: &Env) -> Result<String, CliError> {
    env.selection
        .project
        .clone()
        .ok_or_else(|| CliError::no_context("no project selected"))
}

fn program_of(env: &Env) -> Result<String, CliError> {
    env.selection
        .program
        .clone()
        .ok_or_else(|| CliError::no_context("no program selected"))
}

/// A path the daemon (another process, another working directory) resolves the same way.
fn absolute(path: &str) -> String {
    std::path::absolute(path)
        .unwrap_or_else(|_| PathBuf::from(path))
        .display()
        .to_string()
}

/// Opens the selected project (and program) on `session` with `access`.
fn bootstrap(session: &Session, env: &Env, scope: Scope, access: Access) -> Result<(), CliError> {
    let project = absolute(&project_of(env)?);
    let program = match scope {
        Scope::Project => None,
        Scope::Program => Some(program_of(env)?),
    };
    session.open_project(
        &project,
        access,
        hydra_client::Discard::Keep,
        Some(env.deadline_s),
    )?;
    if let Some(program) = program {
        session.open_program(&program, None, access, None, Some(env.deadline_s))?;
    }
    Ok(())
}

/// Runs `f` against a read-only view of the selected project/program on the right daemon.
///
/// `LiteCapable` commands go to `hydra-lite` when it is running (always, with `--backend lite`,
/// which starts it); a `use_full_daemon` refusal moves the whole sequence to the full daemon.
fn on_program<F>(env: &Env, capability: Capability, scope: Scope, f: F) -> Result<Outcome, CliError>
where
    F: Fn(&Session) -> Result<Value, CliError>,
{
    let run_on = |session: &Session, access: Access| -> Result<Value, CliError> {
        bootstrap(session, env, scope, access)?;
        f(session)
    };
    if capability == Capability::FullOnly && env.backend == Choice::Lite {
        return Err(CliError::new(
            Exit::FullDaemonRequired,
            "use_full_daemon",
            "this command needs the full daemon; --backend lite was given",
        ));
    }
    if capability == Capability::LiteCapable && env.backend != Choice::Full {
        let lite = match env.backend {
            Choice::Lite => Some(daemon::attach_or_start(env, Instance::Lite)?),
            _ => daemon::attach(env, Instance::Lite)?,
        };
        if let Some(session) = lite {
            match run_on(&session, Access::ReadOnly) {
                Ok(result) => {
                    return Ok(Outcome {
                        backend: Instance::Lite.label(),
                        result,
                    });
                }
                Err(e) if e.exit == Exit::FullDaemonRequired && env.backend == Choice::Auto => {}
                Err(e) => return Err(e),
            }
        }
    }
    let session = daemon::attach_or_start(env, Instance::Full)?;
    let result = run_on(&session, Access::ReadOnly)?;
    Ok(Outcome {
        backend: Instance::Full.label(),
        result,
    })
}

/// Runs a `HydraCli.java` operation and returns its answer.
fn script(
    session: &Session,
    env: &Env,
    op: &str,
    target: Option<&str>,
    opts: &[(&'static str, String)],
) -> Result<Value, CliError> {
    let mut args = vec![op.to_owned()];
    if let Some(t) = target {
        args.push(format!("target={t}"));
    }
    args.extend(opts.iter().map(|(k, v)| format!("{k}={v}")));
    run_script(session, env, &args, ProgramArg::Active)
}

fn run_script(
    session: &Session,
    env: &Env,
    args: &[String],
    program: ProgramArg,
) -> Result<Value, CliError> {
    let mut f = fields([
        ("script", Value::String(SCRIPT_NAME.to_owned())),
        (
            "args",
            Value::Array(args.iter().cloned().map(Value::String).collect()),
        ),
        ("maxChars", Value::from(SCRIPT_MAX_CHARS)),
    ]);
    if program == ProgramArg::None {
        f.insert("program".to_owned(), Value::Null);
    }
    let reply = call(session, env, "script", f)?;
    parse_script_output(&reply)
}

/// Reads the answer line out of a `script` reply.
fn parse_script_output(reply: &Value) -> Result<Value, CliError> {
    if reply.get("truncated") == Some(&Value::Bool(true)) {
        return Err(CliError::new(
            Exit::Failed,
            "output_truncated",
            "the answer is larger than the script output cap; narrow it with --limit",
        ));
    }
    let output = reply
        .get("output")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let line = output
        .lines()
        .find_map(|l| l.strip_prefix(SCRIPT_MARK))
        .ok_or_else(|| {
            CliError::new(
                Exit::Failed,
                "script_no_answer",
                format!("the script printed no answer: {}", output.trim()),
            )
        })?;
    let answer: Value = serde_json::from_str(line).map_err(|e| {
        CliError::new(
            Exit::Failed,
            "script_bad_answer",
            format!("unreadable script answer: {e}"),
        )
    })?;
    if answer.get("ok") == Some(&Value::Bool(true)) {
        return Ok(answer.get("result").cloned().unwrap_or(Value::Null));
    }
    let error = answer.get("error").cloned().unwrap_or(Value::Null);
    let code = error
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("failed");
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("the script failed");
    let exit = match code {
        "not_found" => Exit::NotFound,
        "bad_request" => Exit::Usage,
        _ => Exit::Failed,
    };
    Err(CliError::new(exit, code, message))
}

fn project_exists(project: &str) -> bool {
    let p = Path::new(project);
    if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("gpr")) {
        p.is_file()
    } else {
        p.is_dir()
    }
}

/// Creates an empty project through the full daemon.
fn create_project(env: &Env, project: &str) -> Result<(), CliError> {
    let path = Path::new(project);
    let name = path
        .file_stem()
        .and_then(|n| n.to_str())
        .filter(|_| {
            path.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("gpr"))
        })
        .ok_or_else(|| {
            CliError::usage("a project to create must be given as <folder>/<name>.gpr")
        })?;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map_or_else(|| ".".to_owned(), |d| d.display().to_string());
    std::fs::create_dir_all(&dir).map_err(|e| {
        CliError::new(
            Exit::Failed,
            "project_dir",
            format!("cannot create {dir}: {e}"),
        )
    })?;
    let session = daemon::attach_or_start(env, Instance::Full)?;
    let args = [
        "create_project".to_owned(),
        format!("dir={}", dir.replace('\\', "/")),
        format!("name={name}"),
    ];
    run_script(&session, env, &args, ProgramArg::None).map(|_| ())
}

fn open(env: &Env, path: &str, creation: Creation) -> Result<Outcome, CliError> {
    let project = absolute(path);
    if creation == Creation::IfMissing && !project_exists(&project) {
        create_project(env, &project)?;
    }
    let selected = Env {
        selection: Selection {
            project: Some(project),
            program: env.requested_program.clone(),
        },
        ..env.clone()
    };
    let scope = if selected.selection.program.is_some() {
        Scope::Program
    } else {
        Scope::Project
    };
    let outcome = on_program(&selected, Capability::LiteCapable, scope, |s| {
        let project = s.call("project", Map::new(), Some(selected.deadline_s))?;
        let program = match scope {
            Scope::Program => Some(call(s, &selected, "info", Map::new())?),
            Scope::Project => None,
        };
        Ok(json!({"project": project, "program": program}))
    })?;
    env.remember(&selected.selection)?;
    let mut result = outcome.result;
    result["selection"] = json!({
        "project": selected.selection.project,
        "program": selected.selection.program,
        "contextFile": env.context_file.display().to_string(),
    });
    Ok(Outcome {
        backend: outcome.backend,
        result,
    })
}

fn import(env: &Env, a: &ImportArgs) -> Result<Outcome, CliError> {
    let project = absolute(&project_of(env)?);
    if !project_exists(&project) {
        create_project(env, &project)?;
    }
    let session = daemon::attach_or_start(env, Instance::Full)?;
    session.open_project(
        &project,
        Access::Writable,
        hydra_client::Discard::Keep,
        Some(env.deadline_s),
    )?;
    let mut f = Map::new();
    f.insert("file".to_owned(), Value::String(absolute(&a.file)));
    put_text(&mut f, "folder", a.folder.as_deref());
    put_text(&mut f, "name", a.name.as_deref());
    put_text(&mut f, "language", a.language.as_deref());
    put_text(&mut f, "compiler", a.compiler.as_deref());
    put_number(&mut f, "timeout", a.timeout_s);
    f.insert(
        "analyze".to_owned(),
        Value::Bool(a.analysis == Analysis::Run),
    );
    f.insert(
        "duplicate".to_owned(),
        Value::Bool(a.duplicates == Duplicates::Allow),
    );
    f.insert("wait".to_owned(), Value::from(600_000_u64));
    let result = call(&session, env, "import", f)?;
    let program = result
        .get("path")
        .or_else(|| result.pointer("/existing/0/path"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    env.remember(&Selection {
        project: Some(project),
        program: program.or_else(|| env.selection.program.clone()),
    })?;
    Ok(Outcome {
        backend: Instance::Full.label(),
        result,
    })
}

fn analyze(env: &Env, timeout_s: Option<u64>) -> Result<Outcome, CliError> {
    let session = daemon::attach_or_start(env, Instance::Full)?;
    bootstrap(&session, env, Scope::Program, Access::Writable)?;
    let mut f = Map::new();
    put_number(&mut f, "timeout", timeout_s);
    let analysis = call(&session, env, "analyze", f)?;
    let save = call(&session, env, "save", Map::new())?;
    Ok(Outcome {
        backend: Instance::Full.label(),
        result: json!({"analysis": analysis, "save": save}),
    })
}

/// Every instance a command line addresses, with its session if one is running.
fn running(env: &Env) -> Vec<(Instance, Result<Option<Session>, CliError>)> {
    [Instance::Full, Instance::Lite]
        .into_iter()
        .map(|i| (i, daemon::attach(env, i)))
        .collect()
}

fn status(env: &Env) -> Outcome {
    let mut daemons = Vec::new();
    for (instance, attached) in running(env) {
        let entry = match attached {
            Ok(Some(session)) => {
                let detail = if instance == Instance::Full {
                    call(&session, env, "status", Map::new())
                        .unwrap_or_else(|e| json!({"error": e.message}))
                } else {
                    session.hello().clone()
                };
                json!({
                    "backend": instance.label(),
                    "instance": instance.name(env),
                    "running": true,
                    "endpoint": daemon::public_endpoint(&session),
                    "detail": detail,
                })
            }
            Ok(None) => json!({
                "backend": instance.label(),
                "instance": instance.name(env),
                "running": false,
            }),
            Err(e) => json!({
                "backend": instance.label(),
                "instance": instance.name(env),
                "running": false,
                "error": {"code": e.code, "message": e.message},
            }),
        };
        daemons.push(entry);
    }
    Outcome {
        backend: "none",
        result: json!({
            "state": env.state.display().to_string(),
            "install": env.ghidra.as_ref().map(|p| p.display().to_string()),
            "selection": {"project": env.selection.project, "program": env.selection.program},
            "daemons": daemons,
        }),
    }
}

fn start(env: &Env) -> Result<Outcome, CliError> {
    let instance = if env.backend == crate::args::BackendChoice::Lite {
        Instance::Lite
    } else {
        Instance::Full
    };
    let session = daemon::attach_or_start(env, instance)?;
    Ok(Outcome {
        backend: instance.label(),
        result: json!({
            "instance": instance.name(env),
            "endpoint": daemon::public_endpoint(&session),
        }),
    })
}

fn shutdown(env: &Env, force: Force) -> Result<Outcome, CliError> {
    let mut stopped = Vec::new();
    let mut idle = Vec::new();
    let mut first_error = None;
    for (instance, attached) in running(env) {
        match attached {
            Ok(Some(session)) => {
                let mut f = Map::new();
                f.insert("force".to_owned(), Value::Bool(force == Force::Yes));
                match call(&session, env, "shutdown", f) {
                    Ok(_) => stopped.push(instance.label()),
                    Err(e) if e.code == "closed" => stopped.push(instance.label()),
                    Err(e) => first_error = first_error.or(Some(e)),
                }
            }
            Ok(None) => idle.push(instance.label()),
            Err(e) => first_error = first_error.or(Some(e)),
        }
    }
    match first_error {
        Some(e) => Err(e.with_hint("pass --force to stop a daemon other clients are connected to")),
        None => Ok(Outcome {
            backend: "none",
            result: json!({"stopped": stopped, "notRunning": idle}),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_told_from_names() {
        for a in [
            "0x140001000",
            "rva:0x1000",
            "va:0x1",
            "ram:00401000",
            "EXTERNAL:0000000d",
        ] {
            assert!(looks_like_address(a), "{a}");
        }
        for n in [
            "main",
            "FUN_140001010",
            "std::vector",
            "operator new",
            "a:b:c",
            ":12",
        ] {
            assert!(!looks_like_address(n), "{n}");
        }
    }

    #[test]
    fn a_script_answer_is_found_among_other_output() {
        let reply = json!({"output": "noise\nHYDRA-CLI-JSON {\"ok\":true,\"result\":{\"n\":1}}\n"});
        assert_eq!(parse_script_output(&reply).expect("ok"), json!({"n": 1}));
    }

    #[test]
    fn a_script_error_keeps_its_code_and_picks_the_exit() {
        let reply = json!({"output": "HYDRA-CLI-JSON {\"ok\":false,\"error\":{\"code\":\"not_found\",\"message\":\"no function named x\"}}"});
        let e = parse_script_output(&reply).expect_err("fails");
        assert_eq!((e.exit, e.code.as_str()), (Exit::NotFound, "not_found"));
        let bad = json!({"output": "HYDRA-CLI-JSON {\"ok\":false,\"error\":{\"code\":\"bad_request\",\"message\":\"m\"}}"});
        assert_eq!(
            parse_script_output(&bad).expect_err("fails").exit,
            Exit::Usage
        );
    }

    #[test]
    fn missing_or_cut_script_output_is_a_failure_not_a_guess() {
        let none = json!({"output": "just text"});
        assert_eq!(
            parse_script_output(&none).expect_err("fails").code,
            "script_no_answer"
        );
        let cut = json!({"output": "HYDRA-CLI-JSON {\"ok\":tr", "truncated": true});
        assert_eq!(
            parse_script_output(&cut).expect_err("fails").code,
            "output_truncated"
        );
        let broken = json!({"output": "HYDRA-CLI-JSON {nope"});
        assert_eq!(
            parse_script_output(&broken).expect_err("fails").code,
            "script_bad_answer"
        );
    }

    #[test]
    fn project_existence_follows_the_gpr_rule() {
        let dir = std::env::temp_dir().join(format!("hydra-exists-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let gpr = dir.join("p.gpr");
        assert!(!project_exists(&gpr.display().to_string()));
        std::fs::write(&gpr, "").expect("gpr");
        assert!(project_exists(&gpr.display().to_string()));
        assert!(project_exists(&dir.display().to_string()));
    }
}
