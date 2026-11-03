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
//! The `hydra` command line against fake daemons: exit codes, the JSON contract, the request
//! sequences, the lite-first routing and the fall-back on `use_full_daemon`. No JVM is involved;
//! the real thing is exercised by the lane's measured run, see `CLI.md`.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{Value, json};

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

/// What a fake daemon does with a request other than `hello`: an answer or `(code, message)`.
type Reply = Result<Value, (&'static str, &'static str)>;
type Script = Arc<dyn Fn(&Value) -> Reply + Send + Sync>;

/// A loopback daemon that logs every request it is sent.
struct Fake {
    log: Arc<Mutex<Vec<Value>>>,
}

impl Fake {
    fn start(state: &Path, instance: &str, script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let port = listener.local_addr().expect("address").port();
        std::fs::write(
            state.join(format!("{instance}.json")),
            json!({"host": "127.0.0.1", "port": port, "token": "t0k", "instance": instance})
                .to_string(),
        )
        .expect("endpoint file");
        let log = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&log);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let seen = Arc::clone(&seen);
                let script = Arc::clone(&script);
                thread::spawn(move || serve(stream, &seen, &script));
            }
        });
        Self { log }
    }

    fn cmds(&self) -> Vec<String> {
        self.log
            .lock()
            .expect("log")
            .iter()
            .map(|r| r["cmd"].as_str().unwrap_or("").to_owned())
            .collect()
    }

    fn request(&self, cmd: &str) -> Value {
        self.log
            .lock()
            .expect("log")
            .iter()
            .find(|r| r["cmd"] == cmd)
            .cloned()
            .unwrap_or_else(|| panic!("no {cmd} request was sent"))
    }
}

fn serve(stream: TcpStream, seen: &Mutex<Vec<Value>>, script: &Script) {
    let mut writer = stream.try_clone().expect("write half");
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { return };
        let request: Value = serde_json::from_str(&line).expect("a JSON request");
        seen.lock().expect("log").push(request.clone());
        let id = request["id"].clone();
        let answer = if request["cmd"] == "hello" {
            json!({"id": id, "ok": true, "ms": 0, "result": {
                "protocol": 3, "protocolMin": 2, "protocolMax": 3, "minClient": "1.0.0",
                "hydraVersion": "12.3-hydra.7", "ghidraVersion": "12.3"}})
        } else {
            match script(&request) {
                Ok(result) => json!({"id": id, "ok": true, "ms": 1, "result": result}),
                Err((code, message)) => json!({"id": id, "ok": false, "ms": 0,
                    "error": {"code": code, "message": message, "details": {}}}),
            }
        };
        if writeln!(writer, "{answer}").is_err() {
            return;
        }
    }
}

/// A daemon that opens everything and answers queries with canned text.
fn friendly() -> Script {
    Arc::new(|r: &Value| match r["cmd"].as_str().unwrap_or("") {
        "open_project" => Ok(json!({"id": "p1", "writable": r["writable"]})),
        "project" => Ok(json!({"id": "p1", "name": "T"})),
        "open_program" => Ok(json!({"key": "p1:/a.exe"})),
        "info" => Ok(json!({"key": "p1:/a.exe", "functions": 3})),
        "functions" => Ok(
            json!({"functions": [{"address": "0x1000", "name": "main", "size": 9}],
                                  "truncated": false}),
        ),
        "decompile" => Ok(json!({"c": "int main(void) { return 0; }\n", "name": "main"})),
        "script" => Ok(script_output(r)),
        "shutdown" => Ok(json!({"stopping": true})),
        other => panic!("the fake daemon was sent {other}"),
    })
}

fn script_output(r: &Value) -> Value {
    let args = r["args"].as_array().expect("script args");
    let op = args[0].as_str().expect("op");
    let target = args.get(1).and_then(Value::as_str).unwrap_or("");
    let line = if target == "target=missing" {
        r#"HYDRA-CLI-JSON {"ok":false,"error":{"code":"not_found","message":"no function named missing"}}"#
            .to_owned()
    } else {
        format!(
            r#"HYDRA-CLI-JSON {{"ok":true,"result":{{"op":"{op}","args":{}}}}}"#,
            json!(args)
        )
    };
    json!({"output": format!("log noise\n{line}\n"), "truncated": false})
}

struct Lane {
    state: PathBuf,
    context: PathBuf,
}

impl Lane {
    fn new(name: &str) -> Self {
        let n = NEXT_DIR.fetch_add(1, Ordering::SeqCst);
        let state =
            std::env::temp_dir().join(format!("hydra-cli-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        std::fs::create_dir_all(&state).expect("state dir");
        let context = state.join("context.json");
        Self { state, context }
    }

    fn hydra(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hydra"))
            .args(args)
            .env("HYDRA_STATE", &self.state)
            .env("HYDRA_CONTEXT", &self.context)
            .env_remove("HYDRA_PROJECT")
            .env_remove("HYDRA_PROGRAM")
            .env_remove("HYDRA_GHIDRA")
            .env_remove("GHIDRA_INSTALL_DIR")
            .env_remove("HYDRA_LITE")
            .arg("--no-start")
            .output()
            .expect("hydra runs")
    }
}

fn json_of(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is one JSON object ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("exit code")
}

const SELECT: [&str; 4] = ["--project", "C:/p/T.gpr", "--program", "/a.exe"];

fn with_select<'a>(rest: &[&'a str]) -> Vec<&'a str> {
    SELECT.iter().chain(rest.iter()).copied().collect()
}

#[test]
fn info_opens_the_project_and_program_read_only_then_asks() {
    let lane = Lane::new("info");
    let full = Fake::start(&lane.state, "hydra", friendly());
    let out = lane.hydra(&with_select(&["info"]));
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stdout));
    let v = json_of(&out);
    assert_eq!(
        (v["ok"].clone(), v["backend"].clone()),
        (json!(true), json!("full"))
    );
    assert_eq!(v["result"]["functions"], 3);
    assert_eq!(
        full.cmds(),
        ["hello", "open_project", "open_program", "info"]
    );
    assert_eq!(full.request("open_project")["writable"], false);
    assert_eq!(full.request("open_program")["path"], "/a.exe");
    assert!(
        full.request("open_project")["path"]
            .as_str()
            .expect("path")
            .ends_with("T.gpr"),
        "the project path is sent as given, made absolute"
    );
}

#[test]
fn decompile_sends_an_address_or_a_name() {
    let lane = Lane::new("decomp");
    let full = Fake::start(&lane.state, "hydra", friendly());
    let by_name = lane.hydra(&with_select(&["decompile", "main", "--timeout", "7"]));
    assert_eq!(code(&by_name), 0);
    let by_address = lane.hydra(&with_select(&["decompile", "0x1000", "--max-chars", "50"]));
    assert_eq!(code(&by_address), 0);
    let log = full.log.lock().expect("log");
    let decompiles: Vec<&Value> = log.iter().filter(|r| r["cmd"] == "decompile").collect();
    assert_eq!(decompiles.len(), 2);
    assert_eq!(
        (&decompiles[0]["name"], &decompiles[0]["timeout"]),
        (&json!("main"), &json!(7))
    );
    assert!(decompiles[0].get("address").is_none());
    assert_eq!(
        (&decompiles[1]["address"], &decompiles[1]["maxChars"]),
        (&json!("0x1000"), &json!(50))
    );
}

#[test]
fn text_mode_prints_the_c_and_nothing_else() {
    let lane = Lane::new("text");
    let _full = Fake::start(&lane.state, "hydra", friendly());
    let out = lane.hydra(&with_select(&["--text", "decompile", "main"]));
    assert_eq!(code(&out), 0);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "int main(void) { return 0; }\n"
    );
}

#[test]
fn script_commands_pass_their_options_and_unwrap_the_answer() {
    let lane = Lane::new("script");
    let full = Fake::start(&lane.state, "hydra", friendly());
    let out = lane.hydra(&with_select(&[
        "xrefs",
        "main",
        "--direction",
        "from",
        "--limit",
        "5",
    ]));
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stdout));
    let v = json_of(&out);
    assert_eq!(v["command"], "xrefs");
    assert_eq!(
        v["result"]["args"],
        json!(["xrefs", "target=main", "direction=from", "limit=5"])
    );
    let request = full.request("script");
    assert_eq!(request["script"], "HydraCli.java");
    assert!(
        request.get("program").is_none(),
        "the active program is used"
    );
}

#[test]
fn a_script_not_found_is_exit_3_with_its_message() {
    let lane = Lane::new("scriptnf");
    let _full = Fake::start(&lane.state, "hydra", friendly());
    let out = lane.hydra(&with_select(&["callers", "missing"]));
    assert_eq!(code(&out), 3);
    let v = json_of(&out);
    assert_eq!(
        (v["ok"].clone(), v["exit"].clone()),
        (json!(false), json!(3))
    );
    assert_eq!(v["error"]["code"], "not_found");
    assert!(
        v["error"]["message"]
            .as_str()
            .expect("message")
            .contains("missing")
    );
}

#[test]
fn engine_errors_map_to_exit_codes() {
    let cases: [(&'static str, i32); 5] = [
        ("not_found", 3),
        ("busy", 5),
        ("read_only", 8),
        ("no_program", 7),
        ("failed", 1),
    ];
    for (engine_code, want) in cases {
        let lane = Lane::new("errors");
        let _full = Fake::start(
            &lane.state,
            "hydra",
            Arc::new(move |r: &Value| match r["cmd"].as_str().unwrap_or("") {
                "open_project" => Ok(json!({"id": "p1"})),
                "open_program" => Ok(json!({})),
                _ => Err((engine_code, "refused")),
            }),
        );
        let out = lane.hydra(&with_select(&["info"]));
        assert_eq!(code(&out), want, "engine code {engine_code}");
        assert_eq!(json_of(&out)["error"]["code"], engine_code);
    }
}

#[test]
fn without_a_selection_nothing_is_contacted_and_the_exit_is_7() {
    let lane = Lane::new("nocontext");
    let full = Fake::start(&lane.state, "hydra", friendly());
    let out = lane.hydra(&["info"]);
    assert_eq!(code(&out), 7);
    let v = json_of(&out);
    assert_eq!(v["error"]["code"], "no_context");
    assert!(
        v["error"]["hint"]
            .as_str()
            .expect("hint")
            .contains("hydra open")
    );
    assert!(
        full.cmds().len() <= 1,
        "at most the attach hello: {:?}",
        full.cmds()
    );
    assert!(!full.cmds().contains(&"open_project".to_owned()));
}

#[test]
fn no_daemon_and_no_start_is_exit_4() {
    let lane = Lane::new("nodaemon");
    let out = lane.hydra(&with_select(&["info"]));
    assert_eq!(code(&out), 4);
    assert_eq!(json_of(&out)["error"]["code"], "no_daemon");
}

#[test]
fn usage_errors_are_exit_2_and_still_json() {
    let lane = Lane::new("usage");
    for args in [
        &["frobnicate"][..],
        &["info", "--bogus"],
        &["functions", "--limit", "x"],
        &[],
    ] {
        let out = lane.hydra(args);
        assert_eq!(code(&out), 2, "{args:?}");
        assert_eq!(json_of(&out)["ok"], false);
    }
}

#[test]
fn help_and_version_need_no_daemon() {
    let lane = Lane::new("help");
    let help = lane.hydra(&["help"]);
    assert_eq!(code(&help), 0);
    assert!(String::from_utf8_lossy(&help.stdout).contains("exit codes:"));
    let version = lane.hydra(&["version"]);
    assert_eq!(code(&version), 0);
    assert_eq!(json_of(&version)["result"]["protocol"], 3);
}

#[test]
fn open_remembers_the_selection_for_the_next_command() {
    let lane = Lane::new("open");
    let full = Fake::start(&lane.state, "hydra", friendly());
    let out = lane.hydra(&["open", "C:/p/T.gpr", "--program", "/a.exe"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(json_of(&out)["result"]["selection"]["program"], "/a.exe");
    let next = lane.hydra(&["functions", "--contains", "ma", "--limit", "5"]);
    assert_eq!(code(&next), 0, "{}", String::from_utf8_lossy(&next.stdout));
    let request = full.request("functions");
    assert_eq!(
        (&request["contains"], &request["limit"]),
        (&json!("ma"), &json!(5))
    );
}

#[test]
fn lite_answers_read_only_queries_when_it_is_running() {
    let lane = Lane::new("lite");
    let full = Fake::start(&lane.state, "hydra", friendly());
    let lite = Fake::start(&lane.state, "hydra-lite", friendly());
    let out = lane.hydra(&with_select(&["info"]));
    assert_eq!(code(&out), 0);
    assert_eq!(json_of(&out)["backend"], "lite");
    assert_eq!(
        lite.cmds(),
        ["hello", "open_project", "open_program", "info"]
    );
    assert!(
        full.cmds().is_empty(),
        "the full daemon was not touched: {:?}",
        full.cmds()
    );
}

#[test]
fn a_use_full_daemon_refusal_moves_the_whole_sequence_to_the_full_daemon() {
    let lane = Lane::new("refusal");
    let full = Fake::start(&lane.state, "hydra", friendly());
    let lite = Fake::start(
        &lane.state,
        "hydra-lite",
        Arc::new(|r: &Value| match r["cmd"].as_str().unwrap_or("") {
            "open_project" => Ok(json!({"id": "p1"})),
            "open_program" => Ok(json!({})),
            _ => Err(("use_full_daemon", "not served here")),
        }),
    );
    let out = lane.hydra(&with_select(&["functions"]));
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(json_of(&out)["backend"], "full");
    assert_eq!(
        lite.cmds(),
        ["hello", "open_project", "open_program", "functions"]
    );
    assert_eq!(
        full.cmds(),
        ["hello", "open_project", "open_program", "functions"]
    );
}

#[test]
fn commands_lite_cannot_answer_skip_it_and_a_forced_lite_is_exit_9() {
    let lane = Lane::new("fullonly");
    let full = Fake::start(&lane.state, "hydra", friendly());
    let lite = Fake::start(&lane.state, "hydra-lite", friendly());
    let out = lane.hydra(&with_select(&["decompile", "main"]));
    assert_eq!(code(&out), 0);
    assert_eq!(json_of(&out)["backend"], "full");
    assert!(lite.cmds().is_empty(), "{:?}", lite.cmds());
    let forced = lane.hydra(&with_select(&["--backend", "lite", "decompile", "main"]));
    assert_eq!(code(&forced), 9);
    assert_eq!(json_of(&forced)["error"]["code"], "use_full_daemon");
    assert_eq!(full.cmds().iter().filter(|c| *c == "decompile").count(), 1);
}

#[test]
fn backend_full_ignores_a_running_lite_daemon() {
    let lane = Lane::new("forcefull");
    let _full = Fake::start(&lane.state, "hydra", friendly());
    let lite = Fake::start(&lane.state, "hydra-lite", friendly());
    let out = lane.hydra(&with_select(&["--backend", "full", "info"]));
    assert_eq!(json_of(&out)["backend"], "full");
    assert_eq!(lite.cmds().len(), 0, "lite was not asked");
}

#[test]
fn shutdown_stops_every_running_daemon_and_passes_force() {
    let lane = Lane::new("shutdown");
    let full = Fake::start(&lane.state, "hydra", friendly());
    let lite = Fake::start(&lane.state, "hydra-lite", friendly());
    let out = lane.hydra(&["shutdown", "--force"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(json_of(&out)["result"]["stopped"], json!(["full", "lite"]));
    assert_eq!(full.request("shutdown")["force"], true);
    assert_eq!(lite.request("shutdown")["force"], true);
}

#[test]
fn shutdown_with_nothing_running_is_a_success() {
    let lane = Lane::new("shutdown-none");
    let out = lane.hydra(&["shutdown"]);
    assert_eq!(code(&out), 0);
    assert_eq!(
        json_of(&out)["result"]["notRunning"],
        json!(["full", "lite"])
    );
}

#[test]
fn status_starts_nothing_and_reports_what_runs() {
    let lane = Lane::new("status");
    let out = lane.hydra(&["status"]);
    assert_eq!(code(&out), 0);
    let v = json_of(&out);
    assert_eq!(v["result"]["daemons"][0]["running"], false);
    assert_eq!(v["result"]["daemons"][1]["running"], false);
}
