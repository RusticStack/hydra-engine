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
//! `hydra-agent call`: the differential harness's Rust side.
//!
//! One request per stdin line; one answer per stdout line. The answer is the engine's own line,
//! byte for byte (the session keeps raw replies), so a comparison against the Python client's
//! `call_raw` reply can be made on the exact bytes as well as on the parsed value.
//!
//! A request may carry `"deadline": <seconds>`, which is not sent: it is the client-side limit,
//! as `call(..., deadline=)` is in Python. A client-side failure (deadline, closed, incompatible)
//! is printed as a synthetic `ok:false` line with `"clientSide": true`, so the harness sees it
//! instead of a hang.

use std::io::{BufRead, Write};
use std::path::Path;

use std::sync::Arc;

use hydra_client::{ConnectOptions, Endpoint, FullDaemon, LiteMode, Session};
use serde_json::{Map, Value, json};

/// Keep each answer's raw line, or only its parsed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeepRaw {
    /// Do not keep the line (the smaller path).
    Drop,
    /// Keep the engine's exact bytes for the differential harness.
    Keep,
}

/// One request line's three parts: the command, its fields, and the client-side deadline.
type Request = (String, Map<String, Value>, Option<f64>);

/// Runs the request loop until stdin ends.
///
/// Per-request failures are answer lines; only a connection failure ends the program.
pub(crate) fn run(
    endpoint: &Path,
    client: &str,
    harness: &str,
    raw: KeepRaw,
    full_daemon: Option<Arc<dyn FullDaemon>>,
) -> std::process::ExitCode {
    let lite_mode = match LiteMode::from_env() {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("hydra-agent call: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    let options = ConnectOptions {
        client: client.to_owned(),
        harness: harness.to_owned(),
        check: true,
        hello_deadline: Some(5.0),
        keep_raw: raw == KeepRaw::Keep,
        full_daemon,
        lite_mode,
    };
    let session = match Endpoint::read_file(endpoint).and_then(|ep| Session::connect(ep, &options))
    {
        Ok(session) => session,
        Err(e) => {
            eprintln!("hydra-agent call: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut session = Some(session);
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let answer = match request(&line) {
            Ok((cmd, _request, _deadline)) if cmd == "__reconnect" => {
                // Harness control: the daemon was stopped and started again, so the endpoint
                // file names a new port and token. Re-dial and report the new protocol.
                match Endpoint::read_file(endpoint).and_then(|ep| {
                    session
                        .take()
                        .ok_or_else(hydra_client::Error::closed)?
                        .reconnect(ep, &options)
                }) {
                    Ok(fresh) => {
                        let protocol = fresh.protocol();
                        session = Some(fresh);
                        format!(
                            "{}\n",
                            json!({"ok": true, "result": {"protocol": protocol}})
                        )
                    }
                    Err(e) => client_side(&e),
                }
            }
            Ok((cmd, request, deadline)) => {
                let Some(current) = session.as_ref() else {
                    return std::process::ExitCode::FAILURE;
                };
                match current.call_raw(&cmd, request, deadline) {
                    Ok(reply) => reply
                        .raw
                        .unwrap_or_else(|| format!("{value}\n", value = reply.value)),
                    Err(e) => client_side(&e),
                }
            }
            Err(message) => format!(
                "{}\n",
                json!({"ok": false, "clientSide": true,
                       "error": {"code": "bad_request", "message": message}})
            ),
        };
        if stdout.write_all(answer.as_bytes()).is_err() {
            break;
        }
        let _ = stdout.flush();
    }
    if let Some(session) = session.take() {
        session.close();
    }
    std::process::ExitCode::SUCCESS
}

fn request(line: &str) -> Result<Request, String> {
    let value: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let Value::Object(mut object) = value else {
        return Err("a request must be a JSON object".to_owned());
    };
    let cmd = object
        .remove("cmd")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or_else(|| "a request needs a cmd".to_owned())?;
    object.remove("id");
    let deadline = object.remove("deadline").and_then(|v| v.as_f64());
    Ok((cmd, object, deadline))
}

fn client_side(e: &hydra_client::Error) -> String {
    format!(
        "{}\n",
        json!({"ok": false, "clientSide": true,
               "error": {"code": e.code(), "message": e.message(), "details": e.details()}})
    )
}

/// Connects, prints the identity, `ping` and a compact `status`, and exits.
pub(crate) fn probe(endpoint: &Path, client: &str, harness: &str) -> std::process::ExitCode {
    let options = ConnectOptions {
        client: client.to_owned(),
        harness: harness.to_owned(),
        check: true,
        hello_deadline: Some(5.0),
        keep_raw: false,
        ..ConnectOptions::default()
    };
    match Endpoint::read_file(endpoint).and_then(|ep| Session::connect(ep, &options)) {
        Ok(session) => {
            let ping = session.call("ping", Map::new(), Some(5.0));
            let status = session.call("status", Map::new(), Some(5.0));
            let summary = json!({
                "protocol": session.protocol(),
                "hello": session.hello(),
                "ping": ping.ok(),
                "lanes": status.as_ref().ok().and_then(|s| s.get("lanes")),
                "projects": status.as_ref().ok().and_then(|s| s.get("projects")),
                "clients": status.as_ref().ok().and_then(|s| s.get("clients")),
            });
            println!("{summary}");
            session.close();
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("hydra-agent probe: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
