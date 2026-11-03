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
//! A session on a `hydra-lite` daemon (HYDRA-LITE.md, "Clients") against a fake lite daemon and a
//! fake full daemon. The cases are those of `examples/cc_lite.py`, which tests the Python client.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use hydra_client::session::fields;
use hydra_client::{
    ConnectOptions, Endpoint, Error, FullDaemon, LiteMode, Result, Session, USE_FULL_DAEMON,
};
use serde_json::{Value, json};

type Handler = Box<dyn Fn(&mut Value, &Value) -> Value + Send + Sync>;

/// A loopback server; `handler(connection state, request)` is the reply object for a request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Lite,
    Full,
}

struct Server {
    endpoint: Endpoint,
    requests: Arc<Mutex<Vec<Value>>>,
    connections: Arc<AtomicUsize>,
}

impl Server {
    fn start(kind: Kind, handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(handler);
        let (reqs, conns) = (Arc::clone(&requests), Arc::clone(&connections));
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                conns.fetch_add(1, Ordering::SeqCst);
                let (handler, reqs) = (Arc::clone(&handler), Arc::clone(&reqs));
                thread::spawn(move || serve(&stream, &handler, &reqs));
            }
        });
        let mut value = json!({"host": "127.0.0.1", "port": port, "token": "t", "protocol": 3,
                               "protocolMin": 2, "protocolMax": 3});
        if kind == Kind::Lite {
            value["lite"] = Value::Bool(true);
        }
        Self {
            endpoint: Endpoint::from_value(value).expect("endpoint"),
            requests,
            connections,
        }
    }

    fn cmds(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("lock")
            .iter()
            .map(|r| r["cmd"].as_str().unwrap_or("").to_owned())
            .collect()
    }

    fn requests(&self) -> Vec<Value> {
        self.requests.lock().expect("lock").clone()
    }
}

fn serve(stream: &TcpStream, handler: &Arc<Handler>, requests: &Arc<Mutex<Vec<Value>>>) {
    let mut writer = stream.try_clone().expect("clone");
    let mut conn = json!({});
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { return };
        let request: Value = serde_json::from_str(&line).expect("a request line");
        requests.lock().expect("lock").push(request.clone());
        let mut reply = handler(&mut conn, &request);
        // `_before`: an event the daemon sends ahead of the answer, with the id of the request
        if let Some(mut event) = reply.as_object_mut().and_then(|o| o.remove("_before")) {
            event["id"] = request["id"].clone();
            let _ = writeln!(writer, "{event}");
        }
        reply["id"] = request["id"].clone();
        let _ = writeln!(writer, "{reply}");
        let _ = writer.flush();
    }
}

fn hello() -> Value {
    json!({"protocol": 3, "minClient": "1.0.0", "hydraVersion": "12.3-hydra.6",
           "ghidraVersion": "12.3", "ghidra": "12.3", "protocolMin": 2, "protocolMax": 3,
           "capabilities": {}, "limits": {}, "policy": {}})
}

fn ok(result: &Value) -> Value {
    json!({"ok": true, "result": result, "ms": 0})
}

fn refusal(reason: &str, cmd: &str) -> Value {
    json!({"ok": false, "ms": 0, "error": {
        "code": USE_FULL_DAEMON, "message": format!("{cmd} is for the full daemon"),
        "details": {"reason": reason, "cmd": cmd}}})
}

/// What hydra-lite does: answers `hello`, `open_project`, `open_program`, `functions`; refuses the rest,
/// and after a refusal only ping and hello.
fn lite() -> Server {
    Server::start(
        Kind::Lite,
        Box::new(|conn, req| {
            let cmd = req["cmd"].as_str().unwrap_or("");
            if cmd == "hello" {
                let mut h = hello();
                h["source"] = json!("lite");
                return ok(&h);
            }
            if conn["diverged"] == json!(true) && cmd != "ping" {
                return refusal("diverged_connection", cmd);
            }
            match cmd {
                "ping" => ok(&json!({"pong": true})),
                "open_project" => ok(&json!({"id": "p1", "source": "lite"})),
                "open_program" => ok(&json!({"path": req["path"], "source": "lite"})),
                "functions" => ok(&json!({"source": "lite", "functions": []})),
                _ => {
                    conn["diverged"] = json!(true);
                    refusal("unsupported_command", cmd)
                }
            }
        }),
    )
}

/// The full daemon: answers everything; `open_project` hands out `ids` in turn.
fn full(ids: &[&str]) -> Server {
    let ids: Mutex<Vec<String>> = Mutex::new(ids.iter().rev().map(|s| (*s).to_owned()).collect());
    Server::start(
        Kind::Full,
        Box::new(move |_conn, req| {
            let cmd = req["cmd"].as_str().unwrap_or("");
            match cmd {
                "hello" => {
                    let mut h = hello();
                    h["source"] = json!("full");
                    ok(&h)
                }
                "open_project" => {
                    let id = ids
                        .lock()
                        .expect("lock")
                        .pop()
                        .unwrap_or_else(|| "p9".to_owned());
                    ok(&json!({"id": id, "source": "full"}))
                }
                "open_program" => {
                    let mut reply = ok(&json!({"path": req["path"], "source": "full"}));
                    reply["_before"] = json!({"event": "progress", "message": "opening"});
                    reply
                }
                _ => {
                    let mut echo = req.clone();
                    if let Some(o) = echo.as_object_mut() {
                        o.remove("id");
                        o.remove("cmd");
                    }
                    ok(&json!({"source": "full", "cmd": cmd, "echo": echo}))
                }
            }
        }),
    )
}

#[derive(Debug)]
struct Stub {
    endpoint: Result<Endpoint>,
    asked: AtomicUsize,
}

impl Stub {
    fn to(server: &Server) -> Arc<Self> {
        Arc::new(Self {
            endpoint: Ok(server.endpoint.clone()),
            asked: AtomicUsize::new(0),
        })
    }
}

impl FullDaemon for Stub {
    fn endpoint(&self) -> Result<Endpoint> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        match &self.endpoint {
            Ok(e) => Ok(e.clone()),
            Err(e) => Err(Error::Invalid(e.to_string())),
        }
    }
}

fn options(stub: &Arc<Stub>) -> ConnectOptions {
    let daemon: Arc<dyn FullDaemon> = Arc::<Stub>::clone(stub);
    let mut o = ConnectOptions::new("agent", "h").with_full_daemon(daemon);
    o.check = false;
    o
}

fn call(s: &Session, cmd: &str, f: serde_json::Map<String, Value>) -> Result<Value> {
    s.call(cmd, f, Some(30.0))
}

#[test]
fn a_refusal_moves_the_session_and_the_request_is_sent_again() {
    let (lite, full) = (lite(), full(&["p1"]));
    let stub = Stub::to(&full);
    let s = Session::connect(lite.endpoint.clone(), &options(&stub)).expect("connect");
    assert_eq!(
        call(&s, "open_project", fields([("path", json!("a.gpr"))])).unwrap()["source"],
        "lite"
    );
    call(&s, "open_program", fields([("path", json!("/a.exe"))])).unwrap();
    assert_eq!(call(&s, "functions", fields([])).unwrap()["source"], "lite");
    assert!(!s.failed_over());
    let d = call(&s, "decompile", fields([("name", json!("entry"))])).unwrap();
    assert_eq!(d["source"], "full");
    assert_eq!(d["echo"], json!({"name": "entry"}));
    assert!(s.failed_over());
    assert_eq!(stub.asked.load(Ordering::SeqCst), 1);
    assert_eq!(
        full.cmds(),
        ["hello", "open_project", "open_program", "decompile"],
        "the replay, then the request"
    );
    assert!(
        full.requests()[1].get("token").is_none(),
        "a replayed request carries no token"
    );
    let before = lite.cmds();
    assert_eq!(call(&s, "functions", fields([])).unwrap()["source"], "full");
    assert_eq!(call(&s, "info", fields([])).unwrap()["source"], "full");
    assert_eq!(lite.cmds(), before, "the lite daemon saw nothing more");
    assert_eq!(s.current_endpoint().port, full.endpoint.port);
    let ids: Vec<u64> = full
        .requests()
        .iter()
        .filter(|r| r["cmd"] == "decompile")
        .map(|r| r["id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, [5], "the request kept the id the caller got");
}

#[test]
fn project_ids_are_rewritten_when_the_full_daemon_numbers_them_differently() {
    let (lite, full) = (lite(), full(&["p7"]));
    let stub = Stub::to(&full);
    let s = Session::connect(lite.endpoint, &options(&stub)).expect("connect");
    call(&s, "open_project", fields([("path", json!("a.gpr"))])).unwrap();
    call(&s, "open_program", fields([("path", json!("/a.exe"))])).unwrap();
    call(
        &s,
        "decompile",
        fields([("program", json!("p1:/a.exe")), ("project", json!("p1"))]),
    )
    .unwrap();
    let sent = full
        .requests()
        .into_iter()
        .find(|r| r["cmd"] == "decompile")
        .unwrap();
    assert_eq!(sent["program"], "p7:/a.exe");
    assert_eq!(sent["project"], "p7");
    call(&s, "info", fields([("program", json!("p1:/a.exe"))])).unwrap();
    assert_eq!(full.requests().last().unwrap()["program"], "p7:/a.exe");
    call(&s, "info", fields([("program", json!("p2:/b.exe"))])).unwrap();
    assert_eq!(
        full.requests().last().unwrap()["program"],
        "p2:/b.exe",
        "other ids stay"
    );
}

#[test]
fn requests_in_flight_when_the_first_is_refused_are_answered_by_the_full_daemon() {
    let (lite, full) = (lite(), full(&["p1"]));
    let stub = Stub::to(&full);
    let s = Session::connect(lite.endpoint, &options(&stub)).expect("connect");
    call(&s, "open_project", fields([("path", json!("a.gpr"))])).unwrap();
    let a = s.send("decompile", fields([("name", json!("x"))])).unwrap();
    let b = s.send("journal", fields([])).unwrap();
    let (ra, rb) = (
        s.wait(a, Some(30.0)).unwrap(),
        s.wait(b, Some(30.0)).unwrap(),
    );
    assert_eq!(ra["result"]["cmd"], "decompile");
    assert_eq!(rb["result"]["cmd"], "journal");
    assert_eq!(stub.asked.load(Ordering::SeqCst), 1, "one move for both");
    assert_eq!(
        full.cmds(),
        ["hello", "open_project", "decompile", "journal"]
    );
}

#[test]
fn a_move_that_fails_returns_the_refusal_with_the_reason() {
    let lite = lite();
    let stub = Arc::new(Stub {
        endpoint: Err(Error::Invalid("no JVM".to_owned())),
        asked: AtomicUsize::new(0),
    });
    let s = Session::connect(lite.endpoint, &options(&stub)).expect("connect");
    call(&s, "open_project", fields([("path", json!("a.gpr"))])).unwrap();
    let e = call(&s, "decompile", fields([("name", json!("x"))])).unwrap_err();
    let Error::Session(se) = &e else {
        panic!("{e:?}")
    };
    assert_eq!(se.code, USE_FULL_DAEMON);
    assert!(
        se.details.to_string().contains("no JVM"),
        "{:?}",
        se.details
    );
    assert!(!s.failed_over());
    let e = call(&s, "decompile", fields([("name", json!("x"))])).unwrap_err();
    let Error::Session(se) = &e else {
        panic!("{e:?}")
    };
    assert_eq!(
        se.details["reason"], "diverged_connection",
        "the second try sees lite's own refusal"
    );
    assert_eq!(
        stub.asked.load(Ordering::SeqCst),
        1,
        "the move is tried once"
    );
}

#[test]
fn lite_mode_only_returns_the_refusal() {
    let (lite, full) = (lite(), full(&["p1"]));
    let stub = Stub::to(&full);
    let o = options(&stub).with_lite_mode(LiteMode::Only);
    let s = Session::connect(lite.endpoint, &o).expect("connect");
    let e = call(&s, "decompile", fields([("name", json!("x"))])).unwrap_err();
    let Error::Session(se) = &e else {
        panic!("{e:?}")
    };
    assert_eq!(
        (se.code.as_str(), se.details["reason"].as_str()),
        (USE_FULL_DAEMON, Some("unsupported_command"))
    );
    assert_eq!(se.details["cmd"], "decompile");
    assert_eq!(stub.asked.load(Ordering::SeqCst), 0);
    assert_eq!(e.code(), USE_FULL_DAEMON);
}

#[test]
fn without_a_full_daemon_the_refusal_is_returned() {
    let lite = lite();
    let mut o = ConnectOptions::new("agent", "h");
    o.check = false;
    let s = Session::connect(lite.endpoint, &o).expect("connect");
    let e = call(&s, "decompile", fields([("name", json!("x"))])).unwrap_err();
    let Error::Session(se) = &e else {
        panic!("{e:?}")
    };
    assert_eq!(se.code, USE_FULL_DAEMON);
}

#[test]
fn a_daemon_that_is_not_lite_is_never_moved() {
    let full = full(&["p1"]);
    let other = Server::start(
        Kind::Full,
        Box::new(|_c, req| {
            if req["cmd"] == "hello" {
                ok(&hello())
            } else {
                refusal("unsupported_command", req["cmd"].as_str().unwrap_or(""))
            }
        }),
    );
    let stub = Stub::to(&full);
    let s = Session::connect(other.endpoint, &options(&stub)).expect("connect");
    let e = call(&s, "decompile", fields([])).unwrap_err();
    assert_eq!(e.code(), USE_FULL_DAEMON);
    assert_eq!(
        stub.asked.load(Ordering::SeqCst),
        0,
        "only an endpoint marked lite arms the move"
    );
}

#[test]
fn a_full_lite_daemon_sends_the_session_to_the_full_daemon_at_connect() {
    let full = full(&["p1"]);
    // a lite daemon with all its workers busy answers the first line with no id and closes
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let mut w = stream;
        let _ = writeln!(
            w,
            "{}",
            json!({"ok": false, "ms": 0, "error": {
            "code": USE_FULL_DAEMON, "message": "64 connections are served already",
            "details": {"reason": "capacity"}}})
        );
    });
    let busy = Endpoint::from_value(
        json!({"host": "127.0.0.1", "port": port, "token": "t", "lite": true}),
    )
    .unwrap();
    let stub = Stub::to(&full);
    let s = Session::connect(busy, &options(&stub)).expect("the full daemon's session");
    assert_eq!(s.hello()["source"], "full");
    assert_eq!(stub.asked.load(Ordering::SeqCst), 1);
    assert_eq!(full.connections.load(Ordering::SeqCst), 1);
}

#[test]
fn the_mode_comes_from_the_environment_setting() {
    assert_eq!(LiteMode::parse("auto").unwrap(), LiteMode::Auto);
    assert!(LiteMode::parse("maybe").is_err());
}
