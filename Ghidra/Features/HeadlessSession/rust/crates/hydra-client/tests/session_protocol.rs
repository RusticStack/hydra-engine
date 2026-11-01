//! The client against a fake engine: the observable behaviour of `ghidra_session.SocketSession`
//! and `_Base`, test by test. The fake engine is the one `examples/client_compat_tests.py` uses
//! (`FakeEngine`), with the same answers: a `hello` answered by a rule and every other command
//! with `{"cmd": <name>}`.

use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hydra_client::error::code;
use hydra_client::session::fields;
use hydra_client::{
    Access, CommentKind, ConnectOptions, Discard, EditOp, Endpoint, Session, SessionError,
};
use serde_json::{Map, Value, json};

type Handler = Box<dyn FnMut(&Value, &mut ReplyWriter) + Send>;

/// Writes protocol lines to one connection.
struct ReplyWriter(BufWriter<TcpStream>);

impl ReplyWriter {
    #[expect(clippy::needless_pass_by_value, reason = "the fake builds one value per answer")]
    fn response(&mut self, id: &Value, result: Value) {
        self.line(&json!({"id": id, "ok": true, "result": result, "ms": 0}));
    }

    #[expect(clippy::needless_pass_by_value, reason = "the fake builds one value per answer")]
    fn error(&mut self, id: &Value, error: Value) {
        self.line(&json!({"id": id, "ok": false, "error": error, "ms": 0}));
    }

    fn line(&mut self, value: &Value) {
        let _ = writeln!(self.0, "{value}");
        let _ = self.0.flush();
    }

    fn raw(&mut self, text: &str) {
        let _ = self.0.write_all(text.as_bytes());
        let _ = self.0.flush();
    }

    fn shutdown(&mut self) {
        let _ = self.0.get_ref().shutdown(std::net::Shutdown::Both);
        let _ = self.0.flush();
    }
}

struct FakeEngine {
    endpoint: Endpoint,
    requests: Arc<Mutex<Vec<Value>>>,
    closed: Arc<AtomicUsize>,
    listener: TcpListener,
}

impl FakeEngine {
    fn start(handler: Handler) -> Self {
        Self::start_with_token("x", handler)
    }

    fn start_with_token(token: &str, mut handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let address = listener.local_addr().expect("the bound address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicUsize::new(0));
        let endpoint = Endpoint::from_value(json!({
            "host": "127.0.0.1",
            "port": address.port(),
            "token": token,
        }))
        .expect("a complete endpoint");
        let seen = Arc::clone(&requests);
        let close_count = Arc::clone(&closed);
        let accept = listener.try_clone().expect("a listener clone");
        thread::spawn(move || {
            let Ok((stream, _)) = accept.accept() else {
                return;
            };
            let reader = BufReader::new(stream.try_clone().expect("a read half"));
            let mut writer = ReplyWriter(BufWriter::new(stream));
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let Ok(request) = serde_json::from_str::<Value>(&line) else {
                    break;
                };
                seen.lock().expect("the request log").push(request.clone());
                handler(&request, &mut writer);
            }
            close_count.fetch_add(1, Ordering::SeqCst);
        });
        Self {
            endpoint,
            requests,
            closed,
            listener,
        }
    }

    fn hellos(&self) -> Vec<Value> {
        self.requests
            .lock()
            .expect("the request log")
            .iter()
            .filter(|r| r["cmd"] == "hello")
            .cloned()
            .collect()
    }

    fn requests(&self) -> Vec<Value> {
        self.requests.lock().expect("the request log").clone()
    }

    fn wait_closed(&self, count: usize) {
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            if self.closed.load(Ordering::SeqCst) >= count {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("the fake engine did not see {count} close(s)");
    }
}

impl Drop for FakeEngine {
    fn drop(&mut self) {
        // Shutting the listener down unblocks an accept thread no client ever joined.
        let _ = self.listener.set_nonblocking(true);
        let _ = TcpStream::connect(format!(
            "{}:{}",
            self.endpoint.host, self.endpoint.port
        ));
    }
}

fn v2_answer(_request: &Value) -> Value {
    json!({"protocol": 2, "minClient": "1.0.0", "hydraVersion": "12.3-hydra.3",
           "ghidraVersion": "12.3", "ghidra": "12.3"})
}

fn v3_answer(request: &Value) -> Value {
    let protocol = hydra_client::requested_protocol(request);
    let mut out = json!({"protocol": protocol, "minClient": "1.0.0",
                         "hydraVersion": "12.3-hydra.4", "ghidraVersion": "12.3"});
    if protocol == 3
        && let Some(map) = out.as_object_mut()
    {
        map.insert("protocolMin".to_owned(), json!(2));
        map.insert("protocolMax".to_owned(), json!(3));
    }
    out
}

fn hello_or_cmd(answer: fn(&Value) -> Value) -> Handler {
    Box::new(move |request: &Value, writer: &mut ReplyWriter| {
        let id = &request["id"];
        if request["cmd"] == "hello" {
            writer.response(id, answer(request));
        } else {
            writer.response(id, json!({"cmd": request["cmd"]}));
        }
    })
}

fn connect(engine: &FakeEngine) -> Session {
    Session::connect(engine.endpoint.clone(), &ConnectOptions::new("cc", "tests"))
        .expect("the hello is accepted")
}

// Ported from `t_fake_v2_server`.
#[test]
fn fake_v2_server_is_asked_for_3_and_the_session_says_2() {
    let engine = FakeEngine::start(hello_or_cmd(v2_answer));
    let session = connect(&engine);
    let hellos = engine.hellos();
    assert_eq!(hellos.len(), 1, "one hello");
    assert_eq!(hellos[0]["protocol"], json!(3));
    assert_eq!(hellos[0]["clientVersion"], json!("1.1.0"));
    assert_eq!(hellos[0]["client"], json!("cc"));
    assert_eq!(hellos[0]["harness"], json!("tests"));
    assert_eq!(hellos[0]["token"], json!("x"));
    assert_eq!(session.protocol(), 2);
    assert_eq!(session.hello()["protocol"], json!(2));
    assert_eq!(session.call("ping", Map::new(), None).unwrap(), json!({"cmd": "ping"}));
    session.close();
    engine.wait_closed(1);
}

// Ported from `t_fake_v3_server` (the 1.1.0 half; the stock 1.0.0 half has no Rust port).
#[test]
fn fake_v3_server_answers_3_and_keeps_the_v3_keys() {
    let engine = FakeEngine::start(hello_or_cmd(v3_answer));
    let session = connect(&engine);
    assert_eq!(session.protocol(), 3);
    assert_eq!(session.hello()["protocolMin"], json!(2));
    assert_eq!(session.hello()["protocolMax"], json!(3));
    assert_eq!(session.call("ping", Map::new(), None).unwrap(), json!({"cmd": "ping"}));
    let asked: Vec<Value> = engine.hellos().iter().map(|h| h["protocol"].clone()).collect();
    assert_eq!(asked, vec![json!(3)]);
    session.close();
    engine.wait_closed(1);
}

#[test]
fn an_engine_of_a_later_protocol_is_refused_and_closed() {
    let engine = FakeEngine::start(Box::new(|request: &Value, writer: &mut ReplyWriter| {
        let mut answer = v3_answer(request);
        answer["protocol"] = json!(4);
        answer["protocolMin"] = json!(4);
        answer["protocolMax"] = json!(5);
        writer.response(&request["id"], answer);
    }));
    let e = Session::connect(engine.endpoint.clone(), &ConnectOptions::new("cc", "tests"))
        .expect_err("protocol 4 must be refused");
    let msg = e.to_string();
    assert!(msg.contains("protocol 4"), "{msg}");
    assert!(msg.contains("2..3"), "{msg}");
    engine.wait_closed(1);
}

#[test]
fn non_protocol_lines_and_events_do_not_become_replies() {
    let engine = FakeEngine::start(Box::new(|request: &Value, writer: &mut ReplyWriter| {
        let id = &request["id"];
        if request["cmd"] == "hello" {
            writer.line(&json!({"event": "ready", "protocol": 2, "ghidra": "12.3"}));
            writer.raw("a JVM line that is not protocol\n");
            writer.raw("   \n");
            writer.response(id, v2_answer(request));
            return;
        }
        if request["cmd"] == "decompile" {
            writer.line(&json!({"event": "progress", "id": id, "message": "Analyzing",
                                "progress": 1, "maximum": 4}));
        }
        writer.response(id, json!({"cmd": request["cmd"]}));
    }));
    let session = connect(&engine);
    assert_eq!(session.call("ping", Map::new(), None).unwrap(), json!({"cmd": "ping"}));
    let events = session.take_events();
    assert_eq!(events.len(), 1, "the ready event, read before the hello answer");
    assert_eq!(events[0]["event"], json!("ready"));
    assert_eq!(
        session.call("decompile", Map::new(), None).unwrap(),
        json!({"cmd": "decompile"})
    );
    let events = session.take_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], json!("progress"));
    session.close();
    engine.wait_closed(1);
}

#[test]
fn an_unterminated_last_line_is_still_a_reply() {
    let engine = FakeEngine::start(Box::new(|request: &Value, writer: &mut ReplyWriter| {
        let id = &request["id"];
        if request["cmd"] == "hello" {
            writer.response(id, v2_answer(request));
        } else {
            writer.raw(&format!("{{\"id\": {id}, \"ok\": true, \"result\": 7}}\n"));
            // Then the stream stays open; the client's reply is complete.
        }
    }));
    let session = connect(&engine);
    assert_eq!(session.call("ping", Map::new(), None).unwrap(), json!(7));
    session.close();
    engine.wait_closed(1);
}

#[test]
fn a_closed_stream_is_a_closed_session_error() {
    let engine = FakeEngine::start(Box::new(|request: &Value, writer: &mut ReplyWriter| {
        let id = &request["id"];
        if request["cmd"] == "hello" {
            writer.response(id, v2_answer(request));
            return;
        }
        writer.shutdown();
    }));
    let session = connect(&engine);
    let e = session
        .call("drop", Map::new(), Some(2.0))
        .expect_err("the connection ended");
    assert_eq!(e.code(), code::CLOSED, "{e}");
    engine.wait_closed(1);
}

#[test]
fn an_ok_false_answer_carries_the_engines_code_message_and_details() {
    let engine = FakeEngine::start(Box::new(|request: &Value, writer: &mut ReplyWriter| {
        let id = &request["id"];
        if request["cmd"] == "hello" {
            writer.response(id, v2_answer(request));
        } else {
            writer.error(
                id,
                json!({"code": "busy", "message": "program is held",
                       "details": {"holder": "client 3"}, "trace": ["at x"]}),
            );
        }
    }));
    let session = connect(&engine);
    let e = session
        .call("info", Map::new(), None)
        .expect_err("busy must be an error");
    let hydra_client::Error::Session(SessionError { code: c, message, details, trace }) = e else {
        panic!("expected a SessionError");
    };
    assert_eq!(c, "busy");
    assert_eq!(message, "program is held");
    assert_eq!(details["holder"], json!("client 3"));
    assert_eq!(trace, Some(json!(["at x"])));
    session.close();
    engine.wait_closed(1);
}

#[test]
fn a_deadline_cancels_the_request_and_the_connection_stays_usable() {
    let answered = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&answered);
    let engine = FakeEngine::start(Box::new(move |request: &Value, writer: &mut ReplyWriter| {
        let id = &request["id"];
        let cmd = request["cmd"].as_str().unwrap_or_default();
        match cmd {
            "hello" => writer.response(id, v2_answer(request)),
            "cancel" => {
                seen.fetch_add(1, Ordering::SeqCst);
                writer.response(id, json!({"cancelled": 0}));
            }
            // The info request is never answered: the client's deadline must fire.
            "info" => {}
            _ => writer.response(id, json!({"cmd": cmd})),
        }
    }));
    let session = connect(&engine);
    let started = Instant::now();
    let e = session
        .call("info", Map::new(), Some(0.2))
        .expect_err("the deadline must fire");
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(150), "returned too early: {elapsed:?}");
    assert_eq!(e.code(), code::DEADLINE_EXCEEDED);
    let details = e.details();
    assert_eq!(details["deadlineS"], json!(0.2));
    assert_eq!(details["target"], json!(2));
    assert!(details["cancelId"].is_u64(), "cancel id: {details}");
    // The cancel is written after the error is built; give the server a moment to read it.
    let end = Instant::now() + Duration::from_secs(2);
    while answered.load(Ordering::SeqCst) == 0 && Instant::now() < end {
        thread::sleep(Duration::from_millis(5));
    }
    // The cancel carried target and parallel=true.
    let requests = engine.requests();
    let cancel = requests
        .iter()
        .find(|r| r["cmd"] == "cancel")
        .expect("a cancel was sent");
    assert_eq!(cancel["target"], json!(2));
    assert_eq!(cancel["parallel"], json!(true));
    assert_eq!(answered.load(Ordering::SeqCst), 1);
    // The connection is still usable: a new request gets a new id.
    assert_eq!(session.call("ping", Map::new(), None).unwrap(), json!({"cmd": "ping"}));
    session.close();
    engine.wait_closed(1);
}

#[test]
fn the_write_helpers_send_the_protocols_fields() {
    let engine = FakeEngine::start(hello_or_cmd(v2_answer));
    let session = connect(&engine);
    let ops = [
        EditOp::Rename {
            address: "0x401000".to_owned(),
            name: "renamed".to_owned(),
        },
        EditOp::Comment {
            address: "0x401000".to_owned(),
            text: "a plate".to_owned(),
            kind: CommentKind::Plate,
        },
    ];
    session
        .apply_overlay("prog", "ov-agent", &ops, None)
        .unwrap();
    session.drop_overlay("prog", "ov-agent", None).unwrap();
    session
        .edit(
            "prog",
            &[EditOp::Signature {
                address: "0x401000".to_owned(),
                signature: "void f(int)".to_owned(),
            }],
            None,
        )
        .unwrap();
    session.save("prog", Some("bench tag"), None).unwrap();
    session
        .fork_project("p1", "C:/forks/a", Access::Writable, Some(600), None)
        .unwrap();
    session
        .open_program_upgrading("/swkotor.exe", Some("f1"), None, None)
        .unwrap();
    session
        .close_project(Some("f1"), Some(Discard::Discard), None)
        .unwrap();
    session.close_project(Some("p1"), None, None).unwrap();
    session.close();

    let requests = engine.requests();
    let request = |cmd: &str| {
        requests
            .iter()
            .find(|r| r["cmd"] == cmd)
            .unwrap_or_else(|| panic!("no {cmd} request"))
    };
    let overlay = request("apply_overlay");
    assert_eq!(overlay["program"], json!("prog"));
    assert_eq!(overlay["overlay"], json!("ov-agent"));
    assert_eq!(
        overlay["ops"],
        json!([
            {"op": "rename", "address": "0x401000", "name": "renamed"},
            {"op": "comment", "address": "0x401000", "text": "a plate", "type": "plate"}
        ])
    );
    let drop = request("drop_overlay");
    assert_eq!(drop["program"], json!("prog"));
    assert_eq!(drop["overlay"], json!("ov-agent"));
    let edit = request("edit");
    assert_eq!(
        edit["ops"],
        json!([{"op": "signature", "address": "0x401000", "signature": "void f(int)"}])
    );
    assert_eq!(request("save")["comment"], json!("bench tag"));
    let fork = request("fork_project");
    assert_eq!(fork["project"], json!("p1"));
    assert_eq!(fork["path"], json!("C:/forks/a"));
    assert_eq!(fork["writable"], json!(true));
    assert_eq!(fork["timeout"], json!(600));
    let upgrade = requests
        .iter()
        .find(|r| r["cmd"] == "open_program" && r["upgrade"] == json!(true))
        .expect("the upgrading open");
    assert_eq!(upgrade["path"], json!("/swkotor.exe"));
    assert_eq!(upgrade["project"], json!("f1"));
    assert_eq!(upgrade["writable"], json!(true));
    let closes: Vec<&Value> = requests
        .iter()
        .filter(|r| r["cmd"] == "close_project")
        .collect();
    assert_eq!(closes.len(), 2);
    assert_eq!(closes[0]["discard"], json!(true));
    assert!(closes[1].get("discard").is_none(), "an omitted discard");
    assert_eq!(closes[1]["project"], json!("p1"));
}

#[test]
fn several_threads_each_get_their_own_answer() {
    let engine = FakeEngine::start(Box::new(|request: &Value, writer: &mut ReplyWriter| {
        let id = &request["id"];
        if request["cmd"] == "hello" {
            writer.response(id, v2_answer(request));
            return;
        }
        let n = request["n"].as_u64().unwrap_or(0);
        thread::sleep(Duration::from_millis(40 - n * 10));
        writer.response(id, json!({"n": n}));
    }));
    let session = Arc::new(connect(&engine));
    let mut handles = Vec::new();
    for n in 0..3_u64 {
        let session = Arc::clone(&session);
        handles.push(thread::spawn(move || {
            session
                .call("work", fields([("n", Value::from(n))]), Some(2.0))
                .expect("an answer")
        }));
    }
    let mut got: Vec<u64> = handles
        .into_iter()
        .map(|h| {
            let reply = h.join().expect("the thread");
            reply["n"].as_u64().expect("a number")
        })
        .collect();
    got.sort_unstable();
    assert_eq!(got, vec![0, 1, 2]);
    Arc::into_inner(session)
        .expect("the only reference")
        .close();
    engine.wait_closed(1);
}

#[test]
fn reconnect_dials_a_restarted_endpoint_with_a_new_token() {
    // The first daemon answers hello, then ends the connection on any other request.
    let first = FakeEngine::start(Box::new(|request: &Value, writer: &mut ReplyWriter| {
        let id = &request["id"];
        if request["cmd"] == "hello" {
            writer.response(id, v2_answer(request));
        } else {
            writer.shutdown();
        }
    }));
    let session = connect(&first);
    let e = session
        .call("work", Map::new(), Some(2.0))
        .expect_err("the daemon ended the session");
    assert_eq!(e.code(), code::CLOSED);
    first.wait_closed(1);

    // The restarted daemon has a new port and a new token; the old session is replaced.
    let second = FakeEngine::start_with_token("y", Box::new(|request: &Value, writer: &mut ReplyWriter| {
        let id = &request["id"];
        if request["cmd"] == "hello" {
            assert_eq!(request["token"], json!("y"), "the new endpoint's token");
            writer.response(id, v2_answer(request));
        } else {
            writer.response(id, json!({"cmd": request["cmd"]}));
        }
    }));
    let session = session
        .reconnect(second.endpoint.clone(), &ConnectOptions::new("cc", "tests"))
        .expect("the restarted daemon accepts the same client");
    assert_eq!(session.protocol(), 2);
    assert_eq!(
        session.call("ping", Map::new(), None).unwrap(),
        json!({"cmd": "ping"})
    );
    // A new connection starts its ids at 1 again: hello took 1, so this reply was 2.
    let requests = second.requests();
    assert_eq!(requests[0]["id"], json!(1));
    assert_eq!(requests[0]["token"], json!("y"));
    session.close();
    second.wait_closed(1);
}

#[test]
fn a_labelled_view_sends_its_labels_and_a_per_call_label_wins() {
    let engine = FakeEngine::start(hello_or_cmd(v2_answer));
    let session = connect(&engine);
    let view = session.labelled(Some("agent-a"), Some("claude-code"));
    view.call("info", Map::new(), None).unwrap();
    view.call(
        "info",
        fields([("client", Value::String("other".to_owned()))]),
        None,
    )
    .unwrap();
    view.cancel_all().unwrap();
    let requests = engine.requests();
    let infos: Vec<&Value> = requests.iter().filter(|r| r["cmd"] == "info").collect();
    assert_eq!(infos.len(), 2);
    assert_eq!(infos[0]["client"], json!("agent-a"));
    assert_eq!(infos[0]["harness"], json!("claude-code"));
    assert_eq!(infos[0]["parallel"], json!(true));
    assert_eq!(infos[1]["client"], json!("other"));
    let cancel = requests.iter().find(|r| r["cmd"] == "cancel").unwrap();
    assert_eq!(cancel["all"], json!(true));
    assert_eq!(cancel["client"], json!("agent-a"));
    session.close();
    engine.wait_closed(1);
}

#[test]
fn keep_raw_returns_the_engines_line_byte_for_byte() {
    let engine = FakeEngine::start(Box::new(|request: &Value, writer: &mut ReplyWriter| {
        let id = &request["id"];
        if request["cmd"] == "hello" {
            writer.response(id, v2_answer(request));
        } else {
            writer.raw(&format!(
                "{{\"id\":{id},\"ok\":true,\"result\":{{\"z\":1, \"a\":2}},\"ms\":3}}\n"
            ));
        }
    }));
    let mut options = ConnectOptions::new("cc", "tests");
    options.keep_raw = true;
    let session = Session::connect(engine.endpoint.clone(), &options).expect("hello");
    let reply = session
        .call_raw("info", Map::new(), None)
        .expect("an answer");
    let raw = reply.raw.expect("the raw line");
    assert_eq!(raw, "{\"id\":2,\"ok\":true,\"result\":{\"z\":1, \"a\":2},\"ms\":3}\n");
    assert_eq!(reply.value["result"], json!({"z": 1, "a": 2}));
    session.close();
    engine.wait_closed(1);
}

#[test]
fn a_zero_or_negative_deadline_is_refused_before_anything_is_sent() {
    let engine = FakeEngine::start(hello_or_cmd(v2_answer));
    let session = connect(&engine);
    for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
        let e = session
            .call("ping", Map::new(), Some(bad))
            .expect_err("an unusable deadline");
        assert_eq!(e.code(), code::INVALID, "for {bad}");
    }
    // Only the hello was sent.
    assert_eq!(engine.requests().len(), 1);
    session.close();
    engine.wait_closed(1);
}
