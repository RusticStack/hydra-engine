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
//! The connection: an endpoint, a JSON-lines channel, and request/response matching.
//!
//! Ported from `ghidra_session._Base` and `SocketSession`. A reader thread owns the read half
//! and routes every answer to the waiter registered for its `id` (or keeps it until the caller
//! waits), so several threads may call at once, as the Python client allows. A reply line is
//! delivered whole, and, when [`ConnectOptions::keep_raw`] is set, byte for byte beside its
//! parsed value; that is what the differential harness compares.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::error::{Error, Result, SessionError};
use crate::lite::{FullDaemon, LiteMode, STATE_COMMANDS, USE_FULL_DAEMON};
use crate::version::{CLIENT_VERSION, PROTOCOL, check_compatible};

/// How long a `hello` may take at most (Python's `HELLO_DEADLINE_S`).
pub const HELLO_DEADLINE_S: f64 = 5.0;

/// The daemon's endpoint file: `{"host", "port", "token", ...}`.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// The address the daemon listens on (`"127.0.0.1"`).
    pub host: String,
    /// The port it listens on.
    pub port: u16,
    /// The token its `hello` requires.
    pub token: String,
    /// The whole file, for the protocol and install checks.
    pub value: Value,
}

impl Endpoint {
    /// Reads `<state>/<instance>.json`, the file `Daemon` writes and reads.
    ///
    /// # Errors
    /// [`code::IO`] when the file cannot be read; [`code::BAD_ENDPOINT`] when it is not JSON.
    pub fn read_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let value: Value = serde_json::from_str(&text)?;
        Self::from_value(value)
    }

    /// Reads `<state>/<instance>.json`.
    ///
    /// # Errors
    /// As [`Endpoint::read_file`].
    pub fn from_state(state: &Path, instance: &str) -> Result<Self> {
        Self::read_file(&state.join(format!("{instance}.json")))
    }

    /// Builds one from an endpoint object.
    ///
    /// # Errors
    /// [`code::BAD_ENDPOINT`] when `host`, `port` or `token` is missing or unusable. The Python
    /// client raises `KeyError`/`ValueError` there.
    pub fn from_value(value: Value) -> Result<Self> {
        let host = value
            .get("host")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Endpoint("the endpoint has no host".to_owned()))?
            .to_owned();
        let port = value
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or_else(|| Error::Endpoint("the endpoint has no usable port".to_owned()))?;
        let token = value
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Endpoint("the endpoint has no token".to_owned()))?
            .to_owned();
        Ok(Self {
            host,
            port,
            token,
            value,
        })
    }

    fn socket_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// What a connection calls itself, and how it behaves.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// The `client` label of the connection (`hello.client`).
    pub client: String,
    /// The `harness` label (`hello.harness`).
    pub harness: String,
    /// Run [`check_compatible`] on the answer; the Python `SocketSession` default.
    pub check: bool,
    /// Limit the `hello` wait, in seconds; `None` waits without a limit, as Python does.
    pub hello_deadline: Option<f64>,
    /// Keep each answer's raw line beside its parsed value (`call_raw`/the `call` command).
    pub keep_raw: bool,
    /// Where to find the full daemon when the daemon dialled is a `hydra-lite` one (its endpoint
    /// file says `"lite": true`) and answers `use_full_daemon`; `None`: the refusal is returned.
    pub full_daemon: Option<Arc<dyn FullDaemon>>,
    /// `HYDRA_LITE`: with [`LiteMode::Only`] a refusal is returned even when `full_daemon` is set.
    pub lite_mode: LiteMode,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            client: String::new(),
            harness: String::new(),
            check: true,
            hello_deadline: None,
            keep_raw: false,
            full_daemon: None,
            lite_mode: LiteMode::Off,
        }
    }
}

impl ConnectOptions {
    /// Options for one connection, checked, with no hello deadline.
    #[must_use]
    pub fn new(client: impl Into<String>, harness: impl Into<String>) -> Self {
        Self {
            client: client.into(),
            harness: harness.into(),
            ..Self::default()
        }
    }

    /// Lets the session move to the full daemon that `daemon` finds when a lite daemon refuses.
    #[must_use]
    pub fn with_full_daemon(mut self, daemon: Arc<dyn FullDaemon>) -> Self {
        self.full_daemon = Some(daemon);
        self
    }

    /// Sets the `HYDRA_LITE` mode.
    #[must_use]
    pub fn with_lite_mode(mut self, mode: LiteMode) -> Self {
        self.lite_mode = mode;
        self
    }
}

/// One whole answer: the parsed object and, when asked for, its exact line.
#[derive(Debug, Clone)]
pub struct Reply {
    /// The parsed response object.
    pub value: Value,
    /// The line exactly as the engine wrote it, including its `\n`, when `keep_raw` is set.
    pub raw: Option<String>,
}

struct Arrival {
    value: Value,
    raw: Option<String>,
}

struct State {
    arrived: HashMap<u64, Arrival>,
    waiters: HashMap<u64, Sender<Arrival>>,
    abandoned: HashSet<u64>,
    events: Vec<Value>,
    closed: bool,
    /// A reply line that could not be read as the protocol promises; ends the session.
    protocol_error: Option<String>,
}

/// The callback every progress event is handed to.
type EventHandler = Arc<dyn Fn(&Value) + Send + Sync>;

/// A request that succeeded and changed what the lite daemon holds for the session.
struct Journaled {
    cmd: String,
    fields: Map<String, Value>,
    /// The project id the daemon gave (`open_project`).
    project: Option<String>,
}

/// What a session on a `hydra-lite` daemon keeps to be able to move to the full daemon.
#[derive(Default)]
struct Lite {
    /// The full daemon; taken (set to `None`) when the move starts, so it is tried once.
    full: Option<Arc<dyn FullDaemon>>,
    /// Armed at connect: the endpoint is a lite one and the caller gave a [`FullDaemon`].
    armed: bool,
    journal: Vec<Journaled>,
    /// The requests sent and not answered yet.
    requests: BTreeMap<u64, (String, Map<String, Value>)>,
    /// Project ids of the lite daemon -> those the full daemon gave the same projects.
    idmap: HashMap<String, String>,
    /// The endpoint of the full daemon, once the session lives there.
    moved_to: Option<Endpoint>,
}

struct Inner {
    stream: Mutex<TcpStream>,
    state: Mutex<State>,
    lite: Mutex<Lite>,
    next_id: AtomicU64,
    keep_raw: bool,
    on_event: Mutex<Option<EventHandler>>,
    client: String,
    harness: String,
}

/// Locks a mutex, ignoring a poison: a panic in one caller must not end the session for the
/// others (the Python client's locks have no poison either).
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether a request's answer is still wanted (`Tracked`) or must be dropped (`Abandoned`,
/// used for the `cancel` a deadline sends).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendMode {
    Tracked,
    Abandoned,
}

/// A connected session: `hello` done, protocol known, requests correlated by `id`.
pub struct Session {
    inner: Arc<Inner>,
    reader: Option<JoinHandle<()>>,
    hello: Value,
    protocol: i64,
    endpoint: Endpoint,
    options: ConnectOptions,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("client", &self.options.client)
            .field("harness", &self.options.harness)
            .field("protocol", &self.protocol)
            .field("endpoint", &self.endpoint.socket_address())
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Dials the endpoint, sends `hello` and checks the answer.
    ///
    /// On a socket `hello` must be the first request, with the endpoint's token; it asks for
    /// protocol [`PROTOCOL`] and the answer fixes what the connection speaks
    /// ([`Session::protocol`]), exactly as `SocketSession.__init__` does.
    ///
    /// # Errors
    /// [`code::IO`] when the connection fails, [`code::INCOMPATIBLE`] when the engine refuses,
    /// or a [`SessionError`] with the engine's code for an `ok:false` answer.
    pub fn connect(endpoint: Endpoint, options: &ConnectOptions) -> Result<Self> {
        let stream = TcpStream::connect(endpoint.socket_address())?;
        stream.set_nodelay(true)?;
        let read_stream = stream.try_clone()?;
        let inner = Arc::new(Inner {
            stream: Mutex::new(stream),
            state: Mutex::new(State {
                arrived: HashMap::new(),
                waiters: HashMap::new(),
                abandoned: HashSet::new(),
                events: Vec::new(),
                closed: false,
                protocol_error: None,
            }),
            lite: Mutex::new(Lite::default()),
            next_id: AtomicU64::new(0),
            keep_raw: options.keep_raw,
            on_event: Mutex::new(None),
            client: options.client.clone(),
            harness: options.harness.clone(),
        });
        let reader_inner = Arc::clone(&inner);
        let reader = thread::Builder::new()
            .name("hydra-client-reader".to_owned())
            .spawn(move || reader_loop(&reader_inner, read_stream))?;
        let mut session = Self {
            inner,
            reader: Some(reader),
            hello: Value::Null,
            protocol: 0,
            endpoint,
            options: options.clone(),
        };
        let hello = match session.call(
            "hello",
            fields([
                ("token", Value::String(session.endpoint.token.clone())),
                ("client", Value::String(options.client.clone())),
                ("harness", Value::String(options.harness.clone())),
                ("clientVersion", Value::String(CLIENT_VERSION.to_owned())),
                ("protocol", Value::from(PROTOCOL)),
            ]),
            options.hello_deadline,
        ) {
            Ok(hello) => hello,
            Err(e) => {
                session.close();
                // a lite daemon whose workers are all busy refuses the connection itself
                if let Error::Session(refusal) = &e
                    && refusal.code == USE_FULL_DAEMON
                    && !options.lite_mode.returns_refusals()
                    && let Some(full) = options.full_daemon.clone()
                {
                    return Self::connect(full.endpoint()?, options);
                }
                return Err(e);
            }
        };
        if options.check
            && let Err(e) = check_compatible(&hello, CLIENT_VERSION, None, None)
        {
            session.close();
            return Err(e);
        }
        session.protocol = hello
            .get("protocol")
            .and_then(Value::as_i64)
            .filter(|p| *p == 2 || *p == 3)
            .unwrap_or(PROTOCOL);
        session.hello = hello;
        let lite_endpoint = session.endpoint.value.get("lite") == Some(&Value::Bool(true));
        if lite_endpoint && !options.lite_mode.returns_refusals() && options.full_daemon.is_some() {
            let mut lite = lock(&session.inner.lite);
            lite.full.clone_from(&options.full_daemon);
            lite.armed = true;
        }
        Ok(session)
    }

    /// True once this session has moved from a `hydra-lite` daemon to the full daemon.
    #[must_use]
    pub fn failed_over(&self) -> bool {
        lock(&self.inner.lite).moved_to.is_some()
    }

    /// The endpoint the session talks to now: the one it dialled, or the full daemon's after a
    /// move.
    #[must_use]
    pub fn current_endpoint(&self) -> Endpoint {
        lock(&self.inner.lite)
            .moved_to
            .clone()
            .unwrap_or_else(|| self.endpoint.clone())
    }

    /// The `hello` answer.
    #[must_use]
    pub fn hello(&self) -> &Value {
        &self.hello
    }

    /// The protocol this connection runs at: 2 or 3, from the `hello` answer.
    #[must_use]
    pub fn protocol(&self) -> i64 {
        self.protocol
    }

    /// The endpoint this session dialled.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The labels this connection sent.
    #[must_use]
    pub fn options(&self) -> &ConnectOptions {
        &self.options
    }

    /// The progress events received so far (Python's `events`), oldest first.
    #[must_use]
    pub fn events(&self) -> Vec<Value> {
        let state = lock(&self.inner.state);
        state.events.clone()
    }

    /// Removes and returns the events received so far.
    pub fn take_events(&self) -> Vec<Value> {
        let mut state = lock(&self.inner.state);
        std::mem::take(&mut state.events)
    }

    /// Installs the callback every future event is handed to (Python's `on_event`).
    pub fn set_event_handler(&self, handler: impl Fn(&Value) + Send + Sync + 'static) {
        *lock(&self.inner.on_event) = Some(Arc::new(handler));
    }

    /// True once the connection has ended.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        lock(&self.inner.state).closed
    }

    /// Sends one request and returns its id, without waiting.
    ///
    /// # Errors
    /// [`code::IO`] when the line cannot be written.
    pub fn send(&self, cmd: &str, fields: Map<String, Value>) -> Result<u64> {
        self.send_inner(cmd, fields, SendMode::Tracked)
    }

    fn send_inner(&self, cmd: &str, fields: Map<String, Value>, mode: SendMode) -> Result<u64> {
        let rid = self.inner.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        if mode == SendMode::Abandoned {
            lock(&self.inner.state).abandoned.insert(rid);
        }
        // The stream lock is held from the bookkeeping to the write, so a move to the full daemon
        // (which sends again whatever is in `requests`, under the same lock) neither misses this
        // request nor sends it twice.
        let mut stream = lock(&self.inner.stream);
        let fields = {
            let mut lite = lock(&self.inner.lite);
            let fields = remap(&lite.idmap, fields);
            if lite.armed {
                lite.requests.insert(rid, (cmd.to_owned(), fields.clone()));
            }
            fields
        };
        let line = request_line(rid, cmd, fields)?;
        stream.write_all(line.as_bytes())?;
        stream.flush()?;
        Ok(rid)
    }

    /// Waits for one request's answer and returns the whole response object.
    ///
    /// `deadline` is seconds, client side only (it is never sent). When it passes, `cancel
    /// target=<rid> parallel=true` is sent, the late answer is dropped and
    /// `SessionError("deadline_exceeded")` is raised; the connection stays usable.
    ///
    /// # Errors
    /// [`code::CLOSED`], [`code::DEADLINE_EXCEEDED`], an engine `ok:false` code, or
    /// [`code::BAD_REPLY`] when a line could not be read as the protocol promises.
    ///
    pub fn wait(&self, rid: u64, deadline: Option<f64>) -> Result<Value> {
        self.wait_reply(rid, deadline).map(|reply| reply.value)
    }

    /// [`Session::wait`] keeping the raw line when the session was opened with `keep_raw`.
    ///
    /// # Errors
    /// As [`Session::wait`].
    ///
    pub fn wait_reply(&self, rid: u64, deadline: Option<f64>) -> Result<Reply> {
        let end = match deadline {
            Some(seconds) if seconds.is_finite() && seconds > 0.0 => {
                Some(Instant::now() + Duration::from_secs_f64(seconds))
            }
            Some(seconds) => {
                return Err(Error::Invalid(format!(
                    "deadline must be a positive number of seconds, not {seconds}"
                )));
            }
            None => None,
        };
        let state = Arc::clone(&self.inner);
        let rx = {
            let mut st = lock(&self.inner.state);
            if let Some(arrival) = st.arrived.remove(&rid) {
                return Ok(finish(arrival));
            }
            if let Some(problem) = st.protocol_error.clone() {
                return Err(Error::BadReply(problem));
            }
            if st.closed {
                return Err(Error::closed());
            }
            let (tx, rx) = channel();
            st.waiters.insert(rid, tx);
            rx
        };
        // One wait: the channel wakes on an answer, on close (the sender is dropped) and on the
        // deadline. A registered waiter is removed under the state lock before a cancel, which
        // is what keeps a late answer from being delivered after the deadline error.
        let received = match end {
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(end) => {
                let left = end.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    Err(RecvTimeoutError::Timeout)
                } else {
                    rx.recv_timeout(left)
                }
            }
        };
        match received {
            Ok(arrival) => Ok(finish(arrival)),
            Err(RecvTimeoutError::Disconnected) => {
                let mut st = lock(&state.state);
                if let Some(arrival) = st.arrived.remove(&rid) {
                    return Ok(finish(arrival));
                }
                if let Some(problem) = st.protocol_error.clone() {
                    return Err(Error::BadReply(problem));
                }
                Err(Error::closed())
            }
            Err(RecvTimeoutError::Timeout) => {
                let deadline_s = deadline.unwrap_or(0.0);
                let mut st = lock(&state.state);
                if let Some(arrival) = st.arrived.remove(&rid) {
                    return Ok(finish(arrival));
                }
                if st.closed {
                    return Err(Error::closed());
                }
                // Still registered: take the waiter out and, still under the lock, look once
                // more, so an answer routed just now is not lost to the timeout.
                st.waiters.remove(&rid);
                if let Ok(arrival) = rx.try_recv() {
                    return Ok(finish(arrival));
                }
                st.abandoned.insert(rid);
                drop(st);
                lock(&self.inner.lite).requests.remove(&rid);
                let cancel = self
                    .send_inner(
                        "cancel",
                        fields([
                            ("target", Value::from(rid)),
                            ("parallel", Value::Bool(true)),
                        ]),
                        SendMode::Abandoned,
                    )
                    .ok();
                Err(Error::deadline_exceeded(deadline_s, rid, cancel))
            }
        }
    }

    /// Sends one request, waits for its answer and returns `result`.
    ///
    /// # Errors
    /// As [`Session::wait`], plus [`code::BAD_REPLY`] for an `ok:true` answer with no `result`.
    ///
    pub fn call(
        &self,
        cmd: &str,
        fields: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        check_deadline(deadline)?;
        let rid = self.send(cmd, fields)?;
        let response = self.wait(rid, deadline)?;
        if response.get("ok") == Some(&Value::Bool(true)) {
            response.get("result").cloned().ok_or_else(|| {
                Error::BadReply(format!("the answer to request {rid} has no result"))
            })
        } else {
            Err(answer_error(&response))
        }
    }

    /// Like [`Session::call`] but returns the whole response: `result` plus `stale`,
    /// `refreshed`, `ms` and the rest.
    ///
    /// # Errors
    /// As [`Session::call`].
    ///
    pub fn call_raw(
        &self,
        cmd: &str,
        fields: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Reply> {
        check_deadline(deadline)?;
        let rid = self.send(cmd, fields)?;
        self.wait_reply(rid, deadline)
    }

    /// A view whose requests all carry `client`/`harness` (and `parallel`), as Python's
    /// `labelled(...)`.
    #[must_use]
    pub fn labelled(&self, client: Option<&str>, harness: Option<&str>) -> Labelled<'_> {
        Labelled {
            session: self,
            client: client.map(str::to_owned),
            harness: harness.map(str::to_owned),
            parallel: true,
        }
    }

    /// Re-dials a fresh endpoint: the daemon may have restarted between the two, so the caller
    /// re-reads the endpoint file. This client's ids start again at 1 on the new connection,
    /// as a new `SocketSession` does.
    ///
    /// # Errors
    /// As [`Session::connect`].
    pub fn reconnect(self, endpoint: Endpoint, options: &ConnectOptions) -> Result<Self> {
        drop(self);
        Self::connect(endpoint, options)
    }

    /// Shuts the connection down and waits for the reader thread.
    pub fn close(mut self) {
        self.shutdown();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }

    fn shutdown(&self) {
        let _ = self
            .inner
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .shutdown(Shutdown::Both);
        let mut state = lock(&self.inner.state);
        state.closed = true;
        state.waiters.clear();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// One caller's view of a shared connection: every request carries this view's labels.
#[derive(Debug)]
pub struct Labelled<'a> {
    session: &'a Session,
    client: Option<String>,
    harness: Option<String>,
    parallel: bool,
}

impl Labelled<'_> {
    /// The fields this view adds to `fields`, unless the call names its own.
    #[must_use]
    pub fn with_labels(&self, fields: Map<String, Value>) -> Map<String, Value> {
        let mut out = fields;
        if let Some(client) = &self.client {
            out.entry("client".to_owned())
                .or_insert_with(|| Value::String(client.clone()));
        }
        if let Some(harness) = &self.harness {
            out.entry("harness".to_owned())
                .or_insert_with(|| Value::String(harness.clone()));
        }
        if self.parallel {
            out.entry("parallel".to_owned())
                .or_insert(Value::Bool(true));
        }
        out
    }

    /// [`Session::call`] with this view's labels.
    ///
    /// # Errors
    /// As [`Session::call`].
    ///
    pub fn call(
        &self,
        cmd: &str,
        fields: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        self.session.call(cmd, self.with_labels(fields), deadline)
    }

    /// [`Session::send`] with this view's labels.
    ///
    /// # Errors
    /// As [`Session::send`].
    pub fn send(&self, cmd: &str, fields: Map<String, Value>) -> Result<u64> {
        self.session.send(cmd, self.with_labels(fields))
    }

    /// [`Session::wait`].
    ///
    /// # Errors
    /// As [`Session::wait`].
    ///
    pub fn wait(&self, rid: u64, deadline: Option<f64>) -> Result<Value> {
        self.session.wait(rid, deadline)
    }

    /// Cancels one of this view's requests by id.
    ///
    /// # Errors
    /// As [`Session::call`].
    ///
    pub fn cancel(&self, target: u64) -> Result<Value> {
        self.call("cancel", fields([("target", Value::from(target))]), None)
    }

    /// Cancels every request carrying this view's label, and no other caller's.
    ///
    /// # Errors
    /// As [`Session::call`].
    ///
    pub fn cancel_all(&self) -> Result<Value> {
        self.call("cancel", fields([("all", Value::Bool(true))]), None)
    }
}

/// Validates a client-side deadline the way `_check_deadline` does, before anything is sent.
fn check_deadline(deadline: Option<f64>) -> Result<()> {
    match deadline {
        Some(seconds) if seconds.is_finite() && seconds > 0.0 => Ok(()),
        Some(seconds) => Err(Error::Invalid(format!(
            "deadline must be a positive number of seconds, not {seconds}"
        ))),
        None => Ok(()),
    }
}

/// A request's field map from pairs; a tiny helper so call sites read like the Python kwargs.
#[must_use]
pub fn fields(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> Map<String, Value> {
    pairs
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn finish(arrival: Arrival) -> Reply {
    Reply {
        value: arrival.value,
        raw: arrival.raw,
    }
}

fn answer_error(response: &Value) -> Error {
    let error = response.get("error").cloned().unwrap_or(Value::Null);
    Error::Session(SessionError::from_error_object(&error))
}

/// The request line for `rid`: `{"id", "cmd", ...fields}` and a newline.
fn request_line(rid: u64, cmd: &str, fields: Map<String, Value>) -> Result<String> {
    let mut request = Map::new();
    request.insert("id".to_owned(), Value::from(rid));
    request.insert("cmd".to_owned(), Value::String(cmd.to_owned()));
    request.extend(fields);
    let mut line = serde_json::to_string(&Value::Object(request))?;
    line.push('\n');
    Ok(line)
}

/// `fields` with the project ids of the lite daemon replaced by the full daemon's (`program`
/// `p1:/a.exe` and `project`).
fn remap(idmap: &HashMap<String, String>, mut fields: Map<String, Value>) -> Map<String, Value> {
    if idmap.is_empty() {
        return fields;
    }
    for key in ["program", "project"] {
        let Some(Value::String(text)) = fields.get(key) else {
            continue;
        };
        let (head, rest) = text
            .split_once(':')
            .map_or((text.as_str(), None), |(h, r)| (h, Some(r)));
        if let Some(new) = idmap.get(head) {
            let replaced = rest.map_or_else(|| new.clone(), |r| format!("{new}:{r}"));
            fields.insert(key.to_owned(), Value::String(replaced));
        }
    }
    fields
}

fn is_refusal(object: &Map<String, Value>) -> bool {
    object.get("ok") == Some(&Value::Bool(false))
        && object
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str)
            == Some(USE_FULL_DAEMON)
}

/// What `handle_line` made of a line.
enum Handled {
    Done,
    /// A lite daemon refused request `id`; the object is its answer.
    Refused(u64, Map<String, Value>),
}

fn reader_loop(inner: &Arc<Inner>, stream: TcpStream) {
    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let text = String::from_utf8_lossy(&line);
                match handle_line(inner, text.as_ref()) {
                    Ok(Handled::Done) => {}
                    Ok(Handled::Refused(id, refusal)) => {
                        if let Some(moved) = fail_over(inner, id, refusal) {
                            reader = moved;
                        }
                    }
                    Err(problem) => {
                        let mut state = lock(&inner.state);
                        state.protocol_error = Some(problem);
                        break;
                    }
                }
            }
        }
    }
    close_state(inner);
}

/// Hands an answer to its waiter (or keeps it until the caller waits).
fn deliver(inner: &Arc<Inner>, id: u64, object: Map<String, Value>, raw: Option<String>) {
    let mut state = lock(&inner.state);
    if state.abandoned.remove(&id) {
        drop(state);
        lock(&inner.lite).requests.remove(&id);
        return;
    }
    let arrival = Arrival {
        value: Value::Object(object),
        raw,
    };
    if let Some(waiter) = state.waiters.remove(&id) {
        drop(state);
        // The waiter may have given up between its last check and this line; then the answer
        // is unwanted.
        let _ = waiter.send(arrival);
    } else {
        state.arrived.insert(id, arrival);
    }
}

/// An answer arrived on a connection that may be lite: forget the request, and keep it for the
/// replay when it changed what the daemon holds for this session.
fn note(inner: &Arc<Inner>, id: u64, object: &Map<String, Value>) {
    let mut lite = lock(&inner.lite);
    if !lite.armed {
        return;
    }
    let Some((cmd, fields)) = lite.requests.remove(&id) else {
        return;
    };
    if object.get("ok") == Some(&Value::Bool(true)) && STATE_COMMANDS.contains(&cmd.as_str()) {
        let project = (cmd == "open_project")
            .then(|| {
                object
                    .get("result")
                    .and_then(|r| r.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .flatten();
        lite.journal.push(Journaled {
            cmd,
            fields,
            project,
        });
    }
}

/// Reads protocol lines from `reader` until the answer to `rid` (a line with `ok`); events, which
/// carry the id of their request but no `ok`, and other lines are skipped. `None` when the connection ends first.
fn read_answer(reader: &mut BufReader<TcpStream>, rid: u64) -> Option<Map<String, Value>> {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        if let Ok(Value::Object(object)) = serde_json::from_str::<Value>(line.trim_start())
            && object.get("id").and_then(Value::as_u64) == Some(rid)
            && object.contains_key("ok")
        {
            return Some(object);
        }
    }
}

/// Sends one request on a connection that nobody else reads yet and waits for its answer.
fn ask(
    stream: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    rid: u64,
    cmd: &str,
    fields: Map<String, Value>,
) -> std::result::Result<Value, String> {
    let line = request_line(rid, cmd, fields).map_err(|e| e.to_string())?;
    stream
        .write_all(line.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|e| format!("{cmd}: {e}"))?;
    let answer = read_answer(reader, rid).ok_or_else(|| format!("{cmd}: the connection ended"))?;
    if answer.get("ok") == Some(&Value::Bool(true)) {
        Ok(answer.get("result").cloned().unwrap_or(Value::Null))
    } else {
        Err(format!(
            "{cmd}: {}",
            answer
                .get("error")
                .map_or_else(|| "refused".to_owned(), Value::to_string)
        ))
    }
}

/// The lite daemon refused request `id` (`refusal` is its answer). Connects to the full daemon,
/// opens there again what this session had opened, swaps the connection under the session and
/// sends again every request that has no answer. Runs on the reader thread. Returns the reader
/// of the new connection, or `None` when the move failed; the refusal is then the answer, with
/// `details.failover` saying why.
fn fail_over(
    inner: &Arc<Inner>,
    id: u64,
    mut refusal: Map<String, Value>,
) -> Option<BufReader<TcpStream>> {
    let (full, journal) = {
        let mut lite = lock(&inner.lite);
        let full = lite.full.take();
        lite.armed = false;
        let journal: Vec<(String, Map<String, Value>, Option<String>)> = lite
            .journal
            .iter()
            .map(|j| (j.cmd.clone(), j.fields.clone(), j.project.clone()))
            .collect();
        (full, journal)
    };
    match move_to_full(inner, full, &journal) {
        Ok(reader) => Some(reader),
        Err(why) => {
            lock(&inner.lite).requests.remove(&id);
            if let Some(Value::Object(error)) = refusal.get_mut("error") {
                let details = error
                    .entry("details")
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Value::Object(details) = details {
                    details.insert("failover".to_owned(), Value::String(why));
                }
            }
            deliver(inner, id, refusal, None);
            None
        }
    }
}

fn move_to_full(
    inner: &Arc<Inner>,
    full: Option<Arc<dyn FullDaemon>>,
    journal: &[(String, Map<String, Value>, Option<String>)],
) -> std::result::Result<BufReader<TcpStream>, String> {
    let full = full.ok_or_else(|| "no full daemon is configured".to_owned())?;
    let endpoint = full.endpoint().map_err(|e| e.to_string())?;
    let mut stream = TcpStream::connect(endpoint.socket_address()).map_err(|e| e.to_string())?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut next = 0_u64;
    let mut step = || {
        next += 1;
        next
    };
    ask(
        &mut stream,
        &mut reader,
        step(),
        "hello",
        fields([
            ("token", Value::String(endpoint.token.clone())),
            ("client", Value::String(inner.client.clone())),
            ("harness", Value::String(inner.harness.clone())),
            ("clientVersion", Value::String(CLIENT_VERSION.to_owned())),
            ("protocol", Value::from(PROTOCOL)),
        ]),
    )?;
    let mut idmap: HashMap<String, String> = HashMap::new();
    for (cmd, request, old_project) in journal {
        let mut request = remap(&idmap, request.clone());
        request.remove("token");
        let result = ask(&mut stream, &mut reader, step(), cmd, request)?;
        if let (Some(old), Some(new)) = (old_project, result.get("id").and_then(Value::as_str))
            && old != new
        {
            idmap.insert(old.clone(), new.to_owned());
        }
    }
    let abandoned = lock(&inner.state).abandoned.clone();
    let write_half = stream.try_clone().map_err(|e| e.to_string())?;
    let mut current = lock(&inner.stream);
    let mut lite = lock(&inner.lite);
    lite.idmap = idmap;
    let pending: Vec<(u64, String, Map<String, Value>)> = lite
        .requests
        .iter()
        .filter(|(rid, _)| !abandoned.contains(rid))
        .map(|(rid, (cmd, request))| (*rid, cmd.clone(), remap(&lite.idmap, request.clone())))
        .collect();
    let old = std::mem::replace(&mut *current, write_half);
    let _ = old.shutdown(Shutdown::Both);
    lite.moved_to = Some(endpoint);
    for (rid, cmd, request) in pending {
        let wire = request_line(rid, &cmd, request).map_err(|e| e.to_string())?;
        current
            .write_all(wire.as_bytes())
            .and_then(|()| current.flush())
            .map_err(|e| e.to_string())?;
    }
    Ok(reader)
}

fn handle_line(inner: &Arc<Inner>, line: &str) -> std::result::Result<Handled, String> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || !trimmed.starts_with('{') {
        // Not protocol (a JVM message on stdout); ignore, as the Python client does.
        return Ok(Handled::Done);
    }
    let value: Value = serde_json::from_str(line)
        .map_err(|e| format!("a reply line is not valid JSON: {e}: {}", line.trim()))?;
    let Value::Object(object) = value else {
        return Err(format!(
            "a reply line is not a JSON object: {}",
            line.trim()
        ));
    };
    if object.contains_key("event") && !object.contains_key("ok") {
        let mut state = lock(&inner.state);
        state.events.push(Value::Object(object));
        drop(state);
        return Ok(Handled::Done);
    }
    let id = match object.get("id").and_then(Value::as_u64) {
        Some(id) => id,
        // The acceptor of a full hydra-lite daemon answers before it reads a line, so its
        // refusal has no id: it is the answer to the first request.
        None if is_refusal(&object) => 1,
        // The Python client keeps such a line under `_pending[None]`, where it can never be
        // matched; ignoring it is the same from every caller's point of view.
        None => return Ok(Handled::Done),
    };
    let raw = if inner.keep_raw {
        Some(line.to_owned())
    } else {
        None
    };
    if is_refusal(&object) && lock(&inner.lite).armed {
        return Ok(Handled::Refused(id, object));
    }
    note(inner, id, &object);
    deliver(inner, id, object, raw);
    Ok(Handled::Done)
}

fn close_state(inner: &Arc<Inner>) {
    let mut state = lock(&inner.state);
    state.closed = true;
    state.waiters.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn endpoint_requires_host_port_token() {
        let e = Endpoint::from_value(json!({"host": "127.0.0.1", "port": 1, "token": "t"}))
            .expect("a complete endpoint");
        assert_eq!(e.socket_address(), "127.0.0.1:1");
        for bad in [
            json!({"port": 1, "token": "t"}),
            json!({"host": "h", "token": "t"}),
            json!({"host": "h", "port": 1}),
            json!({"host": "h", "port": 70000, "token": "t"}),
            json!({"host": "h", "port": 0, "token": "t"}),
        ] {
            assert!(Endpoint::from_value(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn fields_helper_builds_a_json_object() {
        let f = fields([("a", Value::from(1)), ("b", Value::Bool(true))]);
        assert_eq!(Value::Object(f), json!({"a": 1, "b": true}));
    }
}
