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
//! The session state and the commands of the lite daemon: the clients, the projects they joined and
//! the programs they opened, held the way `Session`, `ProjectEntry` and `ProgramEntry` hold them,
//! and the commands of the lite set (HYDRA-LITE.md) executed against it. A request that is not in
//! the set, or whose answer would need something this build cannot reproduce, is a
//! [`Failure::Refuse`], never a guess.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use crate::error::{Failure, Reason, Refusal, SessionError, USE_FULL_DAEMON, refuse};
use crate::identity::{Identity, Live, SUPPORTED_GHIDRA, requested_protocol};
use crate::javaish::ChmOrder;
use crate::json::{Json, parse};
use crate::os::now_ms;
use crate::program::{self, ProgramView};
use crate::project::{self, Index, IndexItem, Resolved};
use crate::request::Request;

/// How long a computed disk revision is reused (`ProjectEntry.REVISION_TTL_MS`).
const REVISION_TTL_MS: u64 = 1000;

/// The most programs `format` scans (`ProjectFormat.MAX_PROGRAMS`); more are refused, not truncated.
const MAX_FORMAT_PROGRAMS: usize = 64;

/// The longest request line (`Connection.MAX_LINE_BYTES`).
pub const MAX_LINE_BYTES: usize = 64 * 1024 * 1024;

/// How the daemon was started.
#[derive(Debug, Clone)]
pub struct Config {
    /// The instance name (`-instance`).
    pub instance: String,
    /// The endpoint file this daemon publishes.
    pub endpoint_file: String,
    /// The token clients must present.
    pub token: String,
    /// The listening port.
    pub port: u16,
    /// The process id.
    pub pid: u32,
    /// When the daemon started, epoch milliseconds.
    pub started_at: u64,
    /// How long an unused read-only program or project stays open (`-keepWarm`), milliseconds.
    pub keep_warm_ms: u64,
}

#[derive(Debug, Clone)]
struct ClientState {
    name: String,
    harness: String,
    protocol: u8,
    protocol_fixed: bool,
    projects: Vec<String>,
    active_project: Option<String>,
    programs: Vec<String>,
    active: Option<String>,
    seen_generation: HashMap<String, i64>,
}

#[derive(Debug, Clone)]
struct ProgramEntry {
    path: String,
    key: String,
    view: Arc<ProgramView>,
    users: Vec<u32>,
    revision: String,
    last_used: u64,
    open_ms: u64,
}

#[derive(Debug)]
struct ProjectEntry {
    id: String,
    resolved: Resolved,
    canonical: String,
    open_ms: u64,
    last_used: u64,
    users: Vec<u32>,
    programs: Vec<ProgramEntry>,
    open_revision: Option<String>,
    generation: i64,
    disk: Option<(Option<String>, Instant)>,
    format: Json,
}

impl ProjectEntry {
    fn disk_revision(&mut self) -> Option<String> {
        if let Some((rev, at)) = &self.disk
            && u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX) < REVISION_TTL_MS
        {
            return rev.clone();
        }
        let rev = project::revision(&self.resolved).ok();
        self.disk = Some((rev.clone(), Instant::now()));
        rev
    }

    fn stale(&mut self) -> bool {
        let open = self.open_revision.clone();
        let disk = self.disk_revision();
        matches!((open, disk), (Some(o), Some(d)) if o != d)
    }

    fn program(&self, path: &str) -> Option<&ProgramEntry> {
        self.programs.iter().find(|e| e.path == path)
    }
}

#[derive(Debug, Default)]
struct State {
    clients: BTreeMap<u32, ClientState>,
    next_client: u32,
    next_project: u32,
    projects: Vec<ProjectEntry>,
    ids: ChmOrder,
}

impl State {
    fn project(&self, id: &str) -> Option<&ProjectEntry> {
        self.projects.iter().find(|p| p.id == id)
    }

    fn project_mut(&mut self, id: &str) -> Option<&mut ProjectEntry> {
        self.projects.iter_mut().find(|p| p.id == id)
    }

    fn client(&self, id: u32) -> Result<&ClientState, Failure> {
        self.clients
            .get(&id)
            .ok_or_else(|| SessionError::new("failed", "the client is gone").into())
    }

    fn client_mut(&mut self, id: u32) -> Result<&mut ClientState, Failure> {
        self.clients
            .get_mut(&id)
            .ok_or_else(|| SessionError::new("failed", "the client is gone").into())
    }
}

/// The engine: state shared by every connection.
#[derive(Debug)]
pub struct Engine {
    cfg: Config,
    identity: Option<Identity>,
    state: Mutex<State>,
    slots: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    stopping: AtomicBool,
    /// Requests answered with a result or an error the Java daemon gives too.
    pub answered: AtomicU64,
    /// Requests refused with `use_full_daemon`.
    pub refused: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Which listing `project_list` builds: the `projects` of `hello` or the command `projects`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListMode {
    Hello,
    Projects,
}

/// A count as a JSON number.
fn count(n: usize) -> Json {
    Json::uint(u64::try_from(n).unwrap_or(u64::MAX))
}

fn is_project_id(s: &str) -> bool {
    s.strip_prefix('p')
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// `PROGRAM_KEY` `(p\d+):(/.*)` as `matches()`: the project id and the path.
fn program_key(text: &str) -> Option<(&str, &str)> {
    let colon = text.find(':')?;
    let (id, rest) = (&text[..colon], &text[colon + 1..]);
    if !is_project_id(id) || !rest.starts_with('/') {
        return None;
    }
    if rest
        .chars()
        .any(|c| matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}'))
    {
        return None;
    }
    Some((id, rest))
}

/// A path the project's folder tree answers exactly as written: `/`, or `/a/b` with no empty or
/// dotted segment.
fn canonical_path(p: &str) -> bool {
    if p == "/" {
        return true;
    }
    p.starts_with('/')
        && p[1..]
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != ".." && !s.chars().any(char::is_control))
}

fn join_path(folder: &str, name: &str) -> String {
    if folder == "/" {
        format!("/{name}")
    } else {
        format!("{folder}/{name}")
    }
}

fn unsupported_request(msg: impl Into<String>) -> Failure {
    refuse(Reason::UnsupportedRequest, msg)
}

/// `Scheduler.decide` gives these commands a slot, so `Session.execute` reads `wait` before the
/// command runs.
fn admits_with_wait(cmd: &str) -> bool {
    matches!(
        cmd,
        "list"
            | "functions"
            | "decompile"
            | "rename"
            | "comment"
            | "open_program"
            | "switch"
            | "open_project"
    )
}

/// The commands a protocol 3 connection runs in parallel unless the request says `ordered`.
fn read_class(cmd: &str) -> bool {
    matches!(
        cmd,
        "info"
            | "functions"
            | "decompile"
            | "list"
            | "project"
            | "projects"
            | "programs"
            | "journal"
            | "overlays"
    )
}

/// What a connection does with a reply.
#[derive(Debug, Default)]
pub struct Output {
    /// The reply line without its terminator, if the request gets one.
    pub line: Option<String>,
    /// Close the connection after sending it.
    pub close: bool,
    /// The reply is the answer to a `shutdown` that stops the daemon.
    pub stop: bool,
}

/// One client connection: its login state and the engine state of its client.
#[derive(Debug)]
pub struct Connection {
    engine: Arc<Engine>,
    id: u32,
    authenticated: bool,
    diverged: bool,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.engine.disconnect(self.id);
    }
}

impl Engine {
    /// Creates the engine. Without an identity only `ping` is answered.
    #[must_use]
    pub fn new(cfg: Config, identity: Option<Identity>) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            identity,
            state: Mutex::new(State {
                next_client: 1,
                next_project: 1,
                ..State::default()
            }),
            slots: Mutex::new(HashMap::new()),
            stopping: AtomicBool::new(false),
            answered: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        })
    }

    /// True once a `shutdown` has been accepted.
    #[must_use]
    pub fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Registers a new client and returns its connection (`Session.connect`).
    #[must_use]
    pub fn connect(self: &Arc<Self>) -> Connection {
        let mut st = lock(&self.state);
        let id = st.next_client;
        st.next_client += 1;
        st.clients.insert(
            id,
            ClientState {
                name: String::new(),
                harness: String::new(),
                protocol: 2,
                protocol_fixed: false,
                projects: Vec::new(),
                active_project: None,
                programs: Vec::new(),
                active: None,
                seen_generation: HashMap::new(),
            },
        );
        Connection {
            engine: Arc::clone(self),
            id,
            authenticated: false,
            diverged: false,
        }
    }

    /// The number of connected clients.
    #[must_use]
    pub fn client_count(&self) -> usize {
        lock(&self.state).clients.len()
    }

    /// `Session.disconnect`: the client leaves every project it joined.
    fn disconnect(&self, id: u32) {
        let mut st = lock(&self.state);
        let joined: Vec<String> = st
            .clients
            .get(&id)
            .map(|c| c.projects.clone())
            .unwrap_or_default();
        for pid in joined {
            self.leave_project(&mut st, id, &pid);
        }
        st.clients.remove(&id);
    }

    /// `Session.reap`: closes the programs and projects nobody used for the keep-warm time.
    pub fn reap(&self) {
        let now = now_ms();
        let warm = self.cfg.keep_warm_ms;
        let mut st = lock(&self.state);
        let mut closed = Vec::new();
        for p in &mut st.projects {
            p.programs
                .retain(|e| !(e.users.is_empty() && now.saturating_sub(e.last_used) >= warm));
            if p.users.is_empty()
                && p.programs.is_empty()
                && now.saturating_sub(p.last_used) >= warm
            {
                closed.push(p.id.clone());
            }
        }
        for id in closed {
            st.projects.retain(|p| p.id != id);
            st.ids.remove(&id);
        }
    }

    /// The pause between two reaps (`HeadlessSession.startReaper`).
    #[must_use]
    pub fn reap_lap_ms(&self) -> u64 {
        (self.cfg.keep_warm_ms / 4).clamp(1000, 15_000)
    }

    fn slot(&self, canonical: &str) -> Arc<Mutex<()>> {
        Arc::clone(
            lock(&self.slots)
                .entry(canonical.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    fn identity(&self) -> Result<&Identity, Failure> {
        let id = self.identity.as_ref().ok_or_else(|| {
            refuse(
                Reason::NoIdentity,
                "this daemon has not learned the engine's identity",
            )
        })?;
        if id.ghidra_version() != Some(SUPPORTED_GHIDRA) {
            return Err(refuse(
                Reason::UnsupportedEngine,
                format!(
                    "the engine runs Ghidra {}, this build was checked against {SUPPORTED_GHIDRA}",
                    id.ghidra_version().unwrap_or("(unknown)")
                ),
            ));
        }
        Ok(id)
    }

    fn live(&self, client: u32) -> Live<'_> {
        Live {
            instance: &self.cfg.instance,
            endpoint_file: &self.cfg.endpoint_file,
            pid: self.cfg.pid,
            port: self.cfg.port,
            started_at: self.cfg.started_at,
            now: now_ms(),
            client,
        }
    }
}

// ---- the reply envelope -------------------------------------------------------------------------

fn error_object(code: &str, message: &str, details: Option<&Json>) -> Json {
    let mut e = Json::obj()
        .with("code", Json::str(code))
        .with("message", Json::str(message));
    if let Some(d) = details {
        e.put("details", d.clone());
    }
    e
}

fn envelope(id: Option<&Json>, outcome: Result<Json, Json>, ms: u64) -> Json {
    let mut o = Json::obj();
    if let Some(id) = id {
        o.put("id", id.clone());
    }
    match outcome {
        Ok(result) => {
            o.put("ok", Json::Bool(true));
            o.put("result", result);
        }
        Err(error) => {
            o.put("ok", Json::Bool(false));
            o.put("error", error);
        }
    }
    o.put("ms", Json::uint(ms));
    o
}

fn refusal_json(r: &Refusal, cmd: &str) -> Json {
    let mut details = Json::obj().with("reason", Json::str(r.reason.as_str()));
    if !cmd.is_empty() {
        details.put("cmd", Json::str(cmd));
    }
    error_object(USE_FULL_DAEMON, &r.message, Some(&details))
}

fn failure_json(f: &Failure, cmd: &str) -> Json {
    match f {
        Failure::Error(e) => error_object(e.code, &e.message, e.details.as_ref()),
        Failure::Refuse(r) => refusal_json(r, cmd),
    }
}

impl Connection {
    /// The id of this connection's client.
    #[must_use]
    pub fn client_id(&self) -> u32 {
        self.id
    }

    /// The reply for a request line that could not be read.
    #[must_use]
    pub fn too_long(&mut self) -> Output {
        let e = error_object(
            "bad_request",
            &format!("request line longer than {MAX_LINE_BYTES} bytes"),
            None,
        );
        Output {
            line: Some(envelope(None, Err(e), 0).to_text()),
            close: true,
            stop: false,
        }
    }

    /// Handles one request line (without its terminator).
    pub fn handle(&mut self, raw: &[u8]) -> Output {
        let text = String::from_utf8_lossy(raw);
        if text.chars().all(char::is_whitespace) {
            return Output::default();
        }
        let start = Instant::now();
        let Ok(req @ Json::Obj(_)) = parse(&text) else {
            let r = Refusal::new(
                Reason::UnparsableRequest,
                "the request is not one strict JSON object",
            );
            return self.refusal_output(None, &r, "", 0);
        };
        let id = req.get("id").cloned();
        let cmd = match req.get("cmd") {
            Some(Json::Str(s)) => s.clone(),
            Some(Json::Num(n)) => n.clone(),
            Some(Json::Bool(b)) => b.to_string(),
            _ => String::new(),
        };
        let request = Request::new(req);
        if !self.authenticated {
            return self.authenticate(&request, id.as_ref(), &cmd, &start);
        }
        if cmd == "hello" {
            self.negotiate(&request);
        }
        if let Err(e) = request.label("client").and(request.label("harness")) {
            return self.error_output(id.as_ref(), &Failure::Error(e), &cmd, 0);
        }
        if self.diverged && cmd != "ping" && cmd != "hello" {
            let r = Refusal::new(
                Reason::DivergedConnection,
                "an earlier request on this connection was refused; reconnect to the full daemon",
            );
            return self.refusal_output(id.as_ref(), &r, &cmd, 0);
        }
        let inline = matches!(cmd.as_str(), "ping" | "cancel" | "status" | "health");
        if !inline {
            let v3 = self.v3();
            let early = request.bool_opt("parallel").and_then(|par| {
                if par != Some(true) && v3 && read_class(&cmd) {
                    request.bool_opt("ordered").map(|_| ())
                } else {
                    Ok(())
                }
            });
            if let Err(f) = early {
                return self.error_output(id.as_ref(), &f, &cmd, 0);
            }
        }
        let outcome = self.engine.execute(self.id, &cmd, &request);
        self.finish(id.as_ref(), &cmd, outcome, &start)
    }

    fn v3(&self) -> bool {
        lock(&self.engine.state)
            .clients
            .get(&self.id)
            .is_some_and(|c| c.protocol >= 3)
    }

    fn negotiate(&self, hello: &Request) {
        let mut st = lock(&self.engine.state);
        if let Some(c) = st.clients.get_mut(&self.id)
            && !c.protocol_fixed
        {
            c.protocol = requested_protocol_of(hello);
            c.protocol_fixed = true;
        }
    }

    fn authenticate(
        &mut self,
        req: &Request,
        id: Option<&Json>,
        cmd: &str,
        start: &Instant,
    ) -> Output {
        let supplied = match req.raw("token") {
            Some(Json::Str(s)) => s.as_str(),
            _ => "",
        };
        let ok = cmd == "hello"
            && constant_time_eq(supplied.as_bytes(), self.engine.cfg.token.as_bytes());
        if !ok {
            let e = SessionError::new(
                "unauthorized",
                "the first request must be {\"cmd\":\"hello\",\"token\":...} with the token from the endpoint file",
            );
            let mut out = self.error_output(id, &Failure::Error(e), cmd, 0);
            out.close = true;
            return out;
        }
        self.authenticated = true;
        self.negotiate(req);
        let outcome = self.engine.execute(self.id, cmd, req);
        self.finish(id, cmd, outcome, start)
    }

    fn finish(
        &mut self,
        id: Option<&Json>,
        cmd: &str,
        outcome: Result<Json, Failure>,
        start: &Instant,
    ) -> Output {
        let inline = matches!(cmd, "ping" | "cancel" | "status" | "health");
        let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut out = match outcome {
            Ok(result) => {
                self.engine.answered.fetch_add(1, Ordering::Relaxed);
                let stop = cmd == "shutdown";
                if stop {
                    self.engine.stopping.store(true, Ordering::SeqCst);
                }
                Output {
                    line: Some(envelope(id, Ok(result), elapsed).to_text()),
                    close: false,
                    stop,
                }
            }
            Err(Failure::Error(e)) => {
                self.engine.answered.fetch_add(1, Ordering::Relaxed);
                Output {
                    line: Some(
                        envelope(id, Err(failure_json(&Failure::Error(e), cmd)), elapsed).to_text(),
                    ),
                    close: false,
                    stop: false,
                }
            }
            Err(Failure::Refuse(r)) => return self.refusal_output(id, &r, cmd, elapsed),
        };
        if !inline && let Some(line) = out.line.take() {
            out.line = Some(self.engine.annotate(self.id, line));
        }
        out
    }

    fn error_output(&self, id: Option<&Json>, f: &Failure, cmd: &str, ms: u64) -> Output {
        self.engine.answered.fetch_add(1, Ordering::Relaxed);
        Output {
            line: Some(envelope(id, Err(failure_json(f, cmd)), ms).to_text()),
            close: false,
            stop: false,
        }
    }

    fn refusal_output(&mut self, id: Option<&Json>, r: &Refusal, cmd: &str, ms: u64) -> Output {
        self.diverged = true;
        self.engine.refused.fetch_add(1, Ordering::Relaxed);
        Output {
            line: Some(envelope(id, Err(refusal_json(r, cmd)), ms).to_text()),
            close: false,
            stop: false,
        }
    }
}

fn requested_protocol_of(hello: &Request) -> u8 {
    let mut j = Json::obj();
    if let Some(p) = hello.raw("protocol") {
        j.put("protocol", p.clone());
    }
    requested_protocol(&j)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = u8::from(a.len() != b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---- annotate ------------------------------------------------------------------------------------

impl Engine {
    /// `Session.annotate`: adds `stale` (and `refreshed`) to a reply line of a non-inline command.
    fn annotate(&self, client: u32, line: String) -> String {
        let mut st = lock(&self.state);
        let Some(c) = st.clients.get(&client) else {
            return line;
        };
        let joined = c.projects.clone();
        let mut stale = Vec::new();
        let mut refreshed = Vec::new();
        for id in joined {
            let Some(p) = st.project_mut(&id) else {
                continue;
            };
            let generation = p.generation;
            let (open_rev, is_stale, disk) = {
                let s = p.stale();
                (
                    p.open_revision.clone(),
                    s,
                    p.disk.as_ref().and_then(|d| d.0.clone()),
                )
            };
            let seen = st
                .clients
                .get_mut(&client)
                .and_then(|c| c.seen_generation.insert(id.clone(), generation));
            if seen.is_some_and(|s| s < generation) {
                refreshed.push(Json::obj().with("project", Json::str(&id)));
            }
            if is_stale {
                stale.push(
                    Json::obj()
                        .with("project", Json::str(&id))
                        .with("revision", Json::opt_str(open_rev.as_deref()))
                        .with("diskRevision", Json::opt_str(disk.as_deref()))
                        .with("suggest", Json::str("refresh")),
                );
            }
        }
        if stale.is_empty() && refreshed.is_empty() {
            return line;
        }
        // the reply object is rewritten with the two members after `ms`
        match parse(&line) {
            Ok(mut j) => {
                if !stale.is_empty() {
                    j.put("stale", Json::Arr(stale));
                }
                if !refreshed.is_empty() {
                    j.put("refreshed", Json::Arr(refreshed));
                }
                j.to_text()
            }
            Err(_) => line,
        }
    }
}

// ---- dispatch ------------------------------------------------------------------------------------

impl Engine {
    fn execute(&self, client: u32, cmd: &str, req: &Request) -> Result<Json, Failure> {
        if cmd == "ping" {
            return Ok(Json::obj().with("pong", Json::Bool(true)));
        }
        let supported = matches!(
            cmd,
            "hello"
                | "projects"
                | "programs"
                | "open_project"
                | "close_project"
                | "project"
                | "list"
                | "open_program"
                | "switch"
                | "info"
                | "close_program"
                | "functions"
                | "shutdown"
        );
        if !supported {
            return Err(refuse(
                Reason::UnsupportedCommand,
                format!("'{cmd}' is not in the lite command set"),
            ));
        }
        self.identity()?;
        if req.bool_opt("parallel")? == Some(true) {
            return Err(unsupported_request(
                "parallel requests are not served by the lite daemon (their replies may overtake each other)",
            ));
        }
        if req.has("overlay") && matches!(cmd, "open_program" | "switch" | "info" | "functions") {
            return Err(unsupported_request(
                "overlays are not served by the lite daemon",
            ));
        }
        if admits_with_wait(cmd) {
            req.wait_ms()?;
        }
        match cmd {
            "hello" => self.hello(client, req),
            "shutdown" => self.shutdown(client, req),
            "projects" => self.projects_cmd(client),
            "programs" => self.programs_cmd(client),
            "open_project" => self.open_project(client, req),
            "close_project" => self.close_project(client, req),
            "project" => self.project_cmd(client, req),
            "list" => self.list_cmd(client, req),
            "open_program" | "switch" => self.open_program(client, req),
            "info" => self.info_cmd(client, req),
            "close_program" => self.close_program(client, req),
            _ => self.functions_cmd(client, req),
        }
    }

    fn hello(&self, client: u32, req: &Request) -> Result<Json, Failure> {
        let identity = self.identity()?;
        let mut st = lock(&self.state);
        {
            let c = st.client_mut(client)?;
            if let Some(n) = req.str_opt("client")? {
                c.name = n;
            }
            if let Some(h) = req.str_opt("harness")? {
                c.harness = h;
            }
            req.str_opt("clientVersion")?;
        }
        let protocol = st.client(client)?.protocol;
        let projects = Self::project_list(&mut st, protocol, ListMode::Hello, client)?;
        Ok(identity.hello_result(protocol, &self.live(client), projects))
    }

    fn shutdown(&self, client: u32, req: &Request) -> Result<Json, Failure> {
        let others = lock(&self.state)
            .clients
            .keys()
            .filter(|k| **k != client)
            .count();
        if others > 0 && !req.bool_opt("force")?.unwrap_or(false) {
            return Err(SessionError::with_details(
                "conflict",
                format!(
                    "{others} other client(s) are connected; pass \"force\":true to stop anyway"
                ),
                Json::obj().with("clients", count(others)),
            )
            .into());
        }
        Ok(Json::obj().with("stopping", Json::Bool(true)))
    }

    /// The `projects` array of `hello` / `projects`: every open project in the Java map's order.
    fn project_list(
        st: &mut State,
        protocol: u8,
        mode: ListMode,
        client: u32,
    ) -> Result<Json, Failure> {
        let order: Vec<String> = st
            .ids
            .order()
            .ok_or_else(|| {
                refuse(
                    Reason::InexactValue,
                    "the order of the project ids is not reproducible",
                )
            })?
            .into_iter()
            .map(str::to_owned)
            .collect();
        let (joined, active) = {
            let c = st.client(client)?;
            (c.projects.clone(), c.active_project.clone())
        };
        let mut out = Vec::with_capacity(order.len());
        for id in order {
            let Some(p) = st.project_mut(&id) else {
                continue;
            };
            let mut j = Self::project_info(p, protocol)?;
            if mode == ListMode::Projects {
                j.put("joined", Json::Bool(joined.contains(&id)));
                j.put("active", Json::Bool(active.as_deref() == Some(id.as_str())));
            }
            out.push(j);
        }
        Ok(Json::Arr(out))
    }

    fn projects_cmd(&self, client: u32) -> Result<Json, Failure> {
        let mut st = lock(&self.state);
        let protocol = st.client(client)?.protocol;
        let list = Self::project_list(&mut st, protocol, ListMode::Projects, client)?;
        let active = st.client(client)?.active_project.clone();
        Ok(Json::obj()
            .with("activeProject", Json::opt_str(active.as_deref()))
            .with("projects", list))
    }

    /// `ProjectEntry.info`.
    fn project_info(p: &mut ProjectEntry, protocol: u8) -> Result<Json, Failure> {
        let now = now_ms();
        let files = Index::read(&p.resolved.index_file())?.item_count();
        let disk = p.disk_revision();
        let stale = p.stale();
        let mut o = Json::obj()
            .with("id", Json::str(&p.id))
            .with("name", Json::str(&p.resolved.name))
            .with("dir", Json::str(&p.resolved.dir))
            .with("gpr", Json::str(p.resolved.gpr()))
            .with("writable", Json::Bool(false))
            .with("openMs", Json::uint(p.open_ms))
            .with("idleMs", Json::uint(now.saturating_sub(p.last_used)))
            .with("files", count(files))
            .with("users", Json::ints(p.users.iter().map(|u| u64::from(*u))))
            .with("programs", count(p.programs.len()))
            .with("revision", Json::opt_str(p.open_revision.as_deref()))
            .with("diskRevision", Json::opt_str(disk.as_deref()))
            .with("stale", Json::Bool(stale))
            .with("generation", Json::int(p.generation))
            .with("fork", Json::Null);
        if protocol >= 3 {
            o.put("format", p.format.clone());
        }
        Ok(o)
    }

    /// `Access.projectFor`.
    fn project_for(st: &State, client: u32, req: &Request) -> Result<String, Failure> {
        let mut key = req.str_opt("project")?;
        if key.is_none() && req.has("program") {
            let prog = req.str("program")?;
            if let Some((id, _)) = program_key(&prog) {
                key = Some(id.to_owned());
            }
        }
        let c = st.client(client)?;
        let key = key.or_else(|| c.active_project.clone()).ok_or_else(|| {
            SessionError::no_project("no project selected; send open_project first")
        })?;
        let mut found = st.project(&key).map(|p| p.id.clone());
        if found.is_none() && !is_project_id(&key) {
            let r = project::resolve(&key)?;
            let canon = project::canonical(&r);
            found = st
                .projects
                .iter()
                .find(|p| p.canonical == canon)
                .map(|p| p.id.clone());
        }
        let Some(id) = found else {
            return Err(SessionError::with_details(
                "no_project",
                format!("project {key} is not open; send open_project"),
                Json::obj().with("project", Json::str(&key)),
            )
            .into());
        };
        if !c.projects.contains(&id) {
            return Err(SessionError::with_details(
                "no_project",
                format!("this client has not joined project {id}; send open_project"),
                Json::obj().with("project", Json::str(&id)),
            )
            .into());
        }
        Ok(id)
    }

    fn project_cmd(&self, client: u32, req: &Request) -> Result<Json, Failure> {
        let mut st = lock(&self.state);
        let id = Self::project_for(&st, client, req)?;
        req.wait_ms()?;
        let protocol = st.client(client)?.protocol;
        let p = st
            .project_mut(&id)
            .ok_or_else(|| SessionError::no_project(format!("project {id} was closed")))?;
        let info = Self::project_info(p, protocol);
        p.last_used = now_ms();
        info
    }
}

// ---- open_project / close_project ---------------------------------------------------------------

impl Engine {
    fn join_project(st: &mut State, client: u32, id: &str) -> Result<(), Failure> {
        let now = now_ms();
        if let Some(p) = st.project_mut(id) {
            if !p.users.contains(&client) {
                p.users.push(client);
            }
            p.last_used = now;
        }
        let generation = st.project(id).map_or(1, |p| p.generation);
        let c = st.client_mut(client)?;
        c.seen_generation.entry(id.to_owned()).or_insert(generation);
        if !c.projects.iter().any(|x| x == id) {
            c.projects.push(id.to_owned());
        }
        c.active_project = Some(id.to_owned());
        Ok(())
    }

    fn open_project(&self, client: u32, req: &Request) -> Result<Json, Failure> {
        let path = req.str("path")?;
        let resolved = project::resolve(&path)?;
        let writable = req.bool_opt("writable")?.unwrap_or(false);
        req.bool_opt("discard")?;
        if writable {
            return Err(unsupported_request(
                "a writable project is for the full daemon",
            ));
        }
        let canonical = project::canonical(&resolved);
        let slot = self.slot(&canonical);
        let _guard = lock(&slot);
        {
            let mut st = lock(&self.state);
            let existing = st
                .projects
                .iter()
                .find(|p| p.canonical == canonical)
                .map(|p| p.id.clone());
            if let Some(id) = existing {
                Self::join_project(&mut st, client, &id)?;
                let protocol = st.client(client)?.protocol;
                let p = st
                    .project_mut(&id)
                    .ok_or_else(|| SessionError::no_project("the project was closed"))?;
                let mut info = Self::project_info(p, protocol)?;
                info.put("opened", Json::Bool(false));
                return Ok(info);
            }
        }
        let t0 = Instant::now();
        let built = self.build_project(&resolved)?;
        let open_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut st = lock(&self.state);
        let id = format!("p{}", st.next_project);
        st.next_project += 1;
        st.ids.insert(&id);
        st.projects.push(ProjectEntry {
            id: id.clone(),
            resolved,
            canonical,
            open_ms,
            last_used: now_ms(),
            users: Vec::new(),
            programs: Vec::new(),
            open_revision: built.0,
            generation: 1,
            disk: None,
            format: built.1,
        });
        Self::join_project(&mut st, client, &id)?;
        let protocol = st.client(client)?.protocol;
        let p = st
            .project_mut(&id)
            .ok_or_else(|| SessionError::no_project("the project was closed"))?;
        let mut info = Self::project_info(p, protocol)?;
        info.put("opened", Json::Bool(true));
        Ok(info)
    }

    /// Everything a project must satisfy to be presented here, and its `format` block. Returns the
    /// revision it was opened at.
    fn build_project(&self, r: &Resolved) -> Result<(Option<String>, Json), Failure> {
        let bad = |m: String| refuse(Reason::UnsupportedProject, m);
        if let Some(name) = project::sweep_pending(&r.dir) {
            return Err(bad(format!(
                "{} holds {name}, which the full daemon cleans up before it opens a project",
                r.dir
            )));
        }
        if Path::new(&r.sidecar()).exists() {
            return Err(bad("the project is a fork of another".into()));
        }
        let revision = project::revision(r).ok();
        let index = Index::read(&r.index_file())?;
        let versioned = Path::new(&r.rep()).join("versioned").join("~index.dat");
        if versioned.exists() && Index::read(&versioned)?.item_count() > 0 {
            return Err(bad("the project has versioned files".into()));
        }
        let identity = self.identity()?;
        let format = Self::format_block(r, &index, identity)?;
        Ok((revision, format))
    }

    fn format_block(r: &Resolved, index: &Index, identity: &Identity) -> Result<Json, Failure> {
        let idata = Path::new(&r.rep()).join("idata");
        let mut programs = 0usize;
        let mut dt = false;
        let mut stack = vec!["/".to_owned()];
        while let Some(folder) = stack.pop() {
            for sub in index.sub_folders(&folder) {
                stack.push(join_path(&folder, &sub));
            }
            for item in index.folder(&folder).map(Vec::as_slice).unwrap_or_default() {
                let props = project::read_props(&idata, item)?;
                if props.file_type != 0 || props.content_type != "Program" {
                    return Err(refuse(
                        Reason::UnsupportedProject,
                        format!(
                            "{} is not a database program ({})",
                            item.name, props.content_type
                        ),
                    ));
                }
                let stored = project::stored_file(&idata, item)?;
                let header = project::read_header(&stored.path).map_err(|e| {
                    refuse(Reason::UnsupportedProgram, format!("{}: {e}", item.name))
                })?;
                program::check_header(&header)?;
                dt |= header.data_type_manager.is_some();
                programs += 1;
            }
        }
        if programs > MAX_FORMAT_PROGRAMS {
            return Err(refuse(
                Reason::UnsupportedProject,
                format!("more than {MAX_FORMAT_PROGRAMS} programs"),
            ));
        }
        let h = identity.hello_value("hydraVersion");
        let g = identity.hello_value("ghidraVersion");
        let versions = |v: i64| {
            Json::obj()
                .with("min", Json::int(v))
                .with("max", Json::int(v))
                .with("current", Json::int(v))
        };
        let (pmin, dtm) = if programs == 0 {
            (
                Json::obj()
                    .with("min", Json::Null)
                    .with("max", Json::Null)
                    .with("current", Json::int(program::PROGRAM_DB_VERSION)),
                Json::Null,
            )
        } else {
            (
                versions(program::PROGRAM_DB_VERSION),
                if dt {
                    versions(program::DATA_TYPE_DB_VERSION)
                } else {
                    Json::Null
                },
            )
        };
        Ok(Json::obj()
            .with("programDb", pmin)
            .with("dataTypeDb", dtm)
            .with("upgradeRequired", Json::Bool(false))
            .with("oneWay", Json::Bool(false))
            .with("newerThanEngine", Json::Bool(false))
            .with("programsScanned", count(programs))
            .with("truncated", Json::Bool(false))
            .with(
                "engine",
                Json::obj().with("hydraVersion", h).with("ghidraVersion", g),
            ))
    }

    fn close_project(&self, client: u32, req: &Request) -> Result<Json, Failure> {
        let mut st = lock(&self.state);
        let id = Self::project_for(&st, client, req)?;
        req.bool_opt("discard")?;
        req.wait_ms()?;
        let closed = self.leave_project(&mut st, client, &id);
        let active = st.client(client)?.active_project.clone();
        Ok(Json::obj()
            .with("project", Json::str(&id))
            .with("left", Json::Bool(true))
            .with("closed", Json::Bool(closed))
            .with("activeProject", Json::opt_str(active.as_deref())))
    }

    /// `ProjectCommands.leaveProject`. Returns true when the project was closed.
    fn leave_project(&self, st: &mut State, client: u32, id: &str) -> bool {
        let prefix = format!("{id}:");
        let mine: Vec<String> = st
            .clients
            .get(&client)
            .map(|c| {
                c.programs
                    .iter()
                    .filter(|k| k.starts_with(&prefix))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let keep_warm_ms = self.cfg.keep_warm_ms;
        for key in mine {
            Self::release_use(st, client, &key, keep_warm_ms);
        }
        if let Some(p) = st.project_mut(id) {
            p.users.retain(|u| *u != client);
            p.last_used = now_ms();
        }
        if let Some(c) = st.clients.get_mut(&client) {
            c.seen_generation.remove(id);
            c.projects.retain(|x| x != id);
            if c.active_project.as_deref() == Some(id) {
                c.active_project = c.projects.first().cloned();
            }
        }
        let close =
            self.cfg.keep_warm_ms == 0 && st.project(id).is_some_and(|p| p.users.is_empty());
        if close {
            st.projects.retain(|p| p.id != id);
            st.ids.remove(id);
        }
        close
    }

    /// `releaseUseHeld` for a read-only program and a plain reader.
    fn release_use(st: &mut State, client: u32, key: &str, keep_warm_ms: u64) {
        let dispose = keep_warm_ms == 0;
        let Some((pid, path)) = program_key(key) else {
            return;
        };
        if let Some(p) = st.project_mut(pid) {
            let now = now_ms();
            if let Some(e) = p.programs.iter_mut().find(|e| e.path == path) {
                e.users.retain(|u| *u != client);
                e.last_used = now;
            }
            if dispose {
                p.programs
                    .retain(|e| !(e.path == path && e.users.is_empty()));
            }
        }
        if let Some(c) = st.clients.get_mut(&client) {
            c.programs.retain(|k| k != key);
            if c.active.as_deref() == Some(key) {
                c.active = c.programs.first().cloned();
            }
        }
    }
}

// ---- programs -----------------------------------------------------------------------------------

/// The newest stored file of a program item, after checking that the item is a database program.
fn stored_of(r: &Resolved, item: &IndexItem) -> Result<project::StoredFile, Failure> {
    let idata = Path::new(&r.rep()).join("idata");
    let props = project::read_props(&idata, item)?;
    if props.file_type != 0 || props.content_type != "Program" {
        return Err(refuse(
            Reason::UnsupportedProject,
            format!(
                "{} is not a database program ({})",
                item.name, props.content_type
            ),
        ));
    }
    project::stored_file(&idata, item)
}

/// The domain metadata of a stored program (`GhidraFileData.getMetadata`), read from its header.
fn metadata_of(
    stored: &project::StoredFile,
    item: &IndexItem,
) -> Result<Vec<(String, String)>, Failure> {
    project::read_header(&stored.path)
        .map(|h| h.metadata)
        .map_err(|e| refuse(Reason::UnsupportedProgram, format!("{}: {e}", item.name)))
}

fn md_value<'a>(md: &'a [(String, String)], key: &str) -> Option<&'a str> {
    md.iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// `collectByName`: the files with this name, depth first, folders in `String` order.
fn collect(index: &Index, folder: &str, name: &str, out: &mut Vec<(String, IndexItem)>) {
    if let Some(i) = index
        .folder(folder)
        .and_then(|items| items.iter().find(|i| i.name == name))
    {
        out.push((join_path(folder, name), i.clone()));
    }
    for sub in index.sub_folders(folder) {
        collect(index, &join_path(folder, &sub), name, out);
    }
}

/// Looks a file up by project path (`/a/b`) or bare name, as `ProjectCommands.findFile` does.
fn find_file(p_id: &str, index: &Index, name: &str) -> Result<(String, IndexItem), Failure> {
    if name.starts_with('/') {
        if !canonical_path(name) || name == "/" {
            return Err(refuse(
                Reason::InexactValue,
                format!("the path {name} is not one the project tree resolves exactly"),
            ));
        }
        let slash = name.rfind('/').unwrap_or(0);
        let folder = if slash == 0 { "/" } else { &name[..slash] };
        let leaf = &name[slash + 1..];
        let hit = index
            .folder(folder)
            .and_then(|items| items.iter().find(|i| i.name == leaf));
        return match hit {
            Some(item) => Ok((name.to_owned(), item.clone())),
            None => Err(
                SessionError::not_found(format!("no such file in project {p_id}: {name}")).into(),
            ),
        };
    }
    if name.contains('/') || name.is_empty() {
        return Err(refuse(
            Reason::InexactValue,
            format!("the name {name:?} is not one the project tree resolves exactly"),
        ));
    }
    let mut found: Vec<(String, IndexItem)> = Vec::new();
    // depth first, folders in String order, as `collectByName` walks them
    collect(index, "/", name, &mut found);
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(SessionError::not_found(format!("no file named {name} in project {p_id}")).into()),
        _ => Err(SessionError::with_details(
            "conflict",
            format!("several files are named {name}; pass the project path"),
            Json::obj().with(
                "candidates",
                Json::strings(found.iter().map(|(p, _)| p.as_str())),
            ),
        )
        .into()),
    }
}

impl Engine {
    fn open_program(&self, client: u32, req: &Request) -> Result<Json, Failure> {
        let path = req.str("path")?;
        let (scoped_project, name) = match program_key(&path) {
            Some((id, p)) => (Some(id.to_owned()), p.to_owned()),
            None => (None, path.clone()),
        };
        let (pid, resolved) = {
            let st = lock(&self.state);
            let id = match &scoped_project {
                Some(id) => Self::project_for_key(&st, client, id)?,
                None => Self::project_for(&st, client, req)?,
            };
            req.wait_ms()?;
            let p = st
                .project(&id)
                .ok_or_else(|| SessionError::no_project(format!("project {id} was closed")))?;
            (id, p.resolved.clone())
        };
        let writable = req.bool_opt("writable")?.unwrap_or(false);
        let share = req.bool_opt("share")?.unwrap_or(false);
        if share && !writable {
            return Err(SessionError::bad_request(
                "\"share\":true opens a program writable for several clients; it needs \"writable\":true",
            )
            .into());
        }
        if writable {
            return Err(unsupported_request(
                "a writable program is for the full daemon",
            ));
        }
        let index = Index::read(&resolved.index_file())?;
        let (file_path, item) = find_file(&pid, &index, &name)?;
        let stored = stored_of(&resolved, &item)?;
        let key = format!("{pid}:{file_path}");
        // join an open program, or open it outside the state lock
        {
            let mut st = lock(&self.state);
            if st
                .project(&pid)
                .and_then(|p| p.program(&file_path))
                .is_some()
            {
                Self::use_program(&mut st, client, &pid, &file_path, 0)?;
                return Self::program_info(&st, client, &pid, &file_path);
            }
        }
        let t0 = Instant::now();
        let view = program::open(&stored, &item.name)?;
        let open_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        let revision = project::program_revision(
            &file_path,
            stored.length,
            stored.modified_ms,
            stored.version,
        );
        let mut st = lock(&self.state);
        let p = st
            .project_mut(&pid)
            .ok_or_else(|| SessionError::no_project(format!("project {pid} was closed")))?;
        let opened_here = p.program(&file_path).is_none();
        if opened_here {
            p.programs.push(ProgramEntry {
                path: file_path.clone(),
                key,
                view: Arc::new(view),
                users: Vec::new(),
                revision,
                last_used: now_ms(),
                open_ms,
            });
        }
        Self::use_program(
            &mut st,
            client,
            &pid,
            &file_path,
            if opened_here { open_ms } else { 0 },
        )?;
        Self::program_info(&st, client, &pid, &file_path)
    }

    fn project_for_key(st: &State, client: u32, id: &str) -> Result<String, Failure> {
        // `scoped.addProperty("project", id)` then projectFor: the key is a project id
        let c = st.client(client)?;
        let Some(p) = st.project(id) else {
            return Err(SessionError::with_details(
                "no_project",
                format!("project {id} is not open; send open_project"),
                Json::obj().with("project", Json::str(id)),
            )
            .into());
        };
        if !c.projects.contains(&p.id) {
            return Err(SessionError::with_details(
                "no_project",
                format!(
                    "this client has not joined project {}; send open_project",
                    p.id
                ),
                Json::obj().with("project", Json::str(&p.id)),
            )
            .into());
        }
        Ok(p.id.clone())
    }

    /// `useProgram`: the client uses the program and it becomes its active one.
    fn use_program(
        st: &mut State,
        client: u32,
        pid: &str,
        path: &str,
        open_ms: u64,
    ) -> Result<(), Failure> {
        let key = format!("{pid}:{path}");
        let now = now_ms();
        if let Some(p) = st.project_mut(pid) {
            p.last_used = now;
            if let Some(e) = p.programs.iter_mut().find(|e| e.path == path) {
                if !e.users.contains(&client) {
                    e.users.push(client);
                }
                e.last_used = now;
                if open_ms > 0 {
                    e.open_ms = open_ms;
                }
            }
        }
        let c = st.client_mut(client)?;
        if !c.programs.contains(&key) {
            c.programs.push(key.clone());
        }
        c.active = Some(key);
        c.active_project = Some(pid.to_owned());
        Ok(())
    }

    /// `ProgramCommands.programInfo`, with `openMs` appended when the program was just used.
    fn program_info(st: &State, client: u32, pid: &str, path: &str) -> Result<Json, Failure> {
        let mut o = Self::program_info_base(st, client, pid, path)?;
        let open_ms = st
            .project(pid)
            .and_then(|p| p.program(path))
            .map_or(0, |e| e.open_ms);
        o.put("openMs", Json::uint(open_ms));
        Ok(o)
    }

    fn program_info_base(st: &State, client: u32, pid: &str, path: &str) -> Result<Json, Failure> {
        let p = st
            .project(pid)
            .ok_or_else(|| SessionError::no_project(format!("project {pid} was closed")))?;
        let e = p
            .program(path)
            .ok_or_else(|| SessionError::no_program(format!("{pid}:{path} was closed")))?;
        let c = st.client(client)?;
        let v = &e.view;
        Ok(Json::obj()
            .with("key", Json::str(&e.key))
            .with("project", Json::str(pid))
            .with("path", Json::str(path))
            .with("name", Json::str(&v.name))
            .with("mode", Json::str("read_only"))
            .with("owner", Json::Null)
            .with("mine", Json::Bool(false))
            .with(
                "active",
                Json::Bool(c.active.as_deref() == Some(e.key.as_str())),
            )
            .with("language", Json::str(&v.language))
            .with("compiler", Json::str(&v.compiler))
            .with("imageBase", Json::str(&v.image_base))
            .with("format", Json::opt_str(v.format.as_deref()))
            .with("executable", Json::opt_str(v.executable.as_deref()))
            .with("sha256", Json::opt_str(v.sha256.as_deref()))
            .with("md5", Json::opt_str(v.md5.as_deref()))
            .with("functions", count(v.function_count))
            .with("analyzed", Json::Bool(v.analyzed))
            .with("changed", Json::Bool(false))
            .with("revision", Json::str(&e.revision))
            .with("projectRevision", Json::opt_str(p.open_revision.as_deref()))
            .with("generation", Json::int(p.generation))
            .with("cachedUpgrade", Json::Bool(false))
            .with("upgradeCache", Json::Null)
            .with("cacheBuild", Json::str("none"))
            .with("cacheBuildInfo", Json::Null)
            .with("users", Json::ints(e.users.iter().map(|u| u64::from(*u))))
            .with("overlays", Json::Arr(Vec::new()))
            .with("writers", Json::Arr(Vec::new()))
            .with("writer", Json::Bool(false))
            .with("journalSeq", Json::int(0))
            .with("unsavedEdits", Json::int(0)))
    }

    /// `Access.selected`: the program a command acts on, as `(project id, path)`.
    fn selected(st: &State, client: u32, req: &Request) -> Result<(String, String), Failure> {
        let c = st.client(client)?;
        if !req.has("program") {
            let Some(key) = c.active.clone() else {
                return Err(
                    SessionError::no_program("no active program; send open_program first").into(),
                );
            };
            let found = program_key(&key).and_then(|(pid, path)| {
                st.project(pid)
                    .and_then(|p| p.program(path))
                    .map(|_| (pid.to_owned(), path.to_owned()))
            });
            return found.ok_or_else(|| {
                SessionError::no_program(format!("{key} was closed; send open_program")).into()
            });
        }
        let mut path = req.str("program")?;
        let pid = Self::project_for(st, client, req)?;
        if let Some((_, p)) = program_key(&path).map(|(i, p)| (i.to_owned(), p.to_owned())) {
            path = p;
        }
        if !path.starts_with('/') {
            let resolved = st
                .project(&pid)
                .ok_or_else(|| SessionError::no_project(format!("project {pid} was closed")))?
                .resolved
                .clone();
            let index = Index::read(&resolved.index_file())?;
            path = find_file(&pid, &index, &path)?.0;
        }
        let key = format!("{pid}:{path}");
        let open = st.project(&pid).and_then(|p| p.program(&path)).is_some();
        if !open || !c.programs.contains(&key) {
            return Err(SessionError::with_details(
                "no_program",
                format!("{key} is not open for this client; send open_program first"),
                Json::obj().with("program", Json::str(&key)),
            )
            .into());
        }
        Ok((pid, path))
    }

    fn info_cmd(&self, client: u32, req: &Request) -> Result<Json, Failure> {
        let mut st = lock(&self.state);
        let (pid, path) = Self::selected(&st, client, req)?;
        req.wait_ms()?;
        let out = Self::program_info_base(&st, client, &pid, &path);
        Self::touch(&mut st, &pid, &path);
        out
    }

    fn touch(st: &mut State, pid: &str, path: &str) {
        let now = now_ms();
        if let Some(p) = st.project_mut(pid) {
            p.last_used = now;
            if let Some(e) = p.programs.iter_mut().find(|e| e.path == path) {
                e.last_used = now;
            }
        }
    }

    fn programs_cmd(&self, client: u32) -> Result<Json, Failure> {
        let st = lock(&self.state);
        let c = st.client(client)?;
        let mut out = Vec::new();
        for key in &c.programs {
            if let Some((pid, path)) = program_key(key)
                && st.project(pid).and_then(|p| p.program(path)).is_some()
            {
                out.push(Self::program_info_base(&st, client, pid, path)?);
            }
        }
        Ok(Json::obj()
            .with("activeProject", Json::opt_str(c.active_project.as_deref()))
            .with("active", Json::opt_str(c.active.as_deref()))
            .with("programs", Json::Arr(out)))
    }

    fn close_program(&self, client: u32, req: &Request) -> Result<Json, Failure> {
        let mut st = lock(&self.state);
        let (pid, path) = Self::selected(&st, client, req)?;
        req.wait_ms()?;
        req.bool_opt("discard")?;
        let key = format!("{pid}:{path}");
        Self::release_use(&mut st, client, &key, self.cfg.keep_warm_ms);
        let active = st.client(client)?.active.clone();
        Ok(Json::obj()
            .with("closed", Json::str(&key))
            .with("discarded", Json::Bool(false))
            .with("active", Json::opt_str(active.as_deref())))
    }

    fn functions_cmd(&self, client: u32, req: &Request) -> Result<Json, Failure> {
        let (view, pid, path) = {
            let st = lock(&self.state);
            let (pid, path) = Self::selected(&st, client, req)?;
            req.wait_ms()?;
            let view = st
                .project(&pid)
                .and_then(|p| p.program(&path))
                .map(|e| Arc::clone(&e.view))
                .ok_or_else(|| SessionError::no_program(format!("{pid}:{path} was closed")))?;
            (view, pid, path)
        };
        if req.has("regex") {
            return Err(unsupported_request(
                "a regex is Java's java.util.regex; the lite daemon takes `contains` only",
            ));
        }
        let sub = req.str_opt("contains")?;
        let limit = usize::try_from(req.num("limit", 200, 1, 10_000)?).unwrap_or(200);
        let offset = usize::try_from(req.num("offset", 0, 0, i64::from(i32::MAX))?).unwrap_or(0);
        let reply = functions_page(&view, sub.as_deref(), offset, limit);
        Self::touch(&mut lock(&self.state), &pid, &path);
        Ok(reply)
    }
}

/// `FunctionTable.page`: the reply of `functions` for a table and the request's arguments.
#[must_use]
pub fn functions_page(view: &ProgramView, sub: Option<&str>, offset: usize, limit: usize) -> Json {
    let row = |f: &program::FunctionRow| {
        Json::obj()
            .with("name", Json::str(&f.name))
            .with("address", Json::str(&f.address))
            .with("size", Json::uint(f.size))
            .with("thunk", Json::Bool(f.thunk))
            .with("external", Json::Bool(false))
    };
    let n = view.functions.len();
    let mut out = Vec::new();
    let mut truncated = false;
    match sub {
        None => {
            let start = offset.min(n);
            let end = start.saturating_add(limit).min(n);
            out.extend(view.functions[start..end].iter().map(row));
            truncated = n - start > limit;
        }
        Some(sub) => {
            let mut seen = 0usize;
            for f in &view.functions {
                if !f.name.contains(sub) {
                    continue;
                }
                if seen < offset {
                    seen += 1;
                    continue;
                }
                seen += 1;
                if out.len() >= limit {
                    truncated = true;
                    break;
                }
                out.push(row(f));
            }
        }
    }
    Json::obj()
        .with("functions", Json::Arr(out.clone()))
        .with("offset", count(offset))
        .with("returned", count(out.len()))
        .with("truncated", Json::Bool(truncated))
}

// ---- list ---------------------------------------------------------------------------------------

struct Page {
    offset: usize,
    limit: usize,
    out: Vec<Json>,
    index: usize,
    more: bool,
}

impl Page {
    /// `Page.offer`: true when the page is full and the walk can stop.
    fn offer(&mut self, item: impl FnOnce() -> Result<Json, Failure>) -> Result<bool, Failure> {
        let at = self.index;
        self.index += 1;
        if at < self.offset {
            return Ok(false);
        }
        if self.out.len() >= self.limit {
            self.more = true;
            return Ok(true);
        }
        self.out.push(item()?);
        Ok(false)
    }
}

struct ListQuery<'a> {
    r: &'a Resolved,
    pid: &'a str,
    index: &'a Index,
    recursive: bool,
    programs_only: bool,
    metadata: bool,
    sha: Option<&'a str>,
    open: &'a HashMap<String, Json>,
}

impl ListQuery<'_> {
    fn walk(&self, folder: &str, page: &mut Page) -> Result<bool, Failure> {
        for sub in self.index.sub_folders(folder) {
            let path = join_path(folder, &sub);
            if !self.programs_only
                && page.offer(|| {
                    Ok(Json::obj()
                        .with("path", Json::str(&path))
                        .with("kind", Json::str("folder")))
                })?
            {
                return Ok(true);
            }
            if self.recursive && self.walk(&path, page)? {
                return Ok(true);
            }
        }
        let files = self.index.file_order(folder).ok_or_else(|| {
            refuse(
                Reason::InexactValue,
                format!("the order of the files of {folder} is not reproducible"),
            )
        })?;
        for item in files {
            let path = join_path(folder, &item.name);
            if let Some(sha) = self.sha {
                let stored = stored_of(self.r, item)?;
                let metadata = metadata_of(&stored, item)?;
                if !md_value(&metadata, "Executable SHA256")
                    .is_some_and(|v| v.eq_ignore_ascii_case(sha))
                {
                    continue;
                }
            }
            if page.offer(|| self.describe(&path, item))? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn describe(&self, path: &str, item: &IndexItem) -> Result<Json, Failure> {
        let stored = stored_of(self.r, item)?;
        let mut e = Json::obj()
            .with("path", Json::str(path))
            .with("key", Json::str(format!("{}:{path}", self.pid)))
            .with("kind", Json::str("file"))
            .with("name", Json::str(&item.name))
            .with("contentType", Json::str("Program"))
            .with("program", Json::Bool(true))
            .with("versioned", Json::Bool(false))
            .with("readOnly", Json::Bool(true))
            .with("bytes", Json::uint(stored.length));
        if self.metadata {
            let metadata = metadata_of(&stored, item)?;
            e.put(
                "sha256",
                Json::opt_str(md_value(&metadata, "Executable SHA256")),
            );
            e.put(
                "language",
                Json::opt_str(md_value(&metadata, "Language ID")),
            );
            e.put(
                "format",
                Json::opt_str(md_value(&metadata, "Executable Format")),
            );
            e.put(
                "executable",
                Json::opt_str(md_value(&metadata, "Executable Location")),
            );
        }
        e.put("open", self.open.get(path).cloned().unwrap_or(Json::Null));
        Ok(e)
    }
}

impl Engine {
    fn list_cmd(&self, client: u32, req: &Request) -> Result<Json, Failure> {
        let (pid, resolved, open) = {
            let mut st = lock(&self.state);
            let id = Self::project_for(&st, client, req)?;
            req.wait_ms()?;
            let p = st
                .project_mut(&id)
                .ok_or_else(|| SessionError::no_project(format!("project {id} was closed")))?;
            p.last_used = now_ms();
            let now = now_ms();
            let open: HashMap<String, Json> = p
                .programs
                .iter()
                .map(|e| {
                    (
                        e.path.clone(),
                        Json::obj()
                            .with("project", Json::str(&p.id))
                            .with("path", Json::str(&e.path))
                            .with("mode", Json::str("read_only"))
                            .with("owner", Json::Null)
                            .with("idleMs", Json::uint(now.saturating_sub(e.last_used)))
                            .with("users", Json::ints(e.users.iter().map(|u| u64::from(*u))))
                            .with("ownerLabel", Json::Null)
                            .with("busy", Json::Null)
                            .with("writers", Json::Arr(Vec::new()))
                            .with("journalSeq", Json::int(0))
                            .with("unsavedEdits", Json::int(0))
                            .with("orphanedMs", Json::Null)
                            .with("revision", Json::str(&e.revision))
                            .with("cachedUpgrade", Json::Bool(false))
                            .with("cacheBuild", Json::str("none")),
                    )
                })
                .collect();
            (id, p.resolved.clone(), open)
        };
        let folder = req.str_opt("folder")?.unwrap_or_else(|| "/".to_owned());
        let recursive = req.bool_opt("recursive")?.unwrap_or(true);
        let programs_only = req.bool_opt("programsOnly")?.unwrap_or(false);
        let metadata = req.bool_opt("metadata")?.unwrap_or(true);
        let sha = req.str_opt("sha256")?;
        let offset = usize::try_from(req.num("offset", 0, 0, i64::from(i32::MAX))?).unwrap_or(0);
        let limit = usize::try_from(req.num("limit", 1000, 1, 100_000)?).unwrap_or(1000);
        if !canonical_path(&folder) {
            return Err(refuse(
                Reason::InexactValue,
                format!("the folder {folder:?} is not one the project tree resolves exactly"),
            ));
        }
        let index = Index::read(&resolved.index_file())?;
        if index.folder(&folder).is_none() {
            return Err(SessionError::not_found(format!("no such folder: {folder}")).into());
        }
        let q = ListQuery {
            r: &resolved,
            pid: &pid,
            index: &index,
            recursive,
            programs_only: programs_only || sha.is_some(),
            metadata: metadata || sha.is_some(),
            sha: sha.as_deref(),
            open: &open,
        };
        let mut page = Page {
            offset,
            limit,
            out: Vec::new(),
            index: 0,
            more: false,
        };
        q.walk(&folder, &mut page)?;
        let returned = page.out.len();
        Ok(Json::obj()
            .with("project", Json::str(&pid))
            .with("folder", Json::str(&folder))
            .with("entries", Json::Arr(page.out))
            .with("offset", count(offset))
            .with("returned", count(returned))
            .with("truncated", Json::Bool(page.more)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_keys_match_the_java_pattern() {
        assert_eq!(
            program_key("p1:/alpha.exe"),
            Some(("p1", "/alpha.exe")),
            "a key"
        );
        assert_eq!(
            program_key("p12:/a/b"),
            Some(("p12", "/a/b")),
            "a deeper path"
        );
        assert_eq!(program_key("alpha.exe"), None, "a bare name");
        assert_eq!(program_key("p:/x"), None, "no digits");
        assert_eq!(program_key("p1:x"), None, "no slash");
        assert_eq!(
            program_key("p1:/a\nb"),
            None,
            "a line break defeats the dot"
        );
    }

    #[test]
    fn project_ids_and_paths() {
        assert!(is_project_id("p7"), "an id");
        assert!(!is_project_id("p"), "no digits");
        assert!(!is_project_id("P7"), "case");
        assert!(canonical_path("/"), "root");
        assert!(canonical_path("/a/b"), "folders");
        assert!(!canonical_path("/a/"), "trailing slash");
        assert!(!canonical_path("/a//b"), "empty segment");
        assert!(!canonical_path("a"), "relative");
        assert!(!canonical_path("/a/../b"), "dotted");
    }

    fn view(n: usize) -> ProgramView {
        ProgramView {
            name: "x".into(),
            language: "l".into(),
            compiler: "c".into(),
            image_base: "0x0".into(),
            format: None,
            executable: None,
            sha256: None,
            md5: None,
            function_count: n,
            analyzed: false,
            functions: (0..n)
                .map(|i| program::FunctionRow {
                    name: format!("f{i}"),
                    address: format!("0x{:x}", 0x1000 + i),
                    size: 1,
                    thunk: false,
                })
                .collect(),
        }
    }

    #[test]
    fn function_pages_follow_the_table_rules() {
        let v = view(5);
        let p = functions_page(&v, None, 1, 2);
        assert_eq!(
            p.get("returned").map(Json::to_text).as_deref(),
            Some("2"),
            "two rows"
        );
        assert_eq!(
            p.get("truncated").map(Json::to_text).as_deref(),
            Some("true"),
            "more follow"
        );
        let p = functions_page(&v, None, 3, 10);
        assert_eq!(
            p.get("truncated").map(Json::to_text).as_deref(),
            Some("false"),
            "the last page"
        );
        let p = functions_page(&v, Some("f3"), 0, 10);
        assert_eq!(
            p.get("returned").map(Json::to_text).as_deref(),
            Some("1"),
            "contains"
        );
        let p = functions_page(&v, None, 99, 10);
        assert_eq!(
            p.get("returned").map(Json::to_text).as_deref(),
            Some("0"),
            "past the end"
        );
    }

    #[test]
    fn refusals_name_their_reason() {
        let r = Refusal::new(Reason::UnsupportedCommand, "no");
        let j = refusal_json(&r, "decompile");
        assert_eq!(
            j.to_text(),
            r#"{"code":"use_full_daemon","message":"no","details":{"reason":"unsupported_command","cmd":"decompile"}}"#,
            "the documented shape"
        );
    }

    #[test]
    fn constant_time_compare() {
        assert!(constant_time_eq(b"abc", b"abc"), "equal");
        assert!(!constant_time_eq(b"abc", b"abd"), "differs");
        assert!(!constant_time_eq(b"abc", b"abcd"), "length differs");
    }
}
