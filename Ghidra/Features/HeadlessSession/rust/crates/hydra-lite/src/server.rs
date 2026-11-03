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
//! The process around the engine: the command line, the instance lock, the loopback listener, the
//! endpoint file, the connection threads and the idle timeout, all as the Java daemon
//! (`HeadlessSession`) does them.

#![allow(
    clippy::print_stderr,
    reason = "a daemon with no console: stderr is the launcher's log file"
)]

use std::io::{self, BufRead, BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::engine::{Config, Connection, Engine, MAX_LINE_BYTES};
use crate::error::{Reason, USE_FULL_DAEMON};
use crate::identity::{Identity, Live, SUPPORTED_GHIDRA, command_key, learn, write_atomic};
use crate::json::Json;
use crate::os::{now_ms, random_token};

/// The default cap on simultaneous connections.
pub const DEFAULT_WORKERS: usize = 64;

/// What the command line asks for.
#[derive(Debug, Clone)]
pub struct Options {
    /// The Java command line the launcher would have run, after `--`.
    pub java_argv: Vec<String>,
    /// The identity cache file (default `STATE/INSTANCE.front-identity.json`).
    pub identity: Option<PathBuf>,
    /// The most connections served at once.
    pub workers: usize,
    /// `learn`: the endpoint file of a running Java daemon to learn the identity from.
    pub learn_from: Option<PathBuf>,
}

/// The value after `flag` in an argument list.
#[must_use]
pub fn value_of<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .map(String::as_str)
}

/// Parses `[learn] [--identity FILE] [--workers N] [--from ENDPOINT] -- <java command line>`.
///
/// # Errors
///
/// The usage message.
pub fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut o = Options {
        java_argv: Vec::new(),
        identity: None,
        workers: DEFAULT_WORKERS,
        learn_from: None,
    };
    let mut learning = false;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "learn" => learning = true,
            "--identity" => o.identity = Some(it.next().ok_or("--identity needs a file")?.into()),
            "--workers" => {
                o.workers = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|n| *n > 0)
                    .ok_or("--workers needs a number above 0")?;
            }
            "--from" => {
                o.learn_from = Some(it.next().ok_or("--from needs an endpoint file")?.into());
            }
            "--" => {
                o.java_argv = it.collect();
                break;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    if learning && o.learn_from.is_none() {
        return Err("learn needs --from ENDPOINT-FILE".into());
    }
    if !learning {
        o.learn_from = None;
    }
    if o.java_argv.is_empty() {
        return Err(USAGE.into());
    }
    Ok(o)
}

/// The usage text.
pub const USAGE: &str = "usage: hydra-lite [--identity FILE] [--workers N] -- <java command line>\n       hydra-lite learn --from ENDPOINT-FILE [--identity FILE] -- <java command line>";

fn log(msg: &str) {
    eprintln!("hydra-lite: {msg}");
}

fn identity_path(o: &Options) -> Result<PathBuf, String> {
    if let Some(p) = &o.identity {
        return Ok(p.clone());
    }
    let state = value_of(&o.java_argv, "-stateDir").ok_or("the command line has no -stateDir")?;
    let instance =
        value_of(&o.java_argv, "-instance").ok_or("the command line has no -instance")?;
    Ok(Path::new(state).join(format!("{instance}.front-identity.json")))
}

/// `hydra-lite learn`: asks a running Java daemon who it is and keeps the answer.
///
/// # Errors
///
/// A message for the log.
pub fn run_learn(o: &Options) -> Result<(), String> {
    let from = o.learn_from.as_ref().ok_or("learn needs --from")?;
    let path = identity_path(o)?;
    let key = command_key(&o.java_argv);
    let id = learn(from).map_err(|e| format!("{}: {e}", from.display()))?;
    id.save(&path, &key)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    log(&format!(
        "learned the identity of Ghidra {} into {}",
        id.ghidra_version().unwrap_or("?"),
        path.display()
    ));
    Ok(())
}

/// The instance lock: the launcher decides "a daemon is alive" by failing to take this lock, so
/// the daemon holds it for its whole life.
fn hold_instance_lock(state: &Path, instance: &str) -> Result<std::fs::File, String> {
    std::fs::create_dir_all(state).map_err(|e| format!("{}: {e}", state.display()))?;
    let path = state.join(format!("{instance}.lock"));
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    lock.try_lock().map_err(|e| {
        format!(
            "another headless session daemon holds {}: {e}",
            path.display()
        )
    })?;
    Ok(lock)
}

struct Shared {
    engine: Arc<Engine>,
    endpoint_file: PathBuf,
    pid: u32,
    active: AtomicUsize,
    workers: usize,
}

impl Shared {
    /// Removes the endpoint file unless another daemon replaced it (`removeEndpoint`).
    fn remove_endpoint(&self) {
        if let Ok(text) = std::fs::read_to_string(&self.endpoint_file)
            && text.contains(&format!("\"pid\":{},", self.pid))
        {
            let _ = std::fs::remove_file(&self.endpoint_file);
        }
    }

    fn exit(&self) -> ! {
        self.remove_endpoint();
        log(&format!(
            "exiting; answered {}, refused {}",
            self.engine.answered.load(Ordering::Relaxed),
            self.engine.refused.load(Ordering::Relaxed)
        ));
        std::process::exit(0);
    }
}

/// Runs the daemon until it is told to stop or idles out.
///
/// # Errors
///
/// A message for the log when the daemon cannot start.
pub fn run(o: &Options) -> Result<(), String> {
    let state = PathBuf::from(
        value_of(&o.java_argv, "-stateDir").ok_or("the command line has no -stateDir")?,
    );
    let instance = value_of(&o.java_argv, "-instance")
        .ok_or("the command line has no -instance")?
        .to_owned();
    let idle_timeout: u64 = value_of(&o.java_argv, "-idleTimeout")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let keep_warm_s: u64 = value_of(&o.java_argv, "-keepWarm")
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);
    let identity = Identity::load(&identity_path(o)?, &command_key(&o.java_argv)).ok_or(
        "no learned identity for this command line: run `hydra-lite learn` against a Java daemon \
         with it (or start hydra-front once)",
    )?;
    if identity.ghidra_version() != Some(SUPPORTED_GHIDRA) {
        log(&format!(
            "the learned engine runs Ghidra {}, this build was checked against {SUPPORTED_GHIDRA}: \
             every request but ping is refused",
            identity.ghidra_version().unwrap_or("?")
        ));
    }
    let lock = hold_instance_lock(&state, &instance)?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("bind: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let token = random_token().map_err(|e| format!("token: {e}"))?;
    let endpoint_file = state.join(format!("{instance}.json"));
    let pid = std::process::id();
    let started_at = now_ms();
    let endpoint_str = endpoint_file.display().to_string();
    let live = Live {
        instance: &instance,
        endpoint_file: &endpoint_str,
        pid,
        port,
        started_at,
        now: started_at,
        client: 0,
    };
    let endpoint_text = format!("{}\n", identity.endpoint_file(&live, &token).to_text());
    let cfg = Config {
        instance: instance.clone(),
        endpoint_file: endpoint_str.clone(),
        token,
        port,
        pid,
        started_at,
        keep_warm_ms: keep_warm_s.saturating_mul(1000),
    };
    let engine = Engine::new(cfg, Some(identity));
    let shared = Arc::new(Shared {
        engine,
        endpoint_file: endpoint_file.clone(),
        pid,
        active: AtomicUsize::new(0),
        workers: o.workers,
    });
    write_atomic(&endpoint_file, endpoint_text.as_bytes())
        .map_err(|e| format!("endpoint file: {e}"))?;
    log(&format!(
        "listening on 127.0.0.1:{port}, endpoint {}",
        endpoint_file.display()
    ));
    {
        let shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("maint".into())
            .spawn(move || maintain(&shared, idle_timeout))
            .map_err(|e| e.to_string())?;
    }
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        accept(&shared, stream);
    }
    drop(lock);
    Ok(())
}

fn accept(shared: &Arc<Shared>, stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let n = shared.active.fetch_add(1, Ordering::SeqCst);
    if n >= shared.workers {
        shared.active.fetch_sub(1, Ordering::SeqCst);
        refuse_capacity(stream, shared.workers);
        return;
    }
    let conn = shared.engine.connect();
    let s = Arc::clone(shared);
    let spawned = std::thread::Builder::new()
        .name("conn".into())
        .stack_size(512 * 1024)
        .spawn(move || {
            serve(&s, &stream, conn);
            s.active.fetch_sub(1, Ordering::SeqCst);
        });
    if spawned.is_err() {
        shared.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// All workers are busy: say so in the protocol's structured error and close.
fn refuse_capacity(mut stream: TcpStream, workers: usize) {
    let details = Json::obj().with("reason", Json::str(Reason::Capacity.as_str()));
    let err = Json::obj()
        .with("code", Json::str(USE_FULL_DAEMON))
        .with(
            "message",
            Json::str(format!(
                "{workers} connections are served already; use the full daemon"
            )),
        )
        .with("details", details);
    let line = Json::obj()
        .with("ok", Json::Bool(false))
        .with("error", err)
        .with("ms", Json::int(0));
    let _ = stream.write_all(format!("{}\n", line.to_text()).as_bytes());
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);
}

/// One line read with a size limit.
enum Line {
    Text(Vec<u8>),
    TooLong,
    Eof,
}

fn read_line_limited(r: &mut impl BufRead, limit: usize) -> io::Result<Line> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let chunk = r.fill_buf()?;
        if chunk.is_empty() {
            return Ok(if buf.is_empty() {
                Line::Eof
            } else {
                Line::Text(trim_cr(buf))
            });
        }
        let nl = chunk.iter().position(|b| *b == b'\n');
        let end = nl.unwrap_or(chunk.len());
        if buf.len() + end > limit {
            return Ok(Line::TooLong);
        }
        buf.extend_from_slice(&chunk[..end]);
        let used = nl.map_or(end, |i| i + 1);
        r.consume(used);
        if nl.is_some() {
            return Ok(Line::Text(trim_cr(buf)));
        }
    }
}

fn trim_cr(mut b: Vec<u8>) -> Vec<u8> {
    if b.last() == Some(&b'\r') {
        b.pop();
    }
    b
}

fn serve(shared: &Arc<Shared>, stream: &TcpStream, mut conn: Connection) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::with_capacity(1 << 16, read_half);
    let mut writer = io::BufWriter::with_capacity(1 << 16, stream);
    loop {
        let line = match read_line_limited(&mut reader, MAX_LINE_BYTES) {
            Ok(Line::Text(t)) => t,
            Ok(Line::TooLong) => {
                let out = conn.too_long();
                let _ = send(&mut writer, out.line.as_deref());
                break;
            }
            Ok(Line::Eof) | Err(_) => break,
        };
        let out = conn.handle(&line);
        if send(&mut writer, out.line.as_deref()).is_err() {
            break;
        }
        if out.stop {
            drop(conn);
            shared.exit();
        }
        if out.close {
            break;
        }
    }
    let _ = writer.flush();
    drop(writer);
    let _ = stream.shutdown(Shutdown::Both);
}

fn send(w: &mut impl Write, line: Option<&str>) -> io::Result<()> {
    if let Some(l) = line {
        w.write_all(l.as_bytes())?;
        w.write_all(b"\n")?;
        w.flush()?;
    }
    Ok(())
}

/// The reaper and the idle timeout (`HeadlessSession.startReaper` and `idleLoop`).
fn maintain(shared: &Arc<Shared>, idle_timeout: u64) {
    let mut last_reap = std::time::Instant::now();
    let mut idle_since = std::time::Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(250));
        if shared.engine.stopping() {
            shared.exit();
        }
        if shared.engine.client_count() > 0 {
            idle_since = std::time::Instant::now();
        } else if idle_timeout > 0 && idle_since.elapsed() > Duration::from_secs(idle_timeout) {
            log(&format!("no clients for {idle_timeout} s; stopping"));
            shared.exit();
        }
        if last_reap.elapsed() >= Duration::from_millis(shared.engine.reap_lap_ms()) {
            shared.engine.reap();
            last_reap = std::time::Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_command_line_is_split_at_the_double_dash() {
        let o = parse_args(args(&[
            "--workers",
            "4",
            "--",
            "java",
            "-stateDir",
            "S",
            "-instance",
            "i",
        ]))
        .expect("parses");
        assert_eq!(o.workers, 4, "workers");
        assert_eq!(
            value_of(&o.java_argv, "-stateDir"),
            Some("S"),
            "the state dir"
        );
        assert_eq!(
            value_of(&o.java_argv, "-instance"),
            Some("i"),
            "the instance"
        );
        assert!(
            parse_args(args(&["--"])).is_err(),
            "an empty Java command line"
        );
        assert!(
            parse_args(args(&["learn", "--", "x"])).is_err(),
            "learn needs a source"
        );
        assert!(parse_args(args(&["--bogus"])).is_err(), "unknown option");
    }

    #[test]
    fn lines_are_split_and_the_limit_holds() {
        let mut r = io::Cursor::new(b"abc\r\nde\n\nlast".to_vec());
        let mut next = |limit| match read_line_limited(&mut r, limit).expect("read") {
            Line::Text(t) => Some(String::from_utf8(t).expect("utf8")),
            _ => None,
        };
        assert_eq!(next(100).as_deref(), Some("abc"), "CRLF is trimmed");
        assert_eq!(next(100).as_deref(), Some("de"), "LF");
        assert_eq!(next(100).as_deref(), Some(""), "an empty line");
        assert_eq!(
            next(100).as_deref(),
            Some("last"),
            "the last line without a terminator"
        );
        assert!(next(100).is_none(), "end of input");
        let mut long = io::Cursor::new(b"0123456789\n".to_vec());
        assert!(
            matches!(read_line_limited(&mut long, 4), Ok(Line::TooLong)),
            "over the limit"
        );
    }
}
