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
//! `hydra-front`: the front door of a Hydra Engine daemon (PROTOTYPE, see FRONT-DOOR.md).
//!
//! ```text
//! hydra-front [--lazy] [--backend-idle-s N] -- <the JVM command line the launcher would run>
//! ```
//!
//! The front takes the place of the JVM in the launcher's start-up: it publishes the daemon's
//! endpoint file and listens on the loopback socket, authenticates clients, and answers `ping`,
//! `hello` and a cold `shutdown` itself. The first request that needs Ghidra starts the JVM
//! (`-instance NAME.jvm`, so its endpoint file and lock do not collide) and from then on that
//! client's lines go to the JVM and back unchanged. With `--backend-idle-s N` the JVM is stopped
//! again when no client has been attached to it for N seconds.

#![allow(
    clippy::print_stderr,
    reason = "a daemon with no console: stderr is the launcher's log file"
)]

mod backend;
mod conn;
mod identity;
mod json_scan;
mod os;

use conn::Shared;
use identity::{Identity, Live};
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Writes `bytes` to `path` through a sibling temporary file and a rename.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

fn log(msg: &str) {
    eprintln!("hydra-front: {msg}");
}

struct Options {
    lazy: bool,
    backend_idle_s: u64,
    java_argv: Vec<String>,
}

fn parse_args() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let mut o = Options {
        lazy: false,
        backend_idle_s: std::env::var("HYDRA_FRONT_BACKEND_IDLE_S")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        java_argv: Vec::new(),
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--lazy" => o.lazy = true,
            "--backend-idle-s" => {
                o.backend_idle_s = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--backend-idle-s needs a number")?;
            }
            "--" => {
                o.java_argv = args.collect();
                break;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    if o.java_argv.is_empty() {
        return Err(
            "usage: hydra-front [--lazy] [--backend-idle-s N] -- <java command line>".into(),
        );
    }
    Ok(o)
}

/// The value after `flag` in an argument list.
fn value_of<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .map(String::as_str)
}

/// The instance lock: the launcher decides "a daemon is alive" by failing to take this lock
/// (`ghidra_session.py` `Daemon.jvm_alive`), so the front holds it for its whole life, as the JVM did.
fn hold_instance_lock(state: &Path, instance: &str) -> Result<std::fs::File, String> {
    let path = state.join(format!("{instance}.lock"));
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    lock.try_lock()
        .map_err(|e| format!("another daemon holds {}: {e}", path.display()))?;
    Ok(lock)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log(&e);
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let o = parse_args()?;
    let state = PathBuf::from(
        value_of(&o.java_argv, "-stateDir").ok_or("the command line has no -stateDir")?,
    );
    let instance = value_of(&o.java_argv, "-instance")
        .ok_or("the command line has no -instance")?
        .to_owned();
    let idle_timeout: u64 = value_of(&o.java_argv, "-idleTimeout")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let endpoint_file = state.join(format!("{instance}.json"));
    let jvm_instance = format!("{instance}.jvm");
    let jvm_endpoint = state.join(format!("{jvm_instance}.json"));
    let identity_path = state.join(format!("{instance}.front-identity.json"));
    let mut backend_argv = o.java_argv.clone();
    if let Some(i) = backend_argv.iter().position(|a| a == "-instance") {
        backend_argv[i + 1].clone_from(&jvm_instance);
    }
    let key = identity::command_key(&o.java_argv);

    let lock = hold_instance_lock(&state, &instance)?;

    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("bind: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let token = os::random_token().map_err(|e| format!("token: {e}"))?;
    let started_at = os::now_ms();
    let pid = std::process::id();
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

    let cached = Identity::load(&identity_path, &key);
    let shared = Arc::new(Shared {
        backend: backend::Backend::new(backend_argv, jvm_endpoint)
            .map_err(|e| format!("job: {e}"))?,
        identity: Mutex::new(cached.clone()),
        token: token.clone(),
        identity_path,
        key,
        instance: instance.clone(),
        endpoint_file: endpoint_str.clone(),
        pid,
        port,
        started_at,
        next_client: AtomicU64::new(1),
        open_clients: AtomicUsize::new(0),
        shutdown: AtomicBool::new(false),
        native_replies: AtomicU64::new(0),
    });

    let endpoint_text = if let Some(ident) = &cached {
        log("cached identity found: the JVM starts on the first request that needs it");
        ident.endpoint_file(&live, &token)
    } else {
        // No identity yet: start the JVM once to learn it (the launcher waits for the endpoint anyway).
        log("no cached identity: starting the JVM once to learn it");
        let ep = shared
            .backend
            .ensure()
            .map_err(|e| format!("backend: {e}"))?;
        learn_identity(&shared, &ep);
        identity::patch_endpoint(&ep.text, &live, &token)
            .ok_or("the backend's endpoint file is unreadable")?
    };
    write_atomic(&endpoint_file, endpoint_text.as_bytes())
        .map_err(|e| format!("endpoint file: {e}"))?;
    log(&format!(
        "listening on 127.0.0.1:{port}, endpoint {}",
        endpoint_file.display()
    ));
    if o.lazy && cached.is_none() {
        shared.backend.stop();
        log("--lazy: the JVM is stopped until a client needs it");
    }

    {
        let shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("maint".into())
            .spawn(move || maintain(&shared, &endpoint_file, o.backend_idle_s, idle_timeout))
            .map_err(|e| e.to_string())?;
    }

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let shared = Arc::clone(&shared);
        let _ = std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || conn::serve(&shared, stream));
    }
    drop(lock);
    Ok(())
}

/// Reads the identity from the running backend (a protocol 3 `hello` of its own) and keeps it. The
/// decompiler hash arrives in the background, so it retries for a while.
fn learn_identity(shared: &Arc<Shared>, ep: &backend::Endpoint) {
    let hello = r#"{"id":1,"cmd":"hello","client":"hydra-front","protocol":3}"#;
    for _ in 0..60 {
        if let Ok((_s, reply)) = backend::open_authenticated(ep, hello)
            && let Some(result) = json_scan::split_object(reply.trim_end())
                .and_then(|m| json_scan::get(&m, "result").map(str::to_owned))
            && let Some(ident) = Identity::from_backend(&result, &ep.text)
        {
            shared.learn(ident);
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    log("the backend's identity did not become complete; cold hellos will start the JVM");
}

/// Idle policies and the end of the process.
fn maintain(
    shared: &Arc<Shared>,
    endpoint_file: &Path,
    backend_idle_s: u64,
    idle_timeout: u64,
) -> ! {
    let mut no_clients = 0u64;
    loop {
        std::thread::sleep(Duration::from_millis(250));
        let running = shared.backend.running();
        if shared.shutdown.load(Ordering::SeqCst) && !running {
            break;
        }
        if running
            && backend_idle_s > 0
            && shared.backend.attached() == 0
            && shared.backend.idle_for() >= Duration::from_secs(backend_idle_s)
        {
            log("no client attached to the JVM: stopping it");
            shared.backend.stop();
        }
        if shared.open_clients.load(Ordering::SeqCst) == 0 {
            no_clients += 250;
            if idle_timeout > 0 && no_clients >= idle_timeout * 1000 {
                log("idle timeout: no clients");
                break;
            }
        } else {
            no_clients = 0;
        }
    }
    shared.backend.stop();
    let _ = std::fs::remove_file(endpoint_file);
    log(&format!(
        "exiting; JVM starts {}, requests answered here {}",
        shared.backend.starts.load(Ordering::SeqCst),
        shared.native_replies.load(Ordering::Relaxed)
    ));
    std::process::exit(0);
}
