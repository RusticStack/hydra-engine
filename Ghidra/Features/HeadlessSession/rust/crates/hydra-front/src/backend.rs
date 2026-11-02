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
//! The JVM backend: started on the first request only it can serve, stopped when no client is
//! attached to it for a while, and always ended with the front (a Job Object).

use crate::json_scan;
use crate::os::KillOnClose;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// How long a backend may take to publish its endpoint and answer (a cold JVM is 1.5-6 s).
const START_TIMEOUT: Duration = Duration::from_secs(180);

/// Where to reach a running backend.
#[derive(Clone, Debug)]
pub(crate) struct Endpoint {
    pub port: u16,
    pub token: String,
    /// The endpoint file's text, as the backend wrote it.
    pub text: String,
}

#[derive(Debug, Default)]
struct Inner {
    child: Option<Child>,
    ep: Option<Endpoint>,
}

/// The backend and its accounting.
#[derive(Debug)]
pub(crate) struct Backend {
    argv: Vec<String>,
    endpoint_file: PathBuf,
    job: KillOnClose,
    inner: Mutex<Inner>,
    attached: AtomicUsize,
    /// Milliseconds since `epoch` at which the last attached client left (or the backend started).
    idle_mark_ms: AtomicU64,
    epoch: Instant,
    /// Backends started over the front's life (the lazy-start evidence).
    pub starts: AtomicUsize,
}

impl Backend {
    /// A backend that is run as `argv` and publishes `endpoint_file`.
    pub(crate) fn new(argv: Vec<String>, endpoint_file: PathBuf) -> io::Result<Self> {
        Ok(Self {
            argv,
            endpoint_file,
            job: KillOnClose::new()?,
            inner: Mutex::new(Inner::default()),
            attached: AtomicUsize::new(0),
            idle_mark_ms: AtomicU64::new(0),
            epoch: Instant::now(),
            starts: AtomicUsize::new(0),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether a backend process is alive. Reaps one that exited.
    pub(crate) fn running(&self) -> bool {
        let mut g = self.lock();
        Self::reap(&mut g)
    }

    fn reap(g: &mut Inner) -> bool {
        match g.child.as_mut().map(Child::try_wait) {
            Some(Ok(None)) => true,
            Some(_) => {
                g.child = None;
                g.ep = None;
                false
            }
            None => false,
        }
    }

    /// The clients attached right now.
    pub(crate) fn attached(&self) -> usize {
        self.attached.load(Ordering::SeqCst)
    }

    /// Seconds since the last attached client left, or since the backend started.
    pub(crate) fn idle_for(&self) -> Duration {
        let now = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(now.saturating_sub(self.idle_mark_ms.load(Ordering::SeqCst)))
    }

    fn mark_idle(&self) {
        let now = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.idle_mark_ms.store(now, Ordering::SeqCst);
    }

    /// Starts the backend when it is not running and returns its endpoint. Concurrent callers wait
    /// for the one start.
    pub(crate) fn ensure(&self) -> io::Result<Endpoint> {
        let mut g = self.lock();
        if Self::reap(&mut g)
            && let Some(ep) = &g.ep
        {
            return Ok(ep.clone());
        }
        let _ = fs::remove_file(&self.endpoint_file);
        let mut cmd = Command::new(&self.argv[0]);
        cmd.args(&self.argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let mut child = cmd.spawn()?;
        if let Err(e) = self.job.assign(&child) {
            let _ = child.kill();
            return Err(e);
        }
        let pid = child.id();
        let end = Instant::now() + START_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::other(format!(
                    "the backend exited with {status} while starting"
                )));
            }
            if let Some(ep) = self.read_endpoint(pid)
                && TcpStream::connect(("127.0.0.1", ep.port)).is_ok()
            {
                self.starts.fetch_add(1, Ordering::SeqCst);
                self.mark_idle();
                g.child = Some(child);
                g.ep = Some(ep.clone());
                return Ok(ep);
            }
            if Instant::now() > end {
                let _ = child.kill();
                return Err(io::Error::other(
                    "the backend did not publish an endpoint in time",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn read_endpoint(&self, pid: u32) -> Option<Endpoint> {
        let text = fs::read_to_string(&self.endpoint_file).ok()?;
        let m = json_scan::split_object(&text)?;
        if json_scan::get(&m, "pid")?.parse::<u32>().ok()? != pid {
            return None;
        }
        Some(Endpoint {
            port: json_scan::get(&m, "port")?.parse().ok()?,
            token: json_scan::unquote(json_scan::get(&m, "token")?)?,
            text,
        })
    }

    /// Counts a client as attached until the guard drops.
    pub(crate) fn attach(&self) -> AttachGuard<'_> {
        self.attached.fetch_add(1, Ordering::SeqCst);
        AttachGuard { backend: self }
    }

    /// Stops the backend with a protocol `shutdown`, then kills it if it lingers. Safe to call
    /// when none runs.
    pub(crate) fn stop(&self) {
        let mut g = self.lock();
        let Some(ep) = g.ep.clone() else {
            if let Some(mut c) = g.child.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
            return;
        };
        let _ = send_shutdown(&ep);
        if let Some(mut c) = g.child.take() {
            let end = Instant::now() + Duration::from_secs(45);
            while Instant::now() < end {
                if matches!(c.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if matches!(c.try_wait(), Ok(None)) {
                let _ = c.kill();
            }
            let _ = c.wait();
        }
        g.ep = None;
        let _ = fs::remove_file(&self.endpoint_file);
    }
}

/// While alive, one client counts as attached to the backend.
#[derive(Debug)]
pub(crate) struct AttachGuard<'a> {
    backend: &'a Backend,
}

impl Drop for AttachGuard<'_> {
    fn drop(&mut self) {
        if self.backend.attached.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.backend.mark_idle();
        }
    }
}

/// Opens an authenticated connection to the backend with `hello` (the first line a client sent,
/// its token replaced); returns the stream and the backend's reply line to that hello.
pub(crate) fn open_authenticated(ep: &Endpoint, hello: &str) -> io::Result<(TcpStream, String)> {
    let mut m = json_scan::to_owned_members(
        &json_scan::split_object(hello)
            .ok_or_else(|| io::Error::other("hello is not an object"))?,
    );
    json_scan::set(&mut m, "token", json_scan::quote(&ep.token));
    let mut line = json_scan::join_object(&m);
    line.push('\n');
    let mut s = TcpStream::connect(("127.0.0.1", ep.port))?;
    s.set_nodelay(true)?;
    s.write_all(line.as_bytes())?;
    let mut reply = String::new();
    let mut r = BufReader::new(s.try_clone()?);
    if r.read_line(&mut reply)? == 0 {
        return Err(io::Error::other("the backend closed during hello"));
    }
    // The reader buffered nothing beyond the reply: the backend sends nothing before the next
    // request, and an unsolicited event could only follow a request.
    debug_assert!(r.buffer().is_empty(), "no bytes follow the hello reply");
    Ok((s, reply))
}

fn send_shutdown(ep: &Endpoint) -> io::Result<()> {
    let hello = r#"{"id":1,"cmd":"hello","client":"hydra-front","protocol":3}"#;
    let (mut s, _) = open_authenticated(ep, hello)?;
    s.write_all(b"{\"id\":2,\"cmd\":\"shutdown\"}\n")?;
    let mut buf = String::new();
    let _ = BufReader::new(s).read_line(&mut buf);
    Ok(())
}
