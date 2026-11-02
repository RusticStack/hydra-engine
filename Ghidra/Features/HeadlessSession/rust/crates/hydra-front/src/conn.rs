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
//! One client connection: authenticated and answered here while the front can answer, then piped
//! line for line to a backend connection of its own from the first request that needs the JVM.
//!
//! Per-connection state (protocol, label, programs, requests in flight, lanes, the ordered lane,
//! `Governor` and `Waits` accounting) lives in the JVM against that backend connection, so it is
//! exactly what a direct connection would have had. The front keeps no request state: after the
//! attach every line goes through unchanged and in order, both ways.

use crate::backend::{self, Backend};
use crate::identity::{self, Identity, Live};
use crate::json_scan::{self, Member};
use crate::os::now_ms;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// The longest request line the engine reads (`Connection.MAX_LINE_BYTES`).
const MAX_LINE_BYTES: u64 = 64 * 1024 * 1024;

/// What every connection shares.
#[derive(Debug)]
pub(crate) struct Shared {
    pub backend: Backend,
    pub identity: Mutex<Option<Identity>>,
    pub token: String,
    pub identity_path: std::path::PathBuf,
    pub key: String,
    pub instance: String,
    pub endpoint_file: String,
    pub pid: u32,
    pub port: u16,
    pub started_at: u64,
    pub next_client: AtomicU64,
    pub open_clients: AtomicUsize,
    /// Set when a client asked for `shutdown` and the front is going down.
    pub shutdown: AtomicBool,
    /// Requests the front answered itself.
    pub native_replies: AtomicU64,
}

impl Shared {
    pub(crate) fn live(&self, client: u64) -> Live<'_> {
        Live {
            instance: &self.instance,
            endpoint_file: &self.endpoint_file,
            pid: self.pid,
            port: self.port,
            started_at: self.started_at,
            now: now_ms(),
            client,
        }
    }

    /// Remembers an identity, in memory and on disk.
    pub(crate) fn learn(&self, ident: Identity) {
        let _ = ident.save(&self.identity_path, &self.key);
        *self
            .identity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ident);
    }

    fn identity(&self) -> Option<Identity> {
        self.identity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// `{"id":ID,"ok":true,"result":RESULT,"ms":0}` in the engine's key order.
fn ok_reply(id: Option<&str>, result: &str) -> String {
    let mut s = String::from("{");
    if let Some(id) = id {
        s.push_str("\"id\":");
        s.push_str(id);
        s.push(',');
    }
    s.push_str("\"ok\":true,\"result\":");
    s.push_str(result);
    s.push_str(",\"ms\":0}\n");
    s
}

/// `{"id":ID,"ok":false,"error":{"code":..,"message":..},"ms":0}`.
fn error_reply(id: Option<&str>, code: &str, message: &str, details: Option<&str>) -> String {
    let mut s = String::from("{");
    if let Some(id) = id {
        s.push_str("\"id\":");
        s.push_str(id);
        s.push(',');
    }
    s.push_str("\"ok\":false,\"error\":{\"code\":");
    s.push_str(&json_scan::quote(code));
    s.push_str(",\"message\":");
    s.push_str(&json_scan::quote(message));
    if let Some(d) = details {
        s.push_str(",\"details\":");
        s.push_str(d);
    }
    s.push_str("},\"ms\":0}\n");
    s
}

/// Reads one line (without the newline) into `buf`; `Ok(false)` at end of input.
fn read_line(r: &mut impl BufRead, buf: &mut Vec<u8>) -> io::Result<bool> {
    buf.clear();
    let n = io::Read::take(&mut *r, MAX_LINE_BYTES + 1).read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(false);
    }
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > MAX_LINE_BYTES {
        return Err(io::Error::other("request line over the limit"));
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    Ok(true)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn id_of<'a>(m: &[Member<'a>]) -> Option<&'a str> {
    json_scan::get(m, "id").filter(|v| *v != "null")
}

/// Serves one client until it leaves.
pub(crate) fn serve(shared: &Arc<Shared>, stream: TcpStream) {
    shared.open_clients.fetch_add(1, Ordering::SeqCst);
    let _ = Client::new(shared, stream).and_then(Client::run);
    shared.open_clients.fetch_sub(1, Ordering::SeqCst);
}

/// One connection's front-side state.
struct Client<'a> {
    shared: &'a Arc<Shared>,
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    /// The first (authenticating) hello, replayed to the backend on attach.
    hello: String,
    protocol: u8,
    id: u64,
}

/// Why a client attaches: its authenticating hello still needs the backend's reply (`Hello`, with
/// the request id to answer under), or a later request needs the JVM (`Request`, forwarded first).
enum Entry<'a> {
    Hello(Option<&'a str>),
    Request(String),
}

/// What the front did with a detached request.
enum Native {
    Answered,
    Stop,
    NeedsBackend,
}

impl<'a> Client<'a> {
    fn new(shared: &'a Arc<Shared>, stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self {
            shared,
            writer: stream.try_clone()?,
            reader: BufReader::with_capacity(16 * 1024, stream),
            hello: String::new(),
            protocol: 2,
            id: 0,
        })
    }

    fn send(&mut self, reply: &str) -> io::Result<()> {
        self.writer.write_all(reply.as_bytes())
    }

    /// The next non-blank request line that is a JSON object. `Ok(None)` at end of input; a line
    /// that is not one is answered `bad_request` here and skipped, as the engine does.
    fn next_request(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<String>> {
        loop {
            if !read_line(&mut self.reader, buf)? {
                return Ok(None);
            }
            let text = String::from_utf8_lossy(buf).into_owned();
            if text.trim().is_empty() {
                continue;
            }
            if json_scan::split_object(&text).is_some() {
                return Ok(Some(text));
            }
            self.send(&error_reply(
                None,
                "bad_request",
                "not a JSON object: malformed request",
                None,
            ))?;
        }
    }

    /// The first request must be `hello` with the token (`Connection.authenticate`). `Ok(false)`:
    /// refused, the connection is to be closed.
    fn authenticate(&mut self, buf: &mut Vec<u8>) -> io::Result<bool> {
        let Some(text) = self.next_request(buf)? else {
            return Ok(false);
        };
        let m = json_scan::split_object(&text).ok_or_else(|| io::Error::other("unparsable"))?;
        let cmd = json_scan::get(&m, "cmd")
            .and_then(json_scan::unquote)
            .unwrap_or_default();
        let supplied = json_scan::get(&m, "token")
            .and_then(json_scan::unquote)
            .unwrap_or_default();
        if cmd != "hello" || !constant_time_eq(&supplied, &self.shared.token) {
            let msg = "the first request must be {\"cmd\":\"hello\",\"token\":...} with the token from the endpoint file";
            self.send(&error_reply(id_of(&m), "unauthorized", msg, None))?;
            return Ok(false);
        }
        self.protocol = identity::requested_protocol(&m);
        self.id = self.shared.next_client.fetch_add(1, Ordering::SeqCst);
        self.hello = text;
        Ok(true)
    }

    fn run(mut self) -> io::Result<()> {
        let mut buf = Vec::new();
        if !self.authenticate(&mut buf)? {
            return Ok(());
        }
        let hello = self.hello.clone();
        let first =
            json_scan::split_object(&hello).ok_or_else(|| io::Error::other("hello vanished"))?;
        let first_id = id_of(&first).map(str::to_owned);
        // Cold and cached: answer the hello here and leave the JVM down.
        let cached = if self.shared.backend.running() {
            None
        } else {
            self.shared.identity()
        };
        let Some(identity) = cached else {
            return self.attach(Entry::Hello(first_id.as_deref()));
        };
        let result = identity.hello_result(self.protocol, &self.shared.live(self.id));
        self.send(&ok_reply(first_id.as_deref(), &result))?;
        self.shared.native_replies.fetch_add(1, Ordering::Relaxed);

        // Detached: only what needs no JVM is answered here; the first other request attaches.
        while let Some(text) = self.next_request(&mut buf)? {
            match self.answer_natively(&text)? {
                Native::Answered => {}
                Native::Stop => return Ok(()),
                Native::NeedsBackend => return self.attach(Entry::Request(text)),
            }
        }
        Ok(())
    }

    /// Answers one detached request without the JVM, if it can.
    fn answer_natively(&mut self, text: &str) -> io::Result<Native> {
        let m = json_scan::split_object(text).ok_or_else(|| io::Error::other("unparsable"))?;
        let id = id_of(&m);
        let cmd = json_scan::get(&m, "cmd")
            .and_then(json_scan::unquote)
            .unwrap_or_default();
        let shared = self.shared;
        if shared.backend.running() {
            return Ok(Native::NeedsBackend);
        }
        match cmd.as_str() {
            "ping" => self.send(&ok_reply(id, "{\"pong\":true}"))?,
            "hello" => {
                let Some(ident) = shared.identity() else {
                    return Ok(Native::NeedsBackend);
                };
                // a later hello never changes the connection's protocol (PROTOCOL-3.md 3.1)
                let result = ident.hello_result(self.protocol, &shared.live(self.id));
                self.send(&ok_reply(id, &result))?;
            }
            "shutdown" => {
                let others = shared.open_clients.load(Ordering::SeqCst).saturating_sub(1);
                if others > 0 && json_scan::get(&m, "force") != Some("true") {
                    let msg = format!(
                        "{others} other client(s) are connected; pass \"force\":true to stop anyway"
                    );
                    let details = format!("{{\"clients\":{others}}}");
                    self.send(&error_reply(id, "conflict", &msg, Some(&details)))?;
                } else {
                    self.send(&ok_reply(id, "{\"stopping\":true}"))?;
                    shared.shutdown.store(true, Ordering::SeqCst);
                    return Ok(Native::Stop);
                }
            }
            _ => return Ok(Native::NeedsBackend),
        }
        shared.native_replies.fetch_add(1, Ordering::Relaxed);
        Ok(Native::Answered)
    }

    /// Connects this client to the backend (starting it when needed) and pipes both directions until
    /// either side closes. `hello_id`: the first hello still waits for its reply (`Some`, holding its
    /// id); `pending`: the request that triggered the attach, forwarded first.
    fn attach(mut self, entry: Entry<'_>) -> io::Result<()> {
        let shared = self.shared;
        let answer_hello = matches!(entry, Entry::Hello(_));
        let (hello_id, pending) = match entry {
            Entry::Hello(id) => (id, None),
            Entry::Request(text) => (None, Some(text)),
        };
        let hello = self.hello.clone();
        let connected = shared.backend.ensure().and_then(|ep| {
            let (s, reply) = backend::open_authenticated(&ep, &hello)?;
            Ok((ep, s, reply))
        });
        let (ep, backend_stream, reply) = match connected {
            Ok(t) => t,
            Err(e) => {
                let msg = format!("the engine backend is not available: {e}");
                return self.send(&error_reply(hello_id, "failed", &msg, None));
            }
        };
        if answer_hello {
            let patched = identity::patch_hello_reply(&reply, &shared.live(self.id))
                .unwrap_or_else(|| reply.clone());
            self.send(&patched)?;
            // learn the identity for the next cold start
            if let Some(result) = json_scan::split_object(reply.trim_end())
                .and_then(|m| json_scan::get(&m, "result").map(str::to_owned))
                && let Some(ident) = Identity::from_backend(&result, &ep.text)
            {
                shared.learn(ident);
            }
        }
        let _guard = shared.backend.attach();
        let mut to_backend = backend_stream.try_clone()?;
        let mut to_client = self.writer.try_clone()?;
        let closer_client = self.writer.try_clone()?;
        let closer_backend = backend_stream.try_clone()?;
        let down = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let mut r = BufReader::with_capacity(32 * 1024, backend_stream);
                let _ = io::copy(&mut r, &mut to_client);
                let _ = closer_client.shutdown(Shutdown::Both);
            })?;

        let mut buf = Vec::new();
        let mut next = pending.map(String::into_bytes);
        while let Some(mut out) =
            next.take()
                .or_else(|| match read_line(&mut self.reader, &mut buf) {
                    Ok(true) => Some(std::mem::take(&mut buf)),
                    _ => None,
                })
        {
            if wants_shutdown(&out) {
                shared.shutdown.store(true, Ordering::SeqCst);
            }
            out.push(b'\n');
            if to_backend.write_all(&out).is_err() {
                break;
            }
        }
        let _ = closer_backend.shutdown(Shutdown::Both);
        let _ = down.join();
        let _ = self.writer.shutdown(Shutdown::Both);
        Ok(())
    }
}

/// Whether a request line is a `shutdown` (a cheap scan first: the parse only runs on a candidate).
fn wants_shutdown(line: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"shutdown";
    if !line.windows(NEEDLE.len()).any(|w| w == NEEDLE) {
        return false;
    }
    std::str::from_utf8(line)
        .ok()
        .and_then(json_scan::split_object)
        .and_then(|m| json_scan::get(&m, "cmd").and_then(json_scan::unquote))
        .is_some_and(|c| c == "shutdown")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_have_the_engine_shape() {
        assert_eq!(
            ok_reply(Some("7"), "{\"pong\":true}"),
            "{\"id\":7,\"ok\":true,\"result\":{\"pong\":true},\"ms\":0}\n"
        );
        assert_eq!(
            ok_reply(None, "1"),
            "{\"ok\":true,\"result\":1,\"ms\":0}\n",
            "no id, no key"
        );
        assert_eq!(
            error_reply(Some("\"a\""), "conflict", "m", Some("{\"clients\":1}")),
            "{\"id\":\"a\",\"ok\":false,\"error\":{\"code\":\"conflict\",\"message\":\"m\",\"details\":{\"clients\":1}},\"ms\":0}\n"
        );
    }

    #[test]
    fn shutdown_is_found_by_command_not_by_substring() {
        assert!(
            wants_shutdown(br#"{"id":1,"cmd":"shutdown","force":true}"#),
            "a shutdown"
        );
        assert!(
            !wants_shutdown(br#"{"id":1,"cmd":"edit","comment":"shutdown"}"#),
            "text only"
        );
    }

    #[test]
    fn tokens_compare_in_full() {
        assert!(constant_time_eq("abc", "abc"), "equal");
        assert!(!constant_time_eq("abc", "abd"), "differ");
        assert!(!constant_time_eq("abc", "ab"), "length");
    }
}
