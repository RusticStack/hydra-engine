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
//! What the lite daemon knows of the engine it stands in for: the `hello` result and the endpoint
//! file of a Java daemon that ran with the same command line. It cannot compute them (the Ghidra
//! version, the install directory, the decompiler hash, the advertised capabilities all live in
//! the JVM), so it learns them once and keeps them in the same cache file the front door
//! (`hydra-front`) writes, `NAME.front-identity.json`, keyed by the same command line hash.

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use crate::json::{Json, parse};

/// The protocols the engine serves (`HydraInfo.PROTOCOL_MIN` and `PROTOCOL_MAX`).
pub const PROTOCOL_MIN: u8 = 2;
/// The highest protocol the engine serves.
pub const PROTOCOL_MAX: u8 = 3;

/// The `hello` result keys a protocol 2 connection never sees (PROTOCOL-3.md 3.1, C1).
const V3_KEYS: [&str; 8] = [
    "protocolMin",
    "protocolMax",
    "capabilities",
    "limits",
    "policy",
    "paths",
    "platform",
    "analysisIdentity",
];

/// The Ghidra release whose database constants this build was checked against: program database
/// 33, data type database 3 and the language `x86:LE:64:default` 4.9.
pub const SUPPORTED_GHIDRA: &str = "12.3";

/// The protocol a `hello` asks for, as the engine answers it (`Client.requestedProtocol`): the
/// requested value when it lies in `[2, 3]`, 3 when larger, and 2 when absent, smaller or not a
/// JSON integer.
#[must_use]
pub fn requested_protocol(hello: &Json) -> u8 {
    let Some(Json::Num(raw)) = hello.get("protocol") else {
        return PROTOCOL_MIN;
    };
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    if raw.is_empty() || digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return PROTOCOL_MIN;
    }
    if raw.starts_with('-') {
        return PROTOCOL_MIN;
    }
    match raw.trim_start_matches('0').parse::<u128>() {
        Ok(v) if v >= u128::from(PROTOCOL_MAX) => PROTOCOL_MAX,
        Ok(v) => u8::try_from(v).map_or(PROTOCOL_MIN, |v| v.max(PROTOCOL_MIN)),
        Err(_) if raw.trim_start_matches('0').is_empty() => PROTOCOL_MIN,
        Err(_) => PROTOCOL_MAX,
    }
}

/// The live values put into an identity that is served or published.
#[derive(Debug, Clone, Copy)]
pub struct Live<'a> {
    /// The daemon instance name the launcher asked for.
    pub instance: &'a str,
    /// The endpoint file this daemon publishes.
    pub endpoint_file: &'a str,
    /// This process's id (the endpoint file's `pid`).
    pub pid: u32,
    /// This daemon's listening port.
    pub port: u16,
    /// When this daemon started, in epoch milliseconds.
    pub started_at: u64,
    /// The current time, in epoch milliseconds.
    pub now: u64,
    /// The id of the asking client.
    pub client: u32,
}

/// What a Java daemon with this command line said about itself.
#[derive(Debug, Clone)]
pub struct Identity {
    hello: Json,
    endpoint: Json,
}

/// Why an identity could not be learned.
#[derive(Debug)]
#[non_exhaustive]
pub enum LearnError {
    /// The endpoint file or the connection failed.
    Io(io::Error),
    /// The daemon answered something that is not a complete protocol 3 `hello`.
    Reply(String),
}

impl std::fmt::Display for LearnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Reply(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for LearnError {}

impl From<io::Error> for LearnError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl Identity {
    /// Builds one from a Java daemon's protocol 3 `hello` result and its endpoint file. `None`
    /// when the hello is not a complete v3 one or the decompiler hash has not arrived yet (a
    /// cache holding `null` there would be wrong for good).
    #[must_use]
    pub fn from_backend(hello_result: &Json, endpoint: &Json) -> Option<Self> {
        hello_result.get("capabilities")?;
        if hello_result.to_text().contains("\"sha256\":null") {
            return None;
        }
        hello_result.members()?;
        endpoint.members()?;
        Some(Self {
            hello: hello_result.clone(),
            endpoint: endpoint.clone(),
        })
    }

    /// Reads the cache file; `None` when it is absent, damaged or for another command line.
    #[must_use]
    pub fn load(path: &Path, key: &str) -> Option<Self> {
        let text = fs::read_to_string(path).ok()?;
        let doc = parse(text.trim_end()).ok()?;
        if doc.get("key")?.as_str()? != key {
            return None;
        }
        let (hello, endpoint) = (doc.get("hello")?.clone(), doc.get("endpoint")?.clone());
        hello.members()?;
        endpoint.members()?;
        Some(Self { hello, endpoint })
    }

    /// Writes the cache atomically.
    ///
    /// # Errors
    ///
    /// The file error.
    pub fn save(&self, path: &Path, key: &str) -> io::Result<()> {
        let doc = Json::obj()
            .with("key", Json::str(key))
            .with("hello", self.hello.clone())
            .with("endpoint", self.endpoint.clone());
        write_atomic(path, doc.to_text().as_bytes())
    }

    /// The Ghidra version the learned engine runs.
    #[must_use]
    pub fn ghidra_version(&self) -> Option<&str> {
        self.hello.get("ghidraVersion")?.as_str()
    }

    /// A member of the learned `hello` result, `null` when absent.
    #[must_use]
    pub fn hello_value(&self, key: &str) -> Json {
        self.hello.get(key).cloned().unwrap_or(Json::Null)
    }

    /// The `hello` result for a connection of `protocol`: the learned one with the live values
    /// filled in and `projects` as given.
    #[must_use]
    pub fn hello_result(&self, protocol: u8, live: &Live<'_>, projects: Json) -> Json {
        let mut h = self.hello.clone();
        set_live(&mut h, live);
        h.put("protocol", Json::uint(u64::from(protocol)));
        h.put(
            "uptimeMs",
            Json::uint(live.now.saturating_sub(live.started_at)),
        );
        h.put("projects", projects);
        h.put("client", Json::uint(u64::from(live.client)));
        if protocol < PROTOCOL_MAX {
            for k in V3_KEYS {
                h.remove(k);
            }
        }
        h
    }

    /// The endpoint file this daemon publishes: the learned one with the live pid, port, token,
    /// start time and instance.
    #[must_use]
    pub fn endpoint_file(&self, live: &Live<'_>, token: &str) -> Json {
        let mut e = self.endpoint.clone();
        e.put("pid", Json::uint(u64::from(live.pid)));
        e.put("port", Json::uint(u64::from(live.port)));
        e.put("token", Json::str(token));
        e.put("started", Json::uint(live.started_at));
        e.put("instance", Json::str(live.instance));
        e
    }
}

fn set_live(h: &mut Json, live: &Live<'_>) {
    if let Some(Json::Obj(paths)) = h.get("paths") {
        let mut p = Json::Obj(paths.clone());
        p.put("instance", Json::str(live.instance));
        p.put("endpointFile", Json::str(live.endpoint_file));
        h.put("paths", p);
    }
    h.put("pid", Json::uint(u64::from(live.pid)));
    h.put("startedAt", Json::uint(live.started_at));
    h.put(
        "listen",
        Json::obj()
            .with("host", Json::str("127.0.0.1"))
            .with("port", Json::uint(u64::from(live.port))),
    );
}

/// A stable key for a Java command line (FNV-1a over the arguments), the one `hydra-front` uses.
#[must_use]
pub fn command_key(argv: &[String]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for a in argv {
        for b in a.bytes().chain(std::iter::once(0)) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}

/// Writes `bytes` to `path` through a sibling temporary file and a rename.
///
/// # Errors
///
/// The file error.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut f = fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)
}

/// Learns the identity from a running Java daemon: reads its endpoint file, sends it a protocol 3
/// `hello` and keeps the result. Retries for a while because the decompiler hash is computed in
/// the background.
///
/// # Errors
///
/// [`LearnError`] when the endpoint is unreadable or the daemon never gives a complete hello.
pub fn learn(endpoint_file: &Path) -> Result<Identity, LearnError> {
    let text = fs::read_to_string(endpoint_file)?;
    let endpoint = parse(text.trim_end()).map_err(|e| LearnError::Reply(e.to_string()))?;
    let (Some(Json::Str(host)), Some(Json::Num(port)), Some(Json::Str(token))) = (
        endpoint.get("host"),
        endpoint.get("port"),
        endpoint.get("token"),
    ) else {
        return Err(LearnError::Reply(
            "the endpoint file lacks host, port or token".into(),
        ));
    };
    let addr = format!("{host}:{port}");
    let mut last = String::from("no attempt");
    for _ in 0..60 {
        match ask_hello(&addr, token) {
            Ok(result) => {
                if let Some(id) = Identity::from_backend(&result, &endpoint) {
                    return Ok(id);
                }
                last = "the hello is not complete yet".into();
            }
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(LearnError::Reply(last))
}

fn ask_hello(addr: &str, token: &str) -> Result<Json, LearnError> {
    let mut s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    let req = Json::obj()
        .with("id", Json::int(1))
        .with("cmd", Json::str("hello"))
        .with("client", Json::str("hydra-lite"))
        .with("protocol", Json::int(3))
        .with("token", Json::str(token));
    s.write_all(format!("{}\n", req.to_text()).as_bytes())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line)?;
    let reply = parse(line.trim_end()).map_err(|e| LearnError::Reply(e.to_string()))?;
    match (reply.get("ok"), reply.get("result")) {
        (Some(Json::Bool(true)), Some(r)) => Ok(r.clone()),
        _ => Err(LearnError::Reply(format!(
            "the daemon refused the hello: {line}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto(req: &str) -> u8 {
        requested_protocol(&parse(req).expect("json"))
    }

    #[test]
    fn negotiation_follows_the_engine_rule() {
        assert_eq!(proto(r#"{"cmd":"hello"}"#), 2, "absent");
        assert_eq!(proto(r#"{"protocol":3}"#), 3, "three");
        assert_eq!(proto(r#"{"protocol":9}"#), 3, "larger");
        assert_eq!(proto(r#"{"protocol":1}"#), 2, "smaller");
        assert_eq!(proto(r#"{"protocol":0}"#), 2, "zero");
        assert_eq!(proto(r#"{"protocol":-3}"#), 2, "negative");
        assert_eq!(proto(r#"{"protocol":"3"}"#), 2, "a string");
        assert_eq!(proto(r#"{"protocol":3.0}"#), 2, "a float");
        assert_eq!(proto(r#"{"protocol":true}"#), 2, "a boolean");
        assert_eq!(proto(r#"{"protocol":null}"#), 2, "null");
        assert_eq!(
            proto(r#"{"protocol":99999999999999999999999999999999999999999}"#),
            3,
            "huge"
        );
    }

    const HELLO: &str = r#"{"protocol":3,"hydraVersion":"x","ghidraVersion":"12.3","pid":1,"uptimeMs":5,"listen":{"host":"127.0.0.1","port":1},"memory":{"usedMb":1},"protocolMin":2,"protocolMax":3,"capabilities":{"a":1},"limits":{},"policy":{},"paths":{"instance":"a"},"platform":{},"analysisIdentity":{"decompiler":{"sha256":"ab"}},"projects":[],"client":7}"#;

    fn identity() -> Identity {
        Identity::from_backend(
            &parse(HELLO).expect("json"),
            &parse(r#"{"protocol":2,"pid":1,"port":1,"token":"t","started":1}"#).expect("json"),
        )
        .expect("identity")
    }

    fn live() -> Live<'static> {
        Live {
            instance: "i",
            endpoint_file: "e",
            pid: 9,
            port: 8,
            started_at: 100,
            now: 150,
            client: 3,
        }
    }

    #[test]
    fn a_v2_hello_has_no_v3_key_and_keeps_order() {
        let v2 = identity()
            .hello_result(2, &live(), Json::Arr(Vec::new()))
            .to_text();
        assert_eq!(
            v2,
            r#"{"protocol":2,"hydraVersion":"x","ghidraVersion":"12.3","pid":9,"uptimeMs":50,"listen":{"host":"127.0.0.1","port":8},"memory":{"usedMb":1},"projects":[],"client":3,"startedAt":100}"#,
            "v2 drops the identity block; live fields are this daemon's"
        );
        let v3 = identity()
            .hello_result(3, &live(), Json::Arr(Vec::new()))
            .to_text();
        assert!(v3.contains("\"capabilities\""), "v3 keeps the block");
        assert!(v3.contains("\"instance\":\"i\""), "paths.instance is live");
    }

    #[test]
    fn a_hello_with_a_pending_decompiler_hash_is_not_kept() {
        let h = parse(&HELLO.replace("\"sha256\":\"ab\"", "\"sha256\":null")).expect("json");
        assert!(
            Identity::from_backend(&h, &Json::obj()).is_none(),
            "null hash"
        );
        let v2 = parse(r#"{"protocol":2}"#).expect("json");
        assert!(
            Identity::from_backend(&v2, &Json::obj()).is_none(),
            "a v2 hello"
        );
    }

    #[test]
    fn the_cache_round_trips_and_checks_its_key() {
        let dir = std::env::temp_dir().join(format!("hl-ident-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let f = dir.join("x.front-identity.json");
        identity().save(&f, "k1").expect("save");
        assert!(Identity::load(&f, "k1").is_some(), "same key");
        assert!(Identity::load(&f, "k2").is_none(), "another command line");
        assert_eq!(
            Identity::load(&f, "k1")
                .and_then(|i| i.ghidra_version().map(str::to_owned))
                .as_deref(),
            Some("12.3"),
            "the version is readable"
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn the_command_key_is_the_front_doors() {
        let a = command_key(&["-stateDir".into(), "S".into()]);
        assert_eq!(a.len(), 16, "16 hex digits");
        assert_ne!(
            a,
            command_key(&["-stateDir".into(), "T".into()]),
            "depends on the arguments"
        );
    }
}
