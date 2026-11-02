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
//! What the front knows of the engine without a JVM: the protocol negotiation rule and the cached
//! identity (the `hello` result and the endpoint file of the last backend that ran with the same
//! command line), from which a cold `hello` is answered.

use crate::json_scan::{self, Member};
use std::fs;
use std::path::Path;

/// The protocols the engine serves (`HydraInfo.PROTOCOL_MIN` and `PROTOCOL_MAX`).
const PROTOCOL_MIN: u8 = 2;
const PROTOCOL_MAX: u8 = 3;

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

/// The protocol a `hello` asks for, as the engine answers it (`Client.requestedProtocol`): the
/// requested value in `[2, 3]`, 3 when larger, 2 when absent, smaller or not a JSON integer.
pub(crate) fn requested_protocol(hello: &[Member<'_>]) -> u8 {
    let Some(raw) = json_scan::get(hello, "protocol") else {
        return PROTOCOL_MIN;
    };
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return PROTOCOL_MIN;
    }
    match raw.parse::<u128>() {
        Ok(v) if v >= u128::from(PROTOCOL_MAX) => PROTOCOL_MAX,
        Ok(v) => u8::try_from(v).map_or(PROTOCOL_MIN, |v| v.max(PROTOCOL_MIN)),
        Err(_) => PROTOCOL_MAX,
    }
}

/// The live values a front puts into an identity it serves or patches.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Live<'a> {
    /// The daemon instance name the launcher asked for (the backend runs as `NAME.jvm`).
    pub instance: &'a str,
    /// The endpoint file the front publishes.
    pub endpoint_file: &'a str,
    /// The front's process id (the endpoint file's `pid`).
    pub pid: u32,
    /// The front's listening port.
    pub port: u16,
    /// When the front started, in epoch milliseconds.
    pub started_at: u64,
    /// The current time, in epoch milliseconds.
    pub now: u64,
    /// The id of this client.
    pub client: u64,
}

/// A cached identity: the `hello` result of a protocol 3 connection, and the endpoint file.
#[derive(Clone, Debug)]
pub(crate) struct Identity {
    hello: Vec<(String, String)>,
    endpoint: Vec<(String, String)>,
}

impl Identity {
    /// Builds one from a backend's v3 `hello` result and its endpoint file text. `None` when the
    /// hello is not a complete v3 one or the decompiler hash has not arrived yet (it is computed in
    /// the background; a cache holding `null` would be wrong forever).
    pub(crate) fn from_backend(hello_result: &str, endpoint: &str) -> Option<Self> {
        let hello = json_scan::to_owned_members(&json_scan::split_object(hello_result)?);
        let endpoint = json_scan::to_owned_members(&json_scan::split_object(endpoint)?);
        if !hello.iter().any(|(k, _)| k == "capabilities") {
            return None;
        }
        if hello_result.contains("\"sha256\":null") {
            return None;
        }
        Some(Self { hello, endpoint })
    }

    /// Reads the cache file; `None` when it is absent, damaged or for another command line.
    pub(crate) fn load(path: &Path, key: &str) -> Option<Self> {
        let text = fs::read_to_string(path).ok()?;
        let m = json_scan::split_object(&text)?;
        if json_scan::unquote(json_scan::get(&m, "key")?)? != key {
            return None;
        }
        Some(Self {
            hello: json_scan::to_owned_members(&json_scan::split_object(json_scan::get(
                &m, "hello",
            )?)?),
            endpoint: json_scan::to_owned_members(&json_scan::split_object(json_scan::get(
                &m, "endpoint",
            )?)?),
        })
    }

    /// Writes the cache atomically.
    pub(crate) fn save(&self, path: &Path, key: &str) -> std::io::Result<()> {
        let body = json_scan::join_object(&[
            ("key".to_owned(), json_scan::quote(key)),
            ("hello".to_owned(), json_scan::join_object(&self.hello)),
            (
                "endpoint".to_owned(),
                json_scan::join_object(&self.endpoint),
            ),
        ]);
        crate::write_atomic(path, body.as_bytes())
    }

    /// The `hello` result for a connection of `protocol`, with the live values filled in.
    pub(crate) fn hello_result(&self, protocol: u8, live: &Live<'_>) -> String {
        let mut f = self.hello.clone();
        set_live(&mut f, live);
        json_scan::set(&mut f, "protocol", protocol.to_string());
        json_scan::set(
            &mut f,
            "uptimeMs",
            live.now.saturating_sub(live.started_at).to_string(),
        );
        json_scan::set(&mut f, "client", live.client.to_string());
        if protocol < PROTOCOL_MAX {
            f.retain(|(k, _)| !V3_KEYS.contains(&k.as_str()));
        }
        json_scan::join_object(&f)
    }

    /// The endpoint file the front publishes: the backend's, with the front's pid, port and token.
    pub(crate) fn endpoint_file(&self, live: &Live<'_>, token: &str) -> String {
        let mut f = self.endpoint.clone();
        json_scan::set(&mut f, "pid", live.pid.to_string());
        json_scan::set(&mut f, "port", live.port.to_string());
        json_scan::set(&mut f, "token", json_scan::quote(token));
        json_scan::set(&mut f, "started", live.started_at.to_string());
        json_scan::set(&mut f, "instance", json_scan::quote(live.instance));
        json_scan::join_object(&f)
    }
}

/// The endpoint file for a front that has no cached identity yet: the backend's file text with
/// the front's pid, port and token.
pub(crate) fn patch_endpoint(backend_text: &str, live: &Live<'_>, token: &str) -> Option<String> {
    let mut f = json_scan::to_owned_members(&json_scan::split_object(backend_text)?);
    json_scan::set(&mut f, "pid", live.pid.to_string());
    json_scan::set(&mut f, "port", live.port.to_string());
    json_scan::set(&mut f, "token", json_scan::quote(token));
    json_scan::set(&mut f, "started", live.started_at.to_string());
    json_scan::set(&mut f, "instance", json_scan::quote(live.instance));
    Some(json_scan::join_object(&f))
}

fn set_live(f: &mut Vec<(String, String)>, live: &Live<'_>) {
    if let Some(paths) = json_scan::get_owned(f, "paths")
        && let Some(p) = json_scan::split_object(&paths)
    {
        let mut p = json_scan::to_owned_members(&p);
        json_scan::set(&mut p, "instance", json_scan::quote(live.instance));
        json_scan::set(&mut p, "endpointFile", json_scan::quote(live.endpoint_file));
        json_scan::set(f, "paths", json_scan::join_object(&p));
    }
    json_scan::set(f, "pid", live.pid.to_string());
    json_scan::set(f, "startedAt", live.started_at.to_string());
    json_scan::set(
        f,
        "listen",
        format!("{{\"host\":\"127.0.0.1\",\"port\":{}}}", live.port),
    );
}

/// Rewrites the `pid` and `listen` of a backend's `hello` reply line to the front's, so that every
/// client sees one daemon. `None` when the line is not a `hello` success.
pub(crate) fn patch_hello_reply(reply: &str, at: &Live<'_>) -> Option<String> {
    let outer = json_scan::split_object(reply.trim_end())?;
    if json_scan::get(&outer, "ok")? != "true" {
        return None;
    }
    let mut result =
        json_scan::to_owned_members(&json_scan::split_object(json_scan::get(&outer, "result")?)?);
    set_live(&mut result, at);
    let mut outer = json_scan::to_owned_members(&outer);
    json_scan::set(&mut outer, "result", json_scan::join_object(&result));
    let mut s = json_scan::join_object(&outer);
    s.push('\n');
    Some(s)
}

/// A stable key for a backend command line (FNV-1a over the arguments).
pub(crate) fn command_key(argv: &[String]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for a in argv {
        for b in a.bytes().chain(std::iter::once(0)) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto(req: &str) -> u8 {
        requested_protocol(&json_scan::split_object(req).expect("object"))
    }

    #[test]
    fn negotiation_follows_the_engine_rule() {
        assert_eq!(proto(r#"{"cmd":"hello"}"#), 2, "absent");
        assert_eq!(proto(r#"{"protocol":3}"#), 3, "three");
        assert_eq!(proto(r#"{"protocol":9}"#), 3, "larger");
        assert_eq!(proto(r#"{"protocol":1}"#), 2, "smaller");
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

    const HELLO: &str = r#"{"protocol":3,"hydraVersion":"x","pid":1,"uptimeMs":5,"listen":{"host":"127.0.0.1","port":1},"memory":{"usedMb":1},"protocolMin":2,"protocolMax":3,"capabilities":{"a":1},"limits":{},"policy":{},"paths":{},"platform":{},"analysisIdentity":{"decompiler":{"sha256":"ab"}},"projects":[],"client":7}"#;

    fn identity() -> Identity {
        Identity::from_backend(
            HELLO,
            r#"{"protocol":2,"pid":1,"port":1,"token":"t","started":1}"#,
        )
        .expect("identity")
    }

    #[test]
    fn a_v2_hello_has_no_v3_key_and_keeps_order() {
        let live = Live {
            instance: "i",
            endpoint_file: "e",
            pid: 9,
            port: 8,
            started_at: 100,
            now: 150,
            client: 3,
        };
        let v2 = identity().hello_result(2, &live);
        assert_eq!(
            v2,
            r#"{"protocol":2,"hydraVersion":"x","pid":9,"uptimeMs":50,"listen":{"host":"127.0.0.1","port":8},"memory":{"usedMb":1},"projects":[],"client":3,"startedAt":100}"#,
            "v2 drops the identity block; live fields are the front's"
        );
        let v3 = identity().hello_result(3, &live);
        assert!(v3.contains("\"capabilities\""), "v3 keeps the block");
    }

    #[test]
    fn a_hello_with_a_pending_decompiler_hash_is_not_cached() {
        let h = HELLO.replace("\"sha256\":\"ab\"", "\"sha256\":null");
        assert!(Identity::from_backend(&h, "{}").is_none(), "null hash");
        assert!(
            Identity::from_backend(r#"{"protocol":2}"#, "{}").is_none(),
            "v2 hello"
        );
    }

    #[test]
    fn a_backend_reply_is_patched_in_place() {
        let live = Live {
            instance: "i",
            endpoint_file: "e",
            pid: 9,
            port: 8,
            started_at: 1,
            now: 2,
            client: 1,
        };
        let reply = format!("{{\"id\":1,\"ok\":true,\"result\":{HELLO},\"ms\":4}}\n");
        let p = patch_hello_reply(&reply, &live).expect("patched");
        assert!(
            p.starts_with("{\"id\":1,\"ok\":true,\"result\":{\"protocol\":3"),
            "order kept: {p}"
        );
        assert!(
            p.contains("\"pid\":9") && p.contains("\"port\":8") && p.ends_with(",\"ms\":4}\n"),
            "{p}"
        );
    }
}
