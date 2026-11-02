//! The TRACE-1 raw segment writer: `crc-hex8 SP canonical-json LF`, hash-chained from a per-segment genesis.
//! Byte-identical to `hydralysis.trace_wire` and `hydra-trace::raw` (a golden vector in the tests pins it).

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const GENESIS: &str = "hydra.trace.segment/1\n";

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The keyed correlation id of `data`: HMAC-SHA256 under `key`, truncated to 128 bits, hex.
pub(crate) fn keyed_id(key: &[u8], data: &[u8]) -> String {
    match <Hmac<Sha256> as Mac>::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(data);
            hex(&mac.finalize().into_bytes()[..16])
        }
        Err(_) => String::new(),
    }
}

fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                return Err("floating point number".into());
            }
            let _ = write!(out, "{n}");
        }
        Value::String(s) => string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(key, out);
                out.push(':');
                write(&map[key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Canonical JSON: sorted keys, minimal separators, ASCII only (DEL and above escaped), no floats.
pub(crate) fn canon(value: &Value) -> Result<String, String> {
    let mut out = String::with_capacity(256);
    write(value, &mut out)?;
    Ok(out)
}

/// A hash chain over one segment.
#[derive(Debug)]
pub(crate) struct Chain {
    head: String,
    n: u64,
}

impl Chain {
    pub(crate) fn new(segment: &str) -> Self {
        Self {
            head: hex(&Sha256::digest(format!("{GENESIS}{segment}").as_bytes())),
            n: 0,
        }
    }

    /// Set `n`, `prev`, `hash` on `record` and return its framed line.
    pub(crate) fn push(&mut self, mut record: Map<String, Value>) -> Result<Vec<u8>, String> {
        record.insert("n".into(), Value::from(self.n));
        record.insert("prev".into(), Value::from(self.head.clone()));
        let hash = hex(&Sha256::digest(
            canon(&Value::Object(record.clone()))?.as_bytes(),
        ));
        record.insert("hash".into(), Value::from(hash.clone()));
        let body = canon(&Value::Object(record))?;
        let mut line = format!("{:08x} ", crc32fast::hash(body.as_bytes())).into_bytes();
        line.extend_from_slice(body.as_bytes());
        line.push(b'\n');
        self.head = hash;
        self.n += 1;
        Ok(line)
    }

    pub(crate) fn head(&self) -> &str {
        &self.head
    }

    pub(crate) fn count(&self) -> u64 {
        self.n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_the_python_twin_byte_for_byte() {
        let mut chain = Chain::new("sess/etw/1");
        let record = json!({"kind": "core.marker", "source_id": "etw", "source_seq": 0,
            "payload": {"s": "\u{e9}\u{7f}", "n": u64::MAX}});
        let Value::Object(map) = record else {
            unreachable!()
        };
        let line = String::from_utf8(chain.push(map).expect("canonical")).expect("ascii");
        assert_eq!(
            line,
            "cf81972f {\"hash\":\"9a7b021c24c9d5351906cd62720c5425642fbb9757f71ed0009cc9ca8d05c15d\",\"kind\":\"core.marker\",\"n\":0,\"payload\":{\"n\":18446744073709551615,\"s\":\"\\u00e9\\u007f\"},\"prev\":\"b7daa813e26bd6f67cef1abc48e3bba6640d59521f0bbdd5b4c7d93249f11470\",\"source_id\":\"etw\",\"source_seq\":0}\n"
        );
        assert_eq!(
            chain.head(),
            "9a7b021c24c9d5351906cd62720c5425642fbb9757f71ed0009cc9ca8d05c15d"
        );
    }

    #[test]
    fn floats_are_refused() {
        assert!(canon(&json!({"t": 1.5})).is_err());
    }

    #[test]
    fn keyed_ids_depend_on_the_key() {
        assert_ne!(keyed_id(&[1; 32], b"a"), keyed_id(&[2; 32], b"a"));
        assert_eq!(keyed_id(&[1; 32], b"a").len(), 32);
    }
}
