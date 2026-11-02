//! The TRACE-1 raw segment writer: `crc-hex8 SP canonical-json LF`, hash-chained from a per-segment genesis.
//! Byte-identical to `hydralysis.trace_wire` and `hydra-trace::raw` (a golden vector in the tests pins it).

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const GENESIS: &str = "hydra.trace.segment/1\n";

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_into(bytes: &[u8], out: &mut String) {
    out.reserve(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 15)]));
    }
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    hex_into(bytes, &mut s);
    s
}

/// The keyed correlation id of `data`: HMAC-SHA256 under `key`, truncated to 128 bits, hex.
pub(crate) fn keyed_id(key: &[u8], data: &[u8]) -> String {
    thread_local! {
        /// The HMAC state after the key schedule, for the key last used on this thread: the consumer callback uses one
        /// key for the whole session, so the two pad blocks are hashed once rather than once per string.
        static KEYED: std::cell::RefCell<Option<(Vec<u8>, Hmac<Sha256>)>> = const { std::cell::RefCell::new(None) };
    }
    KEYED.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.as_ref().is_none_or(|(k, _)| k.as_slice() != key) {
            match <Hmac<Sha256> as Mac>::new_from_slice(key) {
                Ok(mac) => *slot = Some((key.to_vec(), mac)),
                Err(_) => return String::new(),
            }
        }
        let Some((_, base)) = slot.as_ref() else {
            return String::new();
        };
        let mut mac = base.clone();
        mac.update(data);
        hex(&mac.finalize().into_bytes()[..16])
    })
}

fn string(s: &str, out: &mut String) {
    out.push('"');
    // Fast path: printable ASCII with nothing to escape is copied as one run.
    if s.bytes()
        .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
    {
        out.push_str(s);
        out.push('"');
        return;
    }
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
            // `serde_json::Map` is a BTreeMap here (the workspace does not enable `preserve_order`; the golden
            // test below would fail if it did), so iteration is already in sorted key order.
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(key, out);
                out.push(':');
                write(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Canonical JSON: sorted keys, minimal separators, ASCII only (DEL and above escaped), no floats.
#[cfg(test)]
pub(crate) fn canon(value: &Value) -> Result<String, String> {
    let mut out = String::with_capacity(256);
    write(value, &mut out)?;
    Ok(out)
}

struct WriteBytes<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for WriteBytes<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
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

    /// Chain `record` after the previous one and return its framed line. The record is canonicalised once, with `n`
    /// and `prev` merged in at their sorted positions; `hash` covers those bytes and is spliced in (sorted) afterwards,
    /// so nothing is cloned and nothing is canonicalised twice.
    pub(crate) fn push(&mut self, record: &Map<String, Value>) -> Result<Vec<u8>, String> {
        let mut plain = String::with_capacity(512);
        plain.push('{');
        let mut splice: Option<usize> = None;
        let mut first = true;
        let (mut n_done, mut prev_done) = (false, false);
        let mut entries = record.iter().peekable();
        loop {
            // The smallest pending key among the record's own entries and the two chain fields.
            let own = entries.peek().map(|(k, _)| k.as_str());
            let (key, kind) = if !n_done && own.is_none_or(|k| "n" < k) {
                ("n", 1)
            } else if !prev_done && own.is_none_or(|k| "prev" < k) {
                ("prev", 2)
            } else if let Some(k) = own {
                (k, 0)
            } else {
                break;
            };
            if !first {
                plain.push(',');
            }
            first = false;
            if splice.is_none() && key > "hash" {
                splice = Some(plain.len());
            }
            string(key, &mut plain);
            plain.push(':');
            match kind {
                1 => {
                    let _ = write!(plain, "{}", self.n);
                    n_done = true;
                }
                2 => {
                    string(&self.head, &mut plain);
                    prev_done = true;
                }
                _ => {
                    if let Some((_, value)) = entries.next() {
                        write(value, &mut plain)?;
                    }
                }
            }
        }
        plain.push('}');
        let at = splice.unwrap_or(plain.len() - 1);
        let digest = Sha256::digest(plain.as_bytes());
        let mut hash = String::with_capacity(64);
        hex_into(&digest, &mut hash);
        let mut body = String::with_capacity(plain.len() + 80);
        body.push_str(&plain[..at]);
        if splice.is_none() {
            body.push(',');
        }
        body.push_str("\"hash\":\"");
        body.push_str(&hash);
        body.push('"');
        if splice.is_some() {
            body.push(',');
        }
        body.push_str(&plain[at..]);
        let mut line = Vec::with_capacity(body.len() + 10);
        let _ = write!(
            WriteBytes(&mut line),
            "{:08x} ",
            crc32fast::hash(body.as_bytes())
        );
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
        let line = String::from_utf8(chain.push(&map).expect("canonical")).expect("ascii");
        assert_eq!(
            line,
            "cf81972f {\"hash\":\"9a7b021c24c9d5351906cd62720c5425642fbb9757f71ed0009cc9ca8d05c15d\",\"kind\":\"core.marker\",\"n\":0,\"payload\":{\"n\":18446744073709551615,\"s\":\"\\u00e9\\u007f\"},\"prev\":\"b7daa813e26bd6f67cef1abc48e3bba6640d59521f0bbdd5b4c7d93249f11470\",\"source_id\":\"etw\",\"source_seq\":0}\n"
        );
        assert_eq!(
            chain.head(),
            "9a7b021c24c9d5351906cd62720c5425642fbb9757f71ed0009cc9ca8d05c15d"
        );
    }

    /// The previous two-pass implementation, kept as the reference the one-pass chain must match.
    fn reference(head: &str, n: u64, mut record: Map<String, Value>) -> (String, String) {
        record.insert("n".into(), Value::from(n));
        record.insert("prev".into(), Value::from(head));
        let first = canon(&Value::Object(record.clone())).expect("canonical");
        let hash = hex(&Sha256::digest(first.as_bytes()));
        record.insert("hash".into(), Value::from(hash.clone()));
        let body = canon(&Value::Object(record)).expect("canonical");
        (
            format!("{:08x} {body}\n", crc32fast::hash(body.as_bytes())),
            hash,
        )
    }

    #[test]
    fn one_pass_chain_equals_the_two_pass_reference() {
        let mut chain = Chain::new("sess/etw/1");
        let (mut head, mut n) = (chain.head().to_owned(), 0u64);
        let shapes = [
            json!({"kind": "etw.file", "source_id": "etw", "source_seq": 1, "process_id": 77, "thread_id": 5,
                "payload": {"a": [1, 2, {"z": "q\"\\\n"}], "b": null}}),
            json!({"kind": "core.capture.gap", "source_id": "etw", "acquisition": "atomic", "zeta": true, "payload": {}}),
            json!({"aaa": 1, "payload": {"\u{e9}": "\u{1f600}"}}),
            json!({}),
        ];
        for shape in shapes {
            let Value::Object(map) = shape else {
                unreachable!()
            };
            let (expected, expected_hash) = reference(&head, n, map.clone());
            let line = String::from_utf8(chain.push(&map).expect("canonical")).expect("ascii");
            assert_eq!(line, expected);
            head = expected_hash;
            n += 1;
            assert_eq!(chain.head(), head);
        }
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
