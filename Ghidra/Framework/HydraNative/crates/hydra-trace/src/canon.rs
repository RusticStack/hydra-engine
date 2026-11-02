//! Canonical JSON for chained records: sorted keys, minimal separators, ASCII only (`\uXXXX`,
//! surrogate pairs above the BMP) and no floating point. This is byte-identical to Python's
//! `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)` for
//! the values TRACE-1 allows. Times are integer nanoseconds so no float formatting can differ.

use serde_json::{Map, Value};
use std::io::Write;

/// A value TRACE-1 does not allow in a chained record.
#[derive(Debug, PartialEq, Eq)]
pub struct NotCanonical(pub &'static str);

impl std::fmt::Display for NotCanonical {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not canonical: {}", self.0)
    }
}

impl std::error::Error for NotCanonical {}

/// The canonical bytes of `value`.
pub fn to_vec(value: &Value) -> Result<Vec<u8>, NotCanonical> {
    let mut out = Vec::with_capacity(256);
    write(value, &mut out)?;
    Ok(out)
}

/// The canonical bytes of the object `map` without its `skip` key, with no copy of the map.
pub fn to_vec_without(map: &Map<String, Value>, skip: &str) -> Result<Vec<u8>, NotCanonical> {
    let mut out = Vec::with_capacity(256);
    write_object(map, Some(skip), None, &mut out)?;
    Ok(out)
}

/// One serialization pass for a chained record: the canonical bytes of `map` (which must not
/// hold `key`) go to `digest`, then the same bytes with `key` set to the string `digest` returns
/// are produced by splicing the entry into its sorted position. Equal to hashing
/// `to_vec(map)` and then `to_vec(map + key)`, without serializing twice.
pub fn to_vec_with_string(
    map: &Map<String, Value>,
    key: &str,
    digest: impl FnOnce(&[u8]) -> String,
) -> Result<Vec<u8>, NotCanonical> {
    let mut out = Vec::with_capacity(320);
    let mut at = None;
    write_object(map, Some(key), Some((key, &mut at)), &mut out)?;
    let text = digest(&out);
    let (offset, comma_before, comma_after) = at.unwrap_or((out.len() - 1, false, false));
    let mut insert = Vec::with_capacity(text.len() + key.len() + 8);
    if comma_before {
        insert.push(b',');
    }
    string(key, &mut insert);
    insert.push(b':');
    string(&text, &mut insert);
    if comma_after {
        insert.push(b',');
    }
    out.splice(offset..offset, insert);
    Ok(out)
}

/// Where a spliced entry goes: byte offset, comma before, comma after.
type SplicePoint = Option<(usize, bool, bool)>;

fn write_object(
    map: &Map<String, Value>,
    skip: Option<&str>,
    mut splice: Option<(&str, &mut SplicePoint)>,
    out: &mut Vec<u8>,
) -> Result<(), NotCanonical> {
    // serde_json's default Map is a BTreeMap, so iteration is sorted by key. Keys are ASCII by
    // contract, where byte order equals Python's code point order.
    out.push(b'{');
    let mut written = 0usize;
    for (key, item) in map {
        if skip == Some(key.as_str()) {
            continue;
        }
        if let Some((k, at)) = splice.as_mut()
            && at.is_none()
            && key.as_str() > *k
        {
            // Before this entry: the new entry is followed by a comma.
            **at = Some((out.len() + usize::from(written > 0), false, true));
        }
        if written > 0 {
            out.push(b',');
        }
        string(key, out);
        out.push(b':');
        write(item, out)?;
        written += 1;
    }
    if let Some((_, at)) = splice.as_mut()
        && at.is_none()
    {
        // After every entry: before the closing brace, preceded by a comma unless empty.
        **at = Some((out.len(), written > 0, false));
    }
    out.push(b'}');
    Ok(())
}

fn write(value: &Value, out: &mut Vec<u8>) -> Result<(), NotCanonical> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if n.is_f64() {
                return Err(NotCanonical("floating point number"));
            }
            let _ = write!(out, "{n}");
        }
        Value::String(s) => string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => write_object(map, None, None, out)?,
    }
    Ok(())
}

/// True for a byte that is written as itself.
fn plain(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\'
}

fn string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    // Runs of plain printable ASCII are copied whole; only the rest takes the escape path.
    let bytes = s.as_bytes();
    let mut run = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if plain(b) {
            i += 1;
            continue;
        }
        out.extend_from_slice(&bytes[run..i]);
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            _ if b < 0x80 => {
                let _ = write!(out, "\\u{:04x}", u16::from(b));
            }
            _ => {
                // `s` is valid UTF-8 and `i` is at a character boundary.
                if let Some(c) = s[i..].chars().next() {
                    let mut units = [0u16; 2];
                    for unit in c.encode_utf16(&mut units) {
                        let _ = write!(out, "\\u{unit:04x}");
                    }
                    i += c.len_utf8() - 1;
                }
            }
        }
        i += 1;
        run = i;
    }
    out.extend_from_slice(&bytes[run..]);
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorted_ascii_minimal() {
        let v = json!({"b": 1, "a": ["x", "é", "😀", "\u{7f}"], "c": null});
        assert_eq!(
            String::from_utf8(to_vec(&v).unwrap()).unwrap(),
            "{\"a\":[\"x\",\"\\u00e9\",\"\\ud83d\\ude00\",\"\\u007f\"],\"b\":1,\"c\":null}"
        );
    }

    #[test]
    fn escapes() {
        let v = json!({"k": "a\"b\\c\nd\te\u{1}f\u{8}\u{c}é"});
        assert_eq!(
            String::from_utf8(to_vec(&v).unwrap()).unwrap(),
            "{\"k\":\"a\\\"b\\\\c\\nd\\te\\u0001f\\b\\fé\"}".replace('é', "\\u00e9")
        );
    }

    #[test]
    fn floats_refused() {
        assert!(to_vec(&json!({"t": 1.5})).is_err());
    }

    #[test]
    fn spliced_entry_equals_a_full_serialization() {
        for v in [
            json!({}),
            json!({"a": 1}),
            json!({"a": 1, "z": 2}),
            json!({"x": 1, "y": {"hash": "inner"}}),
            json!({"a": 1, "i": [1, 2], "kind": "k", "n": 5, "prev": "p"}),
            json!({"zz": 1}),
        ] {
            let map = v.as_object().unwrap().clone();
            let mut seen = Vec::new();
            let spliced = to_vec_with_string(&map, "hash", |b| {
                seen = b.to_vec();
                "abc".into()
            })
            .unwrap();
            let mut full = map.clone();
            full.insert("hash".into(), "abc".into());
            assert_eq!(spliced, to_vec(&Value::Object(full)).unwrap(), "{v}");
            assert_eq!(seen, to_vec(&v).unwrap(), "{v}");
            let mut with = map.clone();
            with.insert("hash".into(), "old".into());
            assert_eq!(to_vec_without(&with, "hash").unwrap(), seen);
        }
    }
}
