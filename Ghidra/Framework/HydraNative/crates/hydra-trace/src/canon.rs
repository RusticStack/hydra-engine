//! Canonical JSON for chained records: sorted keys, minimal separators, ASCII only (`\uXXXX`,
//! surrogate pairs above the BMP) and no floating point. This is byte-identical to Python's
//! `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)` for
//! the values TRACE-1 allows. Times are integer nanoseconds so no float formatting can differ.

use serde_json::Value;

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

fn write(value: &Value, out: &mut Vec<u8>) -> Result<(), NotCanonical> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if n.is_f64() {
                return Err(NotCanonical("floating point number"));
            }
            out.extend_from_slice(n.to_string().as_bytes());
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
        Value::Object(map) => {
            // serde_json's default Map is a BTreeMap, so iteration is sorted by key. Keys are
            // ASCII by contract, where byte order equals Python's code point order.
            out.push(b'{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                string(key, out);
                out.push(b':');
                write(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.extend_from_slice(format!("\\u{unit:04x}").as_bytes());
                }
            }
            c => out.push(c as u8),
        }
    }
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
    fn floats_refused() {
        assert!(to_vec(&json!({"t": 1.5})).is_err());
    }
}
