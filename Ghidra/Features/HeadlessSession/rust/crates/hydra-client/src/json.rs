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
//! Canonical JSON and the reply digests the benchmark uses.
//!
//! The benchmark identifies a reply by `hashlib.sha256(json.dumps(obj, sort_keys=True)).hexdigest()
//! [:24]` after removing volatile fields. To compare a Rust agent's replies with the Python
//! agents' on the same run, this module writes JSON exactly as Python's `json.dumps` does with
//! its defaults (`ensure_ascii=True`, separators `", "` and `": "`, sorted keys) and hashes it.
//! Only the values the agent hashes are ever serialized: strings, numbers, booleans, null, arrays
//! and objects.

use std::fmt::Write as _;

use serde_json::{Map, Value};

/// `json.dumps(value, sort_keys=True)` with Python's default separators and `ensure_ascii`.
///
/// Object keys come out sorted: `serde_json`'s default `Map` is a `BTreeMap`, whose byte order
/// on UTF-8 is Python's code-point order. Floats use Python's `repr` form (`1.0`, `1e-05`,
/// `1e+16`), so a digest is the same number the Python client would produce.
#[must_use]
pub fn python_dumps(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&python_number(n)),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_string(out, key);
                out.push_str(": ");
                write_value(out, item);
            }
            out.push('}');
        }
    }
}

fn python_number(number: &serde_json::Number) -> String {
    if number.is_i64() || number.is_u64() {
        return number.to_string();
    }
    python_float(number.as_f64().unwrap_or(f64::NAN))
}

/// Python's `repr` of a finite float, as `json.dumps` writes it.
fn python_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() { "-Infinity" } else { "Infinity" }.to_owned();
    }
    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0" } else { "0.0" }.to_owned();
    }
    // serde_json writes a float through ryu: the shortest digits that round-trip. Python's
    // repr uses the same shortest digits; only the notation thresholds and the exponent text
    // differ, so the digits are re-laid out here.
    let raw = serde_json::Number::from_f64(value).map_or_else(String::new, |n| n.to_string());
    let (mantissa, exp10) = match raw.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i32>().unwrap_or(0)),
        None => (raw.as_str(), 0),
    };
    let negative = mantissa.starts_with('-');
    let unsigned = mantissa.trim_start_matches('-');
    let (int_part, frac_part) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    let mut digits: String = format!("{int_part}{frac_part}");
    let mut point = i32::try_from(int_part.len()).unwrap_or(0) + exp10;
    let leading = digits.bytes().take_while(|b| *b == b'0').count();
    digits.drain(..leading);
    point -= i32::try_from(leading).unwrap_or(0);
    while digits.ends_with('0') {
        digits.pop();
    }
    if digits.is_empty() {
        return if negative { "-0.0" } else { "0.0" }.to_owned();
    }
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    // The exponent of the first significant digit; Python switches to scientific notation
    // outside -4..16.
    let exponent = point - 1;
    if !(-4..16).contains(&exponent) {
        let (first, rest) = digits.split_at(1);
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        let _ = write!(out, "e{exponent:+03}");
    } else if point <= 0 {
        out.push_str("0.");
        for _ in 0..-point {
            out.push('0');
        }
        out.push_str(&digits);
    } else if usize::try_from(point).unwrap_or(0) >= digits.len() {
        out.push_str(&digits);
        for _ in 0..(point - i32::try_from(digits.len()).unwrap_or(0)) {
            out.push('0');
        }
        out.push_str(".0");
    } else {
        let at = usize::try_from(point).unwrap_or(0);
        let (whole, frac) = digits.split_at(at);
        out.push_str(whole);
        out.push('.');
        out.push_str(frac);
    }
    out
}

/// Python's `json.dumps` string escaping with `ensure_ascii=True`.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ' '..='~' => out.push(ch),
            other => {
                let mut buf = [0u16; 2];
                for unit in other.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

/// SHA-256 of `data`, lowercase hex.
///
/// Written here so the client needs no hashing crate; checked against the standard vectors and
/// against Python's `hashlib` in the lane's differential harness.
#[must_use]
#[expect(
    clippy::many_single_char_names,
    reason = "SHA-256 round variables are the letters a..h of FIPS 180-4"
)]
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
        0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
        0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
        0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
        0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
        0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_len = u64::try_from(data.len()).unwrap_or(u64::MAX).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, add) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(add);
        }
    }
    let mut out = String::with_capacity(64);
    for word in h {
        let _ = write!(out, "{word:08x}");
    }
    out
}

/// The benchmark's reply digest: the first 24 hex digits of the SHA-256 of [`python_dumps`].
#[must_use]
pub fn digest(value: &Value) -> String {
    let full = sha256_hex(python_dumps(value).as_bytes());
    full.chars().take(24).collect()
}

/// The projection `decomp_hash` hashes: `name`, `entry`, `completed`, `signature`, `c`,
/// `truncated`, `error`, with `null` for an absent key (Python's `r.get(k)`).
#[must_use]
pub fn decompile_projection(reply: &Value) -> Value {
    const KEYS: [&str; 7] = [
        "name",
        "entry",
        "completed",
        "signature",
        "c",
        "truncated",
        "error",
    ];
    let mut out = Map::new();
    for key in KEYS {
        out.insert(
            key.to_owned(),
            reply.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sha256_matches_the_standard_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn dumps_matches_python_for_structures() {
        // Generated with: json.dumps(obj, sort_keys=True)
        let cases = [
            (json!(null), "null"),
            (json!(true), "true"),
            (json!(false), "false"),
            (json!(0), "0"),
            (json!(-7), "-7"),
            (json!("a\"b\\c"), "\"a\\\"b\\\\c\""),
            (json!("line\nnext\ttab"), "\"line\\nnext\\ttab\""),
            (json!("\u{7f}"), "\"\\u007f\""),
            (json!("\u{e9}"), "\"\\u00e9\""),
            (json!("\u{1f600}"), "\"\\ud83d\\ude00\""),
            (json!([1, "x", null]), "[1, \"x\", null]"),
            (
                json!({"b": 1, "a": [true, {"d": 2, "c": 3}]}),
                "{\"a\": [true, {\"c\": 3, \"d\": 2}], \"b\": 1}",
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(python_dumps(&value), expected, "for {value}");
        }
    }

    #[test]
    fn floats_match_pythons_repr() {
        // values and expected text generated from Python's json.dumps.
        let cases: [(f64, &str); 15] = [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (1.5, "1.5"),
            (-2.25, "-2.25"),
            (1e-5, "1e-05"),
            (1e-4, "0.0001"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (1.234_567_890_123_456_7e16, "1.2345678901234568e+16"),
            (1.5e20, "1.5e+20"),
            (2.5e-7, "2.5e-07"),
            (123_456_789.125, "123456789.125"),
            (5e-324, "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
        ];
        for (value, expected) in cases {
            assert_eq!(python_float(value), expected, "for {value:?}");
        }
    }

    #[test]
    fn digest_is_pythons_first_24_hex_digits() {
        // python -I -c "import hashlib,json; print(hashlib.sha256(json.dumps({'b':1,'a':2},
        //   sort_keys=True).encode()).hexdigest()[:24])"
        let value = json!({"b": 1, "a": 2});
        assert_eq!(digest(&value), "21501dbaf73f5223934d2228");
    }

    #[test]
    fn decompile_projection_fills_absent_keys_with_null() {
        let projection = decompile_projection(&json!({"name": "f", "c": "code"}));
        assert_eq!(
            projection,
            json!({"name": "f", "entry": null, "completed": null, "signature": null,
                   "c": "code", "truncated": null, "error": null})
        );
    }
}
