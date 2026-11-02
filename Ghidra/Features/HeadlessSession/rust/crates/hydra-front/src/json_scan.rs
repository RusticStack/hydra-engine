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
//! Top-level surgery on one JSON object without reordering or re-encoding it.
//!
//! The daemon's replies have a stable key order that clients and goldens depend on, and a
//! `serde_json::Value` without `preserve_order` sorts keys. The front only ever needs to read a few
//! top-level fields of a request and to replace a few top-level fields of a reply, so it splits the
//! object into `(key, raw value text)` pairs and joins them back byte for byte.

/// One member of a JSON object: the decoded key and the raw text of its value.
pub(crate) type Member<'a> = (String, &'a str);

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

/// The index just past the string that starts at `i` (which holds the opening quote).
fn string_end(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

/// The index just past the value that starts at `i`.
fn value_end(b: &[u8], i: usize) -> Option<usize> {
    match *b.get(i)? {
        b'"' => string_end(b, i),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => {
                        j = string_end(b, j)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            return Some(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            None
        }
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n')
            {
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

/// Splits a JSON object into its members, in order. `None` when `text` is not one JSON object
/// (the caller answers `bad_request`); the values are not validated beyond their extent.
pub(crate) fn split_object(text: &str) -> Option<Vec<Member<'_>>> {
    let b = text.as_bytes();
    let mut i = skip_ws(b, 0);
    if b.get(i) != Some(&b'{') {
        return None;
    }
    i = skip_ws(b, i + 1);
    let mut out = Vec::new();
    if b.get(i) == Some(&b'}') {
        return (skip_ws(b, i + 1) == b.len()).then_some(out);
    }
    loop {
        if b.get(i) != Some(&b'"') {
            return None;
        }
        let ke = string_end(b, i)?;
        let key: String = serde_json::from_str(&text[i..ke]).ok()?;
        i = skip_ws(b, ke);
        if b.get(i) != Some(&b':') {
            return None;
        }
        i = skip_ws(b, i + 1);
        let ve = value_end(b, i)?;
        out.push((key, &text[i..ve]));
        i = skip_ws(b, ve);
        match b.get(i)? {
            b',' => i = skip_ws(b, i + 1),
            b'}' => return (skip_ws(b, i + 1) == b.len()).then_some(out),
            _ => return None,
        }
    }
}

/// Looks a member up by key (the last one wins, as in a parser that overwrites).
pub(crate) fn get<'a>(members: &[Member<'a>], key: &str) -> Option<&'a str> {
    members
        .iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, v)| *v)
}

/// The raw value of `key` in an owned member list.
pub(crate) fn get_owned(members: &[(String, String)], key: &str) -> Option<String> {
    members
        .iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
}

/// The JSON text of a string value.
pub(crate) fn quote(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| String::from("\"\""))
}

/// The decoded value of a raw JSON string, or `None` when the raw text is not a string.
pub(crate) fn unquote(raw: &str) -> Option<String> {
    if raw.starts_with('"') {
        serde_json::from_str(raw).ok()
    } else {
        None
    }
}

/// Joins members back into one object text.
pub(crate) fn join_object<S: AsRef<str>>(members: &[(String, S)]) -> String {
    let mut s = String::from("{");
    for (n, (k, v)) in members.iter().enumerate() {
        if n > 0 {
            s.push(',');
        }
        s.push_str(&quote(k));
        s.push(':');
        s.push_str(v.as_ref());
    }
    s.push('}');
    s
}

/// An owned copy of a split object, ready for edits.
pub(crate) fn to_owned_members(members: &[Member<'_>]) -> Vec<(String, String)> {
    members
        .iter()
        .map(|(k, v)| (k.clone(), (*v).to_owned()))
        .collect()
}

/// Sets `key` to `raw`; appends it when absent.
pub(crate) fn set(members: &mut Vec<(String, String)>, key: &str, raw: String) {
    if let Some(m) = members.iter_mut().find(|(k, _)| k == key) {
        m.1 = raw;
    } else {
        members.push((key.to_owned(), raw));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_and_rejoins_without_reordering() {
        let t = r#"{"b":1,"a":{"x":[1,{"y":"}"}],"s":"q\"uote"},"c":"z","d":null,"e":-1.5e3}"#;
        let m = split_object(t).expect("an object");
        let keys: Vec<_> = m.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            ["b", "a", "c", "d", "e"],
            "key order is the text order"
        );
        assert_eq!(join_object(&m), t, "rejoining is byte for byte");
        assert_eq!(get(&m, "d"), Some("null"), "a literal keeps its text");
    }

    #[test]
    fn rejects_what_is_not_one_object() {
        for t in [
            "",
            "[]",
            "{",
            "{\"a\"}",
            "{\"a\":1,}",
            "{\"a\":1} x",
            "\"s\"",
            "{\"a\":}",
        ] {
            assert!(split_object(t).is_none(), "{t:?} is not an object");
        }
        assert_eq!(
            split_object(" { } ").map(|m| m.len()),
            Some(0),
            "empty is fine"
        );
    }

    #[test]
    fn set_replaces_in_place_and_appends() {
        let mut m = to_owned_members(&split_object(r#"{"a":1,"b":2}"#).expect("object"));
        set(&mut m, "a", "9".into());
        set(&mut m, "c", "3".into());
        assert_eq!(
            join_object(&m),
            r#"{"a":9,"b":2,"c":3}"#,
            "in place, then appended"
        );
    }
}
