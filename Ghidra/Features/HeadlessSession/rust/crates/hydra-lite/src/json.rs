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
//! An order-preserving JSON value, a strict parser, and a writer that produces the bytes Gson
//! writes (`disableHtmlEscaping`, `serializeNulls`, compact).
//!
//! The daemon's replies have a fixed key order and a fixed string escaping that clients and the
//! reply-parity gate compare byte for byte, so no map type that sorts or normalises is used.
//! Numbers keep the text they were read with (Gson's `LazilyParsedNumber` does the same), so an
//! `id` is echoed exactly as the client wrote it.

use std::fmt::Write as _;

/// A JSON value. Objects are association lists in insertion order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as the text it was read or built with.
    Num(String),
    /// A string.
    Str(String),
    /// An array.
    Arr(Vec<Json>),
    /// An object; keys are unique and keep the position of their first insertion.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// An empty object.
    #[must_use]
    pub fn obj() -> Self {
        Self::Obj(Vec::new())
    }

    /// A string value.
    #[must_use]
    pub fn str(s: impl Into<String>) -> Self {
        Self::Str(s.into())
    }

    /// A signed integer value.
    #[must_use]
    pub fn int(v: i64) -> Self {
        Self::Num(v.to_string())
    }

    /// An unsigned integer value.
    #[must_use]
    pub fn uint(v: u64) -> Self {
        Self::Num(v.to_string())
    }

    /// A string value or `null`.
    #[must_use]
    pub fn opt_str(s: Option<&str>) -> Self {
        s.map_or(Self::Null, |s| Self::Str(s.to_owned()))
    }

    /// An array of strings.
    #[must_use]
    pub fn strings<'a>(items: impl IntoIterator<Item = &'a str>) -> Self {
        Self::Arr(items.into_iter().map(Self::str).collect())
    }

    /// An array of integers.
    #[must_use]
    pub fn ints(items: impl IntoIterator<Item = u64>) -> Self {
        Self::Arr(items.into_iter().map(Self::uint).collect())
    }

    /// Sets `key` (Gson `JsonObject.add`: an existing key keeps its position), and returns `self`.
    #[must_use]
    pub fn with(mut self, key: &str, value: Json) -> Self {
        self.put(key, value);
        self
    }

    /// Sets `key` in an object; does nothing on another kind of value.
    pub fn put(&mut self, key: &str, value: Json) {
        if let Self::Obj(members) = self {
            if let Some(slot) = members.iter_mut().find(|(k, _)| k == key) {
                slot.1 = value;
            } else {
                members.push((key.to_owned(), value));
            }
        }
    }

    /// The member `key` of an object.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Self::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The text of a string value.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The members of an object.
    #[must_use]
    pub fn members(&self) -> Option<&[(String, Json)]> {
        match self {
            Self::Obj(m) => Some(m),
            _ => None,
        }
    }

    /// Removes `key` from an object.
    pub fn remove(&mut self, key: &str) {
        if let Self::Obj(members) = self {
            members.retain(|(k, _)| k != key);
        }
    }

    /// The compact text Gson writes for this value.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    /// Appends the compact text Gson writes for this value.
    pub fn write(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(true) => out.push_str("true"),
            Self::Bool(false) => out.push_str("false"),
            Self::Num(n) => out.push_str(n),
            Self::Str(s) => write_string(out, s),
            Self::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Self::Obj(members) => {
                out.push('{');
                for (i, (k, v)) in members.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(out, k);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// Writes a string as Gson's `JsonWriter` does with HTML escaping off: `"` `\` and the control
/// characters are escaped (`\t \b \n \r \f` short, the rest `\u00xx` in lower case), as are
/// U+2028 and U+2029; every other character is written as it is.
pub fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{c}' => out.push_str("\\f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Why a text is not accepted as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The text ended inside a value.
    Eof,
    /// An unexpected character at a byte offset.
    Unexpected(usize),
    /// Text follows the value.
    Trailing(usize),
    /// Nesting deeper than the limit.
    TooDeep,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eof => f.write_str("unexpected end of input"),
            Self::Unexpected(at) => write!(f, "unexpected character at offset {at}"),
            Self::Trailing(at) => write!(f, "text after the value at offset {at}"),
            Self::TooDeep => f.write_str("nesting too deep"),
        }
    }
}

impl std::error::Error for ParseError {}

const MAX_DEPTH: usize = 128;

/// Parses strict JSON (RFC 8259). Gson's lenient forms (unquoted names, single quotes, comments,
/// trailing commas) are not accepted: a caller that meets one refuses instead of guessing.
///
/// # Errors
///
/// [`ParseError`] for text that is not exactly one JSON value.
pub fn parse(text: &str) -> Result<Json, ParseError> {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i < p.b.len() {
        return Err(ParseError::Trailing(p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.i += 1;
        }
    }

    fn peek(&self) -> Result<u8, ParseError> {
        self.b.get(self.i).copied().ok_or(ParseError::Eof)
    }

    fn expect(&mut self, c: u8) -> Result<(), ParseError> {
        if self.peek()? == c {
            self.i += 1;
            Ok(())
        } else {
            Err(ParseError::Unexpected(self.i))
        }
    }

    fn literal(&mut self, word: &str, v: Json) -> Result<Json, ParseError> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(ParseError::Unexpected(self.i))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError::TooDeep);
        }
        match self.peek()? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Json::Str(self.string()?)),
            b't' => self.literal("true", Json::Bool(true)),
            b'f' => self.literal("false", Json::Bool(false)),
            b'n' => self.literal("null", Json::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(ParseError::Unexpected(self.i)),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.expect(b'{')?;
        let mut out = Json::obj();
        self.ws();
        if self.peek()? == b'}' {
            self.i += 1;
            return Ok(out);
        }
        loop {
            self.ws();
            if self.peek()? != b'"' {
                return Err(ParseError::Unexpected(self.i));
            }
            let key = self.string()?;
            self.ws();
            self.expect(b':')?;
            self.ws();
            let v = self.value(depth + 1)?;
            out.put(&key, v);
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    return Ok(out);
                }
                _ => return Err(ParseError::Unexpected(self.i)),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.ws();
        if self.peek()? == b']' {
            self.i += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(ParseError::Unexpected(self.i)),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let mut v = 0u32;
        for _ in 0..4 {
            let d = char::from(self.peek()?)
                .to_digit(16)
                .ok_or(ParseError::Unexpected(self.i))?;
            v = v * 16 + d;
            self.i += 1;
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        let mut run = self.i;
        loop {
            let c = self.peek()?;
            match c {
                b'"' => {
                    out.push_str(self.slice(run, self.i)?);
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    out.push_str(self.slice(run, self.i)?);
                    self.i += 1;
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                // a surrogate pair; a lone surrogate is not text
                                if self.b[self.i..].starts_with(b"\\u") {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return Err(ParseError::Unexpected(self.i));
                                    }
                                    0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                } else {
                                    return Err(ParseError::Unexpected(self.i));
                                }
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).ok_or(ParseError::Unexpected(self.i))?);
                        }
                        _ => return Err(ParseError::Unexpected(self.i - 1)),
                    }
                    run = self.i;
                }
                0..=0x1f => return Err(ParseError::Unexpected(self.i)),
                _ => self.i += 1,
            }
        }
    }

    fn slice(&self, from: usize, to: usize) -> Result<&str, ParseError> {
        std::str::from_utf8(&self.b[from..to]).map_err(|_| ParseError::Unexpected(from))
    }

    fn number(&mut self) -> Result<Json, ParseError> {
        let start = self.i;
        if self.peek()? == b'-' {
            self.i += 1;
        }
        match self.peek()? {
            b'0' => self.i += 1,
            b'1'..=b'9' => self.digits(),
            _ => return Err(ParseError::Unexpected(self.i)),
        }
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            self.need_digits()?;
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            self.need_digits()?;
        }
        Ok(Json::Num(self.slice(start, self.i)?.to_owned()))
    }

    fn digits(&mut self) {
        while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
            self.i += 1;
        }
    }

    fn need_digits(&mut self) -> Result<(), ParseError> {
        if matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
            self.digits();
            Ok(())
        } else {
            Err(ParseError::Unexpected(self.i))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_and_numbers_survive_a_round_trip() {
        let text = r#"{"id":1.50,"b":[1,2e3,-0],"a":{"z":null,"y":true},"s":"x\"\\\n\u0001 é"}"#;
        let v = parse(text).expect("parses");
        assert_eq!(
            v.to_text(),
            r#"{"id":1.50,"b":[1,2e3,-0],"a":{"z":null,"y":true},"s":"x\"\\\n\u0001\u2028é"}"#,
            "key order, number text and Gson escapes are kept"
        );
    }

    #[test]
    fn a_duplicate_key_keeps_the_first_position_and_the_last_value() {
        let v = parse(r#"{"a":1,"b":2,"a":3}"#).expect("parses");
        assert_eq!(
            v.to_text(),
            r#"{"a":3,"b":2}"#,
            "Gson JsonObject.add replaces in place"
        );
    }

    #[test]
    fn gson_escapes_only_what_it_escapes() {
        let mut s = String::new();
        write_string(&mut s, "a<b>&='\u{7f}\u{1f}\u{2029}/");
        assert_eq!(
            s, "\"a<b>&='\u{7f}\\u001f\\u2029/\"",
            "no HTML escaping, DEL kept"
        );
    }

    #[test]
    fn lenient_gson_forms_are_refused() {
        for bad in [
            "{a:1}",
            "{'a':1}",
            "{\"a\":1,}",
            "[1,]",
            "{\"a\":1} x",
            "",
            "{\"a\":01}",
        ] {
            assert!(parse(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn surrogate_pairs_decode() {
        let v = parse(r#""😀""#).expect("parses");
        assert_eq!(v.as_str(), Some("\u{1f600}"), "a pair is one scalar value");
        assert!(parse(r#""\ud83d""#).is_err(), "a lone surrogate is refused");
    }
}
